package rbac_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/EduGoGroup/identity-shared/auth/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Runner único de los vectores golden del matcher.
//
// ############################################################################################
// # AVISO — testdata/permission_matcher_golden_edugo.json ES UN VECTOR DE PRUEBA VENDORIZADO. #
// # NO SE EDITA, NO SE «NEUTRALIZA», NO SE REGENERA.                                          #
// ############################################################################################
//
// Ese fixture es un contrato cross-language entre tres implementaciones del mismo algoritmo: este
// matcher Go, la función iam.permission_matches() de Postgres y el PermissionMatcher Kotlin del
// cliente KMP. Todas las copias deben coincidir BYTE A BYTE con el maestro; si no coinciden, el
// contrato deja de estar verificado y las tres implementaciones pueden divergir en silencio.
//
// La forma fiable de comprobarlo es el hash, no la ruta: el maestro ya se movió una vez.
//
//	sha256 = c63c299777524f9a110e861f8ae1ff457d650c68ce657d8291083553574a76c6
//
// A 2026-07-27 vive en el repo de EduGo, en
// EduUI/edugo-ui-kmp/docs/archive/e2e-integration-plan/permissions-redesign-spec/fixtures/permission_matcher_golden.json
//
// Por eso el fixture conserva cadenas que nombran recursos del dominio de negocio de EduGo, ajenos
// por completo a este módulo, algo que sería inaceptable en cualquier otro archivo de este paquete.
// Es la ÚNICA excepción autorizada a la regla de frontera: aquí esas cadenas no son dominio
// modelado, son literales opacos de un vector de prueba —lo que se verifica es la FORMA del pattern,
// no la palabra—. Renombrarlas para «limpiar» el paquete mutaría el contrato y rompería la
// comparación con Kotlin y con Postgres sin que ningún test de este repo lo detecte.
//
// No existe un flag -update: estos fixtures son contratos de entrada, no goldens regenerables desde
// la implementación. Si un caso falla, el defecto está en el código, no en el fixture.
var goldenFixtures = []struct {
	name string // prefijo del subtest, para que los ids de ambos fixtures no colisionen
	path string
}{
	{name: "edugo", path: "testdata/permission_matcher_golden_edugo.json"},
	{name: "wapp", path: "testdata/permission_matcher_golden_wapp.json"},
}

// goldenMatcherCase es un caso del vector golden para PermissionMatches.
type goldenMatcherCase struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Pattern  string `json:"pattern"`
	Request  string `json:"request"`
	Expected bool   `json:"expected"`
}

// goldenGrantsCase es un caso del vector golden para EvaluateGrants.
type goldenGrantsCase struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Allow    []string `json:"allow"`
	Deny     []string `json:"deny"`
	Request  string   `json:"request"`
	Expected bool     `json:"expected"`
}

type goldenFile struct {
	Version      string              `json:"version"`
	MatcherCases []goldenMatcherCase `json:"matcher_cases"`
	GrantsCases  []goldenGrantsCase  `json:"grants_cases"`
}

// loadGoldenFixture carga y valida un vector golden. Un fixture ausente, vacío o ilegible es un
// fallo fatal: sin él no hay contrato verificado y un test «verde» sería una mentira.
func loadGoldenFixture(t *testing.T, path string) goldenFile {
	t.Helper()
	// #nosec G304 -- la ruta la construye el propio test a partir de constantes de testdata; no
	// proviene de entrada externa.
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("no se pudo leer el fixture golden %s: %v", path, err)
	}
	var gf goldenFile
	if err := json.Unmarshal(raw, &gf); err != nil {
		t.Fatalf("no se pudo deserializar el fixture golden %s: %v", path, err)
	}
	if gf.Version == "" {
		t.Fatalf("el fixture golden %s no declara version", path)
	}
	if len(gf.MatcherCases) == 0 {
		t.Fatalf("el fixture golden %s no tiene matcher_cases", path)
	}
	if len(gf.GrantsCases) == 0 {
		t.Fatalf("el fixture golden %s no tiene grants_cases", path)
	}
	return gf
}

// TestPermissionMatchesGolden corre los casos de matcher de todos los vectores golden.
func TestPermissionMatchesGolden(t *testing.T) {
	t.Parallel()

	for _, fixture := range goldenFixtures {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			gf := loadGoldenFixture(t, fixture.path)
			for _, c := range gf.MatcherCases {
				c := c
				t.Run(c.ID, func(t *testing.T) {
					t.Parallel()
					assert.Equal(t, c.Expected, rbac.PermissionMatches(c.Pattern, c.Request),
						"[%s] %s: pattern=%q request=%q", c.ID, c.Name, c.Pattern, c.Request)
				})
			}
		})
	}
}

// TestEvaluateGrantsGolden corre los casos de grants de todos los vectores golden.
func TestEvaluateGrantsGolden(t *testing.T) {
	t.Parallel()

	for _, fixture := range goldenFixtures {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			gf := loadGoldenFixture(t, fixture.path)
			for _, c := range gf.GrantsCases {
				c := c
				t.Run(c.ID, func(t *testing.T) {
					t.Parallel()
					g := rbac.Grants{Allow: c.Allow, Deny: c.Deny}
					assert.Equal(t, c.Expected, rbac.EvaluateGrants(g, c.Request),
						"[%s] %s: allow=%v deny=%v request=%q", c.ID, c.Name, c.Allow, c.Deny, c.Request)
				})
			}
		})
	}
}

// TestGoldenFixturesCaseCounts fija el tamaño de cada vector: si alguien recorta un fixture, los
// tests de arriba seguirían pasando con menos casos y la pérdida de cobertura sería invisible. Los
// conteos son parte del contrato.
func TestGoldenFixturesCaseCounts(t *testing.T) {
	t.Parallel()

	want := map[string]struct {
		version string
		matcher int
		grants  int
	}{
		"edugo": {version: "1.1.0", matcher: 46, grants: 35},
		"wapp":  {version: "1.0.0", matcher: 15, grants: 22},
	}

	for _, fixture := range goldenFixtures {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			exp, ok := want[fixture.name]
			require.True(t, ok, "fixture %s sin conteo esperado declarado", fixture.name)
			gf := loadGoldenFixture(t, fixture.path)
			assert.Equal(t, exp.version, gf.Version, "version del fixture %s", fixture.name)
			assert.Len(t, gf.MatcherCases, exp.matcher, "matcher_cases del fixture %s", fixture.name)
			assert.Len(t, gf.GrantsCases, exp.grants, "grants_cases del fixture %s", fixture.name)
		})
	}
}
