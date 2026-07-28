package rbac_test

import (
	"testing"

	"github.com/EduGoGroup/identity-shared/auth/rbac"
	"github.com/stretchr/testify/assert"
)

// Tests complementarios a los vectores golden (ver permission_matcher_golden_test.go). Los golden
// cubren la matriz cross-language; estos casos cementan los bordes que los fixtures NO cubren y que
// el contrato de este módulo exige dejar explícitos: request vacío contra cada rama del matcher,
// pattern vacío, comodines intra-segmento y patterns con más de un comodín.

// TestPermissionMatches_EmptyRequest fija el comportamiento de cada rama del matcher ante un request
// vacío: solo el wildcard total lo cubre.
func TestPermissionMatches_EmptyRequest(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		pattern string
		want    bool
	}{
		{"el wildcard total cubre el request vacio", "*", true},
		{"el pattern vacio cubre el request vacio por igualdad", "", true},
		{"un pattern literal no cubre el request vacio", "identity.users.read", false},
		{"un subtree no cubre el request vacio", "identity.users.*", false},
		{"un comodin inicial no cubre el request vacio", "*.read", false},
		{"un comodin intermedio no cubre el request vacio", "identity.*.read", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, rbac.PermissionMatches(tc.pattern, ""),
				"pattern=%q request vacío", tc.pattern)
		})
	}
}

// TestPermissionMatches_EmptyPattern fija que un pattern vacío solo cubre el request vacío: no es un
// comodín accidental.
func TestPermissionMatches_EmptyPattern(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		request string
		want    bool
	}{
		{"cubre el request vacio por igualdad", "", true},
		{"no cubre un request de un solo tramo", "read", false},
		{"no cubre un request multinivel", "identity.users.read", false},
		{"no cubre un request que empieza con punto", ".read", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, rbac.PermissionMatches("", tc.request),
				"pattern vacío request=%q", tc.request)
		})
	}
}

// TestPermissionMatches_IntraSegmentWildcard fija que el comodín solo es válido como segmento
// completo. Un `*` pegado a otros caracteres dentro de un segmento NO es un comodín parcial: el
// matcher no hace globbing de subcadenas y el pattern queda sin cubrir nada (salvo su igualdad
// literal). Esta es la diferencia con `filepath.Match` y con un LIKE de SQL.
func TestPermissionMatches_IntraSegmentWildcard(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		pattern string
		request string
		want    bool
	}{
		{"comodin pegado al final del primer segmento", "ident*.read", "identity.read", false},
		{"comodin pegado al final de un segmento intermedio", "identity.us*.read", "identity.users.read", false},
		{"comodin pegado al inicio de un segmento intermedio", "identity.*ers.read", "identity.users.read", false},
		{"comodin pegado al final del ultimo segmento", "identity.users.rea*", "identity.users.read", false},
		{"comodin pegado al inicio del primer segmento", "*dentity.users.read", "identity.users.read", false},
		{"comodin intra-segmento solo matchea su literal exacto", "ident*.read", "ident*.read", true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, rbac.PermissionMatches(tc.pattern, tc.request),
				"pattern=%q request=%q", tc.pattern, tc.request)
		})
	}
}

// TestPermissionMatches_MultipleWildcards fija que la gramática admite un solo comodín por pattern.
// Con dos o más, el pattern no cubre nada: la rama de subárbol trata el resto como prefijo literal
// (que ningún request válido tiene) y la rama de comodín intermedio lo rechaza explícitamente al
// detectar un segundo `*` en head o tail.
func TestPermissionMatches_MultipleWildcards(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		pattern string
		request string
		want    bool
	}{
		{"dos comodines en comodin inicial mas subtree", "*.*", "identity.users.read", false},
		{"dos comodines intermedios", "identity.*.*.read", "identity.users.roles.read", false},
		{"comodin inicial mas subtree final", "*.users.*", "identity.users.read", false},
		{"comodin intermedio mas subtree final", "identity.*.read.*", "identity.users.read.detail", false},
		{"tres comodines", "*.*.*", "identity.users.read", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, rbac.PermissionMatches(tc.pattern, tc.request),
				"pattern=%q request=%q", tc.pattern, tc.request)
		})
	}
}

// TestEvaluateGrants_ZeroValueDefaultDeny fija el default deny del valor cero: un Grants{} —con
// ambos slices nil— niega cualquier request, incluido el vacío. Un deny sin allow tampoco concede
// nada: la ausencia de allow ya es una negación.
func TestEvaluateGrants_ZeroValueDefaultDeny(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		grants  rbac.Grants
		request string
		want    bool
	}{
		{"valor cero niega un request concreto", rbac.Grants{}, "identity.users.read", false},
		{"valor cero niega el request vacio", rbac.Grants{}, "", false},
		{"valor cero niega el request wildcard", rbac.Grants{}, "*", false},
		{
			name:    "solo deny sin allow niega un request no cubierto por el deny",
			grants:  rbac.Grants{Deny: []string{"identity.users.delete"}},
			request: "identity.users.read",
			want:    false,
		},
		{
			name:    "slices vacios no nil niegan igual que el valor cero",
			grants:  rbac.Grants{Allow: []string{}, Deny: []string{}},
			request: "identity.users.read",
			want:    false,
		},
		{
			name:    "un allow wildcard total tambien cubre el request vacio",
			grants:  rbac.Grants{Allow: []string{"*"}},
			request: "",
			want:    true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, rbac.EvaluateGrants(tc.grants, tc.request),
				"grants=%+v request=%q", tc.grants, tc.request)
		})
	}
}
