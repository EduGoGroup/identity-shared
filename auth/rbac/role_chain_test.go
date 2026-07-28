package rbac_test

import (
	"errors"
	"testing"

	"github.com/EduGoGroup/identity-shared/auth/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parentOfMap construye un parentOf de prueba a partir de un mapa hijo→padre. Un rol ausente del
// mapa se considera canónico: se reporta ok=false y la cadena termina en él.
func parentOfMap(links map[string]string) func(string) (string, bool, error) {
	return func(id string) (string, bool, error) {
		parent, ok := links[id]
		return parent, ok, nil
	}
}

// TestResolveRoleChain recorre la caminata de herencia en todas sus formas de terminación: rol
// canónico, herencia simple, profundidad N, corte por padre vacío y corte por ciclo.
func TestResolveRoleChain(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		root  string
		links map[string]string
		want  []string
	}{
		{
			name:  "rol canonico sin padre devuelve solo a si mismo",
			root:  "super_admin",
			links: nil,
			want:  []string{"super_admin"},
		},
		{
			name:  "herencia simple de un nivel",
			root:  "platform_support",
			links: map[string]string{"platform_support": "super_admin"},
			want:  []string{"platform_support", "super_admin"},
		},
		{
			name: "profundidad N ordenada de mas cercano a mas lejano",
			root: "role_a",
			links: map[string]string{
				"role_a": "role_b",
				"role_b": "role_c",
				"role_c": "role_d",
			},
			want: []string{"role_a", "role_b", "role_c", "role_d"},
		},
		{
			name: "un padre ausente del mapa corta la cadena en el ultimo eslabon conocido",
			root: "role_a",
			links: map[string]string{
				"role_a": "platform_support",
			},
			want: []string{"role_a", "platform_support"},
		},
		{
			name:  "rootID vacio devuelve una cadena vacia",
			root:  "",
			links: map[string]string{"role_a": "role_b"},
			want:  []string{},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			chain, err := rbac.ResolveRoleChain(tc.root, parentOfMap(tc.links))
			require.NoError(t, err)
			assert.Equal(t, tc.want, chain)
		})
	}
}

// TestResolveRoleChain_EmptyParentStopsChain fija que ok=true con parent vacío equivale a «sin
// padre»: la cadena termina sin agregar un eslabón vacío.
func TestResolveRoleChain_EmptyParentStopsChain(t *testing.T) {
	t.Parallel()

	chain, err := rbac.ResolveRoleChain("role_a", func(string) (string, bool, error) {
		return "", true, nil // ok=true pero parent vacío
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"role_a"}, chain)
}

// TestResolveRoleChain_CycleGuardTruncatesWithoutError fija la decisión congelada del guard de
// ciclos: ante datos corruptos (role_a→role_b→role_a) la caminata corta y devuelve la cadena
// truncada con err=nil. No hay loop infinito y no hay error: los eslabones acumulados son válidos.
func TestResolveRoleChain_CycleGuardTruncatesWithoutError(t *testing.T) {
	t.Parallel()

	t.Run("ciclo de dos eslabones", func(t *testing.T) {
		t.Parallel()
		chain, err := rbac.ResolveRoleChain("role_a", parentOfMap(map[string]string{
			"role_a": "role_b",
			"role_b": "role_a",
		}))
		require.NoError(t, err)
		assert.Equal(t, []string{"role_a", "role_b"}, chain)
	})

	t.Run("ciclo mas largo conserva los eslabones visitados una sola vez", func(t *testing.T) {
		t.Parallel()
		chain, err := rbac.ResolveRoleChain("role_a", parentOfMap(map[string]string{
			"role_a": "role_b",
			"role_b": "role_c",
			"role_c": "role_a",
		}))
		require.NoError(t, err)
		assert.Equal(t, []string{"role_a", "role_b", "role_c"}, chain)
	})

	t.Run("autociclo del propio rol raiz", func(t *testing.T) {
		t.Parallel()
		chain, err := rbac.ResolveRoleChain("role_a", parentOfMap(map[string]string{
			"role_a": "role_a",
		}))
		require.NoError(t, err)
		assert.Equal(t, []string{"role_a"}, chain)
	})
}

// TestResolveRoleChain_PropagatesError fija que un fallo del callback se propaga tal cual y descarta
// la cadena entera: un error de lectura no es una jerarquía terminada.
func TestResolveRoleChain_PropagatesError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("fallo de lectura del almacenamiento de roles")

	t.Run("falla en el primer eslabon", func(t *testing.T) {
		t.Parallel()
		chain, err := rbac.ResolveRoleChain("role_a", func(string) (string, bool, error) {
			return "", false, sentinel
		})
		require.ErrorIs(t, err, sentinel)
		assert.Nil(t, chain, "ante error la cadena se descarta por completo")
	})

	t.Run("falla en un eslabon intermedio", func(t *testing.T) {
		t.Parallel()
		chain, err := rbac.ResolveRoleChain("role_a", func(id string) (string, bool, error) {
			if id == "role_a" {
				return "role_b", true, nil
			}
			return "", false, sentinel
		})
		require.ErrorIs(t, err, sentinel)
		assert.Nil(t, chain, "ante error no se devuelve una cadena parcial")
	})
}

// TestMergeGrantChain_Union verifica que la unión de varios niveles produce un único Grants plano con
// todos los allow y todos los deny combinados, y que el resultado se comporta como se espera al
// evaluarlo: el deny del hijo gana sobre el allow del ancestro (precedencia resuelta en
// EvaluateGrants, no en el aplanado).
func TestMergeGrantChain_Union(t *testing.T) {
	t.Parallel()

	ancestor := rbac.Grants{
		Allow: []string{"identity.users.*", "identity.credentials.*"},
		Deny:  []string{},
	}
	child := rbac.Grants{
		Allow: []string{"identity.audit.read"},
		Deny:  []string{"*.delete"},
	}

	merged := rbac.MergeGrantChain([]rbac.Grants{ancestor, child})

	assert.Equal(t, rbac.Grants{
		Allow: []string{"identity.users.*", "identity.credentials.*", "identity.audit.read"},
		Deny:  []string{"*.delete"},
	}, merged)

	assert.True(t, rbac.EvaluateGrants(merged, "identity.users.create"), "allow del ancestro aplica")
	assert.True(t, rbac.EvaluateGrants(merged, "identity.audit.read"), "allow del hijo aplica")
	assert.False(t, rbac.EvaluateGrants(merged, "identity.users.delete"), "deny del hijo gana sobre el allow del ancestro")
}

// TestMergeGrantChain_DedupPreservesFirstAppearanceOrder verifica que un pattern repetido entre
// niveles aparece una sola vez y en la posición de su primera aparición. El orden es parte del
// contrato: la aserción es sobre slices exactos, no sobre conjuntos.
func TestMergeGrantChain_DedupPreservesFirstAppearanceOrder(t *testing.T) {
	t.Parallel()

	ancestor := rbac.Grants{
		Allow: []string{"identity.users.*", "identity.audit.read"},
		Deny:  []string{"*.delete"},
	}
	child := rbac.Grants{
		Allow: []string{"identity.audit.read", "identity.roles.*"}, // identity.audit.read duplicado
		Deny:  []string{"*.delete", "*.update"},                    // *.delete duplicado
	}

	merged := rbac.MergeGrantChain([]rbac.Grants{ancestor, child})

	assert.Equal(t, []string{"identity.users.*", "identity.audit.read", "identity.roles.*"}, merged.Allow)
	assert.Equal(t, []string{"*.delete", "*.update"}, merged.Deny)
}

// TestMergeGrantChain_NeverReturnsNilSlices fija la decisión congelada del wire format: Allow y Deny
// son siempre slices no-nil para que la serialización emita `[]` y nunca `null`, incluso cuando la
// cadena es nil, está vacía, o sus miembros traen campos nil.
func TestMergeGrantChain_NeverReturnsNilSlices(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		chain []rbac.Grants
	}{
		{"cadena nil", nil},
		{"cadena vacia", []rbac.Grants{}},
		{"cadena con un Grants valor cero", []rbac.Grants{{}}},
		{"cadena con miembros de campos nil", []rbac.Grants{{Allow: nil, Deny: nil}, {}}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			merged := rbac.MergeGrantChain(tc.chain)
			require.NotNil(t, merged.Allow, "Allow nunca debe ser nil")
			require.NotNil(t, merged.Deny, "Deny nunca debe ser nil")
			assert.Empty(t, merged.Allow)
			assert.Empty(t, merged.Deny)
		})
	}
}

// TestMergeGrantChain_SingleLevelIsIdentity verifica que un solo nivel se funde en sí mismo: el
// aplanado no reordena ni descarta patterns, ni siquiera cuando un deny cubre un allow del mismo
// nivel (eso lo resuelve EvaluateGrants al evaluar cada request).
func TestMergeGrantChain_SingleLevelIsIdentity(t *testing.T) {
	t.Parallel()

	single := rbac.Grants{
		Allow: []string{"identity.users.*", "identity.sessions.read"},
		Deny:  []string{"identity.users.delete"},
	}

	merged := rbac.MergeGrantChain([]rbac.Grants{single})

	assert.Equal(t, single, merged)
	assert.False(t, rbac.EvaluateGrants(merged, "identity.users.delete"),
		"el aplanado conserva el allow amplio y el deny puntual; la precedencia se aplica al evaluar")
}
