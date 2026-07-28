package jwt_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/EduGoGroup/identity-shared/auth/jwt"
)

// TestTokenUseValues fija los valores literales de `token_use`. Son contrato en el cable: los
// verifican también los clientes de otros lenguajes, así que un cambio aquí rompe tokens vivos.
func TestTokenUseValues(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "identity", jwt.TokenUseIdentity)
	assert.Equal(t, "service", jwt.TokenUseService)
}

func TestServiceClaims_HasScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		scopes   []string
		required string
		want     bool
	}{
		{
			name:     "coincidencia exacta",
			scopes:   []string{"identity.users.create"},
			required: "identity.users.create",
			want:     true,
		},
		{
			name:     "glob de subárbol cubre el verbo",
			scopes:   []string{"identity.users.*"},
			required: "identity.users.create",
			want:     true,
		},
		{
			name:     "glob de subárbol cubre el propio prefijo",
			scopes:   []string{"identity.users.*"},
			required: "identity.users",
			want:     true,
		},
		{
			name:     "glob total cubre cualquier permiso",
			scopes:   []string{"*"},
			required: "identity.sessions.revoke",
			want:     true,
		},
		{
			name:     "glob de sufijo cubre el verbo en cualquier recurso",
			scopes:   []string{"*.read"},
			required: "identity.users.read",
			want:     true,
		},
		{
			name:     "evalúa todos los scopes, no solo el primero",
			scopes:   []string{"billing.read", "identity.users.*"},
			required: "identity.users.delete",
			want:     true,
		},
		{
			name:     "otro subárbol no cubre",
			scopes:   []string{"identity.sessions.*"},
			required: "identity.users.create",
			want:     false,
		},
		{
			name:     "el glob no se extiende hacia arriba",
			scopes:   []string{"identity.users.*"},
			required: "identity.sessions.create",
			want:     false,
		},
		{
			name:     "sin scopes no autoriza nada",
			scopes:   nil,
			required: "identity.users.create",
			want:     false,
		},
		{
			name:     "scope pedido vacío no autoriza, ni con glob total",
			scopes:   []string{"*"},
			required: "",
			want:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			claims := &jwt.ServiceClaims{Scopes: tc.scopes}
			assert.Equal(t, tc.want, claims.HasScope(tc.required))
		})
	}
}

func TestServiceClaims_HasScope_NilReceiver(t *testing.T) {
	t.Parallel()

	var claims *jwt.ServiceClaims
	assert.NotPanics(t, func() {
		assert.False(t, claims.HasScope("identity.users.create"))
		assert.False(t, claims.HasScope(""))
	})
}
