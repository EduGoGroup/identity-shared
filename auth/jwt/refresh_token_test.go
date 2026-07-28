package jwt_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/EduGoGroup/identity-shared/auth"
	"github.com/EduGoGroup/identity-shared/auth/jwt"
)

func TestGenerateRefreshToken_Shape(t *testing.T) {
	t.Parallel()

	before := time.Now()
	rt, err := jwt.GenerateRefreshToken(24 * time.Hour)
	require.NoError(t, err)
	require.NotNil(t, rt)

	assert.True(t, strings.HasPrefix(rt.Token, jwt.RefreshTokenPrefix), "el token debe llevar el prefijo rft_")

	entropy, err := base64.URLEncoding.DecodeString(strings.TrimPrefix(rt.Token, jwt.RefreshTokenPrefix))
	require.NoError(t, err, "el cuerpo del token es base64 URL-safe")
	assert.Len(t, entropy, 32, "256 bits de entropía")

	assert.Equal(t, jwt.HashRefreshToken(rt.Token), rt.TokenHash)
	assert.Len(t, rt.TokenHash, 64, "SHA-256 en hex son 64 caracteres")
	assert.NotEqual(t, rt.Token, rt.TokenHash)
	assert.WithinDuration(t, before.Add(24*time.Hour), rt.ExpiresAt, 5*time.Second)
}

func TestGenerateRefreshToken_IsUniquePerCall(t *testing.T) {
	t.Parallel()

	first, err := jwt.GenerateRefreshToken(time.Hour)
	require.NoError(t, err)
	second, err := jwt.GenerateRefreshToken(time.Hour)
	require.NoError(t, err)

	assert.NotEqual(t, first.Token, second.Token)
	assert.NotEqual(t, first.TokenHash, second.TokenHash)
}

func TestGenerateRefreshToken_RejectsNonPositiveTTL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ttl  time.Duration
	}{
		{name: "ttl cero", ttl: 0},
		{name: "ttl negativo", ttl: -time.Hour},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rt, err := jwt.GenerateRefreshToken(tc.ttl)
			assert.Nil(t, rt, "no debe emitirse una credencial ya vencida")
			assert.ErrorIs(t, err, auth.ErrInvalidInput)
		})
	}
}

// TestHashRefreshToken_HashesThePrefixedString cementa QUÉ se hashea: la cadena completa, prefijo
// incluido. Si alguien recortara el prefijo antes de hashear, todos los hashes ya persistidos
// dejarían de coincidir y cada sesión viva quedaría invalidada.
func TestHashRefreshToken_HashesThePrefixedString(t *testing.T) {
	t.Parallel()

	rt, err := jwt.GenerateRefreshToken(time.Hour)
	require.NoError(t, err)

	withPrefix := sha256.Sum256([]byte(rt.Token))
	assert.Equal(t, hex.EncodeToString(withPrefix[:]), rt.TokenHash)

	withoutPrefix := sha256.Sum256([]byte(strings.TrimPrefix(rt.Token, jwt.RefreshTokenPrefix)))
	assert.NotEqual(t, hex.EncodeToString(withoutPrefix[:]), rt.TokenHash,
		"el hash del cuerpo sin prefijo NO es el hash persistido")
}

func TestHashRefreshToken_IsDeterministic(t *testing.T) {
	t.Parallel()

	const sample = "rft_abc"

	hash := jwt.HashRefreshToken(sample)
	assert.Equal(t, hash, jwt.HashRefreshToken(sample))
	assert.NotEqual(t, hash, jwt.HashRefreshToken("rft_abd"))
	assert.Len(t, hash, 64)
	assert.Equal(t, strings.ToLower(hash), hash, "hex en minúscula")
}
