package password_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/EduGoGroup/identity-shared/auth"
	"github.com/EduGoGroup/identity-shared/auth/password"
)

// TestHashPassword_RoundTrip cubre el camino feliz: hashear y verificar con la contraseña correcta y
// con una incorrecta contra el mismo hash.
func TestHashPassword_RoundTrip(t *testing.T) {
	t.Parallel()

	hash, err := password.HashPassword("s3cr3t-p4ss")
	require.NoError(t, err)
	require.NotEmpty(t, hash)
	assert.NotEqual(t, "s3cr3t-p4ss", hash)

	assert.NoError(t, password.VerifyPassword(hash, "s3cr3t-p4ss"))

	err = password.VerifyPassword(hash, "password-incorrecto")
	require.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrPasswordMismatch)
}

// TestHashPassword_DifferentSaltPerCall cementa que dos hashes de la misma contraseña difieren (salt
// aleatorio) y que ambos verifican correctamente contra ella.
func TestHashPassword_DifferentSaltPerCall(t *testing.T) {
	t.Parallel()

	h1, err := password.HashPassword("misma-clave")
	require.NoError(t, err)
	h2, err := password.HashPassword("misma-clave")
	require.NoError(t, err)

	assert.NotEqual(t, h1, h2)
	assert.NoError(t, password.VerifyPassword(h1, "misma-clave"))
	assert.NoError(t, password.VerifyPassword(h2, "misma-clave"))
}

// TestVerifyPassword_HashNoVerificable cubre los casos donde no hay nada verificable contra qué
// comparar: un hash corrupto y un hash vacío. Ambos deben clasificar como auth.ErrInvalidInput, no
// como un simple desajuste de contraseña.
func TestVerifyPassword_HashNoVerificable(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"hash corrupto": "not-a-valid-bcrypt-hash",
		"hash vacío":    "",
	}

	for name, hash := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := password.VerifyPassword(hash, "cualquier-password")
			require.Error(t, err)
			assert.ErrorIs(t, err, auth.ErrInvalidInput)
			assert.NotErrorIs(t, err, auth.ErrPasswordMismatch)
		})
	}
}

// TestHashPassword_EmptyRejected cementa que una contraseña vacía se rechaza al hashear: las dos
// fuentes de las que parte este paquete la aceptaban felizmente, y aquí se cierra ese hueco.
func TestHashPassword_EmptyRejected(t *testing.T) {
	t.Parallel()

	_, err := password.HashPassword("")
	require.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrInvalidInput)
}

// TestHashPassword_LengthBoundary cementa el límite de bcrypt en bytes: 72 se acepta, 73 se rechaza.
func TestHashPassword_LengthBoundary(t *testing.T) {
	t.Parallel()

	t.Run("72 bytes se acepta", func(t *testing.T) {
		t.Parallel()

		pwd := strings.Repeat("a", 72)
		hash, err := password.HashPassword(pwd)
		require.NoError(t, err)
		assert.NoError(t, password.VerifyPassword(hash, pwd))
	})

	t.Run("73 bytes se rechaza", func(t *testing.T) {
		t.Parallel()

		_, err := password.HashPassword(strings.Repeat("a", 73))
		require.Error(t, err)
		assert.ErrorIs(t, err, auth.ErrInvalidInput)
	})
}

// TestHashPassword_MultibyteBoundary cementa que el límite de 72 es en BYTES, no en caracteres: una
// contraseña CJK que cabe en 72 bytes se acepta, y otra un carácter más larga —que ya no cabe— se
// rechaza, aunque ambas tengan pocos caracteres.
func TestHashPassword_MultibyteBoundary(t *testing.T) {
	t.Parallel()

	// "永" ocupa 3 bytes en UTF-8: 24 * 3 = 72 bytes exactos, 25 * 3 = 75 bytes.
	fits := strings.Repeat("永", 24)
	tooLong := strings.Repeat("永", 25)
	require.Len(t, fits, 72)
	require.Greater(t, len(tooLong), 72)

	hash, err := password.HashPassword(fits)
	require.NoError(t, err)
	assert.NoError(t, password.VerifyPassword(hash, fits))

	_, err = password.HashPassword(tooLong)
	require.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrInvalidInput)
}

// TestDefaultHasher_SatisfiesInterface cementa que *DefaultHasher implementa Hasher, y que sus
// métodos delegan correctamente en las funciones libres del paquete.
func TestDefaultHasher_SatisfiesInterface(t *testing.T) {
	t.Parallel()

	var h password.Hasher = password.NewHasher()

	hash, err := h.HashPassword("mi-clave")
	require.NoError(t, err)
	assert.True(t, h.CheckPasswordHash("mi-clave", hash))
	assert.False(t, h.CheckPasswordHash("clave-falsa", hash))
}

// TestHashPassword_Cost cementa el costo bcrypt en 12 leyendo el costo real embebido en el hash. Sin
// este test, el costo podría cambiarse sin que nada más falle: la constante es privada y no aparece
// en ninguna otra aserción.
func TestHashPassword_Cost(t *testing.T) {
	t.Parallel()

	hash, err := password.HashPassword("cualquier-clave")
	require.NoError(t, err)

	cost, err := bcrypt.Cost([]byte(hash))
	require.NoError(t, err)
	assert.Equal(t, 12, cost)
}

// TestVerifyPassword_ErrorsAreDistinguishable confirma que un desajuste de contraseña y un hash no
// verificable son distinguibles con errors.Is sin necesidad de importar bcrypt, y que no se solapan.
func TestVerifyPassword_ErrorsAreDistinguishable(t *testing.T) {
	t.Parallel()

	hash, err := password.HashPassword("clave-original")
	require.NoError(t, err)

	mismatchErr := password.VerifyPassword(hash, "clave-distinta")
	require.True(t, errors.Is(mismatchErr, auth.ErrPasswordMismatch))
	require.False(t, errors.Is(mismatchErr, auth.ErrInvalidInput))

	corruptErr := password.VerifyPassword("hash-corrupto", "clave-original")
	require.True(t, errors.Is(corruptErr, auth.ErrInvalidInput))
	require.False(t, errors.Is(corruptErr, auth.ErrPasswordMismatch))
}
