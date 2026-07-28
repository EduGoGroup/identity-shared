package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/EduGoGroup/identity-shared/auth"
	"github.com/EduGoGroup/identity-shared/auth/jwt"
)

const (
	kidPrimary   = "k-2026-07"
	kidSecondary = "k-2026-10"
	kidUnknown   = "k-nadie-lo-conoce"
)

// newSigner devuelve un Manager con el `kid` indicado y su clave pública, para poblar un
// MultiVerifier con varias claves a la vez.
func newSigner(t *testing.T, kid string) (*jwt.Manager, *ecdsa.PublicKey) {
	t.Helper()
	key := newSigningKey(t)
	manager, err := jwt.NewManager(key, testIssuer, kid)
	require.NoError(t, err)
	return manager, &key.PublicKey
}

// newIdentityToken emite un Identity Token vigente para testSystem.
func newIdentityToken(t *testing.T, manager *jwt.Manager) string {
	t.Helper()
	token, _, err := manager.GenerateIdentityToken(jwt.IdentityTokenInput{
		UserID: testUserID, System: testSystem, Email: testEmail, TokenVersion: 1, TTL: time.Hour,
	})
	require.NoError(t, err)
	return token
}

func TestNewMultiVerifier_RejectsInvalidInput(t *testing.T) {
	t.Parallel()

	nonP256, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	valid := &newSigningKey(t).PublicKey

	tests := []struct {
		name   string
		issuer string
		byKid  map[string]*ecdsa.PublicKey
	}{
		{name: "issuer vacío", issuer: "", byKid: map[string]*ecdsa.PublicKey{kidPrimary: valid}},
		{name: "mapa nil", issuer: testIssuer, byKid: nil},
		{name: "mapa vacío", issuer: testIssuer, byKid: map[string]*ecdsa.PublicKey{}},
		{name: "clave nil", issuer: testIssuer, byKid: map[string]*ecdsa.PublicKey{kidPrimary: nil}},
		{name: "kid vacío", issuer: testIssuer, byKid: map[string]*ecdsa.PublicKey{"": valid}},
		{
			name:   "clave de otra curva",
			issuer: testIssuer,
			byKid:  map[string]*ecdsa.PublicKey{kidPrimary: &nonP256.PublicKey},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mv, err := jwt.NewMultiVerifier(tc.issuer, tc.byKid)
			assert.Nil(t, mv)
			assert.ErrorIs(t, err, auth.ErrInvalidInput)
		})
	}
}

// TestMultiVerifier_SelectsVerifierByKid es el caso de uso que justifica la pieza: durante una
// rotación conviven dos claves y cada token se comprueba con la suya.
func TestMultiVerifier_SelectsVerifierByKid(t *testing.T) {
	t.Parallel()

	oldSigner, oldPublic := newSigner(t, kidPrimary)
	newSignerManager, newPublic := newSigner(t, kidSecondary)

	mv, err := jwt.NewMultiVerifier(testIssuer, map[string]*ecdsa.PublicKey{
		kidPrimary:   oldPublic,
		kidSecondary: newPublic,
	})
	require.NoError(t, err)

	assert.Equal(t, []string{kidPrimary, kidSecondary}, mv.Kids(), "Kids devuelve el conjunto ordenado")

	for name, manager := range map[string]*jwt.Manager{"clave vieja": oldSigner, "clave nueva": newSignerManager} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			claims, err := mv.ValidateIdentityToken(newIdentityToken(t, manager), testSystem)
			require.NoError(t, err)
			assert.Equal(t, testUserID, claims.Subject)
		})
	}
}

func TestMultiVerifier_ValidateServiceToken(t *testing.T) {
	t.Parallel()

	manager, public := newSigner(t, kidPrimary)
	mv, err := jwt.NewMultiVerifier(testIssuer, map[string]*ecdsa.PublicKey{kidPrimary: public})
	require.NoError(t, err)

	token, _, err := manager.GenerateServiceToken(jwt.ServiceTokenInput{
		ClientID: "reporting-worker", Audience: testAudience, Scopes: []string{"identity.*"}, TTL: time.Hour,
	})
	require.NoError(t, err)

	claims, err := mv.ValidateServiceToken(token, testAudience)
	require.NoError(t, err)
	assert.Equal(t, "reporting-worker", claims.ClientID)

	otherAudience, err := mv.ValidateServiceToken(token, "identity.otra-api")
	assert.Nil(t, otherAudience)
	assert.ErrorIs(t, err, auth.ErrInvalidToken)
}

// TestMultiVerifier_RejectsTokenWithoutKid: en este ecosistema no hay tokens legacy sin `kid` y no
// existe verificador «default», así que un token sin `kid` no tiene con qué comprobarse.
func TestMultiVerifier_RejectsTokenWithoutKid(t *testing.T) {
	t.Parallel()

	key := newSigningKey(t)
	mv, err := jwt.NewMultiVerifier(testIssuer, map[string]*ecdsa.PublicKey{kidPrimary: &key.PublicKey})
	require.NoError(t, err)

	// Firmado con la clave correcta y con claims impecables: lo único que falta es el `kid`.
	token := signCustom(t, gojwt.SigningMethodES256, key, "", validIdentityClaims())

	claims, err := mv.ValidateIdentityToken(token, testSystem)
	assert.Nil(t, claims)
	assert.ErrorIs(t, err, auth.ErrInvalidToken)
	assert.NotErrorIs(t, err, auth.ErrUnknownKid, "no es un kid desconocido: es que no hay kid")
}

func TestMultiVerifier_RejectsNonStringKid(t *testing.T) {
	t.Parallel()

	key := newSigningKey(t)
	mv, err := jwt.NewMultiVerifier(testIssuer, map[string]*ecdsa.PublicKey{kidPrimary: &key.PublicKey})
	require.NoError(t, err)

	token := gojwt.NewWithClaims(gojwt.SigningMethodES256, validIdentityClaims())
	token.Header["kid"] = 1234
	signed, err := token.SignedString(key)
	require.NoError(t, err)

	claims, err := mv.ValidateIdentityToken(signed, testSystem)
	assert.Nil(t, claims)
	assert.ErrorIs(t, err, auth.ErrInvalidToken)
}

func TestMultiVerifier_RejectsUnknownKid(t *testing.T) {
	t.Parallel()

	intruder, _ := newSigner(t, kidUnknown)
	_, public := newSigner(t, kidPrimary)

	mv, err := jwt.NewMultiVerifier(testIssuer, map[string]*ecdsa.PublicKey{kidPrimary: public})
	require.NoError(t, err)

	claims, err := mv.ValidateIdentityToken(newIdentityToken(t, intruder), testSystem)
	assert.Nil(t, claims)
	assert.ErrorIs(t, err, auth.ErrUnknownKid)
	assert.NotErrorIs(t, err, auth.ErrInvalidToken, "un kid desconocido se distingue de un token inválido")
}

// TestMultiVerifier_RejectsTokenSignedByAnotherKeyWithKnownKid comprueba que el `kid` selecciona una
// única clave y no se cae a las demás: el token declara un `kid` que existe, pero está firmado con
// otra clave del propio conjunto.
func TestMultiVerifier_RejectsTokenSignedByAnotherKeyWithKnownKid(t *testing.T) {
	t.Parallel()

	keyA := newSigningKey(t)
	keyB := newSigningKey(t)

	mv, err := jwt.NewMultiVerifier(testIssuer, map[string]*ecdsa.PublicKey{
		kidPrimary:   &keyA.PublicKey,
		kidSecondary: &keyB.PublicKey,
	})
	require.NoError(t, err)

	token := signCustom(t, gojwt.SigningMethodES256, keyB, kidPrimary, validIdentityClaims())

	claims, err := mv.ValidateIdentityToken(token, testSystem)
	assert.Nil(t, claims)
	assert.ErrorIs(t, err, auth.ErrInvalidToken)
}

func TestMultiVerifier_RejectsEmptyExpectedArguments(t *testing.T) {
	t.Parallel()

	manager, public := newSigner(t, kidPrimary)
	mv, err := jwt.NewMultiVerifier(testIssuer, map[string]*ecdsa.PublicKey{kidPrimary: public})
	require.NoError(t, err)

	claims, err := mv.ValidateIdentityToken(newIdentityToken(t, manager), "")
	assert.Nil(t, claims)
	assert.ErrorIs(t, err, auth.ErrInvalidInput)

	serviceClaims, err := mv.ValidateServiceToken(newIdentityToken(t, manager), "")
	assert.Nil(t, serviceClaims)
	assert.ErrorIs(t, err, auth.ErrInvalidInput)
}

// TestMultiVerifier_ConcurrentUse ejercita el verificador **en modo estático** desde varias
// goroutines a la vez: aquí el mapa de claves se escribe una sola vez, en el constructor, y a partir
// de ahí solo se lee.
//
// El caso que de verdad importa —el reemplazo del mapa en caliente— NO se prueba aquí, porque en
// este modo no ocurre nunca: está en TestMultiVerifierFromJWKS_ConcurrentRotation, que rota las
// claves del emisor mientras otras goroutines validan. Antes este comentario afirmaba cubrirlo y no
// lo hacía, así que su `-race` verde no decía nada de fetchAndSwap.
func TestMultiVerifier_ConcurrentUse(t *testing.T) {
	t.Parallel()

	signerA, publicA := newSigner(t, kidPrimary)
	signerB, publicB := newSigner(t, kidSecondary)
	intruder, _ := newSigner(t, kidUnknown)

	mv, err := jwt.NewMultiVerifier(testIssuer, map[string]*ecdsa.PublicKey{
		kidPrimary:   publicA,
		kidSecondary: publicB,
	})
	require.NoError(t, err)

	tokenA := newIdentityToken(t, signerA)
	tokenB := newIdentityToken(t, signerB)
	tokenUnknown := newIdentityToken(t, intruder)

	serviceToken, _, err := signerA.GenerateServiceToken(jwt.ServiceTokenInput{
		ClientID: "reporting-worker", Audience: testAudience, TTL: time.Hour,
	})
	require.NoError(t, err)

	const goroutines = 8
	const iterations = 25

	// Desde una goroutine secundaria solo se usan aserciones que NO abortan (assert, nunca require):
	// llamar a FailNow fuera de la goroutine del test es un uso incorrecto de testing.T.
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range iterations {
				_, errA := mv.ValidateIdentityToken(tokenA, testSystem)
				assert.NoError(t, errA)

				_, errB := mv.ValidateIdentityToken(tokenB, testSystem)
				assert.NoError(t, errB)

				_, errService := mv.ValidateServiceToken(serviceToken, testAudience)
				assert.NoError(t, errService)

				_, errUnknown := mv.ValidateIdentityToken(tokenUnknown, testSystem)
				assert.ErrorIs(t, errUnknown, auth.ErrUnknownKid)

				assert.Len(t, mv.Kids(), 2)
			}
		}()
	}
	wg.Wait()
}
