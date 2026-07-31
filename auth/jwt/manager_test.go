package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/EduGoGroup/identity-shared/auth"
	"github.com/EduGoGroup/identity-shared/auth/jwt"
)

const (
	testIssuer   = "identity"
	testKid      = "k-2026-07"
	testSystem   = "edugo.kmp"
	testEmail    = "persona@example.com"
	testUserID   = "8f2b1c34-5d6e-4a7b-8c9d-0e1f2a3b4c5d"
	testAudience = "identity.api"
	// testEcosystem es la clave NATURAL de un ecosistema (`edugo`), no la namespaced de una
	// aplicación (`edugo.kmp`): son dos vocabularios distintos y el claim lleva el primero.
	testEcosystem = "edugo"
)

// newSigningKey genera una clave ECDSA P-256 de prueba.
func newSigningKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// newTestManager devuelve un Manager listo para firmar y la clave pública con la que verificarlo.
//
// Los tests de este frente NO usan Verifier ni MultiVerifier a propósito: parsean con
// golang-jwt directamente, para que la emisión quede probada contra la especificación JWT y no
// contra otra pieza de este mismo módulo (un error simétrico en emisión y verificación pasaría
// desapercibido si ambas se probaran entre sí).
func newTestManager(t *testing.T) (*jwt.Manager, *ecdsa.PublicKey) {
	t.Helper()
	key := newSigningKey(t)
	m, err := jwt.NewManager(key, testIssuer, testKid)
	require.NoError(t, err)
	return m, &key.PublicKey
}

// parseIdentity verifica la firma de un Identity Token con la clave pública y devuelve sus claims.
func parseIdentity(t *testing.T, tokenString string, pub *ecdsa.PublicKey) *jwt.Claims {
	t.Helper()
	claims := &jwt.Claims{}
	parser := gojwt.NewParser(gojwt.WithValidMethods([]string{"ES256"}), gojwt.WithExpirationRequired())
	token, err := parser.ParseWithClaims(tokenString, claims, func(*gojwt.Token) (any, error) {
		return pub, nil
	})
	require.NoError(t, err)
	require.True(t, token.Valid)
	return claims
}

// parseService verifica la firma de un token de servicio y devuelve sus claims.
func parseService(t *testing.T, tokenString string, pub *ecdsa.PublicKey) *jwt.ServiceClaims {
	t.Helper()
	claims := &jwt.ServiceClaims{}
	parser := gojwt.NewParser(gojwt.WithValidMethods([]string{"ES256"}), gojwt.WithExpirationRequired())
	token, err := parser.ParseWithClaims(tokenString, claims, func(*gojwt.Token) (any, error) {
		return pub, nil
	})
	require.NoError(t, err)
	require.True(t, token.Valid)
	return claims
}

// decodeSegment decodifica el segmento `index` de un JWS compacto (0 = header, 1 = payload) como
// mapa crudo, sin pasar por los structs del paquete. Es la única forma de comprobar qué hay
// realmente en el cable en lugar de qué creemos que pusimos.
func decodeSegment(t *testing.T, tokenString string, index int) map[string]any {
	t.Helper()
	parts := strings.Split(tokenString, ".")
	require.Len(t, parts, 3, "un JWS compacto tiene tres segmentos")

	raw, err := base64.RawURLEncoding.DecodeString(parts[index])
	require.NoError(t, err)

	out := map[string]any{}
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func TestNewManager_RejectsInvalidInput(t *testing.T) {
	t.Parallel()

	nonP256, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name   string
		key    *ecdsa.PrivateKey
		issuer string
		kid    string
	}{
		{name: "clave nil", key: nil, issuer: testIssuer, kid: testKid},
		{name: "issuer vacío", key: newSigningKey(t), issuer: "", kid: testKid},
		{name: "kid vacío", key: newSigningKey(t), issuer: testIssuer, kid: ""},
		{name: "curva distinta de P-256", key: nonP256, issuer: testIssuer, kid: testKid},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, err := jwt.NewManager(tc.key, tc.issuer, tc.kid)
			assert.Nil(t, m)
			assert.ErrorIs(t, err, auth.ErrInvalidInput)
		})
	}
}

func TestNewManager_ExposesKid(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager(t)
	assert.Equal(t, testKid, m.Kid())
}

func TestManager_GenerateIdentityToken_RoundTrip(t *testing.T) {
	t.Parallel()
	m, pub := newTestManager(t)

	before := time.Now()
	token, expiresAt, err := m.GenerateIdentityToken(jwt.IdentityTokenInput{
		UserID:       testUserID,
		System:       testSystem,
		Email:        testEmail,
		TokenVersion: 7,
		TTL:          time.Hour,
	})
	require.NoError(t, err)
	require.NotEmpty(t, token)
	assert.WithinDuration(t, before.Add(time.Hour), expiresAt, 5*time.Second)

	claims := parseIdentity(t, token, pub)

	assert.Equal(t, testSystem, claims.System)
	assert.Equal(t, testEmail, claims.Email)
	assert.Equal(t, jwt.TokenUseIdentity, claims.TokenUse)
	assert.Equal(t, int64(7), claims.TokenVersion)

	assert.Equal(t, testIssuer, claims.Issuer)
	assert.Equal(t, testUserID, claims.Subject, "sub lleva el UserID en plano, sin prefijo")
	assert.Equal(t, gojwt.ClaimStrings{testSystem}, claims.Audience)
	assert.NotEmpty(t, claims.ID, "jti debe venir siempre")

	require.NotNil(t, claims.IssuedAt)
	require.NotNil(t, claims.NotBefore)
	require.NotNil(t, claims.ExpiresAt)
	assert.WithinDuration(t, before, claims.IssuedAt.Time, 5*time.Second)
	assert.WithinDuration(t, before, claims.NotBefore.Time, 5*time.Second)
	assert.WithinDuration(t, expiresAt, claims.ExpiresAt.Time, time.Second)
}

func TestManager_GenerateIdentityToken_JTIIsUniquePerToken(t *testing.T) {
	t.Parallel()
	m, pub := newTestManager(t)

	in := jwt.IdentityTokenInput{UserID: testUserID, System: testSystem, Email: testEmail, TTL: time.Hour}
	first, _, err := m.GenerateIdentityToken(in)
	require.NoError(t, err)
	second, _, err := m.GenerateIdentityToken(in)
	require.NoError(t, err)

	assert.NotEqual(t, parseIdentity(t, first, pub).ID, parseIdentity(t, second, pub).ID)
}

func TestManager_GenerateIdentityToken_RejectsInvalidInput(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager(t)

	valid := jwt.IdentityTokenInput{UserID: testUserID, System: testSystem, Email: testEmail, TTL: time.Hour}

	tests := []struct {
		name  string
		mutar func(in *jwt.IdentityTokenInput)
	}{
		{name: "UserID vacío", mutar: func(in *jwt.IdentityTokenInput) { in.UserID = "" }},
		{name: "System vacío", mutar: func(in *jwt.IdentityTokenInput) { in.System = "" }},
		{name: "Email vacío", mutar: func(in *jwt.IdentityTokenInput) { in.Email = "" }},
		{name: "TTL por debajo del minuto", mutar: func(in *jwt.IdentityTokenInput) { in.TTL = time.Second }},
		{name: "TTL cero", mutar: func(in *jwt.IdentityTokenInput) { in.TTL = 0 }},
		{name: "TokenVersion negativa", mutar: func(in *jwt.IdentityTokenInput) { in.TokenVersion = -1 }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := valid
			tc.mutar(&in)

			token, expiresAt, err := m.GenerateIdentityToken(in)
			assert.ErrorIs(t, err, auth.ErrInvalidInput)
			assert.Empty(t, token)
			assert.True(t, expiresAt.IsZero())
		})
	}
}

func TestManager_GenerateServiceToken_RoundTrip(t *testing.T) {
	t.Parallel()
	m, pub := newTestManager(t)

	scopes := []string{"identity.users.*", "identity.sessions.read"}
	before := time.Now()
	token, expiresAt, err := m.GenerateServiceToken(jwt.ServiceTokenInput{
		ClientID:     "reporting-worker",
		Audience:     testAudience,
		EcosystemKey: testEcosystem,
		Scopes:       scopes,
		TTL:          30 * time.Minute,
	})
	require.NoError(t, err)
	require.NotEmpty(t, token)
	assert.WithinDuration(t, before.Add(30*time.Minute), expiresAt, 5*time.Second)

	claims := parseService(t, token, pub)

	assert.Equal(t, "reporting-worker", claims.ClientID)
	assert.Equal(t, scopes, claims.Scopes)
	assert.Equal(t, jwt.TokenUseService, claims.TokenUse)
	assert.Equal(t, testEcosystem, claims.EcosystemKey, "el ecosistema viaja en su claim propio")
	assert.NotContains(t, claims.Audience, testEcosystem, "el ecosistema NO se mete en aud: son dos ejes")
	assert.Equal(t, "service:reporting-worker", claims.Subject)
	assert.Equal(t, gojwt.ClaimStrings{testAudience}, claims.Audience)
	assert.Equal(t, testIssuer, claims.Issuer)
	assert.NotEmpty(t, claims.ID)
	require.NotNil(t, claims.NotBefore)
	require.NotNil(t, claims.ExpiresAt)
	assert.WithinDuration(t, before, claims.NotBefore.Time, 5*time.Second)
	assert.WithinDuration(t, expiresAt, claims.ExpiresAt.Time, time.Second)

	assert.True(t, claims.HasScope("identity.users.create"), "el scope glob debe cubrir el verbo")
}

func TestManager_GenerateServiceToken_RejectsInvalidInput(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager(t)

	valid := jwt.ServiceTokenInput{ClientID: "reporting-worker", Audience: testAudience, EcosystemKey: testEcosystem, TTL: time.Hour}

	tests := []struct {
		name  string
		mutar func(in *jwt.ServiceTokenInput)
	}{
		{name: "ClientID vacío", mutar: func(in *jwt.ServiceTokenInput) { in.ClientID = "" }},
		{name: "Audience vacía", mutar: func(in *jwt.ServiceTokenInput) { in.Audience = "" }},
		// Sin ecosistema NO se emite. Es la mitad de emisión de la garantía que el verificador
		// cierra por el otro lado: un token de servicio que no dice de parte de quién viene no es
		// un token con un campo menos, es un token que no autoriza nada en destino.
		{name: "EcosystemKey vacía", mutar: func(in *jwt.ServiceTokenInput) { in.EcosystemKey = "" }},
		{name: "TTL por debajo del minuto", mutar: func(in *jwt.ServiceTokenInput) { in.TTL = time.Second }},
		{name: "TTL cero", mutar: func(in *jwt.ServiceTokenInput) { in.TTL = 0 }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := valid
			tc.mutar(&in)

			token, expiresAt, err := m.GenerateServiceToken(in)
			assert.ErrorIs(t, err, auth.ErrInvalidInput)
			assert.Empty(t, token)
			assert.True(t, expiresAt.IsZero())
		})
	}
}

func TestManager_SignedTokensCarryKidAndES256Header(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager(t)

	identityToken, _, err := m.GenerateIdentityToken(jwt.IdentityTokenInput{
		UserID: testUserID, System: testSystem, Email: testEmail, TTL: time.Hour,
	})
	require.NoError(t, err)

	serviceToken, _, err := m.GenerateServiceToken(jwt.ServiceTokenInput{
		ClientID: "reporting-worker", Audience: testAudience, EcosystemKey: testEcosystem, TTL: time.Hour,
	})
	require.NoError(t, err)

	for name, tokenString := range map[string]string{"identity": identityToken, "service": serviceToken} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			header := decodeSegment(t, tokenString, 0)
			assert.Equal(t, testKid, header["kid"], "el kid es obligatorio en el header")
			assert.Equal(t, "ES256", header["alg"])
		})
	}
}

// TestManager_PayloadCarriesNoBusinessClaims es la red de seguridad de la frontera del módulo: si
// alguien añade un claim de negocio a Claims o a ServiceClaims, este test lo caza en el cable, que
// es donde el daño sería permanente (los tokens ya emitidos no se pueden reescribir).
func TestManager_PayloadCarriesNoBusinessClaims(t *testing.T) {
	t.Parallel()
	m, _ := newTestManager(t)

	identityToken, _, err := m.GenerateIdentityToken(jwt.IdentityTokenInput{
		UserID: testUserID, System: testSystem, Email: testEmail, TokenVersion: 3, TTL: time.Hour,
	})
	require.NoError(t, err)

	serviceToken, _, err := m.GenerateServiceToken(jwt.ServiceTokenInput{
		ClientID: "reporting-worker", Audience: testAudience, EcosystemKey: testEcosystem, Scopes: []string{"identity.users.read"}, TTL: time.Hour,
	})
	require.NoError(t, err)

	forbidden := []string{"tenant_id", "roles", "grants"}

	t.Run("identity", func(t *testing.T) {
		t.Parallel()
		payload := decodeSegment(t, identityToken, 1)
		for _, key := range forbidden {
			assert.NotContains(t, payload, key)
		}
		assert.ElementsMatch(t,
			[]string{"system", "email", "token_use", "token_version", "iss", "sub", "aud", "jti", "iat", "nbf", "exp"},
			mapKeys(payload),
			"la lista de claims del Identity Token es cerrada",
		)
	})

	t.Run("service", func(t *testing.T) {
		t.Parallel()
		payload := decodeSegment(t, serviceToken, 1)
		for _, key := range forbidden {
			assert.NotContains(t, payload, key)
		}
		assert.ElementsMatch(t,
			[]string{"client_id", "scopes", "token_use", "ecosystem_key", "iss", "sub", "aud", "jti", "iat", "nbf", "exp"},
			mapKeys(payload),
			"la lista de claims del token de servicio es cerrada",
		)
		// El NOMBRE del claim en el cable es contrato: lo leen verificadores de otros lenguajes
		// que no comparten este struct. Se afirma el literal, no el campo de Go.
		assert.Equal(t, testEcosystem, payload["ecosystem_key"])
	})
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
