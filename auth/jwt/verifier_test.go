package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/EduGoGroup/identity-shared/auth"
	"github.com/EduGoGroup/identity-shared/auth/jwt"
)

// otherSystem es un segundo sistema consumidor: existe para poder probar que un token emitido para
// uno no vale en el otro, que es la frontera que defiende ValidateIdentityToken.
const otherSystem = "edugo.admin-tools"

// newVerifierPair devuelve un Manager que firma y el Verifier que lo comprueba, con la misma clave,
// el mismo issuer y el mismo `kid`. Devuelve también la clave privada para poder forjar tokens que
// Manager nunca emitiría.
func newVerifierPair(t *testing.T) (*jwt.Manager, *jwt.Verifier, *ecdsa.PrivateKey) {
	t.Helper()
	key := newSigningKey(t)
	manager, err := jwt.NewManager(key, testIssuer, testKid)
	require.NoError(t, err)
	verifier, err := jwt.NewVerifier(&key.PublicKey, testIssuer)
	require.NoError(t, err)
	return manager, verifier, key
}

// signCustom firma unos claims arbitrarios con el método y la clave indicados. El header `kid` se
// escribe solo si `kid` no está vacío, para poder producir tokens sin `kid`.
//
// Es la vía deliberada para forjar tokens fuera de contrato (sin `exp`, con `aud` que no cuadra, con
// alg `none`, con HS256): probar el rechazo requiere producir lo que el emisor legítimo no produce.
func signCustom(t *testing.T, method gojwt.SigningMethod, key any, kid string, claims gojwt.Claims) string {
	t.Helper()
	token := gojwt.NewWithClaims(method, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

// validIdentityClaims devuelve los claims de un Identity Token correcto y vigente, listos para que
// cada test mute justo lo que quiere romper.
func validIdentityClaims() jwt.Claims {
	now := time.Now()
	return jwt.Claims{
		System:       testSystem,
		Email:        testEmail,
		TokenUse:     jwt.TokenUseIdentity,
		TokenVersion: 4,
		RegisteredClaims: gojwt.RegisteredClaims{
			ID:        "3f1a6b02-7c8d-4e9f-a0b1-c2d3e4f5a6b7",
			Issuer:    testIssuer,
			Subject:   testUserID,
			Audience:  gojwt.ClaimStrings{testSystem},
			IssuedAt:  gojwt.NewNumericDate(now),
			NotBefore: gojwt.NewNumericDate(now),
			ExpiresAt: gojwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
}

// validServiceClaims devuelve los claims de un token de servicio correcto y vigente.
func validServiceClaims() jwt.ServiceClaims {
	now := time.Now()
	return jwt.ServiceClaims{
		ClientID: "reporting-worker",
		Scopes:   []string{"identity.users.read"},
		TokenUse: jwt.TokenUseService,
		RegisteredClaims: gojwt.RegisteredClaims{
			ID:        "9c8b7a65-4321-4dcb-8a9f-0e1d2c3b4a59",
			Issuer:    testIssuer,
			Subject:   "service:reporting-worker",
			Audience:  gojwt.ClaimStrings{testAudience},
			IssuedAt:  gojwt.NewNumericDate(now),
			NotBefore: gojwt.NewNumericDate(now),
			ExpiresAt: gojwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
}

func TestNewVerifier_RejectsInvalidInput(t *testing.T) {
	t.Parallel()

	nonP256, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name   string
		key    *ecdsa.PublicKey
		issuer string
	}{
		{name: "clave nil", key: nil, issuer: testIssuer},
		{name: "curva distinta de P-256", key: &nonP256.PublicKey, issuer: testIssuer},
		{name: "issuer vacío", key: &newSigningKey(t).PublicKey, issuer: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			verifier, err := jwt.NewVerifier(tc.key, tc.issuer)
			assert.Nil(t, verifier)
			assert.ErrorIs(t, err, auth.ErrInvalidInput)
		})
	}
}

func TestVerifier_ValidateIdentityToken_RoundTrip(t *testing.T) {
	t.Parallel()
	manager, verifier, _ := newVerifierPair(t)

	token, expiresAt, err := manager.GenerateIdentityToken(jwt.IdentityTokenInput{
		UserID:       testUserID,
		System:       testSystem,
		Email:        testEmail,
		TokenVersion: 9,
		TTL:          time.Hour,
	})
	require.NoError(t, err)

	claims, err := verifier.ValidateIdentityToken(token, testSystem)
	require.NoError(t, err)

	assert.Equal(t, testSystem, claims.System)
	assert.Equal(t, testEmail, claims.Email)
	assert.Equal(t, jwt.TokenUseIdentity, claims.TokenUse)
	assert.Equal(t, int64(9), claims.TokenVersion)
	assert.Equal(t, testUserID, claims.Subject)
	assert.Equal(t, testIssuer, claims.Issuer)
	require.NotNil(t, claims.ExpiresAt)
	assert.WithinDuration(t, expiresAt, claims.ExpiresAt.Time, time.Second)
}

func TestVerifier_ValidateServiceToken_RoundTrip(t *testing.T) {
	t.Parallel()
	manager, verifier, _ := newVerifierPair(t)

	token, _, err := manager.GenerateServiceToken(jwt.ServiceTokenInput{
		ClientID: "reporting-worker",
		Audience: testAudience,
		Scopes:   []string{"identity.users.*"},
		TTL:      time.Hour,
	})
	require.NoError(t, err)

	claims, err := verifier.ValidateServiceToken(token, testAudience)
	require.NoError(t, err)

	assert.Equal(t, "reporting-worker", claims.ClientID)
	assert.Equal(t, jwt.TokenUseService, claims.TokenUse)
	assert.Equal(t, "service:reporting-worker", claims.Subject)
	assert.True(t, claims.HasScope("identity.users.create"))
}

func TestVerifier_RejectsEmptyExpectedArguments(t *testing.T) {
	t.Parallel()
	manager, verifier, _ := newVerifierPair(t)

	identityToken, _, err := manager.GenerateIdentityToken(jwt.IdentityTokenInput{
		UserID: testUserID, System: testSystem, Email: testEmail, TTL: time.Hour,
	})
	require.NoError(t, err)
	serviceToken, _, err := manager.GenerateServiceToken(jwt.ServiceTokenInput{
		ClientID: "reporting-worker", Audience: testAudience, TTL: time.Hour,
	})
	require.NoError(t, err)

	t.Run("expectedSystem vacío", func(t *testing.T) {
		t.Parallel()
		claims, err := verifier.ValidateIdentityToken(identityToken, "")
		assert.Nil(t, claims)
		assert.ErrorIs(t, err, auth.ErrInvalidInput)
	})

	t.Run("expectedAudience vacía", func(t *testing.T) {
		t.Parallel()
		claims, err := verifier.ValidateServiceToken(serviceToken, "")
		assert.Nil(t, claims)
		assert.ErrorIs(t, err, auth.ErrInvalidInput)
	})
}

func TestVerifier_ValidateIdentityToken_RejectsSystemMismatch(t *testing.T) {
	t.Parallel()
	manager, verifier, _ := newVerifierPair(t)

	token, _, err := manager.GenerateIdentityToken(jwt.IdentityTokenInput{
		UserID: testUserID, System: testSystem, Email: testEmail, TTL: time.Hour,
	})
	require.NoError(t, err)

	claims, err := verifier.ValidateIdentityToken(token, otherSystem)
	assert.Nil(t, claims)
	assert.ErrorIs(t, err, auth.ErrInvalidToken)
}

// TestVerifier_ValidateIdentityToken_RejectsAudienceMismatch aísla la comprobación de `aud` de la de
// `system`: el token forjado declara el sistema que el verificador espera, pero su audiencia sigue
// siendo otra. Sin la comprobación de `aud`, este token pasaría, y un token de un sistema podría
// reusarse en otro con solo mentir en el claim `system`.
func TestVerifier_ValidateIdentityToken_RejectsAudienceMismatch(t *testing.T) {
	t.Parallel()
	_, verifier, key := newVerifierPair(t)

	claims := validIdentityClaims()
	claims.System = otherSystem
	claims.Audience = gojwt.ClaimStrings{testSystem}
	token := signCustom(t, gojwt.SigningMethodES256, key, testKid, claims)

	got, err := verifier.ValidateIdentityToken(token, otherSystem)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, auth.ErrInvalidToken)
}

func TestVerifier_RejectsWrongTokenUse(t *testing.T) {
	t.Parallel()
	manager, verifier, _ := newVerifierPair(t)

	identityToken, _, err := manager.GenerateIdentityToken(jwt.IdentityTokenInput{
		UserID: testUserID, System: testSystem, Email: testEmail, TTL: time.Hour,
	})
	require.NoError(t, err)
	serviceToken, _, err := manager.GenerateServiceToken(jwt.ServiceTokenInput{
		ClientID: "reporting-worker", Audience: testSystem, TTL: time.Hour,
	})
	require.NoError(t, err)

	t.Run("un token de servicio no pasa por ValidateIdentityToken", func(t *testing.T) {
		t.Parallel()
		claims, err := verifier.ValidateIdentityToken(serviceToken, testSystem)
		assert.Nil(t, claims)
		assert.ErrorIs(t, err, auth.ErrInvalidToken)
	})

	t.Run("un Identity Token no pasa por ValidateServiceToken", func(t *testing.T) {
		t.Parallel()
		claims, err := verifier.ValidateServiceToken(identityToken, testSystem)
		assert.Nil(t, claims)
		assert.ErrorIs(t, err, auth.ErrInvalidToken)
	})
}

// TestVerifier_RejectsWrongTokenUseInIsolation aísla la comprobación de `token_use`: los tokens
// forjados aquí tienen el resto de claims impecable para el método que se invoca, así que lo único
// que puede rechazarlos es `token_use`.
//
// Sin esta versión aislada, el caso de arriba pasaría igual con la comprobación de `token_use`
// desactivada, porque un token de servicio también falla el `system` esperado. La comprobación
// importa por sí misma: es lo que impide que una credencial máquina-a-máquina se haga pasar por un
// usuario ante un servicio que solo mira `sub`.
func TestVerifier_RejectsWrongTokenUseInIsolation(t *testing.T) {
	t.Parallel()
	_, verifier, key := newVerifierPair(t)

	t.Run("identity", func(t *testing.T) {
		t.Parallel()
		for name, tokenUse := range map[string]string{
			"token_use de servicio": jwt.TokenUseService,
			"token_use ausente":     "",
			"token_use inventado":   "admin",
		} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				claims := validIdentityClaims()
				claims.TokenUse = tokenUse
				got, err := verifier.ValidateIdentityToken(signCustom(t, gojwt.SigningMethodES256, key, testKid, claims), testSystem)
				assert.Nil(t, got)
				assert.ErrorIs(t, err, auth.ErrInvalidToken)
			})
		}
	})

	t.Run("servicio", func(t *testing.T) {
		t.Parallel()
		for name, tokenUse := range map[string]string{
			"token_use de identity": jwt.TokenUseIdentity,
			"token_use ausente":     "",
			"token_use inventado":   "admin",
		} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				claims := validServiceClaims()
				claims.TokenUse = tokenUse
				got, err := verifier.ValidateServiceToken(signCustom(t, gojwt.SigningMethodES256, key, testKid, claims), testAudience)
				assert.Nil(t, got)
				assert.ErrorIs(t, err, auth.ErrInvalidToken)
			})
		}
	})
}

func TestVerifier_ValidateServiceToken_RejectsAudienceMismatch(t *testing.T) {
	t.Parallel()
	_, verifier, key := newVerifierPair(t)

	base := validServiceClaims()

	otherAudience := base
	otherAudience.Audience = gojwt.ClaimStrings{"identity.otra-api"}

	extraAudience := base
	extraAudience.Audience = gojwt.ClaimStrings{testAudience, "identity.otra-api"}

	emptyAudience := base
	emptyAudience.Audience = nil

	tests := map[string]jwt.ServiceClaims{
		"audiencia distinta":         otherAudience,
		"audiencia con una de más":   extraAudience,
		"token sin audiencia alguna": emptyAudience,
	}

	for name, claims := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			token := signCustom(t, gojwt.SigningMethodES256, key, testKid, claims)
			got, err := verifier.ValidateServiceToken(token, testAudience)
			assert.Nil(t, got)
			assert.ErrorIs(t, err, auth.ErrInvalidToken)
		})
	}
}

func TestVerifier_RejectsExpiredToken(t *testing.T) {
	t.Parallel()
	_, verifier, key := newVerifierPair(t)

	past := time.Now().Add(-2 * time.Hour)
	claims := validIdentityClaims()
	claims.IssuedAt = gojwt.NewNumericDate(past)
	claims.NotBefore = gojwt.NewNumericDate(past)
	claims.ExpiresAt = gojwt.NewNumericDate(past.Add(time.Minute))
	token := signCustom(t, gojwt.SigningMethodES256, key, testKid, claims)

	got, err := verifier.ValidateIdentityToken(token, testSystem)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, auth.ErrTokenExpired)
	assert.NotErrorIs(t, err, auth.ErrInvalidToken, "un token vencido es un caso distinto de un token inválido")
}

// TestVerifier_AcceptsTokenWithinClockLeeway comprueba el margen de tolerancia de reloj: un token que
// venció hace 10 s se sigue aceptando, porque la diferencia cabe en los 30 s de margen. Sin margen,
// una desviación mínima entre relojes rechazaría tokens legítimos.
func TestVerifier_AcceptsTokenWithinClockLeeway(t *testing.T) {
	t.Parallel()
	_, verifier, key := newVerifierPair(t)

	claims := validIdentityClaims()
	claims.ExpiresAt = gojwt.NewNumericDate(time.Now().Add(-10 * time.Second))
	token := signCustom(t, gojwt.SigningMethodES256, key, testKid, claims)

	got, err := verifier.ValidateIdentityToken(token, testSystem)
	require.NoError(t, err)
	assert.Equal(t, testSystem, got.System)
}

func TestVerifier_RejectsTokenWithoutExpiration(t *testing.T) {
	t.Parallel()
	_, verifier, key := newVerifierPair(t)

	claims := validIdentityClaims()
	claims.ExpiresAt = nil
	token := signCustom(t, gojwt.SigningMethodES256, key, testKid, claims)

	got, err := verifier.ValidateIdentityToken(token, testSystem)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, auth.ErrInvalidToken)
}

func TestVerifier_RejectsNotBeforeInTheFuture(t *testing.T) {
	t.Parallel()
	_, verifier, key := newVerifierPair(t)

	claims := validIdentityClaims()
	claims.NotBefore = gojwt.NewNumericDate(time.Now().Add(time.Hour))
	token := signCustom(t, gojwt.SigningMethodES256, key, testKid, claims)

	got, err := verifier.ValidateIdentityToken(token, testSystem)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, auth.ErrInvalidToken)
}

func TestVerifier_RejectsUnexpectedIssuer(t *testing.T) {
	t.Parallel()
	_, verifier, key := newVerifierPair(t)

	claims := validIdentityClaims()
	claims.Issuer = "otro-emisor"
	token := signCustom(t, gojwt.SigningMethodES256, key, testKid, claims)

	got, err := verifier.ValidateIdentityToken(token, testSystem)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, auth.ErrInvalidToken)
}

// TestVerifier_RejectsAlgNone cubre el ataque más viejo del formato: un token con alg `none` y sin
// firma. El parser solo admite ES256, así que ni llega a mirar la clave.
func TestVerifier_RejectsAlgNone(t *testing.T) {
	t.Parallel()
	_, verifier, _ := newVerifierPair(t)

	token := signCustom(t, gojwt.SigningMethodNone, gojwt.UnsafeAllowNoneSignatureType, testKid, validIdentityClaims())

	got, err := verifier.ValidateIdentityToken(token, testSystem)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, auth.ErrInvalidToken)
}

// TestVerifier_RejectsHS256 cubre la confusión de algoritmo: un atacante firma con HMAC usando como
// secreto algo que sí conoce (aquí, la propia clave pública del emisor, que es dato público) y espera
// que el verificador use ese material como secreto simétrico. Con la lista de métodos cerrada a
// ES256, el token no se llega a comprobar.
func TestVerifier_RejectsHS256(t *testing.T) {
	t.Parallel()
	_, verifier, key := newVerifierPair(t)

	tests := map[string][]byte{
		"secreto arbitrario": []byte("secreto-que-el-atacante-elige"),
		// El material de la clave pública es dato público: si el verificador lo usara como secreto
		// HMAC, cualquiera podría firmar tokens válidos.
		"clave pública usada como secreto": key.X.Bytes(),
	}

	for name, secret := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			token := signCustom(t, gojwt.SigningMethodHS256, secret, testKid, validIdentityClaims())
			got, err := verifier.ValidateIdentityToken(token, testSystem)
			assert.Nil(t, got)
			assert.ErrorIs(t, err, auth.ErrInvalidToken)
		})
	}
}

func TestVerifier_RejectsSignatureFromAnotherKey(t *testing.T) {
	t.Parallel()
	_, verifier, _ := newVerifierPair(t)

	intruder := newSigningKey(t)
	token := signCustom(t, gojwt.SigningMethodES256, intruder, testKid, validIdentityClaims())

	got, err := verifier.ValidateIdentityToken(token, testSystem)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, auth.ErrInvalidToken)
}

func TestVerifier_RejectsMalformedToken(t *testing.T) {
	t.Parallel()
	_, verifier, _ := newVerifierPair(t)

	tests := map[string]string{
		"cadena vacía":            "",
		"texto suelto":            "no-es-un-jwt",
		"tres segmentos basura":   "aaa.bbb.ccc",
		"solo dos segmentos":      "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJpZGVudGl0eSJ9",
		"firma truncada":          "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsifQ.eyJpc3MiOiJpZGVudGl0eSJ9.",
		"payload que no es JSON":  "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsifQ.bm8tanNvbg.YWFh",
		"header que no es base64": "!!!.eyJpc3MiOiJpZGVudGl0eSJ9.YWFh",
	}

	for name, tokenString := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := verifier.ValidateIdentityToken(tokenString, testSystem)
			assert.Nil(t, got)
			assert.ErrorIs(t, err, auth.ErrInvalidToken)
		})
	}
}

// TestVerifier_ExpiredTokenFromUntrustedIssuerIsInvalid: golang-jwt acumula todos los fallos de
// claims en un error unido, así que un token puede venir a la vez vencido y de un emisor en el que
// no confiamos. Clasificarlo como «expirado» es peligroso en el consumidor: el middleware que mapea
// ErrTokenExpired a «pide un refresh» trataría como caducidad rutinaria justo el caso que hay que
// mirar con lupa. Gana siempre la causa más grave.
func TestVerifier_ExpiredTokenFromUntrustedIssuerIsInvalid(t *testing.T) {
	t.Parallel()
	_, verifier, key := newVerifierPair(t)

	past := time.Now().Add(-2 * time.Hour)
	claims := validIdentityClaims()
	claims.Issuer = "emisor-en-el-que-no-confiamos"
	claims.IssuedAt = gojwt.NewNumericDate(past)
	claims.NotBefore = gojwt.NewNumericDate(past)
	claims.ExpiresAt = gojwt.NewNumericDate(past.Add(time.Minute))
	token := signCustom(t, gojwt.SigningMethodES256, key, testKid, claims)

	got, err := verifier.ValidateIdentityToken(token, testSystem)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, auth.ErrInvalidToken,
		"un emisor no confiable pesa más que una expiración, aunque el token traiga las dos cosas")
	assert.NotErrorIs(t, err, auth.ErrTokenExpired,
		"reportarlo como caducidad rutinaria escondería el problema de verdad")
}

// TestVerifier_ExpiredButOtherwiseValidTokenIsExpired es la contraparte del anterior: cuando la
// expiración es el ÚNICO defecto, el veredicto sigue siendo ErrTokenExpired. Sin este test, endurecer
// la clasificación podría acabar marcando como inválido cualquier token simplemente caducado, que es
// el caso rutinario y el que dispara el refresh.
func TestVerifier_ExpiredButOtherwiseValidTokenIsExpired(t *testing.T) {
	t.Parallel()
	_, verifier, key := newVerifierPair(t)

	past := time.Now().Add(-2 * time.Hour)
	claims := validIdentityClaims()
	claims.IssuedAt = gojwt.NewNumericDate(past)
	claims.NotBefore = gojwt.NewNumericDate(past)
	claims.ExpiresAt = gojwt.NewNumericDate(past.Add(time.Minute))
	token := signCustom(t, gojwt.SigningMethodES256, key, testKid, claims)

	got, err := verifier.ValidateIdentityToken(token, testSystem)
	assert.Nil(t, got)
	assert.ErrorIs(t, err, auth.ErrTokenExpired)
	assert.NotErrorIs(t, err, auth.ErrInvalidToken)
}

// TestVerifier_DoesNotValidateIssuedAt fija por test una decisión, no un descuido: `iat` no se
// comprueba. Validarlo (gojwt.WithIssuedAt) no aporta seguridad —`exp` y `nbf` ya acotan la ventana
// de uso, y el token va firmado, así que solo el emisor podría poner un `iat` raro— y sí añade un
// modo de fallo real: el emisor con el reloj adelantado más de clockLeeway dejaría de funcionar.
//
// Lo que este test protege es la honestidad del contrato: si algún día se decide validar `iat`, que
// sea un cambio consciente y documentado, no un efecto colateral.
func TestVerifier_DoesNotValidateIssuedAt(t *testing.T) {
	t.Parallel()
	_, verifier, key := newVerifierPair(t)

	claims := validIdentityClaims()
	claims.IssuedAt = gojwt.NewNumericDate(time.Now().AddDate(10, 0, 0))
	token := signCustom(t, gojwt.SigningMethodES256, key, testKid, claims)

	got, err := verifier.ValidateIdentityToken(token, testSystem)
	require.NoError(t, err, "iat es un dato informativo del emisor, no una comprobación del verificador")
	assert.Equal(t, testSystem, got.System)
}
