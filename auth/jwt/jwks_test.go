package jwt_test

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/EduGoGroup/identity-shared/auth"
	"github.com/EduGoGroup/identity-shared/auth/jwt"
)

// coordinateBytes es el tamaño fijo de una coordenada P-256 en un JWK (RFC 7518 §6.2.1.2).
const coordinateBytes = 32

// jwksEntry es una entrada de JWKS como mapa suelto, no como struct: los tests necesitan publicar
// entradas que el módulo debe descartar (RSA, otra curva, alg incompatible), y para eso hace falta
// poder escribir cualquier forma en el documento.
type jwksEntry map[string]any

// ecEntry construye una entrada JWKS válida para una clave pública P-256.
func ecEntry(kid string, publicKey *ecdsa.PublicKey) jwksEntry {
	x, y := pointCoordinates(publicKey)
	return jwksEntry{
		"kty": "EC",
		"crv": "P-256",
		"kid": kid,
		"use": "sig",
		"alg": "ES256",
		"x":   coordinate(x),
		"y":   coordinate(y),
	}
}

// pointCoordinates devuelve las coordenadas X e Y de una clave pública en octetos de longitud fija,
// que es la forma que exige RFC 7518 §6.2.1.2.
//
// Se leen del punto sin comprimir que expone PublicKey.Bytes (SEC 1 §2.3.3: 0x04 || X || Y) porque
// los campos X e Y del ecdsa.PublicKey quedaron deprecados en Go 1.26.
//
// Entra en pánico si la clave no es válida: esto es un helper de test y una clave inválida aquí es
// un error del propio test, no un caso que haya que cubrir.
func pointCoordinates(publicKey *ecdsa.PublicKey) (x, y []byte) {
	point, err := publicKey.Bytes()
	if err != nil {
		panic(fmt.Sprintf("clave pública de test inválida: %v", err))
	}
	half := (len(point) - 1) / 2
	return point[1 : 1+half], point[1+half:]
}

// coordinate codifica una coordenada como base64url SIN padding, que es lo que exige RFC 7517.
func coordinate(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

// jwksBody serializa un documento JWKS con las entradas dadas.
func jwksBody(t *testing.T, entries ...jwksEntry) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"keys": entries})
	require.NoError(t, err)
	return body
}

// jwksServer es un endpoint JWKS de prueba con cuerpo mutable y contador de peticiones. El contador es
// lo que permite comprobar la política de refetch: cuántas veces se pidió el JWKS, no solo qué se
// aceptó.
type jwksServer struct {
	server *httptest.Server
	hits   atomic.Int64

	mu     sync.Mutex
	body   []byte
	status int
}

func newJWKSServer(t *testing.T, body []byte) *jwksServer {
	t.Helper()
	js := &jwksServer{body: body, status: http.StatusOK}
	js.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		js.hits.Add(1)

		js.mu.Lock()
		status, payload := js.status, js.body
		js.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if _, err := w.Write(payload); err != nil {
			t.Errorf("no se pudo escribir la respuesta del JWKS de prueba: %v", err)
		}
	}))
	t.Cleanup(js.server.Close)
	return js
}

func (js *jwksServer) url() string { return js.server.URL + "/.well-known/jwks.json" }

func (js *jwksServer) setBody(body []byte) {
	js.mu.Lock()
	defer js.mu.Unlock()
	js.body = body
}

func (js *jwksServer) setStatus(status int) {
	js.mu.Lock()
	defer js.mu.Unlock()
	js.status = status
}

func TestNewMultiVerifierFromJWKS_ValidatesTokenWithFetchedKey(t *testing.T) {
	t.Parallel()

	manager, public := newSigner(t, kidPrimary)
	server := newJWKSServer(t, jwksBody(t, ecEntry(kidPrimary, public)))

	// HTTPClient nil a propósito: comprueba que el cliente por defecto (timeout de 10 s) funciona.
	mv, err := jwt.NewMultiVerifierFromJWKS(testIssuer, jwt.JWKSOptions{URL: server.url()})
	require.NoError(t, err)
	assert.Equal(t, []string{kidPrimary}, mv.Kids())
	assert.Equal(t, int64(1), server.hits.Load(), "el constructor hace exactamente un fetch")

	claims, err := mv.ValidateIdentityToken(newIdentityToken(t, manager), testSystem)
	require.NoError(t, err)
	assert.Equal(t, testUserID, claims.Subject)

	serviceToken, _, err := manager.GenerateServiceToken(jwt.ServiceTokenInput{
		ClientID: "reporting-worker", Audience: testAudience, TTL: time.Hour,
	})
	require.NoError(t, err)
	serviceClaims, err := mv.ValidateServiceToken(serviceToken, testAudience)
	require.NoError(t, err)
	assert.Equal(t, "reporting-worker", serviceClaims.ClientID)

	assert.Equal(t, int64(1), server.hits.Load(), "con la caché vigente no se vuelve a pedir el JWKS")
}

// TestNewMultiVerifierFromJWKS_IgnoresUnusableEntries: un JWKS puede publicar claves que no son para
// esto (RSA, otra curva, claves de cifrado). Esas entradas se descartan en silencio, no invalidan el
// documento: el emisor tiene derecho a publicar más de lo que este verificador entiende.
func TestNewMultiVerifierFromJWKS_IgnoresUnusableEntries(t *testing.T) {
	t.Parallel()

	manager, public := newSigner(t, kidPrimary)
	_, otherPublic := newSigner(t, kidSecondary)

	rsa := jwksEntry{
		"kty": "RSA",
		"kid": "rsa-1",
		"use": "sig",
		"alg": "RS256",
		"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":   "AQAB",
	}
	otherX, otherY := pointCoordinates(otherPublic)
	wrongCurve := jwksEntry{
		"kty": "EC",
		"crv": "P-384",
		"kid": "ec-p384",
		"x":   coordinate(otherX),
		"y":   coordinate(otherY),
	}
	wrongAlg := ecEntry("ec-rs256", otherPublic)
	wrongAlg["alg"] = "RS256"
	encryptionUse := ecEntry("ec-enc", otherPublic)
	encryptionUse["use"] = "enc"
	withoutKid := ecEntry("", otherPublic)
	badCoordinate := ecEntry("ec-x-corta", otherPublic)
	badCoordinate["x"] = coordinate([]byte{0x01, 0x02, 0x03})
	paddedCoordinate := ecEntry("ec-x-con-padding", otherPublic)
	paddedCoordinate["x"] = base64.URLEncoding.EncodeToString(otherX) + "=="

	server := newJWKSServer(t, jwksBody(t,
		rsa, wrongCurve, wrongAlg, encryptionUse, withoutKid, badCoordinate, paddedCoordinate,
		ecEntry(kidPrimary, public),
	))

	mv, err := jwt.NewMultiVerifierFromJWKS(testIssuer, jwt.JWKSOptions{
		URL:        server.url(),
		HTTPClient: server.server.Client(),
	})
	require.NoError(t, err)
	assert.Equal(t, []string{kidPrimary}, mv.Kids(), "solo sobrevive la clave EC P-256 utilizable")

	claims, err := mv.ValidateIdentityToken(newIdentityToken(t, manager), testSystem)
	require.NoError(t, err)
	assert.Equal(t, testEmail, claims.Email)
}

// TestNewMultiVerifierFromJWKS_DiscardsPointNotOnCurve: aceptar coordenadas que no caen sobre la curva
// es lo que habilita los ataques de curva inválida, y en un JWKS las pone quien sirve el documento.
func TestNewMultiVerifierFromJWKS_DiscardsPointNotOnCurve(t *testing.T) {
	t.Parallel()

	_, public := newSigner(t, kidPrimary)

	notOnCurve := ecEntry("ec-fuera-de-curva", public)
	x := make([]byte, coordinateBytes)
	y := make([]byte, coordinateBytes)
	for i := range x {
		x[i], y[i] = 0x01, 0x02
	}
	notOnCurve["x"], notOnCurve["y"] = coordinate(x), coordinate(y)

	t.Run("descartada cuando hay otra clave buena", func(t *testing.T) {
		t.Parallel()
		server := newJWKSServer(t, jwksBody(t, notOnCurve, ecEntry(kidPrimary, public)))
		mv, err := jwt.NewMultiVerifierFromJWKS(testIssuer, jwt.JWKSOptions{URL: server.url()})
		require.NoError(t, err)
		assert.Equal(t, []string{kidPrimary}, mv.Kids())
	})

	t.Run("sin claves usables el JWKS es inservible", func(t *testing.T) {
		t.Parallel()
		server := newJWKSServer(t, jwksBody(t, notOnCurve))
		mv, err := jwt.NewMultiVerifierFromJWKS(testIssuer, jwt.JWKSOptions{URL: server.url()})
		assert.Nil(t, mv)
		assert.ErrorIs(t, err, auth.ErrJWKSUnavailable)
	})
}

func TestNewMultiVerifierFromJWKS_NoUsableKeys(t *testing.T) {
	t.Parallel()

	_, public := newSigner(t, kidPrimary)
	onlyRSA := jwksEntry{"kty": "RSA", "kid": "rsa-1", "n": "AQAB", "e": "AQAB"}
	duplicated := jwksBody(t, ecEntry(kidPrimary, public), ecEntry(kidPrimary, public))

	tests := map[string][]byte{
		"documento sin claves":     jwksBody(t),
		"solo claves RSA":          jwksBody(t, onlyRSA),
		"objeto sin campo keys":    []byte(`{"otra-cosa": []}`),
		"respuesta que no es JSON": []byte("<html>error</html>"),
		"keys con tipo incorrecto": []byte(`{"keys": "no-es-una-lista"}`),
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := newJWKSServer(t, body)
			mv, err := jwt.NewMultiVerifierFromJWKS(testIssuer, jwt.JWKSOptions{URL: server.url()})
			assert.Nil(t, mv)
			assert.ErrorIs(t, err, auth.ErrJWKSUnavailable)
		})
	}

	// Un `kid` duplicado no invalida el documento: se conserva la primera entrada y la segunda se
	// descarta, para que el conjunto no dependa del orden en que el emisor las serialice.
	t.Run("kid duplicado conserva una sola entrada", func(t *testing.T) {
		t.Parallel()
		server := newJWKSServer(t, duplicated)
		mv, err := jwt.NewMultiVerifierFromJWKS(testIssuer, jwt.JWKSOptions{URL: server.url()})
		require.NoError(t, err)
		assert.Equal(t, []string{kidPrimary}, mv.Kids())
	})
}

// TestNewMultiVerifierFromJWKS_FailsOnHTTPError: el constructor no puede nacer sin claves. Si naciera
// vacío, cada token se rechazaría con ErrUnknownKid y una caída del emisor de claves se leería como
// «credencial mala» en lugar de «no puedo verificar».
func TestNewMultiVerifierFromJWKS_FailsOnHTTPError(t *testing.T) {
	t.Parallel()

	_, public := newSigner(t, kidPrimary)
	server := newJWKSServer(t, jwksBody(t, ecEntry(kidPrimary, public)))
	server.setStatus(http.StatusInternalServerError)

	mv, err := jwt.NewMultiVerifierFromJWKS(testIssuer, jwt.JWKSOptions{URL: server.url()})
	assert.Nil(t, mv)
	assert.ErrorIs(t, err, auth.ErrJWKSUnavailable)
}

func TestNewMultiVerifierFromJWKS_FailsWhenEndpointIsDown(t *testing.T) {
	t.Parallel()

	_, public := newSigner(t, kidPrimary)
	server := newJWKSServer(t, jwksBody(t, ecEntry(kidPrimary, public)))
	url := server.url()
	server.server.Close()

	mv, err := jwt.NewMultiVerifierFromJWKS(testIssuer, jwt.JWKSOptions{URL: url})
	assert.Nil(t, mv)
	assert.ErrorIs(t, err, auth.ErrJWKSUnavailable)
}

func TestNewMultiVerifierFromJWKS_RejectsInvalidOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		issuer string
		url    string
	}{
		{name: "issuer vacío", issuer: "", url: "https://identity.example/jwks.json"},
		{name: "URL vacía", issuer: testIssuer, url: ""},
		{name: "URL relativa", issuer: testIssuer, url: "/.well-known/jwks.json"},
		{name: "URL sin host", issuer: testIssuer, url: "https:///jwks.json"},
		{name: "esquema no http", issuer: testIssuer, url: "ftp://identity.example/jwks.json"},
		{name: "esquema file", issuer: testIssuer, url: "file:///etc/jwks.json"},
		{name: "URL sin parsear", issuer: testIssuer, url: "http://[::1]:puerto/jwks"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mv, err := jwt.NewMultiVerifierFromJWKS(tc.issuer, jwt.JWKSOptions{URL: tc.url})
			assert.Nil(t, mv)
			assert.ErrorIs(t, err, auth.ErrInvalidInput)
		})
	}
}

// TestMultiVerifierFromJWKS_RefetchesOnRotation es el caso «rotación sin downtime»: el proceso arrancó
// conociendo solo la clave vieja, el emisor ya firma con la nueva, y la primera validación con un
// `kid` que no tenemos dispara un refetch fuera de ciclo que la trae.
func TestMultiVerifierFromJWKS_RefetchesOnRotation(t *testing.T) {
	t.Parallel()

	_, oldPublic := newSigner(t, kidPrimary)
	newManager, newPublic := newSigner(t, kidSecondary)

	server := newJWKSServer(t, jwksBody(t, ecEntry(kidPrimary, oldPublic)))
	mv, err := jwt.NewMultiVerifierFromJWKS(testIssuer, jwt.JWKSOptions{URL: server.url()})
	require.NoError(t, err)
	require.Equal(t, []string{kidPrimary}, mv.Kids())

	// El emisor rota: ahora publica las dos claves.
	server.setBody(jwksBody(t, ecEntry(kidPrimary, oldPublic), ecEntry(kidSecondary, newPublic)))

	claims, err := mv.ValidateIdentityToken(newIdentityToken(t, newManager), testSystem)
	require.NoError(t, err)
	assert.Equal(t, testUserID, claims.Subject)

	assert.Equal(t, []string{kidPrimary, kidSecondary}, mv.Kids())
	assert.Equal(t, int64(2), server.hits.Load(), "un fetch del constructor y un refetch por el kid nuevo")
}

// TestMultiVerifierFromJWKS_RateLimitsRefetchOnUnknownKid: el refetch por `kid` desconocido es una
// puerta que abre un tercero, así que va con limitador. Sin él, un atacante que presente tokens con
// `kid` inventado convierte cada petición suya en una petición nuestra al emisor.
func TestMultiVerifierFromJWKS_RateLimitsRefetchOnUnknownKid(t *testing.T) {
	t.Parallel()

	_, public := newSigner(t, kidPrimary)
	intruder, _ := newSigner(t, kidUnknown)

	server := newJWKSServer(t, jwksBody(t, ecEntry(kidPrimary, public)))
	mv, err := jwt.NewMultiVerifierFromJWKS(testIssuer, jwt.JWKSOptions{
		URL:             server.url(),
		CacheTTL:        time.Hour,
		RefetchCooldown: time.Hour,
	})
	require.NoError(t, err)

	token := newIdentityToken(t, intruder)
	for range 2 {
		claims, err := mv.ValidateIdentityToken(token, testSystem)
		assert.Nil(t, claims)
		assert.ErrorIs(t, err, auth.ErrUnknownKid)
	}

	assert.Equal(t, int64(2), server.hits.Load(),
		"el constructor pide una vez y el kid desconocido provoca UN solo refetch, no uno por intento")
}

// TestMultiVerifierFromJWKS_FailsClosedWithExpiredCache es la prueba de la postura fail-closed: con la
// caché vencida y el emisor caído, un token perfectamente firmado NO se acepta. Servir claves vencidas
// sería aceptar tokens firmados con una clave que el emisor pudo haber retirado justamente porque
// estaba comprometida.
func TestMultiVerifierFromJWKS_FailsClosedWithExpiredCache(t *testing.T) {
	t.Parallel()

	manager, public := newSigner(t, kidPrimary)
	server := newJWKSServer(t, jwksBody(t, ecEntry(kidPrimary, public)))

	mv, err := jwt.NewMultiVerifierFromJWKS(testIssuer, jwt.JWKSOptions{
		URL:      server.url(),
		CacheTTL: time.Nanosecond,
	})
	require.NoError(t, err)

	token := newIdentityToken(t, manager)
	claims, err := mv.ValidateIdentityToken(token, testSystem)
	require.NoError(t, err, "con el emisor en pie, el token es válido")
	require.NotNil(t, claims)

	server.server.Close()

	claims, err = mv.ValidateIdentityToken(token, testSystem)
	assert.Nil(t, claims, "el mismo token, ahora sin claves frescas, no se acepta")
	assert.ErrorIs(t, err, auth.ErrJWKSUnavailable)
	assert.NotErrorIs(t, err, auth.ErrUnknownKid, "no es culpa del token: es que no hay con qué verificar")
}

// TestMultiVerifierFromJWKS_RefreshesExpiredCache cubre el otro lado del TTL: cuando la caché vence y
// el emisor sí responde, el refresco entra antes de verificar y trae el conjunto vigente.
func TestMultiVerifierFromJWKS_RefreshesExpiredCache(t *testing.T) {
	t.Parallel()

	_, oldPublic := newSigner(t, kidPrimary)
	newManager, newPublic := newSigner(t, kidSecondary)

	server := newJWKSServer(t, jwksBody(t, ecEntry(kidPrimary, oldPublic)))
	mv, err := jwt.NewMultiVerifierFromJWKS(testIssuer, jwt.JWKSOptions{
		URL:      server.url(),
		CacheTTL: 10 * time.Millisecond,
	})
	require.NoError(t, err)

	// El emisor retira la clave vieja y publica solo la nueva.
	server.setBody(jwksBody(t, ecEntry(kidSecondary, newPublic)))
	time.Sleep(20 * time.Millisecond)

	claims, err := mv.ValidateIdentityToken(newIdentityToken(t, newManager), testSystem)
	require.NoError(t, err)
	assert.Equal(t, testUserID, claims.Subject)
	assert.Equal(t, []string{kidSecondary}, mv.Kids(), "la clave retirada desaparece del conjunto")
}

// TestMultiVerifierFromJWKS_ConcurrentValidationSharesOneRefetch: con la caché vencida y varias
// goroutines validando a la vez, el refresco se serializa y produce una sola petición, no una por
// goroutine.
func TestMultiVerifierFromJWKS_ConcurrentValidationSharesOneRefetch(t *testing.T) {
	t.Parallel()

	manager, public := newSigner(t, kidPrimary)
	server := newJWKSServer(t, jwksBody(t, ecEntry(kidPrimary, public)))

	mv, err := jwt.NewMultiVerifierFromJWKS(testIssuer, jwt.JWKSOptions{
		URL:      server.url(),
		CacheTTL: 30 * time.Millisecond,
	})
	require.NoError(t, err)

	token := newIdentityToken(t, manager)
	time.Sleep(40 * time.Millisecond)

	var wg sync.WaitGroup
	wg.Add(8)
	for range 8 {
		go func() {
			defer wg.Done()
			_, err := mv.ValidateIdentityToken(token, testSystem)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()

	assert.LessOrEqual(t, server.hits.Load(), int64(2),
		"un fetch del constructor y como mucho un refresco compartido por las 8 goroutines")
}
