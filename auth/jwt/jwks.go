package jwt

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/EduGoGroup/identity-shared/auth"
)

const (
	// defaultJWKSCacheTTL es la edad máxima de la caché de claves antes de exigir un refetch.
	defaultJWKSCacheTTL = 15 * time.Minute

	// defaultJWKSRefetchCooldown es el mínimo entre dos refetch fuera de ciclo (los provocados por
	// un `kid` desconocido). Es un limitador de tasa: sin él, un atacante que presente tokens con
	// `kid` inventado convierte cada petición suya en una petición nuestra al emisor.
	defaultJWKSRefetchCooldown = time.Minute

	// defaultJWKSHTTPTimeout es el timeout del cliente HTTP que se construye cuando el consumidor no
	// aporta uno. Un cliente sin timeout puede colgar la verificación indefinidamente.
	defaultJWKSHTTPTimeout = 10 * time.Second

	// maxJWKSBodyBytes acota lo que se lee del endpoint. El JWKS de un emisor sano pesa menos de un
	// kilobyte; el límite existe para que un endpoint comprometido o roto no pueda agotar la memoria
	// del proceso que verifica.
	maxJWKSBodyBytes = 1 << 20

	// p256CoordinateBytes es el tamaño fijo de cada coordenada de un punto P-256 en un JWK
	// (RFC 7518 §6.2.1.2: octet string de longitud fija, sin recortar ceros a la izquierda).
	p256CoordinateBytes = 32

	// uncompressedPointPrefix es el octeto que encabeza un punto de curva elíptica en formato sin
	// comprimir (SEC 1 §2.3.3), la codificación que espera ecdh.Curve.NewPublicKey.
	uncompressedPointPrefix = 0x04

	jwksKeyTypeEC    = "EC"
	jwksCurveP256    = "P-256"
	jwksUseSignature = "sig"
)

// JWKSOptions configura de dónde y cada cuánto se obtiene el conjunto de claves públicas del emisor.
//
// URL es obligatoria y debe ser absoluta con esquema http o https. El resto tiene valores por
// defecto: HTTPClient nil usa un cliente propio con timeout de 10 s, CacheTTL <= 0 usa 15 minutos y
// RefetchCooldown <= 0 usa 1 minuto.
//
// Si aportas tu propio HTTPClient, dale un Timeout: la verificación se hace en línea con la petición
// que la necesita, y un cliente sin plazo la deja colgada.
type JWKSOptions struct {
	URL             string
	HTTPClient      *http.Client
	CacheTTL        time.Duration
	RefetchCooldown time.Duration
}

// jwksState es el estado mutable del modo JWKS de un MultiVerifier: la configuración resuelta más los
// instantes que gobiernan la política de refresco.
//
// fetchedAt y lastOutOfCycle se leen y escriben bajo el mutex del MultiVerifier. fetchMu es un candado
// aparte que serializa la petición HTTP en sí, para que N validaciones concurrentes con la caché
// vencida produzcan una sola petición al emisor y no N.
type jwksState struct {
	url             string
	client          *http.Client
	cacheTTL        time.Duration
	refetchCooldown time.Duration

	fetchMu sync.Mutex

	fetchedAt      time.Time
	lastOutOfCycle time.Time
}

// NewMultiVerifierFromJWKS construye un MultiVerifier que toma sus claves públicas de un endpoint
// JWKS (RFC 7517) y las mantiene al día.
//
// El constructor hace un primer fetch y falla si no puede completarlo: nunca nace un verificador con
// cero claves, porque un verificador vacío rechazaría todo token con auth.ErrUnknownKid y haría
// pasar una caída del emisor de claves por un problema de credenciales del cliente.
//
// La postura es fail-closed y tiene tres reglas:
//
//   - Si la caché está vencida (edad > CacheTTL), se refresca ANTES de verificar. Si ese refresco
//     falla, la validación devuelve un error que envuelve auth.ErrJWKSUnavailable. No se sirve caché
//     vencida: preferimos rechazar un token bueno a aceptar uno firmado con una clave ya retirada.
//   - Si el `kid` del token no está en una caché vigente, se intenta un refetch fuera de ciclo para
//     absorber una rotación de claves sin downtime, limitado a uno cada RefetchCooldown. Si el `kid`
//     sigue ausente después, la validación devuelve auth.ErrUnknownKid.
//   - Del documento JWKS solo se aceptan claves EC P-256 utilizables para firma. El resto se descarta
//     en silencio; si no queda ninguna, el resultado es auth.ErrJWKSUnavailable.
//
// Devuelve un error que envuelve auth.ErrInvalidInput si el issuer está vacío o la URL falta o no es
// absoluta http/https, y auth.ErrJWKSUnavailable si el primer fetch no produce claves utilizables.
func NewMultiVerifierFromJWKS(issuer string, opts JWKSOptions) (*MultiVerifier, error) {
	if err := requireArg("issuer", issuer); err != nil {
		return nil, err
	}

	state, err := newJWKSState(opts)
	if err != nil {
		return nil, err
	}

	mv := &MultiVerifier{
		issuer: issuer,
		byKid:  map[string]*Verifier{},
		jwks:   state,
	}
	if err := mv.forceRefresh(); err != nil {
		return nil, err
	}
	return mv, nil
}

// newJWKSState valida las opciones y aplica los valores por defecto.
func newJWKSState(opts JWKSOptions) (*jwksState, error) {
	if err := requireArg("opts.URL", opts.URL); err != nil {
		return nil, err
	}
	parsed, err := url.Parse(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("%w: opts.URL no es una URL válida: %w", auth.ErrInvalidInput, err)
	}
	if !parsed.IsAbs() || parsed.Host == "" {
		return nil, fmt.Errorf("%w: opts.URL debe ser una URL absoluta con host, y es %q", auth.ErrInvalidInput, opts.URL)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("%w: el esquema de opts.URL debe ser http o https, y es %q", auth.ErrInvalidInput, parsed.Scheme)
	}

	state := &jwksState{
		url:             opts.URL,
		client:          opts.HTTPClient,
		cacheTTL:        opts.CacheTTL,
		refetchCooldown: opts.RefetchCooldown,
	}
	if state.client == nil {
		state.client = &http.Client{Timeout: defaultJWKSHTTPTimeout}
	}
	if state.cacheTTL <= 0 {
		state.cacheTTL = defaultJWKSCacheTTL
	}
	if state.refetchCooldown <= 0 {
		state.refetchCooldown = defaultJWKSRefetchCooldown
	}
	return state, nil
}

// verifierFromJWKS resuelve el Verifier de un `kid` aplicando la política fail-closed descrita en
// NewMultiVerifierFromJWKS.
func (mv *MultiVerifier) verifierFromJWKS(kid string) (*Verifier, error) {
	refreshed := false
	if mv.cacheStale() {
		if err := mv.refreshIfStale(); err != nil {
			return nil, err
		}
		refreshed = true
	}

	if verifier := mv.lookup(kid); verifier != nil {
		return verifier, nil
	}

	// El `kid` no está y la caché es fresca: puede ser una rotación que aún no hemos visto. Un solo
	// intento por ventana de cooldown, y un fallo aquí NO es fail-closed —la caché sigue vigente— así
	// que el veredicto es «kid desconocido», no «JWKS inalcanzable».
	if !refreshed && mv.tryOutOfCycleRefresh() {
		if verifier := mv.lookup(kid); verifier != nil {
			return verifier, nil
		}
	}

	return nil, fmt.Errorf("%w: el kid %q no está en el JWKS de %s", auth.ErrUnknownKid, kid, mv.jwks.url)
}

// cacheStale reporta si la caché de claves superó su TTL.
func (mv *MultiVerifier) cacheStale() bool {
	mv.mu.RLock()
	defer mv.mu.RUnlock()
	return time.Since(mv.jwks.fetchedAt) > mv.jwks.cacheTTL
}

// refreshIfStale refresca la caché solo si sigue vencida tras ganar el turno de fetch. La segunda
// comprobación no es redundante: mientras esperábamos el turno, otra goroutine pudo refrescarla.
func (mv *MultiVerifier) refreshIfStale() error {
	mv.jwks.fetchMu.Lock()
	defer mv.jwks.fetchMu.Unlock()

	if !mv.cacheStale() {
		return nil
	}
	return mv.fetchAndSwap()
}

// forceRefresh refresca la caché sin mirar su edad. Lo usan el constructor y el refetch fuera de
// ciclo, que ya decidieron por su cuenta que toca pedir.
func (mv *MultiVerifier) forceRefresh() error {
	mv.jwks.fetchMu.Lock()
	defer mv.jwks.fetchMu.Unlock()
	return mv.fetchAndSwap()
}

// tryOutOfCycleRefresh intenta un refetch por `kid` desconocido y reporta si la caché quedó
// actualizada. Devuelve false si el limitador de tasa lo bloquea o si el fetch falla.
func (mv *MultiVerifier) tryOutOfCycleRefresh() bool {
	mv.mu.Lock()
	blocked := !mv.jwks.lastOutOfCycle.IsZero() && time.Since(mv.jwks.lastOutOfCycle) < mv.jwks.refetchCooldown
	if !blocked {
		mv.jwks.lastOutOfCycle = time.Now()
	}
	mv.mu.Unlock()

	if blocked {
		return false
	}
	return mv.forceRefresh() == nil
}

// fetchAndSwap pide el JWKS y reemplaza el mapa de verificadores. Debe llamarse con fetchMu tomado.
//
// El reemplazo es atómico desde fuera: o queda el conjunto nuevo completo, o queda el anterior
// intacto. Un fetch fallido no vacía la caché; quien decide si la caché vieja sirve es la política de
// vigencia, no el resultado de la última petición.
func (mv *MultiVerifier) fetchAndSwap() error {
	keys, err := fetchJWKS(mv.jwks.client, mv.jwks.url)
	if err != nil {
		return err
	}

	verifiers := make(map[string]*Verifier, len(keys))
	for kid, publicKey := range keys {
		verifier, verr := NewVerifier(publicKey, mv.issuer)
		if verr != nil {
			return fmt.Errorf("%w: la clave %q del JWKS de %s no es utilizable: %w", auth.ErrJWKSUnavailable, kid, mv.jwks.url, verr)
		}
		verifiers[kid] = verifier
	}

	mv.mu.Lock()
	mv.byKid = verifiers
	mv.jwks.fetchedAt = time.Now()
	mv.mu.Unlock()
	return nil
}

// jwksDocument es un JSON Web Key Set (RFC 7517 §5).
type jwksDocument struct {
	Keys []jwksKey `json:"keys"`
}

// jwksKey es una entrada del JWKS. Solo se declaran los campos que este módulo mira: los demás
// (`x5c`, `n`, `e`, `key_ops`…) se ignoran, como manda RFC 7517 §5 para los miembros no reconocidos.
type jwksKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// fetchJWKS obtiene el documento JWKS y devuelve las claves utilizables indexadas por `kid`.
//
// Todo fallo se devuelve envuelto en auth.ErrJWKSUnavailable, incluido el caso «respondió, pero no
// hay ni una clave que sirva»: para el verificador, un JWKS sin claves usables es indistinguible de
// no tener JWKS.
func fetchJWKS(client *http.Client, endpoint string) (map[string]*ecdsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: no se pudo construir la petición a %s: %w", auth.ErrJWKSUnavailable, endpoint, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: no se pudo consultar %s: %w", auth.ErrJWKSUnavailable, endpoint, err)
	}

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBodyBytes))
	if closeErr := resp.Body.Close(); closeErr != nil && readErr == nil {
		readErr = closeErr
	}
	if readErr != nil {
		return nil, fmt.Errorf("%w: no se pudo leer la respuesta de %s: %w", auth.ErrJWKSUnavailable, endpoint, readErr)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s respondió %d", auth.ErrJWKSUnavailable, endpoint, resp.StatusCode)
	}

	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%w: la respuesta de %s no es un JWKS válido: %w", auth.ErrJWKSUnavailable, endpoint, err)
	}

	keys := make(map[string]*ecdsa.PublicKey, len(doc.Keys))
	discarded := 0
	for i := range doc.Keys {
		entry := &doc.Keys[i]
		publicKey, ok := parseJWKSKey(entry)
		if !ok {
			discarded++
			continue
		}
		if _, duplicated := keys[entry.Kid]; duplicated {
			// Un JWKS con dos entradas para el mismo `kid` es ambiguo. Se conserva la primera en vez
			// de dejar que la última gane en silencio: así el conjunto resultante no depende del
			// orden del documento.
			discarded++
			continue
		}
		keys[entry.Kid] = publicKey
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: el JWKS de %s no trae ninguna clave EC P-256 utilizable (%d entradas descartadas)",
			auth.ErrJWKSUnavailable, endpoint, discarded)
	}
	return keys, nil
}

// parseJWKSKey reconstruye la clave pública de una entrada JWKS, o reporta ok=false si la entrada no
// sirve para verificar firmas ES256 en este ecosistema.
//
// Se descartan las entradas de otro tipo de clave o curva (un JWKS puede publicar claves RSA o de
// cifrado y eso no es un error), las de uso o algoritmo incompatibles, las que no traen `kid`, y las
// que declaran coordenadas mal codificadas, de tamaño incorrecto o que no caen sobre la curva.
//
// La comprobación del punto sobre la curva no es ceremonia: aceptar un punto fuera de la curva es lo
// que abre la puerta a los ataques de curva inválida, y en un JWKS las coordenadas las pone quien
// sirve el documento, no nosotros.
func parseJWKSKey(entry *jwksKey) (*ecdsa.PublicKey, bool) {
	if entry.Kty != jwksKeyTypeEC || entry.Crv != jwksCurveP256 {
		return nil, false
	}
	if entry.Use != "" && entry.Use != jwksUseSignature {
		return nil, false
	}
	if entry.Alg != "" && entry.Alg != signingAlg {
		return nil, false
	}
	if entry.Kid == "" {
		return nil, false
	}

	x, ok := decodeCoordinate(entry.X)
	if !ok {
		return nil, false
	}
	y, ok := decodeCoordinate(entry.Y)
	if !ok {
		return nil, false
	}

	// La comprobación se delega en crypto/ecdh: NewPublicKey exige el formato sin comprimir de
	// SEC 1 §2.3.3 (0x04 || X || Y), verifica que el punto caiga sobre P-256 y además rechaza el
	// punto al infinito. La vía clásica (elliptic.Curve.IsOnCurve) está deprecada desde Go 1.21 por
	// ser una API de bajo nivel insegura, y no descarta el punto al infinito.
	point := make([]byte, 0, 1+2*p256CoordinateBytes)
	point = append(point, uncompressedPointPrefix)
	point = append(point, x...)
	point = append(point, y...)
	if _, err := ecdh.P256().NewPublicKey(point); err != nil {
		return nil, false
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, true
}

// decodeCoordinate decodifica una coordenada de un JWK EC: base64url sin padding y exactamente
// p256CoordinateBytes bytes (RFC 7518 §6.2.1.2). Devuelve los octetos tal cual, sin normalizar, para
// poder rearmar el punto sin comprimir que espera crypto/ecdh.
func decodeCoordinate(encoded string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) != p256CoordinateBytes {
		return nil, false
	}
	return raw, true
}
