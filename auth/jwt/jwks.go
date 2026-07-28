package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
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

	// failureBackoff es lo que se espera antes de volver a llamar a un emisor que acaba de fallar.
	// Durante esa ventana, las validaciones que necesitan claves frescas reciben el error del último
	// intento sin generar tráfico nuevo. Es corto a propósito: alargarlo prolongaría la caída más allá
	// de lo que dura el problema del emisor.
	failureBackoff = 3 * time.Second

	// maxOutOfCycleRefetches es el presupuesto de refetches por `kid` desconocido dentro de una
	// ventana de RefetchCooldown. No es uno: con un solo turno por ventana, cualquiera que presente un
	// `kid` inventado deja sin refetch a la rotación de clave legítima que venga detrás.
	maxOutOfCycleRefetches = 5

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
// URL es obligatoria y debe ser absoluta. El esquema debe ser https, salvo contra loopback
// (`localhost`, 127.0.0.0/8, ::1), donde también vale http para desarrollo. El resto tiene valores
// por defecto: HTTPClient nil usa un cliente propio con timeout de 10 s, CacheTTL <= 0 usa 15
// minutos y RefetchCooldown <= 0 usa 1 minuto.
//
// Si aportas tu propio HTTPClient, dale un Timeout: la verificación se hace en línea con la petición
// que la necesita, y un cliente sin plazo la deja colgada.
type JWKSOptions struct {
	URL             string
	HTTPClient      *http.Client
	CacheTTL        time.Duration
	RefetchCooldown time.Duration
}

// jwksState es el estado mutable del modo JWKS de un MultiVerifier: la configuración resuelta más lo
// que gobierna la política de refresco.
//
// Todos los campos salvo fetchMu se leen y escriben bajo el mutex del MultiVerifier. fetchMu es un
// candado aparte que serializa la petición HTTP en sí, para que N validaciones concurrentes con la
// caché vencida produzcan una sola petición al emisor y no N.
type jwksState struct {
	url             string
	client          *http.Client
	cacheTTL        time.Duration
	refetchCooldown time.Duration

	fetchMu sync.Mutex

	// fetchedAt es el instante del último fetch CON ÉXITO: es lo que decide si la caché está vigente.
	fetchedAt time.Time

	// lastFailure y lastErr recuerdan el último intento fallido. Sin ellos, un emisor caído hace que
	// cada validación reintente por su cuenta: el fetchMu las pone en fila, pero no las colapsa, y N
	// validaciones acaban siendo N peticiones en serie contra un emisor que ya está en problemas.
	lastFailure time.Time
	lastErr     error

	// windowStart y outOfCycleCount son el presupuesto de refetches fuera de ciclo de la ventana en
	// curso; unknownKids recuerda por qué `kid` ya preguntamos dentro de ella.
	windowStart     time.Time
	outOfCycleCount int
	unknownKids     map[string]struct{}
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
//     Un fallo se recuerda durante unos segundos y se comparte con las validaciones que lleguen
//     mientras tanto, de modo que un emisor caído recibe una petición y no una por validación.
//   - Si el `kid` del token no está en una caché vigente, se intenta un refetch fuera de ciclo para
//     absorber una rotación de claves sin downtime. Está limitado por ventana de RefetchCooldown, y
//     dentro de la ventana no se repite la consulta por un `kid` que ya resultó desconocido. Si el
//     `kid` sigue ausente después, la validación devuelve auth.ErrUnknownKid.
//   - Del documento JWKS solo se aceptan claves EC P-256 utilizables para firma. El resto se descarta
//     en silencio; si no queda ninguna, el resultado es auth.ErrJWKSUnavailable.
//
// Devuelve un error que envuelve auth.ErrInvalidInput si el issuer está vacío, si la URL falta o no
// es absoluta http/https, o si es http contra un host que no es loopback; y auth.ErrJWKSUnavailable
// si el primer fetch no produce claves utilizables.
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

// isLoopbackHost reporta si el host de una URL es la máquina local.
//
// Cubre las dos formas en que aparece: una IP de loopback (127.0.0.0/8, ::1) y el nombre
// `localhost`, que no es una IP pero es lo que se escribe en la práctica.
func isLoopbackHost(hostname string) bool {
	if strings.EqualFold(hostname, "localhost") {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
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
	// El JWKS es el único punto sobre el que descansa «solo identity-core emite» (ADR-0002): quien
	// pueda servir ese documento sustituye el conjunto de claves entero y firma tokens que todos los
	// consumidores aceptan. Ni el `kid` obligatorio ni la comprobación del punto sobre la curva ayudan
	// ahí, porque los pone el atacante. Por eso `http` solo vale contra loopback, que es el caso de
	// desarrollo real; contra cualquier otro host se exige TLS.
	if parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
		return nil, fmt.Errorf("%w: opts.URL apunta a %q por http; fuera de loopback el JWKS se sirve por https",
			auth.ErrInvalidInput, parsed.Host)
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

	// El `kid` no está y la caché es fresca: puede ser una rotación que aún no hemos visto. Se intenta
	// un refetch dentro del presupuesto de la ventana, y un fallo aquí NO es fail-closed —la caché
	// sigue vigente— así que el veredicto es «kid desconocido», no «JWKS inalcanzable».
	if !refreshed && mv.tryOutOfCycleRefresh(kid) {
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

// recentFailure devuelve el error del último intento fallido si todavía está dentro de la ventana de
// backoff, o nil si toca reintentar.
func (mv *MultiVerifier) recentFailure() error {
	mv.mu.RLock()
	defer mv.mu.RUnlock()
	if mv.jwks.lastErr == nil || time.Since(mv.jwks.lastFailure) >= failureBackoff {
		return nil
	}
	return mv.jwks.lastErr
}

// refreshIfStale refresca la caché solo si hace falta, tras ganar el turno de fetch.
//
// Las dos comprobaciones que hay tras tomar fetchMu no son redundantes: mientras esperábamos el
// turno, otra goroutine pudo refrescar la caché (y entonces no hay nada que hacer) o pudo intentarlo
// y fallar (y entonces se comparte SU error en vez de repetir la petición). Sin esto último, un
// emisor colgado convierte N validaciones concurrentes en N peticiones en serie: el candado las
// ordena, pero cada una vuelve a ver la caché vencida y pide otra vez, y la última acaba esperando
// N veces el timeout del cliente.
func (mv *MultiVerifier) refreshIfStale() error {
	mv.jwks.fetchMu.Lock()
	defer mv.jwks.fetchMu.Unlock()

	if !mv.cacheStale() {
		return nil
	}
	if err := mv.recentFailure(); err != nil {
		return err
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
//
// El limitador tiene dos piezas y ninguna sobra:
//
//   - Memoria por `kid` dentro de la ventana. Repetir el mismo `kid` inexistente no vuelve a
//     preguntar: ya sabemos la respuesta. Esto es lo que hace que un atacante que machaca con un
//     `kid` inventado tenga coste cero para el emisor.
//   - Presupuesto de maxOutOfCycleRefetches peticiones por ventana, no una sola. Con una sola, el
//     primero que llegue —que puede ser justo ese `kid` basura— quema el turno de todos, y una
//     rotación de clave legítima se queda sin absorber hasta que expire la ventana. El presupuesto
//     deja pasar al `kid` nuevo de verdad sin abrir la puerta a una tormenta de refetch.
func (mv *MultiVerifier) tryOutOfCycleRefresh(kid string) bool {
	mv.mu.Lock()
	if time.Since(mv.jwks.windowStart) >= mv.jwks.refetchCooldown {
		mv.jwks.windowStart = time.Now()
		mv.jwks.outOfCycleCount = 0
		mv.jwks.unknownKids = make(map[string]struct{})
	}
	_, alreadyAsked := mv.jwks.unknownKids[kid]
	blocked := alreadyAsked || mv.jwks.outOfCycleCount >= maxOutOfCycleRefetches
	if !blocked {
		mv.jwks.outOfCycleCount++
		mv.jwks.unknownKids[kid] = struct{}{}
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
		mv.recordFailure(err)
		return err
	}

	verifiers := make(map[string]*Verifier, len(keys))
	for kid, publicKey := range keys {
		verifier, verr := NewVerifier(publicKey, mv.issuer)
		if verr != nil {
			err := fmt.Errorf("%w: la clave %q del JWKS de %s no es utilizable: %w", auth.ErrJWKSUnavailable, kid, mv.jwks.url, verr)
			mv.recordFailure(err)
			return err
		}
		verifiers[kid] = verifier
	}

	mv.mu.Lock()
	mv.byKid = verifiers
	mv.jwks.fetchedAt = time.Now()
	mv.jwks.lastErr = nil
	mv.jwks.lastFailure = time.Time{}
	mv.mu.Unlock()
	return nil
}

// recordFailure deja constancia de un intento fallido para que las validaciones que lleguen dentro
// de failureBackoff compartan este error en vez de volver a llamar al emisor.
func (mv *MultiVerifier) recordFailure(err error) {
	mv.mu.Lock()
	mv.jwks.lastErr = err
	mv.jwks.lastFailure = time.Now()
	mv.mu.Unlock()
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

	// El punto se rearma en formato sin comprimir (SEC 1 §2.3.3: 0x04 || X || Y) y se delega en
	// ecdsa.ParseUncompressedPublicKey, que en una sola llamada comprueba la codificación, que el
	// punto caiga sobre P-256 y que no sea el punto al infinito. Es la API que Go 1.26 pone en su
	// sitio: construir el ecdsa.PublicKey a mano quedó deprecado, y la vía clásica
	// (elliptic.Curve.IsOnCurve) lo estaba desde Go 1.21 por ser de bajo nivel y aceptar el infinito.
	point := make([]byte, 0, 1+2*p256CoordinateBytes)
	point = append(point, uncompressedPointPrefix)
	point = append(point, x...)
	point = append(point, y...)
	publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, false
	}
	return publicKey, true
}

// decodeCoordinate decodifica una coordenada de un JWK EC: base64url sin padding y exactamente
// p256CoordinateBytes bytes (RFC 7518 §6.2.1.2). Devuelve los octetos tal cual, sin normalizar, para
// poder rearmar el punto sin comprimir.
func decodeCoordinate(encoded string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) != p256CoordinateBytes {
		return nil, false
	}
	return raw, true
}
