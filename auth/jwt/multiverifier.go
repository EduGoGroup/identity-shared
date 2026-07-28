package jwt

import (
	"crypto/ecdsa"
	"fmt"
	"maps"
	"slices"
	"sync"

	gojwt "github.com/golang-jwt/jwt/v5"

	"github.com/EduGoGroup/identity-shared/auth"
)

// MultiVerifier valida tokens frente a varias claves públicas, seleccionando la correcta por el
// header `kid` del token.
//
// Es la pieza que hace posible rotar la clave de firma sin cortar el servicio: durante la rotación
// conviven la clave vieja y la nueva, y cada token se comprueba con la que le corresponde. El `kid`
// es obligatorio y la selección es exacta: un `kid` desconocido devuelve auth.ErrUnknownKid y NO se
// prueba ninguna otra clave. Probar todas las claves conocidas ante un `kid` que no cuadra convierte
// el `kid` en un adorno y regala al atacante un oráculo de firmas.
//
// No existe verificador «default» para tokens sin `kid`: en este ecosistema no hay tokens legacy que
// justificarlo, y un default es precisamente el hueco por el que entra un token sin identificar.
//
// Un MultiVerifier es seguro para uso concurrente. El mapa de claves se protege con un RWMutex
// porque en modo JWKS (ver NewMultiVerifierFromJWKS) se reemplaza en caliente.
type MultiVerifier struct {
	issuer string

	mu    sync.RWMutex
	byKid map[string]*Verifier

	// jwks es nil en el modo estático (NewMultiVerifier) y no nil cuando las claves vienen de un
	// endpoint remoto. Su presencia es lo que activa el refresco y la política fail-closed.
	jwks *jwksState
}

// NewMultiVerifier construye un verificador multi-clave a partir de un mapa `kid` → clave pública.
//
// El mapa debe traer al menos una entrada, ningún `kid` vacío y ninguna clave nil; el issuer es
// obligatorio. Cualquier incumplimiento devuelve un error que envuelve auth.ErrInvalidInput. Se
// construye un Verifier por entrada, así que las claves también deben ser de la curva P-256.
//
// El mapa recibido no se retiene: las claves se copian a la estructura interna, de modo que
// mutarlo después no altera al verificador.
func NewMultiVerifier(issuer string, byKid map[string]*ecdsa.PublicKey) (*MultiVerifier, error) {
	if err := requireArg("issuer", issuer); err != nil {
		return nil, err
	}
	if len(byKid) == 0 {
		return nil, fmt.Errorf("%w: byKid debe traer al menos una clave", auth.ErrInvalidInput)
	}

	// Las entradas se recorren en orden determinista a propósito: con el orden aleatorio del mapa,
	// dos entradas inválidas producirían mensajes de error distintos en ejecuciones distintas.
	verifiers := make(map[string]*Verifier, len(byKid))
	for _, kid := range slices.Sorted(maps.Keys(byKid)) {
		if kid == "" {
			return nil, fmt.Errorf("%w: el kid de una entrada no puede estar vacío", auth.ErrInvalidInput)
		}
		verifier, err := NewVerifier(byKid[kid], issuer)
		if err != nil {
			return nil, fmt.Errorf("entrada %q: %w", kid, err)
		}
		verifiers[kid] = verifier
	}

	return &MultiVerifier{issuer: issuer, byKid: verifiers}, nil
}

// ValidateIdentityToken selecciona la clave por el `kid` del token y delega en el Verifier
// correspondiente. La semántica de aceptación es idéntica a Verifier.ValidateIdentityToken.
//
// Devuelve un error que envuelve auth.ErrInvalidToken si el token no trae `kid` (o no es una
// cadena), auth.ErrUnknownKid si el `kid` no corresponde a ninguna clave conocida y, en modo JWKS,
// auth.ErrJWKSUnavailable si no hay claves frescas con las que decidir.
func (mv *MultiVerifier) ValidateIdentityToken(tokenString, expectedSystem string) (*Claims, error) {
	if err := requireArg("expectedSystem", expectedSystem); err != nil {
		return nil, err
	}
	verifier, err := mv.verifierFor(tokenString)
	if err != nil {
		return nil, err
	}
	return verifier.ValidateIdentityToken(tokenString, expectedSystem)
}

// ValidateServiceToken selecciona la clave por el `kid` del token y delega en el Verifier
// correspondiente. La semántica de aceptación es idéntica a Verifier.ValidateServiceToken.
func (mv *MultiVerifier) ValidateServiceToken(tokenString, expectedAudience string) (*ServiceClaims, error) {
	if err := requireArg("expectedAudience", expectedAudience); err != nil {
		return nil, err
	}
	verifier, err := mv.verifierFor(tokenString)
	if err != nil {
		return nil, err
	}
	return verifier.ValidateServiceToken(tokenString, expectedAudience)
}

// Kids devuelve los identificadores de clave que este verificador acepta ahora mismo, en orden
// alfabético.
//
// Es una foto del estado, no una suscripción: en modo JWKS el conjunto cambia cuando se refresca la
// caché. Está pensado para observabilidad —un healthcheck que publique qué claves tiene cargadas el
// proceso, o un test que compruebe que la rotación llegó— no para tomar decisiones de verificación.
func (mv *MultiVerifier) Kids() []string {
	mv.mu.RLock()
	defer mv.mu.RUnlock()

	kids := make([]string, 0, len(mv.byKid))
	for kid := range mv.byKid {
		kids = append(kids, kid)
	}
	slices.Sort(kids)
	return kids
}

// verifierFor resuelve el Verifier que corresponde al `kid` del token, sin comprobar la firma
// todavía. En modo JWKS puede provocar un refresco de la caché de claves.
func (mv *MultiVerifier) verifierFor(tokenString string) (*Verifier, error) {
	kid, err := kidFromToken(tokenString)
	if err != nil {
		return nil, err
	}

	if mv.jwks != nil {
		return mv.verifierFromJWKS(kid)
	}

	if verifier := mv.lookup(kid); verifier != nil {
		return verifier, nil
	}
	return nil, fmt.Errorf("%w: el kid %q no corresponde a ninguna clave conocida", auth.ErrUnknownKid, kid)
}

// lookup devuelve el Verifier cargado para `kid`, o nil si no hay ninguno.
func (mv *MultiVerifier) lookup(kid string) *Verifier {
	mv.mu.RLock()
	defer mv.mu.RUnlock()
	return mv.byKid[kid]
}

// kidFromToken lee el header `kid` SIN comprobar la firma.
//
// Leer un token no verificado es aceptable aquí y solo aquí: del header se toma únicamente el
// identificador con el que buscar la clave, y esa búsqueda no autoriza nada. Todo lo demás —firma,
// issuer, vigencia, claims— se decide después con la clave encontrada.
func kidFromToken(tokenString string) (string, error) {
	unverified, _, err := gojwt.NewParser().ParseUnverified(tokenString, gojwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("%w: %w", auth.ErrInvalidToken, err)
	}

	raw, present := unverified.Header["kid"]
	if !present {
		return "", fmt.Errorf("%w: el token no trae header kid, que es obligatorio", auth.ErrInvalidToken)
	}
	kid, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%w: el header kid no es una cadena", auth.ErrInvalidToken)
	}
	if kid == "" {
		return "", fmt.Errorf("%w: el header kid está vacío", auth.ErrInvalidToken)
	}
	return kid, nil
}
