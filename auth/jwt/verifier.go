package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"slices"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"

	"github.com/EduGoGroup/identity-shared/auth"
)

// signingAlg es el único algoritmo de firma aceptado al verificar. No hay lista configurable: el
// ecosistema firma siempre ES256 y admitir un segundo algoritmo es la puerta de entrada a los
// ataques de confusión de algoritmo (identity ADR-0002).
const signingAlg = "ES256"

// clockLeeway es el margen de tolerancia de reloj aplicado a `exp`, `nbf` e `iat`.
//
// Sin margen, una desviación de un segundo entre el reloj del emisor y el del verificador rechaza
// tokens legítimos recién emitidos. El valor es deliberadamente pequeño: un margen generoso alarga
// la vida útil real de un token revocado por expiración.
const clockLeeway = 30 * time.Second

// Verifier valida tokens del ecosistema identity contra una sola clave pública ECDSA P-256.
//
// Es la contraparte de Manager: donde Manager firma con una clave y un `kid`, Verifier comprueba con
// la clave pública correspondiente. Para verificar frente a varias claves a la vez (rotación,
// múltiples emisores) se usa MultiVerifier, que selecciona el Verifier por el `kid` del header.
//
// Un Verifier es inmutable tras NewVerifier, por lo que es seguro compartirlo entre goroutines.
type Verifier struct {
	publicKey *ecdsa.PublicKey
	issuer    string
	parser    *gojwt.Parser
}

// NewVerifier construye un verificador para la clave pública dada y el issuer que debe traer el
// claim `iss` de todo token aceptado.
//
// Ambos argumentos son obligatorios: una clave nil, una clave de una curva distinta de P-256 o un
// issuer vacío devuelven un error que envuelve auth.ErrInvalidInput. El issuer no es opcional a
// propósito: un verificador que acepta cualquier `iss` acepta tokens de un emisor en el que este
// ambiente no confía.
func NewVerifier(publicKey *ecdsa.PublicKey, issuer string) (*Verifier, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("%w: publicKey no puede ser nil", auth.ErrInvalidInput)
	}
	if publicKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: publicKey debe ser de la curva P-256, la única válida para %s", auth.ErrInvalidInput, signingAlg)
	}
	if issuer == "" {
		return nil, fmt.Errorf("%w: issuer no puede estar vacío", auth.ErrInvalidInput)
	}

	return &Verifier{
		publicKey: publicKey,
		issuer:    issuer,
		parser: gojwt.NewParser(
			gojwt.WithIssuer(issuer),
			gojwt.WithValidMethods([]string{signingAlg}),
			gojwt.WithExpirationRequired(),
			gojwt.WithLeeway(clockLeeway),
		),
	}, nil
}

// ValidateIdentityToken verifica un Identity Token y devuelve sus claims.
//
// Comprueba, en este orden: firma ES256 con la clave del verificador, `iss`, presencia y vigencia de
// `exp`, `token_use == TokenUseIdentity`, `system == expectedSystem` y que `aud` contenga
// expectedSystem. Las tres últimas comprobaciones son la frontera entre sistemas consumidores: un
// token emitido para un sistema no es aceptable en otro, aunque esté perfectamente firmado por el
// mismo emisor (identity ADR-0006).
//
// expectedSystem es obligatorio; vacío devuelve un error que envuelve auth.ErrInvalidInput, no un
// rechazo de token: un verificador que no sabe qué sistema es no puede decidir nada.
//
// Devuelve un error que envuelve auth.ErrTokenExpired si el token venció, y auth.ErrInvalidToken en
// cualquier otro fallo de verificación.
func (v *Verifier) ValidateIdentityToken(tokenString, expectedSystem string) (*Claims, error) {
	if err := requireArg("expectedSystem", expectedSystem); err != nil {
		return nil, err
	}

	claims := &Claims{}
	if err := v.parse(tokenString, claims); err != nil {
		return nil, err
	}

	if claims.TokenUse != TokenUseIdentity {
		return nil, fmt.Errorf("%w: token_use es %q y se esperaba %q", auth.ErrInvalidToken, claims.TokenUse, TokenUseIdentity)
	}
	if claims.System != expectedSystem {
		return nil, fmt.Errorf("%w: el token fue emitido para el sistema %q y se esperaba %q", auth.ErrInvalidToken, claims.System, expectedSystem)
	}
	if !slices.Contains(claims.Audience, expectedSystem) {
		return nil, fmt.Errorf("%w: la audiencia del token no incluye %q", auth.ErrInvalidToken, expectedSystem)
	}

	return claims, nil
}

// ValidateServiceToken verifica un token de servicio y devuelve sus claims.
//
// Comprueba, además de la firma, el issuer y la vigencia: `token_use == TokenUseService` y que `aud`
// sea exactamente expectedAudience. La audiencia se compara por igualdad estricta, no por
// pertenencia: un token de servicio se emite para una sola audiencia (ver ServiceTokenInput), así
// que un `aud` con más de una entrada no lo produjo este ecosistema.
//
// Comprobar los scopes NO es tarea del verificador: eso lo decide quien conoce la operación, con
// ServiceClaims.HasScope.
//
// expectedAudience es obligatorio; vacío devuelve un error que envuelve auth.ErrInvalidInput.
func (v *Verifier) ValidateServiceToken(tokenString, expectedAudience string) (*ServiceClaims, error) {
	if err := requireArg("expectedAudience", expectedAudience); err != nil {
		return nil, err
	}

	claims := &ServiceClaims{}
	if err := v.parse(tokenString, claims); err != nil {
		return nil, err
	}

	if claims.TokenUse != TokenUseService {
		return nil, fmt.Errorf("%w: token_use es %q y se esperaba %q", auth.ErrInvalidToken, claims.TokenUse, TokenUseService)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != expectedAudience {
		return nil, fmt.Errorf("%w: la audiencia del token es %v y se esperaba exactamente %q", auth.ErrInvalidToken, claims.Audience, expectedAudience)
	}

	return claims, nil
}

// parse verifica la firma y los claims registrados del token, rellenando `claims`. Es el único punto
// del verificador que toca golang-jwt, para que la traducción de errores a las sentinelas canónicas
// ocurra en un solo lugar.
func (v *Verifier) parse(tokenString string, claims gojwt.Claims) error {
	token, err := v.parser.ParseWithClaims(tokenString, claims, v.keyFunc)
	if err != nil {
		if errors.Is(err, gojwt.ErrTokenExpired) {
			return fmt.Errorf("%w: %w", auth.ErrTokenExpired, err)
		}
		return fmt.Errorf("%w: %w", auth.ErrInvalidToken, err)
	}
	if !token.Valid {
		return fmt.Errorf("%w: el token no superó la validación", auth.ErrInvalidToken)
	}
	return nil
}

// keyFunc devuelve la clave con la que comprobar la firma, tras confirmar que el algoritmo declarado
// en el header es ES256.
//
// La comprobación es redundante —el parser ya se construye con WithValidMethods(["ES256"])— y es
// deliberada: es la defensa que queda en pie si alguien afloja la construcción del parser. Sin ella,
// un keyFunc que devuelve la clave sin mirar el método es exactamente el patrón que permite la
// confusión de algoritmo (firmar HS256 usando la clave pública ECDSA como secreto).
func (v *Verifier) keyFunc(token *gojwt.Token) (any, error) {
	if _, ok := token.Method.(*gojwt.SigningMethodECDSA); !ok {
		return nil, fmt.Errorf("%w: el método de firma %q no es ECDSA", auth.ErrInvalidToken, token.Method.Alg())
	}
	if token.Method.Alg() != signingAlg {
		return nil, fmt.Errorf("%w: el método de firma %q no está permitido, solo %s", auth.ErrInvalidToken, token.Method.Alg(), signingAlg)
	}
	return v.publicKey, nil
}

// requireArg rechaza un argumento de cadena vacío con auth.ErrInvalidInput. Existe para que la
// misma exigencia produzca el mismo error tanto en Verifier como en MultiVerifier.
func requireArg(name, value string) error {
	if value == "" {
		return fmt.Errorf("%w: %s no puede estar vacío", auth.ErrInvalidInput, name)
	}
	return nil
}
