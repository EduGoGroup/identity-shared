package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/EduGoGroup/identity-shared/auth"
)

// minTokenTTL es el TTL mínimo aceptado al emitir cualquier token. Un TTL por debajo del minuto no
// sobrevive al margen de tolerancia de reloj del verificador (30 s), así que se rechaza en la
// emisión en vez de producir un token que unos verificadores aceptan y otros no.
const minTokenTTL = time.Minute

// Manager firma tokens del ecosistema identity con una clave privada ECDSA P-256.
//
// Un Manager queda ligado a una sola clave, un solo issuer y un solo `kid`; la rotación de claves se
// hace construyendo un Manager nuevo, no mutando uno existente. El `kid` no es opcional: se escribe
// en el header de todos los tokens que firma este Manager para que el verificador sepa con qué clave
// comprobarlos sin adivinar (identity ADR-0002).
//
// Un Manager es inmutable tras NewManager, por lo que es seguro compartirlo entre goroutines.
type Manager struct {
	privateKey *ecdsa.PrivateKey
	issuer     string
	kid        string
}

// NewManager construye un emisor de tokens a partir de la clave privada de firma, el issuer que se
// escribirá en el claim `iss` y el identificador de la clave que se escribirá en el header `kid`.
//
// Los tres argumentos son obligatorios: una clave nil, un issuer vacío o un `kid` vacío devuelven un
// error que envuelve auth.ErrInvalidInput. La clave debe ser de la curva P-256, la única que admite
// ES256; se comprueba aquí para fallar al construir el emisor en lugar de al firmar el primer token.
func NewManager(privateKey *ecdsa.PrivateKey, issuer, kid string) (*Manager, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("%w: privateKey no puede ser nil", auth.ErrInvalidInput)
	}
	if privateKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: privateKey debe ser de la curva P-256, la única válida para ES256", auth.ErrInvalidInput)
	}
	if issuer == "" {
		return nil, fmt.Errorf("%w: issuer no puede estar vacío", auth.ErrInvalidInput)
	}
	if kid == "" {
		return nil, fmt.Errorf("%w: kid no puede estar vacío, es obligatorio en todos los tokens", auth.ErrInvalidInput)
	}
	return &Manager{privateKey: privateKey, issuer: issuer, kid: kid}, nil
}

// Kid devuelve el identificador de la clave con la que firma este Manager. Es el valor que aparece
// en el header `kid` de sus tokens y el que debe publicarse en el JWKS del emisor.
func (m *Manager) Kid() string {
	return m.kid
}

// IdentityTokenInput son los datos necesarios para emitir un Identity Token.
//
// UserID, System y Email son obligatorios; TTL debe ser de al menos un minuto y TokenVersion no
// puede ser negativa. System identifica al sistema consumidor y viaja a la vez en el claim `system`
// y en la audiencia del token.
type IdentityTokenInput struct {
	UserID       string
	System       string
	Email        string
	TokenVersion int64
	TTL          time.Duration
}

func (in IdentityTokenInput) validate() error {
	if in.UserID == "" {
		return fmt.Errorf("%w: UserID no puede estar vacío", auth.ErrInvalidInput)
	}
	if in.System == "" {
		return fmt.Errorf("%w: System no puede estar vacío", auth.ErrInvalidInput)
	}
	if in.Email == "" {
		return fmt.Errorf("%w: Email no puede estar vacío", auth.ErrInvalidInput)
	}
	if in.TokenVersion < 0 {
		return fmt.Errorf("%w: TokenVersion no puede ser negativa", auth.ErrInvalidInput)
	}
	if in.TTL < minTokenTTL {
		return fmt.Errorf("%w: TTL debe ser de al menos %s", auth.ErrInvalidInput, minTokenTTL)
	}
	return nil
}

// ServiceTokenInput son los datos necesarios para emitir un token de servicio.
//
// ClientID, Audience y EcosystemKey son obligatorios y TTL debe ser de al menos un minuto. Scopes
// puede venir vacío: un token sin scopes acredita al cliente pero no autoriza ninguna operación.
type ServiceTokenInput struct {
	ClientID string
	Audience string
	// EcosystemKey va al claim `ecosystem_key` y es OBLIGATORIO.
	//
	// Que sea obligatorio, y no un campo opcional que el emisor rellena si puede, es la única
	// forma de que la garantía valga algo. Opcional, el modo de fallo sería este: un emisor que
	// olvida poblarlo produce tokens perfectamente firmados que el destino no puede usar para
	// autorizar nada, y el síntoma —403 en todo, o peor, un `if` que trata la cadena vacía como
	// «sin restricción»— aparece a kilómetros del defecto. Obligatorio, el emisor incompleto
	// falla al emitir, con el nombre del campo que falta.
	EcosystemKey string
	Scopes       []string
	TTL          time.Duration
}

func (in ServiceTokenInput) validate() error {
	if in.ClientID == "" {
		return fmt.Errorf("%w: ClientID no puede estar vacío", auth.ErrInvalidInput)
	}
	if in.Audience == "" {
		return fmt.Errorf("%w: Audience no puede estar vacía", auth.ErrInvalidInput)
	}
	if in.EcosystemKey == "" {
		return fmt.Errorf("%w: EcosystemKey no puede estar vacía: sin ella el token no autoriza nada en destino", auth.ErrInvalidInput)
	}
	if in.TTL < minTokenTTL {
		return fmt.Errorf("%w: TTL debe ser de al menos %s", auth.ErrInvalidInput, minTokenTTL)
	}
	return nil
}

// GenerateIdentityToken emite un Identity Token firmado y devuelve el token serializado junto con su
// instante de expiración.
//
// Rellena `iss` con el issuer del Manager, `sub` con in.UserID en plano, `aud` con in.System, un
// `jti` único por token, e `iat`/`nbf` en el instante de emisión. El claim `token_use` queda fijado
// a TokenUseIdentity.
//
// Devuelve un error que envuelve auth.ErrInvalidInput si la entrada no cumple el contrato descrito
// en IdentityTokenInput.
func (m *Manager) GenerateIdentityToken(in IdentityTokenInput) (string, time.Time, error) {
	if err := in.validate(); err != nil {
		return "", time.Time{}, err
	}

	now := time.Now()
	expiresAt := now.Add(in.TTL)

	claims := Claims{
		System:       in.System,
		Email:        in.Email,
		TokenUse:     TokenUseIdentity,
		TokenVersion: in.TokenVersion,
		RegisteredClaims: gojwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    m.issuer,
			Subject:   in.UserID,
			Audience:  gojwt.ClaimStrings{in.System},
			IssuedAt:  gojwt.NewNumericDate(now),
			NotBefore: gojwt.NewNumericDate(now),
			ExpiresAt: gojwt.NewNumericDate(expiresAt),
		},
	}

	return m.sign(claims, expiresAt)
}

// GenerateServiceToken emite un token de servicio firmado y devuelve el token serializado junto con
// su instante de expiración.
//
// Rellena `sub` con `"service:" + in.ClientID` para que el sujeto de un cliente máquina-a-máquina
// nunca colisione con el identificador de un usuario, `aud` con in.Audience y `ecosystem_key` con
// in.EcosystemKey. El claim `token_use` queda fijado a TokenUseService. Se firma con la misma clave
// ES256 y el mismo `kid` que los Identity Token: no hay una vía de firma aparte para servicios
// (identity ADR-0012).
//
// Devuelve un error que envuelve auth.ErrInvalidInput si la entrada no cumple el contrato descrito
// en ServiceTokenInput.
func (m *Manager) GenerateServiceToken(in ServiceTokenInput) (string, time.Time, error) {
	if err := in.validate(); err != nil {
		return "", time.Time{}, err
	}

	now := time.Now()
	expiresAt := now.Add(in.TTL)

	claims := ServiceClaims{
		ClientID:     in.ClientID,
		Scopes:       in.Scopes,
		TokenUse:     TokenUseService,
		EcosystemKey: in.EcosystemKey,
		RegisteredClaims: gojwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    m.issuer,
			Subject:   "service:" + in.ClientID,
			Audience:  gojwt.ClaimStrings{in.Audience},
			IssuedAt:  gojwt.NewNumericDate(now),
			NotBefore: gojwt.NewNumericDate(now),
			ExpiresAt: gojwt.NewNumericDate(expiresAt),
		},
	}

	return m.sign(claims, expiresAt)
}

// sign firma los claims con ES256 e inyecta el header `kid` antes de serializar. Es el único punto
// del paquete que firma, para que ningún token pueda salir sin `kid`.
func (m *Manager) sign(claims gojwt.Claims, expiresAt time.Time) (string, time.Time, error) {
	token := gojwt.NewWithClaims(gojwt.SigningMethodES256, claims)
	token.Header["kid"] = m.kid

	signed, err := token.SignedString(m.privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("no se pudo firmar el token: %w", err)
	}
	return signed, expiresAt, nil
}
