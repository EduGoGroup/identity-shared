package jwt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/EduGoGroup/identity-shared/auth"
)

// RefreshTokenPrefix es el prefijo de todo refresh token emitido por este módulo (identity ADR-0003).
//
// Sirve para reconocer de un vistazo qué clase de credencial es una cadena suelta —en un log, en una
// cabecera o en una tabla— y para que un secreto filtrado sea detectable por escáneres de secretos.
const RefreshTokenPrefix = "rft_"

// refreshTokenEntropyBytes es la cantidad de bytes aleatorios de un refresh token: 256 bits, muy por
// encima de lo que un atacante puede recorrer, y suficiente para que la unicidad no necesite
// comprobación contra la base de datos.
const refreshTokenEntropyBytes = 32

// RefreshToken es un refresh token recién emitido, con las dos caras que necesita el emisor.
//
// Token es el secreto en claro: se entrega al cliente y no debe persistirse. TokenHash es lo que se
// guarda, de modo que un volcado de la tabla de sesiones no permita renovar nada. ExpiresAt es el
// instante en que la credencial deja de ser canjeable, calculado en la emisión.
type RefreshToken struct {
	Token     string
	TokenHash string
	ExpiresAt time.Time
}

// GenerateRefreshToken emite un refresh token opaco con 256 bits de entropía criptográfica y su hash
// para persistir, con expiración a `ttl` del instante actual.
//
// El token es RefreshTokenPrefix seguido de la codificación base64 URL-safe de los bytes aleatorios.
// No es un JWT y no lleva información dentro: su única función es ser canjeable por el emisor, que
// resuelve el resto contra su propio almacén.
//
// `ttl` debe ser estrictamente positivo; si no, devuelve un error que envuelve auth.ErrInvalidInput.
// La validación es deliberada: sin ella un ttl cero o negativo produce en silencio una credencial ya
// vencida, que el cliente acepta como buena y solo falla al primer canje.
func GenerateRefreshToken(ttl time.Duration) (*RefreshToken, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("%w: ttl debe ser mayor que cero", auth.ErrInvalidInput)
	}

	buf := make([]byte, refreshTokenEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("no se pudo generar entropía para el refresh token: %w", err)
	}

	token := RefreshTokenPrefix + base64.URLEncoding.EncodeToString(buf)

	return &RefreshToken{
		Token:     token,
		TokenHash: HashRefreshToken(token),
		ExpiresAt: time.Now().Add(ttl),
	}, nil
}

// HashRefreshToken devuelve el SHA-256 del token en hexadecimal minúscula. Es pura y determinista:
// la misma entrada da siempre la misma salida, y es la única forma correcta de buscar un refresh
// token presentado por un cliente dentro del almacén.
//
// El hash se calcula sobre la CADENA COMPLETA, con RefreshTokenPrefix incluido. No es un detalle
// cosmético: es la definición de la entrada del hash. Si algún día se recortara el prefijo antes de
// hashear, todos los hashes ya persistidos dejarían de coincidir y cada sesión viva quedaría
// invalidada de golpe. No cambies qué se hashea.
func HashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
