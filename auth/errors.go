package auth

import "errors"

// Conjunto canónico de errores del módulo. Los subpaquetes jwt, rbac y password NO declaran
// sentinelas propias: envuelven estas con fmt.Errorf("%w: …") añadiendo el detalle en español.
//
// Esto corrige un defecto heredado de los dos shared originales, donde cada subpaquete declaraba su
// propio ErrInvalidInput con un mensaje distinto: errors.Is(err, auth.ErrInvalidInput) devolvía
// false para un error nacido en auth/jwt, y el consumidor no tenía forma fiable de clasificar.
var (
	// ErrInvalidInput indica que un argumento recibido no cumple el contrato de la función.
	ErrInvalidInput = errors.New("auth: entrada inválida")

	// ErrInvalidToken indica que un token no es verificable: firma inválida, algoritmo no
	// permitido, issuer o audiencia inesperados, token_use equivocado o token malformado.
	ErrInvalidToken = errors.New("auth: token inválido")

	// ErrTokenExpired indica que el token estaba bien firmado pero su exp ya pasó.
	ErrTokenExpired = errors.New("auth: token expirado")

	// ErrUnknownKid indica que el header kid del token no corresponde a ninguna clave conocida por
	// el verificador. Es un caso distinto de ErrInvalidToken: el token puede estar perfectamente
	// firmado por un emisor en el que este ambiente no confía (identity ADR-0012: 401 limpio).
	ErrUnknownKid = errors.New("auth: kid desconocido")

	// ErrJWKSUnavailable indica que el conjunto de claves remoto no se pudo obtener y la caché no
	// tiene una copia vigente. La postura es fail-closed: sin claves frescas no se verifica.
	ErrJWKSUnavailable = errors.New("auth: conjunto de claves JWKS inalcanzable")

	// ErrPasswordMismatch indica que la contraseña no corresponde al hash. Se expone como sentinela
	// para que el consumidor pueda distinguirla de un hash corrupto sin importar bcrypt.
	ErrPasswordMismatch = errors.New("auth: la contraseña no coincide")
)
