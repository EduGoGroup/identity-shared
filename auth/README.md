# auth

Primitivas **puras** de autenticación y autorización del microecosistema `identity`: la cerrajería
que comparten todos los ecosistemas del grupo. Sin base de datos, sin HTTP y **sin conceptos de
negocio** de ningún ecosistema.

`edugo-shared/auth` y `wapp-shared/auth` **reemplazan** su implementación por este módulo: no lo
envuelven ni lo adaptan. Una sola implementación, un solo comportamiento.

## Instalación

```bash
go get github.com/EduGoGroup/identity-shared/auth
```

Repositorio privado: requiere `GOPRIVATE=github.com/EduGoGroup/*` y credencial de `git` con acceso a
la organización.

## Uso

El módulo expone tres subpaquetes. Cada uno se importa por separado según lo que necesites:

| Subpaquete | Qué expone |
| --- | --- |
| `jwt/` | Emisión y verificación ES256 con `kid` obligatorio (`Manager`, `Verifier`, `MultiVerifier`), resolución de llaves desde un endpoint JWKS remoto, y refresh tokens opacos con prefijo `rft_`. |
| `rbac/` | Motor de permisos glob (`PermissionMatches`, `EvaluateGrants`) y resolución de herencia de roles (`ResolveRoleChain`, `MergeGrantChain`). |
| `password/` | Hashing y verificación de contraseñas con bcrypt cost 12 (`HashPassword`, `VerifyPassword`, interfaz `Hasher`). |

**INV-3:** los tests del módulo fundido incluyen los casos golden de **ambos** `*-shared`
originales. Una divergencia de resultado entre ellos es un **bug** que se resuelve, no un
comportamiento nuevo que se documenta. No se relaja ni se borra un golden test para que el build pase.

Ejemplo mínimo: emitir un Identity Token, verificarlo contra el JWKS del emisor, evaluar un permiso
y hashear/verificar una contraseña. `github.com/EduGoGroup/identity-shared/auth/jwt` colisiona de
nombre con `github.com/golang-jwt/jwt/v5`; si tu código necesita importar ambos (por ejemplo para
inspeccionar `gojwt.RegisteredClaims` a bajo nivel), dale un alias a uno de los dos, p. ej.
`identjwt "github.com/EduGoGroup/identity-shared/auth/jwt"`.

```go
package example

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/EduGoGroup/identity-shared/auth"
	"github.com/EduGoGroup/identity-shared/auth/jwt"
	"github.com/EduGoGroup/identity-shared/auth/password"
	"github.com/EduGoGroup/identity-shared/auth/rbac"
)

func Ejemplo() error {
	// (a) Emitir un Identity Token.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	manager, err := jwt.NewManager(privateKey, "identity-core", "local-2026-v1")
	if err != nil {
		return err
	}
	token, _, err := manager.GenerateIdentityToken(jwt.IdentityTokenInput{
		UserID:       "3fa85f64-5717-4562-b3fc-2c963f66afa6",
		System:       "wapp.bff",
		Email:        "persona@example.com",
		TokenVersion: 1,
		TTL:          15 * time.Minute,
	})
	if err != nil {
		return err
	}
	fmt.Println("token emitido:", token)

	// (b) Verificar contra el JWKS del emisor.
	verifier, err := jwt.NewMultiVerifierFromJWKS("identity-core", jwt.JWKSOptions{
		URL: "https://identity.internal/.well-known/jwks.json",
	})
	if err != nil {
		return err
	}
	claims, err := verifier.ValidateIdentityToken(token, "wapp.bff")
	if err != nil {
		return err
	}
	fmt.Println("token de:", claims.Email)

	// (c) Evaluar un permiso.
	grants := rbac.Grants{
		Allow: []string{"identity.users.*"},
		Deny:  []string{"identity.users.delete"},
	}
	if rbac.EvaluateGrants(grants, "identity.users.create") {
		fmt.Println("permitido crear usuarios")
	}

	// (d) Hashear y verificar una contraseña.
	hash, err := password.HashPassword("una-contraseña-de-ejemplo")
	if err != nil {
		return err
	}
	if err := password.VerifyPassword(hash, "una-contraseña-de-ejemplo"); errors.Is(err, auth.ErrPasswordMismatch) {
		fmt.Println("no coincide")
	}

	return nil
}
```

## Política JWKS

Defaults de `NewMultiVerifierFromJWKS`, todos ajustables vía `JWKSOptions`:

| Parámetro | Default |
| --- | --- |
| TTL de caché (`CacheTTL`) | 15 min |
| Cooldown de refetch fuera de ciclo (`RefetchCooldown`) | 1 min |
| Timeout del cliente HTTP | 10 s |

Postura **fail-closed**: si la caché vence y el refetch falla, se rechaza el token — nunca se sirve
una caché vencida.

## Errores

Las sentinelas viven en el paquete raíz `auth` y se clasifican con `errors.Is`, sin importar de qué
subpaquete nazca el error:

- `ErrInvalidInput` — un argumento no cumple el contrato de la función.
- `ErrInvalidToken` — token no verificable: firma, algoritmo, issuer, audiencia o `token_use` inválidos.
- `ErrTokenExpired` — el token estaba bien firmado pero su `exp` ya pasó.
- `ErrUnknownKid` — el `kid` del token no corresponde a ninguna llave conocida por el verificador.
- `ErrJWKSUnavailable` — el JWKS remoto no se pudo obtener y no hay caché vigente.
- `ErrPasswordMismatch` — la contraseña no corresponde al hash.

## RBAC — gramática de permisos

`recurso.accion` con comodines: `*` (todo), `prefix.*` (subárbol), `*.suffix` (cualquier
`<algo>.suffix`) y `prefix.*.suffix`. La evaluación es **default DENY** y **deny precede a allow**.

## Identity Token

El **Identity Token** dice *quién eres*; el **Context Token** de cada ecosistema dice *qué puedes
hacer* en su negocio. Claims del Identity Token:

| Claim | Valor / forma |
| --- | --- |
| `iss` | `identity-core` |
| `sub` | UUID **plano** del usuario global |
| `aud` | `[system]` |
| `system` | identificador de la aplicación del catálogo `systems` |
| `email` | correo del usuario global |
| `token_use` | `identity` |
| `token_version` | versión del contrato de claims |

Parámetros fijados: `kid` de desarrollo `local-2026-v1`; TTL de access `15m` y de refresh `168h`, con
override por system usando doble guion bajo (`IDENTITY_TTL_ACCESS__EDUGO_KMP=30m`).

El token NO lleva grants ni roles; la resolución RBAC la hace `identity-api` contra su BD por
request (identity ADR-0014).

## Desarrollo

```bash
make help            # targets disponibles
make test            # tests unitarios (-short)
make lint            # golangci-lint
make release-check   # fmt-check + vet + lint + test -race + build
```

Historial de cambios en `CHANGELOG.md`. Releases con tags `auth/vX.Y.Z`.
