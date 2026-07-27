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

## Estado: carcasa (Ola 0)

Hoy este módulo tiene únicamente `go.mod` y `doc.go`. **No expone API todavía**, y su `go.mod` no
declara dependencias: las agrega la Ola 1 junto con el código.

Los subpaquetes llegan en la **Ola 1** (tareas T1.2–T1.6):

| Subpaquete | Qué expondrá | Origen |
| --- | --- | --- |
| `jwt/` | JWT ES256 (ECDSA P-256) con `kid`, y `MultiVerifier` que resuelve la llave desde archivo **o desde JWKS**. | Base canónica `wapp-shared/auth/jwt`; el soporte **JWKS es pieza nueva** (ningún `*-shared` lo tiene hoy). |
| `rbac/` | Matcher glob de permisos + herencia de roles por `parent_role_id` (`role_chain`). | Matcher y **golden tests** de `edugo-shared/auth/permission_matcher`; cadena de roles de `wapp-shared`. |
| `password/` | Hashing y verificación de contraseñas con **bcrypt cost 12**. | Valor de EduGo, adoptado como único costo del ecosistema. |

Además, refresh tokens opacos de **32 bytes** persistidos como hash **SHA-256**.

**INV-3:** los tests del módulo fundido deben incluir los casos golden de **ambos** `*-shared`
originales. Una divergencia de resultado entre ellos es un **bug** que se resuelve, no un
comportamiento nuevo que se documenta. No se relaja ni se borra un golden test para que el build pase.

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

## Desarrollo

```bash
make help            # targets disponibles
make test            # tests unitarios (-short)
make lint            # golangci-lint
make release-check   # fmt-check + vet + lint + test -race + build
```

Historial de cambios en `CHANGELOG.md`. Releases con tags `auth/vX.Y.Z`.
