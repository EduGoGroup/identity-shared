# AGENTS.md — identity-shared

> Detalle local. Reglas globales del microecosistema en `../AGENTS.md` (no las repitas). Norte actual del proyecto en `docs/ACTIVE.md`.

## Propósito

**Librería compartida multi-módulo** en Go: la **cerrajería central** del microecosistema `identity`.
No es un servicio: no tiene `cmd/`, no se "levanta". Concentra las primitivas de autenticación y
autorización que hoy están duplicadas en `edugo-shared/auth` y `wapp-shared/auth`, para que ambos
`*-shared` la **reemplacen** (no la envuelvan): una sola implementación, un solo comportamiento.

Alcance de la cerrajería: JWT **ES256** con `kid`, `MultiVerifier` (llaves de archivo + **JWKS**),
refresh token opaco de 32 bytes con hash SHA-256, motor **RBAC glob** (deny > allow, default-deny)
con herencia de roles, y hashing de contraseñas **bcrypt cost 12**.

**INV-1 (frontera innegociable):** aquí no entra ningún concepto de negocio de los ecosistemas
—escuela, unidad académica, ward/acudido, tenant/empresa, sesión de mensajería— ni en código, ni en
tests, ni en ejemplos de documentación. Si un claim o un permiso huele a negocio, no es de identity.

## Estructura

El repo es multi-módulo **de verdad**: **no hay `go.mod` en la raíz**. Cada módulo es un módulo Go
independiente, con su propio `go.mod`, `README.md`, `CHANGELOG.md` y `Makefile`, versionado y
publicado por separado con tags `<modulo>/vX.Y.Z`.

| Módulo | Module path | Foco |
| --- | --- | --- |
| `auth` | `github.com/EduGoGroup/identity-shared/auth` | JWT ES256 + `kid`, MultiVerifier (archivo + JWKS), refresh opaco, RBAC glob con herencia, bcrypt. |

Hoy hay **un** módulo. El inventario no se mantiene a mano: `scripts/list-modules.sh` **descubre**
los módulos con `find . -mindepth 2 -maxdepth 2 -name go.mod`, y de ahí salen la matriz del CI y las
variables del `Makefile` raíz.

### Estado de la Ola 0 (esqueleto)

Lo que existe hoy en `auth/` es la **carcasa**: `go.mod` (sin dependencias todavía) y `doc.go` con la
documentación del paquete. Los subpaquetes **`jwt/`, `rbac/` y `password/` NO existen aún**: los crea
la **Ola 1** (tareas T1.2–T1.6). El `go.mod` y el `doc.go` se adelantan porque sin ellos el CI del
primer push (T0.6) no puede estar verde: la matriz de módulos quedaría vacía y no habría paquete que
compilar, vetear ni lintar.

## Cómo construir y testear

El `Makefile` **raíz** orquesta todos los módulos; cada módulo tiene el mismo contrato de targets en
su propio `Makefile`.

- Raíz: `make help` · `make build-all` · `make test-all` · `make lint-all` · `make ci-local` (fmt-check
  + vet + lint + tests, lo que corre el CI) · `make ci-docker` (mismo pipeline dentro del contenedor
  `golang:1.25` con `golangci-lint v2.4.0`, para reproducir el CI sin gastar minutos de Actions).
- Por módulo: `make -C auth test` / `lint` / `fmt` / `vet` / `release-check`.
- Toolchain fijado: **Go 1.25** (`go 1.25.0` en cada `go.mod`), **golangci-lint v2.4.0**. Las variables
  `GO_VERSION` / `LINT_VERSION` del `Makefile` raíz deben coincidir con `.github/workflows/ci.yml`.

## La fusión que ejecuta la Ola 1 (léelo antes de escribir código aquí)

Este módulo **no se escribe desde cero**: se **funde** a partir de los dos `auth` existentes. La
estrategia es fija, no la reinventes:

1. **Base canónica: `wapp-shared/auth/jwt`.** Es el punto de partida del subpaquete `jwt/` — ya trae
   ES256, selección de llave por `kid` y `MultiVerifier`. Se porta con su layout y su semántica.
2. **Matcher glob: se le suma el de `edugo-shared/auth/permission_matcher`**, y se traen **sus golden
   tests** tal cual. La gramática es `recurso.accion` con `*`, `prefix.*`, `*.suffix`,
   `prefix.*.suffix`; evaluación **default-deny** y **deny precede a allow**.
3. **Herencia de roles: `parent_role_id` (`role_chain`)** — resolución de la cadena de roles con guard
   de ciclos y aplanado del set efectivo de grants.
4. **bcrypt cost 12** — se adopta el **valor de EduGo** como único costo del ecosistema.
5. **JWKS en el `MultiVerifier`** — **pieza nueva**: ningún `*-shared` de hoy la tiene. El verificador
   debe resolver la llave por `kid` tanto desde llaves cargadas de archivo como desde un endpoint
   JWKS. Es la única parte que se diseña, no se porta.

**INV-3 (invariante de la fusión):** los tests del módulo fundido deben incluir los **casos golden de
AMBOS** `*-shared` originales. Si un caso golden de EduGo y uno de wApp discrepan en resultado, eso es
un **bug** que hay que resolver — **no** un "comportamiento nuevo" que se documenta y se deja pasar.
No se borra ni se relaja un golden test para que el build pase.

## Contrato del Identity Token (documentación, no código)

El **Identity Token** dice *quién eres*; cada ecosistema emite aparte su **Context Token** con *qué
puedes hacer* en su negocio. Claims del Identity Token:

| Claim | Valor / forma |
| --- | --- |
| `iss` | `identity-core` |
| `sub` | UUID **plano** del usuario global (sin prefijos ni namespacing) |
| `aud` | `[system]` — arreglo con el system destinatario |
| `system` | identificador de la aplicación del catálogo `systems` |
| `email` | correo del usuario global |
| `token_use` | `identity` |
| `token_version` | versión del contrato de claims |

Parámetros fijados que este módulo debe respetar: `kid` de desarrollo `local-2026-v1`; TTL de access
`15m` y de refresh `168h`, con override por system usando doble guion bajo
(`IDENTITY_TTL_ACCESS__EDUGO_KMP=30m`).

## Convenciones y gotchas locales

- **Código en inglés; documentación, comentarios de doc y logs en español.** Fechas en UTC.
- **Multi-módulo, no monolito**: cada `go.mod` es independiente y se versiona solo. El módulo se llama
  `auth` — su import path es `.../identity-shared/auth`, **no** `.../identity-shared/auth/auth`.
- **`CHANGELOG.md` doble**: uno en la raíz (cambios del repo/tooling) y uno por módulo (cambios de su
  API). Un cambio en `auth/` toca `auth/CHANGELOG.md`, no solo el de la raíz.
- **Releases**: tags **modulares** `<modulo>/vX.Y.Z` (p. ej. `auth/v0.1.0`). `release.yml` lee el
  `CHANGELOG.md` del módulo taggeado.
- **Nunca re-taguees una versión existente.** Si el contenido cambia, sube el número. Re-taguear el
  mismo número con contenido distinto rompe el `go.sum` de los consumidores en CI/cloud con
  `SECURITY ERROR: checksum mismatch` (en local no se nota: el `go.work` resuelve del filesystem).
- **Deps privadas**: `GOPRIVATE=github.com/EduGoGroup/*`. En CI se configura además la credencial de
  `git` con `secrets.GITHUB_TOKEN` antes de cualquier `go mod download`.
- **Ramas**: `main` (estable) + `dev` (integración); el trabajo va en `feature/001-<slug>`. El workflow
  `sync-main-to-dev.yml` reconcilia `main` → `dev` tras cada push a `main`.
- **`docs/` aquí solo lleva `ACTIVE.md`** y documentación técnica local. Los ADR, planes y journal
  viven centralizados en la raíz `Identity-core/`; no los dupliques dentro del proyecto.
