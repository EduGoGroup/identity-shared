# identity-shared

Librería compartida **multi-módulo** en Go del microecosistema `identity`: la **cerrajería central**
de autenticación y autorización del grupo.

Su razón de ser es acabar con la duplicación. Hoy `edugo-shared/auth` y `wapp-shared/auth` implementan
por separado las mismas primitivas —JWT, refresh tokens, matcher de permisos, bcrypt— con diferencias
sutiles de comportamiento. `identity-shared` las funde en **una** implementación, y ambos `*-shared`
la **reemplazan**: no la envuelven ni la adaptan.

## Qué hay dentro

| Módulo | Import path | Foco |
| --- | --- | --- |
| `auth` | `github.com/EduGoGroup/identity-shared/auth` | JWT ES256 con `kid`, `MultiVerifier` (llaves de archivo + JWKS), refresh token opaco de 32 bytes con hash SHA-256, motor RBAC glob (deny > allow, default-deny) con herencia de roles, y bcrypt cost 12. |

El repo **no tiene `go.mod` en la raíz**: cada módulo es independiente, se versiona solo y se publica
con tags `<modulo>/vX.Y.Z`.

## Estado actual: esqueleto (Plan 001, Ola 0)

Este repositorio está en su **Ola 0**: existe la carcasa del proyecto con el estándar del grupo
(documentación, `Makefile`, linter, CI/CD), y el módulo `auth` con su `go.mod` y su `doc.go`.

**Los subpaquetes `jwt/`, `rbac/` y `password/` todavía no existen.** Los crea la **Ola 1**
(tareas T1.2–T1.6), fundiendo `wapp-shared/auth/jwt` como base canónica con el matcher glob y los
golden tests de `edugo-shared/auth/permission_matcher`, la herencia `parent_role_id`, bcrypt cost 12
y el soporte JWKS del `MultiVerifier` (pieza nueva). El `go.mod` no declara dependencias todavía: las
agrega la Ola 1 junto con el código.

## Instalación

```bash
go get github.com/EduGoGroup/identity-shared/auth
```

Es un repositorio **privado**: configura `GOPRIVATE=github.com/EduGoGroup/*` y una credencial de `git`
con acceso a la organización antes de resolver dependencias.

## Uso

Los comandos habituales, desde la raíz:

```bash
make help        # lista los targets disponibles
make ci-local    # fmt-check + vet + lint + tests + govulncheck (lo mismo que corre el CI); `make ci` es su alias
make vuln        # govulncheck en cada módulo: falla si hay una vulnerabilidad alcanzable
make ci-docker   # el mismo pipeline dentro del contenedor golang:$GO_VERSION, sin gastar Actions
make test-all    # tests unitarios de todos los módulos
```

Por módulo: `make -C auth test`, `make -C auth lint`, `make -C auth release-check`.

El inventario de módulos no se mantiene a mano: `scripts/list-modules.sh` los descubre buscando los
`go.mod` a un nivel de profundidad, y de ahí salen tanto las variables del `Makefile` raíz como la
matriz del workflow de CI.

## Toolchain fijado

La fuente única es [versions.env](./versions.env): la lee el `Makefile` (`include versions.env`) y los
workflows la cargan en `$GITHUB_ENV`. Ninguna versión se escribe a mano en un workflow.

| Pieza | Versión |
| --- | --- |
| Go | `1.27.4` (`GO_VERSION`; `go 1.27.4` en cada `go.mod`) |
| golangci-lint | `v2.14.0` (`GOLANGCI_LINT_VERSION`) |
| govulncheck | `v1.9.0` (`GOVULNCHECK_VERSION`) |

## El Identity Token

`identity` emite el **Identity Token** (*quién eres*); cada ecosistema emite aparte su **Context
Token** (*qué puedes hacer* en su negocio). Claims del Identity Token: `iss=identity-core`, `sub` con
el UUID plano del usuario, `aud=[system]`, `system`, `email`, `token_use=identity` y `token_version`.

Ningún proyecto `identity-*` contiene conceptos de negocio de los ecosistemas. Esa frontera es
innegociable y aplica también a los tests y a los ejemplos de esta documentación.

## Documentación

- `AGENTS.md` — fuente única para agentes: estructura, estrategia de fusión, convenciones y gotchas.
- `docs/ACTIVE.md` — el norte actual de este proyecto.
- `CHANGELOG.md` (raíz) y `auth/CHANGELOG.md` — historial de cambios del repo y del módulo.

Los ADR, planes y bitácora del microecosistema viven centralizados en la raíz `Identity-core/`, no
dentro de este repositorio.
