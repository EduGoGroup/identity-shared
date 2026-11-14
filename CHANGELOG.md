# Changelog

Todos los cambios relevantes del repositorio `identity-shared` deben registrarse aquí.
El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/) y
[Versionado Semántico](https://semver.org/lang/es/).

Los cambios de la **API de un módulo** se registran en el `CHANGELOG.md` de ese módulo
(p. ej. `auth/CHANGELOG.md`). Aquí se registra lo transversal: estructura del repo, tooling,
linter, `Makefile` raíz, scripts y workflows.

## [Unreleased]

### Changed

- **Plan 054 (EduGo): toolchain a Go 1.27.4 y golangci-lint v2.14.0, con `versions.env` como fuente
  única.** Nuevo `versions.env` en la raíz (`GO_VERSION`, `GOLANGCI_LINT_VERSION`): el `Makefile` raíz
  lo incluye (`include versions.env`; `ci-docker` usa `golang:$(GO_VERSION)-bookworm`) y `ci.yml` y
  `release.yml` lo cargan en `$GITHUB_ENV` antes de `setup-go`, así que ninguna versión queda escrita a
  mano en un workflow. Los workflows corren con `GOWORK: 'off'` a nivel de workflow. Actions:
  `actions/checkout@v5` → `@v7` (también en `sync-main-to-dev.yml`), `actions/setup-go@v6` → `@v7`;
  `golangci/golangci-lint-action@v9` se queda. Nuevo alias `make ci` → `ci-local`. Lo libera
  `auth/v0.3.2`.

- **El ecosistema pasa a Go 1.26.5 como base** (`go 1.26.5` en cada `go.mod`, `GO_VERSION` de los
  workflows y `golang:1.26.5-bookworm` en `ci-docker`). Va con **golangci-lint v2.12.2**, y no es
  opcional: la v2.4.0 anterior se niega a arrancar contra un módulo 1.26 con «the Go language
  version (go1.25) used to build golangci-lint is lower than the targeted Go version». De paso se
  actualizan las actions que ya avisaban de la deprecación de Node 20 —`actions/checkout@v5`,
  `actions/setup-go@v6`, `golangci/golangci-lint-action@v9`— y se corrige el `go install` del target
  `tools`, que apuntaba al import path de la v1 (`golangci-lint/cmd/…` en vez de
  `golangci-lint/v2/cmd/…`) y por tanto nunca habría instalado la versión fijada.

### Added

- Esqueleto del repositorio creado por el **Plan 001** (Ola 0): estándar de proyecto del grupo
  calcado de `edugo-shared` y de `wapp-shared`.
- `AGENTS.md` (fuente única local, con la estrategia de fusión de la Ola 1 y la invariante INV-3),
  `CLAUDE.md`, `GEMINI.md`, `README.md` y `CHANGELOG.md`.
- `Makefile` raíz multi-módulo con targets autodocumentados, `ci-local` y `ci-docker`; toolchain
  fijado a Go 1.26.5 y golangci-lint v2.12.2.
- `.golangci.yml` (`version: "2"`) y `.gitignore` de proyecto Go.
- `docs/ACTIVE.md` con el norte del proyecto.
- `scripts/list-modules.sh`: descubre los módulos con `find . -mindepth 2 -maxdepth 2 -name go.mod`
  (sin manifest que mantener) y expone `--set <all|integration>` con `--format <plain|json>` para
  alimentar el `Makefile` raíz y la matriz del CI.
- Workflows `ci.yml` (matriz `prepare-modules` + `validate` + `integration`), `release.yml` (tags
  modulares `<modulo>/v*`) y `sync-main-to-dev.yml`, con `GOPRIVATE` y credencial de `git` para
  dependencias privadas de la organización.
- Módulo `auth`: `go.mod` (`github.com/EduGoGroup/identity-shared/auth`, `go 1.26.5`, todavía sin
  dependencias), `doc.go`, `README.md`, `CHANGELOG.md` y `Makefile`. Los subpaquetes `jwt/`, `rbac/`
  y `password/` los crea la Ola 1 (T1.2–T1.6).
- Cierre de la **Ola 1**: el módulo `auth` pasó de carcasa a funcional (subpaquetes `jwt/`, `rbac/`
  y `password/`) y cortó su primer release, `auth/v0.1.0`. Detalle de la API en `auth/CHANGELOG.md`,
  no aquí.
- La matriz `prepare-modules` + `validate` del workflow `ci.yml` ya valida código real de los tres
  subpaquetes, no solo el esqueleto del módulo.
