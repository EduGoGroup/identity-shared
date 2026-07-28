---
plan: 001
estado: en curso
actualizado: 2026-07-27
---
# Norte actual — identity-shared

**La Ola 1 del Plan 001 está cerrada.** El módulo `auth` dejó de ser carcasa: expone los
subpaquetes `jwt/`, `rbac/` y `password/`, con 81 funciones de test (330 subtests) y ~4.000 líneas
de Go. Paridad **INV-3** verificada: 118 subtests golden de ambos fixtures (`edugo-shared/auth` y
`wapp-shared/auth`), cero divergencias.

El cierre de la ola cortó el tag **`auth/v0.1.0`** (tags modulares `<modulo>/vX.Y.Z`; este repo
nunca corta un tag raíz), validado con Go 1.25.4 y golangci-lint v2.4.0, que era el toolchain de
entonces.

**Después, el ecosistema pasó a Go 1.26.5** (ver el `CHANGELOG.md` de la raíz y el del módulo).
`main` va por delante del tag: exige `go 1.26.5`, usa `ecdsa.ParseUncompressedPublicKey` para
validar las claves del JWKS —los campos `X`/`Y` del `ecdsa.PublicKey` quedaron deprecados en 1.26—
y fija **golangci-lint v2.12.2**, porque la v2.4.0 se niega a analizar un módulo 1.26. Gates en
verde con ese toolchain: `gofmt`, `vet`, `build`, `go test -short -race ./...` y el linter con 0
hallazgos.

**`auth/v0.2.0` publicado** con las dos cosas dentro: el salto de toolchain y el endurecimiento del
JWKS. Cierra los [bugs 0001–0005](../../docs/bugs/README.md), los cinco que encontró la revisión
adversarial de la 0.1.0 — single-flight que se perdía al fallar el emisor, cooldown que un tercero
podía quemar, `http://` aceptado fuera de loopback, clasificación de errores que escondía la causa
grave y dos promesas de test que no se sostenían. Es minor y no parche por dos motivos
independientes: exige Go 1.26.5 y `http://` remoto deja de ser configuración válida.

342 subtests en verde (12 nuevos), linter con 0 hallazgos, y cada arreglo con un test que se
comprobó que **falla** con el código anterior.

**Este repo queda estable** hasta que un consumidor pida API nueva sobre `auth`.

**Lo siguiente es la Ola 2**, y es de `identity-infrastructure`, no de este repo.

Rige **INV-1**: aquí no entra ningún concepto de negocio de los ecosistemas, ni en código, ni en
tests, ni en ejemplos.

El norte del microecosistema se coordina en `../../docs/ACTIVE.md`.
