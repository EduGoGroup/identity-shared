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

Corrida autoritativa con el toolchain fijado, **Go 1.25.4 sobre el Mac** (la de la Ola 1 se hizo en
un contenedor con Go 1.24.7 y un `replace` local de `x/crypto`): `gofmt -l` sin salida, `go vet` y
`go build` limpios, `go test -short -race ./...` verde — `jwt` 1,66 s, `rbac` 1,49 s, `password`
14,15 s, que es lo que cuesta bcrypt cost 12 — y golangci-lint **v2.4.0 (la del CI) con 0
hallazgos**. El `go.sum` se generó con `go mod tidy` y red real; `go.mod` no cambió.

El cierre de la ola corta el tag **`auth/v0.1.0`** (tags modulares `<modulo>/vX.Y.Z`; este repo
nunca corta un tag raíz).

**Lo siguiente es la Ola 2**, y es de `identity-infrastructure`, no de este repo. `identity-shared`
queda estable hasta que un consumidor pida API nueva sobre `auth`.

Rige **INV-1**: aquí no entra ningún concepto de negocio de los ecosistemas, ni en código, ni en
tests, ni en ejemplos.

El norte del microecosistema se coordina en `../../docs/ACTIVE.md`.
