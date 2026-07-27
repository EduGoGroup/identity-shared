---
plan: 001
estado: en curso
actualizado: 2026-07-27
---
# Norte actual — identity-shared

Plan 001 en curso. La **Ola 0** dejó el esqueleto del repositorio con el estándar del grupo:
documentación, `Makefile` raíz multi-módulo, `.golangci.yml`, `scripts/list-modules.sh` y los tres
workflows (`ci`, `release`, `sync-main-to-dev`). El módulo `auth` existe como carcasa: `go.mod`
(module path `github.com/EduGoGroup/identity-shared/auth`, `go 1.25.0`, aún sin dependencias) y
`doc.go`. No hay código funcional todavía.

**Lo siguiente es la Ola 1 (T1.2–T1.6):** crear los subpaquetes `jwt/`, `rbac/` y `password/`
fundiendo `wapp-shared/auth/jwt` como base canónica con el matcher glob y los golden tests de
`edugo-shared/auth/permission_matcher`, la herencia de roles por `parent_role_id` (`role_chain`),
bcrypt cost 12 y el soporte JWKS en el `MultiVerifier` — esta última, la única pieza que se diseña en
vez de portarse. Rige **INV-3**: los tests deben incluir los casos golden de ambos `*-shared`
originales, y una divergencia de resultado es un bug, no un comportamiento nuevo.

Rige también **INV-1**: aquí no entra ningún concepto de negocio de los ecosistemas, ni en código, ni
en tests, ni en ejemplos.

El norte del microecosistema se coordina en `../../docs/ACTIVE.md`.
