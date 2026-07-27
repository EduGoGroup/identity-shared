# Changelog — auth

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/)
y [Versionado Semantico](https://semver.org/lang/es/).

## [Unreleased]

### Added

- Esqueleto del modulo `auth` creado por el **Plan 001** (Ola 0), calcado del molde de modulo de
  `wapp-shared/auth`:
  - `go.mod` con module path `github.com/EduGoGroup/identity-shared/auth` y `go 1.25.0`, **sin
    dependencias** todavia (las agrega la Ola 1 junto con el codigo).
  - `doc.go` con la documentacion del paquete: proposito de la cerrajeria, alcance de las cuatro
    piezas (JWT ES256 con `kid` + MultiVerifier archivo/JWKS, refresh opaco de 32 bytes con hash
    SHA-256, RBAC glob default-deny con herencia de roles, bcrypt cost 12) y claims del Identity
    Token.
  - `README.md`, `CHANGELOG.md` y `Makefile` con el contrato de targets del modulo.
- El modulo **no expone API todavia**. Los subpaquetes `jwt/`, `rbac/` y `password/` los crea la
  **Ola 1** (tareas T1.2–T1.6), fundiendo `wapp-shared/auth/jwt` como base canonica con el matcher
  glob y los golden tests de `edugo-shared/auth/permission_matcher`, la herencia `parent_role_id`
  (`role_chain`), bcrypt cost 12 y el soporte JWKS del MultiVerifier (pieza nueva). Rige INV-3: los
  tests deben incluir los casos golden de ambos shared originales.
