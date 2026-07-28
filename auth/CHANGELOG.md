# Changelog — auth

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/)
y [Versionado Semantico](https://semver.org/lang/es/).

## [Unreleased]

### Changed

- **El módulo exige Go 1.26.5** (`go 1.26.5` en `go.mod`). Es un cambio visible para el consumidor:
  un proyecto con un toolchain anterior ya no puede compilarlo. La base del microecosistema se fijó
  en 1.26.5 para todos los repos `identity-*`.
- `parseJWKSKey` valida el punto de la clave con **`ecdsa.ParseUncompressedPublicKey`**, la API que
  Go 1.26 pone en su sitio: en una sola llamada comprueba la codificación sin comprimir
  (SEC 1 §2.3.3), que el punto caiga sobre P-256 y que no sea el punto al infinito. Sustituye al
  rodeo por `crypto/ecdh` + construcción manual del `ecdsa.PublicKey`, que dejó de ser válido porque
  **los campos `X` e `Y` quedaron deprecados en Go 1.26**. Mismo comportamiento observable, menos
  superficie: desaparecen las dependencias de `crypto/ecdh` y `math/big`.
- Los helpers de test leen las coordenadas de `PublicKey.Bytes()` en vez de `X`/`Y`, por lo mismo.


## [0.1.0]

Primera version funcional de la cerrajeria. La **Ola 1 del Plan 001** fundio `wapp-shared/auth` y
`edugo-shared/auth` en una sola implementacion: los dos la reemplazan, no la envuelven.

### Added

- **`auth` (paquete raiz)** — conjunto **canonico** de errores centinela, sin logica:
  `ErrInvalidInput`, `ErrInvalidToken`, `ErrTokenExpired`, `ErrUnknownKid`, `ErrJWKSUnavailable`,
  `ErrPasswordMismatch`. Los tres subpaquetes los envuelven con `fmt.Errorf("%w: …")`, de modo que
  `errors.Is` clasifica igual sin importar de donde nazca el error.
- **`auth/jwt` — emision.** `Manager` ES256 (ECDSA P-256) con `kid` **obligatorio**:
  `NewManager(privateKey, issuer, kid)` rechaza clave nil, curva distinta de P-256, issuer vacio y
  `kid` vacio. `GenerateIdentityToken` emite el **Identity Token** con los claims del contrato
  (`iss`, `sub` UUID plano, `aud=[system]`, `system`, `email`, `token_use=identity`,
  `token_version`, mas `jti`/`iat`/`nbf`/`exp`). `GenerateServiceToken` emite el token M2M
  (`token_use=service`, `client_id`, `scopes`, `sub="service:<client_id>"`) con el **mismo** par
  ES256 y `kid`.
- **`auth/jwt` — verificacion.** `Verifier` de una clave y `MultiVerifier` que selecciona por `kid`.
  Ambos validan `iss`, algoritmo restringido a ES256, `exp` obligatorio y leeway de 30 s.
  `ValidateIdentityToken` exige ademas `token_use=identity`, que `system` coincida con el esperado y
  que `aud` lo contenga (identity ADR-0006: un token de `edugo.kmp` no vale en
  `edugo.admin-tools`). `ValidateServiceToken` exige `token_use=service` y audiencia exacta.
- **`auth/jwt` — JWKS (pieza nueva, ningun `*-shared` la tenia).**
  `NewMultiVerifierFromJWKS(issuer, opts)` consume un endpoint JWKS estandar (RFC 7517) y alimenta
  al MultiVerifier. Politica **fail-closed**:
  - Defaults: `CacheTTL` 15 min, `RefetchCooldown` 1 min, cliente HTTP propio con timeout de 10 s.
  - El constructor hace un primer fetch y falla si no obtiene al menos una clave usable: nunca nace
    un verificador vacio.
  - Cache vencida → refetch antes de verificar; si el refetch falla, se **rechaza** el token. No se
    sirve cache vencida.
  - `kid` ausente con cache vigente → un refetch fuera de ciclo (rotacion sin downtime), limitado a
    uno por `RefetchCooldown` para que un `kid` basura no provoque una tormenta de peticiones.
  - Filtro de claves: solo `kty=EC` + `crv=P-256`, `kid` no vacio, `use` ausente o `sig`, `alg`
    ausente o `ES256`, coordenadas base64url sin padding de 32 bytes y punto **sobre la curva** y
    distinto del punto al infinito, validado con `crypto/ecdh`. `kid` duplicado: gana el primero.
    Cuerpo acotado a 1 MiB.
  - `Kids()` expone el conjunto de `kid` en cache, ordenado, para healthchecks.
- **`auth/jwt` — refresh token opaco.** 32 bytes de `crypto/rand` en Base64 URL-safe con prefijo
  legible **`rft_`** (identity ADR-0003). `TokenHash` es el SHA-256 hex de la cadena **completa,
  prefijo incluido**. Solo el hash se persiste.
- **`auth/rbac` — motor de permisos.** `PermissionMatches` (gramatica `recurso.accion` con `*`,
  `prefix.*`, `*.suffix` y `prefix.*.suffix`) y `EvaluateGrants` con **deny-precedence** y
  **default-deny**. `ResolveRoleChain` resuelve la herencia por `parent_role_id` mediante un
  callback inyectado, con guard de ciclos; `MergeGrantChain` aplana la cadena deduplicando y
  preservando el orden de primera aparicion.
- **`auth/rbac` — paridad verificada (INV-3).** Se ejecutan **ambas** suites golden como un unico
  runner parametrizado: `testdata/permission_matcher_golden_edugo.json` (copia **byte-identica** del
  fixture de `edugo-shared/auth`, 46 + 35 casos, contrato cross-language con el matcher Kotlin del
  KMP y con `iam.permission_matches()` de Postgres) y `testdata/permission_matcher_golden_wapp.json`
  (15 + 22 casos, los que en wapp eran table-driven, convertidos a fixture). **118 subtests golden**,
  cero divergencias. Un test adicional fija version y conteo de cada fixture: recortar un fixture no
  puede pasar inadvertido.
- **`auth/password`** — `HashPassword` / `VerifyPassword` con **bcrypt cost 12** e interfaz `Hasher`
  con `DefaultHasher`. El cost queda **cementado por test** leyendolo del hash con `bcrypt.Cost`.

### Changed

Divergencias deliberadas respecto a los originales. Todas obedecen a un ADR de identity o a una
regla del microecosistema; ninguna es una "mejora" discrecional.

- **HS256 desaparece por completo** (identity ADR-0002 y ADR-0012). `wapp-shared` firmaba los tokens
  de servicio con HS256 y un secreto simetrico propio; aqui los service tokens van **ES256 con
  `kid`**, con el mismo par que los Identity Token. El `ServiceJWTManager` de wapp no se porto: se
  reescribio como dos metodos del `Manager` unico.
- **El `kid` no es opcional.** En wapp se aplicaba con un `WithKid` opt-in y el `MultiVerifier` tenia
  un verificador *default* para tokens legacy sin `kid`. Aqui `NewManager` exige `kid` y un token sin
  `kid` se rechaza: en identity no hay legado que verificar.
- **`kid` desconocido tiene su propio error** (`ErrUnknownKid`), distinto de `ErrInvalidToken`: el
  token puede estar bien firmado por un emisor en el que este ambiente no confia (ADR-0012 pide un
  401 limpio).
- **Refresh token con prefijo `rft_`** (ADR-0003). wapp no lo tenia. El hash se calcula sobre la
  cadena con prefijo.
- **Cero conceptos de negocio (INV-1).** Se eliminaron `TenantID` de los claims de usuario y de
  servicio, y los tests heredados se reescribieron con gramatica neutra `identity.*`. Unica
  excepcion: el fixture golden vendorizado de EduGo, que se copia byte-identico porque mutarlo
  rompe el contrato con Kotlin y Postgres.
- **El Identity Token no lleva grants ni roles.** Es la lista cerrada del contrato. La resolucion
  RBAC la hace `identity-api` contra su propia BD por request; ver **identity ADR-0014**.
- **Un solo conjunto de errores.** Los originales declaraban `ErrInvalidInput` en cada subpaquete con
  mensajes distintos, asi que `errors.Is` fallaba entre paquetes. Ahora viven en el paquete raiz.
- **`VerifyPassword` expone `ErrPasswordMismatch`**: el consumidor distingue "no coincide" de "hash
  corrupto" **sin importar** `golang.org/x/crypto/bcrypt`, que era lo que ambos originales obligaban.
- **Superficie muerta no portada** (regla de cero codigo deprecado): la interfaz `PermissionEvaluator`
  y la constante `TokenUseRefresh` de wapp, y de `edugo-shared` el `jwt_extract.go` con
  `ParseUnverified` y la `blacklist` en memoria — esta ultima porque identity ADR-0008 decidio **no**
  revocar access tokens vigentes.

### Fixed

Huecos de los originales que esta version cierra:

- `GenerateRefreshToken` **valida el TTL**: un `ttl <= 0` devuelve error en vez de producir en
  silencio un token ya vencido.
- **La contrasena vacia se rechaza.** Los dos originales la hasheaban sin protestar.
- `NewManager` **valida la curva** de la clave privada: una P-384 falla en el constructor con un
  error claro, no al firmar con un error opaco de la libreria JWT.
- `ErrTokenExpired` se devuelve **envuelto** con el error subyacente del parser. wapp lo devolvia
  desnudo y se perdia el detalle.
- El cost de bcrypt, la longitud y el encoding del refresh token y la ausencia de claims de negocio
  quedan **cementados por tests**: en los originales podian cambiarse sin que nada fallara.
- La validacion del punto de una clave JWKS ya no usa `elliptic.Curve.IsOnCurve` —deprecada desde
  Go 1.21 por ser una API de bajo nivel insegura y detectada por staticcheck SA1019 en golangci-lint
  2.12— sino `ecdh.P256().NewPublicKey` sobre el punto sin comprimir (SEC 1 §2.3.3). Ademas de la
  comprobacion sobre la curva, esta rechaza el punto al infinito, que `IsOnCurve` aceptaba.
