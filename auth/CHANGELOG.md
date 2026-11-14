# Changelog — auth

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/)
y [Versionado Semantico](https://semver.org/lang/es/).

## [Unreleased]

## [0.3.2] - 2026-11-14

Solo toolchain y dependencias (plan 054 de EduGo, homologación de Go). No cambia una línea de código
de este módulo, ni su API, ni su comportamiento.

### Changed

- **Go `1.26.5` → `1.27.4`** (directiva `go` del `go.mod`). El parche, no solo la minor: `govulncheck`
  midió vulnerabilidades alcanzables en la librería estándar de `go1.27.1` (`net/http`, `crypto/tls`,
  `crypto/x509`…) corregidas hasta `go1.27.4`. Los consumidores de esta versión necesitan Go `1.27.4`
  o `GOTOOLCHAIN=auto`.
- **`github.com/stretchr/testify` `v1.11.1` → `v1.12.1`** (solo tests). Al subir, `go mod tidy` cambia
  las indirectas: salen `davecgh/go-spew`, `pmezard/go-difflib` y `gopkg.in/yaml.v3`, entra
  `go.yaml.in/yaml/v3 v3.0.5`.

### Security

- **`golang.org/x/crypto` `v0.54.0` → `v0.59.0`**, la última publicada. `GOWORK=off govulncheck ./...`
  con `go1.27.4`: **No vulnerabilities found**.

## [0.3.1] - 2026-08-02

Parche de seguridad de dependencias. No cambia una línea de este módulo: sube `golang.org/x/crypto`
de `v0.51.0` a `v0.54.0`.

### Security

- **`golang.org/x/crypto` v0.51.0 → v0.54.0.** `govulncheck` reportaba 14 vulnerabilidades en los
  módulos requeridos, con arreglo publicado desde `v0.52.0`. **Ninguna era alcanzable** desde este
  código (`Your code is affected by 0 vulnerabilities`, antes y después), pero este módulo es la
  cerrajería del SSO del grupo —bcrypt y la firma ES256— y lo que arrastre lo heredan todos sus
  consumidores: la deuda no se queda aquí, se reparte. Se sube a la última publicada, no a la mínima
  que cierra el reporte, para no volver a pasar por aquí en el próximo aviso.

  Tras el bump quedan **0** de esas 14. La que sobrevive es **GO-2026-5932** —el paquete
  `x/crypto/openpgp`, declarado sin mantenimiento e inseguro por diseño— y **no tiene versión con
  arreglo** (`Fixed in: N/A`): no se cierra subiendo, y este módulo no importa ese paquete.

  Sin cambios de comportamiento ni de API.

## [0.3.0]

El ecosistema entra en el token de servicio. Es la pieza que faltaba para que identity T4.2 —el
canje `POST /auth/token`— pueda emitir algo que el destino sepa autorizar: hasta esta versión un
Service Token decía QUÉ operación cubre, por los scopes, pero no sobre las aplicaciones de QUIÉN.

**Cambio incompatible**, en fuente y en cable: el campo es obligatorio al emitir y su ausencia se
rechaza al verificar. Sube a minor por eso, aunque a fecha del release no haya ningún token de
servicio vivo — la versión describe el contrato, no la suerte que se tuvo con el calendario.

### Added

- **El token de servicio lleva el ecosistema** (`ecosystem_key`), pedido por identity T4.2. Es lo que
  el Service Token gana sobre la API key en claro: identity ADR-0022 fija el ecosistema como «el dato
  con el que se autoriza en destino», y sin él un token de servicio está perfectamente firmado y es
  inservible —el consumidor sabe QUÉ operación cubre, por los scopes, pero no sobre las aplicaciones
  de QUIÉN—. Tres piezas: `ServiceClaims.EcosystemKey` (`claims.go`), `ServiceTokenInput.EcosystemKey`
  que `GenerateServiceToken` escribe (`manager.go`) y la comprobación de presencia en
  `Verifier.ValidateServiceToken` (`verifier.go`).

  El claim va APARTE de `aud` y no dentro: `aud` responde *a quién va dirigido* el token y
  `ecosystem_key` *de parte de quién viene*. Son ejes ortogonales, y fundirlos devuelve el límite
  entre ecosistemas a una convención de nombrado que hay que partir por un separador —el error de
  modelado que identity ADR-0022 ya quitó del `client_id`—.

### Changed

- **Cambio incompatible (fuente): `ServiceTokenInput.EcosystemKey` es OBLIGATORIO.** Un
  `GenerateServiceToken` con el campo vacío devuelve error envuelto sobre `auth.ErrInvalidInput` en
  lugar de emitir. No es sutil ni silencioso: el código que construía la entrada sin ese campo
  compila igual —Go rellena el valor cero— y falla en la primera emisión. Se eligió así a propósito
  frente a un campo opcional, porque un emisor que lo olvida produciría tokens firmados que el
  destino no puede usar, con el síntoma a kilómetros del defecto.
- **Cambio incompatible (cable): `Verifier.ValidateServiceToken` rechaza un token de servicio sin
  `ecosystem_key`** con `auth.ErrInvalidToken`. Afecta a los tokens acuñados por versiones
  anteriores del módulo. A fecha de este cambio no hay ninguno vivo —en identity el canje
  `POST /auth/token` es justamente lo que T4.2 introduce, y hasta ahora no existía ningún emisor de
  tokens de servicio en producción—, así que no hace falta ventana de convivencia; si apareciera un
  emisor de otro lenguaje, tendría que poblar el claim antes de subir esta versión.

## [0.2.0]

Endurecimiento del JWKS y salto de toolchain. La 0.1.0 dejó la cerrajería funcionando; esta versión
cierra los cinco defectos que encontró la revisión adversarial posterior —ninguno era un fail-open,
todos estaban en la única pieza que se diseñó desde cero en vez de portarse— y sube la base a Go
1.26.5.

**Cambio incompatible:** exige Go 1.26.5. Un proyecto con un toolchain anterior ya no compila este
módulo. Por eso es una minor y no un parche.

### Fixed

- **El refresco del JWKS ya no pierde el single-flight cuando el emisor falla** (bug 0001). Antes,
  `fetchAndSwap` solo movía `fetchedAt` en caso de éxito, así que cada goroutine que ganaba el
  candado volvía a ver la caché vencida y volvía a pedir: el candado no colapsaba la estampida, la
  **serializaba**. Con un emisor colgado, 20 validaciones concurrentes eran 20 peticiones y la
  última esperaba 20 timeouts. Ahora el fallo se recuerda durante `failureBackoff` (3 s) y se
  comparte con quien llegue en esa ventana: **una petición**, y las demás fallan en microsegundos.
  La postura sigue siendo fail-closed; lo que cambia es que rechazar sale barato.
- **Un `kid` inventado ya no bloquea la absorción de una rotación legítima** (bug 0002). El
  limitador de refetch fuera de ciclo era un turno único por ventana y global: bastaba un token con
  `kid` basura para que la clave nueva de verdad se quedara fuera hasta que expirara el `CacheTTL`.
  Ahora son dos piezas: memoria por `kid` dentro de la ventana —repetir el mismo `kid` inexistente
  no vuelve a molestar al emisor, así que machacar con él cuesta cero— y un presupuesto de
  `maxOutOfCycleRefetches` (5) por ventana en lugar de uno, que deja pasar al `kid` nuevo sin abrir
  la puerta a una tormenta de refetch.
- **El JWKS por `http://` solo se acepta contra loopback** (bug 0003). Antes cualquier host valía y
  la documentación lo listaba sin advertencia. Es el único punto sobre el que descansa el ADR-0002:
  quien sirva ese documento sustituye el conjunto de claves entero y forja tokens que todos los
  consumidores aceptan; ni el `kid` obligatorio ni la comprobación del punto sobre la curva ayudan,
  porque los pone el atacante. `localhost`, 127.0.0.0/8 y ::1 siguen valiendo para desarrollo.
- **La clasificación de errores ya no pierde el motivo más grave** (bug 0004). golang-jwt une todos
  los fallos de claims en un solo error, y se preguntaba primero por la expiración: un token de un
  emisor no confiable **que además** estaba vencido se reportaba como «expirado», de modo que un
  middleware que mapea `ErrTokenExpired` a «pide un refresh» trataba como caducidad rutinaria justo
  el caso que hay que vigilar. Ahora gana la causa más grave y la expiración solo se reporta cuando
  es el único defecto.
- **`TestMultiVerifier_ConcurrentUse` ya no promete lo que no cubre** (bug 0005). Decía ejercitar el
  reemplazo del mapa de claves en caliente y construía el verificador en modo estático, donde eso no
  ocurre nunca. El caso real está ahora en `TestMultiVerifierFromJWKS_ConcurrentRotation`, que rota
  las claves del emisor mientras otras goroutines validan.

### Changed

- **`iat` no se valida, y ahora lo dice** (bug 0004). El comentario de `clockLeeway` afirmaba cubrir
  `exp`, `nbf` e `iat`, pero faltaba `gojwt.WithIssuedAt` y un `iat` a diez años en el futuro se
  aceptaba. Se corrige la documentación en vez de añadir la comprobación, y la decisión queda fijada
  por test: validar `iat` no aporta seguridad —`exp` y `nbf` ya acotan la ventana, y el token va
  firmado, así que solo el emisor podría falsearlo— y sí añade un modo de fallo real, el del emisor
  con el reloj adelantado.
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
