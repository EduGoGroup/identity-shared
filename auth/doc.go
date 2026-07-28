// Package auth es la cerrajería central del microecosistema identity: las primitivas puras de
// autenticación y autorización que comparten todos los ecosistemas del grupo.
//
// Reúne en una sola implementación lo que hoy está duplicado en edugo-shared/auth y en
// wapp-shared/auth. Ambos la reemplazan; no la envuelven ni la adaptan. Es una librería pura: sin
// base de datos, sin HTTP y sin conceptos de negocio de ningún ecosistema.
//
// # Alcance
//
// La cerrajería cubre cuatro piezas:
//
//   - JWT ES256 (ECDSA P-256) con selección de llave por kid, y un MultiVerifier que resuelve la
//     llave tanto desde llaves cargadas de archivo como desde un endpoint JWKS.
//   - Refresh tokens opacos de 32 bytes, persistidos como hash SHA-256.
//   - Motor RBAC de permisos glob (recurso.accion, con *, prefix.*, *.suffix y prefix.*.suffix),
//     de evaluación default-deny y con deny precediendo a allow, más herencia de roles por
//     parent_role_id.
//   - Hashing de contraseñas con bcrypt cost 12.
//
// # Organización
//
// El paquete raíz auth no tiene lógica: expone únicamente el conjunto canónico de errores
// centinela que los tres subpaquetes envuelven. Así errors.Is funciona igual sin importar de qué
// subpaquete venga el error — defecto que arrastraban los dos shared originales, donde cada
// subpaquete declaraba su propio ErrInvalidInput con un mensaje distinto.
//
//   - jwt — emisión y verificación de tokens, MultiVerifier con JWKS, refresh opaco.
//   - rbac — matcher glob, evaluación de grants y cadena de herencia de roles.
//   - password — hashing y verificación con bcrypt.
//
// # Procedencia
//
// La Ola 1 del Plan 001 fundió, no escribió desde cero: la base canónica es wapp-shared/auth/jwt,
// a la que se le sumaron el matcher glob con los golden tests de edugo-shared/auth y su cadena de
// herencia de roles, bcrypt cost 12 y el soporte JWKS del MultiVerifier — esta última, la única
// pieza diseñada en vez de portada. Rige la invariante INV-3: los tests incluyen los casos golden
// de ambos shared originales, y una divergencia de resultado es un bug, no un comportamiento
// nuevo.
//
// Divergencias deliberadas respecto a los originales, todas por mandato de un ADR de identity:
// el algoritmo de firma es ES256 con kid obligatorio y HS256 no existe ni para tokens de servicio
// (ADR-0002 y ADR-0012); el refresh token lleva prefijo legible rft_ y su SHA-256 se calcula sobre
// la cadena completa, prefijo incluido (ADR-0003); y no hay verificador «default» para tokens sin
// kid, porque en identity no existe legado que verificar.
//
// # Identity Token
//
// El Identity Token que emite identity dice quién eres; cada ecosistema emite aparte su Context
// Token con qué puedes hacer en su negocio. Sus claims son: iss (identity-core), sub (el UUID
// plano del usuario global), aud (arreglo con el system destinatario), system, email, token_use
// (identity) y token_version.
package auth
