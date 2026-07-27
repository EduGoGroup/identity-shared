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
// # Estado
//
// Este paquete es todavía la carcasa del módulo (Ola 0 del Plan 001): declara el propósito y fija
// el module path, pero no expone API. Los subpaquetes jwt, rbac y password los crea la Ola 1
// (tareas T1.2 a T1.6), y con ellos llegan las dependencias del go.mod, hoy vacío.
//
// La Ola 1 funde, no escribe desde cero: la base canónica es wapp-shared/auth/jwt, a la que se le
// suman el matcher glob con los golden tests de edugo-shared/auth/permission_matcher, la herencia
// parent_role_id, bcrypt cost 12 y el soporte JWKS del MultiVerifier — esta última, la única pieza
// que se diseña en vez de portarse. Rige la invariante INV-3: los tests deben incluir los casos
// golden de ambos shared originales, y una divergencia de resultado es un bug, no un
// comportamiento nuevo.
//
// # Identity Token
//
// El Identity Token que emite identity dice quién eres; cada ecosistema emite aparte su Context
// Token con qué puedes hacer en su negocio. Sus claims son: iss (identity-core), sub (el UUID
// plano del usuario global), aud (arreglo con el system destinatario), system, email, token_use
// (identity) y token_version.
package auth
