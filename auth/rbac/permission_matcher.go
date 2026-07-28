package rbac

import "strings"

// PermissionMatches reporta si `pattern` cubre el permiso `request`.
//
// Es el espejo Go exacto de iam.permission_matches() (la función de Postgres) y debe coincidir 1:1
// con el PermissionMatcher Kotlin del cliente KMP. Las tres implementaciones se validan contra el
// mismo vector golden vendorizado (ver testdata/): cualquier cambio de comportamiento aquí rompe el
// contrato cross-language, no solo este paquete.
//
// Reglas (rutas por segmentos, con extensión wildcard-first):
//
//	`*`                  → cubre cualquier request
//	`pattern == request` → coincidencia exacta
//	`prefix.*`           → cubre `prefix` y `prefix.<lo-que-sea>` (subárbol completo)
//	`*.suffix`           → cubre cualquier request cuyo tramo final sea `.suffix`
//	                       (p. ej. `*.create` cubre `users.create` y `identity.users.create`)
//	`prefix.*.suffix`    → cubre cualquier request que empiece con `prefix.`, tenga al menos un
//	                       segmento intermedio y termine con `.suffix`
//	sufijo `:own`        → es semánticamente distinto: no se mezcla con el mismo pattern sin `:own`
//
// ATENCIÓN — EL ORDEN DE LAS RAMAS ES PARTE DEL CONTRATO, NO UN DETALLE DE ESTILO.
// La rama `prefix.*` se evalúa ANTES que `prefix.*.suffix` para preservar la semántica histórica
// cuando el pattern termina literalmente en `.*`. Reordenarlas rompe los casos golden M21, M27 y
// M28: `users.*` debe cubrir `users.read:own` (M21) por la comparación de prefijo con startsWith, y
// `.*` debe cubrir tanto la cadena vacía (M27) como `.foo` (M28), tratando el prefijo vacío como un
// prefijo válido.
// Si un refactor futuro «simplifica» el orden, esos tres casos fallan.
//
// ATENCIÓN — LA ASIMETRÍA DE `:own` ES INTENCIONAL Y ESTÁ CONGELADA COMO CONTRATO.
// Un request terminado en `:own` SÍ queda cubierto por la rama de subárbol (`users.*` cubre
// `users.read:own`, caso golden M21; `admin.*` cubre `admin.users.read:own`, M22) pero NO por las
// ramas con comodín inicial ni intermedio (un pattern de la forma `*.verbo` no cubre un request
// `recurso.verbo:own`, M36; ni uno de la forma `prefijo.*.verbo` cubre `prefijo.recurso.verbo:own`,
// M44). No es un descuido: es el comportamiento que ya emiten Postgres y el KMP, y los tres motores
// deben seguir divergiendo igual. No lo «arregles».
func PermissionMatches(pattern, request string) bool {
	if pattern == "*" {
		return true
	}
	if pattern == request {
		return true
	}
	// prefix.* (subárbol). Debe evaluarse antes que prefix.*.suffix para preservar la semántica
	// histórica cuando el pattern termina literalmente en `.*`.
	if strings.HasSuffix(pattern, ".*") {
		prefix := pattern[:len(pattern)-2]
		return request == prefix || strings.HasPrefix(request, prefix+".")
	}
	// *.suffix → cualquier request `<algo>.suffix`.
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // conserva el punto, p. ej. ".create"
		return len(request) > len(suffix) && strings.HasSuffix(request, suffix)
	}
	// prefix.*.suffix → request que empieza con `prefix.`, algo en medio, y termina en `.suffix`.
	if i := strings.Index(pattern, ".*."); i > 0 {
		head := pattern[:i+1] // `prefix.`
		tail := pattern[i+2:] // `.suffix`
		// Validar que no haya otro `*`: los patterns soportados son los listados en la doc y la
		// forma `prefix.*` ya quedó descartada por la rama anterior.
		if strings.Contains(head, "*") || strings.Contains(tail, "*") {
			return false
		}
		if !strings.HasPrefix(request, head) || !strings.HasSuffix(request, tail) {
			return false
		}
		// Si head y tail se solapan dentro del request, no hay segmento intermedio.
		if len(request) <= len(head)+len(tail) {
			return false
		}
		// Exigir al menos un segmento intermedio real entre head y tail.
		middle := request[len(head) : len(request)-len(tail)]
		return !strings.HasPrefix(middle, ".") && !strings.HasSuffix(middle, ".")
	}
	return false
}

// EvaluateGrants decide si `request` está permitido por `g` aplicando precedencia deny-sobre-allow:
// si algún pattern de Deny cubre el request → false, sin mirar los allow. Si ninguno lo cubre,
// devuelve true solo si algún pattern de Allow lo cubre.
//
// La postura por defecto es denegar: un Grants sin allow (incluido el valor cero Grants{}) niega
// cualquier request.
func EvaluateGrants(g Grants, request string) bool {
	for _, d := range g.Deny {
		if PermissionMatches(d, request) {
			return false
		}
	}
	for _, a := range g.Allow {
		if PermissionMatches(a, request) {
			return true
		}
	}
	return false
}
