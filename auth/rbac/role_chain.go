package rbac

// ResolveRoleChain devuelve la cadena de herencia de un rol: el propio rol (rootID) seguido de todos
// sus ancestros, del más cercano al más lejano.
//
// Es agnóstica al almacenamiento: `parentOf` resuelve el padre de un rol y reporta ok=false —o un
// parent vacío— cuando el rol es canónico, es decir, cuando no tiene padre. Ambas señales cortan la
// cadena sin añadir un eslabón vacío. Soporta profundidad N.
//
// DECISIÓN CONGELADA — el guard de ciclos corta la cadena SIN devolver error. Si un rol ya visitado
// vuelve a aparecer (A→B→A), la caminata termina y se devuelven los eslabones acumulados con
// err=nil. Es una defensa ante datos corruptos, no una validación: el esquema no impide un ciclo, y
// los grants ya acumulados siguen siendo válidos porque la precedencia deny-sobre-allow de
// EvaluateGrants se mantiene intacta sobre un subconjunto de la cadena. Devolver error aquí
// convertiría un dato sucio en una denegación total de servicio para ese principal.
//
// El error de `parentOf` sí se propaga y descarta la cadena entera (devuelve nil): un fallo de
// lectura no es lo mismo que una jerarquía terminada, y resolver permisos con una cadena
// incompleta por un fallo de infraestructura concedería menos —o más— de lo debido.
func ResolveRoleChain(rootID string, parentOf func(id string) (parent string, ok bool, err error)) ([]string, error) {
	chain := make([]string, 0, 4)
	visited := make(map[string]struct{}, 4)
	current := rootID
	for current != "" {
		if _, seen := visited[current]; seen {
			// Ciclo detectado: corta la cadena sin propagar error.
			break
		}
		visited[current] = struct{}{}
		chain = append(chain, current)

		parent, ok, err := parentOf(current)
		if err != nil {
			return nil, err
		}
		if !ok || parent == "" {
			break
		}
		current = parent
	}
	return chain, nil
}

// MergeGrantChain funde una cadena de Grants (uno por nivel de la jerarquía de roles) en un único
// Grants plano. El orden esperado es «ancestro primero, hijo después», pero el resultado es
// invariante al orden: se unen todos los allow y todos los deny, deduplicando los patterns
// repetidos y preservando la posición de su primera aparición.
//
// DECISIÓN CONGELADA 1 — Allow y Deny se inicializan como slices VACÍOS, nunca nil. El wire format
// debe emitir `[]` y jamás `null`: los consumidores (APIs y cliente KMP) reciben la misma
// estructura plana Grants{Allow, Deny} y no deben necesitar ramas defensivas para distinguir
// «lista vacía» de «campo ausente». Por eso una cadena nil también devuelve slices no-nil.
//
// DECISIÓN CONGELADA 2 — aquí NO se aplica la precedencia deny-sobre-allow: no se descartan los
// allow que algún deny llegue a cubrir. Esa responsabilidad es exclusivamente de EvaluateGrants,
// que evalúa por request y no por conjunto. Aplanar sin resolver mantiene intacta la semántica: un
// deny del hijo gana sobre un allow del ancestro en el momento de evaluar, sin importar de qué
// nivel de la cadena provenga cada uno. Si el aplanado «resolviera» los conflictos, el resultado
// dependería del orden de la cadena y dejaría de ser invariante.
func MergeGrantChain(chain []Grants) Grants {
	out := Grants{Allow: []string{}, Deny: []string{}}
	seenAllow := make(map[string]struct{})
	seenDeny := make(map[string]struct{})
	for _, g := range chain {
		for _, p := range g.Allow {
			if _, ok := seenAllow[p]; ok {
				continue
			}
			seenAllow[p] = struct{}{}
			out.Allow = append(out.Allow, p)
		}
		for _, p := range g.Deny {
			if _, ok := seenDeny[p]; ok {
				continue
			}
			seenDeny[p] = struct{}{}
			out.Deny = append(out.Deny, p)
		}
	}
	return out
}
