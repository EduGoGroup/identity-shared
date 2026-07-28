// Package rbac implementa la evaluación de permisos basada en patrones glob de rutas y la
// resolución de cadenas de herencia de roles.
//
// El paquete es deliberadamente puro: no toca red, ni disco, ni base de datos, y no declara
// sentinelas de error propias. La única dependencia es la biblioteca estándar.
package rbac

// Grants es el wire format de los permisos de un principal: una lista de patterns que conceden
// (Allow) y una lista de patterns que niegan (Deny).
//
// Ambos campos se serializan siempre como arreglos JSON, nunca como null: los productores de este
// tipo (ver MergeGrantChain) inicializan los slices vacíos para que el consumidor —incluido el
// cliente KMP— pueda asumir `[]` sin ramas defensivas.
type Grants struct {
	// Allow lista los patterns que conceden permiso.
	Allow []string `json:"allow"`
	// Deny lista los patterns que niegan permiso; tienen precedencia sobre Allow al evaluar.
	Deny []string `json:"deny"`
}
