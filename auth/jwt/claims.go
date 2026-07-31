// Package jwt emite los tokens del ecosistema identity y define su forma en el cable.
//
// El emisor firma siempre con ES256 (ECDSA P-256) y publica el identificador de la clave en el
// header `kid`, que es obligatorio: no existe firma simétrica ni token sin `kid` (identity ADR-0002
// y ADR-0012).
//
// Hay dos usos de token, distinguidos por el claim `token_use`:
//
//   - Identity Token (`token_use = "identity"`): acredita a un usuario ante un sistema concreto.
//     Lleva una lista cerrada de claims propios (`system`, `email`, `token_use`, `token_version`)
//     más los registrados de OIDC. No transporta autorización: quien necesite decidir permisos
//     consulta al servicio correspondiente y evalúa con el paquete rbac.
//   - Service Token (`token_use = "service"`): acredita a un cliente máquina-a-máquina frente a una
//     audiencia concreta, con una lista de scopes evaluada por patrones glob.
package jwt

import (
	gojwt "github.com/golang-jwt/jwt/v5"

	"github.com/EduGoGroup/identity-shared/auth/rbac"
)

const (
	// TokenUseIdentity es el valor del claim `token_use` de un Identity Token. Su valor literal es
	// parte del contrato en el cable: cambiarlo invalida los tokens ya emitidos y a los
	// verificadores de otros lenguajes.
	TokenUseIdentity = "identity"

	// TokenUseService es el valor del claim `token_use` de un token de servicio
	// (máquina-a-máquina). Igual que TokenUseIdentity, su valor literal es contrato.
	TokenUseService = "service"
)

// Claims son los claims de un Identity Token: la lista cerrada de claims propios más los
// registrados de OIDC que aporta gojwt.RegisteredClaims (`iss`, `sub`, `aud`, `jti`, `iat`, `nbf`,
// `exp`).
//
// La frontera del módulo es explícita: aquí NO viven conceptos de negocio. No hay claims de
// organización, de roles ni de permisos, y no deben añadirse. Un token es una credencial de
// identidad, no una foto de la autorización del portador: acoplarle autorización obliga a reemitir
// el token en cada cambio de permisos y convierte cualquier token vigente en una ventana de
// privilegios obsoletos.
//
// `sub` lleva el identificador del usuario en plano (sin prefijo), a diferencia del token de
// servicio (ver ServiceClaims). `aud` lleva el mismo valor que `system`, para que un token emitido
// para un sistema no sea aceptable en otro.
//
// `token_version` es el contador de invalidación del usuario: el verificador de turno puede
// comparar el valor del token con el vigente en el emisor y rechazar los tokens anteriores a un
// cambio de contraseña o a un cierre de sesión global.
type Claims struct {
	System       string `json:"system"`
	Email        string `json:"email"`
	TokenUse     string `json:"token_use"`
	TokenVersion int64  `json:"token_version"`

	gojwt.RegisteredClaims
}

// ServiceClaims son los claims de un token de servicio: la credencial de un cliente
// máquina-a-máquina, sin usuario detrás.
//
// `sub` lleva el prefijo `service:` seguido del ClientID para que un sujeto de servicio nunca se
// confunda con un identificador de usuario, y `aud` lleva la audiencia única a la que el token da
// acceso. `scopes` son patrones de permiso evaluados con HasScope.
//
// Igual que Claims, no transporta ningún concepto de negocio.
//
// # Por qué `ecosystem_key` SÍ cabe aquí y no viola la frontera del módulo
//
// La cabecera de Claims dice que aquí no viven conceptos de negocio, y `ecosystem_key` es la
// excepción razonada, no un olvido de esa regla. Lo que la regla prohíbe es la AUTORIZACIÓN
// fotografiada —roles, permisos, grants—, porque acoplarla al token obliga a reemitirlo en cada
// cambio y convierte cualquier token vigente en una ventana de privilegios obsoletos. El
// ecosistema no es eso: es una propiedad de la IDENTIDAD del portador, tan inmutable como el
// `client_id` con el que se registró, y por eso está exactamente al mismo nivel. Es el gemelo de
// `system` en Claims, que ya vive aquí por el mismo motivo.
//
// # Por qué NO va dentro de `aud`
//
// Son dos ejes ortogonales. `aud` responde A QUIÉN va dirigido el token —qué servicio puede
// aceptarlo—; `ecosystem_key` responde DE PARTE DE QUIÉN viene —sobre las aplicaciones de qué
// ecosistema puede actuar el portador—. Meterlos en el mismo campo obliga a que el verificador
// parta una cadena para separarlos, y a partir de ahí el límite entre ecosistemas depende de una
// convención de nombrado en vez de un dato. Es el error de modelado que identity ADR-0022 ya
// eliminó una vez del `client_id`, y no se reintroduce por la puerta de la audiencia.
//
// # Qué se rompe sin él
//
// Nada, en la firma; todo, en el destino. Un token de servicio sin este claim está perfectamente
// firmado y es inservible: quien lo recibe sabe QUÉ operación cubre —por los scopes— pero no
// sobre las aplicaciones de QUIÉN, que es el dato con el que se autoriza en destino (identity
// ADR-0022). Por eso el emisor lo exige (ver ServiceTokenInput) y el verificador lo comprueba.
type ServiceClaims struct {
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
	TokenUse string   `json:"token_use"`
	// EcosystemKey es la clave natural del ecosistema al que pertenece la credencial —`edugo`,
	// `wapp`, `identity`—, NUNCA la clave namespaced de una aplicación (`edugo.kmp`).
	//
	// Es obligatorio: no hay valor que signifique «todos los ecosistemas», ni cadena vacía, ni
	// comodín. Un token que llegara con él vacío no lo emitió este módulo, y el verificador lo
	// rechaza en vez de dejar que el consumidor decida qué hacer con «ningún ecosistema» —que en
	// una comparación no casa con nada, pero en un `if` mal escrito casa con todo—.
	EcosystemKey string `json:"ecosystem_key"`

	gojwt.RegisteredClaims
}

// HasScope reporta si alguno de los scopes del token cubre el permiso `required`.
//
// La comparación NO es por igualdad: delega en rbac.PermissionMatches, el mismo motor de patrones
// glob que usa la evaluación de permisos del ecosistema (identity ADR-0012). Así un token con el
// scope `identity.users.*` cubre `identity.users.create` sin enumerar cada verbo, y un scope y un
// permiso escritos igual se comportan igual en los tres lenguajes que implementan el motor.
//
// Es seguro sobre un receptor nil y con `required` vacío: ambos casos devuelven false, porque
// «ningún scope» y «ningún permiso pedido» no son razones para autorizar.
func (c *ServiceClaims) HasScope(required string) bool {
	if c == nil || required == "" {
		return false
	}
	for _, scope := range c.Scopes {
		if rbac.PermissionMatches(scope, required) {
			return true
		}
	}
	return false
}
