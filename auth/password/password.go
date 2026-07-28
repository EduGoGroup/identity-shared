// Package password hashea y verifica contraseñas con bcrypt, con un único costo fijo para todo el
// microecosistema y un contrato de errores que no obliga al consumidor a importar bcrypt.
package password

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/EduGoGroup/identity-shared/auth"
)

// bcryptCost es el costo computacional de bcrypt para todo el microecosistema: ~250ms por hash en
// hardware típico, el balance entre resistencia a fuerza bruta y UX aceptable en un login. No se
// exporta ni se hace configurable: un costo variable entre servicios haría que el mismo ataque fuera
// más barato contra unos que otros sin que nadie lo decidiera a propósito.
const bcryptCost = 12

// maxPasswordLength es el límite de bcrypt: 72 BYTES, no caracteres. bcrypt trunca en silencio
// cualquier byte a partir del 73, así que aceptar una contraseña más larga sin avisar crearía
// contraseñas donde el sufijo no importa para la verificación, una superficie de confusión que aquí
// se cierra devolviendo error en vez de truncar.
const maxPasswordLength = 72

// Hasher define el contrato para hashear y verificar contraseñas. Existe para que los consumidores
// puedan sustituir la implementación (por ejemplo en tests) sin depender del tipo concreto.
type Hasher interface {
	// HashPassword genera un hash bcrypt de password.
	HashPassword(password string) (string, error)
	// CheckPasswordHash indica si password corresponde a hash. El orden de los parámetros es
	// password primero, hash segundo — al revés que VerifyPassword. Invertirlos compila sin
	// protestar porque ambos son string; revisa la firma con cuidado.
	CheckPasswordHash(password, hash string) bool
}

// DefaultHasher es la implementación de Hasher basada en bcrypt con bcryptCost. Es la única
// implementación de este paquete; existe como tipo concreto para que los consumidores puedan
// declarar su dependencia como la interfaz Hasher y aun así construirla con NewHasher.
type DefaultHasher struct{}

// NewHasher construye un DefaultHasher listo para usar. No tiene estado propio: el costo y el resto
// de parámetros de bcrypt son constantes del paquete, no de la instancia.
func NewHasher() *DefaultHasher {
	return &DefaultHasher{}
}

// HashPassword genera un hash bcrypt de password. Delega en la función libre HashPassword del
// paquete; existe como método para satisfacer Hasher.
func (h *DefaultHasher) HashPassword(password string) (string, error) {
	return HashPassword(password)
}

// CheckPasswordHash indica si password corresponde a hash. El orden de los parámetros es password
// primero, hash segundo — al revés que VerifyPassword. Delega en VerifyPassword y colapsa su error a
// bool porque Hasher, a diferencia de la función libre, no distingue el motivo del fallo.
func (h *DefaultHasher) CheckPasswordHash(password, hash string) bool {
	return VerifyPassword(hash, password) == nil
}

// HashPassword genera un hash bcrypt de password con bcryptCost.
//
// password vacío o mayor de maxPasswordLength bytes se rechaza con un error que envuelve
// auth.ErrInvalidInput: una contraseña vacía hasheada con éxito es una puerta trasera silenciosa (las
// dos fuentes de las que se parte la aceptaban), y una contraseña por encima del límite de bcrypt se
// truncaría sin avisar en vez de fallar.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("%w: el password no puede estar vacío", auth.ErrInvalidInput)
	}
	if len(password) > maxPasswordLength {
		return "", fmt.Errorf("%w: el password excede el máximo de %d bytes que admite bcrypt "+
			"(el límite es en bytes, no en caracteres)", auth.ErrInvalidInput, maxPasswordLength)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("no se pudo generar el hash bcrypt: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword verifica que password corresponda a hashedPassword. El orden de los parámetros es
// hash primero, password segundo — al revés que CheckPasswordHash. Revisa la firma con cuidado: como
// ambos son string, invertirlos compila sin protestar.
//
// Devuelve nil si coincide. Si hashedPassword es un hash bcrypt válido pero no corresponde a
// password, devuelve un error que envuelve auth.ErrPasswordMismatch, para que el consumidor lo
// clasifique con errors.Is sin importar golang.org/x/crypto/bcrypt. Cualquier otro fallo de bcrypt
// (hash corrupto, con formato inválido o vacío) devuelve un error que envuelve auth.ErrInvalidInput:
// no es que la contraseña esté mal, es que no hay nada verificable contra qué compararla.
func VerifyPassword(hashedPassword, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err == nil {
		return nil
	}
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return fmt.Errorf("%w: el password no coincide con el hash", auth.ErrPasswordMismatch)
	}
	return fmt.Errorf("%w: hash bcrypt no verificable: %w", auth.ErrInvalidInput, err)
}
