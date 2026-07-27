#!/usr/bin/env bash
#
# list-modules.sh — inventario de modulos Go de identity-shared.
#
# A diferencia de la version de edugo-shared (que lee un manifest TSV), aqui los modulos se
# DESCUBREN en el arbol: cualquier directorio de primer nivel con su propio go.mod es un modulo.
# Con un solo modulo no hay manifest que mantener, y agregar uno nuevo no requiere tocar este script.
#
# Consumidores: el Makefile raiz (variables MODULES / INTEGRATION_MODULES) y la matriz de
# .github/workflows/ci.yml.

set -euo pipefail

SET="all"
FORMAT="plain"

usage() {
	cat <<'EOF'
Uso: list-modules.sh [--set <all|integration>] [--format <plain|json>]

Lista los modulos Go del repositorio, descubiertos como los directorios de primer nivel
que contienen un go.mod propio.

Opciones:
  --set <conjunto>    Conjunto de modulos a listar (por defecto: all)
                        all           todos los modulos del repositorio
                        integration   modulos con tests de integracion
                                      (hoy identico a "all")
  --format <formato>  Formato de salida (por defecto: plain)
                        plain   un modulo por linea
                        json    arreglo JSON en una sola linea, p. ej. ["auth"]
  -h, --help          Mostrar esta ayuda

Ejemplos:
  ./scripts/list-modules.sh
  ./scripts/list-modules.sh --set all --format json
  ./scripts/list-modules.sh --set integration --format json
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--set)
		[[ $# -ge 2 ]] || {
			echo "list-modules.sh: --set requiere un valor" >&2
			exit 1
		}
		SET="$2"
		shift 2
		;;
	--set=*)
		SET="${1#*=}"
		shift
		;;
	--format)
		[[ $# -ge 2 ]] || {
			echo "list-modules.sh: --format requiere un valor" >&2
			exit 1
		}
		FORMAT="$2"
		shift 2
		;;
	--format=*)
		FORMAT="${1#*=}"
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "list-modules.sh: opcion desconocida: $1" >&2
		usage >&2
		exit 1
		;;
	esac
done

case "$SET" in
all | integration) ;;
*)
	echo "list-modules.sh: --set invalido: $SET (validos: all, integration)" >&2
	exit 1
	;;
esac

case "$FORMAT" in
plain | json) ;;
*)
	echo "list-modules.sh: --format invalido: $FORMAT (validos: plain, json)" >&2
	exit 1
	;;
esac

# Raiz del repositorio: el directorio padre de scripts/.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Descubrimiento: directorios de primer nivel con go.mod propio (./<modulo>/go.mod).
MODULES=()
while IFS= read -r gomod; do
	module="${gomod#./}"
	module="${module%/go.mod}"
	MODULES+=("$module")
done < <(find . -mindepth 2 -maxdepth 2 -name go.mod -not -path './.git/*' | sort)

# El conjunto "integration" es, por ahora, el mismo que "all": ningun modulo se excluye.
# Cuando algun modulo deje de tener tests de integracion, este es el punto donde se filtra.

if [[ ${#MODULES[@]} -eq 0 ]]; then
	if [[ "$FORMAT" == "json" ]]; then
		echo "[]"
	fi
	exit 0
fi

if [[ "$FORMAT" == "json" ]]; then
	out=""
	for module in "${MODULES[@]}"; do
		out+="\"$module\","
	done
	echo "[${out%,}]"
else
	printf '%s\n' "${MODULES[@]}"
fi
