# identity-shared - Makefile raiz (multi-modulo)
# Orquesta operaciones y releases en todos los modulos independientes.

MODULE_NAME = github.com/EduGoGroup/identity-shared

# Versiones fijadas del toolchain de CI (deben coincidir con .github/workflows/ci.yml)
GO_VERSION   := 1.26.5
LINT_VERSION := v2.12.2

MODULES := $(shell ./scripts/list-modules.sh --set all | tr '\n' ' ')
INTEGRATION_MODULES := $(shell ./scripts/list-modules.sh --set integration | tr '\n' ' ')

RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[0;33m
BLUE = \033[0;34m
NC = \033[0m

.DEFAULT_GOAL := help

.PHONY: help
help: ## Mostrar ayuda de comandos disponibles
	@echo "$(BLUE)identity-shared - Comandos disponibles:$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-25s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)Modulos: $(MODULES)$(NC)"

.PHONY: build-all
build-all: ## Verificar que todos los modulos compilan
	@echo "$(BLUE)Compilando todos los modulos...$(NC)"
	@for module in $(MODULES); do \
		echo "$(YELLOW)Building $$module...$(NC)"; \
		(cd $$module && go build ./...) || exit 1; \
		echo "$(GREEN)  $$module compilado$(NC)"; \
	done
	@echo "$(GREEN)Todos los modulos compilados$(NC)"

.PHONY: test-all
test-all: ## Ejecutar tests unitarios en todos los modulos
	@echo "$(BLUE)Ejecutando tests en todos los modulos...$(NC)"
	@for module in $(MODULES); do \
		echo "$(YELLOW)Testing $$module...$(NC)"; \
		(cd $$module && go test -short -v ./...) || exit 1; \
		echo "$(GREEN)  $$module tests passed$(NC)"; \
		echo ""; \
	done
	@echo "$(GREEN)Todos los modulos pasaron los tests$(NC)"

.PHONY: test-race-all
test-race-all: ## Ejecutar tests con race detection en todos los modulos
	@echo "$(BLUE)Ejecutando tests con race detection...$(NC)"
	@for module in $(MODULES); do \
		echo "$(YELLOW)Testing $$module with race detection...$(NC)"; \
		(cd $$module && go test -race -short -v ./...) || exit 1; \
		echo "$(GREEN)  $$module passed$(NC)"; \
	done
	@echo "$(GREEN)Todos los modulos pasaron los race tests$(NC)"

.PHONY: test-integration-all
test-integration-all: ## Ejecutar tests de integracion en modulos que los usan
	@echo "$(BLUE)Ejecutando tests de integracion...$(NC)"
	@export INTEGRATION_TESTS=true; \
	for module in $(INTEGRATION_MODULES); do \
		echo "$(YELLOW)Integration Testing $$module...$(NC)"; \
		(cd $$module && go test -v -cover ./...) || exit 1; \
		echo ""; \
	done
	@echo "$(GREEN)Ejecucion de tests de integracion completada$(NC)"

.PHONY: lint-all
lint-all: ## Ejecutar linter en todos los modulos
	@echo "$(BLUE)Ejecutando linter en todos los modulos...$(NC)"
	@for module in $(MODULES); do \
		echo "$(YELLOW)Linting $$module...$(NC)"; \
		(cd $$module && golangci-lint run ./...) || exit 1; \
		echo "$(GREEN)  $$module linted$(NC)"; \
	done
	@echo "$(GREEN)Todos los modulos pasaron el linter$(NC)"

.PHONY: fmt-all
fmt-all: ## Formatear codigo en todos los modulos
	@echo "$(BLUE)Formateando codigo en todos los modulos...$(NC)"
	@for module in $(MODULES); do \
		echo "$(YELLOW)Formatting $$module...$(NC)"; \
		(cd $$module && go fmt ./...); \
		echo "$(GREEN)  $$module formatted$(NC)"; \
	done
	@echo "$(GREEN)Todos los modulos formateados$(NC)"

.PHONY: fmt-check-all
fmt-check-all: ## Validar que todos los modulos esten formateados (no muta)
	@echo "$(BLUE)Validando formato en todos los modulos...$(NC)"
	@for module in $(MODULES); do \
		unformatted=$$(cd $$module && gofmt -l .); \
		if [ -n "$$unformatted" ]; then \
			echo "$(RED)Archivos sin formatear en $$module:$(NC)"; \
			echo "$$unformatted"; \
			exit 1; \
		fi; \
		echo "$(GREEN)  $$module formato OK$(NC)"; \
	done
	@echo "$(GREEN)Formato validado en todos los modulos$(NC)"

.PHONY: vet-all
vet-all: ## Ejecutar go vet en todos los modulos
	@echo "$(BLUE)Ejecutando go vet en todos los modulos...$(NC)"
	@for module in $(MODULES); do \
		echo "$(YELLOW)Vetting $$module...$(NC)"; \
		(cd $$module && go vet ./...) || exit 1; \
		echo "$(GREEN)  $$module vetted$(NC)"; \
	done
	@echo "$(GREEN)Todos los modulos pasaron go vet$(NC)"

.PHONY: tidy-all
tidy-all: ## Ejecutar go mod tidy en todos los modulos
	@echo "$(BLUE)Ejecutando go mod tidy en todos los modulos...$(NC)"
	@for module in $(MODULES); do \
		echo "$(YELLOW)Tidying $$module...$(NC)"; \
		(cd $$module && go mod tidy); \
		echo "$(GREEN)  $$module tidied$(NC)"; \
	done
	@echo "$(GREEN)Todos los modulos tidied$(NC)"

.PHONY: check-all
check-all: fmt-all vet-all lint-all test-all build-all ## Validacion completa de todos los modulos
	@echo "$(GREEN)Validacion completa exitosa$(NC)"

.PHONY: tools
tools: ## Instalar herramientas de CI (golangci-lint fijado a $(LINT_VERSION))
	@echo "$(YELLOW)Instalando golangci-lint $(LINT_VERSION)...$(NC)"
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(LINT_VERSION)
	@echo "$(GREEN)Herramientas instaladas$(NC)"

.PHONY: ci-local
ci-local: fmt-check-all vet-all lint-all test-all ## Pre-push: fmt + vet + lint + tests con herramientas locales
	@echo "$(GREEN)CI local OK$(NC)"

.PHONY: ci-docker
ci-docker: ## Simula el CI en Docker (Go $(GO_VERSION) + golangci-lint $(LINT_VERSION)) — requiere Docker
	@which docker > /dev/null 2>&1 || (echo "$(RED)Docker no instalado$(NC)" && exit 1)
	@echo "$(YELLOW)Ejecutando CI en Docker (Go $(GO_VERSION) + golangci-lint $(LINT_VERSION))...$(NC)"
	@docker run --rm \
		-e GOPRIVATE=github.com/EduGoGroup/* \
		-e GOFLAGS=-buildvcs=false \
		-v "$(HOME)/.netrc:/root/.netrc:ro" \
		-v "$$(go env GOPATH)/pkg/mod:/go/pkg/mod" \
		-v "$(CURDIR):/workspace" \
		-w /workspace \
		golang:$(GO_VERSION)-bookworm \
		bash -c "set -e; \
			curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b /usr/local/bin $(LINT_VERSION) && \
			make fmt-check-all vet-all lint-all test-all" \
		2>&1
	@echo "$(GREEN)CI Docker OK$(NC)"

.PHONY: changelog-module
changelog-module: ## Recordar donde registrar un cambio de modulo (MODULE=path)
	@if [ -z "$(MODULE)" ]; then \
		echo "$(RED)Uso: make changelog-module MODULE=auth$(NC)"; \
		exit 1; \
	fi
	@echo "$(YELLOW)Registra el cambio en $(MODULE)/CHANGELOG.md bajo [Unreleased]$(NC)"

.PHONY: release-module
release-module: ## Crear y empujar tag de release para un modulo (MODULE=path VERSION=vX.Y.Z)
	@if [ -z "$(MODULE)" ] || [ -z "$(VERSION)" ]; then \
		echo "$(RED)Uso: make release-module MODULE=auth VERSION=v0.1.0$(NC)"; \
		exit 1; \
	fi
	@$(MAKE) -C $(MODULE) release VERSION=$(VERSION)

.PHONY: clean-all
clean-all: ## Limpiar archivos generados en todos los modulos
	@echo "$(BLUE)Limpiando todos los modulos...$(NC)"
	@for module in $(MODULES); do \
		(cd $$module && rm -rf build coverage && go clean -testcache); \
	done
	@rm -rf build coverage
	@echo "$(GREEN)Limpieza completada$(NC)"

.PHONY: version
version: ## Mostrar versiones de herramientas
	@echo "$(BLUE)Versiones:$(NC)"
	@echo "Go: $$(go version)"
	@echo "Module: $(MODULE_NAME)"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "golangci-lint: $$(golangci-lint version 2>&1 | head -1)"; \
	else \
		echo "golangci-lint: no instalado"; \
	fi
