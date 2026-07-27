# Modulo auth - Makefile
# Contrato de targets comun a todos los modulos de identity-shared.

MODULE_NAME = github.com/EduGoGroup/identity-shared/auth
MODULE_PATH = auth

GREEN = \033[0;32m
YELLOW = \033[0;33m
RED = \033[0;31m
BLUE = \033[0;34m
NC = \033[0m

.DEFAULT_GOAL := help

.PHONY: help
help: ## Mostrar ayuda de comandos disponibles
	@echo "$(BLUE)$(MODULE_NAME) - Comandos disponibles:$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

.PHONY: build
build: ## Verificar que el modulo compila
	@go build ./...
	@echo "$(GREEN)$(MODULE_PATH) compilado$(NC)"

.PHONY: test
test: ## Ejecutar tests unitarios
	@go test -short -v ./...

.PHONY: test-race
test-race: ## Ejecutar tests con race detection
	@go test -short -race -v ./...

.PHONY: test-integration
test-integration: ## Ejecutar tests de integracion
	@INTEGRATION_TESTS=true go test -v -cover -timeout 10m ./...

.PHONY: coverage
coverage: ## Generar reporte de cobertura en coverage/
	@mkdir -p coverage
	@go test -short -race -coverprofile=coverage/coverage.out -covermode=atomic ./...
	@go tool cover -func=coverage/coverage.out | tail -1

.PHONY: fmt
fmt: ## Formatear el codigo del modulo
	@go fmt ./...
	@echo "$(GREEN)$(MODULE_PATH) formateado$(NC)"

.PHONY: fmt-check
fmt-check: ## Validar el formato sin mutar archivos
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "$(RED)Archivos sin formatear:$(NC)"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	@echo "$(GREEN)$(MODULE_PATH) formato OK$(NC)"

.PHONY: vet
vet: ## Ejecutar go vet
	@go vet ./...
	@echo "$(GREEN)$(MODULE_PATH) vetted$(NC)"

.PHONY: lint
lint: ## Ejecutar golangci-lint
	@golangci-lint run ./...
	@echo "$(GREEN)$(MODULE_PATH) linted$(NC)"

.PHONY: tidy
tidy: ## Ejecutar go mod tidy
	@go mod tidy
	@echo "$(GREEN)$(MODULE_PATH) tidied$(NC)"

.PHONY: ci-local
ci-local: fmt-check vet lint test ## Pre-push del modulo: fmt + vet + lint + tests
	@echo "$(GREEN)CI local OK ($(MODULE_PATH))$(NC)"

.PHONY: release-check
release-check: fmt-check vet lint test-race build ## Validacion completa previa a un release
	@echo "$(GREEN)$(MODULE_PATH) listo para release$(NC)"

.PHONY: release
release: release-check ## Crear y empujar el tag del modulo (VERSION=vX.Y.Z)
	@if [ -z "$(VERSION)" ]; then \
		echo "$(RED)Uso: make release VERSION=v0.1.0$(NC)"; \
		exit 1; \
	fi
	@echo "$(YELLOW)Recuerda: nunca re-taguees una version existente; sube el numero.$(NC)"
	@git tag -a "$(MODULE_PATH)/$(VERSION)" -m "Release $(MODULE_PATH) $(VERSION)"
	@git push origin "$(MODULE_PATH)/$(VERSION)"
	@echo "$(GREEN)Tag $(MODULE_PATH)/$(VERSION) publicado$(NC)"

.PHONY: clean
clean: ## Limpiar archivos generados
	@rm -rf build coverage
	@go clean -testcache
	@echo "$(GREEN)$(MODULE_PATH) limpio$(NC)"
