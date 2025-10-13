.PHONY: help dev clean bundle

help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

dev: ## Set up development environment
	uv sync --all-extras
	@echo "Ready! Run the POC with: uv run {{ cookiecutter.project_slug }}"

bundle: ## Create standalone POC file for exam submission
	@echo "Bundling POC into single file..."
	uv run python scripts/bundle.py
	@echo ""
	@echo "Bundle created! Include both files in your exam report:"
	@echo "  1. dist/poc_standalone.py (the POC code)"
	@echo "  2. dist/requirements.txt (dependencies to install)"
	@echo ""
	@echo "Assessor setup: pip install -r requirements.txt && python poc_standalone.py --help"

bundle-no-server: ## Create bundle without server.py
	@echo "Bundling POC (without server)..."
	uv run python scripts/bundle.py --no-server
	@echo ""
	@echo "Bundle created! Copy dist/poc_standalone.py into your exam report."

clean: ## Clean up generated files
	rm -rf __pycache__ .pytest_cache .ruff_cache dist
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -f logs/*.ndjson