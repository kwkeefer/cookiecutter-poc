.PHONY: help docs docs-serve docs-clean install-docs

help:
	@echo "Cookiecutter POC Template - Available Commands"
	@echo "================================================"
	@echo ""
	@echo "Documentation:"
	@echo "  make docs          Build Sphinx documentation"
	@echo "  make docs-serve    Build docs and start local HTTP server"
	@echo "  make docs-clean    Clean generated docs and example project"
	@echo "  make install-docs  Install documentation dependencies"
	@echo ""

install-docs:
	@echo "Installing documentation dependencies..."
	pip install -e ".[docs]"

docs: install-docs
	@echo "Building documentation..."
	@cd docs && make html
	@echo ""
	@echo "Documentation built successfully!"
	@echo "Open: docs/_build/html/index.html"

docs-serve: docs
	@echo "Starting documentation server on http://localhost:8000"
	@echo "Press Ctrl+C to stop"
	@cd docs/_build/html && python -m http.server 8000

docs-clean:
	@echo "Cleaning documentation..."
	@cd docs && make clean
	@echo "Documentation cleaned!"
