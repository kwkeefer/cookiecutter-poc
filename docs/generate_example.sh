#!/usr/bin/env bash
# Generate example POC project for Sphinx documentation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_DIR="$(dirname "$SCRIPT_DIR")"

# Remove old generated example if it exists
if [ -d "$SCRIPT_DIR/your_project" ]; then
    echo "Removing old your_project..."
    rm -rf "$SCRIPT_DIR/your_project"
fi

echo "Generating example project for documentation..."

# Generate project with cookiecutter using no-input mode
# This creates a real, importable Python project for Sphinx to document
cd "$SCRIPT_DIR"
uvx cookiecutter "$TEMPLATE_DIR" --no-input \
    project_name="Your Project" \
    project_slug="your_project" \
    target_url="http://target.local" \
    version="0.1.0" \
    python_version="3.12"

echo "Example project generated at: $SCRIPT_DIR/your_project"
echo "Sphinx can now import from: your_project/src/your_project"
