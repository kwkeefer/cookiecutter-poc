#!/usr/bin/env bash
# Generate example POC project for Sphinx documentation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_DIR="$(dirname "$SCRIPT_DIR")"

# Remove old generated example if it exists
if [ -d "$SCRIPT_DIR/poc_example" ]; then
    echo "Removing old poc_example..."
    rm -rf "$SCRIPT_DIR/poc_example"
fi

echo "Generating example project for documentation..."

# Generate project with cookiecutter using no-input mode
# This creates a real, importable Python project for Sphinx to document
cd "$SCRIPT_DIR"
cookiecutter "$TEMPLATE_DIR" --no-input \
    full_name="Example User" \
    github_username="example" \
    project_name="POC Example" \
    project_slug="poc_example" \
    target_url="http://target.local" \
    version="0.1.0" \
    python_version="3.12"

echo "Example project generated at: $SCRIPT_DIR/poc_example"
echo "Sphinx can now import from: poc_example/src/poc_example"
