#!/usr/bin/env python
"""Post-generation hooks for the POC template."""

import os
import subprocess
import sys
from pathlib import Path


def run_command(cmd, description):
    """Run a shell command."""
    print(f"{description}...")
    try:
        subprocess.run(cmd, shell=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Warning: {description} failed: {e}")
        return False


def main():
    """Execute post-generation tasks."""
    print("\n" + "="*50)
    print("Setting up your POC project...")
    print("="*50)

    # Initialize git repository
    if not Path('.git').exists():
        run_command('git init', 'Initializing git repository')
        run_command('git add .', 'Adding files to git')
        run_command('git commit -m "Initial POC setup"', 'Creating initial commit')

    # Check if uv is available
    if subprocess.run(['which', 'uv'], capture_output=True).returncode == 0:
        print("\n✓ uv is installed")
        print("\nNext steps:")
        print("1. cd {{ cookiecutter.project_slug }}")
        print("2. make dev                    # Install dependencies")
        print("3. uv run {{ cookiecutter.project_slug }} --server   # Start callback server")
        print("4. uv run {{ cookiecutter.project_slug }} -t TARGET  # Run exploit")
    else:
        print("\n⚠ uv is not installed")
        print("\nInstall uv:")
        print("  curl -LsSf https://astral.sh/uv/install.sh | sh")
        print("\nOr use pip with venv:")
        print("1. cd {{ cookiecutter.project_slug }}")
        print("2. python -m venv venv")
        print("3. source venv/bin/activate")
        print("4. pip install -e .")

    print("\n" + "="*50)
    print("✨ POC template ready!")
    print("="*50)
    print("\nEdit src/{{ cookiecutter.package_name }}/exploit.py to add your exploit code")
    print("Drop payloads in payloads/ directory")
    print("Check logs in logs/server.ndjson")
    print("\nHappy hacking! 🚀")


if __name__ == '__main__':
    main()