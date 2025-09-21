#!/usr/bin/env python
"""Pre-generation hooks for the cookiecutter template."""

import re
import sys


MODULE_REGEX = r'^[_a-zA-Z][_a-zA-Z0-9]+$'

module_name = '{{ cookiecutter.package_name }}'

if not re.match(MODULE_REGEX, module_name):
    print(f'ERROR: The project slug ({module_name}) is not a valid Python module name.')
    print('Please use only letters, numbers, and underscores. The name must start with a letter or underscore.')
    sys.exit(1)

# Validate Python version
python_version = '{{ cookiecutter.python_version }}'
try:
    major, minor = python_version.split('.')
    major, minor = int(major), int(minor)
    if major < 3 or (major == 3 and minor < 8):
        print(f'ERROR: Python version {python_version} is too old. Please use Python 3.8 or newer.')
        sys.exit(1)
except ValueError:
    print(f'ERROR: Invalid Python version format: {python_version}. Expected format: X.Y (e.g., 3.12)')
    sys.exit(1)

print(f"Creating project: {{ cookiecutter.project_name }}")
print(f"Project slug: {{ cookiecutter.project_slug }}")
print(f"Package name: {module_name}")
print(f"Python version: {python_version}")