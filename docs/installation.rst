Installation
============

Getting started with the Cookiecutter POC Template.

Prerequisites
-------------

* Python 3.12 or higher
* ``cookiecutter`` installed (via uvx or pip)

Quick Install
-------------

Using uvx (recommended):

.. code-block:: bash

   uvx cookiecutter https://github.com/kwkeefer/cookiecutter-poc

Or using pip:

.. code-block:: bash

   pip install cookiecutter
   cookiecutter https://github.com/kwkeefer/cookiecutter-poc

From Local Template
-------------------

If you have the template cloned locally:

.. code-block:: bash

   uvx cookiecutter /path/to/cookiecutter-poc

Template Prompts
----------------

When you run cookiecutter, you'll be prompted for:

* **full_name**: Your name (for project metadata)
* **github_username**: Your GitHub username
* **project_name**: Human-readable project name (e.g., "HTB Admirer POC")
* **project_slug**: Python package name (auto-generated from project_name)
* **target_url**: Default target URL (can be changed later)
* **version**: Project version (default: 0.1.0)
* **python_version**: Python version requirement (default: 3.14)

Generated Project Structure
----------------------------

After generation, you'll have:

.. code-block:: text

   your_project/
   ├── src/
   │   └── your_project/
   │       ├── cli.py              # CLI entry point
   │       ├── exploit.py          # Your exploit code goes here
   │       ├── utils/              # Utility modules
   │       │   ├── output.py
   │       │   ├── reverse_shells.py
   │       │   ├── shell_catcher.py
   │       │   └── ...
   │       └── servers/
   │           └── server.py       # HTTP callback server
   ├── payloads/                   # Files to serve (XSS, shells, etc)
   ├── logs/                       # Server logs
   ├── tests/                      # Tests (optional)
   ├── pyproject.toml              # Project configuration
   └── Makefile                    # Convenient commands

Setup Your Project
------------------

After generating a project:

.. code-block:: bash

   cd your_project
   make dev          # Creates venv, installs dependencies
   source .venv/bin/activate  # Or: .venv\\Scripts\\activate on Windows

Verify Installation
-------------------

Test that everything works:

.. code-block:: bash

   # Run the CLI
   make run

   # Or directly:
   python -m your_project --help

   # Start the server
   python -m your_project.servers.server

Next Steps
----------

* Read the :doc:`quickstart` guide
* Browse :doc:`examples` for common patterns
* Check the :doc:`api/index` for detailed documentation
