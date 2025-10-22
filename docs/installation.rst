Installation
============

Getting started with ``cookiecutter-poc``.

Prerequisites
-------------

* Python 3.12 or higher
* `uv <https://docs.astral.sh/uv/>`_ installed (provides uvx and package management)

Install uv:

.. code-block:: bash

   # macOS/Linux
   curl -LsSf https://astral.sh/uv/install.sh | sh

   # Or with pip
   pip install uv

   # Or with brew (macOS)
   brew install uv

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
   └── pyproject.toml              # Project configuration

Run Your Project
----------------

No setup needed! Just run it:

.. code-block:: bash

   # Run the CLI
   uv run your_project --help

   # Start the callback server
   uv run your_project --server

   # Run against a target
   uv run your_project --target http://target.local

Next Steps
----------

* Read the :doc:`quickstart` guide
* Browse :doc:`examples` for common patterns
* Check the :doc:`api/index` for detailed documentation
