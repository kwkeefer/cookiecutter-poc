cookiecutter-poc
================

A `cookiecutter <https://cookiecutter.readthedocs.io/en/stable/README.html>`_ template for rapid Proof-of-Concepts in web security research and exploit development.

**Focus on hacking, not boilerplate code.**

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   installation
   quickstart
   payloads
   examples
   workflows
   api/index

Features
--------

* **Quick POC Creation** - Generate new projects in seconds
* **Built-in Utilities** - Common exploit patterns
* **HTTP Servers** - Log callbacks, serve payloads
* **Reverse Shell Management** - Generate and catch shells directly in Python
* **XSS & XXE Helpers** - Pre-built payload generators

Quick Start
-----------

Generate a new POC project:

.. code-block:: bash

   uvx cookiecutter https://github.com/kwkeefer/cookiecutter-poc

Inside your generated project:

.. code-block:: bash

   cd your_project
   uv run your_project --help       # Run the POC CLI
   uv run your_project --server     # Start HTTP callback server

Philosophy
----------

This template follows the **KISS Principle** (Keep It Simple, Stupid):

* Quick POC creation over robustness
* Minimal dependencies over feature-richness
* Clear, direct code over abstractions
* Working exploits over perfect code

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
