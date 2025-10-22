Cookiecutter POC Template Documentation
=========================================

Welcome to the Cookiecutter POC Template documentation! This template helps you quickly create lean, fast Proof-of-Concept projects for security research and exploitation development.

The goal is **speed and simplicity** - get a working POC fast without unnecessary complexity.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   installation
   quickstart
   examples
   workflows
   api/index

Features
--------

* **Quick POC Creation** - Generate new projects in seconds
* **Built-in Utilities** - Common exploit patterns pre-implemented
* **HTTP Servers** - Log callbacks, serve payloads
* **Reverse Shell Management** - Generate and catch shells directly in Python
* **XSS & XXE Helpers** - Pre-built payload generators
* **Minimal Dependencies** - Keep it simple and fast

Quick Start
-----------

Generate a new POC project:

.. code-block:: bash

   uvx cookiecutter /path/to/this/template

Inside your generated project:

.. code-block:: bash

   make dev          # Setup environment
   make run          # Run the POC CLI
   python servers/server.py  # Start callback server

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
