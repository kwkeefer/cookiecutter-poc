# Cookiecutter POC Template

A minimal Python cookiecutter template for quickly creating Proof of Concept (POC) exploits and security tools. Built for speed and simplicity - no unnecessary complexity.

## Quick Start

```bash
# Install uv (if needed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Generate a new POC project
uvx cookiecutter https://github.com/kwkeefer/cookiecutter-poc

# Run it
cd your_project
uv run your_project --help
```

## Features

- **KISS principle** - Keep It Simple, Stupid
- **Built-in HTTP server** - Log callbacks and serve payloads
- **Utility modules** - Encoding, shells, XSS, file uploads, and more
- **Ready-to-use payloads** - Webshells, XSS, reverse shells
- **Simple CLI** - Argparse-based with colored output

## Documentation

Full documentation available at: **https://cookiecutter-poc.readthedocs.io/en/latest/**

- [Installation Guide](https://cookiecutter-poc.readthedocs.io/en/latest/installation.html)
- [Quick Start Tutorial](https://cookiecutter-poc.readthedocs.io/en/latest/quickstart.html)
- [Examples & Patterns](https://cookiecutter-poc.readthedocs.io/en/latest/examples.html)
- [API Reference](https://cookiecutter-poc.readthedocs.io/en/latest/api/index.html)

## Disclaimer

**This software is intended for authorized security testing and research purposes only.**

Use responsibly and only on systems you have explicit permission to test. Unauthorized access to computer systems is illegal. Don't use this to hack stuff you're not supposed to be hacking. Don't do dumb stuff.

The authors are not responsible for misuse or for any damage caused by this software.

## License

MIT