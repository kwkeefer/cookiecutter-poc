#!/usr/bin/env python3
"""
Bundle POC into a single standalone file for exam submission.

This script traces all dependencies from exploit.py and cli.py,
inlines the used utility modules, and produces a single file.
"""

import ast
import sys
from pathlib import Path
from collections import defaultdict
from typing import Set, Dict, List, Tuple

# Get standard library module names (Python 3.10+)
STDLIB_MODULES = sys.stdlib_module_names if hasattr(sys, 'stdlib_module_names') else set()

# Known third-party packages used in POC template
KNOWN_PACKAGES = {
    'requests': 'requests',
    'httpx': 'httpx',
    'colorama': 'colorama',
    'bs4': 'beautifulsoup4',
    'beautifulsoup4': 'beautifulsoup4',
    'netifaces': 'netifaces',
    'urllib3': 'urllib3',
    'retrying': 'retrying',
    'Crypto': 'pycryptodome',
}


class DependencyTracer(ast.NodeVisitor):
    """AST visitor to find imports from our project package"""

    def __init__(self, package_name: str):
        self.package_name = package_name
        self.internal_imports: Set[str] = set()  # e.g., 'utils.output', 'servers.server'
        self.external_imports: List[Tuple[str, str]] = []  # (import_line, module_name)
        self.from_imports: Dict[str, Set[str]] = defaultdict(set)  # module -> {names}

    def visit_Import(self, node):
        """Handle: import foo"""
        for alias in node.names:
            module = alias.name
            if not module.startswith(self.package_name):
                # External import
                as_name = f" as {alias.asname}" if alias.asname else ""
                self.external_imports.append((f"import {module}{as_name}", module))
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        """Handle: from foo import bar"""
        if node.module is None:
            return

        # Check if it's an internal import
        if node.module.startswith(self.package_name):
            # Strip package name: 'poc.utils.output' -> 'utils.output'
            relative_module = node.module[len(self.package_name) + 1:]
            self.internal_imports.add(relative_module)

            # Track what's imported from this module
            for alias in node.names:
                name = alias.name
                if name != '*':
                    self.from_imports[relative_module].add(name)
        else:
            # External import - preserve the full import line
            names = ', '.join(
                f"{alias.name}" + (f" as {alias.asname}" if alias.asname else "")
                for alias in node.names
            )
            self.external_imports.append((f"from {node.module} import {names}", node.module))

        self.generic_visit(node)


def find_all_dependencies(
    start_modules: List[str],
    package_name: str,
    src_root: Path
) -> Tuple[Set[str], List[Tuple[str, str]]]:
    """
    Recursively find all internal dependencies starting from given modules.

    Returns:
        (internal_modules, external_imports)
    """
    internal_modules = set()
    all_external_imports = []
    to_process = list(start_modules)
    processed = set()

    while to_process:
        module_path = to_process.pop(0)

        if module_path in processed:
            continue
        processed.add(module_path)
        internal_modules.add(module_path)

        # Find the actual file
        module_rel_path = module_path.replace('.', '/')
        file_path = src_root / f"{module_rel_path}.py"
        if not file_path.exists():
            # Try __init__.py
            file_path = src_root / module_rel_path / '__init__.py'

        if not file_path.exists():
            print(f"Warning: Could not find {file_path}", file=sys.stderr)
            continue

        # Parse the file
        with open(file_path) as f:
            try:
                tree = ast.parse(f.read(), filename=str(file_path))
            except SyntaxError as e:
                print(f"Warning: Syntax error in {file_path}: {e}", file=sys.stderr)
                continue

        # Find imports
        tracer = DependencyTracer(package_name)
        tracer.visit(tree)

        # Add external imports
        all_external_imports.extend(tracer.external_imports)

        # Add internal imports to process queue
        for internal_import in tracer.internal_imports:
            if internal_import not in processed:
                to_process.append(internal_import)

    return internal_modules, all_external_imports


def read_module_source(module_path: str, src_root: Path) -> str:
    """Read the source code of a module, stripping imports and docstrings"""
    module_rel_path = module_path.replace('.', '/')
    file_path = src_root / f"{module_rel_path}.py"
    if not file_path.exists():
        file_path = src_root / module_rel_path / '__init__.py'

    with open(file_path) as f:
        source = f.read()

    # Parse and remove imports
    tree = ast.parse(source)

    # Find the line ranges to keep
    # We'll strip: shebang, imports, module docstring, __main__ blocks
    lines = source.split('\n')

    # Skip shebang
    start_line = 0
    if lines and lines[0].startswith('#!'):
        start_line = 1

    # Find first non-import, non-docstring statement
    imports_end = start_line
    found_docstring = False
    main_block_start = None

    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            imports_end = max(imports_end, node.end_lineno)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and not found_docstring:
            # Module docstring
            imports_end = max(imports_end, node.end_lineno)
            found_docstring = True
        elif isinstance(node, ast.If):
            # Check if this is "if __name__ == '__main__':"
            if (isinstance(node.test, ast.Compare) and
                isinstance(node.test.left, ast.Name) and
                node.test.left.id == '__name__'):
                main_block_start = node.lineno
                break
        else:
            pass

    # Get lines from after imports to before __main__ block
    if main_block_start:
        code_lines = lines[imports_end:main_block_start - 1]
    else:
        code_lines = lines[imports_end:]

    # Strip leading empty lines
    while code_lines and not code_lines[0].strip():
        code_lines.pop(0)

    # Strip trailing empty lines
    while code_lines and not code_lines[-1].strip():
        code_lines.pop()

    return '\n'.join(code_lines)


def get_package_name(module_name: str) -> str:
    """Extract top-level package name from module path"""
    # 'requests.adapters' -> 'requests'
    # 'bs4.element' -> 'bs4'
    return module_name.split('.')[0]


def get_third_party_packages(external_imports: List[Tuple[str, str]]) -> Set[str]:
    """
    Filter external imports to only third-party packages (not stdlib).

    Returns set of package names suitable for requirements.txt
    """
    third_party = set()

    for _, module_name in external_imports:
        pkg_name = get_package_name(module_name)

        # Skip if it's stdlib
        if pkg_name in STDLIB_MODULES:
            continue

        # Map to pypi package name if known
        if pkg_name in KNOWN_PACKAGES:
            third_party.add(KNOWN_PACKAGES[pkg_name])
        else:
            # Unknown package, use module name as-is
            third_party.add(pkg_name)

    return third_party


def bundle_poc(
    project_root: Path,
    package_name: str,
    include_server: bool = True,
    output_file: Path = None
) -> str:
    """
    Bundle the POC into a single file.

    Args:
        project_root: Root of the project
        package_name: Name of the package (project slug)
        include_server: Whether to include server.py
        output_file: Where to write the output (default: dist/poc_standalone.py)
    """
    src_root = project_root / 'src' / package_name

    # Start with exploit.py and cli.py
    start_modules = ['exploit', 'cli']

    # Optionally add server
    if include_server:
        start_modules.append('servers.server')

    print(f"[*] Tracing dependencies from: {', '.join(start_modules)}")

    # Find all dependencies
    internal_modules, external_imports = find_all_dependencies(
        start_modules,
        package_name,
        src_root
    )

    print(f"[*] Found {len(internal_modules)} internal modules")
    print(f"[*] Found {len(set(imp[1] for imp in external_imports))} external imports")

    # Deduplicate external imports while preserving order
    seen_modules = set()
    unique_external = []
    for import_line, module in external_imports:
        if module not in seen_modules:
            seen_modules.add(module)
            unique_external.append(import_line)

    # Build the output
    output_parts = []

    # Header
    output_parts.append('#!/usr/bin/env python3')
    output_parts.append('"""')
    output_parts.append(f'Standalone POC bundle - generated by bundle.py')
    output_parts.append('"""')
    output_parts.append('')

    # External imports
    output_parts.append('# External imports')
    for import_line in sorted(set(unique_external)):
        output_parts.append(import_line)
    output_parts.append('')

    # Disable SSL warnings (common in POCs)
    if 'requests' in seen_modules:
        output_parts.append('# Disable SSL warnings')
        output_parts.append('import urllib3')
        output_parts.append('urllib3.disable_warnings()')
        output_parts.append('')

    # Sort modules for logical ordering
    # Priority: paths -> output -> network -> others -> server -> cli -> exploit
    priority_order = [
        'utils.paths',
        'utils.output',
        'utils.network',
        'utils.encoding',
        'utils.cookie',
        'utils.timing',
        'utils.process',
        'utils.html_parser',
        'utils.file_upload',
        'utils.batch_request',
        'utils.xss',
        'utils.xxe',
        'utils.reverse_shells',
        'utils.shell_catcher',
        'utils.zip_util',
        'utils.server_hooks',
        'servers.server',
        'cli',
        'exploit',
    ]

    sorted_modules = []
    for module in priority_order:
        if module in internal_modules:
            sorted_modules.append(module)

    # Add any remaining modules
    for module in sorted(internal_modules):
        if module not in sorted_modules:
            sorted_modules.append(module)

    # Inline each module
    for module_path in sorted_modules:
        # Skip __init__.py modules (usually empty or just version info)
        if module_path.endswith('.__init__') or module_path == '__init__' or '.' not in module_path and module_path not in ['cli', 'exploit']:
            # Check if it's just a package marker
            module_rel_path = module_path.replace('.', '/')
            file_path = src_root / f"{module_rel_path}.py"
            if not file_path.exists():
                file_path = src_root / module_rel_path / '__init__.py'
            if file_path.exists():
                content = file_path.read_text()
                # Only include if it has substantial content (not just imports/docstrings/__version__)
                if content.count('\n') > 10 or 'def ' in content or 'class ' in content:
                    pass  # Include it
                else:
                    continue  # Skip it

        print(f"[*] Inlining {module_path}")

        output_parts.append(f'# ==== {module_path} ====')
        output_parts.append('')

        source = read_module_source(module_path, src_root)

        # Special handling for specific modules
        if module_path == 'utils.paths':
            # Fix PROJECT_ROOT calculation for standalone bundle
            source = source.replace(
                'PROJECT_ROOT = Path(__file__).parent.parent.parent.parent',
                'PROJECT_ROOT = Path(__file__).parent.absolute()  # Standalone bundle'
            )
        elif module_path == 'cli':
            # Fix server module reference
            source = source.replace(
                'server_args = argparse.Namespace(port=args.port, bind=\'0.0.0.0\')\n            server.main_with_args(server_args)',
                'server_args = argparse.Namespace(port=args.port, bind=\'0.0.0.0\')\n            main_with_args(server_args)  # server module inlined'
            )
            # Fix __version__ reference
            source = source.replace(
                'version=f"%(prog)s {__version__}"',
                'version=f"%(prog)s 0.1.0"  # version inlined'
            )

        # Replace internal imports with comments (they're already inlined)
        source_lines = source.split('\n')
        cleaned_lines = []
        for line in source_lines:
            stripped = line.strip()
            if stripped.startswith(('from ' + package_name, 'import ' + package_name)):
                # Comment out internal imports
                cleaned_lines.append('# ' + line + '  # (inlined)')
            else:
                cleaned_lines.append(line)

        output_parts.append('\n'.join(cleaned_lines))
        output_parts.append('')

    # Add main entry point
    output_parts.append('# ==== Entry Point ====')
    output_parts.append('')
    output_parts.append('if __name__ == "__main__":')
    output_parts.append('    main()')

    bundle_content = '\n'.join(output_parts)

    # Write to file
    if output_file is None:
        output_file = project_root / 'dist' / 'poc_standalone.py'

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(bundle_content)

    print(f"[+] Bundle written to: {output_file}")
    print(f"[+] Total size: {len(bundle_content)} bytes ({len(bundle_content.split())} lines)")

    # Generate requirements.txt
    third_party_packages = get_third_party_packages(external_imports)
    if third_party_packages:
        requirements_file = output_file.parent / 'requirements.txt'
        requirements_content = '\n'.join(sorted(third_party_packages)) + '\n'
        requirements_file.write_text(requirements_content)
        print(f"[+] Requirements written to: {requirements_file}")
        print(f"[+] Dependencies: {', '.join(sorted(third_party_packages))}")
    else:
        print(f"[*] No third-party dependencies found")

    return bundle_content


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='Bundle POC into standalone file')
    parser.add_argument(
        '--no-server',
        action='store_true',
        help='Exclude server.py from bundle'
    )
    parser.add_argument(
        '--output', '-o',
        type=Path,
        help='Output file path (default: dist/poc_standalone.py)'
    )

    args = parser.parse_args()

    # Find project root (assumes we're in scripts/ directory)
    project_root = Path(__file__).parent.parent

    # Try to detect package name from pyproject.toml
    pyproject = project_root / 'pyproject.toml'
    if pyproject.exists():
        import tomllib
        with open(pyproject, 'rb') as f:
            config = tomllib.load(f)
            package_name = config.get('project', {}).get('name', '').replace('-', '_')
    else:
        # Fallback: look for src/* directory
        src_dirs = list((project_root / 'src').iterdir())
        if src_dirs:
            package_name = src_dirs[0].name
        else:
            print("[!] Could not detect package name", file=sys.stderr)
            sys.exit(1)

    print(f"[*] Package name: {package_name}")
    print(f"[*] Project root: {project_root}")

    bundle_poc(
        project_root=project_root,
        package_name=package_name,
        include_server=not args.no_server,
        output_file=args.output
    )


if __name__ == '__main__':
    main()
