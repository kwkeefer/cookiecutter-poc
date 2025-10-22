#!/usr/bin/env python3
"""
Simple zip utilities for POC projects.
Quick and dirty functions for zipping files and folders.

Note: All functions return Path objects (from pathlib).
      - Path objects work directly with most APIs expecting strings
      - To convert to string: str(zip_path)
      - Examples: zip_path = zip_file('test.txt')  # Returns Path
                 path_str = str(zip_path)         # Convert to string
"""

import zipfile
from pathlib import Path
from {{cookiecutter.project_slug}}.utils.output import out


def zip_file(file_path, output_path=None, name_in_zip=None):
    """
    Zip a single file (can be from another directory).

    Args:
        file_path: Path to the file to zip (str or Path)
        output_path: Where to save the zip (defaults to file_name.zip in current dir)
        name_in_zip: Name of file inside the zip (defaults to filename only)
                     Can include path traversal for zip slip: '../../../etc/crontab'
                     Maps to 'arcname' parameter in zipfile library

    Returns:
        Path to the created zip file

    Examples:
        zip_file('/etc/passwd', 'stolen_passwd.zip')
        zip_file('../secret.txt')  # Creates secret.zip in current dir

        # Zip slip - file extracts to ../../../evil.sh
        zip_file('payload.sh', 'malicious.zip', name_in_zip='../../../evil.sh')
    """
    file_path = Path(file_path)

    if not file_path.exists():
        out.error(f"File not found: {file_path}")
        return None

    if not file_path.is_file():
        out.error(f"Not a file: {file_path}")
        return None

    # Default output name: original_filename.zip in current directory
    if output_path is None:
        output_path = Path(file_path.name + '.zip')
    else:
        output_path = Path(output_path)

    # Default name_in_zip: just the filename (not full path)
    if name_in_zip is None:
        name_in_zip = file_path.name

    try:
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Add file with specified name inside the zip
            zf.write(file_path, arcname=name_in_zip)

        out.success(f"Zipped {file_path} -> {output_path}")
        out.info(f"Name in zip: {name_in_zip}")
        out.debug(f"Size: {output_path.stat().st_size} bytes")
        return output_path

    except Exception as e:
        out.error(f"Failed to zip file: {e}")
        return None


def zip_folder(folder_path, output_path=None):
    """
    Zip an entire folder (recursively).

    Args:
        folder_path: Path to the folder to zip (str or Path)
        output_path: Where to save the zip (defaults to folder_name.zip)

    Returns:
        Path to the created zip file

    Examples:
        zip_folder('/home/user/documents', 'exfil_docs.zip')
        zip_folder('../sensitive_data/')  # Creates sensitive_data.zip
    """
    folder_path = Path(folder_path)

    if not folder_path.exists():
        out.error(f"Folder not found: {folder_path}")
        return None

    if not folder_path.is_dir():
        out.error(f"Not a directory: {folder_path}")
        return None

    # Default output name: folder_name.zip
    if output_path is None:
        output_path = Path(folder_path.name + '.zip')
    else:
        output_path = Path(output_path)

    try:
        file_count = 0
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Walk through all files in the directory
            for file in folder_path.rglob('*'):
                if file.is_file():
                    # Get relative path from the folder being zipped
                    arcname = file.relative_to(folder_path)
                    zf.write(file, arcname=arcname)
                    file_count += 1
                    out.debug(f"Added: {arcname}")

        out.success(f"Zipped {folder_path} -> {output_path}")
        out.info(f"Packed {file_count} files, size: {output_path.stat().st_size} bytes")
        return output_path

    except Exception as e:
        out.error(f"Failed to zip folder: {e}")
        return None


def quick_zip(path, output=None):
    """
    Quick helper - automatically detects if path is file or folder and zips it.

    Args:
        path: Path to file or folder
        output: Output zip path (optional)

    Returns:
        Path to created zip file or None

    Examples:
        quick_zip('/etc/passwd')
        quick_zip('../important_stuff/')
    """
    path = Path(path)

    if path.is_file():
        return zip_file(path, output)
    elif path.is_dir():
        return zip_folder(path, output)
    else:
        out.error(f"Path doesn't exist or is not accessible: {path}")
        return None


def zip_multiple(paths, output_path="archive.zip", names_in_zip=None):
    """
    Zip multiple files/folders into a single archive.

    Args:
        paths: List of paths (can mix files and folders)
        output_path: Where to save the zip
        names_in_zip: Optional list of custom names for files in zip (must match paths length)
                      Can include path traversal for zip slip attacks
                      Maps to 'arcname' parameter in zipfile library
                      If None, uses default naming

    Returns:
        Path to created zip file or None

    Examples:
        # Normal usage
        zip_multiple(['/etc/passwd', '/etc/shadow'], 'exfil.zip')

        # With custom names (zip slip)
        zip_multiple(
            ['payload1.txt', 'payload2.txt'],
            'malicious.zip',
            names_in_zip=['../../../var/www/shell.php', '../../../../etc/cron.d/backdoor']
        )
    """
    output_path = Path(output_path)

    if names_in_zip is not None and len(names_in_zip) != len(paths):
        out.error(f"names_in_zip length ({len(names_in_zip)}) must match paths length ({len(paths)})")
        return None

    try:
        file_count = 0
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for idx, p in enumerate(paths):
                path = Path(p)

                if not path.exists():
                    out.warning(f"Skipping non-existent: {path}")
                    continue

                if path.is_file():
                    # Use custom name_in_zip if provided, otherwise use filename
                    arcname = names_in_zip[idx] if names_in_zip else path.name
                    zf.write(path, arcname=arcname)
                    file_count += 1
                    out.debug(f"Added file: {path.name} -> {arcname}")

                elif path.is_dir():
                    if names_in_zip:
                        out.warning(f"Skipping folder (names_in_zip only work with files): {path}")
                        continue
                    # Add folder with its name as prefix
                    for file in path.rglob('*'):
                        if file.is_file():
                            arcname = Path(path.name) / file.relative_to(path)
                            zf.write(file, arcname=arcname)
                            file_count += 1
                    out.debug(f"Added folder: {path.name}")

        out.success(f"Created archive: {output_path}")
        out.info(f"Packed {file_count} files, size: {output_path.stat().st_size} bytes")
        return output_path

    except Exception as e:
        out.error(f"Failed to create archive: {e}")
        return None


def extract_zip(zip_path, extract_to=None):
    """
    Extract a zip file (bonus utility).

    Args:
        zip_path: Path to the zip file
        extract_to: Where to extract (defaults to current dir)

    Returns:
        Path to extraction directory or None

    Examples:
        extract_zip('data.zip')
        extract_zip('archive.zip', '/tmp/extracted/')
    """
    zip_path = Path(zip_path)

    if not zip_path.exists() or not zip_path.is_file():
        out.error(f"Zip file not found: {zip_path}")
        return None

    if extract_to is None:
        extract_to = Path('.')
    else:
        extract_to = Path(extract_to)

    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(extract_to)
            file_list = zf.namelist()

        out.success(f"Extracted {len(file_list)} files to {extract_to}")
        return extract_to

    except Exception as e:
        out.error(f"Failed to extract: {e}")
        return None


if __name__ == "__main__":
    # Example usage
    print("=== Zip Utility Examples ===\n")

    # Example 1: Zip a single file
    print("1. Zipping a single file:")
    # zip_file('/etc/hosts', 'hosts_backup.zip')

    # Example 2: Zip a folder
    print("\n2. Zipping a folder:")
    # zip_folder('/home/user/documents', 'docs_archive.zip')

    # Example 3: Quick zip (auto-detect)
    print("\n3. Quick zip:")
    # quick_zip('/etc/passwd')

    # Example 4: Multiple files/folders
    print("\n4. Multiple items:")
    # zip_multiple(['/etc/passwd', '/home/user/.bashrc', '/tmp/data/'], 'combined.zip')

    print("\n[!] Uncomment examples to test")