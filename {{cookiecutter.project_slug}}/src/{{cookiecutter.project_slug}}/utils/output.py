#!/usr/bin/env python3
"""
Simple colored output utilities for POCs.

This module provides colored console output to make POC execution
more readable and easier to debug. Use instead of print() statements.
"""

from colorama import Fore, Style, init

# Initialize colorama
init()


class Output:
    """
    Simple colored output for POCs.

    Provides static methods for different types of console messages
    with color coding and prefixes for better visibility.

    Attributes:
        verbose (bool): Class variable controlling debug output visibility
    """

    verbose = False

    @classmethod
    def set_verbose(cls, enabled: bool):
        """
        Enable or disable verbose (debug) output.

        Args:
            enabled: True to show debug messages, False to hide them

        Examples:
            >>> from utils.output import Output
            >>> Output.set_verbose(True)
            >>> out.debug("This will now be visible")
        """
        cls.verbose = enabled

    @staticmethod
    def success(msg):
        """
        Print a success message in green with [+] prefix.

        Args:
            msg: Message to display

        Examples:
            >>> out.success("Target is vulnerable!")
            >>> [+] Target is vulnerable!  # (in green)
        """
        print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")

    @staticmethod
    def error(msg):
        """
        Print an error message in red with [-] prefix.

        Args:
            msg: Error message to display

        Examples:
            >>> out.error("Connection failed")
            >>> [-] Connection failed  # (in red)
        """
        print(f"{Fore.RED}[-] {msg}{Style.RESET_ALL}")

    @staticmethod
    def info(msg):
        """
        Print an info message in blue with [*] prefix.

        Args:
            msg: Info message to display

        Examples:
            >>> out.info("Starting exploit")
            >>> [*] Starting exploit  # (in blue)
        """
        print(f"{Fore.BLUE}[*] {msg}{Style.RESET_ALL}")

    @staticmethod
    def warning(msg):
        """
        Print a warning message in yellow with [!] prefix.

        Args:
            msg: Warning message to display

        Examples:
            >>> out.warning("Using default credentials")
            >>> [!] Using default credentials  # (in yellow)
        """
        print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")

    @staticmethod
    def debug(msg):
        """
        Print a debug message in magenta with [DEBUG] prefix.

        Only prints if verbose mode is enabled via Output.set_verbose(True).

        Args:
            msg: Debug message to display

        Examples:
            >>> Output.set_verbose(True)
            >>> out.debug("Response: 200 OK")
            >>> [DEBUG] Response: 200 OK  # (in magenta)
            >>>
            >>> Output.set_verbose(False)
            >>> out.debug("This won't print")
            >>> # (no output)
        """
        if Output.verbose:
            print(f"{Fore.MAGENTA}[DEBUG] {msg}{Style.RESET_ALL}")

    @staticmethod
    def status(msg):
        """
        Print a status message in cyan with [...] prefix.

        Args:
            msg: Status message to display

        Examples:
            >>> out.status("Extracting data...")
            >>> [...] Extracting data...  # (in cyan)
        """
        print(f"{Fore.CYAN}[...] {msg}{Style.RESET_ALL}")

    @staticmethod
    def raw(msg, color=None):
        """
        Print a message with no prefix and optional color.

        Args:
            msg: Message to print
            color: Optional colorama color (e.g., Fore.RED)

        Examples:
            >>> out.raw("Plain text")
            >>> Plain text
            >>> out.raw("Colored text", Fore.MAGENTA)
            >>> Colored text  # (in magenta)
        """
        if color:
            print(f"{color}{msg}{Style.RESET_ALL}")
        else:
            print(msg)


# Convenience shortcuts
out = Output()


if __name__ == "__main__":
    # Examples
    print("=== Standard Output ===")
    out.success("Target is vulnerable!")
    out.error("Connection failed")
    out.info("Starting exploit")
    out.warning("Using default credentials")
    out.status("Extracting data...")
    out.raw("No prefix here")
    out.raw("Custom color", Fore.MAGENTA)

    print("\n=== Debug Output (verbose=False) ===")
    out.debug("This debug message won't appear")

    print("\n=== Debug Output (verbose=True) ===")
    Output.set_verbose(True)
    out.debug("Response: 200 OK")
    out.debug("Headers: {'Content-Type': 'application/json'}")