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
    """

    @staticmethod
    def success(msg):
        """
        Print a success message in green with [+] prefix.

        Args:
            msg: Message to display

        Example:
            >>> out.success("Target is vulnerable!")
            [+] Target is vulnerable!  # (in green)
        """
        print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")

    @staticmethod
    def error(msg):
        """
        Print an error message in red with [-] prefix.

        Args:
            msg: Error message to display

        Example:
            >>> out.error("Connection failed")
            [-] Connection failed  # (in red)
        """
        print(f"{Fore.RED}[-] {msg}{Style.RESET_ALL}")

    @staticmethod
    def info(msg):
        """
        Print an info message in blue with [*] prefix.

        Args:
            msg: Info message to display

        Example:
            >>> out.info("Starting exploit")
            [*] Starting exploit  # (in blue)
        """
        print(f"{Fore.BLUE}[*] {msg}{Style.RESET_ALL}")

    @staticmethod
    def warning(msg):
        """
        Print a warning message in yellow with [!] prefix.

        Args:
            msg: Warning message to display

        Example:
            >>> out.warning("Using default credentials")
            [!] Using default credentials  # (in yellow)
        """
        print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")

    @staticmethod
    def debug(msg):
        """
        Print a debug message in magenta with [DEBUG] prefix.

        Args:
            msg: Debug message to display

        Example:
            >>> out.debug("Response: 200 OK")
            [DEBUG] Response: 200 OK  # (in magenta)
        """
        print(f"{Fore.MAGENTA}[DEBUG] {msg}{Style.RESET_ALL}")

    @staticmethod
    def status(msg):
        """
        Print a status message in cyan with [...] prefix.

        Args:
            msg: Status message to display

        Example:
            >>> out.status("Extracting data...")
            [...] Extracting data...  # (in cyan)
        """
        print(f"{Fore.CYAN}[...] {msg}{Style.RESET_ALL}")

    @staticmethod
    def raw(msg, color=None):
        """
        Print a message with no prefix and optional color.

        Args:
            msg: Message to print
            color: Optional colorama color (e.g., Fore.RED)

        Example:
            >>> out.raw("Plain text")
            Plain text
            >>> out.raw("Colored text", Fore.MAGENTA)
            Colored text  # (in magenta)
        """
        if color:
            print(f"{color}{msg}{Style.RESET_ALL}")
        else:
            print(msg)


# Convenience shortcuts
out = Output()


if __name__ == "__main__":
    # Examples
    out.success("Target is vulnerable!")
    out.error("Connection failed")
    out.info("Starting exploit")
    out.warning("Using default credentials")
    out.debug("Response: 200 OK")
    out.status("Extracting data...")
    out.raw("No prefix here")
    out.raw("Custom color", Fore.MAGENTA)