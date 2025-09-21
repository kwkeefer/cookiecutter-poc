#!/usr/bin/env python3
"""Simple colored output utilities for POCs"""

from colorama import Fore, Style, init

# Initialize colorama
init()


class Output:
    """Simple colored output for POCs"""

    @staticmethod
    def success(msg):
        """Green [+] message"""
        print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")

    @staticmethod
    def error(msg):
        """Red [-] message"""
        print(f"{Fore.RED}[-] {msg}{Style.RESET_ALL}")

    @staticmethod
    def info(msg):
        """Blue [*] message"""
        print(f"{Fore.BLUE}[*] {msg}{Style.RESET_ALL}")

    @staticmethod
    def warning(msg):
        """Yellow [!] message"""
        print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")

    @staticmethod
    def debug(msg):
        """Magenta [DEBUG] message"""
        print(f"{Fore.MAGENTA}[DEBUG] {msg}{Style.RESET_ALL}")

    @staticmethod
    def status(msg):
        """Cyan [...] message"""
        print(f"{Fore.CYAN}[...] {msg}{Style.RESET_ALL}")

    @staticmethod
    def raw(msg, color=None):
        """Print with optional color, no prefix"""
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