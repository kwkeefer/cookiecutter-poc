#!/usr/bin/env python3
"""Simple process execution for POCs"""

import subprocess
import shlex


def run(cmd, timeout=30, input_data=None):
    """Run a command and return output

    Args:
        cmd: Command string or list
        timeout: Timeout in seconds
        input_data: Optional stdin data

    Returns:
        (stdout, stderr, returncode)

    Examples:
        # Run simple command
        stdout, stderr, code = run("echo 'test'")

        # Run with arguments
        stdout, stderr, code = run(["./exploit", "target.com", "1337"])

        # Send input to stdin
        stdout, stderr, code = run("./vulnapp", input_data=payload)

        # Check success
        stdout, stderr, code = run("./exploit")
        if code == 0:
            print(f"Success: {stdout}")
        else:
            print(f"Failed: {stderr}")
    """
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            input=input_data,
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode

    except subprocess.TimeoutExpired:
        return "", f"Timeout after {timeout}s", -1
    except Exception as e:
        return "", str(e), -1


if __name__ == "__main__":
    # Examples
    stdout, stderr, code = run("echo 'test'")
    print(f"Output: {stdout.strip()}")

    stdout, stderr, code = run(["ls", "-la", "/tmp"])
    print(f"Return code: {code}")

    # With input
    stdout, stderr, code = run("cat", input_data="hello world")
    print(f"Cat output: {stdout}")