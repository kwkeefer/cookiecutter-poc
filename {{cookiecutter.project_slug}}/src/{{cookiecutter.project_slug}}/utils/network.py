#!/usr/bin/env python3

import netifaces


def get_interfaces():
    """Get network interfaces and their IPv4 addresses."""
    interfaces = {}

    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)

        if netifaces.AF_INET in addrs:
            ipv4_info = addrs[netifaces.AF_INET][0]
            ip_address = ipv4_info.get('addr')

            if ip_address:
                interfaces[iface] = ip_address

    return interfaces


def get_local_ip(exclude_loopback=True):
    """Get the primary local IP address."""
    interfaces = get_interfaces()

    if exclude_loopback and 'lo' in interfaces:
        del interfaces['lo']

    for iface, ip in interfaces.items():
        if not ip.startswith('127.'):
            return ip

    return '127.0.0.1'


def get_callback_host():
    """Get the best callback host address (prefer tun0)."""
    interfaces = get_interfaces()

    # Prefer tun0 if available (VPN connection)
    if 'tun0' in interfaces:
        return interfaces['tun0']

    # Otherwise, find first non-loopback interface
    for iface, ip in interfaces.items():
        if not ip.startswith('127.') and iface != 'lo':
            return ip

    # Fallback to localhost
    return '127.0.0.1'