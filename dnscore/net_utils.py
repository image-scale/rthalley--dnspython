"""Network address utilities.

Helper functions for working with IP addresses independent of version.
"""

import socket

from dnscore import ipv4, ipv6
from dnscore.exceptions import SyntaxError as DNSSyntaxError


AF_INET = socket.AF_INET
AF_INET6 = socket.AF_INET6


def address_family(text):
    """Determine the address family (AF_INET or AF_INET6) of a text address."""
    if ":" in text:
        return AF_INET6
    elif "." in text:
        return AF_INET
    raise DNSSyntaxError(f"cannot determine address family: {text!r}")


def is_address(text):
    """Return True if text is a valid IPv4 or IPv6 address."""
    return ipv4.is_valid(text) or ipv6.is_valid(text)


def canonicalize(text):
    """Return the canonical form of an IP address."""
    af = address_family(text)
    if af == AF_INET:
        return ipv4.canonicalize(text)
    else:
        return ipv6.canonicalize(text)
