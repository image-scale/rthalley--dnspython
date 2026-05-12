"""Reverse DNS name conversion.

Converts between IP addresses and their reverse-map DNS names:
IPv4 addresses map to in-addr.arpa, IPv6 addresses map to ip6.arpa.
"""

import binascii

from dnscore.domain_name import DomainName, from_text as name_from_text
from dnscore.ipv4 import text_to_binary as ipv4_to_binary, binary_to_text as ipv4_to_text
from dnscore.ipv6 import text_to_binary as ipv6_to_binary, binary_to_text as ipv6_to_text
from dnscore.exceptions import SyntaxError as DNSSyntaxError

ipv4_reverse_domain = name_from_text("in-addr.arpa.")
ipv6_reverse_domain = name_from_text("ip6.arpa.")


def from_address(text, v4_origin=None, v6_origin=None):
    """Convert an IP address string to its reverse DNS name.

    text: an IPv4 or IPv6 address string
    v4_origin: origin for IPv4 reverse names (default: in-addr.arpa.)
    v6_origin: origin for IPv6 reverse names (default: ip6.arpa.)

    Returns a DomainName for the reverse lookup.
    """
    if v4_origin is None:
        v4_origin = ipv4_reverse_domain
    if v6_origin is None:
        v6_origin = ipv6_reverse_domain

    try:
        binary = ipv4_to_binary(text)
        octets = list(binary)
        octets.reverse()
        name_text = ".".join(str(o) for o in octets)
        return name_from_text(name_text + "." + v4_origin.to_text())
    except Exception:
        pass

    try:
        binary = ipv6_to_binary(text)
        hex_str = binascii.hexlify(binary).decode("ascii")
        nibbles = list(hex_str)
        nibbles.reverse()
        name_text = ".".join(nibbles)
        return name_from_text(name_text + "." + v6_origin.to_text())
    except Exception:
        pass

    raise DNSSyntaxError(f"not a valid IP address: {text}")


def to_address(name, v4_origin=None, v6_origin=None):
    """Convert a reverse DNS name back to an IP address string.

    name: a DomainName in reverse-map form
    v4_origin: origin for IPv4 reverse names (default: in-addr.arpa.)
    v6_origin: origin for IPv6 reverse names (default: ip6.arpa.)

    Returns an IPv4 or IPv6 address string.
    """
    if v4_origin is None:
        v4_origin = ipv4_reverse_domain
    if v6_origin is None:
        v6_origin = ipv6_reverse_domain

    if isinstance(name, str):
        name = name_from_text(name)

    if name.is_subdomain(v4_origin):
        relative = name.relativize(v4_origin)
        labels = [label.decode("ascii") for label in relative.labels]
        if len(labels) != 4:
            raise DNSSyntaxError(f"not a valid IPv4 reverse name: {name}")
        labels.reverse()
        addr_text = ".".join(labels)
        binary = ipv4_to_binary(addr_text)
        return ipv4_to_text(binary)

    if name.is_subdomain(v6_origin):
        relative = name.relativize(v6_origin)
        labels = [label.decode("ascii") for label in relative.labels]
        if len(labels) != 32:
            raise DNSSyntaxError(f"not a valid IPv6 reverse name: {name}")
        labels.reverse()
        hex_str = "".join(labels)
        binary = binascii.unhexlify(hex_str)
        return ipv6_to_text(binary)

    raise DNSSyntaxError(f"not a reverse DNS name: {name}")
