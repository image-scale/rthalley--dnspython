"""IPv4 address conversion utilities.

Convert between text ("192.168.1.1") and binary (4-byte) representations
of IPv4 addresses.
"""

import struct

from dnscore.exceptions import SyntaxError as DNSSyntaxError


def text_to_binary(text):
    """Convert an IPv4 address string to 4-byte binary.

    Validates the format strictly: exactly 4 decimal octets 0-255,
    no leading zeros (except "0" itself).
    """
    parts = text.split(".")
    if len(parts) != 4:
        raise DNSSyntaxError(f"invalid IPv4 address: {text!r}")
    octets = []
    for part in parts:
        if not part:
            raise DNSSyntaxError(f"invalid IPv4 address: {text!r}")
        if len(part) > 1 and part[0] == "0":
            raise DNSSyntaxError(f"leading zeros in IPv4 address: {text!r}")
        try:
            val = int(part)
        except ValueError:
            raise DNSSyntaxError(f"non-numeric IPv4 octet: {text!r}")
        if val < 0 or val > 255:
            raise DNSSyntaxError(f"IPv4 octet out of range: {text!r}")
        octets.append(val)
    return struct.pack("BBBB", *octets)


def binary_to_text(data):
    """Convert 4-byte binary IPv4 data to text representation."""
    if len(data) != 4:
        raise DNSSyntaxError(f"IPv4 address must be 4 bytes, got {len(data)}")
    return f"{data[0]}.{data[1]}.{data[2]}.{data[3]}"


def is_valid(text):
    """Return True if text is a valid IPv4 address string."""
    try:
        text_to_binary(text)
        return True
    except DNSSyntaxError:
        return False


def canonicalize(text):
    """Return the canonical form of an IPv4 address."""
    return binary_to_text(text_to_binary(text))
