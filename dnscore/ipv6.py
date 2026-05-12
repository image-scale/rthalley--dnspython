"""IPv6 address conversion utilities.

Convert between text ("2001:db8::1") and binary (16-byte) representations
of IPv6 addresses, with support for :: compression and IPv4-mapped addresses.
"""

import struct

from dnscore.exceptions import SyntaxError as DNSSyntaxError


def text_to_binary(text):
    """Convert an IPv6 address string to 16-byte binary.

    Supports :: compression and IPv4-mapped suffixes (e.g., ::ffff:192.168.1.1).
    Strips scope identifiers (e.g., %eth0).
    """
    if "%" in text:
        text = text.split("%")[0]

    if not text:
        raise DNSSyntaxError("empty IPv6 address")

    if "::" in text:
        parts = text.split("::", 1)
        left_str = parts[0]
        right_str = parts[1]

        left_groups = left_str.split(":") if left_str else []
        right_groups = right_str.split(":") if right_str else []

        has_ipv4 = False
        if right_groups and "." in right_groups[-1]:
            has_ipv4 = True
            ipv4_text = right_groups.pop()

        total_specified = len(left_groups) + len(right_groups)
        if has_ipv4:
            total_specified += 2
        fill_count = 8 - total_specified

        if fill_count < 0:
            raise DNSSyntaxError(f"too many groups in IPv6 address: {text!r}")

        groups = left_groups + (["0"] * fill_count) + right_groups
        if has_ipv4:
            groups = groups[:]
            result = bytearray()
            for g in groups:
                val = int(g, 16)
                if val < 0 or val > 0xFFFF:
                    raise DNSSyntaxError(f"invalid IPv6 group: {g}")
                result += struct.pack("!H", val)
            from dnscore.ipv4 import text_to_binary as ipv4_to_bin
            result += ipv4_to_bin(ipv4_text)
            if len(result) != 16:
                raise DNSSyntaxError(f"invalid IPv6 address: {text!r}")
            return bytes(result)
    else:
        groups = text.split(":")
        has_ipv4 = False
        if groups and "." in groups[-1]:
            has_ipv4 = True
            ipv4_text = groups.pop()
            if len(groups) != 6:
                raise DNSSyntaxError(f"invalid IPv6 address: {text!r}")
            result = bytearray()
            for g in groups:
                val = int(g, 16)
                if val < 0 or val > 0xFFFF:
                    raise DNSSyntaxError(f"invalid IPv6 group: {g}")
                result += struct.pack("!H", val)
            from dnscore.ipv4 import text_to_binary as ipv4_to_bin
            result += ipv4_to_bin(ipv4_text)
            return bytes(result)
        if len(groups) != 8:
            raise DNSSyntaxError(f"invalid IPv6 address: {text!r}")

    result = bytearray()
    for g in groups:
        if not g:
            raise DNSSyntaxError(f"empty group in IPv6 address: {text!r}")
        try:
            val = int(g, 16)
        except ValueError:
            raise DNSSyntaxError(f"invalid hex in IPv6 address: {g!r}")
        if val < 0 or val > 0xFFFF:
            raise DNSSyntaxError(f"IPv6 group out of range: {g!r}")
        result += struct.pack("!H", val)

    if len(result) != 16:
        raise DNSSyntaxError(f"invalid IPv6 address: {text!r}")
    return bytes(result)


def binary_to_text(data):
    """Convert 16-byte binary IPv6 data to text with :: compression.

    Uses the standard algorithm: find the longest run of consecutive
    all-zero 16-bit groups and compress it to "::".
    """
    if len(data) != 16:
        raise DNSSyntaxError(f"IPv6 address must be 16 bytes, got {len(data)}")

    chunks = []
    for i in range(0, 16, 2):
        val = (data[i] << 8) | data[i + 1]
        chunks.append(val)

    best_start = -1
    best_len = 0
    cur_start = -1
    cur_len = 0
    for i, val in enumerate(chunks):
        if val == 0:
            if cur_start < 0:
                cur_start = i
                cur_len = 1
            else:
                cur_len += 1
            if cur_len > best_len:
                best_start = cur_start
                best_len = cur_len
        else:
            cur_start = -1
            cur_len = 0

    if best_len < 2:
        return ":".join(f"{c:x}" for c in chunks)

    left = chunks[:best_start]
    right = chunks[best_start + best_len:]
    left_str = ":".join(f"{c:x}" for c in left)
    right_str = ":".join(f"{c:x}" for c in right)

    if not left_str and not right_str:
        return "::"
    elif not left_str:
        return f"::{right_str}"
    elif not right_str:
        return f"{left_str}::"
    else:
        return f"{left_str}::{right_str}"


def is_valid(text):
    """Return True if text is a valid IPv6 address string."""
    try:
        text_to_binary(text)
        return True
    except (DNSSyntaxError, ValueError):
        return False


def is_mapped_ipv4(data):
    """Return True if this is an IPv4-mapped IPv6 address (::ffff:0:0/96)."""
    if len(data) != 16:
        return False
    return data[:12] == b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff"


def canonicalize(text):
    """Return the canonical form of an IPv6 address."""
    return binary_to_text(text_to_binary(text))
