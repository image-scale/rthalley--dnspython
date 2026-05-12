"""DNS message flags.

Defines DNS header flags (QR, AA, TC, RD, RA, AD, CD) and EDNS flags (DO)
with conversion between flag bitmasks and text representations.
"""

from enum import IntFlag


class MessageFlag(IntFlag):
    """DNS message header flags."""
    QR = 0x8000  # Query Response
    AA = 0x0400  # Authoritative Answer
    TC = 0x0200  # Truncated
    RD = 0x0100  # Recursion Desired
    RA = 0x0080  # Recursion Available
    AD = 0x0020  # Authenticated Data
    CD = 0x0010  # Checking Disabled


class EDNSFlag(IntFlag):
    """EDNS (OPT) flags."""
    DO = 0x8000  # DNSSEC OK


def flags_from_text(text):
    """Parse a space-separated string of flag mnemonics to a flag value."""
    result = 0
    for word in text.split():
        word_upper = word.upper()
        try:
            result |= MessageFlag[word_upper]
        except KeyError:
            raise ValueError(f"unknown flag: {word!r}")
    return result


def flags_to_text(flags):
    """Convert a flag bitmask to a space-separated string of mnemonics."""
    parts = []
    for flag in MessageFlag:
        if flags & flag:
            parts.append(flag.name)
    return " ".join(parts)


def edns_flags_from_text(text):
    """Parse a space-separated string of EDNS flag mnemonics."""
    result = 0
    for word in text.split():
        word_upper = word.upper()
        try:
            result |= EDNSFlag[word_upper]
        except KeyError:
            raise ValueError(f"unknown EDNS flag: {word!r}")
    return result


def edns_flags_to_text(flags):
    """Convert an EDNS flag bitmask to a space-separated string."""
    parts = []
    for flag in EDNSFlag:
        if flags & flag:
            parts.append(flag.name)
    return " ".join(parts)
