"""DNS response codes.

Defines DNS rcodes (NOERROR, FORMERR, SERVFAIL, NXDOMAIN, etc.) with
conversion between numeric values, text mnemonics, and DNS message flags.
Extended rcodes use both the 4-bit message flags and 8-bit EDNS extended rcode.
"""

from enum import IntEnum


class ResponseCode(IntEnum):
    """DNS response codes."""
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5
    YXDOMAIN = 6
    YXRRSET = 7
    NXRRSET = 8
    NOTAUTH = 9
    NOTZONE = 10
    DSOTYPENI = 11
    BADVERS = 16
    BADSIG = 16
    BADKEY = 17
    BADTIME = 18
    BADMODE = 19
    BADNAME = 20
    BADALG = 21
    BADTRUNC = 22
    BADCOOKIE = 23


_text_to_rcode = {}
_rcode_to_text = {}

for _member in ResponseCode:
    _text_to_rcode[_member.name] = _member
    if _member.value not in _rcode_to_text:
        _rcode_to_text[_member.value] = _member.name


def rcode_from_text(text):
    """Convert a text mnemonic to a response code value."""
    upper = text.upper()
    result = _text_to_rcode.get(upper)
    if result is not None:
        return int(result)
    raise ValueError(f"unknown response code: {text!r}")


def rcode_to_text(value):
    """Convert a response code value to its text mnemonic."""
    result = _rcode_to_text.get(value)
    if result is not None:
        return result
    if isinstance(value, int) and 0 <= value <= 4095:
        return str(value)
    raise ValueError(f"invalid response code value: {value!r}")


def rcode_from_flags(msg_flags, edns_flags=0):
    """Extract the extended response code from message and EDNS flags.

    The low 4 bits come from the message flags field.
    The high 8 bits come from the EDNS extended rcode field.
    """
    low = msg_flags & 0x000F
    high = (edns_flags >> 20) & 0xFF0
    return high | low


def rcode_to_flags(rcode):
    """Encode a response code into message flags and EDNS extended rcode.

    Returns (msg_flags_bits, edns_rcode_bits).
    msg_flags_bits: the low 4 bits of the rcode
    edns_rcode_bits: the high 8 bits shifted for EDNS OPT header
    """
    low = rcode & 0x000F
    high = (rcode & 0x0FF0) << 20
    return (low, high)
