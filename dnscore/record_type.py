"""DNS record type definitions and utilities.

Defines the standard DNS resource record types (A, AAAA, MX, etc.)
with conversion between numeric values and text mnemonics.
"""

from enum import IntEnum


class RecordType(IntEnum):
    """DNS resource record types."""
    NONE = 0
    A = 1
    NS = 2
    MD = 3
    MF = 4
    CNAME = 5
    SOA = 6
    MB = 7
    MG = 8
    MR = 9
    NULL = 10
    WKS = 11
    PTR = 12
    HINFO = 13
    MINFO = 14
    MX = 15
    TXT = 16
    RP = 17
    AFSDB = 18
    X25 = 19
    ISDN = 20
    RT = 21
    NSAP = 22
    NSAP_PTR = 23
    SIG = 24
    KEY = 25
    PX = 26
    GPOS = 27
    AAAA = 28
    LOC = 29
    NXT = 30
    SRV = 33
    NAPTR = 35
    KX = 36
    CERT = 37
    DNAME = 39
    OPT = 41
    APL = 42
    DS = 43
    SSHFP = 44
    IPSECKEY = 45
    RRSIG = 46
    NSEC = 47
    DNSKEY = 48
    DHCID = 49
    NSEC3 = 50
    NSEC3PARAM = 51
    TLSA = 52
    SMIMEA = 53
    HIP = 55
    CDS = 59
    CDNSKEY = 60
    OPENPGPKEY = 61
    CSYNC = 62
    ZONEMD = 63
    SVCB = 64
    HTTPS = 65
    SPF = 99
    EUI48 = 108
    EUI64 = 109
    TKEY = 249
    TSIG = 250
    IXFR = 251
    AXFR = 252
    MAILB = 253
    MAILA = 254
    ANY = 255
    URI = 256
    CAA = 257
    AVC = 258
    AMTRELAY = 260
    RESINFO = 261
    WALLET = 262
    TA = 32768
    DLV = 32769


_META_TYPES = frozenset({
    RecordType.OPT,
    RecordType.TSIG,
    RecordType.TKEY,
    RecordType.IXFR,
    RecordType.AXFR,
    RecordType.MAILB,
    RecordType.MAILA,
    RecordType.ANY,
})

_SINGLETON_TYPES = frozenset({
    RecordType.SOA,
    RecordType.CNAME,
    RecordType.DNAME,
    RecordType.NSEC,
})

_text_to_type = {}
_type_to_text = {}

for _member in RecordType:
    _mname = _member.name
    _text_to_type[_mname.upper()] = _member
    _type_to_text[_member] = _mname


def type_from_text(text):
    """Convert a text mnemonic or TYPENN string to a record type value.

    Returns an int (RecordType enum member if known).
    """
    upper = text.upper()
    result = _text_to_type.get(upper)
    if result is not None:
        return result
    if upper.startswith("TYPE"):
        try:
            val = int(upper[4:])
            if 0 <= val <= 65535:
                try:
                    return RecordType(val)
                except ValueError:
                    return val
        except ValueError:
            pass
    raise ValueError(f"unknown record type: {text!r}")


def type_to_text(value):
    """Convert a record type value to its text mnemonic.

    Returns the mnemonic like "A" or "TYPENN" for unknown types.
    """
    result = _type_to_text.get(value)
    if result is not None:
        return result
    if isinstance(value, int) and 0 <= value <= 65535:
        return f"TYPE{value}"
    raise ValueError(f"invalid record type value: {value!r}")


def is_meta_type(rtype):
    """Return True if the record type is a meta-type (query/transfer only)."""
    return rtype in _META_TYPES


def is_singleton_type(rtype):
    """Return True if only one RR of this type should exist per name."""
    return rtype in _SINGLETON_TYPES
