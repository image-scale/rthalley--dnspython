"""DNS resource record data.

Provides the base RecordData class and concrete implementations for
common DNS record types (A, AAAA, NS, CNAME, MX, TXT, SOA, PTR, SRV).
"""

import io
import struct

from dnscore import ipv4, ipv6
from dnscore.domain_name import DomainName, from_text as name_from_text, from_wire as name_from_wire
from dnscore.record_type import RecordType
from dnscore.record_class import RecordClass
from dnscore.exceptions import SyntaxError as DNSSyntaxError, FormError

_TYPE_REGISTRY = {}


def register_type(rdtype, cls):
    """Register a record data class for a given record type."""
    _TYPE_REGISTRY[int(rdtype)] = cls


def get_record_class(rdtype):
    """Get the record data class for a given type, or None."""
    return _TYPE_REGISTRY.get(int(rdtype))


class RecordData:
    """Base class for DNS resource record data.

    Subclasses implement specific record types (A, AAAA, MX, etc.).
    Each subclass must implement to_text(), to_wire(), from_text(), from_wire().
    """

    TYPE = None

    def __init__(self, rdclass=RecordClass.IN, rdtype=None):
        if rdtype is None:
            rdtype = self.__class__.TYPE
        self._rdclass = int(rdclass)
        self._rdtype = int(rdtype)

    @property
    def rdclass(self):
        return self._rdclass

    @property
    def rdtype(self):
        return self._rdtype

    def to_text(self):
        raise NotImplementedError

    def to_wire(self):
        buf = io.BytesIO()
        self.write_wire(buf)
        return buf.getvalue()

    def write_wire(self, out, compress=None, origin=None, canonicalize=False):
        raise NotImplementedError

    @classmethod
    def from_text(cls, text, origin=None, rdclass=RecordClass.IN):
        raise NotImplementedError

    @classmethod
    def from_wire(cls, data, offset=0, length=None, rdclass=RecordClass.IN):
        raise NotImplementedError

    def __eq__(self, other):
        if not isinstance(other, RecordData):
            return False
        if self._rdtype != other._rdtype or self._rdclass != other._rdclass:
            return False
        return self.to_wire() == other.to_wire()

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self._rdtype, self._rdclass, self.to_wire()))

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.to_text()}>"

    def __str__(self):
        return self.to_text()

    def __lt__(self, other):
        if not isinstance(other, RecordData):
            return NotImplemented
        if self._rdtype != other._rdtype:
            return self._rdtype < other._rdtype
        return self.to_wire() < other.to_wire()


class ARecord(RecordData):
    """DNS A record — IPv4 address."""

    TYPE = RecordType.A

    def __init__(self, address, rdclass=RecordClass.IN):
        super().__init__(rdclass, RecordType.A)
        ipv4.text_to_binary(address)
        self._address = ipv4.canonicalize(address)

    @property
    def address(self):
        return self._address

    def to_text(self):
        return self._address

    def write_wire(self, out, compress=None, origin=None, canonicalize=False):
        out.write(ipv4.text_to_binary(self._address))

    @classmethod
    def from_text(cls, text, origin=None, rdclass=RecordClass.IN):
        return cls(text.strip(), rdclass)

    @classmethod
    def from_wire(cls, data, offset=0, length=None, rdclass=RecordClass.IN):
        if length is None:
            length = len(data) - offset
        if length != 4:
            raise FormError(f"A record must be 4 bytes, got {length}")
        addr = ipv4.binary_to_text(data[offset:offset + 4])
        return cls(addr, rdclass)


class AAAARecord(RecordData):
    """DNS AAAA record — IPv6 address."""

    TYPE = RecordType.AAAA

    def __init__(self, address, rdclass=RecordClass.IN):
        super().__init__(rdclass, RecordType.AAAA)
        ipv6.text_to_binary(address)
        self._address = ipv6.canonicalize(address)

    @property
    def address(self):
        return self._address

    def to_text(self):
        return self._address

    def write_wire(self, out, compress=None, origin=None, canonicalize=False):
        out.write(ipv6.text_to_binary(self._address))

    @classmethod
    def from_text(cls, text, origin=None, rdclass=RecordClass.IN):
        return cls(text.strip(), rdclass)

    @classmethod
    def from_wire(cls, data, offset=0, length=None, rdclass=RecordClass.IN):
        if length is None:
            length = len(data) - offset
        if length != 16:
            raise FormError(f"AAAA record must be 16 bytes, got {length}")
        addr = ipv6.binary_to_text(data[offset:offset + 16])
        return cls(addr, rdclass)


class _NameRecord(RecordData):
    """Base class for records containing a single domain name (NS, CNAME, PTR)."""

    def __init__(self, target, rdclass=RecordClass.IN, rdtype=None):
        super().__init__(rdclass, rdtype or self.__class__.TYPE)
        if isinstance(target, str):
            target = name_from_text(target)
        if not isinstance(target, DomainName):
            raise TypeError(f"target must be a DomainName, got {type(target)}")
        self._target = target

    @property
    def target(self):
        return self._target

    def to_text(self):
        return self._target.to_text()

    def write_wire(self, out, compress=None, origin=None, canonicalize=False):
        wire = self._target.to_wire(origin=origin, canonicalize=canonicalize)
        out.write(wire)

    @classmethod
    def from_text(cls, text, origin=None, rdclass=RecordClass.IN):
        name = name_from_text(text.strip(), origin=origin)
        return cls(name, rdclass)

    @classmethod
    def from_wire(cls, data, offset=0, length=None, rdclass=RecordClass.IN):
        name, consumed = name_from_wire(data, offset)
        return cls(name, rdclass)


class NSRecord(_NameRecord):
    """DNS NS record — authoritative nameserver."""
    TYPE = RecordType.NS


class CNAMERecord(_NameRecord):
    """DNS CNAME record — canonical name alias."""
    TYPE = RecordType.CNAME


class PTRRecord(_NameRecord):
    """DNS PTR record — pointer (for reverse lookups)."""
    TYPE = RecordType.PTR


class MXRecord(RecordData):
    """DNS MX record — mail exchange with preference."""

    TYPE = RecordType.MX

    def __init__(self, preference, exchange, rdclass=RecordClass.IN):
        super().__init__(rdclass, RecordType.MX)
        if not isinstance(preference, int) or preference < 0 or preference > 65535:
            raise ValueError(f"MX preference must be 0-65535, got {preference}")
        self._preference = preference
        if isinstance(exchange, str):
            exchange = name_from_text(exchange)
        if not isinstance(exchange, DomainName):
            raise TypeError(f"exchange must be a DomainName, got {type(exchange)}")
        self._exchange = exchange

    @property
    def preference(self):
        return self._preference

    @property
    def exchange(self):
        return self._exchange

    def to_text(self):
        return f"{self._preference} {self._exchange.to_text()}"

    def write_wire(self, out, compress=None, origin=None, canonicalize=False):
        out.write(struct.pack("!H", self._preference))
        wire = self._exchange.to_wire(origin=origin, canonicalize=canonicalize)
        out.write(wire)

    @classmethod
    def from_text(cls, text, origin=None, rdclass=RecordClass.IN):
        parts = text.strip().split(None, 1)
        if len(parts) != 2:
            raise DNSSyntaxError(f"MX record needs preference and exchange: {text!r}")
        pref = int(parts[0])
        exchange = name_from_text(parts[1], origin=origin)
        return cls(pref, exchange, rdclass)

    @classmethod
    def from_wire(cls, data, offset=0, length=None, rdclass=RecordClass.IN):
        pref = struct.unpack("!H", data[offset:offset + 2])[0]
        name, consumed = name_from_wire(data, offset + 2)
        return cls(pref, name, rdclass)


class TXTRecord(RecordData):
    """DNS TXT record — text strings."""

    TYPE = RecordType.TXT

    def __init__(self, strings, rdclass=RecordClass.IN):
        super().__init__(rdclass, RecordType.TXT)
        if isinstance(strings, (str, bytes)):
            strings = [strings]
        converted = []
        for s in strings:
            if isinstance(s, str):
                s = s.encode("utf-8")
            if len(s) > 255:
                raise ValueError(f"TXT string exceeds 255 bytes: {len(s)}")
            converted.append(bytes(s))
        if not converted:
            raise ValueError("TXT record must have at least one string")
        self._strings = tuple(converted)

    @property
    def strings(self):
        return self._strings

    def to_text(self):
        parts = []
        for s in self._strings:
            escaped = ""
            for byte_val in s:
                if 0x20 <= byte_val <= 0x7E and byte_val != ord('"') and byte_val != ord('\\'):
                    escaped += chr(byte_val)
                else:
                    escaped += f"\\{byte_val:03d}"
            parts.append(f'"{escaped}"')
        return " ".join(parts)

    def write_wire(self, out, compress=None, origin=None, canonicalize=False):
        for s in self._strings:
            out.write(struct.pack("!B", len(s)))
            out.write(s)

    @classmethod
    def from_text(cls, text, origin=None, rdclass=RecordClass.IN):
        strings = _parse_txt_strings(text.strip())
        return cls(strings, rdclass)

    @classmethod
    def from_wire(cls, data, offset=0, length=None, rdclass=RecordClass.IN):
        if length is None:
            length = len(data) - offset
        end = offset + length
        strings = []
        pos = offset
        while pos < end:
            slen = data[pos]
            pos += 1
            if pos + slen > end:
                raise FormError("TXT string extends past record data")
            strings.append(data[pos:pos + slen])
            pos += slen
        return cls(strings, rdclass)


def _parse_txt_strings(text):
    """Parse TXT record text which may contain quoted strings."""
    strings = []
    i = 0
    while i < len(text):
        if text[i] in (" ", "\t"):
            i += 1
            continue
        if text[i] == '"':
            i += 1
            current = bytearray()
            while i < len(text) and text[i] != '"':
                if text[i] == '\\':
                    i += 1
                    if i >= len(text):
                        raise DNSSyntaxError("incomplete escape in TXT")
                    if text[i].isdigit() and i + 2 < len(text) and text[i+1].isdigit() and text[i+2].isdigit():
                        val = int(text[i:i+3])
                        current.append(val)
                        i += 3
                    else:
                        current.append(ord(text[i]))
                        i += 1
                else:
                    current.append(ord(text[i]))
                    i += 1
            if i < len(text) and text[i] == '"':
                i += 1
            strings.append(bytes(current))
        else:
            current = bytearray()
            while i < len(text) and text[i] not in (" ", "\t"):
                current.append(ord(text[i]))
                i += 1
            strings.append(bytes(current))
    if not strings:
        strings = [b""]
    return strings


class SOARecord(RecordData):
    """DNS SOA record — Start of Authority."""

    TYPE = RecordType.SOA

    def __init__(self, mname, rname, serial, refresh, retry, expire, minimum,
                 rdclass=RecordClass.IN):
        super().__init__(rdclass, RecordType.SOA)
        if isinstance(mname, str):
            mname = name_from_text(mname)
        if isinstance(rname, str):
            rname = name_from_text(rname)
        self._mname = mname
        self._rname = rname
        self._serial = serial & 0xFFFFFFFF
        self._refresh = refresh & 0xFFFFFFFF
        self._retry = retry & 0xFFFFFFFF
        self._expire = expire & 0xFFFFFFFF
        self._minimum = minimum & 0xFFFFFFFF

    @property
    def mname(self):
        return self._mname

    @property
    def rname(self):
        return self._rname

    @property
    def serial(self):
        return self._serial

    @property
    def refresh(self):
        return self._refresh

    @property
    def retry(self):
        return self._retry

    @property
    def expire(self):
        return self._expire

    @property
    def minimum(self):
        return self._minimum

    def to_text(self):
        return (f"{self._mname.to_text()} {self._rname.to_text()} "
                f"{self._serial} {self._refresh} {self._retry} "
                f"{self._expire} {self._minimum}")

    def write_wire(self, out, compress=None, origin=None, canonicalize=False):
        out.write(self._mname.to_wire(origin=origin, canonicalize=canonicalize))
        out.write(self._rname.to_wire(origin=origin, canonicalize=canonicalize))
        out.write(struct.pack("!IIIII",
                              self._serial, self._refresh, self._retry,
                              self._expire, self._minimum))

    @classmethod
    def from_text(cls, text, origin=None, rdclass=RecordClass.IN):
        parts = text.strip().split()
        if len(parts) != 7:
            raise DNSSyntaxError(f"SOA record needs 7 fields, got {len(parts)}")
        mname = name_from_text(parts[0], origin=origin)
        rname = name_from_text(parts[1], origin=origin)
        serial = int(parts[2])
        refresh = int(parts[3])
        retry = int(parts[4])
        expire = int(parts[5])
        minimum = int(parts[6])
        return cls(mname, rname, serial, refresh, retry, expire, minimum, rdclass)

    @classmethod
    def from_wire(cls, data, offset=0, length=None, rdclass=RecordClass.IN):
        mname, consumed = name_from_wire(data, offset)
        pos = offset + consumed
        rname, consumed = name_from_wire(data, pos)
        pos += consumed
        serial, refresh, retry, expire, minimum = struct.unpack(
            "!IIIII", data[pos:pos + 20]
        )
        return cls(mname, rname, serial, refresh, retry, expire, minimum, rdclass)


class SRVRecord(RecordData):
    """DNS SRV record — service location."""

    TYPE = RecordType.SRV

    def __init__(self, priority, weight, port, target, rdclass=RecordClass.IN):
        super().__init__(rdclass, RecordType.SRV)
        if not (0 <= priority <= 65535):
            raise ValueError(f"SRV priority must be 0-65535, got {priority}")
        if not (0 <= weight <= 65535):
            raise ValueError(f"SRV weight must be 0-65535, got {weight}")
        if not (0 <= port <= 65535):
            raise ValueError(f"SRV port must be 0-65535, got {port}")
        self._priority = priority
        self._weight = weight
        self._port = port
        if isinstance(target, str):
            target = name_from_text(target)
        self._target = target

    @property
    def priority(self):
        return self._priority

    @property
    def weight(self):
        return self._weight

    @property
    def port(self):
        return self._port

    @property
    def target(self):
        return self._target

    def to_text(self):
        return f"{self._priority} {self._weight} {self._port} {self._target.to_text()}"

    def write_wire(self, out, compress=None, origin=None, canonicalize=False):
        out.write(struct.pack("!HHH", self._priority, self._weight, self._port))
        out.write(self._target.to_wire(origin=origin, canonicalize=canonicalize))

    @classmethod
    def from_text(cls, text, origin=None, rdclass=RecordClass.IN):
        parts = text.strip().split(None, 3)
        if len(parts) != 4:
            raise DNSSyntaxError(f"SRV record needs 4 fields, got {len(parts)}")
        priority = int(parts[0])
        weight = int(parts[1])
        port = int(parts[2])
        target = name_from_text(parts[3], origin=origin)
        return cls(priority, weight, port, target, rdclass)

    @classmethod
    def from_wire(cls, data, offset=0, length=None, rdclass=RecordClass.IN):
        priority, weight, port = struct.unpack("!HHH", data[offset:offset + 6])
        target, consumed = name_from_wire(data, offset + 6)
        return cls(priority, weight, port, target, rdclass)


register_type(RecordType.A, ARecord)
register_type(RecordType.AAAA, AAAARecord)
register_type(RecordType.NS, NSRecord)
register_type(RecordType.CNAME, CNAMERecord)
register_type(RecordType.PTR, PTRRecord)
register_type(RecordType.MX, MXRecord)
register_type(RecordType.TXT, TXTRecord)
register_type(RecordType.SOA, SOARecord)
register_type(RecordType.SRV, SRVRecord)


def create_from_text(rdtype, text, origin=None, rdclass=RecordClass.IN):
    """Create a record data object from text for the given type."""
    cls = get_record_class(rdtype)
    if cls is None:
        raise ValueError(f"unsupported record type: {rdtype}")
    return cls.from_text(text, origin=origin, rdclass=rdclass)


def create_from_wire(rdtype, data, offset=0, length=None, rdclass=RecordClass.IN):
    """Create a record data object from wire format for the given type."""
    cls = get_record_class(rdtype)
    if cls is None:
        raise ValueError(f"unsupported record type: {rdtype}")
    return cls.from_wire(data, offset=offset, length=length, rdclass=rdclass)
