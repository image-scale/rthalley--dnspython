"""DNS wire format serialization and parsing.

Serialize DNS messages to binary wire format with name compression,
and parse binary DNS messages back to message objects.
"""

import io
import struct

from dnscore.domain_name import DomainName, from_text as name_from_text, from_wire as name_from_wire
from dnscore.record_type import RecordType, type_to_text
from dnscore.record_class import RecordClass
from dnscore.record_data import RecordData, create_from_wire
from dnscore.record_sets import RRSet
from dnscore.message import DNSMessage, QuestionEntry, MessageSection, build_query
from dnscore.msg_flags import MessageFlag
from dnscore.op_code import opcode_from_flags
from dnscore.exceptions import FormError

HEADER_SIZE = 12


class WireWriter:
    """Serialize a DNS message to wire format with optional name compression."""

    def __init__(self, msg_id=0, flags=0, max_size=65535):
        self._buf = io.BytesIO()
        self._id = msg_id
        self._flags = flags
        self._max_size = max_size
        self._compress = {}
        self._counts = [0, 0, 0, 0]
        self._buf.write(b"\x00" * HEADER_SIZE)

    def _write_name(self, name, compress=True):
        """Write a domain name with optional compression."""
        if not isinstance(name, DomainName):
            name = name_from_text(str(name))

        labels = list(name.labels)
        for i in range(len(labels)):
            suffix = DomainName(labels[i:])
            if compress and suffix in self._compress:
                pointer = self._compress[suffix]
                self._buf.write(struct.pack("!H", 0xC000 | pointer))
                return
            pos = self._buf.tell()
            if compress and len(suffix) > 1 and pos <= 0x3FFF:
                self._compress[suffix] = pos
            lbl = labels[i]
            self._buf.write(struct.pack("!B", len(lbl)))
            if lbl:
                self._buf.write(lbl)

    def add_question(self, name, rdtype, rdclass=RecordClass.IN):
        """Write a question entry."""
        if isinstance(name, str):
            name = name_from_text(name)
        self._write_name(name)
        self._buf.write(struct.pack("!HH", int(rdtype), int(rdclass)))
        self._counts[MessageSection.QUESTION] += 1

    def add_rrset(self, section, rrset):
        """Write all records in an RRSet to the specified section."""
        for rdata in rrset:
            self._write_name(rrset.name)
            self._buf.write(struct.pack("!HHI",
                                        int(rrset.rdtype),
                                        int(rrset.rdclass),
                                        int(rrset.ttl)))
            rdata_buf = io.BytesIO()
            rdata.write_wire(rdata_buf)
            rdata_bytes = rdata_buf.getvalue()
            self._buf.write(struct.pack("!H", len(rdata_bytes)))
            self._buf.write(rdata_bytes)
            self._counts[section] += 1

    def write_header(self):
        """Write the DNS message header at the start of the buffer."""
        pos = self._buf.tell()
        self._buf.seek(0)
        self._buf.write(struct.pack("!HHHHHH",
                                    self._id,
                                    self._flags,
                                    self._counts[0],
                                    self._counts[1],
                                    self._counts[2],
                                    self._counts[3]))
        self._buf.seek(pos)

    def get_wire(self):
        """Return the complete wire format bytes."""
        self.write_header()
        return self._buf.getvalue()


def message_to_wire(msg):
    """Serialize a DNSMessage to wire format bytes.

    Handles the question section and all RRSet-based answer/authority/additional sections.
    """
    writer = WireWriter(msg.id, msg.flags)

    for q in msg.question:
        writer.add_question(q.name, q.rdtype, q.rdclass)

    for section_num, section in [(MessageSection.ANSWER, msg.answer),
                                  (MessageSection.AUTHORITY, msg.authority),
                                  (MessageSection.ADDITIONAL, msg.additional)]:
        for rrset in section:
            if isinstance(rrset, RRSet):
                writer.add_rrset(section_num, rrset)

    return writer.get_wire()


def message_from_wire(data):
    """Parse a DNS message from wire format bytes.

    Returns a DNSMessage with all sections populated.
    """
    if len(data) < HEADER_SIZE:
        raise FormError("message too short for DNS header")

    msg_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        "!HHHHHH", data[:HEADER_SIZE]
    )

    msg = DNSMessage(msg_id)
    msg.flags = flags

    pos = HEADER_SIZE

    for _ in range(qdcount):
        name, consumed = name_from_wire(data, pos)
        pos += consumed
        if pos + 4 > len(data):
            raise FormError("question section truncated")
        rdtype, rdclass = struct.unpack("!HH", data[pos:pos + 4])
        pos += 4
        msg.add_question(name, rdtype, rdclass)

    for count, section in [(ancount, msg.answer),
                            (nscount, msg.authority),
                            (arcount, msg.additional)]:
        for _ in range(count):
            name, consumed = name_from_wire(data, pos)
            pos += consumed
            if pos + 10 > len(data):
                raise FormError("resource record header truncated")
            rdtype, rdclass, ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
            pos += 10
            if pos + rdlen > len(data):
                raise FormError("resource record data truncated")

            rdata_end = pos + rdlen
            try:
                rdata = create_from_wire(rdtype, data, offset=pos, length=rdlen, rdclass=rdclass)
            except (ValueError, KeyError):
                pos = rdata_end
                continue

            rrset = None
            for existing in section:
                if (isinstance(existing, RRSet) and
                        existing.name == name and
                        existing.rdtype == int(rdtype) and
                        existing.rdclass == int(rdclass)):
                    rrset = existing
                    break

            if rrset is None:
                rrset = RRSet(name, int(rdtype), int(rdclass), ttl)
                section.append(rrset)

            rrset.add(rdata, ttl=ttl)
            pos = rdata_end

    return msg
