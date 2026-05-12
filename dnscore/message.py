"""DNS message representation and construction.

A DNS message consists of a header (ID, flags, counts) and four sections:
question, answer, authority, and additional. This module provides the
DNSMessage class for building and inspecting DNS query/response messages.
"""

import random
import struct

from dnscore.domain_name import DomainName, from_text as name_from_text
from dnscore.record_type import RecordType, type_to_text
from dnscore.record_class import RecordClass, class_to_text
from dnscore.msg_flags import MessageFlag, flags_to_text
from dnscore.op_code import OpCode, opcode_to_text, opcode_from_flags, opcode_to_flags
from dnscore.resp_code import rcode_to_text
from dnscore.record_sets import RRSet


class MessageSection:
    """Constants for message section indices."""
    QUESTION = 0
    ANSWER = 1
    AUTHORITY = 2
    ADDITIONAL = 3


class QuestionEntry:
    """A single entry in the question section of a DNS message."""

    def __init__(self, name, rdtype, rdclass=RecordClass.IN):
        if isinstance(name, str):
            name = name_from_text(name)
        self._name = name
        self._rdtype = int(rdtype)
        self._rdclass = int(rdclass)

    @property
    def name(self):
        return self._name

    @property
    def rdtype(self):
        return self._rdtype

    @property
    def rdclass(self):
        return self._rdclass

    def to_text(self):
        return (f"{self._name.to_text()} "
                f"{class_to_text(self._rdclass)} "
                f"{type_to_text(self._rdtype)}")

    def __eq__(self, other):
        if not isinstance(other, QuestionEntry):
            return False
        return (self._name == other._name and
                self._rdtype == other._rdtype and
                self._rdclass == other._rdclass)

    def __hash__(self):
        return hash((self._name, self._rdtype, self._rdclass))

    def __repr__(self):
        return f"<Question {self.to_text()}>"


class DNSMessage:
    """A DNS protocol message.

    Contains a header (ID, flags) and four sections: question, answer,
    authority, and additional. Each answer/authority/additional section
    contains RRSet objects.
    """

    def __init__(self, msg_id=None):
        if msg_id is None:
            msg_id = random.randint(0, 65535)
        self._id = msg_id
        self._flags = 0
        self._question = []
        self._answer = []
        self._authority = []
        self._additional = []

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = value & 0xFFFF

    @property
    def flags(self):
        return self._flags

    @flags.setter
    def flags(self, value):
        self._flags = value

    @property
    def question(self):
        return self._question

    @property
    def answer(self):
        return self._answer

    @property
    def authority(self):
        return self._authority

    @property
    def additional(self):
        return self._additional

    def opcode(self):
        """Get the opcode from the message flags."""
        return opcode_from_flags(self._flags)

    def set_opcode(self, opcode):
        """Set the opcode in the message flags."""
        self._flags &= ~0x7800
        self._flags |= opcode_to_flags(opcode)

    def rcode(self):
        """Get the response code from the message flags (low 4 bits only)."""
        return self._flags & 0x000F

    def set_rcode(self, rcode):
        """Set the response code in the message flags (low 4 bits)."""
        self._flags = (self._flags & ~0x000F) | (rcode & 0x000F)

    def is_response(self):
        """Return True if the QR flag is set (this is a response)."""
        return bool(self._flags & MessageFlag.QR)

    def section_by_number(self, number):
        """Get a section by its number (0=question, 1=answer, etc.)."""
        sections = [self._question, self._answer, self._authority, self._additional]
        return sections[number]

    def add_question(self, name, rdtype, rdclass=RecordClass.IN):
        """Add a question entry to the message."""
        entry = QuestionEntry(name, rdtype, rdclass)
        self._question.append(entry)

    def find_rrset(self, section, name, rdtype, rdclass=RecordClass.IN, create=False):
        """Find an RRSet in a section by name, type, and class.

        If create is True and no matching RRSet exists, create one.
        Returns None if not found and create is False.
        """
        if isinstance(name, str):
            name = name_from_text(name)
        for rrset in section:
            if (isinstance(rrset, RRSet) and
                    rrset.name == name and
                    rrset.rdtype == int(rdtype) and
                    rrset.rdclass == int(rdclass)):
                return rrset
        if create:
            rrset = RRSet(name, int(rdtype), int(rdclass))
            section.append(rrset)
            return rrset
        return None

    def get_rrset(self, section, name, rdtype, rdclass=RecordClass.IN):
        """Get an RRSet, raising KeyError if not found."""
        result = self.find_rrset(section, name, rdtype, rdclass)
        if result is None:
            raise KeyError(f"no RRSet for {name} {type_to_text(rdtype)}")
        return result

    def to_text(self):
        """Convert the message to a human-readable text representation."""
        lines = []
        lines.append(f"id {self._id}")
        lines.append(f"opcode {opcode_to_text(self.opcode())}")
        lines.append(f"rcode {rcode_to_text(self.rcode())}")
        lines.append(f"flags {flags_to_text(self._flags)}")

        lines.append(f";QUESTION ({len(self._question)})")
        for q in self._question:
            lines.append(f"  {q.to_text()}")

        lines.append(f";ANSWER ({len(self._answer)})")
        for rrset in self._answer:
            if isinstance(rrset, RRSet):
                for line in rrset.to_text().split("\n"):
                    lines.append(f"  {line}")

        lines.append(f";AUTHORITY ({len(self._authority)})")
        for rrset in self._authority:
            if isinstance(rrset, RRSet):
                for line in rrset.to_text().split("\n"):
                    lines.append(f"  {line}")

        lines.append(f";ADDITIONAL ({len(self._additional)})")
        for rrset in self._additional:
            if isinstance(rrset, RRSet):
                for line in rrset.to_text().split("\n"):
                    lines.append(f"  {line}")

        return "\n".join(lines)

    def __repr__(self):
        return f"<DNSMessage id={self._id} qr={self.is_response()}>"


def build_query(name, rdtype=RecordType.A, rdclass=RecordClass.IN,
                use_edns=False, want_dnssec=False):
    """Build a standard DNS query message.

    Creates a message with QR=0, OPCODE=QUERY, RD=1, and a single
    question entry for the given name/type/class.
    """
    msg = DNSMessage()
    msg.flags = MessageFlag.RD
    msg.set_opcode(OpCode.QUERY)
    if isinstance(name, str):
        name = name_from_text(name)
    msg.add_question(name, rdtype, rdclass)
    return msg


def build_response(query, rcode=0):
    """Build a response message for a query.

    Copies the query ID and question, sets QR=1.
    """
    msg = DNSMessage(query.id)
    msg.flags = query.flags | MessageFlag.QR
    msg.set_rcode(rcode)
    for q in query.question:
        msg.add_question(q.name, q.rdtype, q.rdclass)
    return msg
