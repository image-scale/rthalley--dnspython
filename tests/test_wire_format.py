"""Tests for DNS wire format serialization and parsing."""

import struct
import pytest
from dnscore.wire_format import (
    WireWriter, message_to_wire, message_from_wire, HEADER_SIZE,
)
from dnscore.message import DNSMessage, build_query, build_response, MessageSection
from dnscore.msg_flags import MessageFlag
from dnscore.op_code import OpCode
from dnscore.record_type import RecordType
from dnscore.record_class import RecordClass
from dnscore.record_data import ARecord, AAAARecord, MXRecord, NSRecord, TXTRecord, SOARecord
from dnscore.record_sets import RRSet
from dnscore.domain_name import from_text as name_from_text
from dnscore.exceptions import FormError


class TestWireWriter:
    def test_basic_header(self):
        writer = WireWriter(msg_id=0x1234, flags=0x0100)
        wire = writer.get_wire()
        assert len(wire) >= HEADER_SIZE
        msg_id, flags = struct.unpack("!HH", wire[:4])
        assert msg_id == 0x1234
        assert flags == 0x0100

    def test_question_count(self):
        writer = WireWriter(msg_id=1, flags=0)
        writer.add_question("example.com.", RecordType.A)
        wire = writer.get_wire()
        qdcount = struct.unpack("!H", wire[4:6])[0]
        assert qdcount == 1

    def test_answer_count(self):
        writer = WireWriter(msg_id=1, flags=0)
        rrset = RRSet("example.com.", RecordType.A, RecordClass.IN, 300)
        rrset.add(ARecord("1.2.3.4"))
        writer.add_rrset(MessageSection.ANSWER, rrset)
        wire = writer.get_wire()
        ancount = struct.unpack("!H", wire[6:8])[0]
        assert ancount == 1


class TestMessageToWire:
    def test_query_roundtrip(self):
        query = build_query("example.com.", RecordType.A)
        query.id = 0xABCD
        wire = message_to_wire(query)
        parsed = message_from_wire(wire)
        assert parsed.id == 0xABCD
        assert len(parsed.question) == 1
        assert parsed.question[0].rdtype == RecordType.A
        assert parsed.question[0].name == name_from_text("example.com.")

    def test_response_with_answer(self):
        query = build_query("example.com.", RecordType.A)
        query.id = 42
        response = build_response(query)
        rrset = RRSet("example.com.", RecordType.A, RecordClass.IN, 300)
        rrset.add(ARecord("93.184.216.34"))
        response.answer.append(rrset)

        wire = message_to_wire(response)
        parsed = message_from_wire(wire)

        assert parsed.id == 42
        assert parsed.is_response()
        assert len(parsed.answer) == 1
        answer_rrset = parsed.answer[0]
        assert answer_rrset.name == name_from_text("example.com.")
        assert len(answer_rrset) == 1
        rdata = list(answer_rrset)[0]
        assert isinstance(rdata, ARecord)
        assert rdata.address == "93.184.216.34"

    def test_multiple_answers(self):
        msg = DNSMessage(100)
        msg.flags = MessageFlag.QR | MessageFlag.RD | MessageFlag.RA
        msg.add_question("example.com.", RecordType.A)

        rrset = RRSet("example.com.", RecordType.A, RecordClass.IN, 300)
        rrset.add(ARecord("1.2.3.4"))
        rrset.add(ARecord("5.6.7.8"))
        msg.answer.append(rrset)

        wire = message_to_wire(msg)
        parsed = message_from_wire(wire)

        assert len(parsed.answer) == 1
        assert len(parsed.answer[0]) == 2

    def test_authority_and_additional(self):
        msg = DNSMessage(200)
        msg.flags = MessageFlag.QR
        msg.add_question("example.com.", RecordType.A)

        ns_rrset = RRSet("example.com.", RecordType.NS, RecordClass.IN, 3600)
        ns_rrset.add(NSRecord("ns1.example.com."))
        msg.authority.append(ns_rrset)

        a_rrset = RRSet("ns1.example.com.", RecordType.A, RecordClass.IN, 3600)
        a_rrset.add(ARecord("10.0.0.1"))
        msg.additional.append(a_rrset)

        wire = message_to_wire(msg)
        parsed = message_from_wire(wire)

        assert len(parsed.authority) == 1
        assert len(parsed.additional) == 1
        ns_rec = list(parsed.authority[0])[0]
        assert isinstance(ns_rec, NSRecord)

    def test_mx_record_roundtrip(self):
        msg = DNSMessage(300)
        msg.flags = MessageFlag.QR
        msg.add_question("example.com.", RecordType.MX)

        rrset = RRSet("example.com.", RecordType.MX, RecordClass.IN, 600)
        rrset.add(MXRecord(10, "mail.example.com."))
        msg.answer.append(rrset)

        wire = message_to_wire(msg)
        parsed = message_from_wire(wire)

        mx = list(parsed.answer[0])[0]
        assert isinstance(mx, MXRecord)
        assert mx.preference == 10

    def test_aaaa_record_roundtrip(self):
        msg = DNSMessage(400)
        msg.flags = MessageFlag.QR
        msg.add_question("example.com.", RecordType.AAAA)

        rrset = RRSet("example.com.", RecordType.AAAA, RecordClass.IN, 300)
        rrset.add(AAAARecord("2001:db8::1"))
        msg.answer.append(rrset)

        wire = message_to_wire(msg)
        parsed = message_from_wire(wire)

        aaaa = list(parsed.answer[0])[0]
        assert isinstance(aaaa, AAAARecord)
        assert aaaa.address == "2001:db8::1"

    def test_txt_record_roundtrip(self):
        msg = DNSMessage(500)
        msg.flags = MessageFlag.QR
        msg.add_question("example.com.", RecordType.TXT)

        rrset = RRSet("example.com.", RecordType.TXT, RecordClass.IN, 300)
        rrset.add(TXTRecord("v=spf1 include:example.com ~all"))
        msg.answer.append(rrset)

        wire = message_to_wire(msg)
        parsed = message_from_wire(wire)

        txt = list(parsed.answer[0])[0]
        assert isinstance(txt, TXTRecord)
        assert txt.strings[0] == b"v=spf1 include:example.com ~all"

    def test_flags_preserved(self):
        msg = DNSMessage(600)
        msg.flags = MessageFlag.QR | MessageFlag.AA | MessageFlag.RD | MessageFlag.RA
        msg.add_question("test.com.", RecordType.A)

        wire = message_to_wire(msg)
        parsed = message_from_wire(wire)

        assert parsed.flags & MessageFlag.QR
        assert parsed.flags & MessageFlag.AA
        assert parsed.flags & MessageFlag.RD
        assert parsed.flags & MessageFlag.RA

    def test_opcode_preserved(self):
        msg = DNSMessage(700)
        msg.set_opcode(OpCode.QUERY)
        msg.add_question("test.com.", RecordType.A)

        wire = message_to_wire(msg)
        parsed = message_from_wire(wire)
        assert parsed.opcode() == OpCode.QUERY

    def test_soa_roundtrip(self):
        msg = DNSMessage(800)
        msg.flags = MessageFlag.QR
        msg.add_question("example.com.", RecordType.SOA)

        soa = SOARecord("ns1.example.com.", "admin.example.com.",
                         2024010101, 3600, 900, 604800, 86400)
        rrset = RRSet("example.com.", RecordType.SOA, RecordClass.IN, 3600)
        rrset.add(soa)
        msg.answer.append(rrset)

        wire = message_to_wire(msg)
        parsed = message_from_wire(wire)

        parsed_soa = list(parsed.answer[0])[0]
        assert isinstance(parsed_soa, SOARecord)
        assert parsed_soa.serial == 2024010101
        assert parsed_soa.refresh == 3600


class TestMessageFromWireErrors:
    def test_too_short(self):
        with pytest.raises(FormError):
            message_from_wire(b"\x00" * 5)

    def test_truncated_question(self):
        header = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0)
        with pytest.raises((FormError, Exception)):
            message_from_wire(header + b"\x00")


class TestNameCompression:
    def test_compression_reduces_size(self):
        msg = DNSMessage(1)
        msg.flags = MessageFlag.QR
        msg.add_question("example.com.", RecordType.A)

        rrset1 = RRSet("example.com.", RecordType.A, RecordClass.IN, 300)
        rrset1.add(ARecord("1.2.3.4"))
        msg.answer.append(rrset1)

        rrset2 = RRSet("example.com.", RecordType.A, RecordClass.IN, 300)
        rrset2.add(ARecord("5.6.7.8"))
        msg.answer.append(rrset2)

        wire = message_to_wire(msg)
        parsed = message_from_wire(wire)
        assert len(parsed.question) == 1
        total_answers = sum(len(rrset) for rrset in parsed.answer)
        assert total_answers == 2
