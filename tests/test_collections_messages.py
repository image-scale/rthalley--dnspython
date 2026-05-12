"""Tests for record collections and DNS messages."""

import pytest
from dnscore.record_sets import RRDataSet, RRSet, ZoneNode
from dnscore.message import (
    DNSMessage, QuestionEntry, MessageSection,
    build_query, build_response,
)
from dnscore.record_data import ARecord, MXRecord, NSRecord, TXTRecord, SOARecord
from dnscore.record_type import RecordType
from dnscore.record_class import RecordClass
from dnscore.msg_flags import MessageFlag
from dnscore.op_code import OpCode
from dnscore.domain_name import from_text as name_from_text


class TestRRDataSet:
    def test_create(self):
        ds = RRDataSet(RecordType.A, RecordClass.IN, 300)
        assert ds.rdtype == RecordType.A
        assert ds.rdclass == RecordClass.IN
        assert ds.ttl == 300
        assert len(ds) == 0

    def test_add_record(self):
        ds = RRDataSet(RecordType.A, RecordClass.IN, 300)
        rec = ARecord("1.2.3.4")
        ds.add(rec)
        assert len(ds) == 1
        assert rec in ds

    def test_add_duplicate(self):
        ds = RRDataSet(RecordType.A, RecordClass.IN, 300)
        rec = ARecord("1.2.3.4")
        ds.add(rec)
        ds.add(rec)
        assert len(ds) == 1

    def test_ttl_minimum(self):
        ds = RRDataSet(RecordType.A, RecordClass.IN, 300)
        rec1 = ARecord("1.2.3.4")
        rec2 = ARecord("5.6.7.8")
        ds.add(rec1, ttl=300)
        ds.add(rec2, ttl=100)
        assert ds.ttl == 100

    def test_ttl_not_increased(self):
        ds = RRDataSet(RecordType.A, RecordClass.IN, 100)
        ds.add(ARecord("1.2.3.4"), ttl=100)
        ds.add(ARecord("5.6.7.8"), ttl=500)
        assert ds.ttl == 100

    def test_wrong_type_raises(self):
        ds = RRDataSet(RecordType.A, RecordClass.IN, 300)
        mx = MXRecord(10, "mail.example.com.")
        with pytest.raises(ValueError):
            ds.add(mx)

    def test_remove(self):
        ds = RRDataSet(RecordType.A, RecordClass.IN, 300)
        rec = ARecord("1.2.3.4")
        ds.add(rec)
        ds.remove(rec)
        assert len(ds) == 0

    def test_iter(self):
        ds = RRDataSet(RecordType.A, RecordClass.IN, 300)
        ds.add(ARecord("1.2.3.4"))
        ds.add(ARecord("5.6.7.8"))
        records = list(ds)
        assert len(records) == 2

    def test_bool_empty(self):
        ds = RRDataSet(RecordType.A, RecordClass.IN, 300)
        assert not ds

    def test_bool_non_empty(self):
        ds = RRDataSet(RecordType.A, RecordClass.IN, 300)
        ds.add(ARecord("1.2.3.4"))
        assert ds

    def test_to_text(self):
        ds = RRDataSet(RecordType.A, RecordClass.IN, 300)
        ds.add(ARecord("1.2.3.4"))
        text = ds.to_text()
        assert "300" in text
        assert "IN" in text
        assert "A" in text
        assert "1.2.3.4" in text

    def test_to_text_with_name(self):
        ds = RRDataSet(RecordType.A, RecordClass.IN, 300)
        ds.add(ARecord("1.2.3.4"))
        name = name_from_text("example.com.")
        text = ds.to_text(name=name)
        assert "example.com." in text

    def test_equality(self):
        ds1 = RRDataSet(RecordType.A, RecordClass.IN, 300)
        ds1.add(ARecord("1.2.3.4"))
        ds2 = RRDataSet(RecordType.A, RecordClass.IN, 300)
        ds2.add(ARecord("1.2.3.4"))
        assert ds1 == ds2

    def test_inequality(self):
        ds1 = RRDataSet(RecordType.A, RecordClass.IN, 300)
        ds1.add(ARecord("1.2.3.4"))
        ds2 = RRDataSet(RecordType.A, RecordClass.IN, 300)
        ds2.add(ARecord("5.6.7.8"))
        assert ds1 != ds2

    def test_copy(self):
        ds = RRDataSet(RecordType.A, RecordClass.IN, 300)
        ds.add(ARecord("1.2.3.4"))
        cp = ds.copy()
        assert cp == ds
        assert cp is not ds


class TestRRSet:
    def test_create(self):
        rrset = RRSet("example.com.", RecordType.A, RecordClass.IN, 300)
        assert rrset.name == name_from_text("example.com.")
        assert rrset.rdtype == RecordType.A

    def test_add_and_retrieve(self):
        rrset = RRSet("example.com.", RecordType.A, RecordClass.IN, 300)
        rrset.add(ARecord("1.2.3.4"))
        assert len(rrset) == 1

    def test_to_text(self):
        rrset = RRSet("example.com.", RecordType.A, RecordClass.IN, 300)
        rrset.add(ARecord("1.2.3.4"))
        text = rrset.to_text()
        assert "example.com." in text
        assert "1.2.3.4" in text

    def test_from_rdata(self):
        a1 = ARecord("1.2.3.4")
        a2 = ARecord("5.6.7.8")
        rrset = RRSet.from_rdata("example.com.", 300, a1, a2)
        assert len(rrset) == 2
        assert rrset.ttl == 300

    def test_from_text(self):
        rrset = RRSet.from_text("example.com.", 300, RecordClass.IN, RecordType.A,
                                "1.2.3.4", "5.6.7.8")
        assert len(rrset) == 2

    def test_equality(self):
        r1 = RRSet("example.com.", RecordType.A, RecordClass.IN, 300)
        r1.add(ARecord("1.2.3.4"))
        r2 = RRSet("example.com.", RecordType.A, RecordClass.IN, 300)
        r2.add(ARecord("1.2.3.4"))
        assert r1 == r2

    def test_inequality_name(self):
        r1 = RRSet("a.com.", RecordType.A, RecordClass.IN, 300)
        r1.add(ARecord("1.2.3.4"))
        r2 = RRSet("b.com.", RecordType.A, RecordClass.IN, 300)
        r2.add(ARecord("1.2.3.4"))
        assert r1 != r2

    def test_to_rdataset(self):
        rrset = RRSet("example.com.", RecordType.A, RecordClass.IN, 300)
        rrset.add(ARecord("1.2.3.4"))
        ds = rrset.to_rdataset()
        assert isinstance(ds, RRDataSet)
        assert not isinstance(ds, RRSet)
        assert len(ds) == 1

    def test_repr(self):
        rrset = RRSet("example.com.", RecordType.A, RecordClass.IN, 300)
        rrset.add(ARecord("1.2.3.4"))
        r = repr(rrset)
        assert "example.com." in r
        assert "A" in r


class TestZoneNode:
    def test_create_empty(self):
        node = ZoneNode()
        assert len(node) == 0

    def test_find_create(self):
        node = ZoneNode()
        ds = node.find_rdataset(RecordType.A, create=True)
        assert ds is not None
        assert ds.rdtype == RecordType.A

    def test_find_existing(self):
        node = ZoneNode()
        ds1 = node.find_rdataset(RecordType.A, create=True)
        ds2 = node.find_rdataset(RecordType.A)
        assert ds1 is ds2

    def test_find_nonexistent(self):
        node = ZoneNode()
        result = node.find_rdataset(RecordType.AAAA)
        assert result is None

    def test_get_raises(self):
        node = ZoneNode()
        with pytest.raises(KeyError):
            node.get_rdataset(RecordType.A)

    def test_delete(self):
        node = ZoneNode()
        node.find_rdataset(RecordType.A, create=True)
        node.delete_rdataset(RecordType.A)
        assert len(node) == 0

    def test_multiple_types(self):
        node = ZoneNode()
        node.find_rdataset(RecordType.A, create=True)
        node.find_rdataset(RecordType.AAAA, create=True)
        node.find_rdataset(RecordType.MX, create=True)
        assert len(node) == 3

    def test_iter(self):
        node = ZoneNode()
        node.find_rdataset(RecordType.A, create=True)
        node.find_rdataset(RecordType.MX, create=True)
        types = [ds.rdtype for ds in node]
        assert RecordType.A in types
        assert RecordType.MX in types

    def test_to_text(self):
        node = ZoneNode()
        ds = node.find_rdataset(RecordType.A, create=True)
        ds.add(ARecord("1.2.3.4"), ttl=300)
        text = node.to_text(name=name_from_text("example.com."))
        assert "example.com." in text
        assert "1.2.3.4" in text


class TestQuestionEntry:
    def test_create(self):
        q = QuestionEntry("example.com.", RecordType.A)
        assert q.name == name_from_text("example.com.")
        assert q.rdtype == RecordType.A
        assert q.rdclass == RecordClass.IN

    def test_to_text(self):
        q = QuestionEntry("example.com.", RecordType.A)
        text = q.to_text()
        assert "example.com." in text
        assert "A" in text

    def test_equality(self):
        q1 = QuestionEntry("example.com.", RecordType.A)
        q2 = QuestionEntry("example.com.", RecordType.A)
        assert q1 == q2

    def test_inequality(self):
        q1 = QuestionEntry("a.com.", RecordType.A)
        q2 = QuestionEntry("b.com.", RecordType.A)
        assert q1 != q2


class TestDNSMessage:
    def test_create(self):
        msg = DNSMessage(1234)
        assert msg.id == 1234
        assert len(msg.question) == 0

    def test_auto_id(self):
        msg = DNSMessage()
        assert 0 <= msg.id <= 65535

    def test_add_question(self):
        msg = DNSMessage()
        msg.add_question("example.com.", RecordType.A)
        assert len(msg.question) == 1
        assert msg.question[0].rdtype == RecordType.A

    def test_flags(self):
        msg = DNSMessage()
        msg.flags = MessageFlag.QR | MessageFlag.AA
        assert msg.flags & MessageFlag.QR
        assert msg.flags & MessageFlag.AA

    def test_opcode(self):
        msg = DNSMessage()
        msg.set_opcode(OpCode.QUERY)
        assert msg.opcode() == OpCode.QUERY
        msg.set_opcode(OpCode.UPDATE)
        assert msg.opcode() == OpCode.UPDATE

    def test_rcode(self):
        msg = DNSMessage()
        msg.set_rcode(3)
        assert msg.rcode() == 3

    def test_is_response(self):
        msg = DNSMessage()
        assert not msg.is_response()
        msg.flags |= MessageFlag.QR
        assert msg.is_response()

    def test_sections(self):
        msg = DNSMessage()
        assert msg.section_by_number(MessageSection.QUESTION) is msg.question
        assert msg.section_by_number(MessageSection.ANSWER) is msg.answer
        assert msg.section_by_number(MessageSection.AUTHORITY) is msg.authority
        assert msg.section_by_number(MessageSection.ADDITIONAL) is msg.additional

    def test_find_rrset_create(self):
        msg = DNSMessage()
        rrset = msg.find_rrset(msg.answer, "example.com.", RecordType.A, create=True)
        assert rrset is not None
        assert rrset.name == name_from_text("example.com.")

    def test_find_rrset_existing(self):
        msg = DNSMessage()
        rrset1 = msg.find_rrset(msg.answer, "example.com.", RecordType.A, create=True)
        rrset1.add(ARecord("1.2.3.4"), ttl=300)
        rrset2 = msg.find_rrset(msg.answer, "example.com.", RecordType.A)
        assert rrset1 is rrset2

    def test_find_rrset_not_found(self):
        msg = DNSMessage()
        result = msg.find_rrset(msg.answer, "example.com.", RecordType.A)
        assert result is None

    def test_get_rrset_raises(self):
        msg = DNSMessage()
        with pytest.raises(KeyError):
            msg.get_rrset(msg.answer, "example.com.", RecordType.A)

    def test_to_text(self):
        msg = DNSMessage(1234)
        msg.add_question("example.com.", RecordType.A)
        msg.flags = MessageFlag.RD
        text = msg.to_text()
        assert "1234" in text
        assert "QUERY" in text
        assert "example.com." in text
        assert "QUESTION" in text
        assert "ANSWER" in text

    def test_repr(self):
        msg = DNSMessage(1234)
        assert "1234" in repr(msg)


class TestBuildQuery:
    def test_basic_query(self):
        msg = build_query("example.com.", RecordType.A)
        assert not msg.is_response()
        assert msg.opcode() == OpCode.QUERY
        assert msg.flags & MessageFlag.RD
        assert len(msg.question) == 1
        assert msg.question[0].rdtype == RecordType.A

    def test_custom_type(self):
        msg = build_query("example.com.", RecordType.MX)
        assert msg.question[0].rdtype == RecordType.MX

    def test_custom_class(self):
        msg = build_query("example.com.", RecordType.A, RecordClass.CH)
        assert msg.question[0].rdclass == RecordClass.CH


class TestBuildResponse:
    def test_response_from_query(self):
        query = build_query("example.com.", RecordType.A)
        response = build_response(query)
        assert response.is_response()
        assert response.id == query.id
        assert len(response.question) == 1
        assert response.question[0] == query.question[0]

    def test_response_rcode(self):
        query = build_query("example.com.", RecordType.A)
        response = build_response(query, rcode=3)
        assert response.rcode() == 3
