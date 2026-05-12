"""Tests for DNS dynamic update messages."""

import pytest

from dnscore.update import UpdateMessage, UpdateSection
from dnscore.domain_name import from_text as name_from_text
from dnscore.record_type import RecordType
from dnscore.record_class import RecordClass
from dnscore.record_sets import RRSet
from dnscore.op_code import OpCode
from dnscore.wire_format import message_to_wire, message_from_wire


class TestUpdateCreation:
    def test_creates_with_update_opcode(self):
        msg = UpdateMessage("example.com.")
        assert msg.opcode() == OpCode.UPDATE

    def test_zone_section_has_soa(self):
        msg = UpdateMessage("example.com.")
        assert len(msg.zone_section) == 1
        q = msg.zone_section[0]
        assert q.rdtype == RecordType.SOA
        assert q.name == name_from_text("example.com.")

    def test_zone_name(self):
        msg = UpdateMessage("example.com.")
        assert msg.zone_name == name_from_text("example.com.")

    def test_zone_rdclass(self):
        msg = UpdateMessage("example.com.", rdclass=RecordClass.CH)
        assert msg.zone_rdclass == RecordClass.CH

    def test_zone_from_domain_name(self):
        zone = name_from_text("example.com.")
        msg = UpdateMessage(zone)
        assert msg.zone_name == zone

    def test_sections_empty(self):
        msg = UpdateMessage("example.com.")
        assert len(msg.prerequisite) == 0
        assert len(msg.update_section) == 0
        assert len(msg.additional) == 0

    def test_custom_id(self):
        msg = UpdateMessage("example.com.", msg_id=12345)
        assert msg.id == 12345


class TestPrerequisitePresent:
    def test_name_exists(self):
        msg = UpdateMessage("example.com.")
        msg.present("www.example.com.")
        assert len(msg.prerequisite) == 1
        rrset = msg.prerequisite[0]
        assert rrset.name == name_from_text("www.example.com.")
        assert rrset.rdtype == RecordType.ANY
        assert rrset.rdclass == RecordClass.ANY

    def test_rdtype_exists(self):
        msg = UpdateMessage("example.com.")
        msg.present("www.example.com.", RecordType.A)
        assert len(msg.prerequisite) == 1
        rrset = msg.prerequisite[0]
        assert rrset.rdtype == RecordType.A
        assert rrset.rdclass == RecordClass.ANY

    def test_specific_record(self):
        msg = UpdateMessage("example.com.")
        msg.present("www.example.com.", RecordType.A, "1.2.3.4")
        assert len(msg.prerequisite) == 1
        rrset = msg.prerequisite[0]
        assert rrset.rdtype == RecordType.A
        assert rrset.rdclass == RecordClass.IN
        assert len(rrset) == 1

    def test_multiple_records(self):
        msg = UpdateMessage("example.com.")
        msg.present("www.example.com.", RecordType.A, "1.2.3.4", "5.6.7.8")
        rrset = msg.prerequisite[0]
        assert len(rrset) == 2

    def test_string_rdtype(self):
        msg = UpdateMessage("example.com.")
        msg.present("www.example.com.", "AAAA")
        rrset = msg.prerequisite[0]
        assert rrset.rdtype == RecordType.AAAA

    def test_ttl_is_zero(self):
        msg = UpdateMessage("example.com.")
        msg.present("www.example.com.", RecordType.A, "1.2.3.4")
        rrset = msg.prerequisite[0]
        assert rrset.ttl == 0


class TestPrerequisiteAbsent:
    def test_name_absent(self):
        msg = UpdateMessage("example.com.")
        msg.absent("www.example.com.")
        assert len(msg.prerequisite) == 1
        rrset = msg.prerequisite[0]
        assert rrset.name == name_from_text("www.example.com.")
        assert rrset.rdtype == RecordType.ANY
        assert rrset.rdclass == RecordClass.NONE

    def test_rdtype_absent(self):
        msg = UpdateMessage("example.com.")
        msg.absent("www.example.com.", RecordType.MX)
        rrset = msg.prerequisite[0]
        assert rrset.rdtype == RecordType.MX
        assert rrset.rdclass == RecordClass.NONE

    def test_string_rdtype(self):
        msg = UpdateMessage("example.com.")
        msg.absent("www.example.com.", "AAAA")
        rrset = msg.prerequisite[0]
        assert rrset.rdtype == RecordType.AAAA
        assert rrset.rdclass == RecordClass.NONE


class TestUpdateAdd:
    def test_add_record(self):
        msg = UpdateMessage("example.com.")
        msg.add("www.example.com.", 300, RecordType.A, "1.2.3.4")
        assert len(msg.update_section) == 1
        rrset = msg.update_section[0]
        assert rrset.name == name_from_text("www.example.com.")
        assert rrset.rdtype == RecordType.A
        assert rrset.rdclass == RecordClass.IN
        assert rrset.ttl == 300
        assert len(rrset) == 1

    def test_add_multiple_records(self):
        msg = UpdateMessage("example.com.")
        msg.add("www.example.com.", 300, RecordType.A, "1.2.3.4", "5.6.7.8")
        rrset = msg.update_section[0]
        assert len(rrset) == 2

    def test_add_string_rdtype(self):
        msg = UpdateMessage("example.com.")
        msg.add("www.example.com.", 3600, "A", "10.0.0.1")
        rrset = msg.update_section[0]
        assert rrset.rdtype == RecordType.A

    def test_add_mx(self):
        msg = UpdateMessage("example.com.")
        msg.add("example.com.", 3600, RecordType.MX, "10 mail.example.com.")
        rrset = msg.update_section[0]
        assert rrset.rdtype == RecordType.MX
        assert len(rrset) == 1

    def test_add_ns(self):
        msg = UpdateMessage("example.com.")
        msg.add("example.com.", 3600, RecordType.NS, "ns1.example.com.")
        rrset = msg.update_section[0]
        assert rrset.rdtype == RecordType.NS


class TestUpdateDelete:
    def test_delete_all_at_name(self):
        msg = UpdateMessage("example.com.")
        msg.delete("old.example.com.")
        assert len(msg.update_section) == 1
        rrset = msg.update_section[0]
        assert rrset.name == name_from_text("old.example.com.")
        assert rrset.rdtype == RecordType.ANY
        assert rrset.rdclass == RecordClass.ANY

    def test_delete_rdtype(self):
        msg = UpdateMessage("example.com.")
        msg.delete("www.example.com.", RecordType.A)
        rrset = msg.update_section[0]
        assert rrset.rdtype == RecordType.A
        assert rrset.rdclass == RecordClass.ANY
        assert len(rrset) == 0

    def test_delete_specific_record(self):
        msg = UpdateMessage("example.com.")
        msg.delete("www.example.com.", RecordType.A, "1.2.3.4")
        rrset = msg.update_section[0]
        assert rrset.rdtype == RecordType.A
        assert rrset.rdclass == RecordClass.NONE
        assert len(rrset) == 1

    def test_delete_string_rdtype(self):
        msg = UpdateMessage("example.com.")
        msg.delete("www.example.com.", "AAAA")
        rrset = msg.update_section[0]
        assert rrset.rdtype == RecordType.AAAA


class TestUpdateReplace:
    def test_replace_creates_delete_then_add(self):
        msg = UpdateMessage("example.com.")
        msg.replace("www.example.com.", 300, RecordType.A, "10.0.0.1")
        assert len(msg.update_section) == 2
        del_rrset = msg.update_section[0]
        assert del_rrset.rdtype == RecordType.A
        assert del_rrset.rdclass == RecordClass.ANY
        assert len(del_rrset) == 0

        add_rrset = msg.update_section[1]
        assert add_rrset.rdtype == RecordType.A
        assert add_rrset.rdclass == RecordClass.IN
        assert add_rrset.ttl == 300
        assert len(add_rrset) == 1

    def test_replace_multiple(self):
        msg = UpdateMessage("example.com.")
        msg.replace("www.example.com.", 300, RecordType.A, "10.0.0.1", "10.0.0.2")
        add_rrset = msg.update_section[1]
        assert len(add_rrset) == 2

    def test_replace_string_rdtype(self):
        msg = UpdateMessage("example.com.")
        msg.replace("www.example.com.", 600, "AAAA", "::1")
        add_rrset = msg.update_section[1]
        assert add_rrset.rdtype == RecordType.AAAA


class TestUpdateCombined:
    def test_prereq_and_update(self):
        msg = UpdateMessage("example.com.")
        msg.present("www.example.com.", RecordType.A)
        msg.delete("www.example.com.", RecordType.A)
        msg.add("www.example.com.", 300, RecordType.A, "10.0.0.1")

        assert len(msg.prerequisite) == 1
        assert len(msg.update_section) == 2

    def test_absent_then_add(self):
        msg = UpdateMessage("example.com.")
        msg.absent("new.example.com.")
        msg.add("new.example.com.", 3600, RecordType.A, "192.168.1.1")

        prereq = msg.prerequisite[0]
        assert prereq.rdclass == RecordClass.NONE

        update = msg.update_section[0]
        assert update.rdclass == RecordClass.IN
        assert len(update) == 1

    def test_wire_roundtrip(self):
        msg = UpdateMessage("example.com.", msg_id=9999)
        msg.add("www.example.com.", 300, RecordType.A, "1.2.3.4")
        wire = message_to_wire(msg)
        parsed = message_from_wire(wire)
        assert parsed.id == 9999
        assert parsed.opcode() == OpCode.UPDATE
        assert len(parsed.question) == 1
        assert parsed.question[0].rdtype == RecordType.SOA
