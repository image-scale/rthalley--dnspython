"""Tests for DNS zone management."""

import pytest
from dnscore.zone import Zone, NoSOAError, NoNSError, BadZoneError
from dnscore.domain_name import from_text as name_from_text, EMPTY
from dnscore.record_type import RecordType
from dnscore.record_class import RecordClass
from dnscore.record_data import ARecord, NSRecord, SOARecord, MXRecord


SAMPLE_ZONE = """\
$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400
@ IN NS ns1.example.com.
@ IN NS ns2.example.com.
@ IN A 93.184.216.34
@ IN MX 10 mail.example.com.
www IN A 93.184.216.34
mail IN A 93.184.216.35
"""


class TestZoneFromText:
    def test_load_zone(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        assert zone.origin == name_from_text("example.com.")
        assert len(zone) > 0

    def test_origin(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        assert zone.origin == name_from_text("example.com.")

    def test_rdclass(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        assert zone.rdclass == RecordClass.IN

    def test_has_soa(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        origin_key = name_from_text("example.com.").relativize(zone.origin)
        node = zone.find_node(origin_key)
        assert node is not None
        soa_ds = node.find_rdataset(RecordType.SOA)
        assert soa_ds is not None
        assert len(soa_ds) == 1

    def test_has_ns(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        origin_key = name_from_text("example.com.").relativize(zone.origin)
        node = zone.find_node(origin_key)
        ns_ds = node.find_rdataset(RecordType.NS)
        assert ns_ds is not None
        assert len(ns_ds) == 2

    def test_www_record(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        www_name = name_from_text("www", origin=None)
        node = zone.find_node(www_name)
        assert node is not None
        a_ds = node.find_rdataset(RecordType.A)
        assert a_ds is not None
        assert len(a_ds) == 1

    def test_mail_record(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        mail_name = name_from_text("mail", origin=None)
        node = zone.find_node(mail_name)
        assert node is not None


class TestZoneValidation:
    def test_no_soa_raises(self):
        text = "$ORIGIN example.com.\n@ 3600 IN NS ns1.example.com.\n"
        with pytest.raises(NoSOAError):
            Zone.from_text(text, origin="example.com.")

    def test_no_ns_raises(self):
        text = "$ORIGIN example.com.\n@ 3600 IN SOA ns1.example.com. admin.example.com. 1 3600 900 604800 86400\n"
        with pytest.raises(NoNSError):
            Zone.from_text(text, origin="example.com.")

    def test_skip_check(self):
        text = "$ORIGIN example.com.\n@ 3600 IN A 1.2.3.4\n"
        zone = Zone.from_text(text, origin="example.com.", check_origin=False)
        assert len(zone) > 0


class TestZoneNodeAccess:
    def test_find_node(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        www = name_from_text("www", origin=None)
        node = zone.find_node(www)
        assert node is not None

    def test_find_nonexistent(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        missing = name_from_text("nonexistent", origin=None)
        assert zone.find_node(missing) is None

    def test_get_node_raises(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        missing = name_from_text("nonexistent", origin=None)
        with pytest.raises(KeyError):
            zone.get_node(missing)

    def test_find_rdataset(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        www = name_from_text("www", origin=None)
        ds = zone.find_rdataset(www, RecordType.A)
        assert ds is not None
        assert len(ds) == 1

    def test_find_rdataset_missing(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        www = name_from_text("www", origin=None)
        ds = zone.find_rdataset(www, RecordType.AAAA)
        assert ds is None


class TestZoneDictLike:
    def test_len(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        assert len(zone) >= 3  # origin, www, mail

    def test_contains(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        www = name_from_text("www", origin=None)
        assert www in zone

    def test_not_contains(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        missing = name_from_text("nope", origin=None)
        assert missing not in zone

    def test_getitem(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        www = name_from_text("www", origin=None)
        node = zone[www]
        assert node is not None

    def test_iter(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        names = list(zone)
        assert len(names) >= 3

    def test_delitem(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.", check_origin=False)
        www = name_from_text("www", origin=None)
        assert www in zone
        del zone[www]
        assert www not in zone


class TestZoneModification:
    def test_add_record(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        ftp = name_from_text("ftp", origin=None)
        ds = zone.find_rdataset(ftp, RecordType.A, create=True)
        ds.add(ARecord("10.0.0.1"), ttl=300)
        assert ftp in zone
        retrieved = zone.find_rdataset(ftp, RecordType.A)
        assert len(retrieved) == 1

    def test_delete_rdataset(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.", check_origin=False)
        www = name_from_text("www", origin=None)
        zone.delete_rdataset(www, RecordType.A)
        assert www not in zone

    def test_delete_node(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.", check_origin=False)
        mail = name_from_text("mail", origin=None)
        zone.delete_node(mail)
        assert mail not in zone


class TestZoneToText:
    def test_to_text(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        text = zone.to_text()
        assert "$ORIGIN example.com." in text
        assert "SOA" in text
        assert "NS" in text
        assert "93.184.216.34" in text

    def test_roundtrip(self):
        zone1 = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        text = zone1.to_text()
        zone2 = Zone.from_text(text, origin="example.com.")
        assert len(zone1) == len(zone2)


class TestZoneNames:
    def test_names(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        names = zone.names()
        assert len(names) >= 3

    def test_nodes(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        node_list = zone.nodes()
        assert len(node_list) >= 3
        for name, node in node_list:
            assert node is not None

    def test_absolute_name_access(self):
        zone = Zone.from_text(SAMPLE_ZONE, origin="example.com.")
        abs_name = name_from_text("www.example.com.")
        node = zone.find_node(abs_name)
        assert node is not None
