"""DNS zone management.

A Zone holds DNS resource records organized by domain name and record type.
Zones can be loaded from zone file text and exported back to text format.
"""

from collections import OrderedDict

from dnscore.domain_name import DomainName, from_text as name_from_text, ROOT
from dnscore.record_type import RecordType, type_to_text
from dnscore.record_class import RecordClass, class_to_text
from dnscore.record_sets import RRDataSet, ZoneNode
from dnscore.zone_parser import parse_zone_text


class BadZoneError(Exception):
    """The zone data is malformed."""
    pass


class NoSOAError(BadZoneError):
    """No SOA record at the zone origin."""
    pass


class NoNSError(BadZoneError):
    """No NS record set at the zone origin."""
    pass


class Zone:
    """A DNS zone — a collection of resource records for a domain.

    Provides a dict-like interface mapping DomainNames to ZoneNodes.
    Names stored in the zone are relative to the zone origin.
    """

    def __init__(self, origin, rdclass=RecordClass.IN, relativize=True):
        if isinstance(origin, str):
            origin = name_from_text(origin)
        if not origin.is_absolute():
            raise ValueError("zone origin must be absolute")
        self._origin = origin
        self._rdclass = int(rdclass)
        self._relativize = relativize
        self._nodes = OrderedDict()

    @property
    def origin(self):
        return self._origin

    @property
    def rdclass(self):
        return self._rdclass

    def _make_relative(self, name):
        """Convert an absolute name to relative (within this zone)."""
        if isinstance(name, str):
            name = name_from_text(name)
        if self._relativize and name.is_absolute():
            if name.is_subdomain(self._origin):
                return name.relativize(self._origin)
        return name

    def _make_absolute(self, name):
        """Convert a relative name to absolute using the zone origin."""
        if isinstance(name, str):
            name = name_from_text(name, origin=self._origin)
        if not name.is_absolute():
            return name.derelativize(self._origin)
        return name

    def find_node(self, name, create=False):
        """Find the node for a name. Returns None if not found and create is False."""
        key = self._make_relative(name)
        node = self._nodes.get(key)
        if node is None and create:
            node = ZoneNode()
            self._nodes[key] = node
        return node

    def get_node(self, name):
        """Get the node for a name, raising KeyError if not found."""
        key = self._make_relative(name)
        if key not in self._nodes:
            raise KeyError(f"name {name} not found in zone")
        return self._nodes[key]

    def delete_node(self, name):
        """Remove a name and all its records from the zone."""
        key = self._make_relative(name)
        if key in self._nodes:
            del self._nodes[key]

    def find_rdataset(self, name, rdtype, rdclass=None, create=False):
        """Find an rdataset at a name for a given type/class."""
        if rdclass is None:
            rdclass = self._rdclass
        node = self.find_node(name, create=create)
        if node is None:
            return None
        return node.find_rdataset(rdtype, rdclass, create=create)

    def get_rdataset(self, name, rdtype, rdclass=None):
        """Get an rdataset, raising KeyError if not found."""
        if rdclass is None:
            rdclass = self._rdclass
        node = self.get_node(name)
        return node.get_rdataset(rdtype, rdclass)

    def delete_rdataset(self, name, rdtype, rdclass=None):
        """Remove an rdataset from a name."""
        if rdclass is None:
            rdclass = self._rdclass
        key = self._make_relative(name)
        node = self._nodes.get(key)
        if node is not None:
            node.delete_rdataset(rdtype, rdclass)
            if len(node) == 0:
                del self._nodes[key]

    def names(self):
        """Return all names in the zone (as relative names if relativized)."""
        return list(self._nodes.keys())

    def nodes(self):
        """Return all (name, node) pairs."""
        return list(self._nodes.items())

    def __len__(self):
        return len(self._nodes)

    def __contains__(self, name):
        key = self._make_relative(name)
        return key in self._nodes

    def __getitem__(self, name):
        return self.get_node(name)

    def __iter__(self):
        return iter(self._nodes)

    def __delitem__(self, name):
        self.delete_node(name)

    def to_text(self, relativize=True):
        """Export the zone to text format."""
        lines = []
        lines.append(f"$ORIGIN {self._origin.to_text()}")

        sorted_names = sorted(self._nodes.keys())
        for name in sorted_names:
            node = self._nodes[name]
            if relativize:
                display_name = name.to_text() if len(name) > 0 else "@"
            else:
                display_name = self._make_absolute(name).to_text()

            for ds in node:
                type_text = type_to_text(ds.rdtype)
                class_text = class_to_text(ds.rdclass)
                for rdata in ds:
                    lines.append(
                        f"{display_name} {ds.ttl} {class_text} {type_text} {rdata.to_text()}"
                    )
        return "\n".join(lines)

    def check_origin(self):
        """Validate that the zone has SOA and NS records at the origin.

        Raises NoSOAError or NoNSError if missing.
        """
        origin_key = self._make_relative(self._origin)
        node = self._nodes.get(origin_key)
        if node is None:
            raise NoSOAError("no SOA record at zone origin")

        soa = node.find_rdataset(RecordType.SOA, self._rdclass)
        if soa is None or len(soa) == 0:
            raise NoSOAError("no SOA record at zone origin")

        ns = node.find_rdataset(RecordType.NS, self._rdclass)
        if ns is None or len(ns) == 0:
            raise NoNSError("no NS record set at zone origin")

    @classmethod
    def from_text(cls, text, origin=None, rdclass=RecordClass.IN,
                  default_ttl=0, check_origin=True):
        """Parse zone file text into a Zone object.

        text: zone file content
        origin: zone origin (str or DomainName)
        rdclass: default record class
        default_ttl: default TTL
        check_origin: if True, validate SOA and NS at origin
        """
        if origin is None:
            origin = ROOT
        if isinstance(origin, str):
            origin = name_from_text(origin)

        zone = cls(origin, rdclass)

        entries = parse_zone_text(text, origin=origin, default_ttl=default_ttl,
                                  rdclass=rdclass)

        for entry in entries:
            name_key = zone._make_relative(entry.name)
            node = zone._nodes.get(name_key)
            if node is None:
                node = ZoneNode()
                zone._nodes[name_key] = node

            ds = node.find_rdataset(entry.rdtype, entry.rdclass, create=True)
            ds.add(entry.rdata, ttl=entry.ttl)

        if check_origin:
            zone.check_origin()

        return zone
