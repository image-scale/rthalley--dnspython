"""DNS record collections — RRDataSet, RRSet, and ZoneNode.

An RRDataSet is a set of record data objects sharing the same type, class,
and TTL. An RRSet adds an owner name. A ZoneNode holds multiple RRDataSets
at a single point in the DNS namespace.
"""

from dnscore.record_type import RecordType, type_to_text
from dnscore.record_class import RecordClass, class_to_text
from dnscore.record_data import RecordData
from dnscore.domain_name import DomainName, from_text as name_from_text


class RRDataSet:
    """A set of DNS record data objects of the same type and class.

    All records share a single TTL (the minimum of any added TTL).
    """

    def __init__(self, rdtype, rdclass=RecordClass.IN, ttl=0):
        self._rdtype = int(rdtype)
        self._rdclass = int(rdclass)
        self._ttl = int(ttl)
        self._records = []

    @property
    def rdtype(self):
        return self._rdtype

    @property
    def rdclass(self):
        return self._rdclass

    @property
    def ttl(self):
        return self._ttl

    @ttl.setter
    def ttl(self, value):
        self._ttl = int(value)

    def add(self, rdata, ttl=None):
        """Add a record data object to the set.

        If ttl is provided and less than the current TTL, the set TTL
        is updated to the minimum.
        """
        if int(rdata.rdtype) != self._rdtype:
            raise ValueError(
                f"record type {rdata.rdtype} doesn't match set type {self._rdtype}"
            )
        if ttl is not None:
            if len(self._records) == 0:
                self._ttl = int(ttl)
            elif int(ttl) < self._ttl:
                self._ttl = int(ttl)

        for existing in self._records:
            if existing == rdata:
                return
        self._records.append(rdata)

    def remove(self, rdata):
        """Remove a record from the set."""
        self._records = [r for r in self._records if r != rdata]

    def __len__(self):
        return len(self._records)

    def __iter__(self):
        return iter(self._records)

    def __contains__(self, item):
        return any(r == item for r in self._records)

    def __bool__(self):
        return len(self._records) > 0

    def __eq__(self, other):
        if not isinstance(other, RRDataSet):
            return False
        if self._rdtype != other._rdtype or self._rdclass != other._rdclass:
            return False
        if len(self._records) != len(other._records):
            return False
        for r in self._records:
            if r not in other:
                return False
        return True

    def __hash__(self):
        return hash((self._rdtype, self._rdclass, tuple(sorted(hash(r) for r in self._records))))

    def to_text(self, name=None, origin=None):
        """Convert the RRDataSet to text representation."""
        lines = []
        type_text = type_to_text(self._rdtype)
        class_text = class_to_text(self._rdclass)
        name_text = name.to_text() if name else ""
        for rdata in self._records:
            if name_text:
                lines.append(
                    f"{name_text} {self._ttl} {class_text} {type_text} {rdata.to_text()}"
                )
            else:
                lines.append(
                    f"{self._ttl} {class_text} {type_text} {rdata.to_text()}"
                )
        return "\n".join(lines)

    def copy(self):
        """Return a shallow copy of this RRDataSet."""
        new_set = RRDataSet(self._rdtype, self._rdclass, self._ttl)
        for r in self._records:
            new_set._records.append(r)
        return new_set


class RRSet(RRDataSet):
    """A named resource record set — an RRDataSet with an owner name."""

    def __init__(self, name, rdtype, rdclass=RecordClass.IN, ttl=0):
        super().__init__(rdtype, rdclass, ttl)
        if isinstance(name, str):
            name = name_from_text(name)
        self._name = name

    @property
    def name(self):
        return self._name

    def to_text(self, origin=None):
        """Convert to text with the owner name."""
        return super().to_text(name=self._name, origin=origin)

    def __eq__(self, other):
        if not isinstance(other, RRSet):
            return False
        if self._name != other._name:
            return False
        return super().__eq__(other)

    def __hash__(self):
        return hash((self._name, self._rdtype, self._rdclass))

    def __repr__(self):
        type_text = type_to_text(self._rdtype)
        return f"<RRSet {self._name.to_text()} {type_text} ({len(self)} records)>"

    @classmethod
    def from_rdata(cls, name, ttl, *rdata_list):
        """Create an RRSet from one or more rdata objects."""
        if not rdata_list:
            raise ValueError("at least one rdata is required")
        first = rdata_list[0]
        rrset = cls(name, first.rdtype, first.rdclass, ttl)
        for rd in rdata_list:
            rrset.add(rd)
        return rrset

    @classmethod
    def from_text(cls, name, ttl, rdclass, rdtype, *text_rdata):
        """Create an RRSet from text representations of rdata."""
        from dnscore.record_data import create_from_text
        if isinstance(name, str):
            name = name_from_text(name)
        rrset = cls(name, int(rdtype), int(rdclass), int(ttl))
        for text in text_rdata:
            rdata = create_from_text(int(rdtype), text, rdclass=int(rdclass))
            rrset.add(rdata)
        return rrset

    def to_rdataset(self):
        """Return a copy as a plain RRDataSet (without the name)."""
        ds = RRDataSet(self._rdtype, self._rdclass, self._ttl)
        for r in self._records:
            ds._records.append(r)
        return ds


class ZoneNode:
    """A node in a DNS zone — holds RRDataSets for different types at one name."""

    def __init__(self):
        self._rdatasets = []

    def find_rdataset(self, rdtype, rdclass=RecordClass.IN, create=False):
        """Find or create an RRDataSet for the given type and class."""
        for ds in self._rdatasets:
            if ds.rdtype == int(rdtype) and ds.rdclass == int(rdclass):
                return ds
        if create:
            ds = RRDataSet(int(rdtype), int(rdclass))
            self._rdatasets.append(ds)
            return ds
        return None

    def get_rdataset(self, rdtype, rdclass=RecordClass.IN):
        """Get the RRDataSet for a type/class, or raise KeyError."""
        ds = self.find_rdataset(rdtype, rdclass)
        if ds is None:
            raise KeyError(f"no rdataset for type {rdtype} class {rdclass}")
        return ds

    def delete_rdataset(self, rdtype, rdclass=RecordClass.IN):
        """Remove the RRDataSet for a type/class if present."""
        self._rdatasets = [
            ds for ds in self._rdatasets
            if not (ds.rdtype == int(rdtype) and ds.rdclass == int(rdclass))
        ]

    def rdatasets(self):
        """Return the list of RRDataSets at this node."""
        return list(self._rdatasets)

    def __len__(self):
        return len(self._rdatasets)

    def __iter__(self):
        return iter(self._rdatasets)

    def __bool__(self):
        return len(self._rdatasets) > 0

    def to_text(self, name=None, origin=None):
        """Convert node to text showing all RRDataSets."""
        parts = []
        for ds in self._rdatasets:
            parts.append(ds.to_text(name=name, origin=origin))
        return "\n".join(parts)
