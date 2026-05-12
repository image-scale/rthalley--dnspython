"""Tests for DNS domain name handling."""

import pytest
from dnscore.domain_name import (
    DomainName,
    from_text,
    from_wire,
    Relation,
    ROOT,
    EMPTY,
    EmptyLabelError,
    BadEscapeError,
    LabelTooLongError,
    NameTooLongError,
    BadPointerError,
    BadLabelTypeError,
    AbsoluteConcatError,
    NoParentError,
    NeedAbsoluteError,
)


class TestFromText:
    def test_simple_absolute(self):
        name = from_text("example.com.")
        assert name.to_text() == "example.com."
        assert name.is_absolute()

    def test_simple_relative_becomes_absolute(self):
        name = from_text("example.com")
        assert name.is_absolute()
        assert name.to_text() == "example.com."

    def test_relative_with_no_origin(self):
        name = from_text("example.com", origin=None)
        assert not name.is_absolute()
        assert name.to_text() == "example.com"

    def test_root_name(self):
        name = from_text(".")
        assert name.is_absolute()
        assert name.to_text() == "."
        assert name.label_count() == 1
        assert name.labels == (b"",)

    def test_at_sign_is_origin(self):
        name = from_text("@")
        assert name == ROOT

    def test_at_sign_with_custom_origin(self):
        origin = from_text("example.com.")
        name = from_text("@", origin=origin)
        assert name == origin

    def test_escape_backslash_char(self):
        name = from_text("exam\\ple.com.")
        assert name.labels[0] == b"example"

    def test_escape_decimal(self):
        name = from_text("\\065xample.com.")
        assert name.labels[0] == b"Axample"

    def test_bad_escape_incomplete(self):
        with pytest.raises(BadEscapeError):
            from_text("example\\.com\\")

    def test_bad_escape_non_digit(self):
        with pytest.raises(BadEscapeError):
            from_text("\\12x.com.")

    def test_empty_label_raises(self):
        with pytest.raises(EmptyLabelError):
            from_text("example..com.")

    def test_bytes_input(self):
        name = from_text(b"example.com.")
        assert name.to_text() == "example.com."

    def test_from_text_multilabel(self):
        name = from_text("www.example.com.")
        assert name.label_count() == 4
        assert name.labels[0] == b"www"
        assert name.labels[1] == b"example"
        assert name.labels[2] == b"com"
        assert name.labels[3] == b""


class TestDomainNameProperties:
    def test_is_absolute_true(self):
        name = DomainName([b"www", b"example", b"com", b""])
        assert name.is_absolute()

    def test_is_absolute_false(self):
        name = DomainName([b"www", b"example"])
        assert not name.is_absolute()

    def test_is_wild(self):
        name = from_text("*.example.com.")
        assert name.is_wild()

    def test_is_not_wild(self):
        name = from_text("www.example.com.")
        assert not name.is_wild()

    def test_label_count(self):
        name = from_text("www.example.com.")
        assert name.label_count() == 4

    def test_len(self):
        name = from_text("www.example.com.")
        assert len(name) == 4

    def test_getitem(self):
        name = from_text("www.example.com.")
        assert name[0] == b"www"
        assert name[1] == b"example"
        assert name[-1] == b""

    def test_labels_property(self):
        name = from_text("a.b.")
        assert name.labels == (b"a", b"b", b"")

    def test_immutable(self):
        name = from_text("example.com.")
        with pytest.raises(AttributeError):
            name.labels = (b"foo",)
        with pytest.raises(AttributeError):
            name.x = 1


class TestDomainNameComparison:
    def test_equal_names(self):
        n1 = from_text("example.com.")
        n2 = from_text("example.com.")
        assert n1 == n2

    def test_case_insensitive_equal(self):
        n1 = from_text("Example.COM.")
        n2 = from_text("example.com.")
        assert n1 == n2

    def test_not_equal(self):
        n1 = from_text("foo.com.")
        n2 = from_text("bar.com.")
        assert n1 != n2

    def test_less_than(self):
        n1 = from_text("a.example.com.")
        n2 = from_text("b.example.com.")
        assert n1 < n2

    def test_greater_than(self):
        n1 = from_text("b.example.com.")
        n2 = from_text("a.example.com.")
        assert n1 > n2

    def test_less_equal(self):
        n1 = from_text("a.com.")
        n2 = from_text("a.com.")
        assert n1 <= n2

    def test_greater_equal(self):
        n1 = from_text("b.com.")
        n2 = from_text("a.com.")
        assert n1 >= n2

    def test_not_equal_to_non_name(self):
        name = from_text("example.com.")
        assert name != "example.com."
        assert not (name == "example.com.")

    def test_lt_non_name(self):
        name = from_text("example.com.")
        assert name.__lt__("not a name") is NotImplemented

    def test_absolute_vs_relative(self):
        abs_name = from_text("example.com.")
        rel_name = from_text("example.com", origin=None)
        rel, order, _ = abs_name.full_compare(rel_name)
        assert rel == Relation.NONE
        assert order > 0

    def test_relative_vs_absolute(self):
        rel_name = from_text("example.com", origin=None)
        abs_name = from_text("example.com.")
        rel, order, _ = rel_name.full_compare(abs_name)
        assert rel == Relation.NONE
        assert order < 0


class TestFullCompare:
    def test_equal(self):
        n1 = from_text("www.example.com.")
        n2 = from_text("www.example.com.")
        rel, order, nlabels = n1.full_compare(n2)
        assert rel == Relation.EQUAL
        assert order == 0
        assert nlabels == 4

    def test_subdomain(self):
        n1 = from_text("www.example.com.")
        n2 = from_text("example.com.")
        rel, order, nlabels = n1.full_compare(n2)
        assert rel == Relation.SUBDOMAIN
        assert order > 0
        assert nlabels == 3

    def test_superdomain(self):
        n1 = from_text("example.com.")
        n2 = from_text("www.example.com.")
        rel, order, nlabels = n1.full_compare(n2)
        assert rel == Relation.SUPERDOMAIN
        assert order < 0
        assert nlabels == 3

    def test_common_ancestor(self):
        n1 = from_text("a.example.com.")
        n2 = from_text("b.example.com.")
        rel, order, nlabels = n1.full_compare(n2)
        assert rel == Relation.COMMON_ANCESTOR
        assert order < 0
        assert nlabels == 3

    def test_no_relation(self):
        n1 = from_text("example.com.")
        n2 = from_text("example.org.")
        rel, order, nlabels = n1.full_compare(n2)
        assert rel == Relation.COMMON_ANCESTOR
        assert nlabels == 1


class TestSubdomainSuperdomain:
    def test_is_subdomain(self):
        child = from_text("www.example.com.")
        parent = from_text("example.com.")
        assert child.is_subdomain(parent)

    def test_is_subdomain_self(self):
        name = from_text("example.com.")
        assert name.is_subdomain(name)

    def test_is_not_subdomain(self):
        n1 = from_text("example.com.")
        n2 = from_text("example.org.")
        assert not n1.is_subdomain(n2)

    def test_is_superdomain(self):
        parent = from_text("example.com.")
        child = from_text("www.example.com.")
        assert parent.is_superdomain(child)

    def test_is_superdomain_self(self):
        name = from_text("example.com.")
        assert name.is_superdomain(name)


class TestConcatenation:
    def test_relative_plus_absolute(self):
        rel = from_text("www", origin=None)
        origin = from_text("example.com.")
        result = rel + origin
        assert result == from_text("www.example.com.")

    def test_absolute_concat_raises(self):
        abs_name = from_text("example.com.")
        other = from_text("org.")
        with pytest.raises(AbsoluteConcatError):
            abs_name + other

    def test_absolute_plus_empty(self):
        abs_name = from_text("example.com.")
        result = abs_name + EMPTY
        assert result == abs_name


class TestRelativize:
    def test_relativize_subdomain(self):
        full = from_text("www.example.com.")
        origin = from_text("example.com.")
        rel = full.relativize(origin)
        assert not rel.is_absolute()
        assert rel.to_text() == "www"

    def test_relativize_non_subdomain(self):
        name = from_text("www.other.com.")
        origin = from_text("example.com.")
        result = name.relativize(origin)
        assert result == name

    def test_derelativize(self):
        rel = from_text("www", origin=None)
        origin = from_text("example.com.")
        result = rel.derelativize(origin)
        assert result == from_text("www.example.com.")

    def test_derelativize_absolute(self):
        abs_name = from_text("www.example.com.")
        origin = from_text("example.com.")
        result = abs_name.derelativize(origin)
        assert result == abs_name

    def test_sub_operator(self):
        full = from_text("www.example.com.")
        origin = from_text("example.com.")
        result = full - origin
        assert result.to_text() == "www"


class TestToText:
    def test_absolute_name(self):
        name = from_text("example.com.")
        assert name.to_text() == "example.com."

    def test_omit_final_dot(self):
        name = from_text("example.com.")
        assert name.to_text(omit_final_dot=True) == "example.com"

    def test_root(self):
        assert ROOT.to_text() == "."

    def test_empty(self):
        assert EMPTY.to_text() == "@"

    def test_special_chars_escaped(self):
        name = DomainName([b"a.b", b"com", b""])
        text = name.to_text()
        assert "a\\.b" in text

    def test_non_printable_escaped(self):
        name = DomainName([b"\x01test", b""])
        text = name.to_text()
        assert "\\001" in text


class TestToWire:
    def test_simple_wire(self):
        name = from_text("example.com.")
        wire = name.to_wire()
        assert wire == b"\x07example\x03com\x00"

    def test_root_wire(self):
        wire = ROOT.to_wire()
        assert wire == b"\x00"

    def test_relative_needs_origin(self):
        rel = from_text("www", origin=None)
        with pytest.raises(NeedAbsoluteError):
            rel.to_wire()

    def test_relative_with_origin(self):
        rel = from_text("www", origin=None)
        origin = from_text("example.com.")
        wire = rel.to_wire(origin=origin)
        assert wire == b"\x03www\x07example\x03com\x00"

    def test_canonicalize(self):
        name = from_text("Example.COM.")
        wire = name.to_wire(canonicalize=True)
        assert wire == b"\x07example\x03com\x00"


class TestFromWire:
    def test_simple_wire(self):
        wire = b"\x07example\x03com\x00"
        name, consumed = from_wire(wire)
        assert name == from_text("example.com.")
        assert consumed == len(wire)

    def test_with_offset(self):
        wire = b"\x00\x00\x07example\x03com\x00"
        name, consumed = from_wire(wire, offset=2)
        assert name == from_text("example.com.")

    def test_compression_pointer(self):
        wire = b"\x07example\x03com\x00\x03www\xc0\x00"
        name, consumed = from_wire(wire, offset=13)
        assert name == from_text("www.example.com.")

    def test_forward_pointer_raises(self):
        wire = b"\xc0\x05\x00\x00\x00\x03foo\x00"
        with pytest.raises(BadPointerError):
            from_wire(wire, offset=0)

    def test_bad_label_type_raises(self):
        wire = b"\x40test\x00"
        with pytest.raises(BadLabelTypeError):
            from_wire(wire, offset=0)


class TestHash:
    def test_equal_names_same_hash(self):
        n1 = from_text("example.com.")
        n2 = from_text("example.com.")
        assert hash(n1) == hash(n2)

    def test_case_insensitive_hash(self):
        n1 = from_text("Example.COM.")
        n2 = from_text("example.com.")
        assert hash(n1) == hash(n2)

    def test_usable_as_dict_key(self):
        name = from_text("example.com.")
        d = {name: "value"}
        key = from_text("Example.COM.")
        assert d[key] == "value"


class TestCanonical:
    def test_canonicalize(self):
        name = from_text("Example.COM.")
        canon = name.canonicalize()
        assert canon.labels[0] == b"example"
        assert canon.labels[1] == b"com"


class TestParent:
    def test_parent(self):
        name = from_text("www.example.com.")
        parent = name.parent()
        assert parent == from_text("example.com.")

    def test_parent_of_two_labels(self):
        name = from_text("example.com.")
        parent = name.parent()
        assert parent == from_text("com.")

    def test_root_no_parent(self):
        with pytest.raises(NoParentError):
            ROOT.parent()

    def test_empty_no_parent(self):
        with pytest.raises(NoParentError):
            EMPTY.parent()


class TestChooseRelativity:
    def test_relativize(self):
        name = from_text("www.example.com.")
        origin = from_text("example.com.")
        result = name.choose_relativity(origin, relativize=True)
        assert result.to_text() == "www"

    def test_derelativize(self):
        name = from_text("www", origin=None)
        origin = from_text("example.com.")
        result = name.choose_relativity(origin, relativize=False)
        assert result == from_text("www.example.com.")

    def test_no_origin(self):
        name = from_text("www.example.com.")
        result = name.choose_relativity(None)
        assert result == name


class TestValidation:
    def test_label_too_long(self):
        long_label = b"a" * 64
        with pytest.raises(LabelTooLongError):
            DomainName([long_label, b""])

    def test_label_max_ok(self):
        label = b"a" * 63
        name = DomainName([label, b""])
        assert len(name) == 2

    def test_name_too_long(self):
        labels = [b"a" * 63] * 4 + [b""]
        with pytest.raises(NameTooLongError):
            DomainName(labels)

    def test_str_labels_converted(self):
        name = DomainName(["www", "example", "com", ""])
        assert name.labels == (b"www", b"example", b"com", b"")


class TestSorting:
    def test_sort_names(self):
        names = [
            from_text("b.example.com."),
            from_text("a.example.com."),
            from_text("c.example.com."),
        ]
        sorted_names = sorted(names)
        assert sorted_names[0] == from_text("a.example.com.")
        assert sorted_names[1] == from_text("b.example.com.")
        assert sorted_names[2] == from_text("c.example.com.")

    def test_dnssec_order(self):
        names = [
            from_text("example.com."),
            from_text("a.example.com."),
            from_text("z.example.com."),
        ]
        sorted_names = sorted(names)
        assert sorted_names[0] == from_text("example.com.")
        assert sorted_names[1] == from_text("a.example.com.")
        assert sorted_names[2] == from_text("z.example.com.")


class TestRepr:
    def test_repr(self):
        name = from_text("example.com.")
        assert repr(name) == "<DomainName example.com.>"

    def test_str(self):
        name = from_text("example.com.")
        assert str(name) == "example.com."
