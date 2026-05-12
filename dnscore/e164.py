"""E.164 phone number to ENUM DNS name conversion.

Converts between E.164 telephone numbers and their ENUM DNS
representations under the e164.arpa domain (RFC 6116).
"""

from dnscore.domain_name import from_text as name_from_text
from dnscore.exceptions import SyntaxError as DNSSyntaxError

public_enum_domain = name_from_text("e164.arpa.")


def from_e164(text, origin=None):
    """Convert an E.164 phone number to an ENUM DNS name.

    text: phone number string (e.g., "+1 650 555 1212")
    origin: DNS origin for ENUM names (default: e164.arpa.)

    Non-digit characters are silently stripped.
    Returns a DomainName.
    """
    if origin is None:
        origin = public_enum_domain

    digits = [c for c in text if c.isdigit()]
    if not digits:
        raise DNSSyntaxError(f"no digits in E.164 number: {text}")

    digits.reverse()
    name_text = ".".join(digits) + "." + origin.to_text()
    return name_from_text(name_text)


def to_e164(name, origin=None, want_plus_prefix=True):
    """Convert an ENUM DNS name back to an E.164 phone number.

    name: a DomainName in ENUM form
    origin: DNS origin for ENUM names (default: e164.arpa.)
    want_plus_prefix: if True, prepend "+" to the result

    Returns a phone number string.
    """
    if origin is None:
        origin = public_enum_domain

    if isinstance(name, str):
        name = name_from_text(name)

    if not name.is_subdomain(origin):
        raise DNSSyntaxError(f"name {name} is not under {origin}")

    relative = name.relativize(origin)
    labels = [label.decode("ascii") for label in relative.labels]

    for label in labels:
        if len(label) != 1 or not label.isdigit():
            raise DNSSyntaxError(
                f"invalid ENUM label: {label!r} (must be a single digit)"
            )

    labels.reverse()
    number = "".join(labels)

    if want_plus_prefix:
        return "+" + number
    return number
