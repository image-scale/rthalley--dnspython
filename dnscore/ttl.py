"""DNS Time-To-Live (TTL) handling.

Parse TTL values from text (both numeric and BIND-style time notation
like "1h30m") and validate them within the allowed range.
"""

from dnscore.exceptions import SyntaxError as DNSSyntaxError

MAX_TTL = 2**32 - 1

_TIME_UNITS = {
    "w": 604800,   # weeks
    "d": 86400,    # days
    "h": 3600,     # hours
    "m": 60,       # minutes
    "s": 1,        # seconds
}


def ttl_from_text(text):
    """Parse a TTL value from text.

    Accepts plain integers or BIND-style time strings (e.g., "1h30m", "1w2d").
    Time units: w=weeks, d=days, h=hours, m=minutes, s=seconds.
    A bare number at the end of a multi-unit string is treated as seconds.

    Returns an int.
    """
    if isinstance(text, int):
        val = text
        if val < 0 or val > MAX_TTL:
            raise DNSSyntaxError(f"TTL value {val} out of range (0..{MAX_TTL})")
        return val

    text = str(text).strip()
    if not text:
        raise DNSSyntaxError("empty TTL string")

    try:
        val = int(text)
        if val < 0 or val > MAX_TTL:
            raise DNSSyntaxError(f"TTL value {val} out of range (0..{MAX_TTL})")
        return val
    except ValueError:
        pass

    total = 0
    current_num = 0
    has_digits = False
    has_units = False

    for ch in text:
        if ch.isdigit():
            current_num = current_num * 10 + int(ch)
            has_digits = True
        elif ch.lower() in _TIME_UNITS:
            if not has_digits:
                raise DNSSyntaxError(f"missing number before '{ch}' in TTL")
            total += current_num * _TIME_UNITS[ch.lower()]
            current_num = 0
            has_digits = False
            has_units = True
        else:
            raise DNSSyntaxError(f"invalid character '{ch}' in TTL string")

    if has_digits:
        if has_units:
            total += current_num
        else:
            raise DNSSyntaxError(f"invalid TTL string: {text!r}")

    if not has_units and not has_digits:
        raise DNSSyntaxError(f"invalid TTL string: {text!r}")

    if total < 0 or total > MAX_TTL:
        raise DNSSyntaxError(f"TTL value {total} out of range (0..{MAX_TTL})")

    return total


def ttl_to_text(value):
    """Convert a TTL integer value to its string representation."""
    if value < 0 or value > MAX_TTL:
        raise ValueError(f"TTL value {value} out of range")
    return str(value)
