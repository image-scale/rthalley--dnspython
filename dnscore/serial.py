"""DNS serial number arithmetic per RFC 1982.

Provides a Serial class that wraps an unsigned integer with modular
comparison and arithmetic semantics suitable for DNS SOA serial numbers.
"""


class Serial:
    """A DNS serial number with RFC 1982 wraparound semantics.

    Serial numbers use modular arithmetic over a configurable bit width
    (default 32 bits for DNS SOA serials). Comparisons account for
    wraparound: a serial near 2^32-1 can be "less than" a serial near 0
    if the difference is within half the number space.
    """

    def __init__(self, value, bits=32):
        self._bits = bits
        self._max = 1 << bits
        self._half = 1 << (bits - 1)
        self._value = int(value) % self._max

    @property
    def value(self):
        return self._value

    @property
    def bits(self):
        return self._bits

    def _coerce(self, other):
        if isinstance(other, Serial):
            if other._bits != self._bits:
                return NotImplemented
            return other._value
        if isinstance(other, int):
            return other % self._max
        return NotImplemented

    def __eq__(self, other):
        val = self._coerce(other)
        if val is NotImplemented:
            return NotImplemented
        return self._value == val

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return NotImplemented
        return not result

    def __lt__(self, other):
        val = self._coerce(other)
        if val is NotImplemented:
            return NotImplemented
        if self._value == val:
            return False
        diff = (val - self._value) % self._max
        return 0 < diff < self._half

    def __le__(self, other):
        return self == other or self < other

    def __gt__(self, other):
        val = self._coerce(other)
        if val is NotImplemented:
            return NotImplemented
        if self._value == val:
            return False
        diff = (self._value - val) % self._max
        return 0 < diff < self._half

    def __ge__(self, other):
        return self == other or self > other

    def __add__(self, other):
        if isinstance(other, Serial):
            delta = other._value
        elif isinstance(other, int):
            delta = other
        else:
            return NotImplemented
        if delta < 0 or delta > self._half - 1:
            raise ValueError(
                f"delta {delta} out of range for {self._bits}-bit serial"
            )
        return Serial((self._value + delta) % self._max, self._bits)

    def __iadd__(self, other):
        result = self.__add__(other)
        if result is NotImplemented:
            return NotImplemented
        self._value = result._value
        return self

    def __sub__(self, other):
        if isinstance(other, Serial):
            delta = other._value
        elif isinstance(other, int):
            delta = other
        else:
            return NotImplemented
        if delta < 0 or delta > self._half - 1:
            raise ValueError(
                f"delta {delta} out of range for {self._bits}-bit serial"
            )
        return Serial((self._value - delta) % self._max, self._bits)

    def __isub__(self, other):
        result = self.__sub__(other)
        if result is NotImplemented:
            return NotImplemented
        self._value = result._value
        return self

    def __int__(self):
        return self._value

    def __hash__(self):
        return hash((self._value, self._bits))

    def __repr__(self):
        return f"Serial({self._value}, bits={self._bits})"

    def __str__(self):
        return str(self._value)
