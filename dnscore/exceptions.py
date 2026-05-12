"""Base exceptions for the DNS toolkit."""


class DNSError(Exception):
    """Base class for all DNS-related errors."""
    pass


class SyntaxError(DNSError):
    """A DNS syntax error occurred."""
    pass


class FormError(DNSError):
    """A DNS form error occurred (malformed data)."""
    pass


class ConfigError(DNSError):
    """A DNS configuration error occurred."""
    pass


class TimeoutError(DNSError):
    """A DNS operation timed out."""
    pass
