"""DNS zone file tokenizer.

Tokenizes DNS master file (zone file) text into tokens: identifiers,
quoted strings, end-of-line, end-of-file, with support for comments,
parenthetical grouping, and escape sequences.
"""

from enum import IntEnum


class TokenKind(IntEnum):
    """Types of tokens produced by the tokenizer."""
    EOF = 0
    EOL = 1
    WHITESPACE = 2
    IDENTIFIER = 3
    QUOTED_STRING = 4
    COMMENT = 5


class Token:
    """A single token from a zone file."""

    __slots__ = ("kind", "value")

    def __init__(self, kind, value=""):
        self.kind = kind
        self.value = value

    def __repr__(self):
        return f"Token({TokenKind(self.kind).name}, {self.value!r})"

    def __eq__(self, other):
        if isinstance(other, Token):
            return self.kind == other.kind and self.value == other.value
        return False

    def is_eof(self):
        return self.kind == TokenKind.EOF

    def is_eol(self):
        return self.kind == TokenKind.EOL

    def is_eol_or_eof(self):
        return self.kind in (TokenKind.EOF, TokenKind.EOL)

    def is_whitespace(self):
        return self.kind == TokenKind.WHITESPACE

    def is_identifier(self):
        return self.kind == TokenKind.IDENTIFIER

    def is_quoted_string(self):
        return self.kind == TokenKind.QUOTED_STRING


class Tokenizer:
    """Tokenizer for DNS master file format.

    Reads text and produces tokens. Handles:
    - Unquoted identifiers
    - Quoted strings (with backslash escapes)
    - Semicolon comments
    - Parenthetical grouping (newlines ignored inside parens)
    - Backslash escapes (\\DDD decimal, \\X literal)
    """

    def __init__(self, text, filename="<string>"):
        if isinstance(text, bytes):
            text = text.decode("utf-8")
        self._text = text
        self._filename = filename
        self._pos = 0
        self._line = 1
        self._paren_depth = 0
        self._at_bol = True  # at beginning of line

    @property
    def filename(self):
        return self._filename

    def _peek(self):
        if self._pos >= len(self._text):
            return None
        return self._text[self._pos]

    def _advance(self):
        if self._pos < len(self._text):
            ch = self._text[self._pos]
            self._pos += 1
            if ch == "\n":
                self._line += 1
            return ch
        return None

    def _skip_whitespace(self):
        """Skip spaces and tabs (not newlines)."""
        count = 0
        while self._pos < len(self._text) and self._text[self._pos] in (" ", "\t"):
            self._pos += 1
            count += 1
        return count

    def get(self, want_leading_whitespace=False):
        """Get the next token.

        If want_leading_whitespace is True, whitespace tokens are returned.
        Otherwise they are skipped.
        """
        while True:
            if self._pos >= len(self._text):
                if self._at_bol:
                    return Token(TokenKind.EOF)
                self._at_bol = True
                return Token(TokenKind.EOF)

            ch = self._text[self._pos]

            if ch in (" ", "\t"):
                ws_count = self._skip_whitespace()
                if want_leading_whitespace and ws_count > 0:
                    return Token(TokenKind.WHITESPACE, " " * ws_count)
                continue

            if ch == "\n":
                self._advance()
                if self._paren_depth > 0:
                    continue
                self._at_bol = True
                return Token(TokenKind.EOL)

            if ch == "\r":
                self._advance()
                if self._peek() == "\n":
                    self._advance()
                if self._paren_depth > 0:
                    continue
                self._at_bol = True
                return Token(TokenKind.EOL)

            if ch == ";":
                comment = ""
                self._advance()
                while self._pos < len(self._text) and self._text[self._pos] != "\n":
                    comment += self._advance()
                continue

            if ch == "(":
                self._advance()
                self._paren_depth += 1
                continue

            if ch == ")":
                self._advance()
                if self._paren_depth > 0:
                    self._paren_depth -= 1
                continue

            if ch == '"':
                return self._read_quoted_string()

            self._at_bol = False
            return self._read_identifier()

    def _read_quoted_string(self):
        """Read a quoted string, handling escapes."""
        self._advance()
        result = ""
        while True:
            if self._pos >= len(self._text):
                raise SyntaxError(f"unterminated quoted string at line {self._line}")
            ch = self._text[self._pos]
            if ch == '"':
                self._advance()
                break
            elif ch == "\\":
                self._advance()
                result += self._read_escape()
            else:
                self._advance()
                result += ch
        self._at_bol = False
        return Token(TokenKind.QUOTED_STRING, result)

    def _read_identifier(self):
        """Read an unquoted identifier."""
        result = ""
        while self._pos < len(self._text):
            ch = self._text[self._pos]
            if ch in (" ", "\t", "\n", "\r", ";", "(", ")", '"'):
                break
            if ch == "\\":
                self._advance()
                result += self._read_escape()
            else:
                self._advance()
                result += ch
        return Token(TokenKind.IDENTIFIER, result)

    def _read_escape(self):
        """Read an escape sequence after the backslash."""
        if self._pos >= len(self._text):
            raise SyntaxError(f"incomplete escape at line {self._line}")
        ch = self._text[self._pos]
        if ch.isdigit():
            digits = ch
            self._advance()
            for _ in range(2):
                if self._pos >= len(self._text) or not self._text[self._pos].isdigit():
                    raise SyntaxError(f"incomplete decimal escape at line {self._line}")
                digits += self._text[self._pos]
                self._advance()
            val = int(digits)
            if val > 255:
                raise SyntaxError(f"decimal escape {val} out of range")
            return chr(val)
        else:
            self._advance()
            return ch

    def get_identifier(self):
        """Get the next identifier token's value, skipping whitespace."""
        tok = self.get()
        if not tok.is_identifier():
            raise SyntaxError(
                f"expected identifier, got {TokenKind(tok.kind).name} at line {self._line}"
            )
        return tok.value

    def get_string(self):
        """Get the next token's value (identifier or quoted string)."""
        tok = self.get()
        if not (tok.is_identifier() or tok.is_quoted_string()):
            raise SyntaxError(
                f"expected string, got {TokenKind(tok.kind).name} at line {self._line}"
            )
        return tok.value

    def get_int(self):
        """Get the next token as an integer."""
        value = self.get_identifier()
        try:
            return int(value)
        except ValueError:
            raise SyntaxError(f"expected integer, got {value!r}")

    def get_uint16(self):
        """Get the next token as a uint16."""
        val = self.get_int()
        if val < 0 or val > 65535:
            raise SyntaxError(f"uint16 out of range: {val}")
        return val

    def get_uint32(self):
        """Get the next token as a uint32."""
        val = self.get_int()
        if val < 0 or val > 0xFFFFFFFF:
            raise SyntaxError(f"uint32 out of range: {val}")
        return val

    def get_remaining(self):
        """Get all remaining tokens until EOL/EOF."""
        tokens = []
        while True:
            tok = self.get()
            if tok.is_eol_or_eof():
                break
            tokens.append(tok)
        return tokens

    def unget(self, token):
        """Push a token back to be returned by the next get()."""
        if token.is_identifier() or token.is_quoted_string():
            self._pos -= len(token.value)
        elif token.is_eol():
            self._pos -= 1
