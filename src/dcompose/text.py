"""Escaping for text that comes from an untrusted compose project."""

import re

SAFE_YAML_KEY = re.compile(r"^[A-Za-z0-9_.-]+$")


def printable(text):
    """One line of text with control, format and line-separator characters escaped.

    Stops a config from forging output lines (newlines), rewriting the terminal
    (escape sequences) or reordering text (bidi overrides).
    """
    return "".join(c if c.isprintable() else escape(c) for c in str(text))


def escape(char):
    code = ord(char)
    if code < 0x100:
        return f"\\x{code:02x}"
    return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"
