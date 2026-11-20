"""Turn one raw log line into a Python dict, strictly.

Rejects: invalid UTF-8, invalid JSON, duplicate keys, NaN/Infinity, and
anything that is not a JSON object. Floats are parsed as Decimal so the
timestamp keeps every digit Zeek wrote.
"""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal


class ParseError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class _DuplicateKey(Exception):
    pass


class _NonFinite(Exception):
    pass


def raw_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _no_duplicates(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise _DuplicateKey(k)
        obj[k] = v
    return obj


def _no_constants(name):
    raise _NonFinite(name)


def parse_line(raw: bytes) -> dict:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ParseError("invalid_utf8", str(e)) from None
    try:
        obj = json.loads(
            text,
            object_pairs_hook=_no_duplicates,
            parse_constant=_no_constants,
            parse_float=Decimal,
        )
    except _DuplicateKey as e:
        raise ParseError("duplicate_key", f"key {e.args[0]!r} appears twice") from None
    except _NonFinite as e:
        raise ParseError("non_finite_number", f"{e.args[0]} is not allowed") from None
    except (ValueError, RecursionError) as e:  # JSONDecodeError is a ValueError
        raise ParseError("invalid_json", str(e)[:300]) from None
    if not isinstance(obj, dict):
        raise ParseError("not_object", f"expected a JSON object, got {type(obj).__name__}")
    return obj
