"""
Strict numeric input for the engine's request validation. The sniffer (honeypot/sniffer/flow_mapping.py) and backend
(backend/utils/flowFields.js) apply the same rule; tests/fixtures/strict_numeric_cases.json is the single table for all three.
"""
import math
import re

_DECIMAL = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")


def parse_strict_number(value):
    """A finite float from a JSON number or a plain decimal/exponent string, otherwise None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        if not _DECIMAL.fullmatch(value):
            return None
    elif not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (ValueError, OverflowError):
        return None
    return number if math.isfinite(number) else None
