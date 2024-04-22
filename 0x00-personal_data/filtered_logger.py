#!/usr/bin/env python3
"""Personal data module"""
import re


def filter_datum(fields: list[str], redaction: str,
                 message: str, separator: str) -> str:
    """Obfuscate specified fields in the log message."""
    return re.sub(f'({separator.join(fields)})[^{separator}]+',
                  f'{redaction}', message)
