#!/usr/bin/env python3
"""Personal data module"""
import re


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """ Returns a log message obfuscated """
    for f in fields:
        message: str = re.sub(f'{f}=.*?{separator}',
                              f'{f}={redaction}{separator}', message)
    return message
