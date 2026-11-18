
import re


SQL_INJECTION_PATTERNS = [
    r"\bOR\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",
    r"\bAND\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",
    r"\bUNION\s+(?:ALL\s+)?SELECT\b",
    r"\bSELECT\b.+\bFROM\b",
    r"\bINSERT\s+INTO\b",
    r"\bUPDATE\b.+\bSET\b",
    r"\bDELETE\s+FROM\b",
    r"\bDROP\s+(?:TABLE|DATABASE)\b",
    r"\bALTER\s+TABLE\b",
    r"\bEXEC(?:UTE)?\b",
    r"\bSLEEP\s*\(",
    r"\bBENCHMARK\s*\(",
    r"\bWAITFOR\s+DELAY\b",
    r"\bINFORMATION_SCHEMA\b",
    r"\bLOAD_FILE\s*\(",
    r"\bINTO\s+OUTFILE\b",
    r"--",
    r"/\*",
    r"\*/",
]


COMPILED_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in SQL_INJECTION_PATTERNS
]


def detect_sql_injection(value: str) -> dict:
    """
    Check user input for common SQL injection indicators.

    This is a detection aid, not a replacement for
    parameterized queries and secure database access.
    """

    if not isinstance(value, str):
        return {
            "is_suspicious": False,
            "matched_patterns": []
        }

    matched_patterns = []

    for pattern in COMPILED_PATTERNS:
        if pattern.search(value):
            matched_patterns.append(pattern.pattern)

    return {
        "is_suspicious": bool(matched_patterns),
        "matched_patterns": matched_patterns
    }
