"""
plates.py
---------
Indian number-plate helpers: cleaning, format validation, and OCR-tolerant
watchlist matching.

OCR on real CCTV regularly confuses look-alike characters (O/0, I/1, B/8,
S/5, Z/2, G/6). A watchlist that only matches exact strings would miss a
wanted vehicle because one character was misread. `fuzzy_key` folds every
look-alike group to one symbol, and `match_watchlist` then accepts either an
exact match, a look-alike match, or (for full-length plates) one remaining
character difference. Each match reports which rule fired so an operator
can judge how much to trust it.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional, Tuple

_STANDARD = re.compile(r"^[A-Z]{2}[0-9]{1,2}[A-Z]{0,3}[0-9]{4}$")
_BH_SERIES = re.compile(r"^[0-9]{2}BH[0-9]{4}[A-Z]{1,2}$")
_NON_ALNUM = re.compile(r"[^A-Z0-9]")

_LOOKALIKE = str.maketrans({
    "O": "0", "Q": "0", "D": "0",
    "I": "1", "L": "1", "T": "1",
    "B": "8",
    "S": "5",
    "Z": "2",
    "G": "6",
    "A": "4",
})

STATE_CODES = {
    "AN", "AP", "AR", "AS", "BR", "CG", "CH", "DD", "DL", "GA", "GJ", "HP", "HR", "JH",
    "JK", "KA", "KL", "LA", "LD", "MH", "ML", "MN", "MP", "MZ", "NL", "OD", "PB", "PY",
    "RJ", "SK", "TN", "TR", "TS", "UK", "UP", "WB",
}


def clean(text: str) -> str:
    return _NON_ALNUM.sub("", (text or "").upper())


def is_valid_format(text: str) -> bool:
    t = clean(text)
    if _BH_SERIES.match(t):
        return True
    return bool(_STANDARD.match(t)) and t[:2] in STATE_CODES


def repair(text: str) -> str:
    """Positional repair for the standard format: the first two characters
    must be letters (state code) and the last four must be digits, so a
    misread in those positions can be corrected with high confidence."""
    t = clean(text)
    if len(t) < 6:
        return t
    to_letter = {"0": "O", "1": "I", "8": "B", "5": "S", "2": "Z", "6": "G", "4": "A"}
    to_digit = {v: k for k, v in to_letter.items()} | {"D": "0", "Q": "0", "L": "1", "T": "1"}
    head = "".join(to_letter.get(c, c) for c in t[:2])
    tail = "".join(to_digit.get(c, c) for c in t[-4:])
    return head + t[2:-4] + tail


def fuzzy_key(text: str) -> str:
    return clean(text).translate(_LOOKALIKE)


def _within_one_edit(a: str, b: str) -> bool:
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(1 for x, y in zip(a, b) if x != y) <= 1
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    i = j = diff = 0
    while i < len(short) and j < len(long_):
        if short[i] != long_[j]:
            diff += 1
            if diff > 1:
                return False
            j += 1
            continue
        i += 1
        j += 1
    return True


def match_watchlist(read: str, watchlist: Iterable[str]) -> Optional[Tuple[str, str]]:
    """Returns (watchlisted_plate, match_type) or None.
    match_type is 'exact', 'lookalike' or 'one_char'."""
    r = clean(read)
    if len(r) < 4:
        return None
    rk = fuzzy_key(r)
    best: Optional[Tuple[str, str]] = None
    for plate in watchlist:
        p = clean(plate)
        if r == p:
            return p, "exact"
        pk = fuzzy_key(p)
        if rk == pk:
            best = best or (p, "lookalike")
        elif len(p) >= 8 and len(r) >= 8 and _within_one_edit(rk, pk) and best is None:
            best = (p, "one_char")
    return best
