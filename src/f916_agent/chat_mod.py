"""Human-chat house rules — reject slurs/hate/harassment, tombstone removals."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

CHAT_ADMIN_NAME = "admin"
CHAT_ADMIN_REMOVAL_TEXT = (
    "Removed by admin. Slurs, hate, and sexual harassment aren't allowed "
    "in Human chat."
)

# Display names nobody else may claim (tombstones post as admin).
_RESERVED_NAMES = frozenset(
    {
        "admin",
        "administrator",
        "moderator",
        "mod",
        "system",
        "removed",
        "f916",
        "f916-watch",
        "operator",
        "1f916",
    }
)

_LEET = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "@": "a",
        "$": "s",
        "!": "i",
    }
)

# Distinctive stems checked after spaces are stripped (obfuscation / split posts).
# Keep short/common substrings out of this list ("nga" in singapore, "cum" in scum).
_COMPACT_STEMS = (
    "nigger",
    "nigga",
    "niggers",
    "niggas",
    "nigglet",
    "hitler",
    "faggot",
    "wetback",
    "raghead",
    "tranny",
)

# Whole-token matches on folded (spaced) text.
_WORD_RE = re.compile(
    r"\b(?:"
    r"nigg(?:er|a|ers|as|let|lets)|niga|nga|"
    r"kike|spic|chink|gook|wetback|raghead|"
    r"tranny|faggot|fags?|"
    r"penis|whores?|"
    r"hitler|"
    r"cocks?|dicks?"
    r")\b"
)

_PHRASE_RE = re.compile(
    r"(?:"
    r"my\s+dick|suck\s+my|just\s+cam|"
    r"camel\s+piss|fuck\s+islam|eat\s+camel|"
    r"cum\s*whores?|any\s+cum"
    r")"
)

_SWEAR_DUMP = frozenset(
    {"fuck", "shit", "piss", "ass", "bitch", "cunt", "cock", "dick"}
)

# Handle-only juvenile/sexual names that should not take a message-body hit.
_BAD_NAME_RE = re.compile(r"\b(?:peenis|penis|whores?|dicks?|cocks?|hitler)\b")


def _fold(raw: str) -> str:
    s = (raw or "").lower().translate(_LEET)
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def _compact(folded: str) -> str:
    raw = (folded or "").replace(" ", "")
    # Collapse 3+ repeats ("nigggger") but keep doubles so "nigger" stays intact.
    return re.sub(r"(.)\1{2,}", r"\1\1", raw)


def _swear_dump(folded: str) -> bool:
    words = set((folded or "").split())
    return len(words & _SWEAR_DUMP) >= 3


def _blob_offensive(folded: str) -> bool:
    if not folded:
        return False
    if _WORD_RE.search(folded) or _PHRASE_RE.search(folded) or _swear_dump(folded):
        return True
    compact = _compact(folded)
    return any(stem in compact for stem in _COMPACT_STEMS)


def reserved_chat_name(name: str) -> bool:
    return _fold(name) in _RESERVED_NAMES


def chat_is_offensive(name: str, text: str) -> bool:
    """True when name, body, or the two glued together break house rules."""
    folded_name = _fold(name)
    folded_text = _fold(text)
    if folded_name and _BAD_NAME_RE.search(folded_name):
        return True
    joined = " ".join(part for part in (folded_name, folded_text) if part)
    glued = folded_name.replace(" ", "") + folded_text.replace(" ", "")
    if _blob_offensive(folded_name) or _blob_offensive(folded_text):
        return True
    if joined and _blob_offensive(joined):
        return True
    if glued and glued not in (folded_name.replace(" ", ""), folded_text.replace(" ", "")):
        if any(stem in _compact(glued) for stem in _COMPACT_STEMS):
            return True
        if _WORD_RE.search(glued):
            return True
    return False


def chat_reject_reason(name: str, text: str) -> Optional[str]:
    """Public hint if this post must not land. Does not name the matched token."""
    if reserved_chat_name(name):
        return "that name is reserved"
    if chat_is_offensive(name, ""):
        return "that name isn't allowed"
    if chat_is_offensive(name, text):
        return "that message isn't allowed"
    return None


def redact_chat_message(msg: Dict[str, Any], *, now: float) -> bool:
    """Replace a row with the admin tombstone. Returns True if anything changed."""
    changed = False
    if msg.get("name") != CHAT_ADMIN_NAME:
        msg["name"] = CHAT_ADMIN_NAME
        changed = True
    if msg.get("text") != CHAT_ADMIN_REMOVAL_TEXT:
        msg["text"] = CHAT_ADMIN_REMOVAL_TEXT
        changed = True
    if not msg.get("removed"):
        msg["removed"] = True
        changed = True
    if "vid" in msg:
        msg.pop("vid", None)
        changed = True
    if changed and not msg.get("removed_at"):
        msg["removed_at"] = int(now)
    return changed
