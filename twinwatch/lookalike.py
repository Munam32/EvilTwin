"""Lookalike SSIDs: names close enough to the trusted SSID to fool a user.

An evil twin does not have to copy the name exactly. ` KARIMM` next to
`Karim` (leading space, other case, one extra letter) or `Starbuck5` next to
`Starbucks` shows up as a separate network that a user picks by mistake.

Each name is split into a core, a trailing number and sibling tokens: band
labels anywhere in the name (`5G`, `2.4`, `2.4GHz`, and `4G`, which is often
written for 2.4 GHz) and extender words (`EXT`, `Guest`, `Repeater`, ...).

- Same core but other tokens or another trailing number (`Home` / `Home_5G` /
  `Home-EXT` / `Home-2`, `Lab1` / `Lab2`): siblings, usually the owner's
  other network. They are a separate, weaker relation (SIBLING), since a twin
  can also add such a suffix.
- Otherwise two different names look alike when they match after
  normalising (case, spaces and punctuation dropped, confusable characters
  such as 0/o, 1/l, 5/s and rn/m folded) or are one edit apart (two for names
  of 8+ characters). Names shorter than 4 characters after normalising only
  match when equal, and names with nothing left after normalising (emoji,
  symbols) never match. Names that differ only in digits, or default names
  that differ only in a device code (`TP-Link_31A6` / `TP-Link_A886`), are
  different networks.

Lookalikes and siblings already present while the baseline is learned are
trusted neighbours (Baseline.neighbours) and are not reported.
"""

from __future__ import annotations

import re
import unicodedata

MIN_LEN = 4
LONG_NAME = 8  # from this length, two edits still count as a lookalike

_CONFUSABLE = str.maketrans({"0": "o", "1": "l", "i": "l", "|": "l", "3": "e", "5": "s", "$": "s",
                             "@": "a", "4": "a", "7": "t", "8": "b"})
_MULTI = (("rn", "m"), ("vv", "w"))
_DROP = re.compile(r"[\W_]+")
# Band labels as separate tokens ("Home 2.4", "Home_5G_x") or glued after a letter ("Home5G").
_BAND = re.compile(r"(?:(?<![a-z0-9])(?:2[.\s_-]?4(?:\s*g(?:hz)?)?|[2456]\s*g(?:hz)?)"
                   r"|(?<=[a-z])[2456]g(?:hz)?)(?![a-z0-9])")
_BAND_CLASS = {"2": "2.4", "24": "2.4", "4": "2.4", "5": "5", "6": "6"}  # "4G" usually means 2.4 GHz
_SIBLING = re.compile(r"(?<![a-z0-9])(ext|extender|guest|repeater|rpt|plus|mesh)(?![a-z0-9])")
_TRAILING_NUMBER = re.compile(r"^(.*?)(\d+)$")
# Router default names end in a per-device code: "TP-Link_31A6", "Tenda_A886".
_DEVICE_CODE = re.compile(r"^(.*[_\-\s])([0-9a-f]{4,})$")


def _fold(text: str) -> str:
    text = _DROP.sub("", text).translate(_CONFUSABLE)
    for seq, single in _MULTI:
        text = text.replace(seq, single)
    return text


def normalise(ssid: str) -> str:
    """Case, spacing, punctuation and confusable characters folded away."""
    return _fold(unicodedata.normalize("NFKC", ssid).casefold())


def _parts(ssid: str) -> tuple[str, str, int | None, frozenset[str]]:
    """(folded name without tokens, folded core, trailing number, sibling tokens)."""
    text = unicodedata.normalize("NFKC", ssid).casefold()
    tokens = {_BAND_CLASS[re.sub(r"\D", "", m.group(0))[:2].rstrip("0") or "2"]
              for m in _BAND.finditer(text)}
    text = _BAND.sub(" ", text)
    tokens |= {m.group(1) for m in _SIBLING.finditer(text)}
    text = _SIBLING.sub(" ", text)
    bare = _DROP.sub("", text)
    m = _TRAILING_NUMBER.match(bare)
    core, number = (m.group(1), int(m.group(2))) if m and m.group(1) else (bare, None)
    return _fold(bare), _fold(core), number, frozenset(tokens)


def _edits(a: str, b: str, limit: int) -> int:
    """Levenshtein distance, stopping early once it exceeds `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > limit:
            return limit + 1
        prev = cur
    return prev[-1]


LOOKALIKE, SIBLING = "lookalike", "sibling"
MIN_SIBLING_CORE = 3  # "Lab1" / "Lab2" still count; a bare "5G" does not


def relation(candidate: str, trusted: str) -> str | None:
    """LOOKALIKE, SIBLING or None for a name next to the trusted SSID.

    SIBLING: same core name with another band, extender word or trailing
    number (`Home_5G`, `Home-EXT`, `Home-2`). Usually the owner's other
    network, but also an easy disguise for a twin, so a sibling that was not
    there while learning is checked too (signal `ssid_sibling`).
    """
    if not candidate or candidate == trusted:
        return None
    c_name, c_core, c_num, c_tokens = _parts(candidate)
    t_name, t_core, t_num, t_tokens = _parts(trusted)
    if c_core == t_core:
        if (c_num, c_tokens) != (t_num, t_tokens):
            return SIBLING if len(t_core) >= MIN_SIBLING_CORE else None
    c_code, t_code = (_DEVICE_CODE.match(n.strip().casefold()) for n in (candidate, trusted))
    if c_code and t_code and c_code.group(1) == t_code.group(1):
        return None  # default names of two devices: TP-Link_31A6 / TP-Link_A886
    c, t = normalise(candidate), normalise(trusted)
    if not c or not t:
        return None  # emoji / symbols only
    if c == t:
        return LOOKALIKE
    if len(t_name) < MIN_LEN:
        return None
    if re.sub(r"\d", "", candidate.casefold()) == re.sub(r"\d", "", trusted.casefold()):
        return None  # differ only in digits: a different code or number, not a disguise
    limit = 2 if len(t_name) >= LONG_NAME else 1
    return LOOKALIKE if _edits(c_name, t_name, limit) <= limit else None


def looks_alike(candidate: str, trusted: str) -> bool:
    """True if `candidate` is a different name that could pass for `trusted`."""
    return relation(candidate, trusted) == LOOKALIKE


def related(candidate: str, trusted: str) -> bool:
    """True for lookalike and sibling names: the APs worth checking next to `trusted`."""
    return relation(candidate, trusted) is not None
