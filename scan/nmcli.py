"""Parser for `nmcli -t -f <FIELDS> dev wifi list` output.

Fallback when iw is not installed. nmcli gives no beacon interval,
capability bits or TSF, and reports signal as 0-100 percent.
"""

from __future__ import annotations

from model import APRecord

FIELDS = "BSSID,SSID,FREQ,SIGNAL,SECURITY,WPA-FLAGS,RSN-FLAGS"

_SECURITY = {"WPA1": "WPA", "WPA2": "WPA2", "WPA3": "WPA3", "WEP": "WEP", "OWE": "WPA3"}
_AKM = {"psk": "PSK", "sae": "SAE", "802.1x": "EAP", "owe": "OWE"}


def split_terse(line: str) -> list[str]:
    """Split one terse-mode line on ':' honouring nmcli's '\\:' and '\\\\' escapes."""
    fields, current, escaped = [], [], False
    for ch in line:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(ch)
    fields.append("".join(current))
    return fields


def percent_to_dbm(percent: int) -> float:
    """Inverse of NetworkManager's mapping percent = clamp(2 * (dBm + 100))."""
    return percent / 2 - 100


def _parse_line(line: str) -> APRecord | None:
    parts = split_terse(line)
    if len(parts) != len(FIELDS.split(",")):
        return None
    bssid, ssid, freq, signal, security, wpa_flags, rsn_flags = parts
    if not freq:
        return None

    proto = {_SECURITY[t] for t in security.split() if t in _SECURITY}
    flags = f"{wpa_flags} {rsn_flags}".split()
    akm = {_AKM[f.lower()] for f in flags if f.lower() in _AKM}
    pairwise = {f[5:].upper() for f in flags if f.startswith("pair_")}

    return APRecord(
        bssid=bssid,
        ssid=ssid,
        freq_mhz=int(freq.split()[0]),
        signal_dbm=percent_to_dbm(int(signal)) if signal else None,
        security=tuple(sorted(proto)) or ("OPEN",),
        akm=tuple(sorted(akm)),
        pairwise=tuple(sorted(pairwise)),
    )


def parse(output: str) -> list[APRecord]:
    records = []
    for line in output.splitlines():
        if line.strip():
            record = _parse_line(line)
            if record is not None:
                records.append(record)
    return records
