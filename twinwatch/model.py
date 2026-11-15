"""Shared data schema.

Every data source (live scans, lab recordings, AWID3, WiGLE, synthetic data)
is converted into these types, so features and detectors never depend on
where a scan came from.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace

# Higher rank = stronger protection. Used to detect security downgrades.
SECURITY_RANK = {"OPEN": 0, "WEP": 1, "WPA": 2, "WPA2": 3, "WPA3": 4}

BENIGN = "benign"
EVIL_TWIN = "evil_twin"

PRIVACY_BIT = 0x0010  # capability bit: the AP requires encryption


def derive_security(wpa: bool, rsn: bool, rsn_akm: set[str], privacy: bool) -> tuple[str, ...]:
    """Security protocols from the WPA/RSN elements an AP advertises.

    `rsn_akm` holds normalized AKM names (PSK, SAE, EAP, EAP-SUITE-B, OWE)
    from the RSN element only. Without WPA or RSN, the privacy capability bit
    means WEP.
    """
    security = set()
    if wpa:
        security.add("WPA")
    if rsn:
        if rsn_akm & {"SAE", "OWE", "EAP-SUITE-B"}:
            security.add("WPA3")
        if rsn_akm & {"PSK", "EAP"} or not rsn_akm:
            security.add("WPA2")
    if not security:
        security.add("WEP" if privacy else "OPEN")
    return tuple(sorted(security))


def channel_from_freq(freq_mhz: int) -> int:
    if freq_mhz == 2484:
        return 14
    if 2412 <= freq_mhz < 2484:
        return (freq_mhz - 2407) // 5
    if 5000 <= freq_mhz < 5925:
        return (freq_mhz - 5000) // 5
    if 5955 <= freq_mhz <= 7115:
        return (freq_mhz - 5950) // 5
    return 0


def band_from_freq(freq_mhz: int) -> str:
    if freq_mhz < 3000:
        return "2.4"
    if freq_mhz < 5925:
        return "5"
    return "6"


@dataclass(frozen=True)
class APRecord:
    """One access point as seen in one scan.

    Fields a source cannot provide are None (for example beacon_interval from
    nmcli). `security` holds every protocol the AP advertises, e.g.
    ("WPA", "WPA2") for a mixed-mode AP. `tsf_backwards` counts how often the
    TSF went backwards across this AP's individual beacons, so it is known
    only for per-beacon sources (monitor mode, AWID3).
    """

    bssid: str
    ssid: str
    freq_mhz: int
    signal_dbm: float | None
    security: tuple[str, ...]
    akm: tuple[str, ...] = ()
    pairwise: tuple[str, ...] = ()
    beacon_interval: int | None = None
    capabilities: int | None = None
    tsf: int | None = None
    tsf_backwards: int | None = None
    label: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "bssid", self.bssid.lower())
        unknown = set(self.security) - SECURITY_RANK.keys()
        if unknown or not self.security:
            raise ValueError(f"invalid security {self.security!r} for {self.bssid}")

    @property
    def channel(self) -> int:
        return channel_from_freq(self.freq_mhz)

    @property
    def band(self) -> str:
        return band_from_freq(self.freq_mhz)

    @property
    def oui(self) -> str:
        return self.bssid[:8]

    @property
    def security_rank(self) -> int:
        return max(SECURITY_RANK[s] for s in self.security)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> APRecord:
        d = dict(d)
        for key in ("security", "akm", "pairwise"):
            d[key] = tuple(d.get(key, ()))
        return cls(**d)

    def with_label(self, label: str | None) -> APRecord:
        return replace(self, label=label)


@dataclass(frozen=True)
class Snapshot:
    """All APs seen in one scan cycle (or one time window of a capture)."""

    time: float
    source: str
    aps: tuple[APRecord, ...]
    meta: dict = field(default_factory=dict)

    def for_ssid(self, ssid: str) -> list[APRecord]:
        return [ap for ap in self.aps if ap.ssid == ssid]

    def to_dict(self) -> dict:
        return {
            "time": self.time,
            "source": self.source,
            "meta": self.meta,
            "aps": [ap.to_dict() for ap in self.aps],
        }

    @classmethod
    def from_dict(cls, d: dict) -> Snapshot:
        return cls(
            time=d["time"],
            source=d["source"],
            aps=tuple(APRecord.from_dict(a) for a in d["aps"]),
            meta=d.get("meta", {}),
        )
