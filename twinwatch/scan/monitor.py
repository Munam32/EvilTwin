"""Optional monitor-mode beacon capture with Scapy (adds per-beacon TSF checks).

Listens only: frames are received, never sent. The interface must already be
in monitor mode, and capture needs root. One scan hops across the given
channels (by default all common 2.4 and 5 GHz ones), listening `dwell`
seconds on each, and merges each AP's beacons into one APRecord. Because it
sees every beacon, it can count TSF decreases (`APRecord.tsf_backwards`): a
second device cloning a BSSID on the same channel, which managed-mode scans
merge away.

Put an adapter in monitor mode (as root), e.g.:
    ip link set wlan1 down && iw dev wlan1 set type monitor && ip link set wlan1 up
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from collections.abc import Callable, Iterable
from pathlib import Path

from twinwatch.beacons import merge_window, security_from_suites
from twinwatch.model import PRIVACY_BIT, APRecord, Snapshot, channel_from_freq

DEFAULT_FREQS = tuple([2412 + 5 * i for i in range(13)]
                      + [5180, 5200, 5220, 5240, 5745, 5765, 5785, 5805, 5825])
DWELL_S = 0.4
ARPHRD_IEEE80211_RADIOTAP = 803  # /sys/class/net/<if>/type of a monitor-mode interface
IFF_UP = 0x1  # /sys/class/net/<if>/flags bit of an interface that is up
SYS_NET = Path("/sys/class/net")


class MonitorError(RuntimeError):
    pass


def check_interface(interface: str) -> None:
    if os.geteuid() != 0:
        raise MonitorError("monitor-mode capture needs root (run with sudo)")
    type_file = SYS_NET / interface / "type"
    if not type_file.exists():
        raise MonitorError(f"no interface {interface!r}")
    if int(type_file.read_text()) != ARPHRD_IEEE80211_RADIOTAP:
        raise MonitorError(f"{interface} is not in monitor mode; see `python -m twinwatch.scan.monitor --help`")
    if not int((type_file.parent / "flags").read_text(), 16) & IFF_UP:
        raise MonitorError(f"{interface} is down; bring it up with: sudo ip link set {interface} up")


def set_channel(interface: str, freq_mhz: int) -> None:
    """Retune the receiver. This changes what the adapter listens to; it sends nothing."""
    proc = subprocess.run(["iw", "dev", interface, "set", "freq", str(freq_mhz)],
                          capture_output=True, text=True, timeout=5)
    if proc.returncode != 0:
        raise MonitorError(f"cannot tune {interface} to {freq_mhz} MHz: {proc.stderr.strip()}")


class ChannelBusy(MonitorError):
    """The card is pinned to one channel, usually by a connected managed interface."""


def set_channel_checked(interface: str, freq_mhz: int) -> None:
    try:
        set_channel(interface, freq_mhz)
    except MonitorError as e:
        if "busy" in str(e).lower():
            raise ChannelBusy(str(e)) from e
        raise


def current_freq(interface: str, iw_dev_output: str | None = None) -> int | None:
    """The channel the card is on: a monitor interface reports none, so read it
    from any interface on the same physical card (`iw dev` groups them by phy).
    """
    if iw_dev_output is None:
        iw_dev_output = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5).stdout
    for phy in re.split(r"^phy#\d+$", iw_dev_output, flags=re.M):
        if re.search(rf"^\s*Interface {re.escape(interface)}$", phy, re.M):
            m = re.search(r"channel \d+ \((\d+) MHz\)", phy)
            return int(m.group(1)) if m else None
    return None


def _elements(pkt) -> Iterable:
    from scapy.layers.dot11 import Dot11Elt

    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        yield elt
        elt = elt.payload.getlayer(Dot11Elt)


def frame_to_record(pkt, tuned_freq: int | None = None) -> APRecord | None:
    """A beacon or probe response -> APRecord (one frame); None for anything else."""
    from scapy.layers.dot11 import (Dot11, Dot11Beacon, Dot11EltMicrosoftWPA, Dot11EltRSN,
                                    Dot11ProbeResp, RadioTap)

    body = pkt.getlayer(Dot11Beacon) or pkt.getlayer(Dot11ProbeResp)
    if body is None or not pkt.haslayer(Dot11):
        return None
    radio = pkt.getlayer(RadioTap)
    freq = getattr(radio, "ChannelFrequency", None) or tuned_freq
    if not freq:
        return None
    signal = getattr(radio, "dBm_AntSignal", None)

    ssid, rsn_akm, wpa_akm, pairwise = "", None, None, []
    for elt in _elements(pkt):
        if elt.ID == 0 and not ssid:
            ssid = bytes(elt.info).decode("utf-8", errors="replace")
        if isinstance(elt, Dot11EltRSN):
            rsn_akm = [s.suite for s in elt.akm_suites or []]
            pairwise += [s.cipher for s in elt.pairwise_cipher_suites or []]
        elif isinstance(elt, Dot11EltMicrosoftWPA):
            wpa_akm = [s.suite for s in elt.akm_suites or []]
            pairwise += [s.cipher for s in elt.pairwise_cipher_suites or []]

    # Scapy holds this little-endian field byte-swapped (its flag list puts ESS
    # at bit 8); swap back so values match iw and tshark, e.g. 0x0011 = ESS+privacy.
    capabilities = int.from_bytes(int(body.cap).to_bytes(2, "big"), "little")
    security, akm, ciphers = security_from_suites(rsn_akm, wpa_akm, pairwise,
                                                  bool(capabilities & PRIVACY_BIT))
    return APRecord(
        bssid=pkt[Dot11].addr3,
        ssid=ssid,
        freq_mhz=int(freq),
        signal_dbm=float(signal) if signal is not None else None,
        security=security,
        akm=akm,
        pairwise=ciphers,
        beacon_interval=int(body.beacon_interval),
        capabilities=capabilities,
        tsf=int(body.timestamp),
    )


def capture(interface: str, freqs: Iterable[int] | None = None, dwell: float = DWELL_S,
            sniff: Callable | None = None, tune: Callable[[str, int], None] = set_channel_checked,
            locate: Callable[[str], int | None] = current_freq) -> Snapshot:
    """One scan: hop over `freqs` once, `dwell` seconds each, and merge per AP.

    If the card cannot change channel (it is connected on another interface),
    listen on its current channel for the same total time instead. That still
    covers a twin cloning the connected AP on its own channel.
    """
    if sniff is None:
        # Importing the 802.11 layers registers link type 803 (radiotap) with
        # Scapy; without it, captured frames stay undecoded raw packets.
        import scapy.layers.dot11  # noqa: F401
        from scapy.sendrecv import sniff
    freqs = sorted(set(freqs or DEFAULT_FREQS), key=lambda f: (f > 3000, channel_from_freq(f)))
    try:
        tune(interface, freqs[0])
        plan = [(f, dwell) for f in freqs]
    except ChannelBusy:
        fixed = locate(interface)
        if fixed is None:
            raise MonitorError(f"{interface} cannot change channel and its current channel is unknown; "
                               "disconnect the card's managed interface or use a second adapter") from None
        plan = [(fixed, dwell * len(freqs))]
    frames: list[APRecord] = []
    for i, (freq, seconds) in enumerate(plan):
        if i and len(plan) > 1:
            tune(interface, freq)
        try:
            packets = sniff(iface=interface, timeout=seconds, store=True)
        except OSError as e:
            raise MonitorError(f"capture on {interface} failed: {e.strerror or e}") from e
        frames += [r for r in (frame_to_record(p, freq) for p in packets) if r is not None]
    return Snapshot(time=time.time(), source="monitor", aps=merge_window(frames),
                    meta={"monitor_freqs": [f for f, _ in plan]})


def main(argv: list[str] | None = None) -> None:
    import argparse

    from rich.console import Console

    from twinwatch.report import ap_table

    parser = argparse.ArgumentParser(prog="python -m twinwatch.scan.monitor", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("interface", help="monitor-mode interface")
    parser.add_argument("--ssid")
    args = parser.parse_args(argv)
    try:
        check_interface(args.interface)
        snap = capture(args.interface)
    except MonitorError as e:
        raise SystemExit(f"error: {e}") from None
    freqs = snap.meta["monitor_freqs"]
    aps = snap.for_ssid(args.ssid) if args.ssid else snap.aps
    Console().print(ap_table(aps, title=f"{len(aps)} APs (monitor, {len(freqs)} channel(s): {freqs})"))


if __name__ == "__main__":
    main()
