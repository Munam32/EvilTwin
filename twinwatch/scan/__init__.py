"""Run a managed-mode scan and return it as a Snapshot."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

from twinwatch.model import Snapshot
from twinwatch.scan import iw, nmcli

BACKENDS = ("auto", "iw", "nmcli", "monitor")
# Drop cached iw entries older than this; they are APs no longer in range.
MAX_AGE_MS = 30_000


class ScanError(RuntimeError):
    pass


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ScanError(f"{' '.join(cmd)}: {e}") from e


def _scan_iw(interface: str) -> str:
    if os.geteuid() == 0:
        proc = _run(["iw", "dev", interface, "scan"])
    else:
        # Unprivileged: ask NetworkManager for a fresh scan, then read the
        # kernel's scan cache, which iw can dump without root.
        if shutil.which("nmcli"):
            _run(["nmcli", "dev", "wifi", "list", "ifname", interface, "--rescan", "yes"])
        proc = _run(["iw", "dev", interface, "scan", "dump"])
    if proc.returncode != 0:
        raise ScanError(f"iw scan failed: {proc.stderr.strip()}")
    return proc.stdout


def _scan_nmcli(interface: str) -> str:
    base = ["nmcli", "-t", "-f", nmcli.FIELDS, "dev", "wifi", "list", "ifname", interface]
    proc = _run([*base, "--rescan", "yes"])
    if proc.returncode != 0:
        # NetworkManager rate-limits rescans; fall back to its latest results.
        proc = _run([*base, "--rescan", "no"])
    if proc.returncode != 0:
        raise ScanError(f"nmcli scan failed: {proc.stderr.strip()}")
    return proc.stdout


def default_interface() -> str:
    """First wireless interface the kernel reports."""
    for dev in sorted(Path("/sys/class/net").iterdir()):
        if (dev / "wireless").exists():
            return dev.name
    raise ScanError("no wireless interface found; pass --interface")


def resolve_backend(backend: str) -> str:
    if backend == "auto":
        backend = "iw" if shutil.which("iw") else "nmcli"
    tool = "iw" if backend == "monitor" else backend  # monitor mode tunes channels with iw
    if not shutil.which(tool):
        raise ScanError(f"{tool} is not installed")
    return backend


def scan(interface: str, backend: str = "auto") -> Snapshot:
    backend = resolve_backend(backend)
    if backend == "monitor":
        from twinwatch.scan import monitor

        try:
            monitor.check_interface(interface)
            return monitor.capture(interface)
        except monitor.MonitorError as e:
            raise ScanError(str(e)) from e
    if backend == "iw":
        aps = iw.parse(_scan_iw(interface), max_age_ms=MAX_AGE_MS)
    else:
        aps = nmcli.parse(_scan_nmcli(interface))
    return Snapshot(time=time.time(), source=f"live-{backend}", aps=tuple(aps))
