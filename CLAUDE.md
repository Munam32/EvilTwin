# CLAUDE.md

TwinWatch: passive evil twin Wi-Fi AP detector, Python 3 on Linux. University Information Security project. PRD: https://claude.ai/artifact/HXFkK7hAua2Af59KiQSJ11

## Workflow

- The user commits manually. Never run `git commit` or `git push`. After finishing a part, stop and tell the user which files to commit, with a suggested commit message.
- Work in parts that each end runnable and tested.

## Commands

```bash
.venv/bin/pip install -e '.[dev]'   # add ml / monitor extras when those parts land
.venv/bin/pytest
.venv/bin/twinwatch scan
```

## Hard rules

- Passive only. Never add code that transmits deauthentication, disassociation, jamming or any attack frame, and never decrypt or inspect user traffic.
- The hostapd lab AP is not part of this repo. Do not add an evil twin kit.
- Test fixtures use locally administered MACs (`02:00:00:...`) and invented SSIDs, never real nearby networks.
- `data/raw/` and `data/processed/` hold licence-restricted datasets (AWID3, WiGLE) and stay gitignored.

## Architecture

- Flat layout: modules and packages sit at the repo root and import each other directly (`from model import APRecord`), not through a `twinwatch` package. New top-level modules or packages must be added to `[tool.setuptools]` in `pyproject.toml`.
- `model.py` owns the shared schema. Every source (live scan, lab, AWID3, WiGLE, synthetic) converts to `Snapshot`/`APRecord`; features and detectors must not branch on source.
- Fields a source cannot provide are `None` (nmcli: beacon_interval, capabilities, tsf). Features must handle `None`.
- `APRecord.security` is a tuple of protocols from `SECURITY_RANK`; `security_rank` gives the strongest, used for downgrade detection.
- Labels live on `APRecord.label` (`benign` / `evil_twin` / None). A cloned-BSSID twin is told apart by `bssid@freq`.
- Recordings are JSON Lines, one snapshot per line (`recording.py`).
- Detectors (`naive`, `weighted`, `ml`) share one interface so evaluation can swap them.

## Evaluation discipline

- Train on AWID3 + WiGLE + synthetic data; the lab set is test-only and never used for training or threshold tuning.
- Cross-validate grouped by capture/session, never random rows from one session.
- Results are lab comparisons, not real-world accuracy claims.
