# CLAUDE.md

TwinWatch: passive evil twin Wi-Fi AP detector, Python 3 on Linux. University Information Security project. PRD: https://claude.ai/artifact/HXFkK7hAua2Af59KiQSJ11

## Workflow

- The user commits manually. Never run `git commit` or `git push`. After finishing a part, stop and tell the user which files to commit, with a suggested commit message.
- Work in parts that each end runnable and tested.

## Commands

```bash
.venv/bin/pip install -e '.[eval,monitor,dev]'
.venv/bin/pytest
.venv/bin/twinwatch scan
```

## Hard rules

- Passive only. Never add code that transmits deauthentication, disassociation, jamming or any attack frame, and never decrypt or inspect user traffic.
- The hostapd lab AP is not part of this repo. Do not add an evil twin kit.
- Test fixtures use locally administered MACs (`02:00:00:...`) and invented SSIDs, never real nearby networks.
- Everything under `data/` (raw, processed, lab) is stored on DagsHub only, never in git: AWID3/WiGLE are licence-restricted and lab recordings contain nearby networks' SSIDs and MACs. Never suggest `git add` for data files. Data is versioned with DVC (`dvc add data/<folder>`, commit the `.dvc` pointer, `dvc push`) to the private DagsHub repo `Munam32/TwinWatch`. `.gitignore` lists data folders by name because DVC misreads `/data/*` and then ignores the `.dvc` files. `.env` holds API credentials and stays gitignored.

## Architecture

- `twinwatch/model.py` owns the shared schema. Every source (live scan, lab, AWID3, WiGLE, synthetic) converts to `Snapshot`/`APRecord`; features and detectors must not branch on source.
- Fields a source cannot provide are `None` (nmcli: beacon_interval, capabilities, tsf). Features must handle `None`.
- `APRecord.security` is a tuple of protocols from `SECURITY_RANK`; `security_rank` gives the strongest, used for downgrade detection.
- Labels live on `APRecord.label` (`benign` / `evil_twin` / None). A cloned-BSSID twin is told apart by `bssid@freq`.
- Security protocols are derived in one place, `model.derive_security`, from normalized AKM names (PSK, SAE, EAP, EAP-SUITE-B, OWE). Every parser (iw, AWID3) normalizes to those names and calls it.
- AWID3 converter (`twinwatch/datasets/awid3.py`) reads tshark field-name columns from a CSV or from `tshark` on a pcap. Field names were checked against Wireshark's display-filter reference; real AWID3 column names and label values are still unverified until the dataset arrives.
- WiGLE (`twinwatch/datasets/wigle.py`): credentials `WIGLE_API_NAME` / `WIGLE_API_KEY` from env or `.env`. Never print them. Searches are rate-limited per day: always bound by `--bbox`, and test with mocked HTTP.
- Synthetic generator (`twinwatch/datasets/synth.py`): a twin only gets fields its base has (mirrors None), so models cannot learn source artifacts. No single field may separate twins from benign new APs: `BENIGN_OTHER_VENDOR`, `SPOOFED_OUI`, `TWIN_OTHER_CHANNEL` and `TWIN_SIGNAL_DB` keep vendor, channel and signal overlapping. Lab recordings (`data/lab/`) are never synthetic bases for training. Sessions are identified by `meta["session"]`; split train/test by session, never by snapshot.
- Monitor mode (`twinwatch/scan/monitor.py`) only sniffs; channel changes use `iw ... set freq`, never transmission. Per-beacon logic shared with AWID3 lives in `twinwatch/beacons.py`. Scapy holds the capability field byte-swapped; `frame_to_record` swaps it back. `APRecord.tsf_backwards` (None outside per-beacon sources) feeds the `tsf_anomaly` signal; the synthetic `cloned_same_channel` scenario is generated only for bases with per-beacon TSF.
- Recordings are JSON Lines, one snapshot per line (`twinwatch/recording.py`).
- `twinwatch/features.py` owns the signal list (`SIGNALS`, fixed order = ML feature order). Detectors never read APRecords directly.
- `twinwatch/cluster.py`: DBSCAN over trusted baseline APs, `min_samples` fixed at 1 (trusted APs are never noise), `EPS` from `python -m twinwatch.cluster tune`. Its signals (`cluster_outlier`, `cluster_distance`) feed only the ML detector; the weighted rule ignores signals it has no weight for. `NUMERIC` signals are never listed as reasons.
- `recording.sessions` groups snapshots by (session, SSID); use it for any train/test split.
- A detector is a scorer `signals -> (score 0..1, reasons)` registered in `detectors.DETECTORS`; `detectors.assess` turns scores into Safe / Suspicious / Likely verdicts (0.4 / 0.75). The ML detector plugs in the same way through `detectors.make_scorer("ml", model_path)`; `twinwatch/evaluation/train.py` trains it, grouping CV folds by origin (`meta["origin"]|ssid`), never by session, because synthetic sessions from one source share its devices.

## Evaluation discipline

- `python -m twinwatch.evaluation.evaluate` compares naive, weighted and any `--model NAME=PATH` on test sessions; ablations are models trained with `train --drop-signals`. It skips sessions with a twin in the baseline and warns when a model's training origins overlap the test origins. `results/` is gitignored (it names SSIDs).

- Train on AWID3 + WiGLE + synthetic data; the lab set is test-only and never used for training or threshold tuning.
- Cross-validate grouped by capture/session, never random rows from one session.
- Results are lab comparisons, not real-world accuracy claims.
