# Limitations and constraints

TwinWatch is a passive detector built for a university project. This page lists what it cannot do, where its data falls short, how far its results can be trusted, and the rules the project works under. Figures are from the state of the repository on 2026-11-17, before the lab sessions were recorded.

## 1. Detection limits

These follow from listening passively and comparing against a learned baseline. Most cannot be removed without active checks such as 802.1X certificate validation.

### Clones and spoofing

- **Perfect clone in a normal scan.** A twin that copies the real AP's BSSID, channel, security, beacon interval and capability bits merges with the real AP in an `iw` or `nmcli` scan and cannot be seen. Only monitor mode can catch it: the two devices' TSF timestamps interleave and run backwards. Only the ML detector uses that signal (`tsf_anomaly`).
- **TSF only on the monitored channel.** When the card is connected, monitor mode stays on the connected channel (EBUSY fallback), so a clone on another channel is missed there. While hopping, frames on other channels are missed between dwells.
- **Spoofed vendor prefix.** A twin can choose a MAC address with the real vendor's OUI. The `oui_change` and DBSCAN cluster signals then stay silent. The AWID3 twin did exactly this: the real AP's MAC plus one.
- **Careful twin vs. legitimate new AP.** A twin with a new BSSID that copies the vendor, channel, security and beacon settings looks like a newly installed access point.
  - Weighted misses about half of these twins (48–50% caught in cross-validation).
  - ML catches them by flagging most new APs, including about 84% of legitimate new APs.

### Names

- **Lookalike and sibling names are ambiguous.** Real nearby networks also have lookalike names: 2–4% of networks in the Lahore WiGLE data have one in the same ~110 m cell. In cross-validation, ML rates about half of the harmless new lookalike or sibling neighbours Likely evil twin. Neighbours seen while `learn` runs are trusted and never reported, so this only affects networks that appear later.
- **Twin with a band or extender suffix** (`Home_5G`, `Home-EXT`, `Home-2`). On name alone it is only Suspicious, because owners create such networks all the time. It needs another sign (vendor, downgrade, signal jump) to reach Likely.
- **Names the lookalike rules do not treat as lookalikes:**
  - names shorter than 4 characters after normalising (only exact matches count);
  - names that differ only in digits;
  - default names that differ only in a device code (`TP-Link_31A6` / `TP-Link_A886`);
  - emoji- or symbol-only names;
  - look-alike characters outside the folded set (0/o, 1/l/i, 3/e, 4/a, 5/s, 7/t, 8/b, rn/m, vv/w);
  - names more than 1 edit apart (2 for names of 8+ characters).
- **Hidden-SSID twins in live use.** The pcap converter attributes hidden-SSID beacons to the network whose BSSID advertised the name. Live scans do not, so a clone that hides its SSID (as in the WPA3 downgrade capture) can be missed entirely.

### Baseline and timing

- **Trust on first use.** `twinwatch learn` trusts whatever is on air at that moment. A baseline learned while an attacker is present trusts the attacker. A network that changes (new APs, channel changes after a router reboot) causes alerts until the baseline is relearned.
- **Signal strength.** Signal jumps depend on where the laptop is. Moving around the building causes jumps that a fixed baseline cannot tell apart from a closer twin.
- **Time to alert.** Detection works per scan, every 15 s by default (`--interval`), so a twin is reported at the earliest one scan after it appears.

### Scope

- **What it does not protect against:**
  - it does not check what happens after connecting (captive portals, TLS interception, DNS spoofing);
  - it does not verify 802.1X certificates;
  - it does not stop a device from auto-joining a twin.

  It only warns.
- **Platform and backends:**
  - Linux only.
  - `iw` needs a recent scan from NetworkManager; `nmcli` gives no beacon interval, capabilities or TSF.
  - Monitor mode needs root, a card that supports it, and the `scapy` extra.

## 2. Data limits

### WiGLE (training bases)

- **Missing fields.** No signal strength, AKM, capability bits or TSF; the beacon interval is 0 in every record. Signal levels in synthetic sessions built on WiGLE are simulated, so the signal-based results rest on assumptions.
- **Not real scans.** One record per BSSID with an estimated location, not scans over time. APs are grouped into ~110 m grid cells to stand in for "what one laptop hears", which mixes APs that may never have been on air together.
- **Old and noisy records.**
  - Some records date from 2005–2022. Area downloads were limited to 2023 onward, but the campus SSIDs were not.
  - 45 of 205 campus cells mix security types, partly from stale WEP or open records.
- **Coverage.**
  - The Stanford download stopped at 300 records because of the daily query limit; Google Starbucks has only 3 usable cells.
  - Areas covered: 6 campus or venue SSIDs, two Lahore neighbourhoods, and WPA3 networks in San Francisco and Lahore.
- **Licence and quota.**
  - Data is for this project only, kept private and credited to WiGLE.
  - The daily query limit made it impossible to repeat downloads freely.

### AWID3 (real twin for training, real clone for testing)

- **Source.** An unofficial Kaggle copy (licence stated as "Unknown"), used with the instructor's approval. The official release was requested separately.
- **Missing fields.**
  - The published CSVs lack AKM and cipher suites and the full capability field. Security is approximated: an RSN element (detected through `wlan.rsn.capabilities.mfpc`) counts as WPA2, none as OPEN, so WPA3 and WEP cannot be identified.
  - `radiotap.dbm_antsignal` sums several antennas, so `wlan_radio.signal_dbm` is used instead.
- **Wrong labels.** AWID3 marks some of the twin's own frames `Normal` (Evil_Twin), and the rogue's probe responses `Normal` (Rogue_AP). They were relabelled:
  - Evil_Twin by the twin's BSSID;
  - Rogue_AP by TSF below 1,000 s.

  Both rules were set by inspecting the data.
- **Only management frames.** Of each capture, only beacons and probe responses were kept.
- **One network.** Every attack targets the same AP (`ASUS_5G`), and each folder holds one attack.
- **Krack unusable.** The KRACK copy of the AP ran on a channel that was not captured.

### WPA3 Attacks Dataset (real tests)

- **Labels.** Each file has one scenario label. The twin was labelled by rules chosen after inspecting the data:
  - beacon interval 16 or capabilities `0x0411` (downgrade capture);
  - the SSID `" KARIMM"` (evilTwin and RogueAP captures).
- **One small testbed.** One AP, 4 clients, channel 11; MAC addresses are anonymised.
- **Reordered windows.** In the downgrade capture the twin is on air from the start, so the last clean windows were moved to the front to form a baseline. The time order of that session is therefore not real (marked `meta["reordered"]`).
- **"Evil twin" there means a lookalike name**, not the same SSID. It is used only to test the lookalike signal.

### Synthetic sessions

- **Assumptions behind the attacks.** The generator follows set rates and ranges:
  - 26% of new legitimate APs carry another vendor prefix, taken from real WiGLE cells;
  - 50% of twins copy the real vendor prefix;
  - 50% of twins use another channel;
  - 50% are careful attackers that copy the beacon interval and capabilities;
  - twin signal is 15 dB below to 5 dB above the real AP;
  - hostapd defaults are used for careless attackers.

  Real attackers may behave differently.
- **Mostly synthetic training.** Synthetic rows make up almost all of the training data (about 99%). The model's behaviour reflects these assumptions more than real attacks.
- **Name cases.** Harmless lookalike and sibling cases come from 437 real neighbour pairs, mostly in Lahore. Their twins use a fixed set of name edits and suffixes.

### Lab sessions

- Not recorded yet (as of 2026-11-17). They will come from one home network with the author's own devices and a hostapd twin. That covers one router, one building and one attacker device.

## 3. Evaluation limits

- **No real-world accuracy claim.** All numbers are lab and dataset comparisons. They show whether an approach works, not how often it works in the wild.
- **Small real test set.** 4 held-out real captures from 2 testbeds (AWID3 Rogue_AP, and WPA3 downgrade, evilTwin and RogueAP). ML caught all 4 with 0 false alarms; that is evidence, not a rate.
- **Cross-validation is on mostly synthetic data,** grouped by origin, with whole networks held out together:
  - `cloned_same_channel` comes from a single origin (AWID3), so cross-validation reports 0% for it: when that origin is held out, the model has never seen the attack.
  - "False-positive rate" in cross-validation counts benign AP sightings in synthetic sessions, not alarms per day of real use.
- **Fixed thresholds.** Suspicious at 0.4 and Likely at 0.75 were chosen, not tuned. The lab set is never used for tuning.
- **Pre-lab version.** The shipped model may later be retrained with the held-out captures included. Its accuracy must then be quoted from the earlier tests that did not include them.

## 4. Constraints

- **Passive only.** TwinWatch never transmits deauthentication, disassociation, jamming or any other attack frame, and never decrypts or inspects user traffic. Monitor mode only listens; channel changes use `iw ... set freq`.
- **No attack kit.** The hostapd twin used in the lab is not part of the repository.
- **Authorised testing only.** Attack scenarios run only on the author's own network and devices, with the instructor's approval.
- **Data privacy.**
  - Recordings and datasets contain names and MAC addresses of nearby networks. They are stored only in the private DagsHub repository through DVC, never in git.
  - Lab networks are excluded from WiGLE training data.
  - Test fixtures use invented SSIDs and locally administered MACs.
- **Credentials.** WiGLE, DagsHub and Kaggle credentials stay in `.env`, `.dvc/config.local` and `~/.kaggle/kaggle.json`, never in git or logs.
- **WiGLE terms.** One account, within the daily query limit; extra accounts must not be used to get around it.
- **Model files are pickles.** `.joblib` files run code when loaded, so only load models you trained yourself.
- **Time.** A one-person university project with a fixed deadline: secondary datasets replaced most of the planned own data collection.
