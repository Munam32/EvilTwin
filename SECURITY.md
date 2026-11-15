# Security Policy

TwinWatch is a passive detector for evil twin Wi-Fi access points. This page covers how to report a vulnerability, what the tool does and does not protect against, and how to use it responsibly.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue for a security problem.

Please include:

- what is affected (file, command, or input) and the version or commit;
- steps to reproduce, ideally with a recorded scan file instead of a live network;
- the impact you expect (for example, a crafted beacon that crashes the parser or hides a twin).

You can expect an acknowledgement within 7 days. This is a university project maintained by one person, so fixes are best effort. Reports are credited in the fix unless you ask otherwise.

## Supported versions

Only the latest commit on `main` receives fixes.

## In scope

- Crashes or hangs caused by crafted scan output, beacon frames, pcap files or recordings (`iw`/`nmcli` parsers, monitor-mode capture, AWID3 and WiGLE converters).
- Ways to make the detector rate a twin as Safe that the documented signals should catch.
- Loading untrusted files: model files (`.joblib`) are Python pickles and run code when loaded, so only load models you trained yourself.
- Leaks of credentials (`.env`, `.dvc/config.local`) or of lab data into git.

## Out of scope: known limitations

These are documented design limits, not vulnerabilities:

- **Perfect clones.** A twin that copies the real AP's BSSID, channel, security settings, beacon interval and capability bits cannot be told apart in a managed-mode scan. Monitor mode can reveal it on the channel being monitored, because the two devices' TSF timestamps interleave and go backwards; only the ML detector uses that signal.
- **Spoofed vendor prefix.** A twin can choose a MAC address with the real vendor's prefix, which hides it from the vendor and DBSCAN checks.
- **Trust on first use.** The baseline trusts whatever is present when `twinwatch learn` runs. A baseline learned next to an attacker trusts the attacker.
- **Lab-only accuracy.** Reported detection and false-positive rates come from controlled lab tests on the author's own devices and are not real-world guarantees.

For networks where these limits matter, use WPA3-SAE or WPA2/WPA3-Enterprise (802.1X) with certificate validation, or a VPN.

## Responsible use

- TwinWatch only listens. It never sends deauthentication, disassociation, jamming or other attack frames, and never decrypts or inspects traffic. Contributions that add any of these will not be accepted.
- Run attack scenarios only on networks and devices you own or are authorised to test. The hostapd test AP used in the lab is not part of this repository.
- Scan recordings contain the names and MAC addresses of nearby networks. Keep them private: in this project they are stored in a private DagsHub repository through DVC and are never committed to git.
- Keep API credentials (WiGLE, DagsHub) in `.env`, which is gitignored, and never paste them into issues or logs.
