# Evil Twin IDS: Wi-Fi Rogue Access Point Detection System

A lightweight, Python-based Intrusion Detection System that monitors 802.11 wireless traffic in real time to detect **Evil Twin attacks**: rogue access points that impersonate a legitimate network's SSID to intercept traffic or harvest credentials.

Built as part of a BSc Honours dissertation project, *"Mitigating Evil Twin Threats"*. The system was tested in a virtualized lab environment against rogue APs generated with `airbase-ng`, including scenarios with MAC address spoofing.

## What It Detects

The IDS focuses specifically on **Evil Twin attacks**, identified by two core signals:

- **Duplicate SSID, different BSSID**: the classic Evil Twin fingerprint. If the same network name (SSID) suddenly broadcasts from a BSSID (MAC address) that hasn't been seen before, that's a strong indicator of a rogue clone.
- **Anomalous signal strength**: rogue APs set up close to a victim (e.g. for a targeted attack) often broadcast at a much stronger signal than the legitimate AP. Beacons exceeding a configurable RSSI threshold are flagged as a possible Evil Twin.

It does **not** currently detect other attack classes such as man-in-the-middle, rogue DHCP servers, or denial-of-service: see [Limitations](#limitations-and-known-issues) below.

## How It Works

1. **Packet capture**: `scapy.sniff()` listens on a wireless interface in monitor mode, filtering for management frames (`type mgt`) so only 802.11 Beacon frames are processed.
2. **Beacon parsing**: for each beacon, the IDS extracts the SSID, BSSID, and signal strength (`dBm_AntSignal`).
3. **Whitelist check**: BSSIDs belonging to known, trusted APs are skipped from rogue classification.
4. **Rogue detection logic**:
   - If a beacon's SSID is already known but arrives from a new, non-whitelisted BSSID, it's logged as a duplicate-SSID alert.
   - If the signal strength exceeds the `evil_twin_signal_threshold` (default `-70 dBm`), it's flagged as a possible Evil Twin.
5. **Logging**: every detection event and beacon summary is written to a rotating log file (`rogue_aps.log`, 5 MB per file, 3 backups kept) via Python's `logging` module, alongside console output for live monitoring.
6. **Post-run analysis**: after the capture window ends, the IDS re-parses its own log file to produce a frequency breakdown of detected BSSIDs, and calculates detection performance metrics.

## Performance Metrics

`IDS.py` tracks classification outcomes during a test run (true/false positives and negatives) and, once sniffing finishes, computes:

| Metric | Description |
|---|---|
| **Precision** | Of all APs flagged as rogue, how many actually were |
| **Recall** | Of all actual rogue APs present, how many were detected |
| **F1 Score** | Harmonic mean of precision and recall |
| **Accuracy** | Proportion of all correct classifications (rogue + legitimate) |
| **Detection Time** | Time elapsed between the start of a capture and the first rogue AP detection |

In dissertation testing, the IDS achieved **1.00 precision, recall, F1, and accuracy**, with near-instant detection latency, including against attackers using MAC spoofing.

`metrics_chart.py` turns these results into visual summaries using `matplotlib`:
- **Precision**: horizontal progress/thermometer bar
- **Recall**: pie chart
- **F1 Score**: semicircular gauge
- **Accuracy**: bar chart breakdown of TP / TN / FP / FN counts

These are useful for including results in a report, presentation, or portfolio piece.

## Tech Stack

- **Python 3**
- [**Scapy**](https://scapy.net/): packet crafting and sniffing, 802.11/Dot11 frame parsing
- **logging** (standard library): event logging with automatic log rotation
- **Matplotlib** / **NumPy**: performance metric visualization
- Tested on **Linux**, using a wireless adapter capable of **monitor mode** (Alfa adapters were used during development)

## Requirements

- Dual Linux machines (tested inside Kali Linux VMs, hosted on physical workstations): one to act as the attacker running `airbase-ng`, and one to act as the victim/IDS host
- Dual wireless Alfa network adapters that support monitor mode (one per machine)
- A portable router to act as the legitimate access point (an AC750 was used during testing, connected on the victim side)
- Root/sudo privileges (required for packet sniffing on a wireless interface)
- Python 3.x

Install dependencies:

```bash
pip install scapy matplotlib numpy
```

## Setup

1. Put your wireless adapter into monitor mode, e.g.:
   ```bash
   sudo airmon-ng start wlan0
   ```
2. Update the interface name in `IDS.py` if it differs from `wlan0`:
   ```python
   sniff(iface="wlan0", prn=packet_handler, timeout=60, store=0, filter="type mgt")
   ```
3. Update `whitelist_bssids` with the BSSID(s) of your own legitimate access point(s).
4. (Optional) Adjust `evil_twin_signal_threshold` to suit your environment's signal conditions.

## Usage

Run the IDS with root privileges (required for raw packet capture):

```bash
sudo python3 IDS.py
```

By default, it will:
- Wait 2 seconds before starting (configurable)
- Sniff for 60 seconds (`timeout=60`)
- Print alerts to the console and write them to `rogue_aps.log`
- Run log analysis and print Precision / Recall / F1 / Accuracy at the end

To generate the metric charts (edit the values inside the script to match your own test results first):

```bash
python3 metrics_chart.py
```

This produces `precision_chart.png`, `recall_chart.png`, `f1_score_chart.png`, and `accuracy_chart.png`.

## Project Context and Test Setup

The IDS was evaluated in a controlled, virtualized testbed rather than a live production network:
- A legitimate AP (an AC750 router) represented the trusted network.
- A rogue AP was created using `airbase-ng`, broadcasting a spoofed SSID (`UniTest_AP`) to simulate an Evil Twin, including tests where the attacker spoofed the legitimate AP's MAC address.
- The IDS was run on a victim-side Kali Linux VM to monitor for the attack.
- `airodump-ng` was used on the victim side as a quick sanity check during testing, confirming beacon frames from the rogue AP were actually reaching the victim VM's interface before relying on the IDS's own detection output.

## Limitations and Known Issues

- **Single attack type**: currently detects only Evil Twin-style attacks; no coverage for MITM, rogue DHCP, or DoS attacks.
- **Lab-tested only**: validated in a virtualized environment; hardware behavior (adapter drivers, VM networking) may differ on physical deployments.
- **Concurrent connection conflict**: cannot reliably run at the same time as the monitored device is actively connected to the legitimate AP.
- **Single-machine design**: runs as a standalone client-side script rather than a distributed/centralized system, which limits scalability across larger networks.
- **No GUI**: currently a command-line tool only.

## Potential Future Work

Ideas identified for extending this project beyond the dissertation scope:

- Detect additional attack types (man-in-the-middle, rogue DHCP servers, denial-of-service)
- Centralized alerting: feed multiple IDS instances into a central server for aggregated monitoring and alerts
- Integration into existing network hardware (routers/APs) rather than a standalone script
- A GUI to make the tool accessible to non-technical users
- Improved noise handling to reduce misclassification in high-interference environments

## Disclaimer

This tool was built for academic research and defensive security testing in a controlled lab environment. Only use it on networks and devices you own or have explicit permission to test. Running packet capture tools on networks without authorization may be illegal in your jurisdiction.


