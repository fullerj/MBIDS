# MBIDS

Misuse-Based Intrusion Detection System for Z-Wave networks. The detector consumes over‑the‑air traffic captured with Scapy + GNU Radio, builds an allow-list from a live Z-Way controller, and records packets that violate protocol, topology, or checksum rules. An enhanced pipeline can also correlate captures with the controller’s own log file to spot impersonation attacks.


## Prerequisites

- **Python 2.7** – the code relies on `__builtin__` and other Py2-only modules.
- **Scapy with Z-Wave support** – e.g. Scapy ≥ 2.3.1 plus the [`scapy-radio`](https://github.com/secdev/scapy/tree/master/scapy/radio) extras so that `load_module('gnuradio')` works.
- **GNU Radio runtime** – used to ingest samples from your SDR. The repo includes `Zwave.grc` as a starting flow graph; tailor it to your radio front end and local Z-Wave frequency (e.g. 908.42 MHz in the US).
- **Paramiko** – only required if you intend to run the Z-Way server comparator (`pip2 install paramiko`).
- **Z-Way controller with REST access** – MBIDS builds its device map from `http://<controller>:8083/ZWaveAPI/Data/0`. Make sure the API is reachable from the host running MBIDS.
- **Root / sudo privileges** – Scapy’s GNU Radio integration needs elevated permissions to access the SDR interface.

## Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/<your-account>/MBIDS.git
   cd MBIDS
   ```
2. **Prepare a Python 2 virtualenv (optional but recommended)**
   ```bash
   virtualenv -p python2 venv
   source venv/bin/activate
   ```
3. **Install Python packages**
   ```bash
   pip install scapy paramiko
   # install scapy-radio support (from source if pip does not provide it)
   pip install git+https://github.com/secdev/scapy.git#subdirectory=scapy/layers
   ```
   > Tip: if you already have Scapy with GNU Radio support on your system, simply ensure it is available on the Python path for the interpreter you plan to use.
4. **Install GNU Radio / SDR drivers** – follow the guides for your hardware (HackRF, USRP, etc.), then open `Zwave.grc` in GNU Radio Companion and adjust gain, center frequency, and sample rate.

## Configure Controller Connection

Several scripts hard-code the address of the Z-Way controller. Update these constants before running anything:

- `MBIDS/main.py:306` → change `IP = "10.1.0.66"` to your controller IP/hostname (port defaults to `8083`).
- `MBIDS/Enhanced_main.py:479` – same constant for the enhanced detector.
- `Misuse_Based_IDS.py:682` – legacy detector, update if you plan to run it.
- `MBIDS/Z-Way-Server_Comparator.py:219` – adjust the `host`, `usrn`, and `psswd` used for SSH access to the controller when running the comparator.

Once the IP is correct, MBIDS will call `/ZWaveAPI/Data/0`, pull the device list, and build the allow-list used during detection.

## Running the Detectors

1. **Start your SDR capture**
   - Launch the GNU Radio flow graph (`Zwave.grc`) or your custom equivalent so that Scapy can receive Z-Wave frames on `gr-zwave`.
2. **Run the baseline misuse detector**
   ```bash
   sudo python MBIDS/main.py
   ```
   - The script prints `[BEGIN]` and `[WAITING]` status messages while monitoring traffic.
   - Violations are appended to `IDS_Log` in the project root.
3. **Optional: run the enhanced detector**
   ```bash
   sudo python MBIDS/Enhanced_main.py
   ```
   - Everything the baseline version does, plus it logs known-good packets to `Captured_Packets_Log` for later review.
4. **Optional: correlate with the controller log**
   ```bash
   sudo python MBIDS/Z-Way-Server_Comparator.py
   ```
   - Requires SSH access to the controller. It consumes entries from `Captured_Packets_Log` and flags spoofed controller traffic (e.g., Node ID 1 impersonation) in `IDS_Log`.
5. **Legacy script**
   ```bash
   sudo python Misuse_Based_IDS.py
   ```
   - Early version retained for reference. Prefer the scripts under `MBIDS/` unless you have a reason to reproduce the historical results exactly.

## Understanding the Output

- `IDS_Log` – canonical log of detected misuse cases (invalid source/destination IDs, payload length issues, loopbacks, spoofed controller messages, etc.).
- `Captured_Packets_Log` – written by `Enhanced_main.py`; contains captured packets that initially passed validation and need to be reconciled with the controller logs.
- Console output – the automata states and packet counters are printed to stdout for quick monitoring.

Clear the log files between captures if you want a clean slate:

```bash
> IDS_Log
> Captured_Packets_Log
```

## Typical Workflow

1. Update controller credentials/IP in the scripts.
2. Start the SDR flow graph so Scapy sees Z-Wave frames.
3. Run `MBIDS/main.py` (or `Enhanced_main.py`) as root.
4. Let it capture traffic during your test scenario.
5. Optionally run the comparator to validate controller-originated packets.
6. Review `IDS_Log` and act on any flagged misuse cases.

## Troubleshooting

- If the detector immediately exits or never leaves `WAITING`, confirm that the GNU Radio module loads successfully (`scapy` can list it with `lsmod()`).
- Failures when calling `/ZWaveAPI/Data/0` usually mean the IP/port is incorrect or the controller requires authentication—verify the API is reachable in a browser first.
- Run with `sudo` to avoid permission errors when opening the SDR interface.

Feel free to tailor the scripts for your environment—the detection logic was designed for research and may require adjustments for modern Z-Wave devices or firmware versions.
