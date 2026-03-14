# NetMirror — Lightweight Packet Triage
### Real-Time Network Traffic Analysis & Anomaly Detection

---

## Quick Start

```bash
# 1. Install dependencies
pip install flask flask-socketio scapy eventlet

# 2. Run the application
python3 app.py

# 3. Open browser
http://localhost:5000
```

> **Demo Mode** works without `tcpdump` installed — realistic traffic simulation with auto-injected anomalies.
> **Live Mode** requires `tcpdump` and typically needs `sudo` or CAP_NET_RAW capability.

## Steps to activate Live Mode on your machine:

Install tcpdump if not present: sudo apt install tcpdump
Run the app with root/sudo (required for raw packet capture): sudo python3 app.py

Or grant the capability without sudo: sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)

Select your real interface from the dropdown (e.g., eth0, ens3, wlan0) — any works too
Toggle Live Mode in the UI and click Start

# Classic sudo + venv conflict. sudo uses the system Python, which doesn't have your venv's packages. Two clean ways to fix this:
> Option 1 — Tell sudo to use the venv's Python directly (recommended):
> sudo /home/YOUR DIR/netmirror/venv/bin/python3 app.py

> Option 2 — Grant cap_net_raw to your venv's Python so sudo isn't needed at all:
> sudo setcap cap_net_raw,cap_net_admin+eip /home/YOUR DIR/netmirror/venv/bin/python3
> python3 app.py
> Then just run python3 app.py normally inside the venv, no sudo required.

> Option 3 — Activate the venv inside the sudo shell:
> sudo bash -c "source /home/YOUR DIR/netmirror/venv/bin/activate && python3 app.py"

Why this happens: When you run sudo python3, sudo resets the PATH and environment to root's defaults, completely ignoring your activated venv. Your venv's packages (Flask, flask-socketio, etc.) only exist at /home/YOUR DIR/netmirror/venv/lib/..., which the system Python never sees.
Option 2 is the cleanest for a dev/analyst workflow — you keep working in your venv normally without prefixing sudo every time. The cap_net_raw capability grants just the specific kernel permission needed for raw packet capture, rather than full root access.
If you're unsure where your venv Python is, run this to confirm the path:
bashwhich python3
It should show something like /home/YOUR DIR/netmirror/venv/bin/python3 when the venv is active.


---

## Features

### Traffic Capture
- **Demo Mode**: Realistic simulated traffic with automatic anomaly injection (DNS bursts, ARP sweeps, SYN floods)
- **Live Mode**: Real packet capture via `tcpdump` with BPF filter support
- **Interface selection**: Capture on any/all interfaces or specific NICs
- **BPF Filters**: Full Berkeley Packet Filter syntax (`tcp port 443`, `host 10.0.1.1`, etc.)

### Protocol Analysis
- Real-time protocol distribution (doughnut chart)
- Protocol latency tracking: DNS, HTTP, HTTPS with P95 percentiles
- Color-coded packet table with protocol badges
- Conversation-level bandwidth tracking (Top Talkers)

### Security Anomaly Detection (Blue Team)
| Alert Type | Threshold | MITRE ATT&CK |
|-----------|-----------|--------------|
| DNS Exfiltration | >50 DNS queries/min from single IP | T1071.004 |
| ARP Scan / MitM | >30 ARP requests/min | T1018, T1557.002 |
| SYN Flood | >100 SYN packets/min | T1499 |
| Port Scan | >20 unique ports probed | T1046 |
| ICMP Flood | >60 ICMP packets/min | T1499.002 |
| Data Exfiltration | >10MB to single external IP | T1048 |

### Reporting
- **JSON Report Export**: Full incident report with alerts, top talkers, latency stats, and actionable recommendations
- **PCAP Export**: Raw packet captures for forensic analysis (live mode)
- Click any alert or packet row for detailed drill-down

---

## Interface Overview

```
┌─────────────────────────────────────────────────────────────┐
│ HEADER: Mode | Interface | BPF Filter | Start/Stop | Status │
├──────────────┬──────────────────────────────┬───────────────┤
│ LEFT PANEL   │ MAIN: Packet Table           │ RIGHT PANEL   │
│              │                              │               │
│ KPI Cards    │ Timeline (packets/sec)       │ 🛡 Alerts Feed│
│ Protocol Mix │ ─────────────────────────── │               │
│ Latency Bars │ Filter Chips + Search        │ CRITICAL ──── │
│ Top Talkers  │ ─────────────────────────── │ HIGH ──────── │
│              │ Live Packet Rows             │ MEDIUM ─────  │
│              │  (click for detail)          │ (click for    │
│              │                              │  detail + rec)│
└──────────────┴──────────────────────────────┴───────────────┘
```

---

## Live Capture Setup

```bash
# Option 1: Run as root
sudo python3 app.py

# Option 2: Grant capability to python3
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
python3 app.py

# Option 3: Use tcpdump with setuid (usually pre-configured on most systems)
python3 app.py  # then select Live mode in the UI
```

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /` | GET | Dashboard UI |
| `GET /api/interfaces` | GET | List network interfaces |
| `POST /api/start` | POST | Start capture session |
| `POST /api/stop` | POST | Stop capture session |
| `GET /api/packets` | GET | Fetch packet history |
| `GET /api/alerts` | GET | Fetch security alerts |
| `GET /api/stats` | GET | Live statistics |
| `GET /api/stats/latency` | GET | Protocol latency data |
| `POST /api/export/report` | POST | Download JSON report |
| `GET /api/export/pcap/<id>` | GET | Download PCAP file |

### Start Capture Request Body
```json
{
  "interface": "eth0",
  "filter": "tcp port 80 or tcp port 443",
  "mode": "demo"
}
```

---

## Thresholds Configuration

Edit `THRESHOLDS` dict in `app.py`:

```python
THRESHOLDS = {
    'dns_requests_per_minute': 50,    # DNS exfil trigger
    'arp_requests_per_minute': 30,    # ARP sweep trigger
    'syn_per_minute': 100,            # SYN flood trigger
    'port_scan_unique_ports': 20,     # Port scan trigger
    'icmp_per_minute': 60,            # ICMP flood trigger
    'large_transfer_mb': 10,          # Data exfil (MB) trigger
}
```

---

## Architecture

```
Browser (WS client)
    │
    ▼
Flask + SocketIO (port 5000)
    │
    ├── /api/* routes (REST)
    │
    ├── Packet Processor
    │     ├── Demo Simulator (threading)
    │     └── tcpdump Parser (subprocess + threading)
    │
    ├── Anomaly Detector
    │     ├── DNS rate tracker
    │     ├── ARP rate tracker
    │     ├── SYN flood detector
    │     ├── Port scan detector
    │     └── Data exfil detector
    │
    └── Stats Engine
          ├── Protocol distribution
          ├── Latency tracker
          ├── Conversation stats
          └── Report generator
```
