# NetMirror — User Guide
### Lightweight Packet Triage & Real-Time Network Analysis

**Version:** 1.0 | **Audience:** IT Network Analysts, SOC Analysts, Security Engineers

---

## Table of Contents

1. [Quick Start](#1-quick-start)
2. [UI Layout Overview](#2-ui-layout-overview)
3. [Header Controls](#3-header-controls)
4. [Left Panel — Traffic Intelligence](#4-left-panel--traffic-intelligence)
   - 4.1 KPI Cards
   - 4.2 Protocol Mix Chart
   - 4.3 Protocol Latency
   - 4.4 Top Conversations
5. [Main Panel — Live Packet Table](#5-main-panel--live-packet-table)
6. [Right Panel — Security Alerts](#6-right-panel--security-alerts)
7. [Packet & Alert Detail Modals](#7-packet--alert-detail-modals)
8. [Export Tools](#8-export-tools)
9. [BPF Filter Reference](#9-bpf-filter-reference)
10. [Anomaly Detection Engine](#10-anomaly-detection-engine)
11. [Latency Correlation Engine](#11-latency-correlation-engine)
12. [Deriving Actionable Insight](#12-deriving-actionable-insight)
    - 12.1 Slow Application Triage Workflow
    - 12.2 Security Investigation Workflow
    - 12.3 Baseline & Capacity Planning
    - 12.4 Reading the Protocol Mix
    - 12.5 Top Conversations Analysis
    - 12.6 Alert Triage Decision Tree
13. [Threshold Tuning](#13-threshold-tuning)
14. [API Reference](#14-api-reference)
15. [Troubleshooting](#15-troubleshooting)

---

## 1. Quick Start

### Installation

```bash
# Clone or extract the project
cd ~/netmirror

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install tcpdump (system-level, required for Live Mode)
sudo apt install tcpdump        # Debian / Ubuntu
# sudo yum install tcpdump      # RHEL / CentOS
# brew install tcpdump          # macOS
```

### Running the Application

```bash
# Demo Mode (no root required — simulated traffic with auto-injected anomalies)
python3 app.py

# Live Mode — Option A: sudo with venv Python (recommended for one-off use)
sudo /home/<user>/netmirror/venv/bin/python3 app.py

# Live Mode — Option B: grant capability to venv Python (persistent, no sudo needed)
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
python3 app.py
```

Open your browser to **http://localhost:5000**

> **Demo Mode** is fully functional for learning the interface, testing alert logic, and training. It generates realistic mixed traffic and automatically injects DNS bursts, ARP sweeps, and SYN flood events every ~200 packet ticks.

---

## 2. UI Layout Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│  HEADER: Mode | Interface | BPF Filter | Start | Stop | Report | Clear   │
├─────────────────┬────────────────────────────────────┬───────────────────┤
│  LEFT PANEL     │  MAIN PANEL                        │  RIGHT PANEL      │
│                 │                                    │                   │
│  KPI Cards      │  Traffic Rate Timeline (60s)       │  🛡 Security      │
│  ─────────────  │  ──────────────────────────────    │     Alerts Feed   │
│  Protocol Mix   │  Filter Chips + IP Search          │                   │
│  (Doughnut)     │  ──────────────────────────────    │  CRITICAL items   │
│  ─────────────  │                                    │  HIGH items       │
│  Protocol       │  Live Packet Table                 │  MEDIUM items     │
│  Latency Bars   │  (scrolling, clickable rows)       │  (click any for   │
│  ─────────────  │                                    │   detail modal)   │
│  Top            │                                    │                   │
│  Conversations  │                                    │                   │
└─────────────────┴────────────────────────────────────┴───────────────────┘
```

The layout is a fixed three-column grid. All panels update in real time via WebSocket push — there is no manual refresh needed.

---

## 3. Header Controls

The header is the primary control surface for configuring and starting a capture session.

### Mode Toggle (`Demo` / `Live`)

| Mode | Description |
|------|-------------|
| **Demo** | Simulated traffic. No tcpdump, no root required. Injects DNS bursts, ARP sweeps, SYN floods automatically. Use for training, UI exploration, or testing alert thresholds. |
| **Live** | Real packet capture via tcpdump. Requires `CAP_NET_RAW` (see Quick Start). Displays actual network traffic on the selected interface. |

### Interface Selector

Dropdown populated from `/proc/net/dev`. Select the network interface to capture on:

| Value | When to use |
|-------|-------------|
| `any` | Capture on all interfaces simultaneously. Use for broad visibility or when unsure which interface carries the traffic of interest. |
| `eth0` / `ens3` | Wired LAN interface. Use for server or workstation traffic analysis. |
| `wlan0` | Wireless interface. |
| `lo` | Loopback only. Useful for testing local service latency (e.g., a database on localhost). |
| `docker0` / `virbr0` | Container or VM bridge interfaces. Useful for inspecting containerized application traffic. |

> **Tip:** When troubleshooting a slow application, select the specific interface the application traffic traverses rather than `any` — this reduces noise and keeps the packet table focused.

### BPF Filter Input

Berkeley Packet Filter expressions applied directly to tcpdump. Evaluated in-kernel before packets reach NetMirror — only matching packets are parsed and displayed.

See the full [BPF Filter Reference](#9-bpf-filter-reference) section for syntax and examples.

### Start / Stop Buttons

- **Start** — begins capture. A new session ID is assigned and displayed in the status pill. Stats reset.
- **Stop** — gracefully terminates both tcpdump processes (text parser and PCAP writer). The session PCAP remains on disk and is available for download.

### Report Button

Generates and immediately downloads a structured JSON incident report for the current (or most recent) session. Contains all alerts, top talkers, protocol distribution, latency analysis, and auto-generated recommendations. See [Export Tools](#8-export-tools).

### Clear Button

Clears the packet table display and resets all in-memory stats and alert feeds **without stopping an active capture**. Useful when you want a clean view after adjusting filters mid-session.

### Status Bar (right side of header)

| Indicator | Meaning |
|-----------|---------|
| Grey dot + `IDLE` | No active capture |
| Yellow dot + `DEMO` | Demo simulation running |
| Green dot + `LIVE` | Live tcpdump capture active |
| Red dot (pulsing) | Active capture with at least one security alert |
| `PKT` counter | Total packets processed in this session |
| `ALERTS` counter | Total security alerts fired (turns red when > 0) |
| `UP` timer | Session duration |

---

## 4. Left Panel — Traffic Intelligence

### 4.1 KPI Cards

Four summary cards update continuously:

| Card | What it shows | Actionable threshold |
|------|--------------|---------------------|
| **Packets/s** | 5-second rolling average packet rate | Sudden spike: possible flood or burst transfer. Drop to zero: interface issue or filter too restrictive. |
| **Alerts** | Total security alerts this session | Any value > 0 warrants investigation in the Alerts panel. |
| **Avg Latency** | Mean RTT across all tracked protocols (DNS, TCP, HTTP) | > 100ms average: investigate top-latency protocols. > 500ms: likely service degradation. |
| **Top Protocol** | Highest-volume protocol + its % of total traffic | Unexpected top protocol (e.g., ARP at >5%) is a red flag. |

### 4.2 Protocol Mix Chart

A live doughnut chart showing the proportion of each protocol observed in the current session.

**Reading the chart:**

- **Healthy LAN profile:** TCP + HTTPS dominate (60–80%), with moderate DNS (5–15%) and low ARP (<2%)
- **Concerning signals:**
  - ARP > 5% of all traffic → ARP scanning or misconfiguration
  - DNS > 20% → possible DNS tunneling, misconfigured resolver, or exfiltration
  - ICMP > 5% → network recon or ping flood in progress
  - FTP, Telnet, or NetBIOS visible → unencrypted legacy protocols that should be reviewed

**Interaction:** The chart legend is clickable — clicking a protocol name toggles it off the chart for cleaner comparison of remaining protocols.

### 4.3 Protocol Latency

Horizontal bar chart with one row per tracked protocol showing the rolling average RTT in milliseconds. Bar color encodes health:

| Color | Range | Meaning |
|-------|-------|---------|
| 🟢 Green | 0 – 10ms | Excellent. LAN-local or well-optimized service. |
| 🔵 Cyan | 10 – 50ms | Normal. Expected for most internet services. |
| 🟡 Yellow | 50 – 100ms | Elevated. Investigate if user complaints exist. |
| 🟠 Orange | 100 – 300ms | Degraded. Likely impacting user experience. |
| 🔴 Red | > 300ms | Critical. Service is effectively unresponsive. |

**Protocols tracked:**

| Protocol | How RTT is measured |
|----------|-------------------|
| **DNS** | Time between outbound query (dst port 53) and matching inbound reply (src port 53), keyed on client IP + source port |
| **TCP** | SYN packet timestamp to matching SYN-ACK arrival, keyed on 5-tuple |
| **HTTP** | First PSH from client to port 80/8080 to first PSH response back, keyed on connection |
| **HTTPS** | First PSH from client to port 443/8443 to first PSH response back |

> **Note:** Latency values only appear on **response** packets in the table. Request packets register state internally and show `—` in the Latency column. This is by design — RTT requires observing both directions.

**Actionable insight:**

- If **DNS latency** spikes but TCP latency is normal → resolver is slow; application waits on DNS before connecting. Check resolver health or switch to a faster upstream.
- If **TCP latency** spikes but DNS is normal → network path congestion or server-side connection queue exhaustion. Use Top Conversations to identify which server.
- If **HTTP/HTTPS latency** spikes while TCP SYN→SYN-ACK is fast → the server is accepting connections promptly but slow to generate responses. Indicates application-layer bottleneck (CPU, DB query, etc.) rather than a network problem.
- If **all protocols** show elevated latency simultaneously → suspect the local network segment (switch congestion, duplex mismatch, or full network pipe).

### 4.4 Top Conversations

Ranked list of the top 8 IP conversations by bytes transferred in the last 30 seconds. Each row shows:
- **Rank** — 1 is highest bandwidth
- **Conversation** — `src_ip → dst_ip`
- **Bytes** — total bytes in the 30s window

**Actionable insight:**

- The top conversation consuming disproportionate bandwidth is almost always your starting point for "slow app" complaints — it may be a backup job, video stream, or bulk transfer competing with the affected application.
- An unknown external IP at the top of the list is suspicious — look it up and correlate with the Alerts panel.
- Internal-to-internal conversations dominating over all external traffic may indicate lateral movement or large file transfers between hosts.

---

## 5. Main Panel — Live Packet Table

The center panel is the primary analysis surface. All captured packets stream into the table in real time.

### Traffic Rate Timeline

A 60-second rolling area chart at the top of the main panel shows packet rate per second. Use this to:
- Visually correlate user complaints ("it was slow at 2:15pm") with traffic spikes
- Identify bursty vs. sustained high-traffic periods
- Spot sudden drops to zero (interface down, filter too restrictive, or capture stopped)

### Filter Chips

Quickly narrow the packet table to a single protocol without affecting the underlying capture:

| Chip | Shows |
|------|-------|
| **All** | Every captured packet |
| **TCP** | TCP segments only (includes HTTP, HTTPS, SSH connections) |
| **UDP** | UDP datagrams only |
| **DNS** | DNS queries and responses (UDP/TCP port 53) |
| **ARP** | Layer 2 ARP requests and replies |
| **HTTP** | Packets to/from port 80 or 8080 |
| **ICMP** | Ping, traceroute, unreachable messages |

> Filter chips are client-side display filters only — they do not affect what tcpdump captures or what the anomaly engine processes.

### IP / Info Search

Free-text search box in the top-right of the toolbar. Matches against source IP, destination IP, and the Info column. Use to instantly isolate all traffic from a specific host: type `10.0.1.55` and only that IP's packets remain visible.

### Auto-scroll and Pause Display

- **Auto-scroll** (checked by default) — keeps the table scrolled to the newest packet. Uncheck to manually scroll through the packet history without the view jumping.
- **Pause display** — stops adding new rows to the table (useful for inspecting a specific moment) while the capture and anomaly engine continue running in the background. Resume by unchecking.

### Packet Table Columns

| Column | Description |
|--------|-------------|
| **#** | Sequential packet number for this session |
| **Timestamp** | Capture time to microsecond precision (`HH:MM:SS.ss`) |
| **Source IP** | Originating host address |
| **Destination IP** | Target host address (dimmer text for readability) |
| **Proto** | Color-coded protocol badge |
| **Port** | Destination port number |
| **Flags** | TCP flags (`S`=SYN, `A`=ACK, `P`=PSH, `F`=FIN, `R`=RST, `SA`=SYN-ACK) |
| **Size** | Packet payload size with inline mini bar proportional to 1500 bytes |
| **Info** | Human-readable packet description from tcpdump |
| **Latency** | RTT in ms for response packets; `—` for request packets or untracked protocols. Color-coded by threshold. |

### Row Color Coding

| Background tint | Meaning |
|----------------|---------|
| Purple tint | DNS packet (dst port 53) — heightened attention if frequent from one source |
| Orange tint | ARP packet — always worth monitoring |
| Red tint | TCP SYN without ACK — bare SYN; normal for new connections, suspicious in volume |

### Clicking a Row

Clicking any packet row opens the **Packet Detail Modal** with the full decoded packet fields and service classification. See [Section 7](#7-packet--alert-detail-modals).

---

## 6. Right Panel — Security Alerts

The right panel is the Blue Team monitoring surface. Every alert fired by the anomaly detection engine appears here in reverse-chronological order (newest at top).

### Alert Severity Levels

| Severity | Color | Response expectation |
|----------|-------|---------------------|
| **CRITICAL** | 🔴 Red left border | Immediate investigation. Likely active attack or severe misconfiguration. |
| **HIGH** | 🟠 Orange left border | Investigate within minutes. Potential active threat or policy violation. |
| **MEDIUM** | 🟡 Yellow left border | Investigate within the session. May indicate recon or misconfiguration. |
| **LOW** | 🔵 Cyan left border | Log and review. Informational or low-confidence signal. |

### Alert Card Fields

Each alert card shows:
- **Alert type** — machine-readable identifier (e.g., `DNS EXFILTRATION`)
- **Timestamp** — time the threshold was crossed
- **Message** — human-readable summary with quantified data (e.g., "58 DNS queries/min from 10.0.1.99")
- **Source IP** — the originating host that triggered the alert
- **MITRE ATT&CK ID** — the corresponding technique for threat intelligence correlation

### Toast Notifications

When a new alert fires, a toast notification slides in from the top-right of the screen (visible across all panels). CRITICAL alerts have a red glow. Toasts auto-dismiss after 5 seconds. Clicking a toast opens the Alert Detail Modal directly.

### Clicking an Alert

Opens the **Alert Detail Modal** with full technical detail and remediation recommendation. See [Section 7](#7-packet--alert-detail-modals).

---

## 7. Packet & Alert Detail Modals

### Packet Detail Modal

Opened by clicking any row in the packet table. Displays:

| Field | Description |
|-------|-------------|
| Source / Destination | Full IP:port for both ends |
| Protocol + Service | Protocol badge plus service name (e.g., `TCP` + `HTTPS`) |
| Category | Service category (`web`, `admin`, `infra`, `database`, `email`, `file`) |
| Size | Exact byte count |
| TTL | IP Time-to-Live (useful for OS fingerprinting and detecting TTL manipulation) |
| TCP Flags | Decoded flag string |
| Latency | RTT if this is a response packet |
| Timestamp | Full ISO-8601 timestamp |
| Info | Complete tcpdump info string |

### Alert Detail Modal

Opened by clicking any alert card or toast notification. Displays:

| Field | Description |
|-------|-------------|
| Severity | Color-coded severity badge |
| Source IP | The host that triggered the alert |
| Time | Exact alert timestamp |
| Alert ID | Unique identifier for incident reporting |
| Description | Plain-language explanation of what was detected |
| Technical Detail | Expanded technical context for the analyst |
| Recommendation | Specific actionable remediation steps |
| MITRE ATT&CK | Technique ID and name for threat intelligence workflows |

---

## 8. Export Tools

### JSON Incident Report (`↓ Report` button)

Downloads a structured JSON file covering the full current session. Use this to document incidents, share findings with other team members, or feed into a SIEM.

**Report structure:**

```json
{
  "generated_at": "2026-03-14T09:22:11",
  "tool": "NetMirror v1.0",
  "session": {
    "id": "A3BX92KL",
    "interface": "eth0",
    "filter": "not port 22",
    "mode": "live",
    "packets_analyzed": 14822,
    "duration_seconds": 312.4
  },
  "summary": { ... },
  "alerts": [ ... ],
  "top_talkers": [ ... ],
  "protocol_distribution": { "TCP": 8420, "DNS": 2100, ... },
  "latency_analysis": {
    "DNS":   { "avg_ms": 18.4, "max_ms": 210.0, "min_ms": 2.1 },
    "HTTPS": { "avg_ms": 42.3, "max_ms": 890.0, "min_ms": 8.2 }
  },
  "recommendations": [ ... ]
}
```

**Recommendations section** — auto-generated based on observed alerts and traffic patterns:
- DNS filtering/RPZ zones if `DNS_EXFILTRATION` fired
- Dynamic ARP Inspection if `ARP_SCAN` fired
- SYN cookie enablement if `SYN_FLOOD` fired
- HTTPS enforcement if significant plain HTTP traffic detected

### PCAP Download (Live Mode only)

Available via the API endpoint: `GET /api/export/pcap/<session_id>`

The session ID is shown in the status bar during an active capture and in the stop response. The PCAP file is a standard libpcap format file openable in Wireshark, tshark, or any packet analysis tool.

**Use cases:**
- Deep-dive analysis in Wireshark after initial triage in NetMirror
- Evidence preservation for security incidents
- Offline protocol analysis with Wireshark dissectors
- Feeding into automated analysis pipelines

**Example workflow:**
```bash
# While capture is running, note the session ID from the status bar (e.g., A3BX92KL)
# After stopping, download via curl:
curl -o incident.pcap http://localhost:5000/api/export/pcap/A3BX92KL
# Open in Wireshark:
wireshark incident.pcap
```

---

## 9. BPF Filter Reference

BPF (Berkeley Packet Filter) expressions are entered in the filter input in the header and passed directly to tcpdump. They are evaluated in-kernel — only matching packets reach NetMirror's parser.

> **Important:** Filters apply to live capture only. In Demo Mode, the filter field is accepted but ignored (simulated traffic is generated independently).

### Basic Syntax

```bash
# By host
host 192.168.1.100                # all traffic to or from this IP
src host 10.0.1.55                # only traffic FROM this IP
dst host 8.8.8.8                  # only traffic TO this IP

# By network
net 10.0.0.0/8                    # entire 10.x.x.x range
src net 192.168.1.0/24            # from this subnet

# By port
port 443                          # HTTPS (both directions)
dst port 53                       # outbound DNS queries only
src port 80                       # responses from HTTP servers
portrange 8000-9000               # any port in this range

# By protocol
tcp                               # TCP only
udp                               # UDP only
icmp                              # ICMP only
arp                               # ARP only

# Combinations (and / or / not)
tcp and port 443                  # HTTPS specifically
host 10.0.1.1 and not port 22     # all traffic from host except SSH
src net 10.0.0.0/8 and dst net not 10.0.0.0/8  # outbound from LAN
tcp and (port 80 or port 443)     # both HTTP and HTTPS

# Packet size
greater 1000                      # packets larger than 1000 bytes
less 100                          # small packets (useful for spotting scans)
```

### Recommended Filters for Common Use Cases

| Scenario | Filter |
|----------|--------|
| Focus on one application server | `host 10.0.1.25 and (port 80 or port 443 or port 8080)` |
| DNS analysis only | `port 53` |
| Exclude SSH management traffic | `not port 22` |
| Watch for unencrypted web traffic | `tcp and port 80` |
| Database traffic investigation | `port 3306 or port 5432 or port 27017` |
| Capture only LAN-internal traffic | `src net 10.0.0.0/8 and dst net 10.0.0.0/8` |
| Monitor all outbound connections | `src net 192.168.0.0/16 and dst net not 192.168.0.0/16` |
| Catch large transfers | `greater 1400` |
| SYN-only (new connections) | `tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0` |
| ARP only | `arp` |
| Exclude noisy multicast | `not (dst net 224.0.0.0/4 or dst net 255.255.255.255)` |

---

## 10. Anomaly Detection Engine

The engine runs on every packet regardless of display filters. It uses 60-second rolling windows per source IP. Each alert fires once per threshold crossing and includes a MITRE ATT&CK mapping.

### Detection Rules

#### DNS_EXFILTRATION — HIGH
**Trigger:** More than 50 DNS queries per minute from a single source IP.

**Logic:** DNS queries (dst port 53) from each source IP are timestamped and stored in a rolling 60s window. When the count exceeds 50, an alert fires.

**Why it matters:** Normal hosts generate 5–15 DNS queries per minute. Malware using DNS tunneling (e.g., `iodine`, `dnscat2`) generates hundreds per minute, encoding data in subdomain labels. Compromised hosts running beaconing C2 may also show elevated DNS rates.

**False positive sources:** Corporate DNS resolvers, recursive resolvers on the network, or mass-resolving applications (CDN pre-fetchers). Adjust the threshold for resolver IPs.

#### ARP_SCAN — CRITICAL
**Trigger:** More than 30 ARP requests per minute from a single source MAC/IP.

**Logic:** ARP packets from each source are timestamped in a rolling 60s window. Threshold crossing fires the alert.

**Why it matters:** ARP is a Layer 2 broadcast protocol used to discover MAC addresses for known IPs. Tools like `arp-scan`, `nmap -sn`, and custom scripts sweep entire subnets in seconds by sending rapid ARP requests. An attacker performing ARP cache poisoning for a Man-in-the-Middle attack also floods the segment with gratuitous ARPs.

**False positive sources:** Network monitoring tools, some DHCP servers, switch MAC learning after topology changes.

#### SYN_FLOOD — CRITICAL
**Trigger:** More than 100 TCP SYN packets per minute from a single source IP.

**Logic:** Packets with the SYN flag set and ACK flag absent (pure SYN, not SYN-ACK) are counted per source in a 60s window.

**Why it matters:** TCP SYN flood attacks exhaust connection tables on servers by sending thousands of SYN packets without completing the three-way handshake, consuming server resources for each half-open connection.

**False positive sources:** Load testing tools (`ab`, `wrk`, `vegeta`), fast port scanners (`nmap -T5`), or clients making many short-lived connections to the same server.

#### PORT_SCAN — HIGH
**Trigger:** A single source IP sends SYN packets to more than 20 unique destination ports.

**Logic:** The set of destination ports probed by each source is tracked. When the set size exceeds 20, an alert fires and the set resets.

**Why it matters:** Port scanning is a standard reconnaissance technique preceding exploitation. Tools like `nmap`, `masscan`, and `zmap` sweep thousands of ports per second.

**False positive sources:** Vulnerability scanners (Nessus, OpenVAS, Qualys) running authorized scans. Allowlist their source IPs or run scans from a dedicated segment.

#### ICMP_FLOOD — MEDIUM
**Trigger:** More than 60 ICMP packets per minute from a single source IP.

**Logic:** All ICMP packets (echo request, echo reply, unreachable, etc.) from each source are counted in a 60s window.

**Why it matters:** ICMP floods (`ping -f`) can saturate bandwidth or CPU on small devices. High ICMP rates can also indicate network mapping tools using ICMP sweeps.

**False positive sources:** Network monitoring systems running continuous ping health checks. Use a BPF filter to exclude known monitoring IPs, or raise the threshold.

#### DATA_EXFILTRATION — HIGH
**Trigger:** A single source IP sends more than 10MB to a single external (non-RFC-1918) IP within the session.

**Logic:** Outbound byte counts are accumulated per source IP to non-private destinations. When a source exceeds 10MB to any one external IP, the alert fires and the counter resets for that source.

**Why it matters:** Legitimate user traffic rarely involves bulk transfers to a single external IP outside of cloud storage services. Unexpected large transfers to unfamiliar IPs warrant investigation for data exfiltration.

**False positive sources:** Cloud backup agents (S3, Backblaze), large file uploads, software update downloads. Correlate the destination IP against known-good services.

---

## 11. Latency Correlation Engine

The latency engine pairs request and response packets in real time to compute RTT without any application-level instrumentation.

### How It Works

Three independent trackers, each thread-safe under a shared lock:

**DNS (dns_query_tracker)**
- Key: `(client_ip, server_ip, client_src_port)`
- Register on: outbound packet where `dst_port == 53`
- Resolve on: inbound packet where `src_port == 53` with matching reversed key
- RTT = resolve timestamp − register timestamp

**TCP Handshake (tcp_syn_tracker)**
- Key: `(src_ip, dst_ip, dst_port)`
- Register on: `flags == 'S'` (pure SYN)
- Resolve on: `'S' in flags and 'A' in flags` (SYN-ACK), matching reversed key
- RTT = SYN-ACK arrival − SYN departure

**HTTP/HTTPS (http_req_tracker)**
- Key: `(client_ip, server_ip, server_port)`
- Register on: PSH flag to port 80, 443, 8080, or 8443
- Resolve on: PSH flag back from the same port
- RTT = first response PSH − first request PSH (approximates time-to-first-byte)

**Stale entry eviction:** Any unmatched request entry older than 10 seconds is purged on the next packet arrival for that tracker, preventing unbounded memory growth.

### Interpreting Latency Values

- Latency column shows `—` for request packets (they register state, no RTT yet available)
- Latency column shows a colored value for response packets
- The Protocol Latency sidebar shows a rolling average of the last 20 measured RTTs per service
- The AVG LATENCY KPI is the mean across all services with at least one measurement

---

## 12. Deriving Actionable Insight

### 12.1 Slow Application Triage Workflow

When a user reports "the application is slow," follow this sequence:

**Step 1 — Capture focused traffic**
Use the interface the application server is on. Apply a BPF filter targeting that server:
```
host <app-server-ip> and (port 80 or port 443 or port <app-port>)
```

**Step 2 — Read the Protocol Latency panel**

- Is **DNS latency** elevated (>50ms)? → The client is slow to resolve the server hostname. Every request incurs this penalty. Fix: check resolver health, consider local caching DNS.
- Is **TCP latency** elevated but DNS is normal? → Network path issue between client and server. Investigate switches, routing, or server connection queue.
- Is **HTTP/HTTPS latency** elevated while TCP is fast? → Server accepts connections quickly but is slow to generate responses. This is an **application-layer problem** (CPU, slow queries, thread starvation) — not a network problem. Redirect the investigation to the application team.

**Step 3 — Examine Top Conversations**

Is the application server in the top conversations? If yes, is another conversation consuming more bandwidth? A competing bulk transfer could be saturating the link.

**Step 4 — Check the Alerts panel**

Any `SYN_FLOOD` or `PORT_SCAN` alerts directed at the application server indicate it may be under attack, which can cause apparent slowness.

**Step 5 — Export the PCAP**

If the above doesn't identify the root cause, stop the capture, download the PCAP, and open it in Wireshark. Filter by the server IP and look at TCP retransmissions (`tcp.analysis.retransmission`), zero-window events (`tcp.analysis.zero_window`), and RST packets as deeper indicators.

---

### 12.2 Security Investigation Workflow

When an alert fires:

**Step 1 — Click the alert card**

Read the Technical Detail and note the source IP. Check the MITRE ATT&CK ID to understand what technique is being used.

**Step 2 — Search for the IP in the packet table**

Type the source IP into the IP/Info search box. Review what other protocols this host is generating. A host doing ARP scans AND port scans AND generating DNS bursts is a strong indicator of active compromise.

**Step 3 — Correlate with Top Conversations**

Is the suspect IP in the top conversations? If it's also generating high outbound bytes to an external IP, the `DATA_EXFILTRATION` alert should have fired as well — check if it did.

**Step 4 — Examine the Protocol Mix**

Is the suspect IP's protocol profile unusual compared to neighboring hosts? (Filter by its IP and observe the chart shift.)

**Step 5 — Export the report**

Click `↓ Report`. The JSON report will contain all alerts, the top talkers list, and auto-generated recommendations specific to the alert types observed. Use this as the basis for an incident ticket.

**Step 6 — Preserve the PCAP**

Download the session PCAP for chain-of-custody evidence and deeper forensic analysis. PCAP files contain full packet payloads which may contain the actual exfiltrated content or malware command-and-control traffic.

---

### 12.3 Baseline & Capacity Planning

Run NetMirror in **Demo Mode** first to understand the interface, then run 30–60 minute live sessions during typical business hours:

- **Protocol Mix** — document what the normal distribution looks like. Any future deviation is immediately visible.
- **Packets/s KPI** — establish normal range. Configure alerts (or simply monitor) for sustained values outside that range.
- **Top Conversations** — identify which hosts are legitimate high-bandwidth users (backup agents, file servers, video conferencing). These should appear consistently and not trip the `DATA_EXFILTRATION` threshold with a threshold adjustment.
- **Latency baselines** — normal DNS latency for your resolver, normal TCP handshake time to your key servers. Any degradation from baseline is a leading indicator of problems before users notice.

---

### 12.4 Reading the Protocol Mix

| Observation | Likely cause | Action |
|-------------|-------------|--------|
| ARP > 5% | Subnet too large, or ARP scan in progress | Check with ARP_SCAN alert; consider subnetting |
| DNS > 20% | DNS tunnel, recursive resolver on segment, or CDN pre-fetching | Correlate with DNS_EXFILTRATION alert |
| HTTP (unencrypted) visible at all | Legacy application or misconfiguration | Identify source via Top Conversations; enforce HTTPS |
| FTP visible | File transfer using cleartext protocol | Identify hosts; migrate to SFTP |
| Telnet visible | Remote management using cleartext | Immediate remediation — replace with SSH |
| NetBIOS/SMB dominant | Windows file share traffic normal for LAN | Investigate if unexpected on non-Windows segments |
| ICMP > 5% | Monitoring sweeps or ping flood | Check ICMP_FLOOD alert; identify monitoring source |

---

### 12.5 Top Conversations Analysis

| Observation | Likely cause | Action |
|-------------|-------------|--------|
| Unknown external IP at #1 | Possible exfiltration, unauthorized cloud sync | Cross-reference IP with threat intel; check DATA_EXFILTRATION alert |
| Internal IP sending to many different destinations | Lateral movement or worm spreading | Correlate with PORT_SCAN alert; isolate host |
| Expected server not appearing | Service may be down | Check with ping/connectivity test |
| Backup server at #1 during business hours | Backup job misconfigured | Reschedule backup to off-hours |
| Single user workstation at #1 | Large download, video call, or data exfil | Identify application via port; investigate if unexpected |

---

### 12.6 Alert Triage Decision Tree

```
Alert fires
    │
    ├── CRITICAL (ARP_SCAN or SYN_FLOOD)
    │       │
    │       ├── SYN_FLOOD: Is the source IP external?
    │       │       Yes → Upstream DDoS mitigation, block at perimeter firewall
    │       │       No  → Internal host compromised or misconfigured; isolate
    │       │
    │       └── ARP_SCAN: Is the source IP a known scanner (Nessus/OpenVAS)?
    │               Yes → Authorized scan; add to allowlist; raise threshold
    │               No  → Potential MitM positioning; isolate immediately
    │
    ├── HIGH (DNS_EXFILTRATION, PORT_SCAN, DATA_EXFILTRATION)
    │       │
    │       ├── DNS_EXFILTRATION: Are queries going to many different domains?
    │       │       Yes → DNS tunneling or C2 beaconing; block & investigate host
    │       │       No  → Resolver misconfiguration; check DNS settings
    │       │
    │       ├── PORT_SCAN: Is source IP internal or external?
    │       │       External → Block at firewall; log for threat intel
    │       │       Internal → Authorized scanner? If no, investigate for compromise
    │       │
    │       └── DATA_EXFILTRATION: Is destination IP a known cloud service?
    │               Yes → Authorized backup/sync? If not, block and investigate
    │               No  → High-priority incident; preserve PCAP; escalate
    │
    └── MEDIUM (ICMP_FLOOD)
            │
            └── Is source a known monitoring system?
                    Yes → Raise threshold for that IP
                    No  → Investigate; may be reconnaissance precursor
```

---

## 13. Threshold Tuning

Default thresholds are conservative for general-purpose use. Edit the `THRESHOLDS` dict at the top of `app.py` to match your environment:

```python
THRESHOLDS = {
    'dns_requests_per_minute': 50,      # Lower for strict environments; raise for resolvers
    'arp_requests_per_minute': 30,      # Raise if running network scanners routinely
    'syn_per_minute': 100,              # Raise for high-traffic web servers
    'port_scan_unique_ports': 20,       # Lower to catch slower scans
    'icmp_per_minute': 60,              # Raise if ICMP monitoring is standard practice
    'large_transfer_mb': 10,            # Raise if cloud backups run frequently
}
```

Also adjust `LATENCY_TIMEOUT` (default: 10 seconds) if you are analyzing high-latency WAN links where request-response pairs may take longer to complete:

```python
LATENCY_TIMEOUT = 30.0   # Increase for satellite or high-latency WAN analysis
```

---

## 14. API Reference

All endpoints are available while the application is running. Use them to integrate NetMirror data into scripts, SIEMs, or dashboards.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Dashboard UI |
| `GET` | `/api/interfaces` | List available network interfaces |
| `POST` | `/api/start` | Start a capture session |
| `POST` | `/api/stop` | Stop the active capture session |
| `GET` | `/api/packets` | Fetch packet history (query params: `limit`, `protocol`, `src`) |
| `GET` | `/api/alerts` | Fetch security alerts (query param: `limit`) |
| `GET` | `/api/stats` | Live session statistics |
| `GET` | `/api/stats/latency` | Per-service latency data with avg/min/max/p95 |
| `POST` | `/api/export/report` | Download JSON incident report |
| `GET` | `/api/export/pcap/<session_id>` | Download PCAP file for a session |

### Start Capture Request Body

```json
{
  "interface": "eth0",
  "filter": "not port 22 and not port 5000",
  "mode": "live"
}
```

### WebSocket Events

| Event (server→client) | Payload | Description |
|-----------------------|---------|-------------|
| `packet` | `{packet: {...}, stats: {...}}` | Every captured packet with updated stats |
| `alert` | `{type, severity, src, message, ...}` | Security alert as it fires |
| `status` | `{capture_active, session_id, mode}` | Connection status on WebSocket connect |
| `stats_update` | Same as `/api/stats` | Periodic stats push (every 2s) |

| Event (client→server) | Payload | Description |
|-----------------------|---------|-------------|
| `request_history` | `{limit: N}` | Request last N packets from history |
| `ping_stats` | (none) | Request immediate stats update |

---

## 15. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `ModuleNotFoundError: No module named 'flask'` | sudo uses system Python, not venv | Use `sudo /path/to/venv/bin/python3 app.py` |
| Live Mode starts but shows no packets | tcpdump not capturing (permissions) | Verify with `sudo tcpdump -i eth0 -c 5`. Grant `cap_net_raw` or use sudo. |
| Interface dropdown shows only `any` | `/proc/net/dev` read error | Run `cat /proc/net/dev` to verify; should show interface list |
| Protocol Latency panel empty | No request-response pairs observed | Latency requires both directions. Ensure capture is on the right interface; check BPF filter isn't blocking responses |
| All latency values show `—` | Filter is one-directional | Remove `src` or `dst` qualifiers from BPF filter so both request and response packets are captured |
| PCAP download returns 404 | Session ID mismatch or Demo Mode | PCAP files only exist in Live Mode. Note session ID from status bar before stopping. |
| Alerts firing immediately on start | Demo Mode anomaly injection | Normal. Demo Mode injects bursts every ~200 ticks for training purposes. |
| Very high Packets/s but table is slow | Browser rendering limit hit | Enable "Pause display" or apply a protocol filter chip to reduce table row count |
| DNS latency not appearing | DNS traffic not traversing capture interface | Check: is DNS traffic going out a different interface? Try `interface: any` |
| `sudo: python: command not found` | Python 3 installed as `python3` only | Use `python3` not `python`. Python 2 is end-of-life. |
