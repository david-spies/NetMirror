# NetMirror — Tech Stack

## Overview

NetMirror is a single-machine, single-file Python web application. The architecture is intentionally lean: one `app.py` process handles packet capture (via subprocess), real-time analysis (in-process threads), WebSocket push to the browser, and REST API endpoints — all without a database or external message broker.

---

## Backend

### Runtime
| Component | Version | Role |
|-----------|---------|------|
| **Python** | 3.10+ | Application runtime |
| **Flask** | 3.x | HTTP server, REST API, HTML template rendering |
| **Flask-SocketIO** | 5.x | WebSocket layer over Flask for real-time push |
| **eventlet** | 0.x | Async concurrency driver for Flask-SocketIO (monkey-patches stdlib) |

### Packet Capture
| Component | Role |
|-----------|------|
| **tcpdump** (system binary) | Primary capture engine. Spawned as two subprocesses: one for line-buffered human-readable text output parsed in real time, one for silent binary PCAP writing to disk |
| **subprocess** (stdlib) | Process management for tcpdump instances |
| **threading** (stdlib) | Background threads for the tcpdump reader loop and demo simulator |

### Analysis Engine (Pure Python, stdlib only)
| Module | Role |
|--------|------|
| **re** | Regex parsing of tcpdump `-tttt` text output; TCP flag extraction; packet length extraction |
| **collections.defaultdict / deque** | Ring-buffer packet history (maxlen=5000), per-IP anomaly rate tracking, protocol statistics |
| **ipaddress** | RFC-1918 private address detection for data exfiltration alerts |
| **socket** (stdlib) | `inet_aton()` used in IP address validation during `src.port` dot-notation splitting |
| **time / threading.Lock** | Latency correlation engine — thread-safe request/response pairing for DNS, TCP SYN→SYN-ACK, and HTTP PSH→PSH RTT measurement |

### Data Flow
```
tcpdump (text proc) ──► parse_tcpdump_output() ──► compute_latency()
                                                          │
                                                    process_packet()
                                                    ├── proto_stats
                                                    ├── ip_conversation_stats
                                                    ├── latency_tracker
                                                    ├── check_anomalies()
                                                    │     └── anomaly_tracker['alerts']
                                                    └── socketio.emit('packet', ...)
                                                                │
                                                          Browser (WS)

tcpdump (pcap proc) ──► captures/session_<ID>.pcap  (binary, download on demand)
```

---

## Frontend

### Rendering
| Component | Source | Role |
|-----------|--------|------|
| **Jinja2** | Flask built-in | Server-side template rendering for `index.html` (interface list injection) |
| **Vanilla JS (ES2020)** | Inline in template | All UI logic — no build step, no npm |
| **Socket.IO client** | cdnjs.cloudflare.com v4.7.2 | WebSocket client matching Flask-SocketIO server |
| **Chart.js** | cdnjs.cloudflare.com v4.4.1 | Protocol doughnut chart and 60-second traffic rate timeline |

### Fonts
| Font | Provider | Use |
|------|----------|-----|
| **Share Tech Mono** | Google Fonts | Packet table, KPI values, labels — monospace for aligned data |
| **Barlow Condensed** | Google Fonts | Panel headers, button labels, modal titles |
| **Barlow** | Google Fonts | Body copy, alert messages, descriptions |

### CSS Architecture
- CSS custom properties (variables) for the full dark-terminal color palette
- No preprocessor, no framework — raw CSS with `grid` and `flexbox` layout
- Scanline overlay via `repeating-linear-gradient` pseudo-element on `body`
- Per-protocol color coding via `.proto-*` badge classes
- Severity-based left-border coloring on alert items (critical/high/medium/low)

---

## Concurrency Model

```
Main thread (Flask + eventlet)
    │
    ├── HTTP request handlers  (REST API routes)
    ├── WebSocket event handlers  (connect, ping_stats, request_history)
    │
    └── Background threads (daemon=True, die with main process):
          ├── parse_tcpdump_output()   — reads tcpdump stdout line by line
          └── run_simulation()         — demo mode packet generator
                └── inject_anomaly_burst()  — periodic threat injection
```

eventlet's monkey-patching makes all stdlib I/O cooperative, allowing the Flask dev server to handle WebSocket connections and HTTP requests concurrently without a multi-worker setup.

---

## Storage

| Location | Content | Lifetime |
|----------|---------|---------|
| `captures/session_<ID>.pcap` | Raw binary PCAP from tcpdump `-w` process | Persists on disk until manually deleted |
| `reports/report_<ID>.json` | JSON incident report generated on demand | Persists on disk until manually deleted |
| In-memory `packet_history` deque | Last 5,000 parsed packet dicts | Cleared on each new capture session start |
| In-memory `anomaly_tracker` dicts | Rolling 60s rate windows per source IP | Cleared on each new capture session start |
| In-memory `latency_tracker` | Per-service RTT sample lists (last 100) | Cleared on each new capture session start |

No database. No external cache. All state lives in Python process memory between sessions.

---

## Security Posture of the Tool Itself

- Flask `SECRET_KEY` is a static string — suitable for single-machine use only; rotate if exposing to a network
- `cors_allowed_origins='*'` in SocketIO — restrict this if binding to `0.0.0.0` on a shared network
- tcpdump requires `CAP_NET_RAW` — grant via `setcap` rather than running the full process as root where possible
- No authentication layer — NetMirror is designed for trusted analyst workstations, not public-facing deployment
- PCAP files on disk contain full packet payloads — treat the `captures/` directory as sensitive

---

## Tested Environments

| OS | Python | tcpdump | Notes |
|----|--------|---------|-------|
| Ubuntu 22.04 / 24.04 | 3.10 – 3.12 | 4.99.x | Primary development target |
| Debian 12 | 3.11 | 4.99.x | Confirmed working |
| macOS 13+ | 3.11 (Homebrew) | system tcpdump | Interface names differ (`en0`, `lo0`) |
| WSL2 (Ubuntu) | 3.10+ | 4.99.x | Requires `sudo`; WSL2 network interface visible as `eth0` |

---

## External Dependencies Summary

```
Runtime (pip):
  flask
  flask-socketio
  eventlet

System (apt / brew):
  tcpdump

Browser (CDN, no install):
  socket.io    4.7.2   (cdnjs.cloudflare.com)
  chart.js     4.4.1   (cdnjs.cloudflare.com)
  Google Fonts (Share Tech Mono, Barlow, Barlow Condensed)
```
