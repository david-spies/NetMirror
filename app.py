#!/usr/bin/env python3
"""
NetMirror - Lightweight Packet Triage & Network Traffic Analysis
A web-based wrapper for tcpdump/tshark with real-time anomaly detection.
"""

import os
import sys
import json
import time
import threading
import subprocess
import re
import random
import string
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path
import ipaddress

from flask import Flask, render_template, request, jsonify, send_file, abort
from flask_socketio import SocketIO, emit

# ─── App Setup ────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = 'netmirror-secret-2024'
app.config['CAPTURE_DIR'] = Path('captures')
app.config['REPORT_DIR'] = Path('reports')
app.config['MAX_PACKET_HISTORY'] = 5000

socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins='*')

# ─── Global State ─────────────────────────────────────────────────────────────
capture_state = {
    'active': False,
    'process': None,
    'interface': 'any',
    'filter': '',
    'start_time': None,
    'packet_count': 0,
    'session_id': None,
}

# In-memory packet store (ring buffer)
packet_history = deque(maxlen=5000)

# Anomaly tracking
anomaly_tracker = {
    'dns_requests': defaultdict(list),       # ip -> [timestamps]
    'arp_requests': defaultdict(list),        # ip -> [timestamps]
    'syn_floods': defaultdict(list),          # ip -> [timestamps]
    'port_scans': defaultdict(set),           # ip -> {ports}
    'large_transfers': defaultdict(int),      # ip -> bytes
    'http_errors': defaultdict(list),         # ip -> [timestamps]
    'icmp_floods': defaultdict(list),         # ip -> [timestamps]
    'alerts': deque(maxlen=500),
}

# Protocol stats
proto_stats = defaultdict(int)
ip_conversation_stats = defaultdict(lambda: {'bytes': 0, 'packets': 0, 'last_seen': 0})
latency_tracker = defaultdict(list)  # ip -> [latency_ms]
dns_query_tracker = {}  # query_id -> timestamp for latency calc

# ─── Latency Correlation Engine ──────────────────────────────────────────────
# Tracks in-flight requests so response packets can compute RTT.
#
# dns_query_tracker  : { (src_ip, dst_ip, id_port) -> epoch_float }
#   Keyed by (client_ip, server_ip, src_port) for DNS; matched on the
#   reverse 5-tuple when the reply arrives.
#
# tcp_syn_tracker    : { (src_ip, dst_ip, dst_port) -> epoch_float }
#   Keyed on the SYN; resolved when SYN-ACK arrives on the reverse tuple.
#
# http_req_tracker   : { (src_ip, dst_ip, dst_port) -> epoch_float }
#   Keyed on the first PSH carrying request data; resolved on first PSH reply.
#
# Entries older than LATENCY_TIMEOUT seconds are evicted to prevent unbounded growth.

LATENCY_TIMEOUT = 10.0   # seconds — drop unmatched requests after this

_lat_lock = threading.Lock()
dns_query_tracker  = {}   # (client_ip, server_ip, src_port)  -> timestamp
tcp_syn_tracker    = {}   # (src_ip,    dst_ip,    dst_port)  -> timestamp
http_req_tracker   = {}   # (src_ip,    dst_ip,    dst_port)  -> timestamp


def _evict_stale(tracker: dict, now: float):
    """Remove entries older than LATENCY_TIMEOUT. Called under _lat_lock."""
    stale = [k for k, v in tracker.items() if now - v > LATENCY_TIMEOUT]
    for k in stale:
        del tracker[k]


def compute_latency(pkt: dict) -> float | None:
    """
    Given a parsed packet dict, attempt to match it against a pending
    request and return the RTT in milliseconds.  Returns None when no
    match is found (i.e. the packet is itself a request, or untrackable).

    Side-effect: registers request packets so future response packets
    can be matched against them.
    """
    now   = time.time()
    proto = pkt.get('protocol', '')
    flags = pkt.get('flags', '')
    sip   = pkt.get('src_ip', '')
    dip   = pkt.get('dst_ip', '')
    sp    = pkt.get('src_port', 0)
    dp    = pkt.get('dst_port', 0)

    with _lat_lock:

        # ── DNS  ──────────────────────────────────────────────────────────────
        # Request:  client(sp) -> server:53
        # Response: server:53  -> client(dp)
        if proto == 'DNS':
            _evict_stale(dns_query_tracker, now)
            if dp == 53:
                # Outbound query — register it
                dns_query_tracker[(sip, dip, sp)] = now
                return None
            elif sp == 53:
                # Inbound reply — look for matching query
                key = (dip, sip, dp)   # reverse: original client was dip, server was sip
                if key in dns_query_tracker:
                    rtt = (now - dns_query_tracker.pop(key)) * 1000
                    return round(rtt, 2)

        # ── TCP handshake (SYN → SYN-ACK) ────────────────────────────────────
        # SYN:     client -> server  flags='S'
        # SYN-ACK: server -> client  flags='SA' or 'S.'
        if proto == 'TCP':
            _evict_stale(tcp_syn_tracker, now)
            if flags == 'S':
                # Pure SYN — register
                tcp_syn_tracker[(sip, dip, dp)] = now
                return None
            if 'S' in flags and 'A' in flags:
                # SYN-ACK — look for matching SYN (note: src/dst reversed)
                key = (dip, sip, sp)
                if key in tcp_syn_tracker:
                    rtt = (now - tcp_syn_tracker.pop(key)) * 1000
                    return round(rtt, 2)

        # ── HTTP / HTTPS PSH request → PSH response ───────────────────────────
        # First PSH from client to port 80/443 registers the request time.
        # First PSH back from server resolves it.
        if proto in ('TCP', 'HTTP', 'HTTPS') and 'P' in flags:
            _evict_stale(http_req_tracker, now)
            if dp in (80, 443, 8080, 8443):
                # Client request PSH
                key = (sip, dip, dp)
                if key not in http_req_tracker:
                    http_req_tracker[key] = now
                return None
            elif sp in (80, 443, 8080, 8443):
                # Server response PSH
                key = (dip, sip, sp)
                if key in http_req_tracker:
                    rtt = (now - http_req_tracker.pop(key)) * 1000
                    return round(rtt, 2)

    return None


# Session PCAP snippets
pcap_sessions = {}  # session_id -> {metadata, filepath}

# ─── Anomaly Thresholds ───────────────────────────────────────────────────────
THRESHOLDS = {
    'dns_requests_per_minute': 50,      # >50 DNS/min = potential exfil
    'arp_requests_per_minute': 30,      # >30 ARP/min = potential MitM scan
    'syn_per_minute': 100,              # SYN flood threshold
    'port_scan_unique_ports': 20,       # Unique ports in 60s = port scan
    'icmp_per_minute': 60,              # ICMP flood
    'large_transfer_mb': 10,            # 10MB+ to single external IP
}

SEVERITY = {
    'CRITICAL': '🔴',
    'HIGH': '🟠',
    'MEDIUM': '🟡',
    'LOW': '🔵',
    'INFO': '⚪',
}

# ─── Demo / Simulation Mode ───────────────────────────────────────────────────
DEMO_PROTOCOLS = ['TCP', 'UDP', 'DNS', 'HTTP', 'HTTPS', 'ARP', 'ICMP', 'TLS', 'SSH', 'FTP']
DEMO_IPS_INTERNAL = ['10.0.1.{}'.format(i) for i in range(1, 20)]
DEMO_IPS_EXTERNAL = ['52.{}.{}.{}'.format(random.randint(1,255), random.randint(1,255), random.randint(1,255)) for _ in range(10)]
DEMO_PORTS = {'HTTP': 80, 'HTTPS': 443, 'DNS': 53, 'SSH': 22, 'FTP': 21, 'SMTP': 25, 'RDP': 3389}

simulation_thread = None
simulation_active = False


def generate_session_id():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))


def get_interfaces():
    """Get available network interfaces using /proc/net/dev (always available on Linux)."""
    interfaces = []
    try:
        with open('/proc/net/dev') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    iface = line.split(':')[0].strip()
                    if iface:
                        interfaces.append(iface)
    except Exception:
        pass

    # Always offer 'any' first as a catch-all
    if 'any' not in interfaces:
        interfaces.insert(0, 'any')
    else:
        interfaces.remove('any')
        interfaces.insert(0, 'any')

    # Fall back if somehow empty
    if len(interfaces) <= 1:
        interfaces = ['any', 'eth0', 'lo', 'ens3', 'wlan0', 'docker0']

    return interfaces


def classify_traffic(proto, src_port, dst_port, flags='', payload_size=0):
    """Classify and enrich traffic metadata."""
    service = 'Unknown'
    category = 'other'

    port_map = {
        80: ('HTTP', 'web'), 443: ('HTTPS', 'web'), 8080: ('HTTP-Alt', 'web'),
        8443: ('HTTPS-Alt', 'web'), 22: ('SSH', 'admin'), 23: ('Telnet', 'admin'),
        3389: ('RDP', 'admin'), 53: ('DNS', 'infra'), 67: ('DHCP', 'infra'),
        68: ('DHCP', 'infra'), 123: ('NTP', 'infra'), 25: ('SMTP', 'email'),
        587: ('SMTP-S', 'email'), 993: ('IMAPS', 'email'), 995: ('POP3S', 'email'),
        21: ('FTP', 'file'), 20: ('FTP-Data', 'file'), 445: ('SMB', 'file'),
        139: ('NetBIOS', 'file'), 3306: ('MySQL', 'database'), 5432: ('PostgreSQL', 'database'),
        27017: ('MongoDB', 'database'), 6379: ('Redis', 'database'),
        2181: ('Zookeeper', 'messaging'), 5672: ('AMQP', 'messaging'),
        9200: ('Elasticsearch', 'search'),
    }

    for port in [dst_port, src_port]:
        if port in port_map:
            service, category = port_map[port]
            break

    if proto == 'ARP':
        service, category = 'ARP', 'infra'
    elif proto == 'ICMP':
        service, category = 'ICMP', 'infra'
    elif proto == 'DNS':
        service, category = 'DNS', 'infra'

    return service, category


def check_anomalies(packet):
    """Run anomaly detection on a packet. Returns list of alerts."""
    alerts = []
    now = time.time()
    src = packet.get('src_ip', '')
    dst = packet.get('dst_ip', '')
    proto = packet.get('protocol', '')
    service = packet.get('service', '')
    size = packet.get('size', 0)
    flags = packet.get('flags', '')

    window = 60  # 60-second rolling window

    # ── DNS Exfiltration Detection ─────────────────────────────────────────
    if proto == 'DNS' or service == 'DNS':
        anomaly_tracker['dns_requests'][src].append(now)
        # Clean old entries
        anomaly_tracker['dns_requests'][src] = [
            t for t in anomaly_tracker['dns_requests'][src] if now - t < window
        ]
        count = len(anomaly_tracker['dns_requests'][src])
        if count > THRESHOLDS['dns_requests_per_minute']:
            alerts.append({
                'type': 'DNS_EXFILTRATION',
                'severity': 'HIGH',
                'src': src,
                'message': f'Potential DNS data exfiltration: {count} DNS queries/min from {src}',
                'detail': 'High-volume DNS queries may indicate covert channel or data exfiltration via DNS tunneling.',
                'recommendation': 'Inspect DNS query contents for base64/hex encoding. Consider blocking or rate-limiting.',
                'timestamp': now,
                'mitre': 'T1071.004 - Application Layer Protocol: DNS',
            })

    # ── ARP Scanning / MitM Detection ─────────────────────────────────────
    if proto == 'ARP':
        anomaly_tracker['arp_requests'][src].append(now)
        anomaly_tracker['arp_requests'][src] = [
            t for t in anomaly_tracker['arp_requests'][src] if now - t < window
        ]
        count = len(anomaly_tracker['arp_requests'][src])
        if count > THRESHOLDS['arp_requests_per_minute']:
            alerts.append({
                'type': 'ARP_SCAN',
                'severity': 'CRITICAL',
                'src': src,
                'message': f'ARP sweep/scan detected: {count} ARP requests/min from {src}',
                'detail': 'Rapid ARP requests from a single host indicates network reconnaissance or MitM positioning attempt.',
                'recommendation': 'Verify MAC/IP bindings. Enable Dynamic ARP Inspection (DAI). Isolate suspect host.',
                'timestamp': now,
                'mitre': 'T1018 - Remote System Discovery / T1557.002 - ARP Cache Poisoning',
            })

    # ── SYN Flood Detection ────────────────────────────────────────────────
    if 'S' in flags and 'A' not in flags:
        anomaly_tracker['syn_floods'][src].append(now)
        anomaly_tracker['syn_floods'][src] = [
            t for t in anomaly_tracker['syn_floods'][src] if now - t < window
        ]
        count = len(anomaly_tracker['syn_floods'][src])
        if count > THRESHOLDS['syn_per_minute']:
            alerts.append({
                'type': 'SYN_FLOOD',
                'severity': 'CRITICAL',
                'src': src,
                'message': f'SYN flood attack: {count} SYN packets/min from {src}',
                'detail': 'Excessive SYN packets without completing handshake indicates DoS/DDoS attempt.',
                'recommendation': 'Enable SYN cookies. Rate-limit SYN packets. Consider upstream filtering.',
                'timestamp': now,
                'mitre': 'T1499 - Endpoint Denial of Service',
            })

    # ── Port Scan Detection ────────────────────────────────────────────────
    dst_port = packet.get('dst_port', 0)
    if dst_port and proto == 'TCP' and 'S' in flags:
        anomaly_tracker['port_scans'][src].add(dst_port)
        # Clean by time is harder without timestamps per port; check size
        if len(anomaly_tracker['port_scans'][src]) > THRESHOLDS['port_scan_unique_ports']:
            alerts.append({
                'type': 'PORT_SCAN',
                'severity': 'HIGH',
                'src': src,
                'message': f'Port scan detected: {src} probed {len(anomaly_tracker["port_scans"][src])} unique ports',
                'detail': f'Host {src} is scanning multiple ports on network hosts.',
                'recommendation': 'Block source IP. Enable IDS port-scan detection rules.',
                'timestamp': now,
                'mitre': 'T1046 - Network Service Scanning',
            })
            anomaly_tracker['port_scans'][src] = set()  # Reset after alert

    # ── ICMP Flood ─────────────────────────────────────────────────────────
    if proto == 'ICMP':
        anomaly_tracker['icmp_floods'][src].append(now)
        anomaly_tracker['icmp_floods'][src] = [
            t for t in anomaly_tracker['icmp_floods'][src] if now - t < window
        ]
        count = len(anomaly_tracker['icmp_floods'][src])
        if count > THRESHOLDS['icmp_per_minute']:
            alerts.append({
                'type': 'ICMP_FLOOD',
                'severity': 'MEDIUM',
                'src': src,
                'message': f'ICMP flood: {count} ICMP packets/min from {src}',
                'detail': 'High ICMP rate may indicate ping flood or network recon.',
                'recommendation': 'Rate-limit ICMP. Block if not operationally required.',
                'timestamp': now,
                'mitre': 'T1499.002 - Service Exhaustion Flood',
            })

    # ── Large Data Transfer to External IP ────────────────────────────────
    try:
        dst_addr = ipaddress.ip_address(dst) if dst else None
        if dst_addr and not dst_addr.is_private:
            anomaly_tracker['large_transfers'][src] += size
            mb = anomaly_tracker['large_transfers'][src] / (1024 * 1024)
            if mb > THRESHOLDS['large_transfer_mb']:
                alerts.append({
                    'type': 'DATA_EXFILTRATION',
                    'severity': 'HIGH',
                    'src': src,
                    'message': f'Large data transfer: {mb:.1f}MB from {src} to external {dst}',
                    'detail': 'Unusual volume of data sent to external destination.',
                    'recommendation': 'Review data leaving network. Check for unauthorized cloud uploads or exfil.',
                    'timestamp': now,
                    'mitre': 'T1048 - Exfiltration Over Alternative Protocol',
                })
                anomaly_tracker['large_transfers'][src] = 0  # Reset
    except ValueError:
        pass

    return alerts


def simulate_packet():
    """Generate a realistic simulated packet for demo mode."""
    now = time.time()

    # Occasionally inject anomalous traffic
    inject_anomaly = random.random() < 0.03  # 3% anomaly rate

    if inject_anomaly:
        anomaly_type = random.choice(['dns_burst', 'arp_sweep', 'syn_flood', 'port_scan'])
        if anomaly_type == 'dns_burst':
            return {
                'id': int(now * 1000),
                'timestamp': datetime.now().isoformat(),
                'src_ip': '10.0.1.99',
                'dst_ip': '8.8.8.8',
                'src_port': random.randint(40000, 65535),
                'dst_port': 53,
                'protocol': 'DNS',
                'service': 'DNS',
                'category': 'infra',
                'size': random.randint(60, 120),
                'flags': '',
                'ttl': 64,
                'info': f'Query: {random_subdomain()}.evil-domain.com A',
                'latency_ms': None,
            }
        elif anomaly_type == 'arp_sweep':
            target_ip = f'10.0.1.{random.randint(1, 254)}'
            return {
                'id': int(now * 1000),
                'timestamp': datetime.now().isoformat(),
                'src_ip': '10.0.1.55',
                'dst_ip': target_ip,
                'src_port': 0,
                'dst_port': 0,
                'protocol': 'ARP',
                'service': 'ARP',
                'category': 'infra',
                'size': 42,
                'flags': '',
                'ttl': 0,
                'info': f'Who has {target_ip}? Tell 10.0.1.55',
                'latency_ms': None,
            }

    # Normal traffic
    proto = random.choices(
        DEMO_PROTOCOLS,
        weights=[25, 8, 15, 20, 15, 3, 2, 8, 2, 1],
        k=1
    )[0]

    src = random.choice(DEMO_IPS_INTERNAL)
    dst = random.choice(DEMO_IPS_INTERNAL + DEMO_IPS_EXTERNAL[:3])

    port_map = {'HTTP': 80, 'HTTPS': 443, 'DNS': 53, 'SSH': 22, 'FTP': 21}
    dst_port = port_map.get(proto, random.choice([80, 443, 8080, 3306, 5432, 22, 25]))
    src_port = random.randint(32768, 60999)

    size = random.randint(60, 1500)
    if proto in ['HTTPS', 'TLS']:
        size = random.randint(500, 1460)
    elif proto == 'DNS':
        size = random.randint(60, 200)
    elif proto == 'ARP':
        size = 42

    flags = ''
    if proto == 'TCP':
        flags = random.choice(['S', 'SA', 'A', 'PA', 'FA', 'R'])

    latency = None
    if proto in ['DNS', 'HTTP', 'HTTPS']:
        latency = round(random.gauss(25, 15), 2)
        if latency < 1:
            latency = 1.0

    service, category = classify_traffic(proto, src_port, dst_port)

    infos = {
        'DNS': f'Query: {random.choice(["google.com", "api.stripe.com", "s3.amazonaws.com", "github.com"])} A',
        'HTTP': f'GET /api/v2/{random.choice(["users", "data", "health", "metrics"])} HTTP/1.1',
        'HTTPS': f'TLS Application Data ({size} bytes)',
        'TCP': f'{src_port} → {dst_port} [{flags}] Seq=... Len={size}',
        'SSH': 'Encrypted packet',
        'ARP': f'Who has {dst}? Tell {src}',
        'ICMP': f'Echo (ping) request id=0x{random.randint(0, 65535):04x}',
    }

    return {
        'id': int(now * 1000) + random.randint(0, 999),
        'timestamp': datetime.now().isoformat(),
        'src_ip': src,
        'dst_ip': dst,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': proto,
        'service': service,
        'category': category,
        'size': size,
        'flags': flags,
        'ttl': random.choice([64, 128, 255]),
        'info': infos.get(proto, f'{proto} packet'),
        'latency_ms': latency,
    }


def random_subdomain():
    """Generate a suspicious-looking random subdomain (for DNS exfil simulation)."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(12, 32)))


def run_simulation():
    """Background thread for demo simulation mode."""
    global simulation_active
    burst_counter = 0

    while simulation_active and capture_state['active']:
        # Variable packet rate to simulate real traffic
        packets_per_tick = random.choices([1, 2, 3, 5, 8], weights=[30, 30, 20, 15, 5], k=1)[0]

        for _ in range(packets_per_tick):
            if not simulation_active or not capture_state['active']:
                break

            pkt = simulate_packet()
            process_packet(pkt)

        # Occasionally inject a burst of anomalous packets
        burst_counter += 1
        if burst_counter % 200 == 0:
            inject_anomaly_burst()

        time.sleep(0.1)


def inject_anomaly_burst():
    """Inject a burst of anomalous packets to trigger alerts."""
    burst_type = random.choice(['dns', 'arp', 'syn'])
    count = random.randint(40, 80)
    attacker_ip = f'10.0.1.{random.randint(100, 150)}'

    for i in range(count):
        if burst_type == 'dns':
            pkt = {
                'id': int(time.time() * 1000) + i,
                'timestamp': datetime.now().isoformat(),
                'src_ip': attacker_ip,
                'dst_ip': '8.8.8.8',
                'src_port': random.randint(40000, 65535),
                'dst_port': 53,
                'protocol': 'DNS',
                'service': 'DNS',
                'category': 'infra',
                'size': random.randint(60, 180),
                'flags': '',
                'ttl': 64,
                'info': f'Query: {random_subdomain()}.exfil-domain.net TXT',
                'latency_ms': round(random.gauss(5, 2), 2),
            }
        elif burst_type == 'arp':
            pkt = {
                'id': int(time.time() * 1000) + i,
                'timestamp': datetime.now().isoformat(),
                'src_ip': attacker_ip,
                'dst_ip': f'10.0.1.{i % 254 + 1}',
                'src_port': 0,
                'dst_port': 0,
                'protocol': 'ARP',
                'service': 'ARP',
                'category': 'infra',
                'size': 42,
                'flags': '',
                'ttl': 0,
                'info': f'Who has 10.0.1.{i % 254 + 1}? Tell {attacker_ip}',
                'latency_ms': None,
            }
        else:  # SYN
            pkt = {
                'id': int(time.time() * 1000) + i,
                'timestamp': datetime.now().isoformat(),
                'src_ip': f'{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}',
                'dst_ip': '10.0.1.1',
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 22, 3389]),
                'protocol': 'TCP',
                'service': 'TCP',
                'category': 'other',
                'size': 60,
                'flags': 'S',
                'ttl': random.randint(1, 64),
                'info': 'TCP SYN (potential flood)',
                'latency_ms': None,
            }

        process_packet(pkt)
        time.sleep(0.01)


def process_packet(pkt):
    """Process a packet: store, update stats, check anomalies, emit via WS."""
    global packet_history, proto_stats, ip_conversation_stats

    # Store in history
    packet_history.append(pkt)
    capture_state['packet_count'] += 1

    # Update protocol stats
    proto_stats[pkt['protocol']] += 1

    # Update conversation stats
    conv_key = f"{pkt['src_ip']}→{pkt['dst_ip']}"
    ip_conversation_stats[conv_key]['bytes'] += pkt['size']
    ip_conversation_stats[conv_key]['packets'] += 1
    ip_conversation_stats[conv_key]['last_seen'] = time.time()

    # Latency tracking
    if pkt.get('latency_ms'):
        latency_tracker[pkt['service']].append(pkt['latency_ms'])
        if len(latency_tracker[pkt['service']]) > 100:
            latency_tracker[pkt['service']].pop(0)

    # Anomaly detection
    alerts = check_anomalies(pkt)
    for alert in alerts:
        alert['id'] = f"ALT-{int(time.time() * 1000)}"
        anomaly_tracker['alerts'].appendleft(alert)
        socketio.emit('alert', alert)

    # Emit packet to frontend
    socketio.emit('packet', {
        'packet': pkt,
        'stats': get_live_stats(),
    })


def get_live_stats():
    """Return current live statistics."""
    now = time.time()

    # Top protocols
    top_proto = dict(sorted(proto_stats.items(), key=lambda x: x[1], reverse=True)[:8])

    # Top conversations (last 30s)
    top_convs = sorted(
        [(k, v) for k, v in ip_conversation_stats.items()
         if now - v['last_seen'] < 30],
        key=lambda x: x[1]['bytes'],
        reverse=True
    )[:10]

    # Latency averages
    avg_latency = {}
    for svc, lats in latency_tracker.items():
        if lats:
            avg_latency[svc] = round(sum(lats[-20:]) / len(lats[-20:]), 2)

    return {
        'packet_count': capture_state['packet_count'],
        'protocols': top_proto,
        'top_conversations': [
            {'conv': k, 'bytes': v['bytes'], 'packets': v['packets']}
            for k, v in top_convs
        ],
        'avg_latency': avg_latency,
        'alert_count': len(anomaly_tracker['alerts']),
        'uptime': round(time.time() - capture_state['start_time'], 1) if capture_state['start_time'] else 0,
    }


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    interfaces = get_interfaces()
    return render_template('index.html', interfaces=interfaces)


@app.route('/api/interfaces')
def api_interfaces():
    return jsonify({'interfaces': get_interfaces()})


@app.route('/api/start', methods=['POST'])
def api_start():
    global simulation_thread, simulation_active

    data = request.get_json() or {}
    interface = data.get('interface', 'any')
    pkt_filter = data.get('filter', '')
    mode = data.get('mode', 'demo')  # 'demo' or 'live'

    if capture_state['active']:
        return jsonify({'error': 'Capture already active'}), 400

    session_id = generate_session_id()
    capture_state.update({
        'active': True,
        'interface': interface,
        'filter': pkt_filter,
        'start_time': time.time(),
        'packet_count': 0,
        'session_id': session_id,
        'mode': mode,
    })

    # Reset stats
    proto_stats.clear()
    ip_conversation_stats.clear()
    latency_tracker.clear()
    anomaly_tracker['alerts'].clear()
    for key in ['dns_requests', 'arp_requests', 'syn_floods', 'port_scans', 'large_transfers', 'icmp_floods']:
        anomaly_tracker[key].clear()

    if mode == 'demo':
        simulation_active = True
        simulation_thread = threading.Thread(target=run_simulation, daemon=True)
        simulation_thread.start()
        return jsonify({'status': 'started', 'session_id': session_id, 'mode': 'demo'})
    else:
        # Live capture via tcpdump
        return start_live_capture(interface, pkt_filter, session_id)


def start_live_capture(interface, pkt_filter, session_id):
    """Attempt live capture with tcpdump.

    Two separate processes are used:
      1. TEXT proc  - stdout parsed line-by-line for real-time UI display.
      2. PCAP proc  - silent binary write to disk (using -w).
    This is required because -w suppresses ALL human-readable stdout,
    making the text and PCAP captures mutually exclusive on one process.
    """
    pcap_path = app.config['CAPTURE_DIR'] / f'session_{session_id}.pcap'

    filter_args = pkt_filter.split() if pkt_filter else []

    # Process 1: line-buffered text output for real-time parsing
    text_cmd = ['tcpdump', '-i', interface, '-n', '-l', '-tttt', '-s', '512'] + filter_args
    # Process 2: raw PCAP write to disk (no stdout needed)
    pcap_cmd  = ['tcpdump', '-i', interface, '-n', '-s', '0', '-w', str(pcap_path)] + filter_args

    try:
        text_proc = subprocess.Popen(
            text_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,  # suppress "listening on…" banner to stdout
            text=True,
            bufsize=1,                  # line-buffered so readline() returns promptly
        )
        pcap_proc = subprocess.Popen(
            pcap_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        capture_state['process'] = text_proc
        capture_state['pcap_process'] = pcap_proc

        pcap_sessions[session_id] = {
            'filepath': str(pcap_path),
            'start': datetime.now().isoformat(),
            'interface': interface,
            'filter': pkt_filter,
        }

        t = threading.Thread(target=parse_tcpdump_output, args=(text_proc, session_id), daemon=True)
        t.start()

        return jsonify({'status': 'started', 'session_id': session_id, 'mode': 'live'})

    except FileNotFoundError:
        capture_state['mode'] = 'demo'
        global simulation_active, simulation_thread
        simulation_active = True
        simulation_thread = threading.Thread(target=run_simulation, daemon=True)
        simulation_thread.start()
        return jsonify({
            'status': 'started',
            'session_id': session_id,
            'mode': 'demo',
            'warning': 'tcpdump not found – install with: sudo apt install tcpdump',
        })


import socket as _socket

def _parse_tcpdump_addr(addr):
    """Split 'a.b.c.d.PORT' → (ip, port).  Returns (addr, 0) when no port present.

    tcpdump uses dot-notation for ports: '10.4.24.68.58414'.
    Strategy: split on last dot; if candidate IP has exactly 3 dots and is
    valid, treat the tail as the port.  Otherwise the whole string is the IP.
    """
    parts = addr.rsplit('.', 1)
    if len(parts) == 2 and parts[1].isdigit():
        port = int(parts[1])
        candidate = parts[0]
        if candidate.count('.') == 3:
            try:
                _socket.inet_aton(candidate)
                return candidate, port
            except OSError:
                pass
    return addr, 0


# Real tcpdump -tttt output on Linux 'any' interface includes the interface
# name and direction token between the timestamp and the IP keyword:
#   "2026-03-13 07:30:43.002 eth0 In  IP 10.0.0.1.443 > 10.0.0.2.54321: ..."
# On a physical interface (no 'any') the iface+direction tokens are absent:
#   "2026-03-13 07:30:43.002 IP 10.0.0.1.443 > 10.0.0.2.54321: ..."
# The pattern below handles both forms with optional non-capturing groups.
_TCPDUMP_PATTERN = re.compile(
    r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)'   # timestamp
    r'\s+(?:\S+\s+)?'                                  # optional iface name
    r'(?:In\s+|Out\s+)?'                               # optional direction
    r'IP(?:6)?\s+'                                     # IP or IP6 keyword
    r'(\S+)\s+>\s+(\S+):\s*(.*)'                       # src > dst: info
)

def parse_tcpdump_output(proc, session_id):
    """Parse tcpdump human-readable text output and push packets to the UI."""
    while capture_state['active'] and proc.poll() is None:
        line = proc.stdout.readline()
        if not line:
            continue

        m = _TCPDUMP_PATTERN.match(line.strip())
        if not m:
            continue

        ts, raw_src, raw_dst, info = m.groups()

        src_ip, src_port = _parse_tcpdump_addr(raw_src)
        dst_ip, dst_port = _parse_tcpdump_addr(raw_dst)

        # Protocol detection from info string
        if dst_port == 53 or src_port == 53:
            proto = 'DNS'
        elif 'ICMP' in info or 'icmp' in info:
            proto = 'ICMP'
        elif 'UDP' in info or 'udp' in info:
            proto = 'UDP'
        elif 'ARP' in info or 'arp' in info:
            proto = 'ARP'
        else:
            proto = 'TCP'

        service, category = classify_traffic(proto, src_port, dst_port)

        flags = ''
        flag_match = re.search(r'Flags \[([^\]]+)\]', info)
        if flag_match:
            flags = flag_match.group(1)

        size = 0
        len_match = re.search(r'\blength (\d+)', info)
        if len_match:
            size = int(len_match.group(1))

        pkt = {
            'id': int(time.time() * 1000) + random.randint(0, 999),
            'timestamp': ts,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': proto,
            'service': service,
            'category': category,
            'size': max(size, 42),
            'flags': flags,
            'ttl': 0,
            'info': info[:120],
            'latency_ms': None,
        }

        # ── Latency correlation ───────────────────────────────────────────────
        # Registers requests; returns RTT ms for matching response packets.
        pkt['latency_ms'] = compute_latency(pkt)

        process_packet(pkt)


@app.route('/api/stop', methods=['POST'])
def api_stop():
    global simulation_active

    if not capture_state['active']:
        return jsonify({'error': 'No active capture'}), 400

    simulation_active = False
    capture_state['active'] = False

    for key in ('process', 'pcap_process'):
        proc = capture_state.get(key)
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass
        capture_state[key] = None

    return jsonify({
        'status': 'stopped',
        'session_id': capture_state['session_id'],
        'packets_captured': capture_state['packet_count'],
        'duration': round(time.time() - capture_state['start_time'], 1) if capture_state['start_time'] else 0,
    })


@app.route('/api/packets')
def api_packets():
    limit = int(request.args.get('limit', 200))
    protocol = request.args.get('protocol', '')
    src_filter = request.args.get('src', '')
    severity = request.args.get('severity', '')

    pkts = list(packet_history)[-limit:]

    if protocol:
        pkts = [p for p in pkts if p['protocol'].upper() == protocol.upper()]
    if src_filter:
        pkts = [p for p in pkts if src_filter in p['src_ip'] or src_filter in p['dst_ip']]

    return jsonify({'packets': pkts, 'total': len(packet_history)})


@app.route('/api/alerts')
def api_alerts():
    limit = int(request.args.get('limit', 100))
    alerts = list(anomaly_tracker['alerts'])[:limit]
    return jsonify({'alerts': alerts, 'total': len(alerts)})


@app.route('/api/stats')
def api_stats():
    return jsonify(get_live_stats())


@app.route('/api/stats/latency')
def api_latency_stats():
    result = {}
    for svc, lats in latency_tracker.items():
        if lats:
            recent = lats[-50:]
            result[svc] = {
                'avg': round(sum(recent) / len(recent), 2),
                'min': round(min(recent), 2),
                'max': round(max(recent), 2),
                'p95': round(sorted(recent)[int(len(recent) * 0.95)], 2) if len(recent) >= 5 else round(max(recent), 2),
                'samples': recent[-20:],
            }
    return jsonify(result)


@app.route('/api/export/pcap/<session_id>')
def export_pcap(session_id):
    """Export PCAP snippet for a session."""
    if session_id in pcap_sessions:
        filepath = pcap_sessions[session_id]['filepath']
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True,
                           download_name=f'netmirror_{session_id}.pcap')
    abort(404)


@app.route('/api/export/report', methods=['POST'])
def export_report():
    """Generate a JSON incident report."""
    data = request.get_json() or {}
    
    report = {
        'generated_at': datetime.now().isoformat(),
        'tool': 'NetMirror v1.0',
        'session': {
            'id': capture_state.get('session_id', 'N/A'),
            'interface': capture_state.get('interface', 'N/A'),
            'filter': capture_state.get('filter', 'N/A'),
            'mode': capture_state.get('mode', 'demo'),
            'packets_analyzed': capture_state['packet_count'],
            'duration_seconds': round(time.time() - capture_state['start_time'], 1) if capture_state['start_time'] else 0,
        },
        'summary': get_live_stats(),
        'alerts': list(anomaly_tracker['alerts']),
        'top_talkers': [
            {'conversation': k, **v}
            for k, v in sorted(ip_conversation_stats.items(),
                               key=lambda x: x[1]['bytes'], reverse=True)[:20]
        ],
        'protocol_distribution': dict(proto_stats),
        'latency_analysis': {
            svc: {
                'avg_ms': round(sum(lats) / len(lats), 2),
                'max_ms': round(max(lats), 2),
                'min_ms': round(min(lats), 2),
            }
            for svc, lats in latency_tracker.items() if lats
        },
        'recommendations': generate_recommendations(),
    }

    report_path = app.config['REPORT_DIR'] / f'report_{capture_state.get("session_id", "unknown")}.json'
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    return send_file(report_path, as_attachment=True,
                   download_name=f'netmirror_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json',
                   mimetype='application/json')


def generate_recommendations():
    """Generate actionable recommendations based on observed traffic."""
    recs = []
    alerts = list(anomaly_tracker['alerts'])

    alert_types = {a['type'] for a in alerts}

    if 'DNS_EXFILTRATION' in alert_types:
        recs.append({
            'priority': 'HIGH',
            'category': 'DNS Security',
            'action': 'Implement DNS filtering and monitoring. Consider DNS-over-HTTPS or RPZ zones.',
            'affected': [a['src'] for a in alerts if a['type'] == 'DNS_EXFILTRATION'],
        })

    if 'ARP_SCAN' in alert_types:
        recs.append({
            'priority': 'CRITICAL',
            'category': 'Layer 2 Security',
            'action': 'Enable Dynamic ARP Inspection. Deploy 802.1X port authentication.',
            'affected': [a['src'] for a in alerts if a['type'] == 'ARP_SCAN'],
        })

    if 'SYN_FLOOD' in alert_types:
        recs.append({
            'priority': 'CRITICAL',
            'category': 'DDoS Mitigation',
            'action': 'Enable SYN cookies on all servers. Configure rate limiting at perimeter.',
            'affected': [a['src'] for a in alerts if a['type'] == 'SYN_FLOOD'],
        })

    if 'PORT_SCAN' in alert_types:
        recs.append({
            'priority': 'HIGH',
            'category': 'Intrusion Detection',
            'action': 'Block scanning source IPs. Review firewall ingress rules.',
            'affected': [a['src'] for a in alerts if a['type'] == 'PORT_SCAN'],
        })

    # Check for unencrypted services
    if proto_stats.get('HTTP', 0) > proto_stats.get('HTTPS', 0) * 0.1:
        recs.append({
            'priority': 'MEDIUM',
            'category': 'Encryption',
            'action': 'Significant plain HTTP traffic detected. Enforce HTTPS everywhere.',
            'affected': [],
        })

    return recs


# ─── WebSocket Events ─────────────────────────────────────────────────────────

@socketio.on('connect')
def on_connect():
    emit('status', {
        'capture_active': capture_state['active'],
        'session_id': capture_state.get('session_id'),
        'mode': capture_state.get('mode', 'idle'),
    })


@socketio.on('request_history')
def on_request_history(data):
    limit = data.get('limit', 100)
    pkts = list(packet_history)[-limit:]
    emit('history', {'packets': pkts, 'stats': get_live_stats()})


@socketio.on('ping_stats')
def on_ping_stats():
    emit('stats_update', get_live_stats())


if __name__ == '__main__':
    os.makedirs('captures', exist_ok=True)
    os.makedirs('reports', exist_ok=True)
    print("\n" + "="*60)
    print("  NetMirror - Lightweight Packet Triage")
    print("  http://localhost:5000")
    print("="*60 + "\n")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
