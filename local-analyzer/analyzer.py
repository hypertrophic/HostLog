#!/usr/bin/env python3
# ============================================================
#  ANALYZER.PY — HostLog Local Log Analyzer
#  Place your downloaded logs in the folder defined in
#  config.json under "logs_base_path", then run:
#      python analyzer.py
#  A markdown report will be saved in the reports/ folder.
# ============================================================

import os
import re
import json
import glob
from pathlib import Path
import ipaddress
from typing import List, Tuple, Dict, Set, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

# Optional progress bar support
try:
    from tqdm import tqdm
except ImportError:
    tqdm = lambda x, **kwargs: x

# ─── LOAD CONFIG ────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).parent.absolute()

try:
    with open(SCRIPT_DIR / 'config.json', 'r') as f:
        config = json.load(f)
except (FileNotFoundError, json.JSONDecodeError) as e:
    print(f"Error: Could not load config.json: {e}")
    exit(1)

LOGS_BASE_PATH          = SCRIPT_DIR / config['logs_base_path']
DOMAIN_MAP              = config['domain_map']
THRESHOLDS              = config['thresholds']
LOGIN_PATHS             = [p.lower() for p in config['login_paths']]
SENSITIVE_PATHS         = [p.lower() for p in config['sensitive_paths']]
WORDPRESS_INTERNAL      = [p.lower() for p in config.get('wordpress_internal_paths', [])]
SHELL_PROBE_PATHS       = [p.lower() for p in config.get('shell_probe_paths', [])]
EXPOSURE_PATHS          = [p.lower() for p in config.get('exposure_paths', [])]
XMLRPC_PATHS            = [p.lower() for p in config.get('xmlrpc_paths', [])]
USER_ENUM_PATHS         = [p.lower() for p in config.get('user_enumeration_paths', [])]

HOSTING_NETWORKS = []
for p in config.get('hosting_ipv6_prefixes', []):
    # Ensure common shorthand like '2a02:4780:' is handled as a prefix
    p_clean = p
    if p.endswith(':') and '/' not in p:
        p_clean = p.rstrip(':') + '::/32'
    
    try:
        HOSTING_NETWORKS.append(ipaddress.ip_network(p_clean, strict=False))
    except ValueError:
        print(f"Warning: Invalid hosting IP network configuration: {p}")

SUSPICIOUS_UA           = [ua.lower() for ua in config['suspicious_user_agents']]
ALLOWED_METHODS         = [m.upper() for m in config['allowed_methods']]
WHITELIST_IPS           = set(config['whitelist']['ips'])
WHITELIST_PATHS         = [p.lower() for p in config['whitelist']['paths']]
WHITELIST_UA            = [ua.lower() for ua in config['whitelist']['user_agents']]
PERSISTENT_IP_DAYS      = THRESHOLDS.get('persistent_ip_days', 3)
XMLRPC_THRESHOLD        = THRESHOLDS.get('xmlrpc_posts_per_session', 5)
DISTRIBUTED_SCAN_WINDOW = THRESHOLDS.get('distributed_scan_window_minutes', 60)
DISTRIBUTED_SCAN_MIN    = THRESHOLDS.get('distributed_scan_min_ips', 5)
ADMIN_UA_KEYWORDS       = ['mozilla', 'chrome', 'safari', 'firefox', 'edge']
ADMIN_PATH_PREFIX       = '/wp-admin/'

# ─── LOG LINE PARSER ────────────────────────────────────────

LOG_PATTERN = re.compile(
    r'^\[(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]'
    r'\s*\|\s*(?P<ip>[\d\.a-fA-F:]+)'
    r'\s*\|\s*(?P<method>[A-Z]+)\s+(?P<path>\S+)'
    r'\s*\|\s*Ref:(?P<referer>\S+)'
    r'\s*\|\s*UA:(?P<ua>.+?)(?:\s*\|\s*(?P<custom_key>\w+):(?P<custom_value>.+))?$'
)

def parse_line(line):
    line = line.strip()
    if not line:
        return None
    m = LOG_PATTERN.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group('timestamp'), '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return None
    return {
        'timestamp':    ts,
        'ip':           m.group('ip').strip(),
        'method':       m.group('method').strip().upper(),
        'path':         m.group('path').strip(),
        'referer':      m.group('referer').strip(),
        'ua':           m.group('ua').strip(),
        'custom_key':   m.group('custom_key').strip() if m.group('custom_key') else None,
        'custom_value': m.group('custom_value').strip() if m.group('custom_value') else None,
    }

# ─── LOAD LOGS ──────────────────────────────────────────────

def load_logs(folder_name):
    folder = LOGS_BASE_PATH / folder_name
    if not folder.is_dir():
        return
    files = sorted(folder.glob('access-*.log'))
    for filepath in files:
        with filepath.open('r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                entry = parse_line(line)
                if entry:
                    yield entry

# ─── IP CLASSIFICATION ──────────────────────────────────────

def is_whitelisted(entry):
    if entry['ip'] in WHITELIST_IPS:
        return True
    path_lower = entry['path'].lower()
    if any(path_lower.startswith(p) for p in WHITELIST_PATHS):
        return True
    ua_lower = entry['ua'].lower()
    if any(w in ua_lower for w in WHITELIST_UA):
        return True
    return False

# Cache for IP infrastructure checks to avoid repeated parsing overhead
INFRA_CACHE = {}

def is_hosting_infrastructure(ip_str):
    if ip_str in INFRA_CACHE:
        return INFRA_CACHE[ip_str]
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        res = any(ip_obj in net for net in HOSTING_NETWORKS if ip_obj.version == net.version)
        INFRA_CACHE[ip_str] = res
        return res
    except ValueError:
        return False

# ─── THREAT CLASSIFICATION ──────────────────────────────────

def classify_threat(reason):
    r = reason.lower()
    if 'shell' in r or 'backdoor' in r:
        return 'Shell / backdoor probe'
    if 'xmlrpc' in r:
        return 'XML-RPC abuse'
    if 'user enum' in r:
        return 'User enumeration'
    if 'exposure' in r or 'backup' in r:
        return 'Sensitive file exposure'
    if 'req/hour' in r:
        return 'DDoS indicator'
    if 'req/day' in r:
        return 'DoS indicator'
    if 'persistent' in r:
        return 'Persistent threat'
    if 'login' in r:
        return 'Brute force'
    if 'distributed' in r:
        return 'Distributed scan'
    if 'referer' in r:
        return 'Cross-site login attempt'
    if 'sensitive path' in r:
        return 'Reconnaissance / scan'
    if 'user agent' in r:
        return 'Automated scanner'
    if 'empty' in r and 'agent' in r:
        return 'Suspicious bot'
    if 'method' in r:
        return 'Probe'
    return 'Suspicious activity'

def alert_severity(threat):
    high   = ['Shell / backdoor probe', 'XML-RPC abuse', 'User enumeration', 'Brute force', 
              'DDoS indicator', 'Cross-site login attempt']
    medium = ['Distributed scan', 'Persistent threat', 'Sensitive file exposure', 'DoS indicator', 'Reconnaissance / scan']
    if threat in high:
        return 'HIGH'
    if threat in medium:
        return 'MEDIUM'
    return 'LOW'

# ─── ANALYZE ────────────────────────────────────────────────

@dataclass
class AnalysisResults:
    alerts: List[dict]
    flagged_entries: List[dict]
    ip_ranking: List[Tuple[str, int]]
    ip_total: Dict[str, int]
    ip_daily: Dict[str, Set[str]]
    ip_daily_counts: Dict[str, Dict[str, int]]
    custom_field_counts: Dict[str, Dict[str, int]]
    cf_min: Optional[datetime]
    cf_max: Optional[datetime]
    hosting_ips: Set[str]
    admin_ips: Set[str]
    total_count: int
    all_dates: List[str]

def analyze(entries, domain_name):
    """Performs a single-pass analysis of log entries."""
    alerts_list     = []
    flagged_entries = []

    ip_total        = defaultdict(int)
    ip_hourly       = defaultdict(lambda: defaultdict(int))
    ip_daily        = defaultdict(set)
    ip_login_hour   = defaultdict(lambda: defaultdict(int))
    ip_xmlrpc       = defaultdict(int)
    ip_user_enum    = defaultdict(list)

    # Optimized tracking for single-pass analysis
    ip_daily_counts      = defaultdict(lambda: defaultdict(int))
    ip_admin_hits        = defaultdict(int)
    ip_admin_unique_path = defaultdict(set)
    ip_admin_browser     = defaultdict(bool)
    all_days             = set()

    # Custom field
    custom_field_counts = defaultdict(lambda: defaultdict(int))
    custom_field_min_date = None
    custom_field_max_date = None

    # For distributed scan detection: minute bucket → set of IPs
    minute_bucket_ips   = defaultdict(set)
    minute_bucket_count = defaultdict(lambda: defaultdict(int))

    hosting_ips = set()
    admin_ips   = set()
    total_count = 0

    for e in entries:
        total_count += 1
        entry_flags = []
        ip = e['ip']

        if is_hosting_infrastructure(ip):
            hosting_ips.add(ip)
            continue

        if is_whitelisted(e):
            continue

        hour   = e['timestamp'].strftime('%Y-%m-%d %H')
        minute = e['timestamp'].strftime('%Y-%m-%d %H:%M')
        day    = e['timestamp'].strftime('%Y-%m-%d')
        path   = e['path'].lower()
        ua     = e['ua'].lower()
        referer= e['referer'].lower()
        method = e['method']

        ip_total[ip]        += 1
        ip_hourly[ip][hour] += 1
        ip_daily[ip].add(day)
        ip_daily_counts[ip][day] += 1
        all_days.add(day)

        if path.startswith(ADMIN_PATH_PREFIX):
            ip_admin_hits[ip] += 1
            ip_admin_unique_path[ip].add(path.split('?')[0])
            if any(kw in ua for kw in ADMIN_UA_KEYWORDS):
                ip_admin_browser[ip] = True

        minute_bucket_ips[minute].add(ip)
        minute_bucket_count[minute][ip] += 1

        if method == 'POST' and any(path.startswith(lp) for lp in LOGIN_PATHS):
            ip_login_hour[ip][hour] += 1
            # Flag if login attempt comes from an external domain or no referer
            if referer != '-' and domain_name.lower() not in referer:
                entry_flags.append('suspicious login referer')

        if method == 'POST' and any(path.startswith(xp) for xp in XMLRPC_PATHS):
            ip_xmlrpc[ip] += 1

        if any(path.startswith(up) for up in USER_ENUM_PATHS):
            ip_user_enum[ip].append(e['timestamp'])

        if e['custom_key'] and e['custom_value']:
            custom_field_counts[e['custom_key']][e['custom_value']] += 1
            ts = e['timestamp']
            if custom_field_min_date is None or ts < custom_field_min_date:
                custom_field_min_date = ts
            if custom_field_max_date is None or ts > custom_field_max_date:
                custom_field_max_date = ts

        # Shell / backdoor probe — highest priority
        if any(path.startswith(sp) for sp in SHELL_PROBE_PATHS):
            entry_flags.append('shell probe')

        # Exposure paths
        elif any(path.startswith(ep) for ep in EXPOSURE_PATHS):
            entry_flags.append('exposure path (backup/dump)')

        # WordPress internal — classify separately, don't flag as recon
        elif any(path.startswith(wp) for wp in WORDPRESS_INTERNAL):
            pass  # silently skip, classified as internal

        # Sensitive path
        elif any(path.startswith(sp) for sp in SENSITIVE_PATHS):
            entry_flags.append('sensitive path')

        # Suspicious user agent
        if ua == '' or ua == 'unknown':
            entry_flags.append('empty user agent')
        elif any(s in ua for s in SUSPICIOUS_UA):
            entry_flags.append('suspicious user agent')

        # Disallowed method
        if method not in ALLOWED_METHODS:
            entry_flags.append(f'disallowed method ({method})')

        # Cap flagged entries to 500 to prevent memory exhaustion on massive attacks
        if entry_flags and len(flagged_entries) < 500:
            flagged_entries.append({
                'entry':   e,
                'reasons': entry_flags,
                'threat':  classify_threat(', '.join(entry_flags))
            })

    # Finalize admin sessions
    for ip in ip_total:
        if (ip_admin_hits[ip] >= 3 and 
            ip_admin_browser[ip] and 
            len(ip_admin_unique_path[ip]) >= 3):
            admin_ips.add(ip)

    # Threshold alerts — req/hour
    for ip, hours in ip_hourly.items():
        if ip in admin_ips:
            continue
        for hour, count in hours.items():
            if count >= THRESHOLDS['requests_per_hour']:
                reason = f"{count} req/hour"
                alerts_list.append({'ip': ip, 'when': hour, 'count': count,
                                    'reason': reason, 'threat': classify_threat(reason),
                                    'severity': 'HIGH'})

    # Threshold alerts — req/day
    for ip, total in ip_total.items():
        if ip in admin_ips:
            continue
        if total >= THRESHOLDS['requests_per_day']:
            reason = f"{total} req/day"
            alerts_list.append({'ip': ip, 'when': 'all days', 'count': total,
                                'reason': reason, 'threat': classify_threat(reason),
                                'severity': 'HIGH'})

    # Persistent IP alerts
    for ip, days in ip_daily.items():
        if ip in admin_ips:
            continue
        if len(days) >= PERSISTENT_IP_DAYS:
            day_list = sorted(days)
            reason   = f"active across {len(days)} days ({day_list[0]} → {day_list[-1]})"
            alerts_list.append({'ip': ip, 'when': f"{day_list[0]} → {day_list[-1]}",
                                'count': ip_total[ip], 'reason': reason,
                                'threat': classify_threat('persistent'), 'severity': 'MEDIUM'})

    # Login brute force
    for ip, hours in ip_login_hour.items():
        for hour, count in hours.items():
            if count >= THRESHOLDS['login_posts_per_hour']:
                reason = f"{count} login POSTs in one hour"
                alerts_list.append({'ip': ip, 'when': hour, 'count': count,
                                    'reason': reason, 'threat': classify_threat(reason),
                                    'severity': 'HIGH'})

    # XML-RPC abuse
    for ip, count in ip_xmlrpc.items():
        if count >= XMLRPC_THRESHOLD:
            reason = f"{count} POST requests to xmlrpc.php"
            alerts_list.append({'ip': ip, 'when': 'session', 'count': count,
                                'reason': reason, 'threat': classify_threat('xmlrpc'),
                                'severity': 'HIGH'})

    # User enumeration → attack sequence
    for ip, timestamps in ip_user_enum.items():
        reason = f"probed user enumeration endpoint ({len(timestamps)}x)"
        severity = 'HIGH' if ip_xmlrpc.get(ip, 0) >= XMLRPC_THRESHOLD else 'MEDIUM'
        if ip_xmlrpc.get(ip, 0) >= XMLRPC_THRESHOLD:
            reason += ' followed by XML-RPC attack'
        alerts_list.append({'ip': ip, 'when': timestamps[0].strftime('%Y-%m-%d %H:%M'),
                            'count': len(timestamps), 'reason': reason,
                            'threat': classify_threat('user enum'), 'severity': severity})

    # Distributed scan detection
    # Group minutes where many different IPs sent similar request counts
    suspicious_windows = []
    for minute, ips in minute_bucket_ips.items():
        if len(ips) >= DISTRIBUTED_SCAN_MIN:
            counts = [minute_bucket_count[minute][ip] for ip in ips]
            avg    = sum(counts) / len(counts)
            # Check if counts are suspiciously uniform (all within 20% of average)
            uniform = all(abs(c - avg) / max(avg, 1) < 0.2 for c in counts)
            if uniform:
                suspicious_windows.append((minute, len(ips), list(ips)[:5]))

    if suspicious_windows:
        for minute, ip_count, sample_ips in suspicious_windows:
            reason = f"{ip_count} different IPs sent uniform request counts in 1-minute window"
            alerts_list.append({'ip': f"{ip_count} IPs (e.g. {sample_ips[0]}...)",
                                'when': minute, 'count': ip_count,
                                'reason': reason, 'threat': classify_threat('distributed'),
                                'severity': 'MEDIUM'})

    ip_ranking = sorted(ip_total.items(), key=lambda x: x[1], reverse=True)
    sorted_days = sorted(list(all_days))

    return AnalysisResults(
        alerts=alerts_list,
        flagged_entries=flagged_entries,
        ip_ranking=ip_ranking,
        ip_total=dict(ip_total),
        ip_daily=dict(ip_daily),
        ip_daily_counts=dict(ip_daily_counts),
        custom_field_counts=dict(custom_field_counts),
        cf_min=custom_field_min_date,
        cf_max=custom_field_max_date,
        hosting_ips=hosting_ips,
        admin_ips=admin_ips,
        total_count=total_count,
        all_dates=sorted_days
    )


# ─── REPORT GENERATOR ───────────────────────────────────────

def generate_report(domain, folder, alerts, flagged, ip_ranking, ip_total,
                    ip_daily, ip_daily_counts, custom_field_counts, cf_min, cf_max,
                    hosting_ips, admin_ips, total_count, all_dates):
    now   = datetime.now()
    lines = []
    date_range = f"{all_dates[0]} → {all_dates[-1]}" if all_dates else 'unknown'

    lines.append(f"# HostLog — Analysis Report")
    lines.append(f"")
    lines.append(f"**Domain:** `{domain}`  ")
    lines.append(f"**Folder:** `{folder}`  ")
    lines.append(f"**Log period:** {date_range}  ")
    lines.append(f"**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S')}  ")
    lines.append(f"**Total entries analyzed:** {total_count}  ")
    lines.append(f"")

    if hosting_ips:
        lines.append(f"> **Hosting infrastructure detected:** {len(hosting_ips)} IP(s) auto-classified "
                     f"as hosting infrastructure and excluded from analysis.")
        lines.append(f"")
    if admin_ips:
        lines.append(f"> **Admin sessions detected:** {len(admin_ips)} IP(s) identified as likely "
                     f"admin sessions (browser UA + multi-page `/wp-admin/` navigation) and excluded from alerts.")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"")

    # Alerts grouped by severity
    high_alerts   = [a for a in alerts if a.get('severity') == 'HIGH']
    medium_alerts = [a for a in alerts if a.get('severity') == 'MEDIUM']
    low_alerts    = [a for a in alerts if a.get('severity') == 'LOW']

    lines.append(f"## Alerts ({len(alerts)})")
    lines.append(f"")

    for severity, group in [('HIGH', high_alerts), ('MEDIUM', medium_alerts), ('LOW', low_alerts)]:
        if not group:
            continue
        lines.append(f"### {severity} ({len(group)})")
        lines.append(f"")
        lines.append(f"| IP | When | Count | Reason | Threat |")
        lines.append(f"|---|---|---|---|---|")
        for a in sorted(group, key=lambda x: x['count'], reverse=True):
            lines.append(f"| `{a['ip']}` | {a['when']} | {a['count']} | {a['reason']} | {a['threat']} |")
        lines.append(f"")

    if not alerts:
        lines.append(f"No alerts detected.")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"")

    # Persistent IPs
    persistent = {ip: days for ip, days in ip_daily.items() if len(days) >= PERSISTENT_IP_DAYS}
    lines.append(f"## Persistent IPs ({len(persistent)})")
    lines.append(f"")
    lines.append(f"> IPs seen across {PERSISTENT_IP_DAYS} or more distinct days. "
                 f"May indicate slow attacks that stay under hourly thresholds.")
    lines.append(f"")
    if not persistent:
        lines.append(f"No persistent IPs detected.")
    else:
        lines.append(f"| IP | Days active | First seen | Last seen | Total requests | Daily breakdown |")
        lines.append(f"|---|---|---|---|---|---|")
        for ip, days in sorted(persistent.items(), key=lambda x: len(x[1]), reverse=True):
            day_list  = sorted(days)
            counts    = [ip_daily_counts[ip].get(d, 0) for d in all_dates]
            sparkline = ' '.join(str(c) if c > 0 else '·' for c in counts)
            lines.append(
                f"| `{ip}` | {len(days)} | {day_list[0]} | {day_list[-1]} "
                f"| {ip_total[ip]} | {sparkline} |"
            )
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")

    # Flagged requests
    lines.append(f"## Flagged requests ({len(flagged)})")
    lines.append(f"")
    if not flagged:
        lines.append(f"No flagged requests detected.")
    else:
        lines.append(f"| Timestamp | IP | Method | Path | Threat | Reason |")
        lines.append(f"|---|---|---|---|---|---|")
        for f_ in flagged[:100]:
            e  = f_['entry']
            ts = e['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            lines.append(
                f"| {ts} | `{e['ip']}` | {e['method']} | `{e['path']}` "
                f"| {f_['threat']} | {', '.join(f_['reasons'])} |"
            )
        if len(flagged) > 100:
            lines.append(f"")
            lines.append(f"*{len(flagged) - 100} additional flagged entries not shown.*")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")

    # Top IPs with timeline
    lines.append(f"## Top IPs by request count")
    lines.append(f"")
    lines.append(f"| Rank | IP | Total | Days active | Classification | Daily requests ({' · '.join(all_dates)}) |")
    lines.append(f"|---|---|---|---|---|---|")
    for i, (ip, count) in enumerate(ip_ranking[:20], 1):
        days           = len(ip_daily.get(ip, set()))
        classification = ('Hosting infrastructure' if ip in hosting_ips
                          else 'Admin session' if ip in admin_ips
                          else '—')
        counts         = [ip_daily_counts[ip].get(d, 0) for d in all_dates]
        sparkline      = ' · '.join(str(c) for c in counts)
        lines.append(f"| {i} | `{ip}` | {count} | {days} | {classification} | {sparkline} |")
    if len(ip_ranking) > 20:
        lines.append(f"")
        lines.append(f"*{len(ip_ranking) - 20} additional IPs not shown.*")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")

    # Custom field section
    if custom_field_counts:
        for field_label, value_counts in custom_field_counts.items():
            ranked     = sorted(value_counts.items(), key=lambda x: x[1], reverse=True)
            date_range_cf = ''
            if cf_min and cf_max:
                date_range_cf = f"{cf_min.strftime('%Y-%m-%d')} → {cf_max.strftime('%Y-%m-%d')}"
            lines.append(f"## Custom field — {field_label} ({len(value_counts)} unique values)")
            lines.append(f"")
            if date_range_cf:
                lines.append(f"**Period covered:** {date_range_cf}  ")
            lines.append(f"**Total entries with this field:** {sum(value_counts.values())}  ")
            lines.append(f"**Unique values:** {len(value_counts)}  ")
            lines.append(f"")
            lines.append(f"| Rank | {field_label} | Scan count |")
            lines.append(f"|---|---|---|")
            for i, (val, count) in enumerate(ranked[:50], 1):
                lines.append(f"| {i} | `{val}` | {count} |")
            if len(ranked) > 50:
                lines.append(f"")
                lines.append(f"*{len(ranked) - 50} additional values not shown.*")
            lines.append(f"")
            lines.append(f"---")
            lines.append(f"")

    # Summary
    lines.append(f"## Summary")
    lines.append(f"")
    lines.append(f"- Log period: **{date_range}**")
    lines.append(f"- Total entries analyzed: **{total_count}**")
    lines.append(f"- Unique IPs seen: **{len(ip_total)}**")
    lines.append(f"- Hosting infrastructure IPs excluded: **{len(hosting_ips)}**")
    lines.append(f"- Admin session IPs excluded from alerts: **{len(admin_ips)}**")
    lines.append(f"- HIGH severity alerts: **{len(high_alerts)}**")
    lines.append(f"- MEDIUM severity alerts: **{len(medium_alerts)}**")
    lines.append(f"- LOW severity alerts: **{len(low_alerts)}**")
    lines.append(f"- Persistent IPs (active {PERSISTENT_IP_DAYS}+ days): **{len(persistent)}**")
    lines.append(f"- Flagged requests: **{len(flagged)}**")
    if custom_field_counts:
        for field_label, value_counts in custom_field_counts.items():
            lines.append(f"- Unique {field_label} values logged: **{len(value_counts)}**")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")
    lines.append(f"*Generated by [HostLog](https://github.com/hypertrophic/HostLog)*")

    return '\n'.join(lines)

# ─── SAVE REPORT ────────────────────────────────────────────

def save_report(domain_slug, content):
    reports_dir = SCRIPT_DIR / 'reports'
    reports_dir.mkdir(exist_ok=True)
    filename = f"report-{domain_slug}-{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.md"
    filepath = reports_dir / filename
    filepath.write_text(content, encoding='utf-8')
    return str(filepath)

def save_blocklist(domain_slug, alerts):
    high_ips = set()
    for a in alerts:
        if a.get('severity') == 'HIGH':
            try:
                ipaddress.ip_address(a['ip'])
                high_ips.add(a['ip'])
            except ValueError:
                pass
    if not high_ips:
        return None
    reports_dir = SCRIPT_DIR / 'reports'
    reports_dir.mkdir(exist_ok=True)
    filepath = reports_dir / f"blocklist-{domain_slug}.txt"
    filepath.write_text('\n'.join(sorted(high_ips)), encoding='utf-8')
    return str(filepath)

# ─── MAIN ───────────────────────────────────────────────────
    
def main():
    print(f"\nHostLog Analyzer")
    print(f"{'─' * 40}")

    if not DOMAIN_MAP:
        print("No domains configured in config.json.")
        return

    for domain, folder in DOMAIN_MAP.items():
        print(f"\nAnalyzing: {domain} ({folder}/)")

        # Using tqdm for progress tracking (falls back to generator if not installed)
        entries = tqdm(load_logs(folder), desc="  Reading logs", unit=" lines", leave=False)

        res = analyze(entries, domain)

        if res.total_count == 0:
            print(f"  No log entries found in {folder}/")
            continue

        print(f"  Analyzed {res.total_count} entries")

        persistent_count = sum(1 for days in res.ip_daily.values() if len(days) >= PERSISTENT_IP_DAYS)
        high_count       = sum(1 for a in res.alerts if a.get('severity') == 'HIGH')
        medium_count     = sum(1 for a in res.alerts if a.get('severity') == 'MEDIUM')

        print(f"  Hosting infrastructure IPs: {len(res.hosting_ips)}")
        print(f"  Admin session IPs: {len(res.admin_ips)}")
        print(f"  HIGH alerts: {high_count}")
        print(f"  MEDIUM alerts: {medium_count}")
        print(f"  Persistent IPs: {persistent_count}")
        print(f"  Flagged requests: {len(res.flagged_entries)}")

        domain_slug = domain.replace('.', '-').replace('/', '-')
        report = generate_report(
            domain, folder, res.alerts, res.flagged_entries,
            res.ip_ranking, res.ip_total, res.ip_daily, res.ip_daily_counts,
            res.custom_field_counts, res.cf_min, res.cf_max,
            res.hosting_ips, res.admin_ips, res.total_count, res.all_dates
        )
        filepath = save_report(domain_slug, report)
        print(f"  Report saved: {filepath}")

        blocklist_path = save_blocklist(domain_slug, res.alerts)
        if blocklist_path:
            print(f"  Blocklist generated: {blocklist_path}")

    print(f"\n{'─' * 40}")
    print(f"Done.\n")

if __name__ == '__main__':
    main()
