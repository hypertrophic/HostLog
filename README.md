# HostLog - v2.1.0

A logging and analysis system for PHP sites hosted on **Hostinger Web Hosting**. Built to fill the gap left by Hostinger's lack of accessible raw access logs.

---

## Two parts, one system

| | Logger | Analyzer |
|---|---|---|
| **Language** | PHP | Python |
| **Runs on** | Your Hostinger server | Your local machine |
| **What it does** | Logs every request to daily files | Reads downloaded logs and generates a report |
| **Output** | `.log` files outside `public_html` | Markdown report + blocklist file |

### Repository structure

```
HostLog/
    logger.php              ← upload to server (outside public_html)
    config.php              ← server configuration
    .htaccess               ← drop in each site root
    README.md
    LICENSE
    local-analyzer/
        analyzer.py         ← run locally after downloading logs
        config.json         ← analyzer configuration
        logs/               ← place your downloaded logs here (read Note.md)
        reports/            ← reports saved here automatically (read Note.md)
```

---

## Why this exists

Hostinger shared hosting does not provide terminal access or raw Apache/Nginx log files. HostLog fills that gap — the logger runs automatically before every page load via `auto_prepend_file`, and the analyzer processes those logs locally to surface threats and suspicious activity.

---

## Part 1 — Logger

### Features

- Cloudflare and Proxy-aware IP detection — supports `CF-Connecting-IP`, `X-Real-IP`, and `X-Forwarded-For`
- Spoofing-resistant — validates IP headers before trusting them
- Log injection prevention — strips newlines and control characters from all fields
- Automatic daily log files — one file per domain per day
- Automatic log rotation — archives files that exceed a configurable size limit
- Write-lock protected — prevents file corruption from concurrent requests
- Multi-domain support — log multiple sites into separate folders from one file
- Optional custom field — extract any value from the URL path per domain, with optional regex validation
- IP exclusion — skip logging for specific IPs (e.g., internal server IPs or your personal static IP)
- Zero dependencies — pure PHP, no libraries, no Composer

### Log format

Each request is logged as a single pipe-separated line:

```
[2026-03-18 14:32:01] | 41.142.97.7 | GET /about | Ref:- | UA:Mozilla/5.0...
[2026-03-18 14:33:10] | 41.142.97.7 | GET /shop/item-123 | Ref:- | UA:... | ProductID:item-123
```

| Field | Description |
|---|---|
| Timestamp | `Y-m-d H:i:s` |
| IP address | Real visitor IP, Cloudflare and proxy aware |
| Method + path | HTTP method and full request URI |
| Referer | Origin page if available, `-` if not |
| User agent | Browser or bot identifier |
| Custom field | Optional — any value extracted from the URL path |

### Installation

**Step 1 — Upload logger files**

Upload `logger.php` and `config.php` to a folder **outside** `public_html`. On Hostinger this is typically:

```
/home/your-username/logger.php
/home/your-username/config.php
```

Use Hostinger's File Manager or SFTP to upload. Make sure you access your full hosting file system — not just your domain's `public_html` folder — so you can place the files outside the web root.

**Step 2 — Configure**

Edit `config.php` to match your setup:

```php
define('LOG_BASE_PATH', '/home/your-username/logs');

$host_map = [
    'example.com'     => 'Main',
    'sub.example.com' => 'Sub',
];

$ignore_ips = ['127.0.0.1', '::1'];
```

**Step 3 — Add .htaccess**

Add this line to the `.htaccess` file in the root of each site you want to log. Create it if it doesn't exist:

```apacheconf
# Add this line to your .htaccess for each website
php_value auto_prepend_file "/home/your-username/logger.php"
# Replace your-username with your actual Hostinger username
```

**Step 4 — Verify**

Visit your site and check the logs folder. You should see:

```
/home/your-username/logs/Main/access-2026-04-12.log
```

### Log file structure

```
/home/your-username/logs/
    Main/
        access-2026-04-12.log
        access-2026-04-11.log
    Sub/
        access-2026-04-12.log
        access-2026-04-12-1744123456.log   ← rotated file (size limit reached)
```

### Configuration reference

| Option | Type | Description |
|---|---|---|
| `LOG_BASE_PATH` | `string` | Absolute path to log storage folder |
| `$host_map` | `array` | Domain → folder name mapping |
| `$custom_field` | `array\|null` | Custom field extraction config, or `null` to disable |
| `LOG_MAX_SIZE` | `int` | Max log file size in bytes before rotation (default: 5MB) |
| `CUSTOM_FIELD_PATTERN` | `string\|null` | Optional regex to validate extracted custom field values. Set to `null` to accept any value. |

### Custom field

The logger can extract a value from the URL path for a specific domain. Useful for tracking identifiers like member IDs, product slugs, or any path-based parameter.

```php
$custom_field = [
    'domain' => 'sub.example.com',
    'label'  => 'MemberID',
];
```

To restrict the extracted value to a specific format, set a validation pattern:

```php
define('CUSTOM_FIELD_PATTERN', '#^ID\d+$#i');
```

This prevents noise like `robots.txt` from appearing as custom field values in your logs. Set to `null` to accept any value.

### Cloudflare users

If your site is behind Cloudflare, the logger automatically reads the real visitor IP from the `CF-Connecting-IP` header. No configuration needed.

### Security notes

- Keep `logger.php` and `config.php` outside `public_html`
- The logs folder is created with `0750` permissions — not world-readable
- Log entries are sanitized to prevent log injection attacks

---

## Part 2 — Analyzer

A local Python script that reads your downloaded log files and generates a detailed markdown report with threat detection, IP classification, and a blocklist file.

### Requirements

- Python 3.7+
- No external libraries required — standard library only
- Optional: `pip install tqdm` for a progress bar when reading large log sets

### Features

- Reads all log files for a domain at once — drop 30 days of logs and scan them together
- Cross-day IP tracking — detects slow attacks that stay under hourly thresholds
- Per-domain threshold overrides — set different limits for high-traffic or low-traffic domains
- Admin session detection — automatically excludes your own `/wp-admin/` activity from alerts
- Hosting infrastructure detection — auto-excludes server IPs by IPv6 prefix
- Threat classification with severity levels (HIGH / MEDIUM / LOW)
- Custom field report section — aggregates and ranks any custom URL field values

**Detections:**

| Detection | Severity | Description |
|---|---|---|
| Request threshold exceeded | HIGH | IP exceeds req/hour limit — DDoS indicator |
| Daily request threshold | HIGH | IP exceeds req/day limit — DoS indicator |
| Login brute force | HIGH | 10+ POSTs to login path in one hour |
| XML-RPC abuse | HIGH | 5+ POSTs to `xmlrpc.php` |
| User enumeration | HIGH/MEDIUM | Probe of `/wp-json/wp/v2/users` or `/?author=` |
| Shell / backdoor probe | HIGH | Request to known PHP shell filenames |
| Suspicious login referer | HIGH | Login POST from an external domain |
| Persistent threat | MEDIUM | IP active across 3+ distinct days |
| Distributed scan | MEDIUM | Multiple IPs sending uniform requests in same minute |
| Sensitive file exposure | MEDIUM | Request to backup or dump file paths |
| Reconnaissance / scan | MEDIUM | Request to sensitive paths |
| Automated scanner | LOW | Known scanner user agent or empty user agent |
| Probe | LOW | Disallowed HTTP method |

### Usage

**Step 1 — Download your logs**

Download your log files from Hostinger File Manager and place them in the `local-analyzer/logs/` folder:

```
local-analyzer/
    logs/
        Main/
            access-2026-04-01.log
            access-2026-04-02.log
            ...
        Sub/
            access-2026-04-01.log
```

**Step 2 — Configure**

Edit `local-analyzer/config.json` to match your domains and set your thresholds:

```json
"domains": {
    "example.com": {
        "folder": "Main"
    },
    "sub.example.com": {
        "folder": "Sub",
        "thresholds": {
            "requests_per_hour": 1000,
            "requests_per_day": 8000
        }
    }
}
```

Domains without a `thresholds` block inherit the global thresholds. Per-domain overrides only affect the thresholds you specify — all others fall back to the global values.

**Step 3 — Run**

```bash
cd local-analyzer
python analyzer.py
```

Or on some systems:

```bash
cd local-analyzer
python3 analyzer.py
```

**Step 4 — Check reports**

Reports are saved in `local-analyzer/reports/`:

```
local-analyzer/
    reports/
        report-example-com-2026-04-13_10-00-00.md
        blocklist-example-com.txt
```

The blocklist file contains all HIGH severity IPs, one per line, ready to paste into your `.htaccess` or firewall.

### Whitelist

Add trusted IPs, paths, or user agents to `config.json` to exclude them from analysis:

```json
"whitelist": {
    "ips": ["your.ip.here"],
    "paths": [],
    "user_agents": []
}
```

> **Note:** Your own IP may appear in flagged requests if you access your site's admin panel or make multiple requests in a short period. This is normal — simply add your IP to the whitelist before running the analyzer. Keep in mind that your IP may change every time you reconnect to the internet, so check it before each scan using a service like [whatismyip.com](https://www.whatismyip.com).

> **Important:** Remove your own IPs from the whitelist before sharing `config.json` anywhere.

### Configuration reference

| Key | Description |
|---|---|
| `logs_base_path` | Folder where your downloaded logs are placed |
| `domains` | Domain → folder mapping, with optional per-domain `thresholds` |
| `thresholds.requests_per_hour` | Global alert threshold per IP per hour |
| `thresholds.requests_per_day` | Global alert threshold per IP per day |
| `thresholds.login_posts_per_hour` | Brute force detection threshold |
| `thresholds.persistent_ip_days` | Days before an IP is flagged as persistent |
| `thresholds.xmlrpc_posts_per_session` | XML-RPC abuse threshold |
| `thresholds.distributed_scan_min_ips` | Min IPs in same minute to trigger distributed scan alert |
| `thresholds.distributed_scan_min_avg` | Min average requests per IP before distributed scan fires |
| `hosting_ipv6_prefixes` | IPv6 prefixes (full CIDR) auto-classified as hosting infrastructure |
| `wordpress_internal_paths` | Paths silently ignored (wp-cron, admin-ajax, etc.) |
| `sensitive_paths` | Paths that trigger reconnaissance alerts |
| `shell_probe_paths` | Known PHP shell filenames — trigger HIGH alerts |
| `exposure_paths` | Backup and dump file paths |
| `xmlrpc_paths` | XML-RPC endpoint paths |
| `user_enumeration_paths` | User enumeration endpoint paths |
| `whitelist.ips` | IPs excluded from analysis |
| `whitelist.paths` | Paths excluded from analysis |
| `whitelist.user_agents` | User agents excluded from analysis |

---

## Coming soon

- **PHP dashboard** — browser-based interface to view traffic, flagged requests, and alerts directly on the server
- **Auto-blocking** — automatically write flagged IPs to `.htaccess`
- **Alert system** — notifications when thresholds are exceeded
- **Log deletion** — manage and clean up old log files from the dashboard

---

## License

MIT — free to use, modify, and distribute with attribution.  
Created by [Wissam Boubkir](https://github.com/hypertrophic)

---

*Built for Hostinger Web Hosting. Tested on WordPress and static PHP sites.*
