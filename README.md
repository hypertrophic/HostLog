# HostLog - v3.0.0
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/hypertrophic/HostLog)

A logging, analysis, and threat detection system for PHP sites hosted on **Hostinger Web Hosting**. Built to fill the gap left by Hostinger's lack of accessible raw access logs.

---

## Three parts, one system

| | Logger | Analyzer | Dashboard |
|---|---|---|---|
| **Language** | PHP | Python | PHP |
| **Runs on** | Your Hostinger server | Your local machine | Your Hostinger server |
| **What it does** | Logs every request to daily files | Reads downloaded logs and generates a report | Live browser-based interface for analysis, blocking, and log management |
| **Output** | `.log` files outside `public_html` | Markdown report + blocklist file | Interactive dashboard |

### Repository structure

```
HostLog/
    README.md
    LICENSE
    PRIVATE/
        hostinger-logger/
            logger.php          ← upload outside public_html
            config.php          ← logger configuration
            .htaccess           ← drop in each site root
        hostlog-config/
            config.php          ← dashboard configuration (keep outside public_html)
            analyzer.php        ← dashboard analysis engine (keep outside public_html)
    PUBLIC/
        dashboard/
            index.php           ← login page
            dashboard.php       ← main dashboard view
            actions.php         ← AJAX endpoint for all dashboard actions
            assets/
                style.css
                app.js
            .htaccess           ← blocks directory listing
    local-analyzer/
        analyzer.py             ← run locally after downloading logs
        config.json             ← analyzer configuration
        logs/                   ← place your downloaded logs here (read Note.md)
        reports/                ← reports saved here automatically (read Note.md)
```

> **Security note:** Everything inside `PRIVATE/` must be uploaded **outside** `public_html` on your server. Everything inside `PUBLIC/` goes inside `public_html`. See the [Logger Installation](#installation) and [Dashboard Installation](#dashboard-installation) sections.

---

## Why this exists

Hostinger shared hosting does not provide terminal access or raw Apache/Nginx log files. HostLog fills that gap — the logger runs automatically before every page load via `auto_prepend_file`, and the analyzer and dashboard process those logs to surface threats and suspicious activity.

---

## Part 1 — Logger

### Features

- Cloudflare and proxy-aware IP detection — supports `CF-Connecting-IP`, `X-Real-IP`, and `X-Forwarded-For`
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

From the `PRIVATE/hostinger-logger/` folder, upload `logger.php` and `config.php` to a folder **outside** `public_html`. On Hostinger this is typically:

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
| `$ignore_ips` | `array` | IPs that will never be logged |
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

## Part 3 — Dashboard

A browser-based interface hosted on your server. Password protected. Runs the full analysis engine in PHP — no Python or terminal required.

### Features

**Overview**
- Per-domain summary table — entries, unique IPs, alert counts, log period
- Stat cards — total entries, HIGH alerts, flagged requests, blocked IPs

**Alerts & threat detection**
- Full PHP port of the analyzer's detection engine — same logic, same severity levels, runs live on the server
- Alerts panel grouped by severity (HIGH / MEDIUM / LOW) with one-click blocking
- Flagged requests table with threat classification and per-entry block button

**IP management**
- IP rankings by request count with inline bar chart
- One-click manual block — writes deny rule to `.htaccess`
- One-click unblock per IP
- Unblock all button
- Classification labels — Admin session, Hosting infrastructure, Blocked

**Whitelist manager**
- Add or remove IPs, paths, or user agents at runtime
- Changes are stored in `whitelist.json` and merged with config on next load

**Log management**
- Download raw or filtered logs by domain and date range
- Delete logs by domain with time range selector (30 / 60 / 90 days or specific day)
- Confirmation step before deletion

**Custom field export** *(only shown if a custom field is configured)*
- Aggregates URL-extracted values per domain with a date range selector
- CSV export sorted by count descending

**Auth**
- bcrypt password verification
- CSRF token on all state-changing actions
- Session timeout after 30 minutes of inactivity
- Lockout after 5 failed login attempts

**UI**
- Dark and light theme with toggle, persisted in `localStorage`
- Animated grid login page, section transitions, hover lifts, toast notifications
- JetBrains Mono + Syne typography

### Dashboard installation

**Step 1 — Upload files to the correct locations**

The repository is split into `PRIVATE/` and `PUBLIC/` to make this straightforward:

Upload the contents of `PRIVATE/hostlog-config/` outside `public_html`:
```
/home/your-username/hostlog-config/
    config.php      ← dashboard configuration (never web-accessible)
    analyzer.php    ← analysis engine (never web-accessible)
```

Upload the contents of `PUBLIC/dashboard/` inside `public_html`:
```
/home/your-username/public_html/dashboard/
    index.php
    dashboard.php
    actions.php
    assets/
        style.css
        app.js
    .htaccess
```

Your full server layout should look like this:
```
/home/your-username/
    hostlog-config/
        config.php
        analyzer.php
    logs/
        Main/
        Sub/
    public_html/
        dashboard/
            index.php
            dashboard.php
            actions.php
            assets/
                style.css
                app.js
            .htaccess
```

**Step 2 — Update the require paths**

In `index.php`, `dashboard.php`, and `actions.php`, find this line near the top and replace `your-username` with your actual Hostinger username:

```php
require_once '/home/your-username/hostlog-config/config.php';
```

**Step 3 — Add `.htaccess` to the dashboard folder**

Create `public_html/dashboard/.htaccess`:

```apacheconf
Options -Indexes

<FilesMatch "^(config\.php|analyzer\.php|whitelist\.json)$">
    Order deny,allow
    Deny from all
</FilesMatch>
```

**Step 4 — Configure `config.php`**

Edit the dashboard `config.php` to set your password hash, log path, `.htaccess` path, and domain map:

```php
define('DASHBOARD_PASSWORD_HASH', '$2y$12$your-bcrypt-hash-here');
define('LOG_BASE_PATH',           '/home/your-username/logs');
define('HTACCESS_PATH',           '/home/your-username/public_html/.htaccess');

$host_map = [
    'example.com'     => 'Main',
    'sub.example.com' => 'Sub',
];
```

To generate a bcrypt password hash without terminal access, use an online bcrypt generator or ask your local PHP environment:

```bash
php -r "echo password_hash('your-password', PASSWORD_BCRYPT);"
```

**Step 5 — Access the dashboard**

Visit `https://yourdomain.com/dashboard/` — you will be prompted to log in.

### Dashboard configuration reference

| Option | Description |
|---|---|
| `DASHBOARD_PASSWORD_HASH` | bcrypt hash of your dashboard password |
| `SESSION_TIMEOUT` | Auto-logout after inactivity in seconds (default: 30 min) |
| `MAX_LOGIN_ATTEMPTS` | Failed attempts before lockout (default: 5) |
| `LOCKOUT_DURATION` | Lockout duration in seconds (default: 15 min) |
| `LOG_BASE_PATH` | Must match your logger's `LOG_BASE_PATH` |
| `HTACCESS_PATH` | Absolute path to the `.htaccess` file used for IP blocking |
| `$host_map` | Must match your logger's `$host_map` |
| `$thresholds` | Global analysis thresholds |
| `$domain_thresholds` | Per-domain threshold overrides |

---

## License

MIT — free to use, modify, and distribute with attribution.  
Created by [Wissam Boubkir](https://github.com/hypertrophic)

---

*Built for Hostinger Web Hosting. Tested on WordPress and static PHP sites.*
