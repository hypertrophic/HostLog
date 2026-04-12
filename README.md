# HostLog

A lightweight, plug-and-play visitor logging system for PHP sites hosted on **Hostinger Web Hosting**. Built to fill the gap left by Hostinger's lack of accessible raw access logs.

Logs every request across one or multiple domains into clean, structured daily log files; stored safely outside your public web root.

---

## Why this exists

Hostinger Web Hosting service does not provide terminal access or raw Apache/Nginx log files. This logger runs automatically before every page load via `auto_prepend_file`, giving you full visibility into your traffic without touching your existing site code.

---

## Features

- Cloudflare-aware IP detection — gets the real visitor IP, not Cloudflare's
- Spoofing-resistant — validates IP headers before trusting them
- Log injection prevention — strips newlines and control characters from all fields
- Automatic daily log files — one file per domain per day
- Automatic log rotation — archives files that exceed a configurable size limit
- Write-lock protected — prevents file corruption from concurrent requests
- Multi-domain support — log multiple sites into separate folders from one file
- Optional custom field — extract any value from the URL path per domain
- Zero dependencies — pure PHP, no libraries, no Composer

---

## Log format

Each request is logged as a single pipe-separated line:

```
[2026-03-18 14:32:01] | 41.142.97.7 | GET /about | Ref:- | UA:Mozilla/5.0...
[2026-03-18 14:33:10] | 41.142.97.7 | GET /shop/item-123 | Ref:- | UA:... | ProductID:item-123
```

Fields logged per request:

| Field | Description |
|---|---|
| Timestamp | `Y-m-d H:i:s` |
| IP address | Real visitor IP, Cloudflare and proxy aware |
| Method + path | HTTP method and full request URI |
| Referer | Origin page if available, `-` if not |
| User agent | Browser or bot identifier |
| Custom field | Optional — any value extracted from the URL path |

---

## File structure

```
hostinger-logger/
    logger.php              ← main logger — upload outside public_html
    config.php              ← your configuration — edit this file
    .htaccess               ← drop this in each site root
```

---

## Installation

### Step 1 — Upload logger files

Upload `logger.php` and `config.php` to a folder **outside** `public_html`. On Hostinger this is typically:

```
/home/your-username/logger.php
/home/your-username/config.php
```

You can use Hostinger's File Manager or SFTP to upload (make sure it says: **Access all files of your hosting** not just you domain name files).

### Step 2 — Configure

Edit `config.php` to match your setup:

```php
// Path where logs will be stored (outside public_html)
define('LOG_BASE_PATH', '/home/your-username/logs');

// Map your domains to folder names
$host_map = [
    'example.com'     => 'Main',
    'sub.example.com' => 'Sub',
];
```

### Step 3 — Add .htaccess

Drop the `.htaccess` file into the root of each site (if not existent) you want to log. Update the path to match your username:

```apacheconf
php_value auto_prepend_file "/home/your-username/logger.php"
```

If your site already has an `.htaccess` file, just add that line at the top.

### Step 4 — Verify

Visit your site and check the logs folder. You should see a new file appear:

```
/home/your-username/logs/Main/access-2026-04-12.log
```

---

## Log file structure

Logs are organized by domain and date:

```
/home/your-username/logs/
    Main/
        access-2026-04-12.log
        access-2026-04-11.log
    Sub/
        access-2026-04-12.log
        access-2026-04-12-1744123456.log   ← rotated file (size limit reached)
```

---

## Custom field

The logger can extract a value from the URL path for a specific domain and include it as an extra field in the log entry. Useful for tracking identifiers like member IDs, product slugs, or any path-based parameter.

Configure it in `config.php`:

```php
$custom_field = [
    'domain' => 'sub.example.com',
    'label'  => 'MemberID',
];
```

This would log requests to `sub.example.com/verify/M00123` as:

```
[2026-04-12 10:15:22] | 91.x.x.x | GET /verify/M00123 | Ref:- | UA:... | MemberID:M00123
```

Set `$custom_field = null` to disable this feature entirely.

---

## Configuration reference

| Option | Type | Description |
|---|---|---|
| `LOG_BASE_PATH` | `string` | Absolute path to log storage folder |
| `$host_map` | `array` | Domain → folder name mapping |
| `$custom_field` | `array\|null` | Custom field extraction config, or `null` to disable |
| `LOG_MAX_SIZE` | `int` | Max log file size in bytes before rotation (default: 5MB) |

---

## Cloudflare users

If your site is behind Cloudflare, the logger automatically reads the real visitor IP from the `CF-Connecting-IP` header instead of Cloudflare's proxy IP. No configuration needed.

---

## Security notes

- Keep `logger.php` and `config.php` outside `public_html` — they should never be accessible via a browser URL
- The logs folder is created with `0750` permissions — not world-readable
- Log entries are sanitized to prevent log injection attacks

---

## Coming soon

This is the first part of a larger logging system built for Hostinger. Future releases will include:

- **Log analyzer** — local Python script to parse log files and detect suspicious traffic patterns
- **PHP dashboard** — browser-based interface to view traffic, flagged requests, and alerts
- **Auto-blocking** — automatically write flagged IPs to `.htaccess`
- **Alert system** — notifications when thresholds are exceeded

---

## License

MIT — free to use, modify, and distribute with attribution.  
Created by [Wissam Boubkir](https://github.com/hypertrophic)

---

*Built for Hostinger Web Hosting. Tested on WordPress and static PHP sites.*
