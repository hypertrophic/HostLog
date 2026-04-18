<?php
// ============================================================
//  CONFIG.PHP — HostLog Dashboard Configuration
//  Keep this file outside public_html.
//  To generate a password hash, run:
//      php -r "echo password_hash('your-password', PASSWORD_BCRYPT);"
// ============================================================

// --- CREDENTIALS ---
// Replace with your bcrypt-hashed password
define('DASHBOARD_PASSWORD_HASH', '$2y$12$REPLACE_THIS_WITH_YOUR_ACTUAL_HASH');

// --- SESSION SETTINGS ---
define('SESSION_TIMEOUT',    30 * 60);   // Auto-logout after 30 minutes of inactivity
define('SESSION_NAME',       'hostlog_session');

// --- LOCKOUT SETTINGS ---
define('MAX_LOGIN_ATTEMPTS', 5);         // Failed attempts before lockout
define('LOCKOUT_DURATION',   15 * 60);  // Lockout duration in seconds (15 min)
define('LOCKOUT_FILE',       __DIR__ . '/../.lockout'); // Stored outside web root

// --- PATHS ---
// Must match your logger's config.php LOG_BASE_PATH
define('LOG_BASE_PATH',      '/home/your-username/logs');
define('HTACCESS_PATH',      '/home/your-username/public_html/.htaccess');

// --- DOMAIN MAP ---
// Must match your logger's config.php $host_map
$host_map = [
    'example.com'     => 'Main',
    'sub.example.com' => 'Sub',
];

// --- ANALYSIS THRESHOLDS ---
$thresholds = [
    'requests_per_hour'          => 300,
    'requests_per_day'           => 1000,
    'login_posts_per_hour'       => 10,
    'persistent_ip_days'         => 3,
    'xmlrpc_posts_per_session'   => 5,
    'distributed_scan_min_ips'   => 5,
    'distributed_scan_min_avg'   => 3,
];

// Per-domain threshold overrides (optional)
$domain_thresholds = [
    // 'sub.example.com' => ['requests_per_hour' => 1000, 'requests_per_day' => 8000],
];

// --- WHITELIST (synced with analyzer config.json) ---
$whitelist = [
    'ips'          => [],
    'paths'        => [],
    'user_agents'  => [],
];

// --- PATH LISTS ---
$login_paths = ['/wp-login.php', '/login', '/admin/login'];

$wordpress_internal_paths = [
    '/wp-cron.php', '/wp-admin/admin-ajax.php',
    '/wp-admin/load-scripts.php', '/wp-admin/load-styles.php',
    '/wp-admin/async-upload.php', '/jetpack',
];

$sensitive_paths = [
    '/wp-login.php', '/wp-admin', '/xmlrpc.php', '/wp-config.php',
    '/.env', '/.git', '/wp-content/uploads', '/wp-includes',
    '/readme.html', '/license.txt', '/wp-json/wp/v2/users',
    '/wp-content/debug.log', '/phpmyadmin', '/config',
];

$shell_probe_paths = [
    '/wp_filemanager.php', '/filemanager.php', '/shell.php',
    '/cmd.php', '/c99.php', '/r57.php', '/b374k.php', '/alfa.php', '/wso.php',
];

$exposure_paths = [
    '/backup', '/backup.zip', '/backup.sql', '/db.sql',
    '/dump.sql', '/database.sql', '/wp-backup', '/.backup',
];

$xmlrpc_paths        = ['/xmlrpc.php'];
$user_enum_paths     = ['/wp-json/wp/v2/users', '/?author='];
$allowed_methods     = ['GET', 'POST'];

$suspicious_user_agents = [
    'sqlmap', 'nikto', 'wpscan', 'masscan', 'nmap', 'zgrab', 'nuclei',
    'python-requests', 'python-urllib', 'go-http-client', 'curl/',
    'wget/', 'scrapy', 'libwww-perl', 'semrush', 'ahrefsbot',
    'dotbot', 'majestic', 'petalbot',
];

$hosting_ipv6_prefixes = ['2a02:4780::/32'];

$known_good_bots = [
    'googlebot', 'bingbot', 'yandexbot', 'applebot',
    'claudebot', 'facebookexternalhit',
];
