<?php
// ============================================================
//  LOGGER.PHP — Secure Visitor Logger for Hostinger
//  Location: outside public_html (e.g. /home/your-username/)
//  Triggered automatically via auto_prepend_file in .htaccess
// ============================================================

require_once __DIR__ . '/config.php';

// --- 1. GET REAL IP (Cloudflare-aware, spoofing-resistant) ---
function get_real_ip(): string {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
    } elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        $ip = $_SERVER['HTTP_X_REAL_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    $ip = trim($ip);
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : $_SERVER['REMOTE_ADDR'];
}

// --- 2. SANITIZE STRINGS (prevent log injection) ---
function sanitize_log_field(string $value, int $max_length = 300): string {
    $value = preg_replace('/[\r\n\t]/', ' ', $value);
    $value = preg_replace('/[\x00-\x1F\x7F]/', '', $value);
    return substr(trim($value), 0, $max_length);
}

// --- 3. RESOLVE HOST TO FOLDER ---
$host        = $_SERVER['HTTP_HOST'] ?? 'unknown';
$folder_name = $host_map[$host] ?? null;

// If the host is not in the map, skip logging entirely
if ($folder_name === null) return;

// --- 4. COLLECT AND SANITIZE REQUEST DATA ---
$ip = get_real_ip();

// Skip ignored IPs (internal server IPs, static personal IPs, etc.)
if (isset($ignore_ips) && in_array($ip, $ignore_ips)) return;

$time       = date('Y-m-d H:i:s');
$method     = sanitize_log_field($_SERVER['REQUEST_METHOD']  ?? 'UNKNOWN', 10);
$request    = sanitize_log_field($_SERVER['REQUEST_URI']     ?? '/', 500);
$user_agent = sanitize_log_field($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown');
$referer    = sanitize_log_field($_SERVER['HTTP_REFERER']    ?? '-');

// --- 5. EXTRACT CUSTOM FIELD (optional, configured in config.php) ---
$custom_value = '';
if (!empty($custom_field) && $host === $custom_field['domain']) {
    $path         = parse_url($request, PHP_URL_PATH) ?? '/';
    $raw_value    = sanitize_log_field(basename($path), 100);
    $pattern      = defined('CUSTOM_FIELD_PATTERN') ? CUSTOM_FIELD_PATTERN : null;
    if ($pattern === null || preg_match($pattern, $raw_value)) {
        $custom_value = $raw_value;
    }
}

// --- 6. LOG FOLDER SETUP ---
$domain_logs_folder = LOG_BASE_PATH . '/' . $folder_name;

if (!is_dir($domain_logs_folder)) {
    mkdir($domain_logs_folder, 0750, true);
}

// --- 7. LOG ROTATION ---
// If today's log file exceeds LOG_MAX_SIZE, archive it and start a new one
$log_file = $domain_logs_folder . '/access-' . date('Y-m-d') . '.log';
if (file_exists($log_file) && filesize($log_file) > LOG_MAX_SIZE) {
    rename($log_file, $domain_logs_folder . '/access-' . date('Y-m-d') . '-' . time() . '.log');
}

// --- 8. BUILD LOG ENTRY ---
$log_parts = [
    "[{$time}]",
    $ip,
    "{$method} {$request}",
    "Ref:{$referer}",
    "UA:{$user_agent}",
];

if ($custom_value !== '' && !empty($custom_field)) {
    $log_parts[] = "{$custom_field['label']}:{$custom_value}";
}

$log_entry = implode(' | ', $log_parts) . "\n";

// --- 9. WRITE TO LOG (with write-lock to prevent corruption) ---
file_put_contents($log_file, $log_entry, FILE_APPEND | LOCK_EX);
