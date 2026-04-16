<?php
// ============================================================
//  CONFIG.PHP — Logger Configuration
//  Edit this file to match your hosting setup.
//  Include this file at the top of logger.php.
// ============================================================

// --- LOG STORAGE PATH ---
// Absolute path to the folder where logs will be stored.
// Must be outside public_html so logs are not browser-accessible.
// On Hostinger, this is typically: /home/your-username/logs
define('LOG_BASE_PATH', '/home/your-username/logs');

// --- DOMAIN → FOLDER MAP ---
// Map each domain or subdomain to a folder name under LOG_BASE_PATH.
// Logs for each domain will be saved in their own subfolder.
// Add or remove entries as needed.
$host_map = [
    'example.com'        => 'Main',
    'sub.example.com'    => 'Sub',
];

// --- IGNORE IPS ---
// IPs that will never be logged.
// Add your server's internal IPs and any static IP you want to exclude.
$ignore_ips = ['127.0.0.1', '::1'];

// --- CUSTOM FIELD ---
// Optionally extract a custom value from the URL path for a specific domain.
// Useful for tracking identifiers like member IDs, product slugs, etc.
// Set to null to disable.
$custom_field = [
    'domain' => 'sub.example.com',   // Which domain to extract from
    'label'  => 'MemberID',          // Label used in the log entry
];
// Set to null to disable custom field extraction entirely:
// $custom_field = null;

// --- CUSTOM FIELD VALIDATION (optional) ---
// If set, only values matching this pattern will be logged.
// Leave as null to accept any value from the URL path.
define('CUSTOM_FIELD_PATTERN', null);
// Example: define('CUSTOM_FIELD_PATTERN', '#^ID\d+$#i');

// --- LOG ROTATION SIZE ---
// Maximum log file size in bytes before rotation kicks in.
// Default: 5MB. A new file is created when this limit is reached.
define('LOG_MAX_SIZE', 5 * 1024 * 1024);
