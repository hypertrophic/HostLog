<?php
// ============================================================
//  ACTIONS.PHP — AJAX endpoint for HostLog dashboard actions
// ============================================================

require_once '/home/your-username/hostlog-config/config.php';
require_once '/home/your-username/hostlog-config/analyzer.php';

session_name(SESSION_NAME);
session_start();

header('Content-Type: application/json');

// ─── AUTH CHECK ─────────────────────────────────────────────

if (empty($_SESSION['authenticated']) || empty($_SESSION['last_activity'])
    || (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
    echo json_encode(['ok' => false, 'error' => 'Not authenticated']);
    exit;
}
$_SESSION['last_activity'] = time();

// ─── CSRF CHECK ─────────────────────────────────────────────

$csrfToken = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
if ($csrfToken !== ($_SESSION['csrf_token'] ?? '')) {
    echo json_encode(['ok' => false, 'error' => 'Invalid CSRF token']);
    exit;
}

$action = $_POST['action'] ?? $_GET['action'] ?? '';

// ─── HELPERS ────────────────────────────────────────────────

function respondOk(array $data = []): void {
    echo json_encode(array_merge(['ok' => true], $data));
    exit;
}

function respondError(string $msg): void {
    echo json_encode(['ok' => false, 'error' => $msg]);
    exit;
}

function readHtaccess(): string {
    return file_exists(HTACCESS_PATH) ? file_get_contents(HTACCESS_PATH) : '';
}

function writeHtaccess(string $content): bool {
    return file_put_contents(HTACCESS_PATH, $content, LOCK_EX) !== false;
}

function getBlockedIPs(): array {
    $content = readHtaccess();
    preg_match_all('/# HostLog block\nDeny from ([\d\.a-fA-F:]+)/m', $content, $m);
    return $m[1] ?? [];
}

function isValidIP(string $ip): bool {
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

// ─── ACTIONS ────────────────────────────────────────────────

switch ($action) {

    // --- Block an IP ---
    case 'block_ip':
        $ip = trim($_POST['ip'] ?? '');
        if (!isValidIP($ip)) respondError('Invalid IP address');

        $content    = readHtaccess();
        $blockEntry = "\n# HostLog block\nDeny from {$ip}\n";

        if (str_contains($content, "Deny from {$ip}")) {
            respondError('IP is already blocked');
        }

        // Ensure Order/Deny directives exist
        if (!str_contains($content, 'Order deny,allow')) {
            $blockEntry = "\nOrder deny,allow\n" . $blockEntry;
        }

        if (!writeHtaccess($content . $blockEntry)) {
            respondError('Failed to write .htaccess');
        }
        respondOk(['message' => "Blocked {$ip}"]);

    // --- Unblock an IP ---
    case 'unblock_ip':
        $ip = trim($_POST['ip'] ?? '');
        if (!isValidIP($ip)) respondError('Invalid IP address');

        $content = readHtaccess();
        $pattern = "/\n# HostLog block\nDeny from " . preg_quote($ip, '/') . "\n/";
        $new     = preg_replace($pattern, '', $content);

        if ($new === $content) respondError('IP was not blocked');
        if (!writeHtaccess($new)) respondError('Failed to write .htaccess');
        respondOk(['message' => "Unblocked {$ip}"]);

    // --- Unblock all IPs ---
    case 'unblock_all':
        $content = readHtaccess();
        $new     = preg_replace("/\n# HostLog block\nDeny from [\d\.a-fA-F:]+\n/", '', $content);
        if (!writeHtaccess($new)) respondError('Failed to write .htaccess');
        respondOk(['message' => 'All HostLog blocks removed']);

    // --- Get blocked IPs ---
    case 'get_blocked':
        respondOk(['ips' => getBlockedIPs()]);

    // --- Add to whitelist ---
    case 'whitelist_add':
        global $whitelist;
        $type  = $_POST['type']  ?? '';
        $value = trim($_POST['value'] ?? '');

        if (!in_array($type, ['ips', 'paths', 'user_agents'])) respondError('Invalid whitelist type');
        if ($value === '') respondError('Empty value');
        if ($type === 'ips' && !isValidIP($value)) respondError('Invalid IP address');

        // Read current config and update whitelist
        $configPath = __DIR__ . '/whitelist.json';
        $wl = file_exists($configPath) ? json_decode(file_get_contents($configPath), true) : ['ips' => [], 'paths' => [], 'user_agents' => []];

        if (in_array($value, $wl[$type])) respondError('Already in whitelist');
        $wl[$type][] = $value;

        file_put_contents($configPath, json_encode($wl, JSON_PRETTY_PRINT), LOCK_EX);
        respondOk(['message' => "Added {$value} to whitelist"]);

    // --- Remove from whitelist ---
    case 'whitelist_remove':
        $type  = $_POST['type']  ?? '';
        $value = trim($_POST['value'] ?? '');

        $configPath = __DIR__ . '/whitelist.json';
        $wl = file_exists($configPath) ? json_decode(file_get_contents($configPath), true) : ['ips' => [], 'paths' => [], 'user_agents' => []];

        $wl[$type] = array_values(array_filter($wl[$type], fn($v) => $v !== $value));
        file_put_contents($configPath, json_encode($wl, JSON_PRETTY_PRINT), LOCK_EX);
        respondOk(['message' => "Removed {$value} from whitelist"]);

    // --- Get whitelist ---
    case 'get_whitelist':
        $configPath = __DIR__ . '/whitelist.json';
        $wl = file_exists($configPath) ? json_decode(file_get_contents($configPath), true) : ['ips' => [], 'paths' => [], 'user_agents' => []];
        respondOk(['whitelist' => $wl]);

    // --- Download logs ---
    case 'download_logs':
        global $host_map;
        $domain    = $_POST['domain'] ?? '';
        $dateFrom  = $_POST['date_from'] ?? '';
        $dateTo    = $_POST['date_to']   ?? '';
        $filtered  = ($_POST['filtered'] ?? '0') === '1';

        if (!isset($host_map[$domain])) respondError('Invalid domain');
        $folder = LOG_BASE_PATH . '/' . $host_map[$domain];
        if (!is_dir($folder)) respondError('Log folder not found');

        // Build list of matching files
        $files = glob($folder . '/access-*.log');
        $matchedFiles = [];
        foreach ($files as $f) {
            preg_match('/access-(\d{4}-\d{2}-\d{2})/', basename($f), $dm);
            $fd = $dm[1] ?? null;
            if ($fd) {
                if ($dateFrom && $fd < $dateFrom) continue;
                if ($dateTo   && $fd > $dateTo)   continue;
            }
            $matchedFiles[] = $f;
        }

        if (empty($matchedFiles)) respondError('No log files found for this period');

        header('Content-Type: text/plain');
        header('Content-Disposition: attachment; filename="hostlog-' . slugify($domain) . '-' . date('Y-m-d') . '.log"');

        // For filtered downloads, we'd need to re-analyze — for now stream raw
        // Filtered mode strips lines with no UA and known bots
        foreach ($matchedFiles as $f) {
            $fh = fopen($f, 'r');
            if (!$fh) continue;
            while (($line = fgets($fh)) !== false) {
                if ($filtered) {
                    // Strip empty UA lines
                    if (preg_match('/UA:\s*(\||$)/', $line)) continue;
                }
                echo $line;
            }
            fclose($fh);
        }
        exit;

    // --- Delete logs ---
    case 'delete_logs':
        global $host_map;
        $domains  = $_POST['domains'] ?? [];
        $range    = $_POST['range']   ?? '';
        $specific = $_POST['specific_day'] ?? '';

        if (empty($domains)) respondError('No domains selected');

        $cutoff = null;
        if ($range === 'specific' && $specific) {
            $cutoff = ['exact' => $specific];
        } elseif (in_array($range, ['30', '60', '90'])) {
            $cutoff = ['before' => date('Y-m-d', strtotime("-{$range} days"))];
        } else {
            respondError('Invalid date range');
        }

        $deleted = 0;
        foreach ($domains as $domain) {
            if (!isset($host_map[$domain])) continue;
            $folder = LOG_BASE_PATH . '/' . $host_map[$domain];
            $files  = glob($folder . '/access-*.log') ?: [];
            foreach ($files as $f) {
                preg_match('/access-(\d{4}-\d{2}-\d{2})/', basename($f), $dm);
                $fd = $dm[1] ?? null;
                if (!$fd) continue;
                $doDelete = false;
                if (isset($cutoff['exact'])   && $fd === $cutoff['exact'])   $doDelete = true;
                if (isset($cutoff['before'])  && $fd < $cutoff['before'])    $doDelete = true;
                if ($doDelete && unlink($f)) $deleted++;
            }
        }
        respondOk(['message' => "Deleted {$deleted} log file(s)"]);

    // --- Custom field export ---
    case 'export_custom':
        global $host_map, $thresholds, $domain_thresholds, $whitelist,
               $login_paths, $wordpress_internal_paths, $sensitive_paths,
               $shell_probe_paths, $exposure_paths, $xmlrpc_paths,
               $user_enum_paths, $allowed_methods, $suspicious_user_agents,
               $known_good_bots, $hosting_ipv6_prefixes;

        $domain   = $_POST['domain']    ?? '';
        $dateFrom = $_POST['date_from'] ?? date('Y-m-d', strtotime('-90 days'));
        $dateTo   = $_POST['date_to']   ?? date('Y-m-d');

        if (!isset($host_map[$domain])) respondError('Invalid domain');
        $folder = LOG_BASE_PATH . '/' . $host_map[$domain];

        $analyzer = new HostLogAnalyzer(buildAnalyzerConfig());
        $entries  = $analyzer->loadLogs($folder, $dateFrom, $dateTo);
        $results  = $analyzer->analyze($entries, $domain, $domain_thresholds[$domain] ?? []);

        if (empty($results['custom_counts'])) respondError('No custom field data found');

        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="hostlog-custom-' . slugify($domain) . '-' . date('Y-m-d') . '.csv"');

        $out = fopen('php://output', 'w');
        foreach ($results['custom_counts'] as $label => $values) {
            fputcsv($out, [$label, 'Count']);
            arsort($values);
            foreach ($values as $val => $count) {
                fputcsv($out, [$val, $count]);
            }
        }
        fclose($out);
        exit;

    default:
        respondError('Unknown action');
}

// ─── HELPERS ────────────────────────────────────────────────

function slugify(string $s): string {
    return preg_replace('/[^a-z0-9]+/', '-', strtolower($s));
}

function buildAnalyzerConfig(): array {
    global $thresholds, $whitelist, $login_paths, $wordpress_internal_paths,
           $sensitive_paths, $shell_probe_paths, $exposure_paths, $xmlrpc_paths,
           $user_enum_paths, $allowed_methods, $suspicious_user_agents,
           $known_good_bots, $hosting_ipv6_prefixes;
    return [
        'thresholds'               => $thresholds,
        'whitelist'                => $whitelist,
        'login_paths'              => $login_paths,
        'wordpress_internal_paths' => $wordpress_internal_paths,
        'sensitive_paths'          => $sensitive_paths,
        'shell_probe_paths'        => $shell_probe_paths,
        'exposure_paths'           => $exposure_paths,
        'xmlrpc_paths'             => $xmlrpc_paths,
        'user_enum_paths'          => $user_enum_paths,
        'allowed_methods'          => $allowed_methods,
        'suspicious_user_agents'   => $suspicious_user_agents,
        'known_good_bots'          => $known_good_bots,
        'hosting_ipv6_prefixes'    => $hosting_ipv6_prefixes,
    ];
}