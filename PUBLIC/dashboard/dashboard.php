<?php
// ============================================================
//  DASHBOARD.PHP — HostLog Main Dashboard
// ============================================================

require_once '/home/your-username/hostlog-config/config.php';
require_once '/home/your-username/hostlog-config/analyzer.php';

session_name(SESSION_NAME);
session_start();

// Auth guard
if (empty($_SESSION['authenticated']) || empty($_SESSION['last_activity'])
    || (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
    session_destroy();
    header('Location: index.php');
    exit;
}
$_SESSION['last_activity'] = time();

// Logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}

// CSRF token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf_token'];

// ─── LOAD WHITELIST ─────────────────────────────────────────

$wlPath = __DIR__ . '/whitelist.json';
$runtimeWhitelist = file_exists($wlPath)
    ? json_decode(file_get_contents($wlPath), true)
    : ['ips' => [], 'paths' => [], 'user_agents' => []];

$effectiveWhitelist = [
    'ips'          => array_merge($whitelist['ips'],         $runtimeWhitelist['ips']),
    'paths'        => array_merge($whitelist['paths'],       $runtimeWhitelist['paths']),
    'user_agents'  => array_merge($whitelist['user_agents'], $runtimeWhitelist['user_agents']),
];

// ─── RUN ANALYSIS ───────────────────────────────────────────

$analyzerConfig = [
    'thresholds'               => $thresholds,
    'whitelist'                => $effectiveWhitelist,
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

$analyzer    = new HostLogAnalyzer($analyzerConfig);
$allResults  = [];
$totalAlerts = 0;

foreach ($host_map as $domain => $folder) {
    $folderPath = LOG_BASE_PATH . '/' . $folder;
    $dt         = $domain_thresholds[$domain] ?? [];
    $entries    = $analyzer->loadLogs($folderPath);
    $res        = $analyzer->analyze($entries, $domain, $dt);
    $allResults[$domain] = $res;
    $totalAlerts += count($res['alerts']);
}

// Aggregate top IPs across all domains
$globalIpTotal = [];
foreach ($allResults as $domain => $res) {
    foreach ($res['ip_total'] as $ip => $count) {
        $globalIpTotal[$ip] = ($globalIpTotal[$ip] ?? 0) + $count;
    }
}
arsort($globalIpTotal);
$topIPs = array_slice($globalIpTotal, 0, 20, true);

// Aggregate all alerts
$allAlerts = [];
foreach ($allResults as $domain => $res) {
    foreach ($res['alerts'] as $alert) {
        $allAlerts[] = array_merge($alert, ['domain' => $domain]);
    }
}
usort($allAlerts, fn($a, $b) => match(true) {
    $a['severity'] !== $b['severity'] => ($a['severity'] === 'HIGH' ? -1 : ($b['severity'] === 'HIGH' ? 1 : ($a['severity'] === 'MEDIUM' ? -1 : 1))),
    default => $b['count'] - $a['count']
});

// Aggregate flagged entries
$allFlagged = [];
foreach ($allResults as $domain => $res) {
    foreach ($res['flagged'] as $f) {
        $allFlagged[] = array_merge($f, ['domain' => $domain]);
    }
}
usort($allFlagged, fn($a, $b) => strcmp($b['timestamp'], $a['timestamp']));

// Blocked IPs from .htaccess
function getBlockedIPs(): array {
    if (!file_exists(HTACCESS_PATH)) return [];
    $content = file_get_contents(HTACCESS_PATH);
    preg_match_all('/# HostLog block\nDeny from ([\d\.a-fA-F:]+)/m', $content, $m);
    return $m[1] ?? [];
}
$blockedIPs = getBlockedIPs();

// Helpers
function severityClass(string $s): string {
    return match($s) { 'HIGH' => 'sev-high', 'MEDIUM' => 'sev-medium', default => 'sev-low' };
}
function domainOptions(array $host_map): string {
    $out = '';
    foreach ($host_map as $domain => $_) {
        $out .= '<option value="' . htmlspecialchars($domain) . '">' . htmlspecialchars($domain) . '</option>';
    }
    return $out;
}
?>
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HostLog Dashboard</title>
    <link rel="stylesheet" href="assets/style.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
</head>
<body class="dashboard-page">

<!-- ═══ SIDEBAR ══════════════════════════════════════════ -->
<aside class="sidebar" id="sidebar">
    <div class="sidebar-logo">
        <span class="logo-icon">⬡</span>
        <div>
            <span class="logo-text">HostLog</span>
            <div style="font-size:0.65em;font-family:var(--font-mono);color:rgba(226,230,238,0.3);margin-top:1px;letter-spacing:0.05em;">v3.0.0</div>
        </div>
    </div>
    <nav class="sidebar-nav">
        <a href="#overview"   class="nav-item active" data-section="overview">
            <span class="nav-icon">◈</span> Overview
        </a>
        <a href="#alerts"     class="nav-item" data-section="alerts">
            <span class="nav-icon">◉</span> Alerts
            <?php if ($totalAlerts > 0): ?>
            <span class="nav-badge"><?= $totalAlerts ?></span>
            <?php endif; ?>
        </a>
        <a href="#flagged"    class="nav-item" data-section="flagged">
            <span class="nav-icon">◎</span> Flagged
        </a>
        <a href="#ips"        class="nav-item" data-section="ips">
            <span class="nav-icon">◌</span> IP Rankings
        </a>
        <a href="#blocking"   class="nav-item" data-section="blocking">
            <span class="nav-icon">⊘</span> IP Blocking
        </a>
        <a href="#whitelist"  class="nav-item" data-section="whitelist">
            <span class="nav-icon">◇</span> Whitelist
        </a>
        <a href="#logs"       class="nav-item" data-section="logs">
            <span class="nav-icon">≡</span> Logs
        </a>
        <?php
        $hasCustom = false;
        foreach ($allResults as $res) { if (!empty($res['custom_counts'])) { $hasCustom = true; break; } }
        if ($hasCustom):
        ?>
        <a href="#custom"     class="nav-item" data-section="custom">
            <span class="nav-icon">◈</span> Custom Field
        </a>
        <?php endif; ?>
    </nav>
    <div class="sidebar-footer">
        <button class="theme-toggle" id="themeToggle" title="Toggle theme">
            <span class="theme-icon">◑</span>
        </button>
        <a href="?logout=1" class="btn-logout" onclick="return confirm('Log out?')">Logout</a>
    </div>
</aside>

<!-- ═══ MAIN ═════════════════════════════════════════════ -->
<main class="main-content">

    <!-- TOAST -->
    <div class="toast-container" id="toastContainer"></div>

    <!-- ── OVERVIEW ─────────────────────────────────────── -->
    <section class="section active" id="overview">
        <div class="section-header">
            <h1>Overview</h1>
            <span class="section-sub">Last analysis — <?= date('Y-m-d H:i') ?></span>
        </div>

        <div class="stat-grid">
            <?php
            $totalEntries  = array_sum(array_column($allResults, 'total_count'));
            $totalFlagged  = array_sum(array_map(fn($r) => count($r['flagged']), $allResults));
            $totalBlocked  = count($blockedIPs);
            $highAlerts    = count(array_filter($allAlerts, fn($a) => $a['severity'] === 'HIGH'));
            ?>
            <div class="stat-card">
                <div class="stat-value"><?= number_format($totalEntries) ?></div>
                <div class="stat-label">Total Entries</div>
            </div>
            <div class="stat-card stat-danger">
                <div class="stat-value"><?= $highAlerts ?></div>
                <div class="stat-label">HIGH Alerts</div>
            </div>
            <div class="stat-card stat-warn">
                <div class="stat-value"><?= $totalFlagged ?></div>
                <div class="stat-label">Flagged Requests</div>
            </div>
            <div class="stat-card">
                <div class="stat-value"><?= $totalBlocked ?></div>
                <div class="stat-label">Blocked IPs</div>
            </div>
        </div>

        <!-- Per-domain summary -->
        <div class="card">
            <div class="card-header">Domain Summary</div>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>Entries</th>
                        <th>Unique IPs</th>
                        <th>HIGH</th>
                        <th>MEDIUM</th>
                        <th>LOW</th>
                        <th>Flagged</th>
                        <th>Period</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($allResults as $domain => $res):
                    $high   = count(array_filter($res['alerts'], fn($a) => $a['severity'] === 'HIGH'));
                    $med    = count(array_filter($res['alerts'], fn($a) => $a['severity'] === 'MEDIUM'));
                    $low    = count(array_filter($res['alerts'], fn($a) => $a['severity'] === 'LOW'));
                    $period = !empty($res['all_dates'])
                        ? $res['all_dates'][0] . ' → ' . $res['all_dates'][count($res['all_dates'])-1]
                        : '—';
                ?>
                <tr>
                    <td><span class="mono"><?= htmlspecialchars($domain) ?></span></td>
                    <td><?= number_format($res['total_count']) ?></td>
                    <td><?= number_format(count($res['ip_total'])) ?></td>
                    <td><?= $high > 0 ? "<span style='color:var(--danger);font-weight:700;'>{$high}</span>" : '<span style="color:var(--text-muted);">0</span>' ?></td>
                    <td><?= $med  > 0 ? "<span style='color:var(--warn);font-weight:700;'>{$med}</span>"   : '<span style="color:var(--text-muted);">0</span>' ?></td>
                    <td><?= $low  > 0 ? "<span style='color:var(--info);font-weight:700;'>{$low}</span>"   : '<span style="color:var(--text-muted);">0</span>' ?></td>
                    <td><?= count($res['flagged']) ?></td>
                    <td><span class="mono text-muted"><?= $period ?></span></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </section>

    <!-- ── ALERTS ────────────────────────────────────────── -->
    <section class="section" id="alerts">
        <div class="section-header">
            <h1>Alerts <span class="count-badge"><?= count($allAlerts) ?></span></h1>
        </div>

        <?php if (empty($allAlerts)): ?>
        <div class="empty-state">No alerts detected.</div>
        <?php else: ?>
        <div class="card">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>IP</th>
                        <th>Domain</th>
                        <th>When</th>
                        <th>Count</th>
                        <th>Threat</th>
                        <th>Reason</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($allAlerts as $alert): ?>
                <tr class="alert-row <?= severityClass($alert['severity']) ?>-row">
                    <td><span class="badge <?= severityClass($alert['severity']) ?>"><?= $alert['severity'] ?></span></td>
                    <td><span class="mono"><?= htmlspecialchars($alert['ip']) ?></span></td>
                    <td><span class="mono text-muted"><?= htmlspecialchars($alert['domain']) ?></span></td>
                    <td><span class="mono text-muted"><?= htmlspecialchars($alert['when']) ?></span></td>
                    <td><?= number_format($alert['count']) ?></td>
                    <td><?= htmlspecialchars($alert['threat']) ?></td>
                    <td class="text-muted small"><?= htmlspecialchars($alert['reason']) ?></td>
                    <td>
                        <?php if (filter_var($alert['ip'], FILTER_VALIDATE_IP)): ?>
                        <button class="btn btn-sm btn-danger" onclick="blockIP('<?= htmlspecialchars($alert['ip']) ?>')">Block</button>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>
    </section>

    <!-- ── FLAGGED REQUESTS ──────────────────────────────── -->
    <section class="section" id="flagged">
        <div class="section-header">
            <h1>Flagged Requests <span class="count-badge"><?= count($allFlagged) ?></span></h1>
        </div>

        <?php if (empty($allFlagged)): ?>
        <div class="empty-state">No flagged requests.</div>
        <?php else: ?>
        <div class="card">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>IP</th>
                        <th>Method</th>
                        <th>Path</th>
                        <th>Threat</th>
                        <th>Severity</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach (array_slice($allFlagged, 0, 200) as $f): ?>
                <tr>
                    <td><span class="mono text-muted"><?= htmlspecialchars($f['timestamp']) ?></span></td>
                    <td><span class="mono"><?= htmlspecialchars($f['ip']) ?></span></td>
                    <td><span class="badge badge-method"><?= htmlspecialchars($f['method']) ?></span></td>
                    <td><span class="mono small"><?= htmlspecialchars(substr($f['path'], 0, 60)) ?></span></td>
                    <td><?= htmlspecialchars($f['threat']) ?></td>
                    <td><span class="badge <?= severityClass($f['severity']) ?>"><?= $f['severity'] ?></span></td>
                    <td>
                        <button class="btn btn-sm btn-danger" onclick="blockIP('<?= htmlspecialchars($f['ip']) ?>')">Block</button>
                    </td>
                </tr>
                <?php endforeach; ?>
                <?php if (count($allFlagged) > 200): ?>
                <tr><td colspan="7" class="text-muted small text-center"><?= count($allFlagged) - 200 ?> additional entries not shown</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>
    </section>

    <!-- ── IP RANKINGS ───────────────────────────────────── -->
    <section class="section" id="ips">
        <div class="section-header">
            <h1>IP Rankings</h1>
        </div>
        <div class="card">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>IP Address</th>
                        <th>Total Requests</th>
                        <th>Classification</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                <?php $rank = 1; foreach ($topIPs as $ip => $count):
                    $isBlocked = in_array($ip, $blockedIPs);
                    $isAdmin   = false;
                    $isHosting = false;
                    foreach ($allResults as $res) {
                        if (in_array($ip, $res['admin_ips']))   $isAdmin   = true;
                        if (in_array($ip, $res['hosting_ips'])) $isHosting = true;
                    }
                ?>
                <tr>
                    <td class="text-muted"><?= $rank++ ?></td>
                    <td><span class="mono"><?= htmlspecialchars($ip) ?></span></td>
                    <td>
                        <div class="bar-wrap">
                            <div class="bar" style="width:<?= min(100, round($count / max(1, reset($topIPs)) * 100)) ?>%"></div>
                            <span><?= number_format($count) ?></span>
                        </div>
                    </td>
                    <td>
                        <?php if ($isBlocked):  ?><span class="badge sev-high">Blocked</span><?php
                        elseif ($isAdmin):      ?><span class="badge badge-admin">Admin</span><?php
                        elseif ($isHosting):    ?><span class="badge badge-infra">Infrastructure</span><?php
                        else:                   ?><span class="text-muted">—</span><?php endif; ?>
                    </td>
                    <td class="action-cell">
                        <?php if ($isBlocked): ?>
                        <button class="btn btn-sm btn-outline" onclick="unblockIP('<?= htmlspecialchars($ip) ?>')">Unblock</button>
                        <?php else: ?>
                        <button class="btn btn-sm btn-danger" onclick="blockIP('<?= htmlspecialchars($ip) ?>')">Block</button>
                        <?php endif; ?>
                        <button class="btn btn-sm btn-outline" onclick="whitelistIP('<?= htmlspecialchars($ip) ?>')">Whitelist</button>
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </section>

    <!-- ── IP BLOCKING ───────────────────────────────────── -->
    <section class="section" id="blocking">
        <div class="section-header">
            <h1>IP Blocking</h1>
        </div>

        <div class="two-col">
            <!-- Manual block -->
            <div class="card">
                <div class="card-header">Manual Block</div>
                <div class="card-body">
                    <div class="field-wrap">
                        <label>IP Address</label>
                        <input type="text" id="manualBlockIP" placeholder="e.g. 192.168.1.1" class="mono">
                    </div>
                    <button class="btn btn-danger" onclick="blockIP(document.getElementById('manualBlockIP').value)">
                        Block IP
                    </button>
                </div>
            </div>

            <!-- Unblock all -->
            <div class="card">
                <div class="card-header">Bulk Actions</div>
                <div class="card-body">
                    <p class="text-muted small">Remove all HostLog-managed block rules from .htaccess.</p>
                    <button class="btn btn-outline btn-danger-outline" onclick="unblockAll()">
                        Unblock All IPs
                    </button>
                </div>
            </div>
        </div>

        <!-- Blocked IPs list -->
        <div class="card">
            <div class="card-header">
                Currently Blocked
                <span class="count-badge" id="blockedCount"><?= count($blockedIPs) ?></span>
            </div>
            <div id="blockedList">
            <?php if (empty($blockedIPs)): ?>
            <div class="empty-state">No IPs currently blocked.</div>
            <?php else: ?>
            <table class="data-table">
                <thead><tr><th>IP Address</th><th>Action</th></tr></thead>
                <tbody id="blockedTableBody">
                <?php foreach ($blockedIPs as $ip): ?>
                <tr id="blocked-<?= md5($ip) ?>">
                    <td><span class="mono"><?= htmlspecialchars($ip) ?></span></td>
                    <td><button class="btn btn-sm btn-outline" onclick="unblockIP('<?= htmlspecialchars($ip) ?>')">Unblock</button></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
            </div>
        </div>
    </section>

    <!-- ── WHITELIST ─────────────────────────────────────── -->
    <section class="section" id="whitelist">
        <div class="section-header">
            <h1>Whitelist Manager</h1>
        </div>

        <div class="card">
            <div class="card-header">Add to Whitelist</div>
            <div class="card-body">
                <div class="field-row">
                    <div class="field-wrap flex-1">
                        <label>Type</label>
                        <select id="wlType">
                            <option value="ips">IP Address</option>
                            <option value="paths">Path</option>
                            <option value="user_agents">User Agent</option>
                        </select>
                    </div>
                    <div class="field-wrap flex-3">
                        <label>Value</label>
                        <input type="text" id="wlValue" placeholder="e.g. 192.168.1.1" class="mono">
                    </div>
                    <div class="field-wrap field-btn">
                        <label>&nbsp;</label>
                        <button class="btn btn-primary" onclick="addWhitelist()">Add</button>
                    </div>
                </div>
                <p class="field-hint">Whitelist your own IP before running security scans to avoid false positives.</p>
            </div>
        </div>

        <div class="card">
            <div class="card-header">Current Whitelist</div>
            <div id="whitelistDisplay">
                <?php
                $types = ['ips' => 'IP Addresses', 'paths' => 'Paths', 'user_agents' => 'User Agents'];
                foreach ($types as $type => $label):
                    $items = $effectiveWhitelist[$type] ?? [];
                ?>
                <div class="wl-group">
                    <div class="wl-group-label"><?= $label ?></div>
                    <?php if (empty($items)): ?>
                    <span class="text-muted small">None</span>
                    <?php else: foreach ($items as $item): ?>
                    <div class="wl-item">
                        <span class="mono"><?= htmlspecialchars($item) ?></span>
                        <button class="btn btn-xs btn-ghost" onclick="removeWhitelist('<?= $type ?>', '<?= htmlspecialchars($item) ?>')">✕</button>
                    </div>
                    <?php endforeach; endif; ?>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
    </section>

    <!-- ── LOGS ──────────────────────────────────────────── -->
    <section class="section" id="logs">
        <div class="section-header">
            <h1>Log Management</h1>
        </div>

        <!-- Download -->
        <div class="card">
            <div class="card-header">Download Logs</div>
            <div class="card-body">
                <div class="field-row">
                    <div class="field-wrap">
                        <label>Domain</label>
                        <select id="dlDomain"><?= domainOptions($host_map) ?></select>
                    </div>
                    <div class="field-wrap">
                        <label>From</label>
                        <input type="date" id="dlFrom" value="<?= date('Y-m-d', strtotime('-7 days')) ?>">
                    </div>
                    <div class="field-wrap">
                        <label>To</label>
                        <input type="date" id="dlTo" value="<?= date('Y-m-d') ?>">
                    </div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-primary" onclick="downloadLogs(false)">Download Raw</button>
                    <button class="btn btn-outline" onclick="downloadLogs(true)">Download Filtered</button>
                </div>
                <p class="field-hint warn-hint">⚠ Filtered download removes noisy entries. Legitimate requests may be excluded if incorrectly flagged.</p>
            </div>
        </div>

        <!-- Delete -->
        <div class="card card-danger-border">
            <div class="card-header">Delete Logs</div>
            <div class="card-body">
                <div class="field-row">
                    <div class="field-wrap">
                        <label>Domains</label>
                        <select id="delDomains" multiple>
                            <?= domainOptions($host_map) ?>
                        </select>
                    </div>
                    <div class="field-wrap">
                        <label>Range</label>
                        <select id="delRange" onchange="toggleSpecificDay()">
                            <option value="30">Last 30 days</option>
                            <option value="60">Last 60 days</option>
                            <option value="90">Last 90 days</option>
                            <option value="specific">Specific day</option>
                        </select>
                    </div>
                    <div class="field-wrap" id="specificDayWrap" style="display:none">
                        <label>Date</label>
                        <input type="date" id="specificDay" value="<?= date('Y-m-d') ?>">
                    </div>
                </div>
                <button class="btn btn-danger" onclick="deleteLogs()">Delete Selected Logs</button>
            </div>
        </div>
    </section>

    <!-- ── CUSTOM FIELD ───────────────────────────────────── -->
    <?php if ($hasCustom): ?>
    <section class="section" id="custom">
        <div class="section-header">
            <h1>Custom Field Export</h1>
        </div>

        <div class="card">
            <div class="card-header">Export</div>
            <div class="card-body">
                <div class="field-row">
                    <div class="field-wrap">
                        <label>Domain</label>
                        <select id="cfDomain"><?= domainOptions($host_map) ?></select>
                    </div>
                    <div class="field-wrap">
                        <label>From</label>
                        <input type="date" id="cfFrom" value="<?= date('Y-m-d', strtotime('-90 days')) ?>">
                    </div>
                    <div class="field-wrap">
                        <label>To</label>
                        <input type="date" id="cfTo" value="<?= date('Y-m-d') ?>">
                    </div>
                </div>
                <button class="btn btn-primary" onclick="exportCustom()">Export CSV</button>
            </div>
        </div>

        <!-- Preview -->
        <?php foreach ($allResults as $domain => $res):
            if (empty($res['custom_counts'])) continue;
            foreach ($res['custom_counts'] as $label => $values):
                arsort($values);
                $top = array_slice($values, 0, 10, true);
        ?>
        <div class="card">
            <div class="card-header"><?= htmlspecialchars($domain) ?> — <?= htmlspecialchars($label) ?></div>
            <table class="data-table">
                <thead><tr><th>#</th><th><?= htmlspecialchars($label) ?></th><th>Count</th></tr></thead>
                <tbody>
                <?php $r = 1; foreach ($top as $val => $count): ?>
                <tr>
                    <td class="text-muted"><?= $r++ ?></td>
                    <td><span class="mono"><?= htmlspecialchars($val) ?></span></td>
                    <td><?= number_format($count) ?></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endforeach; endforeach; ?>
    </section>
    <?php endif; ?>

</main>

<script>
    const CSRF = <?= json_encode($csrf) ?>;
</script>
<script src="assets/app.js"></script>
</body>
</html>
