<?php
// ============================================================
//  ANALYZER.PHP — PHP port of the HostLog analysis engine
//  Used internally by the dashboard. Not directly accessible.
// ============================================================

class HostLogAnalyzer {

    private array $thresholds;
    private array $loginPaths;
    private array $wpInternal;
    private array $sensitivePaths;
    private array $shellPaths;
    private array $exposurePaths;
    private array $xmlrpcPaths;
    private array $userEnumPaths;
    private array $allowedMethods;
    private array $suspiciousUA;
    private array $knownGoodBots;
    private array $whitelist;
    private array $hostingPrefixes;

    private array $infraCache = [];

    public function __construct(array $config) {
        $this->thresholds      = $config['thresholds'];
        $this->loginPaths      = array_map('strtolower', $config['login_paths']);
        $this->wpInternal      = array_map('strtolower', $config['wordpress_internal_paths']);
        $this->sensitivePaths  = array_map('strtolower', $config['sensitive_paths']);
        $this->shellPaths      = array_map('strtolower', $config['shell_probe_paths']);
        $this->exposurePaths   = array_map('strtolower', $config['exposure_paths']);
        $this->xmlrpcPaths     = array_map('strtolower', $config['xmlrpc_paths']);
        $this->userEnumPaths   = array_map('strtolower', $config['user_enum_paths']);
        $this->allowedMethods  = array_map('strtoupper', $config['allowed_methods']);
        $this->suspiciousUA    = array_map('strtolower', $config['suspicious_user_agents']);
        $this->knownGoodBots   = array_map('strtolower', $config['known_good_bots']);
        $this->whitelist       = $config['whitelist'];
        $this->hostingPrefixes = $config['hosting_ipv6_prefixes'];
    }

    // ─── PARSE A SINGLE LOG LINE ────────────────────────────

    public function parseLine(string $line): ?array {
        $line = trim($line);
        if ($line === '') return null;

        $pattern = '/^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s*\|\s*([\d\.a-fA-F:]+)\s*\|\s*([A-Z]+)\s+(\S+)\s*\|\s*Ref:(\S+)\s*\|\s*UA:(.+?)(?:\s*\|\s*(\w+):(.+))?$/';

        if (!preg_match($pattern, $line, $m)) return null;

        $ts = $m[1];
        return [
            'timestamp'    => $ts,
            'ts_hour'      => substr($ts, 0, 13),   // "2026-04-12 14"
            'ts_minute'    => substr($ts, 0, 16),   // "2026-04-12 14:32"
            'ts_day'       => substr($ts, 0, 10),   // "2026-04-12"
            'ip'           => trim($m[2]),
            'method'       => strtoupper(trim($m[3])),
            'path'         => trim($m[4]),
            'referer'      => trim($m[5]),
            'ua'           => trim($m[6]),
            'custom_key'   => isset($m[7]) && $m[7] !== '' ? trim($m[7]) : null,
            'custom_value' => isset($m[8]) && $m[8] !== '' ? trim($m[8]) : null,
        ];
    }

    // ─── LOAD ALL LOGS FOR A FOLDER ─────────────────────────

    public function loadLogs(string $folderPath, ?string $dateFrom = null, ?string $dateTo = null): \Generator {
        if (!is_dir($folderPath)) return;

        $files = glob($folderPath . '/access-*.log');
        if (!$files) return;
        sort($files);

        foreach ($files as $filepath) {
            // Filter by date range if provided
            if ($dateFrom || $dateTo) {
                preg_match('/access-(\d{4}-\d{2}-\d{2})/', basename($filepath), $dm);
                $fileDate = $dm[1] ?? null;
                if ($fileDate) {
                    if ($dateFrom && $fileDate < $dateFrom) continue;
                    if ($dateTo   && $fileDate > $dateTo)   continue;
                }
            }

            $fh = fopen($filepath, 'r');
            if (!$fh) continue;
            while (($line = fgets($fh)) !== false) {
                $entry = $this->parseLine($line);
                if ($entry) yield $entry;
            }
            fclose($fh);
        }
    }

    // ─── IP CLASSIFICATION ──────────────────────────────────

    private function isWhitelisted(array $entry): bool {
        if (in_array($entry['ip'], $this->whitelist['ips'])) return true;
        $pathLower = strtolower($entry['path']);
        foreach ($this->whitelist['paths'] as $p) {
            if (str_starts_with($pathLower, strtolower($p))) return true;
        }
        $uaLower = strtolower($entry['ua']);
        foreach ($this->whitelist['user_agents'] as $ua) {
            if (str_contains($uaLower, strtolower($ua))) return true;
        }
        return false;
    }

    private function isHostingInfrastructure(string $ip): bool {
    if (isset($this->infraCache[$ip])) return $this->infraCache[$ip];
    if (!str_contains($ip, ':')) return $this->infraCache[$ip] = false;

    try {
        $ipBin = inet_pton($ip);
        if ($ipBin === false) return $this->infraCache[$ip] = false;

        foreach ($this->hostingPrefixes as $prefix) {
            if (!str_contains($prefix, '/')) continue;
            [$networkAddr, $bits] = explode('/', $prefix, 2);
            $bits       = (int)$bits;
            $networkBin = inet_pton($networkAddr);
            if ($networkBin === false) continue;

            $fullBytes     = intdiv($bits, 8);
            $remainingBits = $bits % 8;

            if (substr($ipBin, 0, $fullBytes) !== substr($networkBin, 0, $fullBytes)) continue;

            if ($remainingBits > 0) {
                $mask = 0xFF & (0xFF << (8 - $remainingBits));
                if ((ord($ipBin[$fullBytes]) & $mask) !== (ord($networkBin[$fullBytes]) & $mask)) continue;
            }

            return $this->infraCache[$ip] = true;
        }
    } catch (\Throwable $e) {
        return $this->infraCache[$ip] = false;
    }

    return $this->infraCache[$ip] = false;
}

    // ─── THREAT CLASSIFICATION ──────────────────────────────

    public function classifyThreat(string $reason): string {
        $r = strtolower($reason);
        if (str_contains($r, 'shell') || str_contains($r, 'backdoor')) return 'Shell / backdoor probe';
        if (str_contains($r, 'xmlrpc'))       return 'XML-RPC abuse';
        if (str_contains($r, 'user enum'))    return 'User enumeration';
        if (str_contains($r, 'exposure') || str_contains($r, 'backup')) return 'Sensitive file exposure';
        if (str_contains($r, 'req/hour'))     return 'DDoS indicator';
        if (str_contains($r, 'req/day'))      return 'DoS indicator';
        if (str_contains($r, 'persistent'))   return 'Persistent threat';
        if (str_contains($r, 'login'))        return 'Brute force';
        if (str_contains($r, 'distributed'))  return 'Distributed scan';
        if (str_contains($r, 'referer'))      return 'Cross-site login attempt';
        if (str_contains($r, 'sensitive'))    return 'Reconnaissance / scan';
        if (str_contains($r, 'user agent'))   return 'Automated scanner';
        if (str_contains($r, 'empty') && str_contains($r, 'agent')) return 'Suspicious bot';
        if (str_contains($r, 'method'))       return 'Probe';
        return 'Suspicious activity';
    }

    public function alertSeverity(string $threat): string {
        $high = ['Shell / backdoor probe', 'XML-RPC abuse', 'User enumeration',
                 'Brute force', 'DDoS indicator', 'Cross-site login attempt'];
        $medium = ['Distributed scan', 'Persistent threat', 'Sensitive file exposure',
                   'DoS indicator', 'Reconnaissance / scan'];
        if (in_array($threat, $high))   return 'HIGH';
        if (in_array($threat, $medium)) return 'MEDIUM';
        return 'LOW';
    }

    private function startsWith(string $haystack, array $needles): bool {
        $h = strtolower($haystack);
        foreach ($needles as $n) {
            if (str_starts_with($h, $n)) return true;
        }
        return false;
    }

    // ─── MAIN ANALYSIS ──────────────────────────────────────

    public function analyze(\Generator $entries, string $domainName, array $domainThresholds = []): array {
        $t = array_merge($this->thresholds, $domainThresholds);

        $alerts        = [];
        $flagged       = [];
        $ipTotal       = [];
        $ipHourly      = [];
        $ipDaily       = [];
        $ipDailyCounts = [];
        $ipLoginHour   = [];
        $ipXmlrpc      = [];
        $ipUserEnum    = [];
        $ipAdminHits   = [];
        $ipAdminPaths  = [];
        $ipAdminBrowser= [];
        $customCounts  = [];
        $cfMin = null; $cfMax = null;
        $minuteIps     = [];
        $minuteCounts  = [];
        $hostingIps    = [];
        $adminIps      = [];
        $allDays       = [];
        $totalCount    = 0;
        $flaggedCapped = false;

        $adminUA = ['mozilla', 'chrome', 'safari', 'firefox', 'edge'];

        foreach ($entries as $e) {
            $totalCount++;
            $ip = $e['ip'];

            if ($this->isHostingInfrastructure($ip)) {
                $hostingIps[$ip] = true;
                continue;
            }
            if ($this->isWhitelisted($e)) continue;

            $hour   = $e['ts_hour'];
            $minute = $e['ts_minute'];
            $day    = $e['ts_day'];
            $path   = strtolower($e['path']);
            $ua     = strtolower($e['ua']);
            $method = $e['method'];

            $ipTotal[$ip]                    = ($ipTotal[$ip] ?? 0) + 1;
            $ipHourly[$ip][$hour]            = ($ipHourly[$ip][$hour] ?? 0) + 1;
            $ipDaily[$ip][$day]              = true;
            $ipDailyCounts[$ip][$day]        = ($ipDailyCounts[$ip][$day] ?? 0) + 1;
            $allDays[$day]                   = true;
            $minuteIps[$minute][$ip]         = true;
            $minuteCounts[$minute][$ip]      = ($minuteCounts[$minute][$ip] ?? 0) + 1;

            // Admin session tracking
            if (str_starts_with($path, '/wp-admin/')) {
                $ipAdminHits[$ip]                          = ($ipAdminHits[$ip] ?? 0) + 1;
                $ipAdminPaths[$ip][strtok($path, '?')]     = true;
                foreach ($adminUA as $kw) {
                    if (str_contains($ua, $kw)) { $ipAdminBrowser[$ip] = true; break; }
                }
            }

            // Login tracking
            if ($method === 'POST' && $this->startsWith($path, $this->loginPaths)) {
                $ipLoginHour[$ip][$hour] = ($ipLoginHour[$ip][$hour] ?? 0) + 1;
            }

            // XML-RPC tracking
            if ($method === 'POST' && $this->startsWith($path, $this->xmlrpcPaths)) {
                $ipXmlrpc[$ip] = ($ipXmlrpc[$ip] ?? 0) + 1;
            }

            // User enum tracking
            if ($this->startsWith($path, $this->userEnumPaths)) {
                $ipUserEnum[$ip][] = $e['ts_minute'];
            }

            // Custom field
            if ($e['custom_key'] && $e['custom_value']) {
                $k = $e['custom_key'];
                $v = $e['custom_value'];
                $customCounts[$k][$v] = ($customCounts[$k][$v] ?? 0) + 1;
                if (!$cfMin || $e['timestamp'] < $cfMin) $cfMin = $e['timestamp'];
                if (!$cfMax || $e['timestamp'] > $cfMax) $cfMax = $e['timestamp'];
            }

            // Per-entry flagging
            if ($flaggedCapped) continue;
            $entryFlags = [];

            // Suspicious login referer
            if ($method === 'POST' && $this->startsWith($path, $this->loginPaths)) {
                $ref = strtolower($e['referer']);
                if ($ref !== '-' && !str_contains($ref, strtolower($domainName))) {
                    $entryFlags[] = 'suspicious login referer';
                }
            }

            if ($this->startsWith($path, $this->shellPaths)) {
                $entryFlags[] = 'shell probe';
            } elseif ($this->startsWith($path, $this->exposurePaths)) {
                $entryFlags[] = 'exposure path (backup/dump)';
            } elseif ($this->startsWith($path, $this->wpInternal)) {
                continue;
            } elseif ($this->startsWith($path, $this->sensitivePaths)) {
                $entryFlags[] = 'sensitive path';
            }

            $isGoodBot = false;
            foreach ($this->knownGoodBots as $bot) {
                if (str_contains($ua, $bot)) { $isGoodBot = true; break; }
            }

            if (!$isGoodBot) {
                if ($ua === '' || $ua === 'unknown') {
                    $entryFlags[] = 'empty user agent';
                } else {
                    foreach ($this->suspiciousUA as $s) {
                        if (str_contains($ua, $s)) { $entryFlags[] = 'suspicious user agent'; break; }
                    }
                }
            }

            if (!in_array($method, $this->allowedMethods)) {
                $entryFlags[] = "disallowed method ({$method})";
            }

            if ($entryFlags) {
                $reason = implode(', ', $entryFlags);
                $threat = $this->classifyThreat($reason);
                $flagged[] = [
                    'timestamp' => $e['timestamp'],
                    'ip'        => $ip,
                    'method'    => $method,
                    'path'      => $e['path'],
                    'ua'        => $e['ua'],
                    'reasons'   => $entryFlags,
                    'threat'    => $threat,
                    'severity'  => $this->alertSeverity($threat),
                ];
                if (count($flagged) >= 500) $flaggedCapped = true;
            }
        }

        // Finalize admin sessions
        foreach ($ipTotal as $ip => $_) {
            if (($ipAdminHits[$ip] ?? 0) >= 3
                && !empty($ipAdminBrowser[$ip])
                && count($ipAdminPaths[$ip] ?? []) >= 3) {
                $adminIps[$ip] = true;
            }
        }

        // req/hour alerts
        foreach ($ipHourly as $ip => $hours) {
            if (isset($adminIps[$ip])) continue;
            foreach ($hours as $hour => $count) {
                if ($count >= $t['requests_per_hour']) {
                    $reason = "{$count} req/hour";
                    $threat = $this->classifyThreat($reason);
                    $alerts[] = ['ip' => $ip, 'when' => $hour, 'count' => $count,
                                 'reason' => $reason, 'threat' => $threat, 'severity' => 'HIGH'];
                }
            }
        }

        // req/day alerts
        foreach ($ipTotal as $ip => $total) {
            if (isset($adminIps[$ip])) continue;
            if ($total >= $t['requests_per_day']) {
                $reason = "{$total} req/day";
                $threat = $this->classifyThreat($reason);
                $alerts[] = ['ip' => $ip, 'when' => 'all days', 'count' => $total,
                             'reason' => $reason, 'threat' => $threat, 'severity' => 'HIGH'];
            }
        }

        // Persistent IP alerts
        $persistDays = $t['persistent_ip_days'];
        foreach ($ipDaily as $ip => $days) {
            if (isset($adminIps[$ip])) continue;
            if (count($days) >= $persistDays) {
                $dayList = array_keys($days);
                sort($dayList);
                $reason = "active across " . count($days) . " days ({$dayList[0]} → {$dayList[count($dayList)-1]})";
                $alerts[] = ['ip' => $ip, 'when' => "{$dayList[0]} → {$dayList[count($dayList)-1]}",
                             'count' => $ipTotal[$ip], 'reason' => $reason,
                             'threat' => 'Persistent threat', 'severity' => 'MEDIUM'];
            }
        }

        // Login brute force
        foreach ($ipLoginHour as $ip => $hours) {
            foreach ($hours as $hour => $count) {
                if ($count >= $t['login_posts_per_hour']) {
                    $reason = "{$count} login POSTs in one hour";
                    $threat = $this->classifyThreat($reason);
                    $alerts[] = ['ip' => $ip, 'when' => $hour, 'count' => $count,
                                 'reason' => $reason, 'threat' => $threat, 'severity' => 'HIGH'];
                }
            }
        }

        // XML-RPC abuse
        foreach ($ipXmlrpc as $ip => $count) {
            if ($count >= $t['xmlrpc_posts_per_session']) {
                $reason = "{$count} POST requests to xmlrpc.php";
                $alerts[] = ['ip' => $ip, 'when' => 'session', 'count' => $count,
                             'reason' => $reason, 'threat' => 'XML-RPC abuse', 'severity' => 'HIGH'];
            }
        }

        // User enumeration
        foreach ($ipUserEnum as $ip => $times) {
            $xmlrpcCount = $ipXmlrpc[$ip] ?? 0;
            $severity = $xmlrpcCount >= $t['xmlrpc_posts_per_session'] ? 'HIGH' : 'MEDIUM';
            $reason   = "probed user enumeration endpoint (" . count($times) . "x)";
            if ($severity === 'HIGH') $reason .= ' followed by XML-RPC attack';
            $alerts[] = ['ip' => $ip, 'when' => $times[0], 'count' => count($times),
                         'reason' => $reason, 'threat' => 'User enumeration', 'severity' => $severity];
        }

        // Distributed scan
        $minIps = $t['distributed_scan_min_ips'];
        $minAvg = $t['distributed_scan_min_avg'];
        foreach ($minuteIps as $minute => $ips) {
            if (count($ips) < $minIps) continue;
            $counts  = array_values($minuteCounts[$minute]);
            $avg     = array_sum($counts) / count($counts);
            if ($avg < $minAvg) continue;
            $uniform = true;
            foreach ($counts as $c) {
                if (abs($c - $avg) / $avg >= 0.2) { $uniform = false; break; }
            }
            if ($uniform) {
                $ipList = array_keys($ips);
                $reason = count($ips) . " different IPs sent uniform request counts in 1-minute window";
                $alerts[] = ['ip' => count($ips) . " IPs (e.g. {$ipList[0]}...)",
                             'when' => $minute, 'count' => count($ips),
                             'reason' => $reason, 'threat' => 'Distributed scan', 'severity' => 'MEDIUM'];
            }
        }

        // Sort IPs by total
        arsort($ipTotal);

        $sortedDays = array_keys($allDays);
        sort($sortedDays);

        return [
            'alerts'            => $alerts,
            'flagged'           => $flagged,
            'flagged_capped'    => $flaggedCapped,
            'ip_total'          => $ipTotal,
            'ip_daily'          => $ipDaily,
            'ip_daily_counts'   => $ipDailyCounts,
            'hosting_ips'       => array_keys($hostingIps),
            'admin_ips'         => array_keys($adminIps),
            'custom_counts'     => $customCounts,
            'cf_min'            => $cfMin,
            'cf_max'            => $cfMax,
            'total_count'       => $totalCount,
            'all_dates'         => $sortedDays,
        ];
    }
}
