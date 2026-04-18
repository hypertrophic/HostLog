<?php
// ============================================================
//  INDEX.PHP — HostLog Dashboard Login
// ============================================================

require_once '/home/your-username/hostlog-config/config.php';

session_name(SESSION_NAME);
session_start();

// Already authenticated → go to dashboard
if (!empty($_SESSION['authenticated']) && !empty($_SESSION['last_activity'])
    && (time() - $_SESSION['last_activity']) <= SESSION_TIMEOUT) {
    header('Location: dashboard.php');
    exit;
}

$error    = '';
$locked   = false;
$lockData = [];

// ─── LOCKOUT CHECK ──────────────────────────────────────────

function getLockData(): array {
    if (!file_exists(LOCKOUT_FILE)) return ['attempts' => 0, 'locked_until' => 0];
    return json_decode(file_get_contents(LOCKOUT_FILE), true) ?: ['attempts' => 0, 'locked_until' => 0];
}

function saveLockData(array $data): void {
    file_put_contents(LOCKOUT_FILE, json_encode($data), LOCK_EX);
}

$lockData = getLockData();
if ($lockData['locked_until'] > time()) {
    $locked    = true;
    $remaining = ceil(($lockData['locked_until'] - time()) / 60);
    $error     = "Too many failed attempts. Try again in {$remaining} minute(s).";
}

// ─── LOGIN HANDLER ──────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$locked) {
    $password = $_POST['password'] ?? '';

    if (password_verify($password, DASHBOARD_PASSWORD_HASH)) {
        // Success — reset lockout, regenerate session
        saveLockData(['attempts' => 0, 'locked_until' => 0]);
        session_regenerate_id(true);
        $_SESSION['authenticated']  = true;
        $_SESSION['last_activity']  = time();
        $_SESSION['csrf_token']     = bin2hex(random_bytes(32));
        header('Location: dashboard.php');
        exit;
    } else {
        $lockData['attempts']++;
        if ($lockData['attempts'] >= MAX_LOGIN_ATTEMPTS) {
            $lockData['locked_until'] = time() + LOCKOUT_DURATION;
            $error = 'Too many failed attempts. Account locked for ' . (LOCKOUT_DURATION / 60) . ' minutes.';
            $locked = true;
        } else {
            $remaining = MAX_LOGIN_ATTEMPTS - $lockData['attempts'];
            $error     = "Incorrect password. {$remaining} attempt(s) remaining.";
        }
        saveLockData($lockData);
    }
}
?>
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HostLog — Login</title>
    <link rel="stylesheet" href="assets/style.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
</head>
<body class="login-page">

<div class="login-bg">
    <div class="login-grid"></div>
</div>

<div class="login-wrap">
    <div class="login-card">
        <div class="login-logo">
            <span class="logo-icon">⬡</span>
            <span class="logo-text">HostLog</span>
        </div>
        <p class="login-sub">Security Dashboard</p>

        <?php if ($error): ?>
        <div class="login-error">
            <span class="error-icon">⚠</span> <?= htmlspecialchars($error) ?>
        </div>
        <?php endif; ?>

        <form method="POST" class="login-form" autocomplete="off">
            <div class="field-wrap">
                <label for="password">Password</label>
                <input
                    type="password"
                    id="password"
                    name="password"
                    autofocus
                    <?= $locked ? 'disabled' : '' ?>
                    placeholder="Enter password"
                >
            </div>
            <button type="submit" class="btn btn-primary btn-full" <?= $locked ? 'disabled' : '' ?>>
                <span>Access Dashboard</span>
                <span class="btn-arrow">→</span>
            </button>
        </form>

        <p class="login-footer">HostLog v3.0.0</p>
    </div>
</div>

<script src="assets/app.js"></script>
</body>
</html>
