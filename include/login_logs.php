<?php
// Login/session history — separate from registration_audit_log (Activity
// Logs). One row per login: who, when they logged in, when (if ever) they
// explicitly logged out, the IP/device they used, and the last page they
// touched while the session was alive. Written to from login.php (insert),
// auth_guard.php's require_role() (last_seen/last_action heartbeat on every
// authenticated request, for every role), and logout.php (close out).

function client_ip() {
    // No reverse proxy in front of this app (plain XAMPP/Apache on one box),
    // so REMOTE_ADDR is the real peer address — deliberately not trusting a
    // client-supplied X-Forwarded-For header, which would be trivially
    // spoofable.
    return (string)($_SERVER['REMOTE_ADDR'] ?? '');
}

// Coarse, dependency-free UA sniffing — good enough for "what did they log in
// with" at a glance, not meant to be exhaustive. Order matters: Edge/Opera UAs
// also contain "Chrome", and Chrome UAs also contain "Safari", so the more
// specific tokens must be checked first.
function parse_user_agent($ua) {
    $ua = (string)$ua;
    if ($ua === '') return 'Unknown device';

    // iPhone/iPad UAs also contain the literal string "like Mac OS X", so
    // that check must come before the desktop macOS one or every iOS device
    // gets misread as a Mac.
    if (preg_match('/iPhone|iPad|iOS/i', $ua)) $os = 'iOS';
    elseif (preg_match('/Windows NT 10\.0/i', $ua)) $os = 'Windows 10/11';
    elseif (preg_match('/Windows NT/i', $ua)) $os = 'Windows';
    elseif (preg_match('/Android/i', $ua)) $os = 'Android';
    elseif (preg_match('/Mac OS X/i', $ua)) $os = 'macOS';
    elseif (preg_match('/Linux/i', $ua)) $os = 'Linux';
    else $os = 'Unknown OS';

    if (preg_match('/Edg\//i', $ua)) $browser = 'Edge';
    elseif (preg_match('/OPR\//i', $ua)) $browser = 'Opera';
    elseif (preg_match('/Chrome\//i', $ua)) $browser = 'Chrome';
    elseif (preg_match('/Firefox\//i', $ua)) $browser = 'Firefox';
    elseif (preg_match('/Safari\//i', $ua)) $browser = 'Safari';
    else $browser = 'Unknown Browser';

    return $os . ' · ' . $browser;
}

// Human label for "where were they" — combines the dashboard file with the
// ?view= query string so the Login Logs modal can show something like
// "Superadmin Dashboard -> Accounts" instead of a raw filename.
function current_page_label() {
    $script = basename((string)($_SERVER['SCRIPT_NAME'] ?? ''));
    $dashboards = [
        'dashboard.php' => 'User Dashboard',
        'admin_dashboard.php' => 'Admin Dashboard',
        'superadmin_dashboard.php' => 'Superadmin Dashboard',
    ];
    $base = $dashboards[$script] ?? ($script !== '' ? $script : 'Unknown page');

    $view = trim((string)($_GET['view'] ?? ''));
    if ($view === '') return $base;

    $viewLabel = ucwords(str_replace('_', ' ', $view));
    return $base . ' -> ' . $viewLabel;
}

// Called once, right after a successful login. Returns the new row's id so
// the caller can stash it in $_SESSION['login_log_id'] — every later
// heartbeat/close-out for this session updates that one row.
function record_login($conn, $idNumber, $username, $fullName, $role) {
    $ip = client_ip();
    $ua = mb_substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255);
    $device = parse_user_agent($ua);
    $sessionId = session_id() ?: '';
    $initialAction = 'Logged in';

    $stmt = $conn->prepare("INSERT INTO login_logs
        (id_number, username, full_name, role, ip_address, user_agent, device_label, session_id, login_time, last_seen, last_action)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), ?)");
    $stmt->bind_param("sssssssss", $idNumber, $username, $fullName, $role, $ip, $ua, $device, $sessionId, $initialAction);
    $stmt->execute();
    $id = $conn->insert_id;
    $stmt->close();
    return $id;
}

// Heartbeat — called from require_role() on every authenticated page view,
// same spirit as the existing users.last_activity touch, just scoped to this
// one login session's row so "last thing they touched" stays current.
function touch_login_log($conn, $logId, $actionLabel) {
    if (empty($logId)) return;
    $stmt = $conn->prepare("UPDATE login_logs SET last_seen = NOW(), last_action = ? WHERE id = ? AND logout_time IS NULL");
    $stmt->bind_param("si", $actionLabel, $logId);
    $stmt->execute();
    $stmt->close();
}

// Called from logout.php. Deliberately guarded by "logout_time IS NULL" so
// it's a no-op if somehow called twice — first close wins.
function close_login_log($conn, $logId) {
    if (empty($logId)) return;
    $stmt = $conn->prepare("UPDATE login_logs SET logout_time = NOW(), last_action = 'Logged out' WHERE id = ? AND logout_time IS NULL");
    $stmt->bind_param("i", $logId);
    $stmt->execute();
    $stmt->close();
}

// Session never explicitly logged out (browser closed, crash, forced session
// kill) still needs a sensible status — computed via TIMESTAMPDIFF in SQL,
// never PHP's time()/strtotime() against a MySQL datetime string, per the
// same MySQL/PHP clock-zone mismatch noted in auth_guard.php.
function login_log_status($row) {
    if (!empty($row['logout_time'])) {
        return ['label' => 'Logged out', 'class' => 'blocked'];
    }
    $windowSeconds = (defined('ACTIVE_WINDOW_MINUTES') ? ACTIVE_WINDOW_MINUTES : 5) * 60;
    if ($row['seconds_since_last_seen'] !== null && (int)$row['seconds_since_last_seen'] <= $windowSeconds) {
        return ['label' => 'Active now', 'class' => 'approved'];
    }
    return ['label' => 'Session idle', 'class' => 'pending'];
}

// How long a session lasted: login_time -> logout_time, or login_time -> now
// for a still-active/never-explicitly-closed session. $seconds always comes
// from duration_seconds in the SQL result (TIMESTAMPDIFF), never a PHP-side
// subtraction against a MySQL datetime string — same clock-zone reasoning as
// everywhere else in this app.
function format_duration($seconds) {
    if ($seconds === null) return '—';
    $seconds = max(0, (int)$seconds);
    if ($seconds < 60) return $seconds . ' sec';

    $days = intdiv($seconds, 86400);
    $hours = intdiv($seconds % 86400, 3600);
    $mins = intdiv($seconds % 3600, 60);

    $parts = [];
    if ($days > 0) $parts[] = $days . ' day' . ($days === 1 ? '' : 's');
    if ($hours > 0) $parts[] = $hours . ' hr' . ($hours === 1 ? '' : 's');
    if ($mins > 0 && $days === 0) $parts[] = $mins . ' min' . ($mins === 1 ? '' : 's');

    return implode(' ', $parts) ?: '< 1 min';
}

// Paginated, filterable query behind the Login Logs view.
function get_login_logs($conn, array $filters, $page, $perPage) {
    $where = [];
    $params = [];
    $types = '';

    $role = $filters['role'] ?? 'all';
    if (in_array($role, ['user', 'admin', 'superadmin'], true)) {
        $where[] = 'role = ?';
        $params[] = $role;
        $types .= 's';
    }

    $status = $filters['status'] ?? 'all';
    if ($status === 'active') {
        $where[] = 'logout_time IS NULL AND TIMESTAMPDIFF(SECOND, last_seen, NOW()) <= ' . ((defined('ACTIVE_WINDOW_MINUTES') ? ACTIVE_WINDOW_MINUTES : 5) * 60);
    } elseif ($status === 'ended') {
        $where[] = 'logout_time IS NOT NULL';
    }

    $search = trim((string)($filters['search'] ?? ''));
    if ($search !== '') {
        $where[] = '(username LIKE ? OR full_name LIKE ? OR id_number LIKE ?)';
        $like = '%' . $search . '%';
        $params[] = $like;
        $params[] = $like;
        $params[] = $like;
        $types .= 'sss';
    }

    $dateFrom = trim((string)($filters['date_from'] ?? ''));
    if ($dateFrom !== '') {
        $where[] = 'login_time >= ?';
        $params[] = $dateFrom . ' 00:00:00';
        $types .= 's';
    }

    $dateTo = trim((string)($filters['date_to'] ?? ''));
    if ($dateTo !== '') {
        $where[] = 'login_time <= ?';
        $params[] = $dateTo . ' 23:59:59';
        $types .= 's';
    }

    $whereSql = $where ? ('WHERE ' . implode(' AND ', $where)) : '';

    $countSql = "SELECT COUNT(*) c FROM login_logs $whereSql";
    $countStmt = $conn->prepare($countSql);
    if ($types !== '') {
        $countStmt->bind_param($types, ...$params);
    }
    $countStmt->execute();
    $total = (int)$countStmt->get_result()->fetch_assoc()['c'];
    $countStmt->close();

    $perPage = max(1, (int)$perPage);
    $totalPages = max(1, (int)ceil($total / $perPage));
    $page = max(1, min((int)$page, $totalPages));
    $offset = ($page - 1) * $perPage;

    $sql = "SELECT *,
                TIMESTAMPDIFF(SECOND, last_seen, NOW()) AS seconds_since_last_seen,
                TIMESTAMPDIFF(SECOND, login_time, COALESCE(logout_time, NOW())) AS duration_seconds
            FROM login_logs $whereSql
            ORDER BY login_time DESC
            LIMIT ? OFFSET ?";
    $stmt = $conn->prepare($sql);
    $allTypes = $types . 'ii';
    $allParams = $params;
    $allParams[] = $perPage;
    $allParams[] = $offset;
    $stmt->bind_param($allTypes, ...$allParams);
    $stmt->execute();
    $rows = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    $stmt->close();

    return ['rows' => $rows, 'total' => $total, 'page' => $page, 'total_pages' => $totalPages];
}
