<?php
// Shared role gate for dashboard.php / admin_dashboard.php / superadmin_dashboard.php.
// Call require_role() before rendering anything sensitive.
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

// Short escape helper — both dashboards render a lot of user-submitted free
// text (names, addresses, delete-request reasons) into authenticated pages,
// so every dynamic value must go through this before being echoed.
function h($v) {
    return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8');
}

// How recently an account must have touched a protected page to count as
// "active now" for the Superadmin's live-activity indicator.
const ACTIVE_WINDOW_MINUTES = 5;

// The one built-in recovery Superadmin account. Unlike every other account,
// it has NO row in the `users` table at all — its identity/credentials live
// entirely in include/default_superadmin.php, so it keeps working even if
// the database is wiped, restored from an old backup, or every real
// Superadmin is ever locked out. See that file to change its username or
// password (plain edit, no hashing step needed).
$GLOBALS['__default_superadmin'] = require __DIR__ . '/default_superadmin.php';
define('DEFAULT_SUPERADMIN_ID', $GLOBALS['__default_superadmin']['id_number']);

function default_superadmin_account() {
    return $GLOBALS['__default_superadmin'];
}

function is_default_superadmin_username($username) {
    return hash_equals(default_superadmin_account()['username'], (string)$username);
}

// Verifies a login/re-auth password for either kind of account: the
// hardcoded recovery Superadmin (plain-string compare against
// include/default_superadmin.php — no hash exists for it, by design) or a
// normal DB-backed account ($storedValue is its bcrypt hash, checked the
// usual way).
function verify_login_password($idNumber, $suppliedPassword, $storedValue) {
    if ($idNumber === DEFAULT_SUPERADMIN_ID) {
        return hash_equals((string)$storedValue, (string)$suppliedPassword);
    }
    return password_verify((string)$suppliedPassword, (string)$storedValue);
}

// Same shape as a `users` row (fetch_any_account()'s return value), for
// whichever page needs to render/act on "my own account" without caring
// whether the logged-in Superadmin is a real DB row or the hardcoded one.
function resolve_self_account($conn, $idNumber) {
    if ($idNumber === DEFAULT_SUPERADMIN_ID) {
        return default_superadmin_account();
    }
    $stmt = $conn->prepare("SELECT * FROM users WHERE id_number = ?");
    $stmt->bind_param("s", $idNumber);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    return $row ?: null;
}

// Both take $secondsSinceActivity — computed in SQL via
// TIMESTAMPDIFF(SECOND, last_activity, NOW()), never in PHP. MySQL's clock
// and PHP's date.timezone are configured independently on this box (MySQL
// follows the OS, PHP is pinned to a fixed zone), so comparing a MySQL
// timestamp string against PHP's time()/strtotime() silently produces a
// several-hour skew. Doing the subtraction entirely inside MySQL sidesteps
// the mismatch rather than trying to reconcile the two zones.
function is_account_active($secondsSinceActivity) {
    if ($secondsSinceActivity === null) return false;
    return $secondsSinceActivity <= ACTIVE_WINDOW_MINUTES * 60;
}

// Human-friendly "last seen" text for the Accounts table — never exposes
// exact timestamps down to the second, just enough to answer "are they on
// right now, or how long ago were they."
function format_last_seen($secondsSinceActivity) {
    if ($secondsSinceActivity === null) return 'Never logged in';
    if (is_account_active($secondsSinceActivity)) return 'Active now';
    $diff = (int)$secondsSinceActivity;
    if ($diff < 3600) {
        $mins = max(1, (int)floor($diff / 60));
        return $mins . ' min' . ($mins === 1 ? '' : 's') . ' ago';
    }
    if ($diff < 86400) {
        $hrs = (int)floor($diff / 3600);
        return $hrs . ' hr' . ($hrs === 1 ? '' : 's') . ' ago';
    }
    $days = (int)floor($diff / 86400);
    return $days . ' day' . ($days === 1 ? '' : 's') . ' ago';
}

// Whether some OTHER Superadmin account (not $excludeIdNumber) has touched
// the app within the last ACTIVE_WINDOW_MINUTES. Used at login time (see
// login.php) to enforce "only one Superadmin session system-wide at a
// time" — reuses the exact same activity signal as the "active now"
// indicator above rather than introducing a separate session/token system.
// Activity label for the Accounts table. Superadmin accounts get a plain
// binary Active/INACTIVE label instead of the generic "N mins/hrs/days ago"
// wording below — since only one Superadmin session is ever allowed active
// at a time (see superadmin_currently_active() below and login.php), "how
// long ago" is less meaningful for this role than a clear active/inactive
// state.
function activity_status_label($role, $secondsSinceActivity) {
    if ($role === 'superadmin') {
        return is_account_active($secondsSinceActivity) ? 'Active' : 'INACTIVE';
    }
    return format_last_seen($secondsSinceActivity);
}

function superadmin_currently_active($conn, $excludeIdNumber) {
    $stmt = $conn->prepare("SELECT 1 FROM users WHERE role = 'superadmin' AND id_number != ? AND last_activity >= (NOW() - INTERVAL " . ACTIVE_WINDOW_MINUTES . " MINUTE) LIMIT 1");
    $stmt->bind_param("s", $excludeIdNumber);
    $stmt->execute();
    $found = (bool)$stmt->get_result()->fetch_row();
    $stmt->close();
    return $found;
}

function require_role(array $allowedRoles) {
    if (empty($_SESSION['username']) || empty($_SESSION['role'])) {
        header('Location: login.php');
        exit;
    }

    global $conn;

    // Re-derive role/status from the database on every single request —
    // session state is a cache of these two columns, never the source of
    // truth. A promotion, demotion, reactivation, or block performed by a
    // Superadmin against a *live* session must take effect on that
    // session's very next navigation, with no logout/re-login step: this
    // is what makes that possible, and it runs before the allowed-roles
    // check below so a role change also routes the session to its new
    // correct dashboard immediately.
    if (!empty($_SESSION['id_number']) && $_SESSION['id_number'] === DEFAULT_SUPERADMIN_ID) {
        // Hardcoded recovery account — no `users` row to re-sync from or to
        // ever go missing/blocked. Always superadmin/approved by definition.
        $freshAccount = default_superadmin_account();
        $_SESSION['role'] = $freshAccount['role'];
        $_SESSION['username'] = $freshAccount['username'];
    } elseif (!empty($_SESSION['id_number'])) {
        $stmt = $conn->prepare("SELECT role, status, profile_status, question1, username FROM users WHERE id_number = ?");
        $stmt->bind_param("s", $_SESSION['id_number']);
        $stmt->execute();
        $freshAccount = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$freshAccount) {
            // Deleted mid-session.
            session_unset();
            session_destroy();
            header('Location: login.php');
            exit;
        }

        if ($freshAccount['status'] !== 'approved') {
            // Blocked/rejected mid-session (e.g. another Superadmin just
            // blocked or demoted-then-blocked this account) — end the
            // session immediately rather than letting stale $_SESSION
            // state keep it alive until natural expiry.
            session_unset();
            session_destroy();
            header('Location: login.php');
            exit;
        }

        $_SESSION['role'] = $freshAccount['role'];
        // A self-service username change (see superadmin_dashboard.php)
        // already updates the current request's session directly; this
        // keeps any OTHER live session/tab for the same account in sync too.
        $_SESSION['username'] = $freshAccount['username'];
    }

    if (!in_array($_SESSION['role'], $allowedRoles, true)) {
        // Logged in, but the wrong tier for this page — send them to the page
        // that matches their actual (possibly just-changed) role rather than
        // a bare error.
        $home = match ($_SESSION['role']) {
            'superadmin' => 'superadmin_dashboard.php',
            'admin' => 'admin_dashboard.php',
            default => 'dashboard.php',
        };
        header('Location: ' . $home);
        exit;
    }

    // Touch last_activity on every authenticated page view — this is the
    // entire mechanism behind the Superadmin's "who's active right now"
    // indicator. No heartbeat/AJAX needed: any navigation refreshes it.
    // Skipped for the hardcoded recovery account — it has no `users` row to
    // update.
    if (!empty($_SESSION['id_number']) && $_SESSION['id_number'] !== DEFAULT_SUPERADMIN_ID) {
        $stmt = $conn->prepare("UPDATE users SET last_activity = NOW() WHERE id_number = ?");
        $stmt->bind_param("s", $_SESSION['id_number']);
        $stmt->execute();
    }

    // Same heartbeat, scoped to this one login session's Login Logs row —
    // keeps "last thing they touched" current for the Superadmin's Login
    // Logs view. Requires include/login_logs.php to already be loaded by
    // whichever page called require_role(); silently skipped otherwise so
    // this never becomes a hard dependency of the shared auth guard.
    if (!empty($_SESSION['login_log_id']) && function_exists('touch_login_log')) {
        touch_login_log($conn, $_SESSION['login_log_id'], function_exists('current_page_label') ? current_page_label() : null);
    }

    // A bare Admin/Superadmin account (created via Superadmin's Create
    // Account form with just a username/password, no confidential profile
    // info yet) must complete that profile before reaching any protected
    // page. Re-checked against the database on every single load — never
    // trusted from session state alone — so this cannot be bypassed by a
    // direct dashboard URL, a stale session, the back button, or closing
    // the completion page without finishing it.
    if (in_array($_SESSION['role'], ['admin', 'superadmin'], true) && !empty($freshAccount)) {
        if ($freshAccount['profile_status'] === 'incomplete') {
            header('Location: complete_profile.php');
            exit;
        }

        // Admin/Superadmin accounts used to be exempt from security
        // questions entirely (OTP-only recovery). That exemption is
        // retired — every Admin/Superadmin must have them now, regardless
        // of how the account was created. A completed profile with no
        // question1 means this account predates the requirement (or came
        // through a creation path that doesn't collect them), so it gets
        // one more mandatory one-time stop before the dashboard. Re-checked
        // against the database on every load, same as the profile-status
        // gate above, so it can't be bypassed by a stale session or a
        // direct dashboard URL.
        if ($freshAccount['profile_status'] === 'complete' && $freshAccount['question1'] === '') {
            header('Location: set_security_questions.php');
            exit;
        }
    }
}
