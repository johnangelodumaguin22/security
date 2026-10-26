<?php
session_start();
include '../include/db_connect.php';
include '../include/login_logs.php'; // for close_login_log()

// ----------------------------
// Free up this account's "active" slot immediately (rather than waiting out
// ACTIVE_WINDOW_MINUTES) — most importantly, this is what lets another
// Superadmin log in right away after this one explicitly logs out, instead
// of having to wait for the activity window to lapse on its own.
// ----------------------------
if (!empty($_SESSION['id_number'])) {
    $stmt = $conn->prepare("UPDATE users SET last_activity = NULL WHERE id_number = ?");
    $stmt->bind_param("s", $_SESSION['id_number']);
    $stmt->execute();
}

// Close out this session's Login Logs row with an explicit logout time.
if (!empty($_SESSION['login_log_id'])) {
    close_login_log($conn, $_SESSION['login_log_id']);
}

// ----------------------------
// Clear all session variables
// ----------------------------
$_SESSION = array();

// ----------------------------
// Destroy session
// ----------------------------
session_destroy();

// ----------------------------
// Remove session cookie (recommended)
// ----------------------------
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// ----------------------------
// Prevent browser caching
// ----------------------------
header("Cache-Control: no-cache, no-store, must-revalidate"); // HTTP 1.1
header("Pragma: no-cache"); // HTTP 1.0
header("Expires: 0"); // Proxies

// ----------------------------
// Redirect to login page
// ----------------------------
header("Location: login.php");
exit;
?>
