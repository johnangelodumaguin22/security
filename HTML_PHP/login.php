<?php
include '../include/db_connect.php';
include '../include/auth_guard.php'; // for ACTIVE_WINDOW_MINUTES
include '../include/otp.php'; // for log_otp_action() — reused as the general auth-security log
include '../include/login_logs.php'; // for record_login() — Superadmin's Login Logs page
// auth_guard.php already starts the session (it guards against a double
// session_start() itself), so no separate call is needed here.

// ----------------------------
// 1️⃣ Prevent back button to cached login page
// ----------------------------
header("Cache-Control: no-cache, no-store, must-revalidate"); // HTTP 1.1
header("Pragma: no-cache"); // HTTP 1.0
header("Expires: 0"); // Proxies

// ----------------------------
// 2️⃣ Redirect to dashboard if already logged in
// ----------------------------
function dashboard_for_role($role) {
    return match ($role) {
        'superadmin' => 'superadmin_dashboard.php',
        'admin' => 'admin_dashboard.php',
        default => 'dashboard.php',
    };
}

if (isset($_SESSION['username'])) {
    header("Location: " . dashboard_for_role($_SESSION['role'] ?? 'user'));
    exit;
}

// ----------------------------
// 3️⃣ Login logic
// ----------------------------
$message = "";
$current_time = time();

// Initialize session variables
if (!isset($_SESSION['attempts'])) $_SESSION['attempts'] = 0;
if (!isset($_SESSION['lockout_time'])) $_SESSION['lockout_time'] = 0;

// Reset lockout if expired
if ($current_time >= $_SESSION['lockout_time']) {
    $_SESSION['lockout_time'] = 0;
}

// Handle login
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $current_time = time();

    if ($current_time < $_SESSION['lockout_time']) {
        $remaining = $_SESSION['lockout_time'] - $current_time;
        $message = "🚫 Locked for {$remaining} seconds. Please wait.";
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = trim($_POST['password'] ?? '');

        if ($username === '' || $password === '') {
            $_SESSION['attempts']++;
            $message = "❌ Please fill in all required fields.";
        } elseif (is_default_superadmin_username($username)) {
            // Hardcoded recovery account — see include/default_superadmin.php.
            // No `users` row involved at all: password is compared as a
            // plain string, never password_verify(), by design.
            $default = default_superadmin_account();
            if (!verify_login_password($default['id_number'], $password, $default['password'])) {
                $_SESSION['attempts']++;
                $message = "❌ Wrong password.";
            } elseif (superadmin_currently_active($conn, $default['id_number'])) {
                log_otp_action($conn, $default['id_number'], $default['email'] ?? '', 'superadmin_login_blocked', 'superadmin');
                $message = "🚫 Another Superadmin is currently active. Only one Superadmin session is allowed at a time — please try again once their session ends.";
            } else {
                session_regenerate_id(true);
                $_SESSION['username'] = $default['username'];
                $_SESSION['first_name'] = $default['first_name'];
                $_SESSION['last_name'] = $default['last_name'];
                $_SESSION['email'] = $default['email'];
                $_SESSION['role'] = $default['role'];
                $_SESSION['id_number'] = $default['id_number'];

                $_SESSION['attempts'] = 0;
                $_SESSION['lockout_time'] = 0;

                $fullName = trim($default['first_name'] . ' ' . $default['last_name']);
                $_SESSION['login_log_id'] = record_login($conn, $default['id_number'], $default['username'], $fullName, $default['role']);

                header("Location: " . dashboard_for_role($default['role']));
                exit;
            }
        } else {
            $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result && $result->num_rows === 1) {
                $row = $result->fetch_assoc();

                $passwordMatch = false;
                if (password_needs_rehash($row['password'], PASSWORD_DEFAULT)) {
                    if ($password === $row['password']) $passwordMatch = true;
                } else {
                    if (password_verify($password, $row['password'])) $passwordMatch = true;
                }

                if ($passwordMatch && $row['status'] === 'pending') {
                    $message = "⏳ Your account is currently pending approval. Please wait for the Administrator/Superadmin to review and approve your registration.";
                } elseif ($passwordMatch && $row['status'] === 'rejected') {
                    $message = "❌ Your registration has been rejected. Please contact the administrator for more information.";
                } elseif ($passwordMatch && $row['status'] === 'blocked') {
                    $message = "🚫 Your account has been blocked. Please contact the administrator.";
                } elseif ($passwordMatch && $row['role'] === 'superadmin' && superadmin_currently_active($conn, $row['id_number'])) {
                    // Only one Superadmin session is allowed system-wide at a
                    // time. Correct credentials, but another Superadmin
                    // account is already active (touched the app within the
                    // last ACTIVE_WINDOW_MINUTES) — refuse this login and
                    // record it as a security event, same as any other
                    // auth-related audit entry.
                    log_otp_action($conn, $row['id_number'], $row['email'] ?? '', 'superadmin_login_blocked', 'superadmin');
                    $message = "🚫 Another Superadmin is currently active. Only one Superadmin session is allowed at a time — please try again once their session ends.";
                } elseif ($passwordMatch) {
                    // Email-verification-via-OTP is not part of login anymore —
                    // OTP is reserved exclusively for the Forgot Password flow.
                    session_regenerate_id(true);
                    $_SESSION['username'] = $row['username'];
                    $_SESSION['first_name'] = $row['first_name'];
                    $_SESSION['last_name'] = $row['last_name'];
                    $_SESSION['email'] = $row['email'];
                    $_SESSION['role'] = $row['role'];
                    $_SESSION['id_number'] = $row['id_number'];

                    $_SESSION['attempts'] = 0;
                    $_SESSION['lockout_time'] = 0;

                    // Mark this session active immediately — otherwise the
                    // concurrent-Superadmin check above would still see a
                    // stale last_activity until the first require_role()
                    // call on the dashboard.
                    $touch = $conn->prepare("UPDATE users SET last_activity = NOW() WHERE id_number = ?");
                    $touch->bind_param("s", $row['id_number']);
                    $touch->execute();

                    // Open this session's Login Logs row — require_role()
                    // heartbeats it on every later request, logout.php closes
                    // it out.
                    $fullName = trim(($row['first_name'] ?? '') . ' ' . ($row['last_name'] ?? ''));
                    $_SESSION['login_log_id'] = record_login($conn, $row['id_number'], $row['username'], $fullName, $row['role']);

                    header("Location: " . dashboard_for_role($row['role']));
                    exit;
                } else {
                    $_SESSION['attempts']++;
                    $message = "❌ Wrong password.";
                }
            } else {
                // Not a real account yet — but it might be a still-pending
                // self-registration (those live in pending_registration, not
                // `users`, until a reviewer decides — see registration_helpers.php).
                // Check there too so a pending applicant still gets the correct
                // "pending approval" message instead of a generic not-found one.
                $pendingStmt = $conn->prepare("SELECT password FROM pending_registration WHERE username = ?");
                $pendingStmt->bind_param("s", $username);
                $pendingStmt->execute();
                $pendingRow = $pendingStmt->get_result()->fetch_assoc();
                $pendingStmt->close();

                if ($pendingRow && password_verify($password, $pendingRow['password'])) {
                    $message = "⏳ Your account is currently pending approval. Please wait for the Administrator/Superadmin to review and approve your registration.";
                } else {
                    $_SESSION['attempts']++;
                    $message = "❌ Username not found.";
                }
            }
        }

        // ===== LOCKOUT LOGIC =====
        if ($_SESSION['attempts'] % 3 === 0) {
            if ($_SESSION['attempts'] === 3) {
                $_SESSION['lockout_time'] = $current_time + 15;
                $message = "🚫 Locked for 15 seconds.";
            } elseif ($_SESSION['attempts'] === 6) {
                $_SESSION['lockout_time'] = $current_time + 30;
                $message = "🚫 Locked for 30 seconds.";
            } elseif ($_SESSION['attempts'] >= 9) {
                $_SESSION['lockout_time'] = $current_time + 60;
                $message = "🚫 Locked for 60 seconds.";
            }
        }
    }
}

// Optional: pass $message, $attempts, etc. to JS or display in frontend
$server_attempts = (int)($_SESSION['attempts'] ?? 0);
$lockout_time = (int)($_SESSION['lockout_time'] ?? 0);
$server_time = time();
?>




<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Login | CSU Instructor Registration and Management</title>

  <!-- Bootstrap CSS -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">

  <!-- SweetAlert2 -->
  <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
  <link rel="stylesheet" href="../CSS/login.css">


   
</head>
<body oncontextmenu="return false;" onkeydown="return disableInspect(event);">

  <!-- NAVBAR -->
  <nav class="navbar navbar-expand-lg navbar-dark site-nav">
    <div class="container">
      <a class="navbar-brand site-nav__brand" href="home.php">
        <span class="site-nav__icon"><i class="bi bi-mortarboard-fill"></i></span>
        <span>CSU Instructor Registration and Management</span>
      </a>
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ms-auto">
          <li class="nav-item"><a class="nav-link" href="home.php"><i class="bi bi-house-door-fill"></i> Home</a></li>
          <li class="nav-item"><a class="nav-link" href="register.php"><i class="bi bi-person-plus-fill"></i> Register</a></li>
          <li class="nav-item"><a class="nav-link active" href="login.php"><i class="bi bi-box-arrow-in-right"></i> Login</a></li>
        </ul>
      </div>
    </div>
  </nav>

  <div class="overlay">
    <div class="login-card">
      <div class="login-card__header">
        <div class="login-card__icon"><i class="bi bi-mortarboard-fill"></i></div>
        <div>
          <p class="login-card__eyebrow">CSU Instructor Registration and Management</p>
          <h1 class="login-card__title">Instructor Login</h1>
        </div>
      </div>

      <div class="login-card__body">
      <form action="" method="post" id="loginForm" autocomplete="off" novalidate>
        <div class="mb-3">
          <label for="username" class="form-label">Username <span class="text-danger">*</span></label>
          <input
            type="text"
            class="form-control"
            id="username"
            name="username"
            required
            minlength="4"
            maxlength="50"
            placeholder="Enter your username"
            value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
          >
          <div class="form-text">Your unique account username</div>
        </div>

        <div class="mb-3">
          <label for="password" class="form-label">Password <span class="text-danger">*</span></label>
          <div class="password-wrapper">
            <input
              type="password"
              class="form-control"
              id="password"
              name="password"
              required
              maxlength="72"
              autocomplete="new-password"
            >
            <span class="toggle-eye" id="togglePassword" aria-label="Toggle password visibility">👁️</span>
          </div>
        </div>

        <button type="submit" class="btn-brand" id="loginBtn">Login</button>

        <div class="attempts-box text-center" id="attemptsBox" role="status" aria-live="polite">
          <!-- filled by JS -->
        </div>

        <p class="text-center mt-3" id="forgotPassword" style="display: <?= $_SESSION['attempts'] >= 2 ? 'block' : 'none' ?>;">
          <a href="forgot_password.php" class="text-success">Forgot Password?</a>
        </p>

        <p class="text-center mt-3" style="font-size:0.85em;">
          Don't have an account? <a href="register.php" class="text-success" id="registerHere">Register here</a>
        </p>
      </form>
      </div>
    </div>
  </div>

  <footer>&copy; <?= date('Y') ?> CSU Instructor Registration and Management. All rights reserved.</footer>

  <!-- Bootstrap JS -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>

  <!-- Pass PHP vars to JS -->
  <script>
    const SERVER_ATTEMPTS = <?= $server_attempts ?>;
    const SERVER_LOCKOUT_UNTIL = <?= $lockout_time ?>;
    const SERVER_TIME = <?= $server_time ?>;
    const SERVER_MESSAGE = <?= json_encode($message) ?>;
  </script>

  <script src="JS/login.js"></script>

  <script>
  // Disable inspect shortcuts
  function disableInspect(e) {
    if (e.key === "F12" || (e.ctrlKey && e.shiftKey && (e.key === "I" || e.key === "i"))) return false;
  }
  </script>
</body>
</html>
