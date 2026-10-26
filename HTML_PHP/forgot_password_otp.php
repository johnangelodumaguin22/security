<?php
// Forgot Password via Email OTP — an alternate path alongside the existing
// ID Number + security-questions flow in forgot_password.php (that flow is
// untouched). Driven entirely by the registered email address + a 6-digit
// OTP, per the spec: never reveal whether an email is registered.
include '../include/db_connect.php';
include '../include/common_passwords.php';
include '../include/otp.php';
include '../include/auth_guard.php';

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
ini_set('display_errors', '0');

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function csrf_ok() {
    return !empty($_POST['csrf_token']) && !empty($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']);
}

function is_strong_password($pwd) {
    if (preg_match('/^\s|\s$/', $pwd)) return false;
    $len = mb_strlen($pwd);
    if ($len < 8 || $len > 72) return false;
    if (isCommonWeakPassword($pwd)) return false;
    return true;
}

const FPO_RESET_WINDOW_SECONDS = 600; // 10 minutes to actually set the new password after OTP verification

$message = "";
$stage = 'enter_email';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_ok()) {
        $message = "⚠️ Your session has expired. Please refresh the page and try again.";
    } else {
        $action = $_POST['action'] ?? '';

        if ($action === 'request_otp') {
            $email = strtolower(trim((string)($_POST['email'] ?? '')));
            // Always the same response regardless of whether the email exists —
            // never reveal account existence.
            $message = "If an account is associated with this email address, a verification code has been sent.";
            if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $stmt = $conn->prepare("SELECT id_number, email, role FROM users WHERE email = ?");
                $stmt->bind_param("s", $email);
                $stmt->execute();
                $account = $stmt->get_result()->fetch_assoc();
                $stmt->close();
                if ($account) {
                    create_otp($conn, $account['id_number'], $account['email'], 'password_reset', $account['role']);
                    log_otp_action($conn, $account['id_number'], $account['email'], 'PASSWORD_RESET_REQUESTED', $account['role']);
                    $_SESSION['fpo_id_number'] = $account['id_number'];
                    $_SESSION['fpo_email'] = $account['email'];
                    $_SESSION['fpo_role'] = $account['role'];
                }
            }
            $stage = 'enter_otp';

        } elseif ($action === 'resend_otp') {
            $stage = 'enter_otp';
            if (!empty($_SESSION['fpo_id_number'])) {
                $result = create_otp($conn, $_SESSION['fpo_id_number'], $_SESSION['fpo_email'], 'password_reset', $_SESSION['fpo_role'] ?? null);
                if ($result['ok']) {
                    $message = "A new code has been sent to your email.";
                } elseif ($result['error'] === 'cooldown') {
                    $message = "Please wait " . $result['retry_after'] . " seconds before requesting another code.";
                } else {
                    $message = "Too many requests. Please try again later.";
                }
            } else {
                // No real account behind this session — same generic message either way.
                $message = "If an account is associated with this email address, a verification code has been sent.";
            }

        } elseif ($action === 'verify_otp') {
            $stage = 'enter_otp';
            $code = '';
            for ($i = 1; $i <= 6; $i++) {
                $code .= preg_replace('/\D/', '', (string)($_POST["otp_$i"] ?? ''));
            }
            if (empty($_SESSION['fpo_id_number'])) {
                $message = "❌ Invalid or expired code. Please request a new one.";
            } elseif (mb_strlen($code) !== 6) {
                $message = "⚠️ Please enter all 6 digits.";
            } else {
                $result = verify_otp($conn, $_SESSION['fpo_id_number'], 'password_reset', $code, $_SESSION['fpo_email'] ?? null, $_SESSION['fpo_role'] ?? null);
                if ($result['ok']) {
                    // Server-side "temporary reset session" — never a client-controlled
                    // URL flag. Expires on its own even if the user never submits step 3.
                    $_SESSION['fpo_reset_verified_until'] = time() + FPO_RESET_WINDOW_SECONDS;
                    $stage = 'reset_password';
                    $message = "✅ Code verified. You may now set a new password.";
                } elseif ($result['error'] === 'locked') {
                    $message = "❌ Too many incorrect attempts. Please request a new code.";
                } else {
                    $message = "❌ Incorrect or expired code. Please try again.";
                }
            }

        } elseif ($action === 'reset_password') {
            $verifiedUntil = $_SESSION['fpo_reset_verified_until'] ?? 0;
            if (empty($_SESSION['fpo_id_number']) || time() > $verifiedUntil) {
                $message = "⚠️ Your verification has expired. Please start again.";
                $stage = 'enter_email';
                unset($_SESSION['fpo_id_number'], $_SESSION['fpo_email'], $_SESSION['fpo_role'], $_SESSION['fpo_reset_verified_until']);
            } else {
                $newPassword = $_POST['newPassword'] ?? '';
                $confirm = $_POST['confirmPassword'] ?? '';
                $stage = 'reset_password';
                if ($newPassword === '' || $confirm === '') {
                    $message = "⚠️ Fill both password fields.";
                } elseif ($newPassword !== $confirm) {
                    $message = "❌ Passwords do not match.";
                } elseif (!is_strong_password($newPassword)) {
                    $message = "❌ Password does not meet strength requirements.";
                } else {
                    $hashed = password_hash($newPassword, PASSWORD_DEFAULT);
                    $stmt = $conn->prepare("UPDATE users SET password = ? WHERE id_number = ?");
                    $stmt->bind_param("ss", $hashed, $_SESSION['fpo_id_number']);
                    $stmt->execute();
                    log_otp_action($conn, $_SESSION['fpo_id_number'], $_SESSION['fpo_email'] ?? '', 'PASSWORD_RESET_SUCCESSFUL', $_SESSION['fpo_role'] ?? null);
                    unset($_SESSION['fpo_id_number'], $_SESSION['fpo_email'], $_SESSION['fpo_role'], $_SESSION['fpo_reset_verified_until']);
                    $stage = 'done';
                    $message = "✅ Your password has been successfully reset. You may now log in.";
                }
            }
        }
    }
}

$autoOpenModal = ($_SERVER['REQUEST_METHOD'] === 'POST') || isset($_SESSION['fpo_id_number']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Forgot Password (Email OTP) | CSU Instructor Registration and Management</title>

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
<link rel="stylesheet" href="../CSS/forgot_password.css">
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
</head>

<body>

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
          <li class="nav-item"><a class="nav-link" href="login.php"><i class="bi bi-box-arrow-in-right"></i> Login</a></li>
        </ul>
      </div>
    </div>
  </nav>

  <div class="fp-page">
    <div class="fp-hero">
      <div class="fp-hero__icon"><i class="bi bi-envelope-check-fill"></i></div>
      <h1>Forgot Password (Email OTP)</h1>
      <p>Enter your registered email to receive a one-time verification code and reset your password.</p>

      <button type="button" class="btn-brand" data-bs-toggle="modal" data-bs-target="#fpModal">
        <i class="bi bi-key-fill"></i> Send OTP
      </button>

      <a href="login.php" class="fp-hero__back"><i class="bi bi-arrow-left"></i> Back to Login</a>
    </div>
  </div>

  <footer>&copy; <?= date('Y') ?> CSU Instructor Registration and Management. All rights reserved.</footer>

  <!-- RESET FLOW MODAL -->
  <div class="modal fade" id="fpModal" tabindex="-1" aria-hidden="true" data-bs-backdrop="static">
    <div class="modal-dialog modal-dialog-centered modal-dialog-scrollable">
      <div class="modal-content">
        <div class="fp-modal__header">
          <div class="fp-modal__icon"><i class="bi bi-envelope-check-fill"></i></div>
          <div>
            <p class="fp-modal__eyebrow">CSU Instructor Registration and Management</p>
            <h5 class="fp-modal__title">Reset via Email OTP</h5>
          </div>
          <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>

        <div class="fp-modal__body">
          <?php if (!empty($message)): ?>
            <div class="fp-alert"><?= h($message) ?></div>
          <?php endif; ?>

          <!-- STEP 1: Enter email -->
          <?php if ($stage === 'enter_email'): ?>
            <form method="post" novalidate>
              <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
              <div class="mb-3 text-start">
                <label class="form-label">Registered Email <span class="text-danger">*</span></label>
                <input type="email" name="email" class="form-control" placeholder="you@csucc.edu.ph" required>
              </div>
              <button type="submit" name="action" value="request_otp" class="btn-brand w-100">Send OTP</button>
            </form>
          <?php endif; ?>

          <!-- STEP 2: Enter OTP -->
          <?php if ($stage === 'enter_otp'): ?>
            <form method="post" id="otpForm">
              <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
              <input type="hidden" name="action" value="verify_otp">
              <div class="otp-boxes mb-3">
                <?php for ($i = 1; $i <= 6; $i++): ?>
                  <input type="text" name="otp_<?= $i ?>" class="otp-box" maxlength="1" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code">
                <?php endfor; ?>
              </div>
              <button type="submit" class="btn-brand w-100">Verify OTP</button>
            </form>
            <form method="post" id="resendForm" style="margin-top:10px;">
              <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
              <input type="hidden" name="action" value="resend_otp">
              <button type="submit" class="btn-ghost" id="resendBtn" style="width:100%;">Resend OTP</button>
            </form>
          <?php endif; ?>

          <!-- STEP 3: Reset password -->
          <?php if ($stage === 'reset_password' || $stage === 'done'): ?>
            <form method="post" id="resetForm" novalidate>
              <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
              <input type="hidden" name="action" value="reset_password">
              <div class="mb-3 text-start">
                <label class="form-label">New Password</label>
                <div class="input-group">
                  <input type="password" name="newPassword" id="newPassword" class="form-control" placeholder="New password" autocomplete="new-password" minlength="8" maxlength="72" required>
                  <span class="input-group-text show-hide-btn" id="toggleNew"><i class="bi bi-eye-fill"></i></span>
                </div>
                <small id="strengthText" class="form-text">Password must be at least 8 characters.</small>
                <div class="strength-bar" aria-hidden="true">
                  <div class="strength-fill" id="strengthFill"></div>
                </div>
                <ul class="mt-2 mb-0" id="pwChecklist" style="list-style:none;padding-left:0;">
                  <li id="chLen">❌ At least 8 characters</li>
                  <li id="chCommon">❌ Not a commonly used password</li>
                </ul>
              </div>
              <div class="mb-3 text-start">
                <label class="form-label">Re-enter Password</label>
                <div class="input-group">
                  <input type="password" name="confirmPassword" id="confirmPassword" class="form-control" placeholder="Re-enter new password" maxlength="72" required>
                  <span class="input-group-text show-hide-btn" id="toggleConfirm"><i class="bi bi-eye-fill"></i></span>
                </div>
              </div>
              <button type="submit" id="resetBtn" class="btn-brand w-100" disabled>Reset Password</button>
            </form>
          <?php endif; ?>
        </div>
      </div>
    </div>
  </div>

<script>
const PHP_STAGE = <?php echo json_encode($stage); ?>;
const PHP_DONE = <?php echo json_encode($stage === 'done'); ?>;
const AUTO_OPEN_MODAL = <?php echo json_encode($autoOpenModal); ?>;
</script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script src="JS/otp_verify.js"></script>
<script src="JS/forgot_password.js"></script>
</body>
</html>
