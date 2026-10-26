<?php
// Shared OTP email-verification page — reached either right after public
// registration, or from login.php's email_verified gate for ANY role
// (User/Instructor/Admin/Superadmin all funnel through this one page).
session_start();
include '../include/db_connect.php';
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

// The URL's ?id=/?purpose= are only a one-time lookup convenience to seed
// the session on first arrival — every POST action below reads exclusively
// from session state, never from resubmitted GET/POST identifiers, so a
// tampered id/purpose in the URL can't redirect verification at anyone else.
if (empty($_SESSION['otp_id_number']) && !empty($_GET['id']) && ($_GET['purpose'] ?? '') === 'email_verification') {
    $stmt = $conn->prepare("SELECT id_number, email, role, email_verified FROM users WHERE id_number = ?");
    $stmt->bind_param("s", trim($_GET['id']));
    $stmt->execute();
    $account = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    if ($account) {
        $_SESSION['otp_id_number'] = $account['id_number'];
        $_SESSION['otp_purpose'] = 'email_verification';
        $_SESSION['otp_email'] = $account['email'];
        $_SESSION['otp_role'] = $account['role'];
    }
}

$idNumber = $_SESSION['otp_id_number'] ?? '';
$email = $_SESSION['otp_email'] ?? '';
$role = $_SESSION['otp_role'] ?? null;
$flash = null;
$justVerified = false;

$account = null;
if ($idNumber !== '') {
    $stmt = $conn->prepare("SELECT id_number, email, email_verified FROM users WHERE id_number = ?");
    $stmt->bind_param("s", $idNumber);
    $stmt->execute();
    $account = $stmt->get_result()->fetch_assoc();
    $stmt->close();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $account) {
    if (!csrf_ok()) {
        $flash = ['type' => 'err', 'text' => 'Your session has expired. Please refresh the page and try again.'];
    } else {
        $action = $_POST['action'] ?? '';
        if ($action === 'verify') {
            $code = '';
            for ($i = 1; $i <= 6; $i++) {
                $code .= preg_replace('/\D/', '', (string)($_POST["otp_$i"] ?? ''));
            }
            if (mb_strlen($code) !== 6) {
                $flash = ['type' => 'err', 'text' => 'Please enter all 6 digits.'];
            } else {
                $result = verify_otp($conn, $idNumber, 'email_verification', $code, $email, $role);
                if ($result['ok']) {
                    $upd = $conn->prepare("UPDATE users SET email_verified = 1 WHERE id_number = ?");
                    $upd->bind_param("s", $idNumber);
                    $upd->execute();
                    $justVerified = true;
                    unset($_SESSION['otp_id_number'], $_SESSION['otp_purpose'], $_SESSION['otp_email'], $_SESSION['otp_role']);
                    $account['email_verified'] = 1;
                } elseif ($result['error'] === 'locked') {
                    $flash = ['type' => 'err', 'text' => 'Too many incorrect attempts. Please request a new code.'];
                } else {
                    $flash = ['type' => 'err', 'text' => 'Incorrect or expired code. Please try again.'];
                }
            }
        } elseif ($action === 'resend') {
            $result = create_otp($conn, $idNumber, $email, 'email_verification', $role);
            if ($result['ok']) {
                $flash = ['type' => 'ok', 'text' => 'A new code has been sent to your email.'];
            } elseif ($result['error'] === 'cooldown') {
                $flash = ['type' => 'err', 'text' => 'Please wait ' . $result['retry_after'] . ' seconds before requesting another code.'];
            } else {
                $flash = ['type' => 'err', 'text' => 'Too many requests. Please try again later.'];
            }
        }
    }
}

$alreadyVerified = $account && (int)$account['email_verified'] === 1 && !$justVerified;
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Verify Your Email | CSU Instructor Registration and Management</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
<link rel="stylesheet" href="../CSS/forgot_password.css">
</head>
<body>

  <nav class="navbar navbar-expand-lg navbar-dark site-nav">
    <div class="container">
      <a class="navbar-brand site-nav__brand" href="home.php">
        <span class="site-nav__icon"><i class="bi bi-mortarboard-fill"></i></span>
        <span>CSU Instructor Registration and Management</span>
      </a>
    </div>
  </nav>

  <div class="fp-page">
    <div class="fp-hero">
      <div class="fp-hero__icon"><i class="bi bi-envelope-check-fill"></i></div>

      <?php if (!$account): ?>
        <h1>Invalid Verification Link</h1>
        <p>This verification link is invalid or has expired. Please log in — you'll be prompted to verify again if needed.</p>
        <a href="login.php" class="btn-brand">Back to Login</a>

      <?php elseif ($justVerified || $alreadyVerified): ?>
        <h1>Email Verified</h1>
        <p>Your email address has been verified. Your account is still <strong>pending approval</strong> — an Administrator or Superadmin needs to review it before you can log in.</p>
        <a href="login.php" class="btn-brand">Back to Login</a>

      <?php else: ?>
        <h1>Verify Your Email</h1>
        <p>We sent a 6-digit code to <strong><?= h($email) ?></strong>. Enter it below — this code expires in 5 minutes.</p>

        <?php if ($flash): ?>
          <div class="fp-alert"><?= h($flash['text']) ?></div>
        <?php endif; ?>

        <form method="post" id="otpForm">
          <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
          <input type="hidden" name="action" value="verify">
          <div class="otp-boxes">
            <?php for ($i = 1; $i <= 6; $i++): ?>
              <input type="text" name="otp_<?= $i ?>" class="otp-box" maxlength="1" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code">
            <?php endfor; ?>
          </div>
          <button type="submit" class="btn-brand" style="margin-top:18px;">Verify OTP</button>
        </form>

        <form method="post" id="resendForm" style="margin-top:14px;">
          <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
          <input type="hidden" name="action" value="resend">
          <button type="submit" class="btn-ghost" id="resendBtn" style="width:100%;">Resend OTP</button>
        </form>
      <?php endif; ?>
    </div>
  </div>

  <footer>&copy; <?= date('Y') ?> CSU Instructor Registration and Management. All rights reserved.</footer>

<script src="JS/otp_verify.js"></script>
</body>
</html>
