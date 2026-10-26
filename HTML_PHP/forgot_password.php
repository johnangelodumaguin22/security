<?php
// 3-step account-recovery flow:
//   1. Employee ID
//   2. Verify identity — the account holder CHOOSES either Email OTP or
//      Security Questions (whichever they can actually complete); only one
//      of the two is required, not both. An account with no security
//      questions on file skips the choice entirely — Email OTP is its only
//      option, and the code is sent automatically right after step 1.
//   3. New Password
// Every stage is derived from SERVER-SIDE session state (pr_current_stage()
// below), never from a client-supplied step/stage parameter, so a stage
// can never be reached — including by directly re-requesting this page —
// without the prior stage's condition already being true in $_SESSION.
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
    // Kept light on purpose: a sane length range plus the shared weak-password
    // blacklist, no forced character-class mix. 72 is bcrypt's (PASSWORD_DEFAULT)
    // input limit — anything longer would be silently truncated when hashed.
    if (preg_match('/^\s|\s$/', $pwd)) return false;
    $len = mb_strlen($pwd);
    if ($len < 8 || $len > 72) return false;
    if (isCommonWeakPassword($pwd)) return false;
    return true;
}

// "j******@gmail.com" — never the full registered address, anywhere in this flow.
function mask_email($email) {
    $at = strpos($email, '@');
    if ($at === false || $at === 0) return str_repeat('*', 6);
    $local = substr($email, 0, $at);
    $domain = substr($email, $at);
    $visible = mb_substr($local, 0, 1, 'UTF-8');
    $maskLen = min(8, max(3, mb_strlen($local, 'UTF-8') - 1));
    return $visible . str_repeat('*', $maskLen) . $domain;
}

// -----------------------------------------------------------------
// Session-scoped escalating lockouts for the two guessable-by-brute-force
// steps this flow adds on top of OTP (which already rate-limits itself in
// include/otp.php — 5 wrong codes locks it, resend has a cooldown + a
// 30-minute cap). Same shape as the lockout already used on login.php.
// -----------------------------------------------------------------
function pr_lock_status($attemptsKey, $lockoutKey) {
    if (!isset($_SESSION[$attemptsKey])) $_SESSION[$attemptsKey] = 0;
    if (!isset($_SESSION[$lockoutKey])) $_SESSION[$lockoutKey] = 0;
    $remaining = $_SESSION[$lockoutKey] - time();
    if ($remaining <= 0) {
        $_SESSION[$lockoutKey] = 0;
        return 0;
    }
    return $remaining;
}
function pr_lock_hit($attemptsKey, $lockoutKey) {
    $_SESSION[$attemptsKey]++;
    $n = $_SESSION[$attemptsKey];
    if ($n >= 9) $_SESSION[$lockoutKey] = time() + 120;
    elseif ($n >= 6) $_SESSION[$lockoutKey] = time() + 45;
    elseif ($n >= 3) $_SESSION[$lockoutKey] = time() + 15;
}
function pr_lock_reset($attemptsKey, $lockoutKey) {
    $_SESSION[$attemptsKey] = 0;
    $_SESSION[$lockoutKey] = 0;
}

// -----------------------------------------------------------------
// The entire multi-step gate. Called after processing any POST, and on
// every plain GET — the visible stage is always recomputed from what's
// actually true in the session, never trusted from the request.
// -----------------------------------------------------------------
function pr_current_stage() {
    if (empty($_SESSION['pr_id_number'])) return 'enter_id';
    if (!empty($_SESSION['pr_otp_verified']) || !empty($_SESSION['pr_questions_verified'])) return 'reset_password';

    // No security questions on file at all — Email OTP is the only option,
    // so there's nothing to choose; request_reset() already sent the code.
    if (empty($_SESSION['pr_needs_questions'])) return 'enter_otp';

    if (empty($_SESSION['pr_verify_method'])) return 'choose_method';
    return $_SESSION['pr_verify_method'] === 'otp' ? 'enter_otp' : 'answer_questions';
}

function pr_reset_session() {
    foreach (['pr_id_number', 'pr_email', 'pr_role', 'pr_needs_questions',
              'pr_question1', 'pr_question2', 'pr_question3', 'pr_verify_method',
              'pr_otp_verified', 'pr_questions_verified'] as $k) {
        unset($_SESSION[$k]);
    }
}

$message = "";

// Fired by JS the moment the visitor closes the modal (X button or Escape)
// without finishing the flow — abandoning it mid-way must not leave a
// resumable session behind. Answered as a bare ack, not the full page, since
// it's sent fire-and-forget from a beforeunload-adjacent event and nothing
// reads the response body. Rate-limit counters (pr_id_attempts, pr_q_attempts
// and their lockouts) are deliberately NOT cleared here — cancelling and
// reopening must not be a way to dodge the brute-force lockout.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'cancel_reset') {
    if (csrf_ok()) {
        pr_reset_session();
    }
    header('Content-Type: text/plain');
    echo 'ok';
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_ok()) {
        $message = "⚠️ Your session has expired. Please refresh the page and try again.";
    } else {
        $action = $_POST['action'] ?? '';

        // ---- Step 1: Employee ID -> look up the registered email ----
        // No OTP is sent here anymore — that only happens once the account
        // holder actually picks Email OTP as their verification method (see
        // 'choose_verify_method' below), except when an account has no
        // security questions on file at all, in which case OTP is the only
        // possible path and there's nothing left to choose.
        if ($action === 'request_reset') {
            $idLock = pr_lock_status('pr_id_attempts', 'pr_id_lockout_until');
            if ($idLock > 0) {
                $message = "🚫 Too many attempts. Please wait {$idLock} seconds and try again.";
            } else {
                $id_number = trim((string)($_POST['id_number'] ?? ''));
                if ($id_number === '') {
                    $message = "⚠️ Please enter your Employee ID.";
                } else {
                    $stmt = $conn->prepare("SELECT id_number, email, role, status, question1, question2, question3 FROM users WHERE id_number = ?");
                    $stmt->bind_param("s", $id_number);
                    $stmt->execute();
                    $account = $stmt->get_result()->fetch_assoc();
                    $stmt->close();

                    // Blocked accounts get their own explicit message — the
                    // account holder needs to know to contact an administrator
                    // rather than assume they mistyped their Employee ID. Named
                    // after the account's actual status (currently only
                    // "blocked" exists in the users.status enum) rather than a
                    // vague combined term, so it stays accurate if another
                    // inactive status is ever added later. Every other
                    // non-recoverable case (doesn't exist, still pending,
                    // rejected, or simply has no email on file) keeps the same
                    // generic message as before — never reveal which of those
                    // it was.
                    if ($account && $account['status'] === 'blocked') {
                        pr_lock_hit('pr_id_attempts', 'pr_id_lockout_until');
                        $message = "🚫 This account has been " . $account['status'] . ". Please contact the system administrator.";
                    } elseif (!$account || $account['status'] !== 'approved' || empty($account['email'])) {
                        pr_lock_hit('pr_id_attempts', 'pr_id_lockout_until');
                        $message = "Unable to process your request. Please check your Employee ID and try again.";
                    } else {
                        pr_lock_reset('pr_id_attempts', 'pr_id_lockout_until');
                        pr_reset_session();
                        $_SESSION['pr_id_number'] = $account['id_number'];
                        $_SESSION['pr_email'] = $account['email'];
                        $_SESSION['pr_role'] = $account['role'];
                        $_SESSION['pr_needs_questions'] = ($account['question1'] !== '');
                        $_SESSION['pr_question1'] = $account['question1'];
                        $_SESSION['pr_question2'] = $account['question2'];
                        $_SESSION['pr_question3'] = $account['question3'];

                        log_otp_action($conn, $account['id_number'], $account['email'], 'PASSWORD_RESET_REQUESTED', $account['role']);

                        if ($_SESSION['pr_needs_questions']) {
                            $message = "Choose how you'd like to verify it's you.";
                        } else {
                            // No security questions on file — nothing to choose.
                            $_SESSION['pr_verify_method'] = 'otp';
                            create_otp($conn, $account['id_number'], $account['email'], 'password_reset', $account['role']);
                            $message = "A verification code has been sent to " . mask_email($account['email']) . ".";
                        }
                    }
                }
            }

        // ---- Step 2 (choice): pick Email OTP or Security Questions ----
        } elseif ($action === 'choose_verify_method') {
            if (empty($_SESSION['pr_id_number'])) {
                $message = "⚠️ Your session has expired. Please start again.";
            } else {
                $method = $_POST['method'] ?? '';
                if (!in_array($method, ['otp', 'questions'], true)) {
                    $message = "⚠️ Please choose a verification method.";
                } elseif ($method === 'questions' && empty($_SESSION['pr_needs_questions'])) {
                    $message = "⚠️ Security questions aren't set up for this account. Please use Email OTP instead.";
                } else {
                    $_SESSION['pr_verify_method'] = $method;
                    if ($method === 'otp') {
                        create_otp($conn, $_SESSION['pr_id_number'], $_SESSION['pr_email'], 'password_reset', $_SESSION['pr_role'] ?? null);
                        $message = "A verification code has been sent to " . mask_email($_SESSION['pr_email']) . ".";
                    } else {
                        $message = "Select each question the way you originally set it up, then enter its answer.";
                    }
                }
            }

        // Lets the account holder back out of whichever method they picked
        // and choose the other one instead — e.g. they started Security
        // Questions but don't actually remember the answers.
        } elseif ($action === 'switch_verify_method') {
            if (!empty($_SESSION['pr_id_number']) && !empty($_SESSION['pr_needs_questions'])) {
                unset($_SESSION['pr_verify_method']);
                $message = "Choose how you'd like to verify it's you.";
            }

        // ---- Step 2 (Email OTP path): resend OTP ----
        } elseif ($action === 'resend_otp') {
            if (empty($_SESSION['pr_id_number'])) {
                $message = "⚠️ Your session has expired. Please start again.";
            } else {
                $result = create_otp($conn, $_SESSION['pr_id_number'], $_SESSION['pr_email'], 'password_reset', $_SESSION['pr_role'] ?? null);
                if ($result['ok']) {
                    $message = "A new code has been sent to " . mask_email($_SESSION['pr_email']) . ".";
                } elseif ($result['error'] === 'cooldown') {
                    $message = "Please wait " . $result['retry_after'] . " seconds before requesting another code.";
                } else {
                    $message = "Too many requests. Please try again later.";
                }
            }

        // ---- Step 2 (Email OTP path): verify the code ----
        } elseif ($action === 'verify_otp') {
            if (empty($_SESSION['pr_id_number'])) {
                $message = "⚠️ Your session has expired. Please start again.";
            } else {
                $code = '';
                for ($i = 1; $i <= 6; $i++) {
                    $code .= preg_replace('/\D/', '', (string)($_POST["otp_$i"] ?? ''));
                }
                if (mb_strlen($code) !== 6) {
                    $message = "⚠️ Please enter all 6 digits.";
                } else {
                    $result = verify_otp($conn, $_SESSION['pr_id_number'], 'password_reset', $code, $_SESSION['pr_email'], $_SESSION['pr_role'] ?? null);
                    if ($result['ok']) {
                        $_SESSION['pr_otp_verified'] = true;
                        $message = "✅ Code verified. You may now set a new password.";
                    } elseif ($result['error'] === 'locked') {
                        $message = "❌ Too many incorrect attempts. Please request a new code.";
                    } else {
                        $message = "❌ Incorrect or expired code. Please try again.";
                    }
                }
            }

        // ---- Step 2 (Security Questions path): all 3 required ----
        } elseif ($action === 'verify_questions') {
            if (empty($_SESSION['pr_id_number'])) {
                $message = "⚠️ Please complete the previous steps first.";
            } else {
                $qLock = pr_lock_status('pr_q_attempts', 'pr_q_lockout_until');
                if ($qLock > 0) {
                    $message = "🚫 Too many attempts. Please wait {$qLock} seconds and try again.";
                } else {
                    $q1 = trim((string)($_POST['q1'] ?? ''));
                    $q2 = trim((string)($_POST['q2'] ?? ''));
                    $q3 = trim((string)($_POST['q3'] ?? ''));
                    $a1 = trim((string)($_POST['a1'] ?? ''));
                    $a2 = trim((string)($_POST['a2'] ?? ''));
                    $a3 = trim((string)($_POST['a3'] ?? ''));

                    $stmt = $conn->prepare("SELECT answer1, answer2, answer3 FROM users WHERE id_number = ?");
                    $stmt->bind_param("s", $_SESSION['pr_id_number']);
                    $stmt->execute();
                    $row = $stmt->get_result()->fetch_assoc();
                    $stmt->close();

                    // Case-insensitive, trimmed comparison — normalized without
                    // being weakened (still a full password_verify per answer,
                    // never a plain string compare).
                    $checkVariant = function ($input, $hash) {
                        if ($input === '' || $hash === '') return false;
                        foreach ([$input, mb_strtolower($input, 'UTF-8')] as $t) {
                            if (password_verify($t, $hash)) return true;
                        }
                        return false;
                    };

                    // The question dropdowns are never pre-filled with which
                    // question this account actually has on file (see the
                    // form below) — the account holder must pick the right
                    // one themselves for each slot, same as the answer, so
                    // picking the wrong question fails this step even with
                    // a correct-looking answer typed into the wrong slot.
                    $allCorrect = $row
                        && $q1 !== '' && $q1 === ($_SESSION['pr_question1'] ?? '')
                        && $q2 !== '' && $q2 === ($_SESSION['pr_question2'] ?? '')
                        && $q3 !== '' && $q3 === ($_SESSION['pr_question3'] ?? '')
                        && $checkVariant($a1, $row['answer1'])
                        && $checkVariant($a2, $row['answer2'])
                        && $checkVariant($a3, $row['answer3']);

                    if ($allCorrect) {
                        pr_lock_reset('pr_q_attempts', 'pr_q_lockout_until');
                        $_SESSION['pr_questions_verified'] = true;
                        log_otp_action($conn, $_SESSION['pr_id_number'], $_SESSION['pr_email'], 'SECURITY_QUESTIONS_VERIFIED', $_SESSION['pr_role'] ?? null);
                        $message = "✅ Verification successful. You may now reset your password.";
                    } else {
                        pr_lock_hit('pr_q_attempts', 'pr_q_lockout_until');
                        log_otp_action($conn, $_SESSION['pr_id_number'], $_SESSION['pr_email'], 'SECURITY_QUESTIONS_FAILED', $_SESSION['pr_role'] ?? null);
                        $message = "❌ One or more answers are incorrect. Please try again.";
                    }
                }
            }

        // ---- Step 3: set new password ----
        } elseif ($action === 'reset_password') {
            // Either verification path is sufficient — they're alternatives,
            // not a required chain.
            $ready = !empty($_SESSION['pr_id_number'])
                     && (!empty($_SESSION['pr_otp_verified']) || !empty($_SESSION['pr_questions_verified']));
            if (!$ready) {
                // Someone reached this branch without having satisfied every
                // prior gate — e.g. by POSTing here directly. Bounce them back
                // to the start rather than touching any password.
                $message = "⚠️ Please complete the previous verification steps first.";
                pr_reset_session();
            } else {
                $newPassword = $_POST['newPassword'] ?? '';
                $confirm = $_POST['confirmPassword'] ?? '';
                if ($newPassword === '' || $confirm === '') {
                    $message = "⚠️ Fill both password fields.";
                } elseif ($newPassword !== $confirm) {
                    $message = "❌ Passwords do not match.";
                } elseif (!is_strong_password($newPassword)) {
                    $message = "❌ Password does not meet strength requirements.";
                } else {
                    $stmt = $conn->prepare("SELECT password FROM users WHERE id_number = ?");
                    $stmt->bind_param("s", $_SESSION['pr_id_number']);
                    $stmt->execute();
                    $current = $stmt->get_result()->fetch_assoc();
                    $stmt->close();

                    if ($current && password_verify($newPassword, $current['password'])) {
                        $message = "❌ New password must be different from your current password.";
                    } else {
                        $hashed = password_hash($newPassword, PASSWORD_DEFAULT);
                        $upd = $conn->prepare("UPDATE users SET password = ? WHERE id_number = ?");
                        $upd->bind_param("ss", $hashed, $_SESSION['pr_id_number']);
                        $upd->execute();
                        log_otp_action($conn, $_SESSION['pr_id_number'], $_SESSION['pr_email'], 'PASSWORD_RESET_SUCCESSFUL', $_SESSION['pr_role'] ?? null);

                        pr_reset_session();
                        pr_lock_reset('pr_id_attempts', 'pr_id_lockout_until');
                        pr_lock_reset('pr_q_attempts', 'pr_q_lockout_until');
                        $_SESSION['pr_done'] = true;
                        $message = "✅ Your password has been successfully reset. You may now log in using your new password.";
                    }
                }
            }
        }
    }
}

$stage = !empty($_SESSION['pr_done']) ? 'done' : pr_current_stage();
if ($stage === 'done') unset($_SESSION['pr_done']);

$maskedEmail = !empty($_SESSION['pr_email']) ? mask_email($_SESSION['pr_email']) : '';

// Step indicator — 3 steps. "Verify Identity" covers the choice screen plus
// whichever single method (Email OTP or Security Questions) the account
// holder ends up completing — it's one step either way, not two.
$stepLabels = ['Employee ID', 'Verify Identity', 'New Password'];
$stepIndexByStage = [
    'enter_id' => 1,
    'choose_method' => 2, 'enter_otp' => 2, 'answer_questions' => 2,
    'reset_password' => 3, 'done' => 3,
];
$currentStepIndex = $stepIndexByStage[$stage] ?? 1;

// The reset flow lives inside a modal. Once the visitor has actually started
// it (any POST back, an in-progress session, or a non-initial stage) the
// modal must reopen automatically on reload — otherwise a validation error
// or a step transition would silently drop them back on the bare landing
// view with no visible feedback.
$autoOpenModal = ($_SERVER['REQUEST_METHOD'] === 'POST') || $stage !== 'enter_id' || isset($_SESSION['pr_id_number']);
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Forgot Password | CSU Instructor Registration and Management</title>

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
<link rel="stylesheet" href="../CSS/forgot_password.css">
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
</head>

<body>

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
          <li class="nav-item"><a class="nav-link" href="login.php"><i class="bi bi-box-arrow-in-right"></i> Login</a></li>
        </ul>
      </div>
    </div>
  </nav>

  <div class="fp-page">
    <div class="fp-hero">
      <div class="fp-hero__icon"><i class="bi bi-shield-lock-fill"></i></div>
      <h1>Forgot Password</h1>
      <p>Verify your Employee ID, then confirm it's you with either an email code or your security questions, and set a new password.</p>

      <button type="button" class="btn-brand" data-bs-toggle="modal" data-bs-target="#fpModal">
        <i class="bi bi-key-fill"></i> Reset Password
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
          <div class="fp-modal__icon"><i class="bi bi-shield-lock-fill"></i></div>
          <div>
            <p class="fp-modal__eyebrow">CSU Instructor Registration and Management</p>
            <h5 class="fp-modal__title">Reset Your Password</h5>
          </div>
          <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>

        <div class="fp-modal__body">

          <?php if ($stage !== 'done'): ?>
          <div class="fp-steps">
            <?php foreach ($stepLabels as $i => $label): $n = $i + 1; ?>
              <div class="fp-step <?= $n < $currentStepIndex ? 'done' : ($n === $currentStepIndex ? 'active' : '') ?>">
                <span class="fp-step__num"><?= $n < $currentStepIndex ? '✓' : $n ?></span>
                <span class="fp-step__label"><?= h($label) ?></span>
              </div>
            <?php endforeach; ?>
          </div>
          <?php endif; ?>

          <?php if (!empty($message)): ?>
            <div class="fp-alert"><?= h($message) ?></div>
          <?php endif; ?>

          <!-- STEP 1: Enter Employee ID -->
          <?php if ($stage === 'enter_id'): ?>
            <form method="post" id="requestResetForm" novalidate>
              <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
              <input type="hidden" name="action" value="request_reset">
              <div class="mb-3 text-start">
                <label class="form-label">Employee ID <span class="text-danger">*</span></label>
                <div class="password-wrapper">
                  <input type="text" name="id_number" id="id_number" class="form-control fp-mask" placeholder="INR-2026-0001" autocomplete="off" required autofocus>
                  <span class="toggle-eye" data-target="id_number">👁️</span>
                </div>
                <div class="form-text">Enter the Employee ID you registered with. We'll send a verification code to the email already on file — it can't be changed here.</div>
              </div>
              <button type="submit" class="btn-brand w-100">Continue</button>
            </form>
          <?php endif; ?>

          <!-- STEP 2 (choice): Email OTP or Security Questions — skipped
               entirely for the rare account with no security questions on
               file (pr_current_stage() sends it straight to 'enter_otp'). -->
          <?php if ($stage === 'choose_method'): ?>
            <p class="fp-modal__body-text">How would you like to verify it's you?</p>
            <div class="d-grid gap-2">
              <form method="post">
                <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                <input type="hidden" name="action" value="choose_verify_method">
                <input type="hidden" name="method" value="otp">
                <button type="submit" class="btn-brand w-100">
                  <i class="bi bi-envelope-fill"></i> Email me a code
                </button>
              </form>
              <form method="post">
                <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                <input type="hidden" name="action" value="choose_verify_method">
                <input type="hidden" name="method" value="questions">
                <button type="submit" class="btn-outline-brand w-100">
                  <i class="bi bi-patch-question-fill"></i> Answer my security questions
                </button>
              </form>
            </div>
          <?php endif; ?>

          <!-- STEP 2 (Email OTP path) -->
          <?php if ($stage === 'enter_otp'): ?>
            <p class="fp-modal__body-text">A verification code was sent to <strong><?= h($maskedEmail) ?></strong>. It expires in 5 minutes.</p>
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
            <?php if (!empty($_SESSION['pr_needs_questions'])): ?>
              <form method="post">
                <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                <input type="hidden" name="action" value="switch_verify_method">
                <button type="submit" class="fp-switch-link"><i class="bi bi-arrow-repeat"></i> Try another way</button>
              </form>
            <?php endif; ?>
          <?php endif; ?>

          <!-- STEP 2 (Security Questions path) -->
          <?php if ($stage === 'answer_questions'): ?>
            <p class="fp-modal__body-text">Select each question the way you originally set it up, then enter its answer.</p>
            <form method="post" id="verifyForm" novalidate>
              <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
              <input type="hidden" name="action" value="verify_questions">

              <div class="mb-3 text-start">
                <label class="form-label" for="q1">Question 1 <span class="text-danger">*</span></label>
                <select name="q1" id="q1" class="form-control" required>
                  <option value="">-- Select the question you answered --</option>
                  <option value="best_friend_elementary">Who is your best friend in Elementary?</option>
                  <option value="first_pet">What is the name of your first pet?</option>
                  <option value="favorite_teacher_highschool">Who is your favorite teacher in high school?</option>
                </select>
                <div class="password-wrapper mt-2">
                  <input type="text" name="a1" id="a1" class="form-control fp-mask" placeholder="Answer" autocomplete="off" required>
                  <span class="toggle-eye" data-target="a1">👁️</span>
                </div>
              </div>

              <div class="mb-3 text-start">
                <label class="form-label" for="q2">Question 2 <span class="text-danger">*</span></label>
                <select name="q2" id="q2" class="form-control" required>
                  <option value="">-- Select the question you answered --</option>
                  <option value="favorite_teacher">What is your favorite teacher's name?</option>
                  <option value="childhood_nickname">What was your childhood nickname?</option>
                  <option value="favorite_food">What is your favorite food as a child?</option>
                </select>
                <div class="password-wrapper mt-2">
                  <input type="text" name="a2" id="a2" class="form-control fp-mask" placeholder="Answer" autocomplete="off" required>
                  <span class="toggle-eye" data-target="a2">👁️</span>
                </div>
              </div>

              <div class="mb-3 text-start">
                <label class="form-label" for="q3">Question 3 <span class="text-danger">*</span></label>
                <select name="q3" id="q3" class="form-control" required>
                  <option value="">-- Select the question you answered --</option>
                  <option value="favorite_color">What is your favorite color?</option>
                  <option value="favorite_sport">What is your favorite sport?</option>
                  <option value="dream_job">What is your dream job?</option>
                </select>
                <div class="password-wrapper mt-2">
                  <input type="text" name="a3" id="a3" class="form-control fp-mask" placeholder="Answer" autocomplete="off" required>
                  <span class="toggle-eye" data-target="a3">👁️</span>
                </div>
              </div>

              <button type="submit" class="btn-brand w-100">Verify Answers</button>
            </form>
            <form method="post">
              <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
              <input type="hidden" name="action" value="switch_verify_method">
              <button type="submit" class="fp-switch-link"><i class="bi bi-arrow-repeat"></i> Try another way</button>
            </form>
          <?php endif; ?>

          <!-- STEP 3: New password + success -->
          <?php if ($stage === 'reset_password' || $stage === 'done'): ?>
            <form method="post" id="resetForm" novalidate>
              <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
              <input type="hidden" name="action" value="reset_password">
              <div class="mb-3 text-start">
                <label class="form-label">New Password</label>
                <div class="password-wrapper">
                  <input type="text" name="newPassword" id="newPassword" class="form-control fp-mask" placeholder="New password" autocomplete="off" minlength="8" maxlength="72" required>
                  <span class="toggle-eye" data-target="newPassword">👁️</span>
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
                <label class="form-label">Confirm New Password</label>
                <div class="password-wrapper">
                  <input type="text" name="confirmPassword" id="confirmPassword" class="form-control fp-mask" placeholder="Re-enter new password" autocomplete="off" maxlength="72" required>
                  <span class="toggle-eye" data-target="confirmPassword">👁️</span>
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
