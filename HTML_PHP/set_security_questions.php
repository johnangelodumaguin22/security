<?php
session_start();
include '../include/db_connect.php';
include '../include/registration_helpers.php';
include '../include/auth_guard.php';

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
ini_set('display_errors', '0');

header("Cache-Control: no-cache, no-store, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

// -----------------------------------------------------------------
// One-time mandatory gate for a pre-existing Admin/Superadmin account that
// already has a complete profile but no security questions on file (the
// old bare-account exemption has been retired). require_role() redirects
// here, so — same as complete_profile.php — this page is its own gate
// rather than calling require_role() again, to avoid a redirect loop.
// Every check is re-verified against the database, never trusted from
// session state, so this step can't be skipped by a stale session, a
// direct URL visit, or the back button.
// -----------------------------------------------------------------
if (empty($_SESSION['username']) || empty($_SESSION['role']) || empty($_SESSION['id_number'])) {
    header('Location: login.php');
    exit;
}
if (!in_array($_SESSION['role'], ['admin', 'superadmin'], true)) {
    header('Location: login.php');
    exit;
}

$myIdNumber = $_SESSION['id_number'];
$stmt = $conn->prepare("SELECT id_number, role, profile_status, question1 FROM users WHERE id_number = ?");
$stmt->bind_param("s", $myIdNumber);
$stmt->execute();
$account = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$account) {
    session_destroy();
    header('Location: login.php');
    exit;
}

if ($account['profile_status'] !== 'complete') {
    header('Location: complete_profile.php');
    exit;
}

// Already has security questions — nothing to do here anymore.
if ($account['question1'] !== '') {
    header('Location: ' . ($account['role'] === 'superadmin' ? 'superadmin_dashboard.php' : 'admin_dashboard.php'));
    exit;
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$errors = [];
$values = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (empty($_POST['csrf_token']) || empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $errors['_form'] = 'Your session has expired. Please refresh the page and try again.';
        $values = $_POST;
    } else {
        try {
            [$errors, $clean] = validateSecurityQuestionFields($_POST);
            if (empty($errors)) {
                saveSecurityQuestionsOnly($conn, $myIdNumber, $clean);
                header('Location: ' . ($account['role'] === 'superadmin' ? 'superadmin_dashboard.php' : 'admin_dashboard.php'));
                exit;
            }
            $values = $_POST;
        } catch (Throwable $e) {
            error_log('Set security questions failed: ' . $e->getMessage());
            $errors['_form'] = 'A server error occurred. Please try again later.';
            $values = $_POST;
        }
    }
}

function pv2($values, $key) {
    return h($values[$key] ?? '');
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Set Security Questions | CSU Instructor Registration and Management</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
  <link rel="stylesheet" href="../CSS/login.css">
  <style>
    .overlay { align-items: flex-start; padding-top: 40px; padding-bottom: 40px; }
    .login-card.profile-card { max-width: 780px; }
    .profile-card .err { color: var(--danger); font-size: 0.8rem; margin-top: 4px; }
    .profile-card .lock-note { background: rgba(255,183,3,0.12); border: 1px solid rgba(255,183,3,0.35); border-radius: 10px; padding: 10px 14px; font-size: 0.85rem; color: var(--ink); margin-bottom: 18px; }
    select.form-control { background: var(--field-bg); border: 1px solid var(--field-border); color: var(--ink); border-radius: 8px; padding: 8px 12px; height: 42px; }
    select.form-control:focus { background: rgba(255,255,255,0.1); border-color: var(--field-border-focus); box-shadow: 0 0 0 3px rgba(61,220,132,0.2); color: var(--ink); }
    select.form-control option { color: #06210d; }
  </style>
</head>
<body oncontextmenu="return false;">

  <div class="overlay">
    <div class="login-card profile-card">
      <div class="login-card__header">
        <div class="login-card__icon"><i class="bi bi-shield-lock-fill"></i></div>
        <div>
          <p class="login-card__eyebrow">CSU Instructor Registration and Management</p>
          <h1 class="login-card__title">Set Your Security Questions</h1>
        </div>
      </div>

      <div class="login-card__body">
        <p class="lock-note">
          <i class="bi bi-shield-lock-fill"></i>
          Security questions are now required for every Admin/Superadmin account,
          used together with the emailed verification code for password recovery.
          This step cannot be skipped or postponed.
        </p>

        <?php if (!empty($errors['_form'])): ?>
          <div class="alert alert-danger"><?= h($errors['_form']) ?></div>
        <?php endif; ?>

        <form method="post" id="setQuestionsForm" autocomplete="off" novalidate>
          <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">

          <div class="row g-3">
            <div class="col-md-4">
              <label for="a1_question" class="form-label">Question 1 *</label>
              <select name="a1_question" id="a1_question" class="form-control" required>
                <option value="">-- Select a question --</option>
                <option value="best_friend_elementary" <?= pv2($values, 'a1_question') === 'best_friend_elementary' ? 'selected' : '' ?>>Who is your best friend in Elementary?</option>
                <option value="first_pet" <?= pv2($values, 'a1_question') === 'first_pet' ? 'selected' : '' ?>>What is the name of your first pet?</option>
                <option value="favorite_teacher_highschool" <?= pv2($values, 'a1_question') === 'favorite_teacher_highschool' ? 'selected' : '' ?>>Who is your favorite teacher in high school?</option>
              </select>
              <?php if (!empty($errors['a1_question'])): ?><div class="err"><?= h($errors['a1_question']) ?></div><?php endif; ?>

              <label for="a1_answer" class="form-label mt-2">Answer *</label>
              <div class="input-group">
                <input type="password" name="a1_answer" id="a1_answer" class="form-control" maxlength="100">
                <button class="btn" type="button" onclick="togglePassword('a1_answer', this)">👁️</button>
              </div>
              <?php if (!empty($errors['a1_answer'])): ?><div class="err"><?= h($errors['a1_answer']) ?></div><?php endif; ?>
            </div>

            <div class="col-md-4">
              <label for="a2_question" class="form-label">Question 2 *</label>
              <select name="a2_question" id="a2_question" class="form-control" required>
                <option value="">-- Select a question --</option>
                <option value="favorite_teacher" <?= pv2($values, 'a2_question') === 'favorite_teacher' ? 'selected' : '' ?>>What is your favorite teacher's name?</option>
                <option value="childhood_nickname" <?= pv2($values, 'a2_question') === 'childhood_nickname' ? 'selected' : '' ?>>What was your childhood nickname?</option>
                <option value="favorite_food" <?= pv2($values, 'a2_question') === 'favorite_food' ? 'selected' : '' ?>>What is your favorite food as a child?</option>
              </select>
              <?php if (!empty($errors['a2_question'])): ?><div class="err"><?= h($errors['a2_question']) ?></div><?php endif; ?>

              <label for="a2_answer" class="form-label mt-2">Answer *</label>
              <div class="input-group">
                <input type="password" name="a2_answer" id="a2_answer" class="form-control" maxlength="100">
                <button class="btn" type="button" onclick="togglePassword('a2_answer', this)">👁️</button>
              </div>
              <?php if (!empty($errors['a2_answer'])): ?><div class="err"><?= h($errors['a2_answer']) ?></div><?php endif; ?>
            </div>

            <div class="col-md-4">
              <label for="a3_question" class="form-label">Question 3 *</label>
              <select name="a3_question" id="a3_question" class="form-control" required>
                <option value="">-- Select a question --</option>
                <option value="favorite_color" <?= pv2($values, 'a3_question') === 'favorite_color' ? 'selected' : '' ?>>What is your favorite color?</option>
                <option value="favorite_sport" <?= pv2($values, 'a3_question') === 'favorite_sport' ? 'selected' : '' ?>>What is your favorite sport?</option>
                <option value="dream_job" <?= pv2($values, 'a3_question') === 'dream_job' ? 'selected' : '' ?>>What is your dream job?</option>
              </select>
              <?php if (!empty($errors['a3_question'])): ?><div class="err"><?= h($errors['a3_question']) ?></div><?php endif; ?>

              <label for="a3_answer" class="form-label mt-2">Answer *</label>
              <div class="input-group">
                <input type="password" name="a3_answer" id="a3_answer" class="form-control" maxlength="100">
                <button class="btn" type="button" onclick="togglePassword('a3_answer', this)">👁️</button>
              </div>
              <?php if (!empty($errors['a3_answer'])): ?><div class="err"><?= h($errors['a3_answer']) ?></div><?php endif; ?>
            </div>
          </div>

          <div class="d-grid mt-4">
            <button type="submit" class="btn-brand">Save and Continue</button>
          </div>
        </form>
      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
  <script src="js/set_security_questions_validate.js"></script>
</body>
</html>
