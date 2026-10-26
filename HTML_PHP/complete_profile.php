<?php
session_start();
include '../include/db_connect.php';
include '../include/common_passwords.php';
include '../include/registration_helpers.php';
include '../include/auth_guard.php';

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
ini_set('display_errors', '0');

header("Cache-Control: no-cache, no-store, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

// -----------------------------------------------------------------
// This page is its own gate rather than a call to require_role() —
// require_role() redirects an incomplete profile_status HERE, so calling
// it again on this same page would loop. Every check below is re-verified
// against the database, never trusted from session state, so the mandatory
// completion step can't be skipped by a stale session, a direct URL visit,
// or the back button.
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
$stmt = $conn->prepare("SELECT * FROM users WHERE id_number = ?");
$stmt->bind_param("s", $myIdNumber);
$stmt->execute();
$account = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$account) {
    session_destroy();
    header('Location: login.php');
    exit;
}

if ($account['profile_status'] === 'complete') {
    header('Location: ' . ($account['role'] === 'superadmin' ? 'superadmin_dashboard.php' : 'admin_dashboard.php'));
    exit;
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$errors = [];
$values = [];
$success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (empty($_POST['csrf_token']) || empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $errors['_form'] = 'Your session has expired. Please refresh the page and try again.';
        $values = $_POST;
    } else {
        try {
            [$errors, $clean] = validateProfileCompletion($conn, $_POST, $myIdNumber, $account['email']);
            if (empty($errors)) {
                completeStaffProfile($conn, $myIdNumber, $clean, (string)($_POST['new_password'] ?? ''));
                $_SESSION['first_name'] = $clean['first_name'];
                $_SESSION['last_name'] = $clean['last_name'];
                $_SESSION['email'] = $clean['email'];
                header('Location: ' . ($account['role'] === 'superadmin' ? 'superadmin_dashboard.php' : 'admin_dashboard.php'));
                exit;
            }
            $values = $_POST;
        } catch (Throwable $e) {
            error_log('Profile completion failed: ' . $e->getMessage());
            $errors['_form'] = 'A server error occurred. Please try again later.';
            $values = $_POST;
        }
    }
}

function pv($values, $key) {
    return h($values[$key] ?? '');
}

// Locked whenever the Superadmin already set an email at account creation
// (Create Account now requires one) — that's the exact address the login
// credentials were emailed to, so it's shown but can't be edited here. Only
// a pre-existing account created before email collection existed (no email
// on file) still gets the original editable field.
$emailLocked = !empty($account['email']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Complete Your Profile | CSU Instructor Registration and Management</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
  <link rel="stylesheet" href="../CSS/login.css">
  <style>
    .overlay { align-items: flex-start; padding-top: 40px; padding-bottom: 40px; }
    .login-card.profile-card { max-width: 780px; }
    select.form-control { background: var(--field-bg); border: 1px solid var(--field-border); color: var(--ink); border-radius: 8px; padding: 8px 12px; height: 42px; }
    select.form-control:focus { background: rgba(255,255,255,0.1); border-color: var(--field-border-focus); box-shadow: 0 0 0 3px rgba(61,220,132,0.2); color: var(--ink); }
    select.form-control option { color: #06210d; }
    .profile-card .err { color: var(--danger); font-size: 0.8rem; margin-top: 4px; }
    .profile-card .lock-note { background: rgba(255,183,3,0.12); border: 1px solid rgba(255,183,3,0.35); border-radius: 10px; padding: 10px 14px; font-size: 0.85rem; color: var(--ink); margin-bottom: 18px; }
  </style>
</head>
<body oncontextmenu="return false;">

  <div class="overlay">
    <div class="login-card profile-card">
      <div class="login-card__header">
        <div class="login-card__icon"><i class="bi bi-person-badge-fill"></i></div>
        <div>
          <p class="login-card__eyebrow">CSU Instructor Registration and Management</p>
          <h1 class="login-card__title">Complete Your Profile</h1>
        </div>
      </div>

      <div class="login-card__body">
        <p class="lock-note">
          <i class="bi bi-shield-lock-fill"></i>
          This account was created without confidential personal information.
          You must complete it now, and set your own password, before you can
          access the dashboard. This step cannot be skipped or postponed.
        </p>

        <?php if (!empty($errors['_form'])): ?>
          <div class="alert alert-danger"><?= h($errors['_form']) ?></div>
        <?php endif; ?>

        <form method="post" id="completeProfileForm" autocomplete="off" novalidate>
          <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">

          <div class="row g-3">
            <div class="col-md-4">
              <label for="first_name" class="form-label">First Name *</label>
              <input type="text" name="first_name" id="first_name" class="form-control" value="<?= pv($values, 'first_name') ?>" minlength="2" maxlength="50" required>
              <?php if (!empty($errors['first_name'])): ?><div class="err"><?= h($errors['first_name']) ?></div><?php endif; ?>
            </div>
            <div class="col-md-4">
              <label for="middle_name" class="form-label">Middle Name</label>
              <input type="text" name="middle_name" id="middle_name" class="form-control" value="<?= pv($values, 'middle_name') ?>" minlength="2" maxlength="50">
              <?php if (!empty($errors['middle_name'])): ?><div class="err"><?= h($errors['middle_name']) ?></div><?php endif; ?>
            </div>
            <div class="col-md-4">
              <label for="last_name" class="form-label">Last Name *</label>
              <input type="text" name="last_name" id="last_name" class="form-control" value="<?= pv($values, 'last_name') ?>" minlength="2" maxlength="50" required>
              <?php if (!empty($errors['last_name'])): ?><div class="err"><?= h($errors['last_name']) ?></div><?php endif; ?>
            </div>
          </div>

          <div class="row g-3 mt-1">
            <div class="col-md-4">
              <label for="extension" class="form-label">Extension</label>
              <input type="text" name="extension" id="extension" class="form-control" value="<?= pv($values, 'extension') ?>" maxlength="10">
              <?php if (!empty($errors['extension'])): ?><div class="err"><?= h($errors['extension']) ?></div><?php endif; ?>
            </div>
            <div class="col-md-4">
              <label for="sex" class="form-label">Sex *</label>
              <select name="sex" id="sex" class="form-control" required>
                <option value="">-- Select --</option>
                <option value="Male" <?= ($values['sex'] ?? '') === 'Male' ? 'selected' : '' ?>>Male</option>
                <option value="Female" <?= ($values['sex'] ?? '') === 'Female' ? 'selected' : '' ?>>Female</option>
              </select>
              <?php if (!empty($errors['sex'])): ?><div class="err"><?= h($errors['sex']) ?></div><?php endif; ?>
            </div>
            <div class="col-md-4">
              <label for="birthdate" class="form-label">Birthdate *</label>
              <input type="date" name="birthdate" id="birthdate" class="form-control" value="<?= pv($values, 'birthdate') ?>" required>
              <?php if (!empty($errors['birthdate'])): ?><div class="err"><?= h($errors['birthdate']) ?></div><?php endif; ?>
            </div>
          </div>

          <div class="row g-3 mt-1">
            <div class="col-md-3">
              <label for="street" class="form-label">Street/Purok *</label>
              <input type="text" name="street" id="street" class="form-control" value="<?= pv($values, 'street') ?>" minlength="2" maxlength="60" required>
              <?php if (!empty($errors['street'])): ?><div class="err"><?= h($errors['street']) ?></div><?php endif; ?>
            </div>
            <div class="col-md-3">
              <label for="barangay" class="form-label">Barangay *</label>
              <input type="text" name="barangay" id="barangay" class="form-control" value="<?= pv($values, 'barangay') ?>" minlength="2" maxlength="60" required>
              <?php if (!empty($errors['barangay'])): ?><div class="err"><?= h($errors['barangay']) ?></div><?php endif; ?>
            </div>
            <div class="col-md-3">
              <label for="city" class="form-label">Municipality/City *</label>
              <input type="text" name="city" id="city" class="form-control" value="<?= pv($values, 'city') ?>" minlength="2" maxlength="60" required>
              <?php if (!empty($errors['city'])): ?><div class="err"><?= h($errors['city']) ?></div><?php endif; ?>
            </div>
            <div class="col-md-3">
              <label for="province" class="form-label">Province *</label>
              <input type="text" name="province" id="province" class="form-control" value="<?= pv($values, 'province') ?>" minlength="2" maxlength="60" required>
              <?php if (!empty($errors['province'])): ?><div class="err"><?= h($errors['province']) ?></div><?php endif; ?>
            </div>
          </div>

          <div class="row g-3 mt-1">
            <div class="col-md-6">
              <label for="region" class="form-label">Region *</label>
              <select name="region" id="region" class="form-control" required>
                <option value="">-- Select Region --</option>
                <?php foreach (REGION_OPTIONS as $regionOpt): ?>
                  <option value="<?= h($regionOpt) ?>" <?= ($values['region'] ?? '') === $regionOpt ? 'selected' : '' ?>><?= h($regionOpt) ?></option>
                <?php endforeach; ?>
              </select>
              <?php if (!empty($errors['region'])): ?><div class="err"><?= h($errors['region']) ?></div><?php endif; ?>
            </div>
            <div class="col-md-3">
              <label for="zip" class="form-label">Zip *</label>
              <input type="text" name="zip" id="zip" class="form-control" value="<?= pv($values, 'zip') ?>" inputmode="numeric" maxlength="4" required>
              <?php if (!empty($errors['zip'])): ?><div class="err"><?= h($errors['zip']) ?></div><?php endif; ?>
            </div>
            <div class="col-md-3">
              <label for="email" class="form-label">Email *</label>
              <?php if ($emailLocked): ?>
                <input type="email" name="email" id="email" class="form-control" value="<?= h($account['email']) ?>" readonly>
                <div class="form-text">This is where your login credentials were sent — it can't be changed here.</div>
              <?php else: ?>
                <input type="email" name="email" id="email" class="form-control" value="<?= pv($values, 'email') ?>" maxlength="100" required>
              <?php endif; ?>
              <?php if (!empty($errors['email'])): ?><div class="err"><?= h($errors['email']) ?></div><?php endif; ?>
            </div>
          </div>

          <hr class="mt-4" style="border-color: rgba(255,255,255,0.12);">
          <p class="form-text mb-2"><i class="bi bi-key-fill"></i> Set your own password. The temporary one used to log in for the first time will stop working once this is saved.</p>

          <div class="row g-3">
            <div class="col-md-6">
              <label for="new_password" class="form-label">New Password *</label>
              <div class="input-group">
                <input type="password" name="new_password" id="new_password" class="form-control" autocomplete="new-password" minlength="8" maxlength="72" required oninput="checkPasswordStrength(); checkMatchPassword();">
                <button class="btn" type="button" onclick="togglePassword('new_password', this)">👁️</button>
              </div>
              <small id="strengthText"></small>
              <div style="width:100%; height:6px; background:rgba(255,255,255,0.12); border-radius:3px; margin-top:2px;">
                <div id="strengthBar" style="height:6px; width:0%; border-radius:3px;"></div>
              </div>
              <?php if (!empty($errors['new_password'])): ?><div class="err"><?= h($errors['new_password']) ?></div><?php endif; ?>
            </div>
            <div class="col-md-6">
              <label for="confirm_new_password" class="form-label">Confirm New Password *</label>
              <div class="input-group">
                <input type="password" name="confirm_new_password" id="confirm_new_password" class="form-control" autocomplete="new-password" required oninput="checkMatchPassword();">
                <button class="btn" type="button" onclick="togglePassword('confirm_new_password', this)">👁️</button>
              </div>
              <small id="matchText"></small>
              <?php if (!empty($errors['confirm_new_password'])): ?><div class="err"><?= h($errors['confirm_new_password']) ?></div><?php endif; ?>
            </div>
          </div>

          <hr class="mt-4" style="border-color: rgba(255,255,255,0.12);">
          <p class="form-text mb-2"><i class="bi bi-shield-lock-fill"></i> Set your security questions. These are used to recover your account together with the emailed verification code.</p>

          <div class="row g-3">
            <div class="col-md-4">
              <label for="a1_question" class="form-label">Question 1 *</label>
              <select name="a1_question" id="a1_question" class="form-control" required>
                <option value="">-- Select a question --</option>
                <option value="best_friend_elementary" <?= ($values['a1_question'] ?? '') === 'best_friend_elementary' ? 'selected' : '' ?>>Who is your best friend in Elementary?</option>
                <option value="first_pet" <?= ($values['a1_question'] ?? '') === 'first_pet' ? 'selected' : '' ?>>What is the name of your first pet?</option>
                <option value="favorite_teacher_highschool" <?= ($values['a1_question'] ?? '') === 'favorite_teacher_highschool' ? 'selected' : '' ?>>Who is your favorite teacher in high school?</option>
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
                <option value="favorite_teacher" <?= ($values['a2_question'] ?? '') === 'favorite_teacher' ? 'selected' : '' ?>>What is your favorite teacher's name?</option>
                <option value="childhood_nickname" <?= ($values['a2_question'] ?? '') === 'childhood_nickname' ? 'selected' : '' ?>>What was your childhood nickname?</option>
                <option value="favorite_food" <?= ($values['a2_question'] ?? '') === 'favorite_food' ? 'selected' : '' ?>>What is your favorite food as a child?</option>
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
                <option value="favorite_color" <?= ($values['a3_question'] ?? '') === 'favorite_color' ? 'selected' : '' ?>>What is your favorite color?</option>
                <option value="favorite_sport" <?= ($values['a3_question'] ?? '') === 'favorite_sport' ? 'selected' : '' ?>>What is your favorite sport?</option>
                <option value="dream_job" <?= ($values['a3_question'] ?? '') === 'dream_job' ? 'selected' : '' ?>>What is your dream job?</option>
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
  <script src="js/complete_profile_validate.js"></script>
</body>
</html>
