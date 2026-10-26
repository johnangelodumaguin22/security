<?php
session_start();

// Include database connection
include '../include/db_connect.php';
include '../include/common_passwords.php';
include '../include/registration_helpers.php';

// This process's mysqli calls throw on error (scoped to this request only —
// PHP 8.0's default is silent failure, so the try/catch below needs this).
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

// Never let a stray warning/notice corrupt the JSON response or leak paths.
ini_set('display_errors', '0');

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// -----------------------------------------------------------------
// Rate limiting (mirrors the escalating lockout used on login.php)
// -----------------------------------------------------------------
function reg_rate_limit_status() {
    if (!isset($_SESSION['reg_attempts'])) $_SESSION['reg_attempts'] = 0;
    if (!isset($_SESSION['reg_lockout_until'])) $_SESSION['reg_lockout_until'] = 0;
    $now = time();
    if ($now >= $_SESSION['reg_lockout_until']) {
        $_SESSION['reg_lockout_until'] = 0;
    }
    return $_SESSION['reg_lockout_until'] - $now;
}

function reg_rate_limit_hit() {
    $_SESSION['reg_attempts']++;
    $now = time();
    if ($_SESSION['reg_attempts'] >= 25) {
        $_SESSION['reg_lockout_until'] = $now + 300;
    } elseif ($_SESSION['reg_attempts'] >= 15) {
        $_SESSION['reg_lockout_until'] = $now + 60;
    } elseif ($_SESSION['reg_attempts'] >= 8) {
        $_SESSION['reg_lockout_until'] = $now + 20;
    }
}

function reg_rate_limit_reset() {
    $_SESSION['reg_attempts'] = 0;
    $_SESSION['reg_lockout_until'] = 0;
}

// Name/address/username/password/security-question validation, id_number
// generation, and the account-creation INSERT now live in
// include/registration_helpers.php (shared with the Superadmin
// "create Admin/Superadmin account" flow).

// Function to register a new public self-registration: always role='user',
// status='pending' — it must be approved by an Admin/Superadmin before login works.
function registerUser($conn, $data) {
    [$errors, $clean] = validateRegistration($conn, $data);

    if (!empty($errors)) {
        return ['status' => false, 'message' => 'Please fix the highlighted errors.', 'errors' => $errors];
    }

    $result = createUserAccount($conn, $clean, $data['password'], 'user', 'pending');
    if ($result['status']) {
        // Email verification via OTP is not part of registration/login anymore
        // — OTP is reserved exclusively for the Forgot Password flow.
        $result['message'] = 'Registration successful! Please wait for administrator approval.';
    } else {
        $result['message'] = $result['message'] ?? 'Please fix the highlighted errors.';
    }
    return $result;
}

// Handle POST request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');

    $remaining = reg_rate_limit_status();
    if ($remaining > 0) {
        echo json_encode(['success' => false, 'message' => "Too many attempts. Please wait {$remaining} seconds and try again."]);
        exit;
    }

    if (empty($_POST['csrf_token']) || empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        echo json_encode(['success' => false, 'message' => 'Your session has expired. Please refresh the page and try again.']);
        exit;
    }

    reg_rate_limit_hit();

    try {
        $result = registerUser($conn, $_POST);
    } catch (Throwable $e) {
        error_log('Registration error: ' . $e->getMessage());
        echo json_encode(['success' => false, 'message' => 'A server error occurred. Please try again later.']);
        exit;
    }

    if ($result['status']) {
        reg_rate_limit_reset();
        session_regenerate_id(true);
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        echo json_encode(['success' => true, 'id_number' => $result['id_number'], 'message' => $result['message']]);
    } else {
        echo json_encode(['success' => false, 'message' => $result['message'], 'errors' => $result['errors'] ?? []]);
    }
    exit;
}

$reg_lock_remaining = reg_rate_limit_status();
?>


<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Registration | CSU Instructor Registration and Management</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="../CSS/register.css">
</head>

<body>

<!-- HEADER -->
<header>
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
          <li class="nav-item">
            <a class="nav-link" href="home.php"><i class="bi bi-house-door-fill"></i> Home</a>
          </li>

          <li class="nav-item">
            <a class="nav-link active" href="register.php"><i class="bi bi-person-plus-fill"></i> Register</a>
          </li>

          <li class="nav-item">
            <a class="nav-link" href="login.php"><i class="bi bi-box-arrow-in-right"></i> Login</a>
          </li>
        </ul>
      </div>
    </div>
  </nav>
</header>


<main>
  <div class="register-card">
    <div class="register-card__header">
      <div class="register-card__icon"><i class="bi bi-mortarboard-fill"></i></div>
      <div>
        <p class="register-card__eyebrow">CSU Instructor Registration and Management</p>
        <h1 class="register-card__title">New Instructor Registration</h1>
      </div>
    </div>

    <?php if ($reg_lock_remaining > 0): ?>
      <div class="register-lockout" role="alert">
        🚫 Too many attempts. Please wait <?= (int)$reg_lock_remaining ?> seconds before trying again.
      </div>
    <?php endif; ?>

    <form action="" method="post" id="registerForm" class="d-flex flex-column flex-grow-1" novalidate>
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">

      <div class="register-card__body">

      <!-- PERSONAL INFO -->
      <h5 class="section-title"><i class="bi bi-person-fill"></i>Personal Info</h5>
      <div class="row g-8 mb-3">
        <div class="col-md-3">
          <label for="id_number" class="form-label">Employee ID *</label>
          <input type="text" name="id_number" id="id_number" class="form-control" >
        </div>
        <div class="col-md-3">
          <label for="first_name" class="form-label">First Name *</label>
          <input type="text" name="first_name" id="first_name" class="form-control" minlength="2" maxlength="50" required>
        </div>
        <div class="col-md-3">
          <label for="middle_name" class="form-label">Middle Name <span class="optional">optional*</span></label>
          <input type="text" name="middle_name" id="middle_name" class="form-control" minlength="2" maxlength="50">
        </div>
        <div class="col-md-3">
          <label for="last_name" class="form-label">Last Name *</label>
          <input type="text" name="last_name" id="last_name" class="form-control" minlength="2" maxlength="50" required>
        </div>
      </div>

      <div class="row g-8 mb-3">
        <div class="col-md-3">
          <label for="extension" class="form-label">Extension <span class="optional">optional*</span></label>
          <input type="text" name="extension" id="extension" class="form-control" maxlength="10">
        </div>
        <div class="col-md-3">
          <label for="sex" class="form-label">Sex *</label>
          <select name="sex" id="sex" class="form-select">
            <option value="">-- Select Sex --</option>
            <option value="Male">Male</option>
            <option value="Female">Female</option>
          </select>
        </div>
        <div class="col-md-3">
          <label for="birthdate" class="form-label">Birthdate *</label>
          <input type="date" name="birthdate" id="birthdate" class="form-control">
        </div>
        <div class="col-md-3">
          <label for="age" class="form-label">Age *</label>
          <input type="number" name="age" id="age" class="form-control" readonly >
        </div>
      </div>
      <h5 class="section-title"><i class="bi bi-geo-alt-fill"></i>Address &amp; Account</h5>
      <div class="row g-8 mb-.5">
        <div class="col-md-3">
          <label for="street" class="form-label">Street/Purok *</label>
          <input type="text" name="street" id="street" class="form-control" minlength="2" maxlength="100" required>
        </div>
        <div class="col-md-3">
          <label for="barangay" class="form-label">Barangay *</label>
          <input type="text" name="barangay" id="barangay" class="form-control" minlength="2" maxlength="100" required>
        </div>
        <div class="col-md-3">
          <label for="city" class="form-label">Municipality/City *</label>
          <input type="text" name="city" id="city" class="form-control" minlength="2" maxlength="100" required>
        </div>
        <div class="col-md-3">
          <label for="province" class="form-label">Province *</label>
          <input type="text" name="province" id="province" class="form-control" minlength="2" maxlength="100" required>
        </div>
      </div>

      <div class="row g-8 mb-.5">
        <div class="col-md-3">
          <label for="region" class="form-label">Region *</label>
          <select name="region" id="region" class="form-select">
            <option value="">-- Select Region --</option>
            <?php foreach (REGION_OPTIONS as $regionOpt): ?>
              <option value="<?= htmlspecialchars($regionOpt, ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars($regionOpt, ENT_QUOTES, 'UTF-8') ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div class="col-md-3">
          <label for="zip" class="form-label">Zip Code *</label>
          <input type="text" name="zip" id="zip" class="form-control" inputmode="numeric" maxlength="4" required>
        </div>
        <div class="col-md-3">
          <label for="email" class="form-label">Email *</label>
          <input type="email" name="email" id="email" class="form-control" maxlength="100" required>
        </div>

        <div class="col-md-3">
          <label for="username" class="form-label">Username *</label>
          <input type="text" name="username" id="username" class="form-control" minlength="5" maxlength="30" required autocomplete="username">
          <div class="form-text">Must start with a letter and include at least one uppercase letter, one number, and one special character (_ or .).</div>
        </div>
      </div><!-- /.row (region/zip/email/username) -->

      <div class="row g-8 mb-2">
        <div class="col-md-3">
          <label for="password" class="form-label">Password *</label>
          <div class="password-wrapper">
            <input type="password" name="password" id="password" class="form-control" minlength="8" maxlength="72" autocomplete="new-password" oninput="checkPasswordStrength(); checkMatchPassword();">
            <span class="toggle-eye" onclick="togglePassword('password', this)">👁️</span>
          </div>
          <small id="strengthText" class="ms-1"></small>
          <div style="width:100%; height:6px; background:#ddd; border-radius:3px; margin-top:2px;">
            <div id="strengthBar" style="height:6px; width:0%; border-radius:3px;"></div>
          </div>
        </div>

        <div class="col-md-3">
          <label for="repassword" class="form-label">Re-enter Password *</label>
          <div class="password-wrapper">
            <input type="password" name="repassword" id="repassword" class="form-control" autocomplete="new-password" oninput="checkMatchPassword();">
            <span class="toggle-eye" onclick="togglePassword('repassword', this)">👁️</span>
          </div>
          <small id="matchText" class="ms-1"></small>
        </div>
      </div>

      <!-- SECURITY QUESTIONS -->
      <h5 class="section-title"><i class="bi bi-shield-lock-fill"></i>Security Questions</h5>
      <div class="row g-8 mb-.5">
        <div class="col-md-4">
          <label for="a1_question" class="form-label">Question 1 *</label>
          <select name="a1_question" id="a1_question" class="form-select">
            <option value="">-- Select a question --</option>
            <option value="best_friend_elementary">Who is your best friend in Elementary?</option>
            <option value="first_pet">What is the name of your first pet?</option>
            <option value="favorite_teacher_highschool">Who is your favorite teacher in high school?</option>
          </select>

            <label for="a1_answer" class="form-label mt-2">Answer *</label>
          <div class="input-group">
              <input type="password" name="a1_answer" id="a1_answer" class="form-control">
              <span class="input-group-text"  style="cursor:pointer;" onclick="togglePassword('a1_answer', this)">👁️</span>
          </div>
          </div>

        <div class="col-md-4">
          <label for="a2_question" class="form-label">Question 2 *</label>
          <select name="a2_question" id="a2_question" class="form-select">
            <option value="">-- Select a question --</option>
            <option value="favorite_teacher">What is your favorite teacher’s name?</option>
            <option value="childhood_nickname">What was your childhood nickname?</option>
            <option value="favorite_food">What is your favorite food as a child?</option>
          </select>

          <label for="a2_answer" class="form-label mt-2">Answer *</label>
          <div class="input-group">
              <input type="password" name="a2_answer" id="a2_answer" class="form-control">
              <span class="input-group-text" style="cursor:pointer;" onclick="togglePassword('a2_answer', this)">👁️</span>
          </div>
        </div>

        <div class="col-md-4">
          <label for="a3_question" class="form-label">Question 3 *</label>
          <select name="a3_question" id="a3_question" class="form-select">
            <option value="">-- Select a question --</option>
            <option value="favorite_color">What is your favorite color?</option>
            <option value="favorite_sport">What is your favorite sport?</option>
            <option value="dream_job">What is your dream job?</option>
          </select>

          <label for="a3_answer" class="form-label mt-2">Answer *</label>
          <div class="input-group">
            <input type="password" name="a3_answer" id="a3_answer" class="form-control">
            <span class="input-group-text" style="cursor:pointer;" onclick="togglePassword('a3_answer', this)">👁️</span>
          </div>
        </div>
      </div>

      </div><!-- /.register-card__body -->

      <div class="register-card__footer">
        <button type="submit" class="register-card__submit">
          <i class="bi bi-check2-circle me-1"></i> Register
        </button>
      </div>
    </form>
  </div>
</main>



  <footer>
    &copy; <?= date('Y') ?> CSU Instructor Registration and Management
  </footer>

</body>
</html>
<script>
// Disable Right Click
document.addEventListener("contextmenu", (e) => e.preventDefault());

// Disable F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+U
document.addEventListener("keydown", (e) => {
  if (
    e.key === "F12" ||
    (e.ctrlKey && e.shiftKey && (e.key === "I" || e.key === "J")) ||
    (e.ctrlKey && e.key === "U")
  ) {
    e.preventDefault();
  }
});
</script>


<!-- register_shared.js must load first — the other 4 files call its
     getErrorBox/showSingleError/clearError/hasProperWordCasing/isNamePart/
     hasRepeatedChars instead of each redefining their own. -->
<script src="js/register_shared.js"></script>
<script src="js/personal_information_register.js"></script>
<script src="js/address_account_register.js"></script>
<script src="js/security_question_register.js"></script>
<script src="js/password_register.js"></script>

<script>
// ✅ Correct Fetch Path
document.addEventListener("DOMContentLoaded", () => {
    fetch("../include/get_next_id.php")
        .then(res => res.text())
        .then(data => {
            document.getElementById("id_number").value = data;
        });
});
</script>