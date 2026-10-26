<?php
include '../include/db_connect.php';
include '../include/auth_guard.php';
include '../include/profile_picture.php';
include '../include/login_logs.php'; // heartbeats this session's Login Logs row (viewed from Superadmin)

require_role(['user', 'admin', 'superadmin']);

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
ini_set('display_errors', '0');

// ----------------------------
// Prevent browser from caching the page
// ----------------------------
header("Cache-Control: no-cache, no-store, must-revalidate"); // HTTP 1.1
header("Pragma: no-cache"); // HTTP 1.0
header("Expires: 0"); // Proxies

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ----------------------------
// Get user info from database
// ----------------------------
$username = $_SESSION['username'];
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$user = $stmt->get_result()->fetch_assoc();

// If user not found in DB (maybe deleted), logout
if (!$user) {
    header("Location: logout.php");
    exit;
}

$flash = null;

// -----------------------------------------------------------------
// This account's own activity feed — its Login Logs sessions (split into
// separate "Logged in"/"Logged out" events) and its own otp_audit_log
// security events (OTP requests, password resets, security-question
// verification), merged and paginated. Scoped to id_number = this account
// only — there is no cross-account visibility from this page, by design.
// -----------------------------------------------------------------
function get_own_activity_log($conn, $idNumber, array $filters, $page = 1, $perPage = 25) {
    $source = $filters['source'] ?? 'all';
    $dateFrom = trim((string)($filters['date_from'] ?? ''));
    $dateTo = trim((string)($filters['date_to'] ?? ''));

    $union = "
        SELECT login_time AS created_at, 'login' AS source, 'Logged in' AS action, ip_address, device_label AS detail
        FROM login_logs WHERE id_number = ?
        UNION ALL
        SELECT logout_time AS created_at, 'login' AS source, 'Logged out' AS action, ip_address, device_label AS detail
        FROM login_logs WHERE id_number = ? AND logout_time IS NOT NULL
        UNION ALL
        SELECT created_at, 'security' AS source, action, ip_address, NULL AS detail
        FROM otp_audit_log WHERE id_number = ?
    ";
    $unionParams = [$idNumber, $idNumber, $idNumber];
    $unionTypes = 'sss';

    $where = [];
    $params = [];
    $types = '';
    if (in_array($source, ['login', 'security'], true)) {
        $where[] = "source = ?";
        $params[] = $source;
        $types .= 's';
    }
    if ($dateFrom !== '') {
        $where[] = "created_at >= ?";
        $params[] = $dateFrom . ' 00:00:00';
        $types .= 's';
    }
    if ($dateTo !== '') {
        $where[] = "created_at <= ?";
        $params[] = $dateTo . ' 23:59:59';
        $types .= 's';
    }
    $whereSql = $where ? ('WHERE ' . implode(' AND ', $where)) : '';

    $countSql = "SELECT COUNT(*) c FROM ($union) combined $whereSql";
    $stmt = $conn->prepare($countSql);
    $stmt->bind_param($unionTypes . $types, ...array_merge($unionParams, $params));
    $stmt->execute();
    $total = (int)$stmt->get_result()->fetch_assoc()['c'];
    $stmt->close();

    $perPage = max(1, (int)$perPage);
    $totalPages = max(1, (int)ceil($total / $perPage));
    $page = max(1, min((int)$page, $totalPages));
    $offset = ($page - 1) * $perPage;

    $listSql = "SELECT * FROM ($union) combined $whereSql ORDER BY created_at DESC LIMIT ? OFFSET ?";
    $stmt = $conn->prepare($listSql);
    $stmt->bind_param($unionTypes . $types . 'ii', ...array_merge($unionParams, $params, [$perPage, $offset]));
    $stmt->execute();
    $rows = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    $stmt->close();

    return ['rows' => $rows, 'total' => $total, 'page' => $page, 'total_pages' => $totalPages];
}

// Humanizes otp_audit_log's mixed-casing action values ('OTP_REQUESTED',
// 'username_changed_by_self') into one consistent, readable label.
function humanize_activity_action($action) {
    $label = ucwords(strtolower(str_replace('_', ' ', $action)));
    return str_replace(['Otp', 'By Self'], ['OTP', '(self-service)'], $label);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (empty($_POST['csrf_token']) || empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $flash = ['type' => 'err', 'text' => 'Your session has expired. Please refresh the page and try again.'];
    } else {
        $action = $_POST['action'] ?? '';
        if ($action === 'upload_profile_picture') {
            $result = handleProfilePictureUpload($_FILES['profile_picture'] ?? null, $user['id_number'], $user['profile_picture']);
            if ($result['status']) {
                $stmt = $conn->prepare("UPDATE users SET profile_picture = ? WHERE id_number = ?");
                $stmt->bind_param("ss", $result['path'], $user['id_number']);
                $stmt->execute();
                $user['profile_picture'] = $result['path'];
                $flash = ['type' => 'ok', 'text' => 'Profile picture updated.'];
            } else {
                $flash = ['type' => 'err', 'text' => $result['message']];
            }
        } elseif ($action === 'remove_profile_picture') {
            deleteProfilePictureFile($user['profile_picture']);
            $stmt = $conn->prepare("UPDATE users SET profile_picture = NULL WHERE id_number = ?");
            $stmt->bind_param("s", $user['id_number']);
            $stmt->execute();
            $user['profile_picture'] = null;
            $flash = ['type' => 'ok', 'text' => 'Profile picture removed.'];
        }
    }
}

// -----------------------------------------------------------------
// Academic modules (My Subjects, Attendance, Grades, etc.) are UI
// scaffolding only for now — no backing tables/logic exist yet. Each
// one renders a "Coming Soon" placeholder in its own panel until the
// real feature is built, so the sidebar/IA can be reviewed before any
// backend work starts.
// -----------------------------------------------------------------
const COMING_SOON_MODULES = [
    'subjects'      => ['label' => 'My Subjects',      'icon' => 'bi-journal-bookmark-fill', 'desc' => "Your assigned subjects and classes will appear here once the academic module is built."],
    'students'      => ['label' => 'My Students',      'icon' => 'bi-people-fill',           'desc' => "Your class lists and student rosters will appear here once the academic module is built."],
    'schedule'      => ['label' => 'Class Schedule',   'icon' => 'bi-calendar-week-fill',    'desc' => "Your weekly teaching schedule will appear here once the academic module is built."],
    'attendance'    => ['label' => 'Attendance',       'icon' => 'bi-clipboard-check-fill',  'desc' => "You'll record and review student attendance here once the academic module is built."],
    'grades'        => ['label' => 'Grades',           'icon' => 'bi-award-fill',            'desc' => "You'll manage and submit student grades here once the academic module is built."],
    'materials'     => ['label' => 'Course Materials', 'icon' => 'bi-folder2-open',          'desc' => "You'll upload and share course materials here once this module is built."],
    'announcements' => ['label' => 'Announcements',    'icon' => 'bi-megaphone-fill',        'desc' => "You'll post announcements to your students here once this module is built."],
    'reports'       => ['label' => 'Reports',          'icon' => 'bi-bar-chart-fill',        'desc' => "Attendance and grade reports will appear here once this module is built."],
];

$view = $_GET['view'] ?? 'overview';
$validViews = array_merge(['overview', 'profile', 'security', 'activity_log'], array_keys(COMING_SOON_MODULES));
if (!in_array($view, $validViews, true)) {
    $view = 'overview';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dashboard | CSU Instructor Registration and Management</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="../CSS/admin_console.css">
</head>
<body>

<div class="app-shell">
  <aside class="sidebar">
    <div class="sidebar__brand">
      <div class="console-icon"><i class="bi bi-mortarboard-fill"></i></div>
      <div>
        <p class="sidebar__eyebrow">CSU IRM</p>
        <p class="sidebar__title">My Dashboard</p>
      </div>
    </div>
    <div class="sidebar__profile-top">
      <div class="sidebar__avatar sidebar__avatar--lg">
        <?php if ($avatarUrl = profile_picture_url($user['profile_picture'])): ?>
          <img src="<?= h($avatarUrl) ?>" alt="">
        <?php else: ?>
          <?= h(strtoupper(substr($user['username'], 0, 1))) ?>
        <?php endif; ?>
      </div>
      <p class="sidebar__profile-top-name"><?= h($user['username']) ?></p>
      <span class="role-tag"><i class="bi bi-mortarboard-fill"></i> <?= h(ucfirst($user['role'])) ?></span>
    </div>
    <nav class="sidebar__nav">
      <p class="sidebar__section-label">Main</p>
      <a href="?view=overview" class="sidebar__link <?= $view === 'overview' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-grid-fill"></i> Dashboard</span>
      </a>

      <p class="sidebar__section-label">Academic</p>
      <a href="?view=subjects" class="sidebar__link <?= $view === 'subjects' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-journal-bookmark-fill"></i> My Subjects</span>
      </a>
      <a href="?view=students" class="sidebar__link <?= $view === 'students' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-people-fill"></i> My Students</span>
      </a>
      <a href="?view=schedule" class="sidebar__link <?= $view === 'schedule' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-calendar-week-fill"></i> Class Schedule</span>
      </a>
      <a href="?view=attendance" class="sidebar__link <?= $view === 'attendance' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-clipboard-check-fill"></i> Attendance</span>
      </a>
      <a href="?view=grades" class="sidebar__link <?= $view === 'grades' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-award-fill"></i> Grades</span>
      </a>

      <p class="sidebar__section-label">Learning</p>
      <a href="?view=materials" class="sidebar__link <?= $view === 'materials' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-folder2-open"></i> Course Materials</span>
      </a>
      <a href="?view=announcements" class="sidebar__link <?= $view === 'announcements' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-megaphone-fill"></i> Announcements</span>
      </a>

      <p class="sidebar__section-label">Reports</p>
      <a href="?view=reports" class="sidebar__link <?= $view === 'reports' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-bar-chart-fill"></i> Reports</span>
      </a>

      <p class="sidebar__section-label">Account</p>
      <a href="?view=profile" class="sidebar__link <?= $view === 'profile' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-person-fill"></i> My Profile</span>
      </a>
      <a href="?view=security" class="sidebar__link <?= $view === 'security' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-shield-lock-fill"></i> Change Password</span>
      </a>
      <a href="?view=activity_log" class="sidebar__link <?= $view === 'activity_log' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-clock-history"></i> Activity Log</span>
      </a>
    </nav>
    <div class="sidebar__footer">
      <a href="logout.php" class="btn-ghost sidebar__logout" style="width:100%; box-sizing:border-box;"><i class="bi bi-box-arrow-right"></i> Logout</a>
    </div>
  </aside>

  <main class="app-main">
  <div class="console-wrap">

    <?php if ($flash): ?>
      <div class="console-flash <?= $flash['type'] === 'ok' ? 'ok' : 'err' ?>"><?= h($flash['text']) ?></div>
    <?php endif; ?>

    <?php if ($view === 'overview'): ?>
      <div class="console-header">
        <div class="console-title">
          <div>
            <p>CSU Instructor Registration and Management</p>
            <h1>Welcome, <?= h($user['first_name']) ?></h1>
          </div>
        </div>
      </div>

      <div class="stat-grid">
        <div class="stat-tile"><div class="stat-tile__icon"><i class="bi bi-person-vcard-fill"></i></div><div><div class="num"><?= h($user['id_number']) ?></div><div class="label">Employee ID</div></div></div>
        <div class="stat-tile"><div class="stat-tile__icon"><i class="bi bi-patch-check-fill"></i></div><div><div class="num"><?= h(ucfirst($user['status'])) ?></div><div class="label">Account status</div></div></div>
        <div class="stat-tile"><div class="stat-tile__icon"><i class="bi bi-award-fill"></i></div><div><div class="num"><?= h(ucfirst($user['role'])) ?></div><div class="label">Role</div></div></div>
      </div>

      <p class="module-desc"><i class="bi bi-info-circle-fill"></i> The Academic, Learning, and Reports modules in the sidebar are planned for an upcoming update — you'll be able to manage subjects, attendance, grades, and more from here once they're built.</p>
    <?php endif; ?>

    <?php if ($view === 'profile'): ?>
      <div class="console-header">
        <div class="console-title"><div><h1>My Profile</h1></div></div>
      </div>

      <div class="panel">
        <div class="panel__header"><h2><i class="bi bi-camera-fill"></i> Profile Picture</h2></div>
        <div class="panel__body">
          <div class="profile-avatar-card">
            <div class="profile-avatar">
              <?php if ($avatarUrl = profile_picture_url($user['profile_picture'])): ?>
                <img src="<?= h($avatarUrl) ?>" alt="">
              <?php else: ?>
                <?= h(strtoupper(substr($user['username'], 0, 1))) ?>
              <?php endif; ?>
            </div>
            <div class="profile-avatar-actions">
              <form method="post" enctype="multipart/form-data" id="avatarUploadForm">
                <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                <input type="hidden" name="action" value="upload_profile_picture">
                <label class="btn-ghost profile-avatar-upload-btn" for="avatarFileInput">
                  <i class="bi bi-upload"></i> Change Photo
                </label>
                <input type="file" name="profile_picture" id="avatarFileInput" accept="image/png,image/jpeg,image/webp" style="display:none" onchange="document.getElementById('avatarUploadForm').submit()">
              </form>
              <?php if ($user['profile_picture']): ?>
              <form method="post">
                <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                <input type="hidden" name="action" value="remove_profile_picture">
                <button type="submit" class="btn-ghost">Remove Photo</button>
              </form>
              <?php endif; ?>
            </div>
            <p class="form-text" style="margin-top:6px; width:100%;">JPG, PNG, or WEBP. Max 2 MB.</p>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel__header"><h2><i class="bi bi-person-lines-fill"></i> Profile Information</h2></div>
        <div class="panel__body">

          <div class="profile-section">
            <h3 class="profile-section__title">Personal Information</h3>
            <div class="form-grid">
              <div class="form-field"><label>Full Name</label>
                <div><?= h(trim("{$user['first_name']} {$user['middle_name']} {$user['last_name']} {$user['extension']}")) ?></div>
              </div>
              <div class="form-field"><label>Sex</label><div><?= h($user['sex']) ?></div></div>
              <div class="form-field"><label>Birthdate</label><div><?= h($user['birthdate']) ?></div></div>
            </div>
          </div>

          <div class="profile-section">
            <h3 class="profile-section__title">Contact &amp; Address</h3>
            <div class="form-grid">
              <div class="form-field full"><label>Email</label><div><?= h($user['email'] ?? 'Not provided') ?></div></div>
              <div class="form-field full"><label>Address</label>
                <div><?= h(trim("{$user['street']}, {$user['barangay']}, {$user['city']}, {$user['province']}, {$user['region']} {$user['zip_code']}")) ?></div>
              </div>
            </div>
          </div>

          <div class="profile-section">
            <h3 class="profile-section__title">Account Information</h3>
            <div class="form-grid">
              <div class="form-field"><label>Employee ID</label><div><?= h($user['id_number']) ?></div></div>
              <div class="form-field"><label>Username</label><div><?= h($user['username']) ?></div></div>
              <div class="form-field"><label>Role</label><div><?= h(ucfirst($user['role'])) ?></div></div>
              <div class="form-field"><label>Member Since</label><div><?= h($user['created_at']) ?></div></div>
            </div>
          </div>

        </div>
      </div>
    <?php endif; ?>

    <?php if ($view === 'security'): ?>
      <div class="console-header">
        <div class="console-title"><div><h1>Change Password</h1></div></div>
      </div>
      <div class="panel">
        <div class="panel__body">
          <p class="panel__empty" style="margin-bottom:14px;">
            Forgot your password, or want to change it? Use the reset flow — you'll need your Employee ID and your three security question answers.
          </p>
          <a href="forgot_password.php" class="btn-primary" style="text-decoration:none; display:inline-block;">
            <i class="bi bi-key-fill"></i> Reset Password
          </a>
        </div>
      </div>
    <?php endif; ?>

    <?php if ($view === 'activity_log'):
      $alSource = $_GET['source'] ?? 'all';
      if (!in_array($alSource, ['all', 'login', 'security'], true)) {
          $alSource = 'all';
      }
      $alDateFrom = trim((string)($_GET['from'] ?? ''));
      $alDateTo = trim((string)($_GET['to'] ?? ''));
      $alPage = max(1, (int)($_GET['page'] ?? 1));

      $ownActivity = get_own_activity_log($conn, $user['id_number'], [
          'source' => $alSource,
          'date_from' => $alDateFrom,
          'date_to' => $alDateTo,
      ], $alPage, 25);

      $alFilterQuery = 'source=' . urlencode($alSource)
          . ($alDateFrom !== '' ? '&from=' . urlencode($alDateFrom) : '')
          . ($alDateTo !== '' ? '&to=' . urlencode($alDateTo) : '');
    ?>
      <div class="console-header">
        <div class="console-title"><div><h1>Activity Log</h1></div></div>
      </div>
      <p class="module-desc"><i class="bi bi-info-circle-fill"></i> A record of your own account activity — logins/logouts (with device and IP) and security events like password resets. Visible only to you.</p>

      <div class="panel">
        <div class="panel__header"><h2><i class="bi bi-clock-history icon-info"></i> My Activity</h2></div>
        <div class="panel__body">
          <div class="role-filter-tabs">
            <?php $alTabSuffix = ($alDateFrom !== '' ? '&from=' . urlencode($alDateFrom) : '') . ($alDateTo !== '' ? '&to=' . urlencode($alDateTo) : ''); ?>
            <a href="?view=activity_log&amp;source=all<?= $alTabSuffix ?>" class="role-filter-tab <?= $alSource === 'all' ? 'active' : '' ?>">All</a>
            <a href="?view=activity_log&amp;source=login<?= $alTabSuffix ?>" class="role-filter-tab <?= $alSource === 'login' ? 'active' : '' ?>">Logins</a>
            <a href="?view=activity_log&amp;source=security<?= $alTabSuffix ?>" class="role-filter-tab <?= $alSource === 'security' ? 'active' : '' ?>">Security</a>
          </div>

          <form method="get" class="filter-bar">
            <input type="hidden" name="view" value="activity_log">
            <input type="hidden" name="source" value="<?= h($alSource) ?>">
            <input type="date" name="from" value="<?= h($alDateFrom) ?>" title="From date">
            <input type="date" name="to" value="<?= h($alDateTo) ?>" title="To date">
            <button type="submit" class="btn-sm btn-edit">Search</button>
            <?php if ($alDateFrom !== '' || $alDateTo !== ''): ?><a href="?view=activity_log&amp;source=<?= h($alSource) ?>" class="btn-sm btn-ghost">Clear</a><?php endif; ?>
          </form>

          <?php if (empty($ownActivity['rows'])): ?>
            <p class="panel__empty">No activity found for these filters.</p>
          <?php else: ?>
            <div class="table-scroll">
            <table class="console-table">
              <thead><tr><th>When</th><th>Type</th><th>Event</th><th>Device</th><th>IP Address</th></tr></thead>
              <tbody>
              <?php foreach ($ownActivity['rows'] as $log): ?>
                <tr>
                  <td><?= h(date('M j, Y g:i A', strtotime($log['created_at']))) ?></td>
                  <td>
                    <?php if ($log['source'] === 'login'): ?>
                      <i class="bi bi-box-arrow-in-right icon-info"></i> Login
                    <?php else: ?>
                      <i class="bi bi-shield-lock-fill icon-warning"></i> Security
                    <?php endif; ?>
                  </td>
                  <td><?= h($log['source'] === 'login' ? $log['action'] : humanize_activity_action($log['action'])) ?></td>
                  <td><?= h($log['detail'] ?: '—') ?></td>
                  <td><?= h($log['ip_address'] ?: '—') ?></td>
                </tr>
              <?php endforeach; ?>
              </tbody>
            </table>
            </div>

            <?php if ($ownActivity['total_pages'] > 1): ?>
            <div class="row-actions" style="justify-content:flex-end; margin-top:14px;">
              <span class="form-text" style="margin-right:8px;">Page <?= (int)$ownActivity['page'] ?> of <?= (int)$ownActivity['total_pages'] ?> (<?= (int)$ownActivity['total'] ?> total)</span>
              <?php if ($ownActivity['page'] > 1): ?>
                <a href="?view=activity_log&amp;<?= $alFilterQuery ?>&amp;page=<?= $ownActivity['page'] - 1 ?>" class="btn-sm btn-ghost">Previous</a>
              <?php endif; ?>
              <?php if ($ownActivity['page'] < $ownActivity['total_pages']): ?>
                <a href="?view=activity_log&amp;<?= $alFilterQuery ?>&amp;page=<?= $ownActivity['page'] + 1 ?>" class="btn-sm btn-ghost">Next</a>
              <?php endif; ?>
            </div>
            <?php endif; ?>
          <?php endif; ?>
        </div>
      </div>
    <?php endif; ?>

    <?php if (array_key_exists($view, COMING_SOON_MODULES)): $module = COMING_SOON_MODULES[$view]; ?>
      <div class="console-header">
        <div class="console-title"><div><h1><?= h($module['label']) ?></h1></div></div>
      </div>
      <div class="panel">
        <div class="panel__header"><h2><i class="bi <?= h($module['icon']) ?> icon-success"></i> <?= h($module['label']) ?></h2></div>
        <div class="panel__body coming-soon">
          <i class="bi bi-cone-striped"></i>
          <h3>Coming Soon</h3>
          <p><?= h($module['desc']) ?></p>
        </div>
      </div>
    <?php endif; ?>

  </div>
  </main>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
