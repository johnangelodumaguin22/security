<?php
session_start();
include '../include/db_connect.php';
include '../include/common_passwords.php';
include '../include/registration_helpers.php';
include '../include/auth_guard.php';
include '../include/permissions.php';
include '../include/mail_approval.php';
include '../include/mail_account_created.php';
include '../include/mail_account_status.php'; // blocked/unblocked/deleted notifications
include '../include/profile_picture.php';
include '../include/otp.php'; // for log_otp_action() — reused as the general auth-security log
include '../include/login_logs.php'; // Login Logs — who's logged in/out, IP, device, last action

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
ini_set('display_errors', '0');

require_role(['superadmin']);

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$myIdNumber = $_SESSION['id_number'];
$flash = null;
$editErrors = [];
$editValues = null;
$editTarget = null;
$pwErrors = [];
$createErrors = [];
$createValues = [];
$showCreateForm = false;
$forceAccountsView = false;
$permissionsAdminId = null;
// Set only when Change Username/Password's Current Password field was
// specifically wrong — reopens that modal and highlights the field itself,
// instead of leaving the visitor to notice a generic banner at the top.
$usernameChangePasswordError = null;
$passwordChangePasswordError = null;

function csrf_ok() {
    return !empty($_POST['csrf_token']) && !empty($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']);
}

// Same rule set as forgot_password.php's is_strong_password() — kept as its
// own copy rather than shared, matching this codebase's existing pattern of
// small per-page helpers instead of over-centralizing.
function is_strong_password($pwd) {
    if (preg_match('/^\s|\s$/', $pwd)) return false;
    $len = mb_strlen($pwd);
    if ($len < 8 || $len > 72) return false;
    if (isCommonWeakPassword($pwd)) return false;
    return true;
}

// -----------------------------------------------------------------
// Rate limiting for account creation — same escalating lockout used on
// register.php and login.php, scoped to its own session key so it never
// interferes with the rest of this dashboard's actions.
// -----------------------------------------------------------------
function create_account_rate_limit_status() {
    if (!isset($_SESSION['ca_attempts'])) $_SESSION['ca_attempts'] = 0;
    if (!isset($_SESSION['ca_lockout_until'])) $_SESSION['ca_lockout_until'] = 0;
    $now = time();
    if ($now >= $_SESSION['ca_lockout_until']) {
        $_SESSION['ca_lockout_until'] = 0;
        return 0;
    }
    return $_SESSION['ca_lockout_until'] - $now;
}

function create_account_rate_limit_hit() {
    $_SESSION['ca_attempts']++;
    $now = time();
    if ($_SESSION['ca_attempts'] >= 25) {
        $_SESSION['ca_lockout_until'] = $now + 300;
    } elseif ($_SESSION['ca_attempts'] >= 15) {
        $_SESSION['ca_lockout_until'] = $now + 60;
    } elseif ($_SESSION['ca_attempts'] >= 8) {
        $_SESSION['ca_lockout_until'] = $now + 20;
    }
}

function create_account_rate_limit_reset() {
    $_SESSION['ca_attempts'] = 0;
    $_SESSION['ca_lockout_until'] = 0;
}

function fetch_any_account($conn, $idNumber) {
    $stmt = $conn->prepare("SELECT * FROM users WHERE id_number = ?");
    $stmt->bind_param("s", $idNumber);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    return $row ?: null;
}

// -----------------------------------------------------------------
// POST actions
// -----------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_ok()) {
        $flash = ['type' => 'err', 'text' => 'Your session has expired. Please refresh the page and try again.'];
    } else {
        $action = $_POST['action'] ?? '';
        $targetId = trim((string)($_POST['id_number'] ?? ''));

        if ($action === 'approve' || $action === 'reject_registration' || $action === 'block_registration') {
            $moduleAction = ['approve' => 'approve', 'reject_registration' => 'reject', 'block_registration' => 'block'][$action];
            $newStatus = ['approve' => 'approved', 'reject_registration' => 'rejected', 'block_registration' => 'blocked'][$action];
            $pendingAccount = $action === 'reject_registration'
                ? discardPendingRegistration($conn, $targetId)
                : promotePendingRegistration($conn, $targetId, $newStatus);

            if (!$pendingAccount) {
                $flash = ['type' => 'err', 'text' => 'That registration is no longer pending.'];
            } else {
                $targetName = trim($pendingAccount['first_name'] . ' ' . $pendingAccount['last_name']);
                log_registration_action($conn, $moduleAction, 'superadmin', $_SESSION['username'], null, $targetId, $targetName, 'pending', $newStatus);
                if ($action === 'approve' && !empty($pendingAccount['email'])) {
                    send_approval_email($pendingAccount['email'], $pendingAccount['first_name']);
                }
                $labels = ['approve' => 'Registration approved.', 'reject_registration' => 'Registration rejected.', 'block_registration' => 'Registration blocked.'];
                $flash = ['type' => 'ok', 'text' => $labels[$action]];
            }

        // Blocking someone else's account is powerful enough to require the
        // acting Superadmin to re-enter their own current password here
        // before it proceeds, same security-confirmation pattern already
        // used for Change Role above. Both block and unblock now also
        // require a written reason — always recorded in the audit trail,
        // surfaced in Activity Logs' detail column.
        } elseif ($action === 'block' || $action === 'unblock') {
            $account = fetch_any_account($conn, $targetId);
            $currentPassword = (string)($_POST['current_password'] ?? '');
            $reason = trim((string)($_POST['reason'] ?? ''));
            $me = $action === 'block' ? resolve_self_account($conn, $myIdNumber) : null;

            if ($action === 'block' && ($currentPassword === '' || !$me || !verify_login_password($myIdNumber, $currentPassword, $me['password']))) {
                $flash = ['type' => 'err', 'text' => 'Incorrect password. Block cancelled.'];
            } elseif ($reason === '' || mb_strlen($reason) < 5 || mb_strlen($reason) > 500 || hasHtmlOrScript($reason)) {
                $flash = ['type' => 'err', 'text' => 'Please provide a reason (5-500 characters, no HTML).'];
            } elseif (!$account) {
                $flash = ['type' => 'err', 'text' => 'Account not found.'];
            } elseif ($targetId === $myIdNumber) {
                $flash = ['type' => 'err', 'text' => 'You cannot block your own account.'];
            } elseif ($action === 'block' && $account['role'] === 'superadmin' && active_superadmin_count($conn) <= 1) {
                $flash = ['type' => 'err', 'text' => 'Action cannot be completed. The system must have at least one active Superadmin.'];
            } else {
                $newStatus = $action === 'block' ? 'blocked' : 'approved';
                $fromStatus = $action === 'block' ? 'approved' : 'blocked';
                $stmt = $conn->prepare("UPDATE users SET status = ? WHERE id_number = ? AND status = ?");
                $stmt->bind_param("sss", $newStatus, $targetId, $fromStatus);
                $stmt->execute();
                if ($stmt->affected_rows > 0) {
                    $targetName = trim(($account['first_name'] ?? '') . ' ' . ($account['last_name'] ?? '')) ?: $account['username'];
                    log_registration_action($conn, $action, 'superadmin', $_SESSION['username'], null, $targetId, $targetName, $fromStatus, $newStatus, $reason);
                    if (!empty($account['email'])) {
                        $action === 'block'
                            ? send_account_blocked_email($account['email'], $account['first_name'] ?? '', $reason)
                            : send_account_unblocked_email($account['email'], $account['first_name'] ?? '', $reason);
                    }
                    $flash = ['type' => 'ok', 'text' => $action === 'block' ? 'Account blocked.' : 'Account unblocked.'];
                } else {
                    $flash = ['type' => 'err', 'text' => 'Account was not in the expected state.'];
                }
            }

        // Change Role — the single action covering both Admin -> Superadmin
        // promotion and Superadmin -> Admin demotion for an already-active
        // account (replaces the old separate promote_to_superadmin/
        // demote_to_admin actions entirely, not just in the UI — a role
        // change is powerful enough to require the ACTING Superadmin to
        // re-enter their own current password here before it proceeds, on
        // top of every other guard already in place). Effective immediately
        // for a live session of the target account — see require_role() in
        // auth_guard.php.
        } elseif ($action === 'change_role') {
            $account = fetch_any_account($conn, $targetId);
            $newRole = $_POST['new_role'] ?? '';
            $currentPassword = (string)($_POST['current_password'] ?? '');
            $reason = trim((string)($_POST['reason'] ?? ''));
            $me = resolve_self_account($conn, $myIdNumber);

            if ($currentPassword === '' || !$me || !verify_login_password($myIdNumber, $currentPassword, $me['password'])) {
                $flash = ['type' => 'err', 'text' => 'Incorrect password. Role change cancelled.'];
            } elseif ($reason === '' || mb_strlen($reason) < 5 || mb_strlen($reason) > 500 || hasHtmlOrScript($reason)) {
                $flash = ['type' => 'err', 'text' => 'Please provide a reason (5-500 characters, no HTML).'];
            } elseif (!$account) {
                $flash = ['type' => 'err', 'text' => 'Account not found.'];
            } elseif ($targetId === $myIdNumber) {
                $flash = ['type' => 'err', 'text' => 'You cannot change your own role here.'];
            } elseif (!in_array($account['role'], ['admin', 'superadmin'], true) || $account['status'] !== 'approved') {
                $flash = ['type' => 'err', 'text' => 'Only an active Admin or Superadmin account can have its role changed.'];
            } elseif (!in_array($newRole, ['admin', 'superadmin'], true) || $newRole === $account['role']) {
                $flash = ['type' => 'err', 'text' => 'Please choose a different role.'];
            } elseif ($newRole === 'admin' && active_superadmin_count($conn) <= 1) {
                $flash = ['type' => 'err', 'text' => 'Action cannot be completed. The system must have at least one active Superadmin.'];
            } else {
                $targetName = trim(($account['first_name'] ?? '') . ' ' . ($account['last_name'] ?? '')) ?: $account['username'];
                $ok = $newRole === 'superadmin'
                    ? promote_to_superadmin($conn, $targetId)
                    : demote_to_admin($conn, $targetId);
                if ($ok) {
                    $logAction = $newRole === 'superadmin' ? 'promote' : 'demote';
                    log_role_change($conn, $logAction, $_SESSION['username'], $targetId, $targetName, $account['status'], $account['status'], $account['role'], $newRole, 'Account Management', $reason);
                    $flash = ['type' => 'ok', 'text' => $targetName . '\'s role has been changed to ' . ucfirst($newRole) . '.'];
                } else {
                    $flash = ['type' => 'err', 'text' => 'Account was not in the expected state.'];
                }
            }

        // Unblocks a blocked Admin/Superadmin with an explicitly chosen role
        // — see the role-picker modal in the Accounts table below. Powerful
        // enough to require a written reason and the acting Superadmin's own
        // password, same as every other sensitive action here. ($action
        // stays 'reactivate_account'/'reactivate' internally — only the
        // user-facing wording changed to "Unblock" — so the existing
        // promote/demote/reactivate role-change audit-log handling keeps
        // working unchanged.)
        } elseif ($action === 'reactivate_account') {
            $account = fetch_any_account($conn, $targetId);
            $chosenRole = $_POST['new_role'] ?? '';
            $reason = trim((string)($_POST['reason'] ?? ''));
            $currentPassword = (string)($_POST['current_password'] ?? '');
            $me = resolve_self_account($conn, $myIdNumber);
            if ($currentPassword === '' || !$me || !verify_login_password($myIdNumber, $currentPassword, $me['password'])) {
                $flash = ['type' => 'err', 'text' => 'Incorrect password. Unblock cancelled.'];
            } elseif ($reason === '' || mb_strlen($reason) < 5 || mb_strlen($reason) > 500 || hasHtmlOrScript($reason)) {
                $flash = ['type' => 'err', 'text' => 'Please provide a reason (5-500 characters, no HTML).'];
            } elseif (!$account) {
                $flash = ['type' => 'err', 'text' => 'Account not found.'];
            } elseif ($targetId === $myIdNumber) {
                $flash = ['type' => 'err', 'text' => 'You cannot unblock your own account.'];
            } elseif (!in_array($account['role'], ['admin', 'superadmin'], true) || $account['status'] !== 'blocked') {
                $flash = ['type' => 'err', 'text' => 'Only a blocked Admin or Superadmin account can be unblocked.'];
            } elseif (!in_array($chosenRole, ['admin', 'superadmin'], true)) {
                $flash = ['type' => 'err', 'text' => 'Please choose a role to unblock this account as.'];
            } else {
                $targetName = trim(($account['first_name'] ?? '') . ' ' . ($account['last_name'] ?? '')) ?: $account['username'];
                if (reactivate_account($conn, $targetId, $chosenRole)) {
                    log_role_change($conn, 'reactivate', $_SESSION['username'], $targetId, $targetName, 'blocked', 'approved', $account['role'], $chosenRole, 'Account Management', $reason);
                    if (!empty($account['email'])) {
                        send_account_unblocked_email($account['email'], $account['first_name'] ?? '', $reason);
                    }
                    $flash = ['type' => 'ok', 'text' => $targetName . ' has been unblocked as ' . ucfirst($chosenRole) . '.'];
                } else {
                    $flash = ['type' => 'err', 'text' => 'Account was not in the expected state.'];
                }
            }

        // Deleting an account outright (no approval step in the way, unlike
        // an Admin's delete request) is powerful enough to require the acting
        // Superadmin to re-enter their own current password here first, same
        // security-confirmation pattern as Block/Change Role above.
        } elseif ($action === 'delete') {
            $account = fetch_any_account($conn, $targetId);
            $reason = trim((string)($_POST['reason'] ?? ''));
            $currentPassword = (string)($_POST['current_password'] ?? '');
            $me = resolve_self_account($conn, $myIdNumber);
            if ($currentPassword === '' || !$me || !verify_login_password($myIdNumber, $currentPassword, $me['password'])) {
                $flash = ['type' => 'err', 'text' => 'Incorrect password. Deletion cancelled.'];
            } elseif (!$account) {
                $flash = ['type' => 'err', 'text' => 'Account not found.'];
            } elseif ($targetId === $myIdNumber) {
                $flash = ['type' => 'err', 'text' => 'You cannot delete your own account.'];
            } elseif ($account['role'] === 'superadmin') {
                $flash = ['type' => 'err', 'text' => 'Superadmins cannot delete another Superadmin account.'];
            // Same reason requirement an Admin already has to meet on a
            // delete *request* — a Superadmin deleting directly (no approval
            // step in the way) must still leave a written reason behind.
            } elseif ($reason === '' || mb_strlen($reason) < 5 || mb_strlen($reason) > 500 || hasHtmlOrScript($reason)) {
                $flash = ['type' => 'err', 'text' => 'Please provide a reason (5-500 characters, no HTML).'];
            } else {
                $targetName = trim(($account['first_name'] ?? '') . ' ' . ($account['last_name'] ?? '')) ?: $account['username'];
                if (!empty($account['email'])) {
                    send_account_deleted_email($account['email'], $account['first_name'] ?? '', $reason);
                }
                $stmt = $conn->prepare("DELETE FROM users WHERE id_number = ?");
                $stmt->bind_param("s", $targetId);
                $stmt->execute();
                log_registration_action($conn, 'delete', 'superadmin', $_SESSION['username'], null, $targetId, $targetName, $account['status'], 'deleted', $reason);
                $flash = ['type' => 'ok', 'text' => 'Account deleted.'];
            }

        } elseif ($action === 'save_edit') {
            $account = fetch_any_account($conn, $targetId);
            if (!$account) {
                $flash = ['type' => 'err', 'text' => 'Account not found.'];
            } else {
                [$errors, $clean] = validateProfileEdit($conn, $_POST, $targetId);
                if (!empty($errors)) {
                    $editErrors = $errors;
                    $editValues = $_POST;
                    $editTarget = $account;
                } else {
                    $stmt = $conn->prepare("UPDATE users SET
                        first_name=?, middle_name=?, last_name=?, extension=?, sex=?, birthdate=?, age=?,
                        street=?, barangay=?, city=?, province=?, region=?, zip_code=?, email=?
                        WHERE id_number=?");
                    $stmt->bind_param(
                        "sssssssssssssss",
                        $clean['first_name'], $clean['middle_name'], $clean['last_name'], $clean['extension'],
                        $clean['sex'], $clean['birthdate'], $clean['age'],
                        $clean['street'], $clean['barangay'], $clean['city'], $clean['province'], $clean['region'],
                        $clean['zip'], $clean['email'], $targetId
                    );
                    $stmt->execute();
                    $flash = ['type' => 'ok', 'text' => 'Account info updated.'];
                }
            }

        // Lets a Superadmin set a new password on someone else's behalf —
        // e.g. the account holder personally asked for their password to be
        // changed. Never available for your own row (use Forgot Password for
        // that) or for another Superadmin's account (same "only that account
        // holder controls it" principle already applied to deleting a
        // Superadmin elsewhere on this page).
        } elseif ($action === 'change_password') {
            $account = fetch_any_account($conn, $targetId);
            if (!$account) {
                $flash = ['type' => 'err', 'text' => 'Account not found.'];
            } elseif ($targetId === $myIdNumber) {
                $flash = ['type' => 'err', 'text' => 'You cannot change your own password here.'];
            } elseif ($account['role'] === 'superadmin') {
                $flash = ['type' => 'err', 'text' => 'Only that Superadmin can change their own password.'];
            } else {
                $newPw = (string)($_POST['new_password'] ?? '');
                $confirmPw = (string)($_POST['confirm_new_password'] ?? '');
                if ($newPw === '' || $confirmPw === '') {
                    $pwErrors['_form'] = 'Please fill in both password fields.';
                } elseif ($newPw !== $confirmPw) {
                    $pwErrors['_form'] = 'Passwords do not match.';
                } elseif (!is_strong_password($newPw)) {
                    $pwErrors['_form'] = 'Password must be 8-72 characters and not a commonly used password.';
                } else {
                    $hashed = password_hash($newPw, PASSWORD_DEFAULT);
                    $stmt = $conn->prepare("UPDATE users SET password = ? WHERE id_number = ?");
                    $stmt->bind_param("ss", $hashed, $targetId);
                    $stmt->execute();
                    log_otp_action($conn, $targetId, $account['email'] ?? '', 'password_changed_by_admin', $account['role']);
                    $flash = ['type' => 'ok', 'text' => 'Password changed for ' . $account['username'] . '.'];
                }
            }

        } elseif ($action === 'review_delete_request') {
            $requestId = (int)($_POST['request_id'] ?? 0);
            $decision = $_POST['decision'] ?? '';
            $stmt = $conn->prepare("SELECT * FROM delete_requests WHERE id = ? AND status = 'pending'");
            $stmt->bind_param("i", $requestId);
            $stmt->execute();
            $reqRow = $stmt->get_result()->fetch_assoc();
            $stmt->close();

            if (!$reqRow || !in_array($decision, ['approve', 'reject'], true)) {
                $flash = ['type' => 'err', 'text' => 'Invalid request.'];
            } else {
                $newStatus = $decision === 'approve' ? 'approved' : 'rejected';
                if ($decision === 'approve') {
                    $target = fetch_any_account($conn, $reqRow['target_id_number']);
                    if ($target && $target['role'] === 'superadmin') {
                        $flash = ['type' => 'err', 'text' => 'Superadmins cannot delete another Superadmin account.'];
                    } elseif ($target && $reqRow['target_id_number'] === $myIdNumber) {
                        $flash = ['type' => 'err', 'text' => 'Refusing to delete your own account via this queue.'];
                    } else {
                        if ($target) {
                            if (!empty($target['email'])) {
                                send_account_deleted_email($target['email'], $target['first_name'] ?? '', $reqRow['reason'] ?? '');
                            }
                            $del = $conn->prepare("DELETE FROM users WHERE id_number = ?");
                            $del->bind_param("s", $reqRow['target_id_number']);
                            $del->execute();
                        }
                        $upd = $conn->prepare("UPDATE delete_requests SET status = ?, reviewed_by_username = ?, reviewed_at = NOW() WHERE id = ?");
                        $upd->bind_param("ssi", $newStatus, $_SESSION['username'], $requestId);
                        $upd->execute();
                        log_registration_action($conn, 'delete_request_approved', 'superadmin', $_SESSION['username'], null, $reqRow['target_id_number'], $reqRow['target_name'], 'pending', 'deleted');
                        $flash = ['type' => 'ok', 'text' => $target ? 'Account deleted and request approved.' : 'Account was already gone; request marked approved.'];
                    }
                } else {
                    $upd = $conn->prepare("UPDATE delete_requests SET status = ?, reviewed_by_username = ?, reviewed_at = NOW() WHERE id = ?");
                    $upd->bind_param("ssi", $newStatus, $_SESSION['username'], $requestId);
                    $upd->execute();
                    log_registration_action($conn, 'delete_request_rejected', 'superadmin', $_SESSION['username'], null, $reqRow['target_id_number'], $reqRow['target_name'], 'pending', 'rejected');
                    $flash = ['type' => 'ok', 'text' => 'Delete request rejected.'];
                }
            }

        } elseif ($action === 'create_account') {
            $showCreateForm = true;
            $caLockRemaining = create_account_rate_limit_status();
            if ($caLockRemaining > 0) {
                $createValues = $_POST;
                $flash = ['type' => 'err', 'text' => "Too many attempts. Please wait {$caLockRemaining} seconds and try again."];
            } else {
                create_account_rate_limit_hit();
                $currentPassword = (string)($_POST['current_password'] ?? '');
                $me = resolve_self_account($conn, $myIdNumber);
                if ($currentPassword === '' || !$me || !verify_login_password($myIdNumber, $currentPassword, $me['password'])) {
                    $createValues = $_POST;
                    $flash = ['type' => 'err', 'text' => 'Incorrect password. Account creation cancelled.'];
                } else {
                    $role = $_POST['new_role'] ?? 'admin';
                    if (!in_array($role, ['admin', 'superadmin'], true)) {
                        $role = 'admin';
                    }
                    // Creating an Admin or Superadmin no longer collects any
                    // confidential personal information — only a login identity
                    // (username + password). The new hire fills in their own
                    // profile on first login (see complete_profile.php), which
                    // also means the temporary password set here is replaced
                    // with one only its owner ever knows.
                    try {
                        [$errors, $clean] = validateBareAccountCreation($conn, $_POST);

                        // The Superadmin now manually chooses this account's
                        // starting password (never a fixed/locked default) —
                        // same composition policy enforced everywhere else in
                        // this app. admin_dashboard.php's own Create Account
                        // still uses its own fixed default, so this check is
                        // only here, not in the shared validateBareAccountCreation().
                        $rawPassword = (string)($_POST['password'] ?? '');
                        $repassword = (string)($_POST['repassword'] ?? '');
                        if ($rawPassword === '') {
                            $errors['password'] = "Password is required.";
                        } elseif (preg_match('/^\s|\s$/', $rawPassword)) {
                            $errors['password'] = "Password cannot have leading or trailing spaces.";
                        } elseif (mb_strlen($rawPassword) < 8 || mb_strlen($rawPassword) > 72) {
                            $errors['password'] = "Password must be between 8 and 72 characters.";
                        } elseif (!preg_match('/[A-Z]/', $rawPassword)) {
                            $errors['password'] = "Password must contain at least one uppercase letter.";
                        } elseif (!preg_match('/[a-z]/', $rawPassword)) {
                            $errors['password'] = "Password must contain at least one lowercase letter.";
                        } elseif (!preg_match('/[0-9]/', $rawPassword)) {
                            $errors['password'] = "Password must contain at least one number.";
                        } elseif (!preg_match('/[!@#$%^&*()_\-+=?]/', $rawPassword)) {
                            $errors['password'] = "Password must contain at least one special character (! @ # $ % ^ & * ( ) _ - + = ?).";
                        } elseif (isCommonWeakPassword($rawPassword)) {
                            $errors['password'] = "This password is too common. Please choose a stronger one.";
                        } elseif (!empty($clean['username']) && stripos($rawPassword, $clean['username']) !== false) {
                            $errors['password'] = "Password must not contain the username.";
                        } elseif ($repassword === '') {
                            $errors['repassword'] = "Please re-enter the password.";
                        } elseif ($rawPassword !== $repassword) {
                            $errors['repassword'] = "Passwords do not match.";
                        }

                        if (!empty($errors)) {
                            $createErrors = $errors;
                            $createValues = $_POST;
                        } else {
                            $result = createBareStaffAccount($conn, $clean['username'], $rawPassword, $role, $clean['email']);
                            if ($result['status']) {
                                create_account_rate_limit_reset();
                                log_registration_action($conn, 'create_account', 'superadmin', $_SESSION['username'], null, $result['id_number'], $clean['username'], '', $role);
                                $emailSent = send_account_created_email($clean['email'], $clean['username'], $rawPassword, $role);
                                $flash = ['type' => 'ok', 'text' => ucfirst($role) . ' account created: ' . $result['id_number'] . '. '
                                    . ($emailSent ? 'Their username and password were emailed to ' . $clean['email'] . '.' : 'The account was created, but the credentials email could not be sent — please share them with the new ' . $role . ' manually.')
                                    . ' They must complete their profile on first login before they can access the dashboard.'];
                                $showCreateForm = false;
                                $forceAccountsView = true;
                            } else {
                                $createErrors = $result['errors'] ?? [];
                                $createValues = $_POST;
                                if (empty($createErrors)) {
                                    $flash = ['type' => 'err', 'text' => $result['message']];
                                }
                            }
                        }
                    } catch (Throwable $e) {
                        error_log('Account creation failed: ' . $e->getMessage());
                        $createValues = $_POST;
                        $flash = ['type' => 'err', 'text' => 'A server error occurred. Please try again later.'];
                    }
                }
            }

        } elseif ($action === 'save_permissions') {
            $targetAdmin = fetch_any_account($conn, $targetId);
            if (!$targetAdmin || $targetAdmin['role'] !== 'admin') {
                $flash = ['type' => 'err', 'text' => 'Invalid Admin account.'];
            } else {
                $current = get_admin_permissions($conn, $targetId);
                $submitted = $_POST['perm'] ?? [];
                $changes = 0;
                foreach (PERMISSION_MODULES as $moduleKey => $module) {
                    if (!empty($module['bundle'])) {
                        // Single checkbox in the editor — checked grants view
                        // + every action for this module together; unchecked
                        // revokes all of it. No partial approve-only state.
                        $checked = !empty($submitted[$moduleKey]['view']);
                        $wantSet = $checked ? array_merge(['view'], array_keys($module['actions'])) : [];
                    } else {
                        $wantActions = [];
                        foreach ($module['actions'] as $actionKey => $actionLabel) {
                            if (!empty($submitted[$moduleKey][$actionKey])) {
                                $wantActions[] = $actionKey;
                            }
                        }
                        // Granting any specific action implies view access; view
                        // can also be granted on its own for read-only access.
                        $wantView = !empty($submitted[$moduleKey]['view']) || !empty($wantActions);
                        $wantSet = $wantView ? array_merge(['view'], $wantActions) : [];
                    }
                    $haveSet = array_keys($current[$moduleKey] ?? []);

                    foreach (array_diff($wantSet, $haveSet) as $toGrant) {
                        $ins = $conn->prepare("INSERT IGNORE INTO admin_permissions (admin_id_number, module, action, granted_by_username) VALUES (?, ?, ?, ?)");
                        $ins->bind_param("ssss", $targetId, $moduleKey, $toGrant, $_SESSION['username']);
                        $ins->execute();
                        log_permission_change($conn, $_SESSION['username'], $targetId, $targetAdmin['username'], $moduleKey, $toGrant, 'granted');
                        $changes++;
                    }
                    foreach (array_diff($haveSet, $wantSet) as $toRevoke) {
                        $del = $conn->prepare("DELETE FROM admin_permissions WHERE admin_id_number = ? AND module = ? AND action = ?");
                        $del->bind_param("sss", $targetId, $moduleKey, $toRevoke);
                        $del->execute();
                        log_permission_change($conn, $_SESSION['username'], $targetId, $targetAdmin['username'], $moduleKey, $toRevoke, 'revoked');
                        $changes++;
                    }
                }
                $flash = ['type' => 'ok', 'text' => $changes > 0 ? 'Permissions updated.' : 'No changes made.'];
                $permissionsAdminId = $targetId;
            }

        } elseif ($action === 'revoke_all_permissions') {
            $targetAdmin = fetch_any_account($conn, $targetId);
            if (!$targetAdmin || $targetAdmin['role'] !== 'admin') {
                $flash = ['type' => 'err', 'text' => 'Invalid Admin account.'];
            } else {
                $current = get_admin_permissions($conn, $targetId);
                $del = $conn->prepare("DELETE FROM admin_permissions WHERE admin_id_number = ?");
                $del->bind_param("s", $targetId);
                $del->execute();
                foreach ($current as $moduleKey => $actions) {
                    foreach (array_keys($actions) as $actionKey) {
                        log_permission_change($conn, $_SESSION['username'], $targetId, $targetAdmin['username'], $moduleKey, $actionKey, 'revoked');
                    }
                }
                $flash = ['type' => 'ok', 'text' => 'All permissions revoked for this Admin.'];
                $permissionsAdminId = $targetId;
            }

        // Not available for the hardcoded recovery account — it has no
        // `users` row for a profile_picture column to live on.
        } elseif ($action === 'upload_profile_picture' && $myIdNumber === DEFAULT_SUPERADMIN_ID) {
            $flash = ['type' => 'err', 'text' => 'A profile picture isn\'t available for the recovery account.'];

        } elseif ($action === 'upload_profile_picture') {
            $me = fetch_any_account($conn, $myIdNumber);
            $result = handleProfilePictureUpload($_FILES['profile_picture'] ?? null, $myIdNumber, $me['profile_picture'] ?? null);
            if ($result['status']) {
                $stmt = $conn->prepare("UPDATE users SET profile_picture = ? WHERE id_number = ?");
                $stmt->bind_param("ss", $result['path'], $myIdNumber);
                $stmt->execute();
                $flash = ['type' => 'ok', 'text' => 'Profile picture updated.'];
            } else {
                $flash = ['type' => 'err', 'text' => $result['message']];
            }

        } elseif ($action === 'remove_profile_picture' && $myIdNumber === DEFAULT_SUPERADMIN_ID) {
            $flash = ['type' => 'err', 'text' => 'A profile picture isn\'t available for the recovery account.'];

        } elseif ($action === 'remove_profile_picture') {
            $me = fetch_any_account($conn, $myIdNumber);
            deleteProfilePictureFile($me['profile_picture'] ?? null);
            $stmt = $conn->prepare("UPDATE users SET profile_picture = NULL WHERE id_number = ?");
            $stmt->bind_param("s", $myIdNumber);
            $stmt->execute();
            $flash = ['type' => 'ok', 'text' => 'Profile picture removed.'];

        // Self-service username change, STEP 1 of 2 — the built-in recovery
        // Superadmin (DEFAULT_SUPERADMIN_ID) is exempt: its username must
        // stay fixed and known, since it's the documented fallback way back
        // in if every other Superadmin account is ever locked out. On
        // success this does NOT apply the change yet — it emails a code to
        // the account's own address and stashes the pending new username in
        // the session; confirm_username_change (below) applies it once that
        // code comes back correct.
        } elseif ($action === 'change_own_username') {
            $me = resolve_self_account($conn, $myIdNumber);
            $newUsernameRaw = (string)($_POST['new_username'] ?? '');
            $newUsername = trim($newUsernameRaw);
            $currentPassword = (string)($_POST['current_password'] ?? '');

            if ($myIdNumber === DEFAULT_SUPERADMIN_ID) {
                $flash = ['type' => 'err', 'text' => 'The default Superadmin account\'s username cannot be changed.'];
            } elseif (!$me) {
                $flash = ['type' => 'err', 'text' => 'Account not found.'];
            } elseif ($currentPassword === '' || !verify_login_password($myIdNumber, $currentPassword, $me['password'])) {
                $flash = ['type' => 'err', 'text' => 'Incorrect password. Username change cancelled.'];
                $usernameChangePasswordError = 'Your current password you inputted is wrong.';
            } elseif ($newUsernameRaw === '' || hasBadSpacing($newUsernameRaw)) {
                $flash = ['type' => 'err', 'text' => 'Username cannot be empty or have leading/trailing/repeated spaces.'];
            } elseif (preg_match('/\s/', $newUsername)) {
                $flash = ['type' => 'err', 'text' => 'Username must not contain spaces.'];
            } elseif (preg_match('/[^A-Za-z0-9_.]/', $newUsername)) {
                $flash = ['type' => 'err', 'text' => 'Username: Special characters are not allowed.'];
            } elseif (!preg_match('/^[A-Za-z]/', $newUsername)) {
                $flash = ['type' => 'err', 'text' => 'Username must start with a letter.'];
            } elseif (mb_strlen($newUsername) < 5 || mb_strlen($newUsername) > 30) {
                $flash = ['type' => 'err', 'text' => 'Username must be between 5 and 30 characters.'];
            } elseif (!preg_match('/[A-Z]/', $newUsername)) {
                $flash = ['type' => 'err', 'text' => 'Username must contain at least one uppercase letter.'];
            } elseif (!preg_match('/[0-9]/', $newUsername)) {
                $flash = ['type' => 'err', 'text' => 'Username must contain at least one number.'];
            } elseif (!preg_match('/[_.]/', $newUsername)) {
                $flash = ['type' => 'err', 'text' => 'Username must contain at least one special character (_ or .).'];
            } elseif (is_reserved_username($newUsername)) {
                $flash = ['type' => 'err', 'text' => 'This username is already taken.'];
            } elseif (empty($me['email'])) {
                $flash = ['type' => 'err', 'text' => 'No email is on file for your account, so this change can\'t be verified. Please contact another Superadmin.'];
            } else {
                $lower = strtolower($newUsername);
                $dupStmt = $conn->prepare("SELECT
                    (SELECT COUNT(*) FROM users WHERE LOWER(username) = ? AND id_number != ?) +
                    (SELECT COUNT(*) FROM pending_registration WHERE LOWER(username) = ?) AS c");
                $dupStmt->bind_param("sss", $lower, $myIdNumber, $lower);
                $dupStmt->execute();
                $dupCount = $dupStmt->get_result()->fetch_assoc()['c'];
                $dupStmt->close();

                if ($dupCount > 0) {
                    $flash = ['type' => 'err', 'text' => 'This username is already taken.'];
                } else {
                    $otpResult = create_otp($conn, $myIdNumber, $me['email'], 'change_username', $me['role']);
                    if (!$otpResult['ok']) {
                        $flash = ['type' => 'err', 'text' => $otpResult['error'] === 'cooldown'
                            ? "Please wait {$otpResult['retry_after']} seconds before requesting another code."
                            : 'Too many code requests. Please try again later.'];
                    } else {
                        $_SESSION['pending_username_change'] = ['new_username' => $newUsername];
                        $flash = ['type' => 'ok', 'text' => 'We emailed a verification code to ' . $me['email'] . '. Enter it below to confirm this change.'];
                    }
                }
            }

        // Self-service username change, STEP 2 of 2 — verifies the code and,
        // only then, actually applies the pending new username.
        } elseif ($action === 'confirm_username_change') {
            $me = resolve_self_account($conn, $myIdNumber);
            $pending = $_SESSION['pending_username_change'] ?? null;
            $code = trim((string)($_POST['otp'] ?? ''));

            if (!$pending || !$me) {
                $flash = ['type' => 'err', 'text' => 'No pending username change. Please start again.'];
            } else {
                $result = verify_otp($conn, $myIdNumber, 'change_username', $code, $me['email'] ?? '', $me['role']);
                if (!$result['ok']) {
                    if ($result['error'] === 'locked') {
                        unset($_SESSION['pending_username_change']);
                        $flash = ['type' => 'err', 'text' => 'Too many incorrect codes. Please start again.'];
                    } else {
                        $flash = ['type' => 'err', 'text' => 'Incorrect or expired code.'];
                    }
                } else {
                    // Re-check uniqueness — time has passed since STEP 1, so
                    // someone else could have taken this username meanwhile.
                    $lower = strtolower($pending['new_username']);
                    $dupStmt = $conn->prepare("SELECT
                        (SELECT COUNT(*) FROM users WHERE LOWER(username) = ? AND id_number != ?) +
                        (SELECT COUNT(*) FROM pending_registration WHERE LOWER(username) = ?) AS c");
                    $dupStmt->bind_param("sss", $lower, $myIdNumber, $lower);
                    $dupStmt->execute();
                    $dupCount = $dupStmt->get_result()->fetch_assoc()['c'];
                    $dupStmt->close();

                    unset($_SESSION['pending_username_change']);
                    if ($dupCount > 0) {
                        $flash = ['type' => 'err', 'text' => 'This username was taken while your code was pending. Please start again.'];
                    } else {
                        $stmt = $conn->prepare("UPDATE users SET username = ? WHERE id_number = ?");
                        $stmt->bind_param("ss", $pending['new_username'], $myIdNumber);
                        $stmt->execute();
                        $_SESSION['username'] = $pending['new_username'];
                        log_otp_action($conn, $myIdNumber, $me['email'] ?? '', 'username_changed_by_self', $me['role']);
                        $flash = ['type' => 'ok', 'text' => 'Username updated to ' . $pending['new_username'] . '.'];
                    }
                }
            }

        } elseif ($action === 'cancel_username_change') {
            unset($_SESSION['pending_username_change']);
            $flash = ['type' => 'ok', 'text' => 'Username change cancelled.'];

        // Self-service password change, STEP 1 of 2 — same
        // DEFAULT_SUPERADMIN_ID exemption and OTP-confirmation pattern as
        // Change Username above.
        } elseif ($action === 'change_own_password') {
            $me = resolve_self_account($conn, $myIdNumber);
            $currentPassword = (string)($_POST['current_password'] ?? '');
            $newPassword = (string)($_POST['new_password'] ?? '');
            $confirmPassword = (string)($_POST['confirm_new_password'] ?? '');

            if ($myIdNumber === DEFAULT_SUPERADMIN_ID) {
                $flash = ['type' => 'err', 'text' => 'The default Superadmin account\'s password cannot be changed here.'];
            } elseif ($currentPassword === '' || !$me || !verify_login_password($myIdNumber, $currentPassword, $me['password'])) {
                $flash = ['type' => 'err', 'text' => 'Incorrect current password.'];
                $passwordChangePasswordError = 'Your current password you inputted is wrong.';
            } elseif ($newPassword === '' || $confirmPassword === '') {
                $flash = ['type' => 'err', 'text' => 'Please fill in both new-password fields.'];
            } elseif ($newPassword !== $confirmPassword) {
                $flash = ['type' => 'err', 'text' => 'New passwords do not match.'];
            } elseif (!is_strong_password($newPassword)) {
                $flash = ['type' => 'err', 'text' => 'Password must be 8-72 characters and not a commonly used password.'];
            } elseif (password_verify($newPassword, $me['password'])) {
                $flash = ['type' => 'err', 'text' => 'New password must be different from your current password.'];
            } elseif (empty($me['email'])) {
                $flash = ['type' => 'err', 'text' => 'No email is on file for your account, so this change can\'t be verified. Please contact another Superadmin.'];
            } else {
                $otpResult = create_otp($conn, $myIdNumber, $me['email'], 'change_password', $me['role']);
                if (!$otpResult['ok']) {
                    $flash = ['type' => 'err', 'text' => $otpResult['error'] === 'cooldown'
                        ? "Please wait {$otpResult['retry_after']} seconds before requesting another code."
                        : 'Too many code requests. Please try again later.'];
                } else {
                    $_SESSION['pending_password_change'] = ['new_password_hash' => password_hash($newPassword, PASSWORD_DEFAULT)];
                    $flash = ['type' => 'ok', 'text' => 'We emailed a verification code to ' . $me['email'] . '. Enter it below to confirm this change.'];
                }
            }

        // Self-service password change, STEP 2 of 2.
        } elseif ($action === 'confirm_password_change') {
            $me = resolve_self_account($conn, $myIdNumber);
            $pending = $_SESSION['pending_password_change'] ?? null;
            $code = trim((string)($_POST['otp'] ?? ''));

            if (!$pending || !$me) {
                $flash = ['type' => 'err', 'text' => 'No pending password change. Please start again.'];
            } else {
                $result = verify_otp($conn, $myIdNumber, 'change_password', $code, $me['email'] ?? '', $me['role']);
                if (!$result['ok']) {
                    if ($result['error'] === 'locked') {
                        unset($_SESSION['pending_password_change']);
                        $flash = ['type' => 'err', 'text' => 'Too many incorrect codes. Please start again.'];
                    } else {
                        $flash = ['type' => 'err', 'text' => 'Incorrect or expired code.'];
                    }
                } else {
                    $stmt = $conn->prepare("UPDATE users SET password = ? WHERE id_number = ?");
                    $stmt->bind_param("ss", $pending['new_password_hash'], $myIdNumber);
                    $stmt->execute();
                    unset($_SESSION['pending_password_change']);
                    log_otp_action($conn, $myIdNumber, $me['email'] ?? '', 'password_changed_by_self', $me['role']);
                    $flash = ['type' => 'ok', 'text' => 'Password updated.'];
                }
            }

        } elseif ($action === 'cancel_password_change') {
            unset($_SESSION['pending_password_change']);
            $flash = ['type' => 'ok', 'text' => 'Password change cancelled.'];
        }
    }
}

// -----------------------------------------------------------------
// My own profile row — used by the "My Profile" view/sidebar avatar.
// -----------------------------------------------------------------
$myAccount = resolve_self_account($conn, $myIdNumber);

// Whether to auto-open the "enter the code we emailed you" modal on this
// page load — set right after STEP 1 of Change Username/Password succeeds,
// cleared once STEP 2 (confirm) succeeds or the change is cancelled.
$awaitingUsernameOtp = !empty($_SESSION['pending_username_change']);
$awaitingPasswordOtp = !empty($_SESSION['pending_password_change']);

// -----------------------------------------------------------------
// Edit form pre-fill (GET ?action=edit&id=...)
// -----------------------------------------------------------------
if ($editTarget === null && ($_GET['action'] ?? '') === 'edit' && !empty($_GET['id'])) {
    $account = fetch_any_account($conn, trim($_GET['id']));
    if ($account) {
        $editTarget = $account;
        $editValues = $account;
    } else {
        $flash = ['type' => 'err', 'text' => 'Account not found.'];
    }
}

// -----------------------------------------------------------------
// Data for the panels
// -----------------------------------------------------------------
$pending = $conn->query("SELECT id_number, first_name, middle_name, last_name, username, created_at
                          FROM pending_registration ORDER BY created_at DESC");
$pendingCount = $pending->num_rows;

// Registration Approval — combined Pending/Approved/Rejected list for
// self-registered Instructors. Pending applications live only in
// pending_registration (never in `users` — see registration_helpers.php);
// Approved/Rejected are real `users` rows (role='user') left behind by a
// past decision. The two are UNIONed here so the "All" tab can still show
// one combined chronological history. Separate from $pending above, which
// stays scoped to just the pending count used for the sidebar badge and
// Overview stat tile regardless of which status tab is selected here.
// Blocked registrations are deliberately excluded — blocking is an
// Accounts-page action, not a registration-review outcome.
$regStatusFilter = $_GET['status'] ?? 'all';
if (!in_array($regStatusFilter, ['all', 'pending', 'approved', 'rejected'], true)) {
    $regStatusFilter = 'all';
}
$regSearch = trim((string)($_GET['rq'] ?? ''));
$regParts = [];
$regParams = [];
$regTypes = '';

if ($regStatusFilter === 'all' || $regStatusFilter === 'pending') {
    $sql = "SELECT id_number, first_name, middle_name, last_name, username, 'pending' AS status, created_at
            FROM pending_registration";
    if ($regSearch !== '') {
        $sql .= " WHERE id_number LIKE ?";
        $regParams[] = '%' . $regSearch . '%';
        $regTypes .= 's';
    }
    $regParts[] = $sql;
}
if ($regStatusFilter === 'all' || $regStatusFilter === 'approved' || $regStatusFilter === 'rejected') {
    $decidedStatuses = $regStatusFilter === 'all' ? ['approved', 'rejected'] : [$regStatusFilter];
    $placeholders = implode(',', array_fill(0, count($decidedStatuses), '?'));
    $sql = "SELECT id_number, first_name, middle_name, last_name, username, status, created_at
            FROM users WHERE role = 'user' AND status IN ($placeholders)";
    foreach ($decidedStatuses as $s) {
        $regParams[] = $s;
        $regTypes .= 's';
    }
    if ($regSearch !== '') {
        $sql .= " AND id_number LIKE ?";
        $regParams[] = '%' . $regSearch . '%';
        $regTypes .= 's';
    }
    $regParts[] = $sql;
}
$registrationsSql = implode(' UNION ALL ', $regParts) . " ORDER BY created_at DESC";
$stmt = $conn->prepare($registrationsSql);
if ($regTypes !== '') {
    $stmt->bind_param($regTypes, ...$regParams);
}
$stmt->execute();
$registrations = $stmt->get_result();

// Role filter tabs (All / Admin / Super Admin) on the Accounts table.
// Whitelisted against a fixed set — an unrecognized or tampered ?role=
// value just falls back to "all" rather than ever reaching the query, so
// there's no way to smuggle arbitrary SQL or an unsupported role through
// the URL.
$roleFilter = $_GET['role'] ?? 'all';
if (!in_array($roleFilter, ['all', 'user', 'admin', 'superadmin'], true)) {
    $roleFilter = 'all';
}

$search = trim((string)($_GET['q'] ?? ''));

// No "status != 'pending'" filter needed here anymore — a pending
// self-registration is never a `users` row (see pending_registration).
$whereClauses = [];
$params = [];
$types = '';
if ($roleFilter !== 'all') {
    $whereClauses[] = "role = ?";
    $params[] = $roleFilter;
    $types .= 's';
}
if ($search !== '') {
    $whereClauses[] = "id_number LIKE ?";
    $params[] = '%' . $search . '%';
    $types .= 's';
}

$accountsWhereSql = $whereClauses ? ('WHERE ' . implode(' AND ', $whereClauses)) : '';
$accountsSql = "SELECT id_number, first_name, middle_name, last_name, username, role, status,
                        TIMESTAMPDIFF(SECOND, last_activity, NOW()) AS seconds_since_activity
                 FROM users $accountsWhereSql
                 ORDER BY created_at DESC";
$stmt = $conn->prepare($accountsSql);
if ($types !== '') {
    $stmt->bind_param($types, ...$params);
}
$stmt->execute();
$accounts = $stmt->get_result();

// Used by the Accounts table below to hide "Demote to Admin" on the last
// active Superadmin — a nicety only; the real guard is the server-side
// check in the 'demote_to_admin' action above, since a button being hidden
// is never itself a security control.
$activeSuperadminCount = active_superadmin_count($conn);

$deleteRequests = $conn->query("SELECT * FROM delete_requests WHERE status = 'pending' ORDER BY created_at ASC");
$deleteRequestCount = $deleteRequests->num_rows;

$totalAccounts = $conn->query("SELECT COUNT(*) c FROM users")->fetch_assoc()['c'];
$blockedCount = $conn->query("SELECT COUNT(*) c FROM users WHERE status = 'blocked'")->fetch_assoc()['c'];
$adminCount = $conn->query("SELECT COUNT(*) c FROM users WHERE role IN ('admin','superadmin')")->fetch_assoc()['c'];
$activeNowCount = $conn->query("SELECT COUNT(*) c FROM users WHERE last_activity >= (NOW() - INTERVAL " . ACTIVE_WINDOW_MINUTES . " MINUTE)")->fetch_assoc()['c'];

// -----------------------------------------------------------------
// Overview: User Role / Account Status statistics (superadmin-only —
// this is the one dashboard with full-system visibility across every
// role, so these breakdowns live here rather than on admin_dashboard.php).
// Two grouped queries instead of separate COUNT(*) calls per role/status.
// A pending self-registration is never a `users` row (see
// pending_registration), so it can't show up in either GROUP BY below —
// $pendingCount (from pending_registration, computed earlier) is used
// directly as the "Pending" status count instead.
// -----------------------------------------------------------------
$roleCounts = ['user' => 0, 'admin' => 0, 'superadmin' => 0];
$roleCountsResult = $conn->query("SELECT role, COUNT(*) c FROM users GROUP BY role");
while ($row = $roleCountsResult->fetch_assoc()) {
    $roleCounts[$row['role']] = (int)$row['c'];
}
$instructorCount = $roleCounts['user'];
$adminOnlyCount = $roleCounts['admin'];
$superadminOnlyCount = $roleCounts['superadmin'];

$statusCounts = ['pending' => $pendingCount, 'approved' => 0, 'blocked' => 0, 'rejected' => 0];
$statusCountsResult = $conn->query("SELECT status, COUNT(*) c FROM users GROUP BY status");
while ($row = $statusCountsResult->fetch_assoc()) {
    $statusCounts[$row['status']] = (int)$row['c'];
}
$approvedCount = $statusCounts['approved'];
$rejectedCount = $statusCounts['rejected'];

// -----------------------------------------------------------------
// Admin Privileges data
// -----------------------------------------------------------------
$selectedAdminId = $permissionsAdminId ?: trim((string)($_GET['admin'] ?? ''));
$selectedAdminAccount = null;
$adminPermissions = [];
$permissionAuditLog = null;
if ($selectedAdminId !== '') {
    $selectedAdminAccount = fetch_any_account($conn, $selectedAdminId);
    if (!$selectedAdminAccount || $selectedAdminAccount['role'] !== 'admin') {
        $selectedAdminAccount = null;
        $selectedAdminId = '';
        if (!$flash) {
            $flash = ['type' => 'err', 'text' => 'Admin account not found.'];
        }
    } else {
        $adminPermissions = get_admin_permissions($conn, $selectedAdminId);
        $logStmt = $conn->prepare("SELECT * FROM permission_audit_log WHERE admin_id_number = ? ORDER BY created_at DESC LIMIT 30");
        $logStmt->bind_param("s", $selectedAdminId);
        $logStmt->execute();
        $permissionAuditLog = $logStmt->get_result();
    }
}
$adminAccountsList = list_admin_accounts($conn);
$caLockRemaining = create_account_rate_limit_status();

// -----------------------------------------------------------------
// Sidebar view routing
// -----------------------------------------------------------------
$view = $_GET['view'] ?? 'overview';
if ($editTarget) {
    $view = 'accounts';
}
if ($showCreateForm) {
    $view = 'create';
}
if ($forceAccountsView) {
    // Just successfully created an account — land on Accounts so it's
    // immediately visible instead of staying on the (now-empty) Create form.
    $view = 'accounts';
    $showCreateForm = false;
}
if ($permissionsAdminId) {
    // Just saved/revoked permissions — land back on that same Admin's matrix
    // instead of the bare picker list.
    $view = 'permissions';
}
if (!in_array($view, ['overview', 'registrations', 'accounts', 'create', 'requests', 'permissions', 'activity_logs', 'login_logs', 'my_profile'], true)) {
    $view = 'overview';
}
if ($view === 'create') {
    $showCreateForm = true;
}
// Preview only — the id_number actually assigned is (re-)generated inside
// createBareStaffAccount()'s own transaction at submit time, same as every
// other id-preview field in this app (e.g. register.php's). A concurrent
// creation between this render and that submit can make the two differ;
// that's expected and already handled by generateNextId()'s retry-on-collision.
$nextIdPreview = $view === 'create' ? generateNextId($conn) : '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Superadmin Dashboard | CSU Instructor Registration and Management</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="../CSS/admin_console.css">
  <?php if ($view === 'overview'): ?>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
  <?php endif; ?>
</head>
<body class="role-superadmin">

<div class="app-shell">
  <aside class="sidebar">
    <div class="sidebar__brand">
      <div class="console-icon"><i class="bi bi-mortarboard-fill"></i></div>
      <div>
        <p class="sidebar__eyebrow">CSU IRM</p>
        <p class="sidebar__title">Superadmin Panel</p>
      </div>
    </div>
    <div class="sidebar__profile-top">
      <div class="sidebar__avatar sidebar__avatar--lg">
        <?php if ($avatarUrl = profile_picture_url($myAccount['profile_picture'] ?? null)): ?>
          <img src="<?= h($avatarUrl) ?>" alt="">
        <?php else: ?>
          <?= h(strtoupper(substr($_SESSION['username'], 0, 1))) ?>
        <?php endif; ?>
      </div>
      <p class="sidebar__profile-top-name"><?= h($_SESSION['username']) ?></p>
      <span class="role-tag"><i class="bi bi-shield-fill-check"></i> Superadmin</span>
    </div>
    <nav class="sidebar__nav">
      <p class="sidebar__section-label">Main</p>
      <a href="?view=overview" class="sidebar__link <?= $view === 'overview' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-grid-fill"></i> Overview</span>
      </a>

      <p class="sidebar__section-label">Account Management</p>
      <a href="?view=registrations" class="sidebar__link <?= $view === 'registrations' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-hourglass-split"></i> Registration Approval</span>
        <?php if ($pendingCount > 0): ?><span class="sidebar__badge"><?= (int)$pendingCount ?></span><?php endif; ?>
      </a>
      <a href="?view=accounts" class="sidebar__link <?= $view === 'accounts' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-people-fill"></i> Accounts</span>
      </a>
      <a href="?view=create" class="sidebar__link <?= $view === 'create' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-person-plus-fill"></i> Create Account</span>
      </a>

      <p class="sidebar__section-label">Access &amp; Security</p>
      <a href="?view=requests" class="sidebar__link <?= $view === 'requests' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-exclamation-triangle-fill"></i> Delete Requests</span>
        <?php if ($deleteRequestCount > 0): ?><span class="sidebar__badge"><?= (int)$deleteRequestCount ?></span><?php endif; ?>
      </a>
      <a href="?view=permissions" class="sidebar__link <?= $view === 'permissions' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-key-fill"></i> Admin Privileges</span>
      </a>
      <a href="?view=activity_logs" class="sidebar__link <?= $view === 'activity_logs' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-clock-history"></i> Activity Logs</span>
      </a>
      <a href="?view=login_logs" class="sidebar__link <?= $view === 'login_logs' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-shield-lock-fill"></i> Login Logs</span>
      </a>
    </nav>
    <div class="sidebar__footer">
      <p class="sidebar__section-label">Account</p>
      <a href="?view=my_profile" class="sidebar__link <?= $view === 'my_profile' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-person-fill"></i> My Profile</span>
      </a>
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
        <h1>Overview</h1>
      </div>
    </div>
  </div>
  <p class="module-desc"><i class="bi bi-info-circle-fill"></i> Full-oversight snapshot — pending work and account totals across the whole system. For a record of every management action taken, see Activity Logs.</p>

  <div class="stat-grid">
    <div class="stat-tile"><div class="stat-tile__icon stat-tile__icon--live"><i class="bi bi-broadcast"></i></div><div><div class="num"><?= (int)$activeNowCount ?></div><div class="label">Active right now</div></div></div>
    <div class="stat-tile"><div class="stat-tile__icon"><i class="bi bi-hourglass-split"></i></div><div><div class="num"><?= (int)$pendingCount ?></div><div class="label">Pending registrations</div></div></div>
    <div class="stat-tile"><div class="stat-tile__icon"><i class="bi bi-people-fill"></i></div><div><div class="num"><?= (int)$totalAccounts ?></div><div class="label">Total accounts</div></div></div>
    <div class="stat-tile"><div class="stat-tile__icon"><i class="bi bi-slash-circle-fill"></i></div><div><div class="num"><?= (int)$blockedCount ?></div><div class="label">Blocked accounts</div></div></div>
    <div class="stat-tile"><div class="stat-tile__icon"><i class="bi bi-shield-fill"></i></div><div><div class="num"><?= (int)$adminCount ?></div><div class="label">Admins &amp; Superadmins</div></div></div>
    <div class="stat-tile"><div class="stat-tile__icon"><i class="bi bi-exclamation-triangle-fill"></i></div><div><div class="num"><?= (int)$deleteRequestCount ?></div><div class="label">Pending delete requests</div></div></div>
  </div>

  <div class="chart-panel-grid">
    <!-- USER ROLE STATISTICS -->
    <div class="panel">
      <div class="panel__header"><h2><i class="bi bi-people-fill icon-info"></i> User Role Statistics</h2></div>
      <div class="panel__body">
        <div class="stat-grid" style="margin-bottom:18px;">
          <div class="stat-tile"><div class="stat-tile__icon"><i class="bi bi-people-fill"></i></div><div><div class="num"><?= (int)$totalAccounts ?></div><div class="label">Total system users</div></div></div>
          <div class="stat-tile stat-tile--instructor"><div class="stat-tile__icon"><i class="bi bi-mortarboard-fill"></i></div><div><div class="num"><?= (int)$instructorCount ?></div><div class="label">Total instructors</div></div></div>
          <div class="stat-tile stat-tile--admin"><div class="stat-tile__icon"><i class="bi bi-shield-fill"></i></div><div><div class="num"><?= (int)$adminOnlyCount ?></div><div class="label">Total admins</div></div></div>
          <div class="stat-tile stat-tile--superadmin"><div class="stat-tile__icon"><i class="bi bi-shield-fill-check"></i></div><div><div class="num"><?= (int)$superadminOnlyCount ?></div><div class="label">Total superadmins</div></div></div>
        </div>
        <div style="max-width:300px; margin:0 auto;">
          <canvas id="roleStatsChart" role="img" aria-label="Doughnut chart comparing the number of Instructor, Admin, and Superadmin accounts"></canvas>
        </div>
      </div>
    </div>

    <!-- USER ACCOUNT STATUS -->
    <div class="panel">
      <div class="panel__header"><h2><i class="bi bi-clipboard2-pulse-fill icon-info"></i> User Account Status</h2></div>
      <div class="panel__body">
        <div class="stat-grid" style="margin-bottom:18px;">
          <div class="stat-tile stat-tile--active"><div class="stat-tile__icon"><i class="bi bi-check-circle-fill"></i></div><div><div class="num"><?= (int)$approvedCount ?></div><div class="label">Active accounts</div></div></div>
          <div class="stat-tile stat-tile--pending"><div class="stat-tile__icon"><i class="bi bi-hourglass-split"></i></div><div><div class="num"><?= (int)$pendingCount ?></div><div class="label">Pending accounts</div></div></div>
          <div class="stat-tile stat-tile--blocked"><div class="stat-tile__icon"><i class="bi bi-slash-circle-fill"></i></div><div><div class="num"><?= (int)$blockedCount ?></div><div class="label">Blocked accounts</div></div></div>
          <div class="stat-tile stat-tile--rejected"><div class="stat-tile__icon"><i class="bi bi-x-circle-fill"></i></div><div><div class="num"><?= (int)$rejectedCount ?></div><div class="label">Rejected accounts</div></div></div>
        </div>
        <p class="form-text" style="margin:-8px 0 14px;">No separate "Inactive" status exists in the system yet — the account statuses actually stored are Active (approved), Pending, Blocked, and Rejected, shown above and in the chart below.</p>
        <div style="max-width:380px; margin:0 auto;">
          <canvas id="statusStatsChart" role="img" aria-label="Bar chart showing the distribution of account statuses"></canvas>
        </div>
      </div>
    </div>
  </div>

  <script>
  document.addEventListener('DOMContentLoaded', () => {
    if (typeof Chart === 'undefined') return;

    // Per-category colors (blue/purple/gold for roles, green/red/orange/grey
    // for status) — a deliberate exception to this console's usual
    // strict-green palette, requested specifically for these two charts so
    // each category is instantly distinguishable. Matches the .stat-tile--*
    // modifier colors used on the cards above.
    new Chart(document.getElementById('roleStatsChart'), {
      type: 'doughnut',
      data: {
        labels: ['Instructors', 'Admins', 'Superadmins'],
        datasets: [{
          data: [<?= (int)$instructorCount ?>, <?= (int)$adminOnlyCount ?>, <?= (int)$superadminOnlyCount ?>],
          backgroundColor: ['#0d6efd', '#6f42c1', '#b8860b'],
          borderColor: '#ffffff',
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        plugins: { legend: { position: 'bottom', labels: { color: '#14291c', font: { size: 12 } } } },
      },
    });

    new Chart(document.getElementById('statusStatsChart'), {
      type: 'bar',
      data: {
        labels: ['Active', 'Pending', 'Blocked', 'Rejected'],
        datasets: [{
          label: 'Accounts',
          data: [<?= (int)$approvedCount ?>, <?= (int)$pendingCount ?>, <?= (int)$blockedCount ?>, <?= (int)$rejectedCount ?>],
          backgroundColor: ['#2f9d68', '#dc3545', '#fd7e14', '#6c757d'],
          borderRadius: 6,
        }],
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, ticks: { precision: 0, color: '#66806f' }, grid: { color: '#e2ede6' } },
          x: { ticks: { color: '#14291c' }, grid: { display: false } },
        },
      },
    });
  });
  </script>
  <?php endif; ?>

  <!-- MY PROFILE -->
  <?php if ($view === 'my_profile'): ?>
  <div class="console-header">
    <div class="console-title"><div><h1>My Profile</h1></div></div>
  </div>

  <div class="panel">
    <div class="panel__header"><h2><i class="bi bi-camera-fill"></i> Profile Picture</h2></div>
    <div class="panel__body">
      <div class="profile-avatar-card">
        <div class="profile-avatar">
          <?php if ($avatarUrl = profile_picture_url($myAccount['profile_picture'] ?? null)): ?>
            <img src="<?= h($avatarUrl) ?>" alt="">
          <?php else: ?>
            <?= h(strtoupper(substr($_SESSION['username'], 0, 1))) ?>
          <?php endif; ?>
        </div>
        <div class="profile-avatar-actions">
          <?php if ($myAccount['id_number'] === DEFAULT_SUPERADMIN_ID): ?>
            <p class="form-text" style="margin:0;">Not available for the recovery account.</p>
          <?php else: ?>
          <form method="post" enctype="multipart/form-data" id="avatarUploadForm">
            <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
            <input type="hidden" name="action" value="upload_profile_picture">
            <label class="btn-ghost profile-avatar-upload-btn" for="avatarFileInput">
              <i class="bi bi-upload"></i> Change Photo
            </label>
            <input type="file" name="profile_picture" id="avatarFileInput" accept="image/png,image/jpeg,image/webp" style="display:none" onchange="document.getElementById('avatarUploadForm').submit()">
          </form>
          <?php if (!empty($myAccount['profile_picture'])): ?>
          <form method="post">
            <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
            <input type="hidden" name="action" value="remove_profile_picture">
            <button type="submit" class="btn-ghost">Remove Photo</button>
          </form>
          <?php endif; ?>
          <?php endif; ?>
        </div>
        <p class="form-text" style="margin-top:6px; width:100%;">JPG, PNG, or WEBP. Max 2 MB.</p>
      </div>
    </div>
  </div>

  <div class="panel">
    <div class="panel__header"><h2><i class="bi bi-person-lines-fill"></i> Profile Information</h2></div>
    <div class="panel__body">
      <div class="form-grid">
        <div class="form-field"><label>Full Name</label>
          <div><?= h(trim("{$myAccount['first_name']} {$myAccount['middle_name']} {$myAccount['last_name']} {$myAccount['extension']}")) ?></div>
        </div>
        <div class="form-field"><label>Username</label><div><?= h($myAccount['username']) ?></div></div>
        <div class="form-field"><label>Email</label><div><?= h($myAccount['email'] ?? 'Not provided') ?></div></div>
        <div class="form-field"><label>Employee ID</label><div><?= h($myAccount['id_number']) ?></div></div>
        <div class="form-field"><label>Role</label><div><?= h(ucfirst($myAccount['role'])) ?></div></div>
        <div class="form-field"><label>Member Since</label><div><?= h($myAccount['created_at']) ?></div></div>
      </div>
    </div>
  </div>

  <div class="panel">
    <div class="panel__header"><h2><i class="bi bi-shield-lock-fill icon-purple"></i> Account Security</h2></div>
    <div class="panel__body">
      <?php if ($myAccount['id_number'] === DEFAULT_SUPERADMIN_ID): ?>
        <p class="panel__empty"><i class="bi bi-info-circle-fill"></i> This is the system's built-in recovery Superadmin account — its username and password stay fixed on purpose, so there's always a known way back in. They can't be changed here.</p>
      <?php else: ?>
        <div class="profile-section">
          <h3 class="profile-section__title">Change Username</h3>
          <p class="form-text">Current username: <strong><?= h($myAccount['username']) ?></strong></p>
          <button type="button" class="btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#changeUsernameModal">
            <i class="bi bi-person-badge-fill"></i> Change Username
          </button>
        </div>

        <div class="profile-section">
          <h3 class="profile-section__title">Change Password</h3>
          <button type="button" class="btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#changePasswordModal">
            <i class="bi bi-key-fill"></i> Change Password
          </button>
        </div>
      <?php endif; ?>
    </div>
  </div>
  <?php endif; ?>

  <!-- CREATE ACCOUNT -->
  <?php if ($view === 'create'): ?>
  <div class="console-header">
    <div class="console-title"><div><h1>Create Admin/Superadmin Account</h1></div></div>
  </div>
  <p class="module-desc"><i class="bi bi-info-circle-fill"></i> Only a login identity and email are set here — no other confidential personal information. The username and initial password are emailed to the address below; the new account fills in its own name, address, birthdate, and a replacement password on first login, before it can reach any dashboard.</p>
  <?php if ($caLockRemaining > 0): ?>
    <div class="console-flash err">🚫 Too many attempts. Please wait <?= (int)$caLockRemaining ?> seconds before trying again.</div>
  <?php endif; ?>
  <div class="panel">
    <div class="panel__body">
      <form method="post" id="registerForm" novalidate>
        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
        <input type="hidden" name="action" value="create_account">
        <div class="form-grid">
          <div class="form-field">
            <label>Employee ID</label>
            <input type="text" value="<?= h($nextIdPreview) ?>" readonly>
          </div>
          <div class="form-field">
            <label>Role</label>
            <select name="new_role" id="new_role">
              <?php foreach (['admin' => 'Admin', 'superadmin' => 'Superadmin'] as $val => $lbl): ?>
                <option value="<?= $val ?>" <?= ($createValues['new_role'] ?? 'admin') === $val ? 'selected' : '' ?>><?= $lbl ?></option>
              <?php endforeach; ?>
            </select>
          </div>
          <div class="form-field">
            <label>Username *</label>
            <input type="text" name="username" value="<?= h($createValues['username'] ?? '') ?>" minlength="5" maxlength="30" required autocomplete="username">
            <?php if (!empty($createErrors['username'])): ?><div class="err"><?= h($createErrors['username']) ?></div><?php endif; ?>
          </div>
          <div class="form-field">
            <label>Email *</label>
            <input type="email" name="email" value="<?= h($createValues['email'] ?? '') ?>" maxlength="100" required autocomplete="email" placeholder="name@<?= h(EMAIL_DOMAIN) ?>">
            <?php if (!empty($createErrors['email'])): ?><div class="err"><?= h($createErrors['email']) ?></div><?php endif; ?>
          </div>
          <div class="form-field">
            <label>Password *</label>
            <input type="password" name="password" minlength="8" maxlength="72" required autocomplete="new-password">
            <div class="form-text">Must be 8-72 characters and include at least one uppercase letter, one lowercase letter, one number, and one special character.</div>
            <?php if (!empty($createErrors['password'])): ?><div class="err"><?= h($createErrors['password']) ?></div><?php endif; ?>
          </div>
          <div class="form-field">
            <label>Re-enter Password *</label>
            <input type="password" name="repassword" minlength="8" maxlength="72" required autocomplete="new-password">
            <?php if (!empty($createErrors['repassword'])): ?><div class="err"><?= h($createErrors['repassword']) ?></div><?php endif; ?>
          </div>

        </div>
        <input type="hidden" name="current_password" id="createAccountPasswordField">
        <p class="panel__empty" style="margin-top:14px;"><i class="bi bi-shield-lock-fill icon-purple"></i> No confidential personal information is collected here. This account must complete its own profile (name, address, birthdate, and a new password) on first login before it can access the dashboard.</p>
        <div class="form-actions">
          <button type="submit" class="btn-primary">Create Account</button>
          <a href="?view=overview" class="btn-ghost">Cancel</a>
        </div>
      </form>
    </div>
  </div>

  <?php endif; ?>

  <!-- REGISTRATION APPROVAL -->
  <?php if ($view === 'registrations'): ?>
  <p class="module-desc"><i class="bi bi-info-circle-fill"></i> Every Instructor/User registration in one place. New sign-ups land as Pending — approve to grant access, reject to deny it outright, or block to shut the account out entirely. Each decision is recorded in Recent Activity.</p>
  <div class="panel">
    <div class="panel__header"><h2><i class="bi bi-hourglass-split icon-warning"></i> Registration Approval</h2></div>
    <div class="panel__body">
      <!-- Status filter as a dropdown, same pattern as the Accounts role
           filter — still instant-click on each option, just a tidier,
           single-row container instead of a separate row of pill tabs. -->
      <?php $regTabSuffix = $regSearch !== '' ? '&rq=' . urlencode($regSearch) : ''; ?>
      <?php $regStatusLabels = ['all' => 'All', 'pending' => 'Pending', 'approved' => 'Approved', 'rejected' => 'Rejected']; ?>
      <form method="get" class="filter-bar">
        <input type="hidden" name="view" value="registrations">
        <input type="hidden" name="status" value="<?= h($regStatusFilter) ?>">
        <div class="dropdown role-filter-dropdown">
          <button type="button" class="btn-sm btn-edit dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false">
            Status: <?= h($regStatusLabels[$regStatusFilter] ?? 'All') ?>
          </button>
          <ul class="dropdown-menu">
            <?php foreach ($regStatusLabels as $val => $lbl): ?>
              <li><a class="dropdown-item <?= $regStatusFilter === $val ? 'active' : '' ?>" href="?view=registrations&amp;status=<?= $val ?><?= $regTabSuffix ?>"><?= $lbl ?></a></li>
            <?php endforeach; ?>
          </ul>
        </div>
        <input type="text" name="rq" placeholder="Filter by Employee ID (e.g. INR-2026-0001)" value="<?= h($regSearch) ?>">
        <button type="submit" class="btn-sm btn-edit">Search</button>
        <?php if ($regSearch !== '' || $regStatusFilter !== 'all'): ?><a href="?view=registrations" class="btn-sm btn-ghost">Clear</a><?php endif; ?>
      </form>

      <?php if ($registrations->num_rows === 0): ?>
        <p class="panel__empty">No registrations found for this filter.</p>
      <?php else: ?>
        <div class="table-scroll">
        <table class="console-table">
          <thead><tr><th>Employee ID</th><th>Name</th><th>Username</th><th>Status</th><th>Registered</th><th>Actions</th></tr></thead>
          <tbody>
          <?php while ($row = $registrations->fetch_assoc()): ?>
            <tr>
              <td><?= h($row['id_number']) ?></td>
              <td><?= h(trim("{$row['first_name']} {$row['middle_name']} {$row['last_name']}")) ?></td>
              <td><?= h($row['username']) ?></td>
              <td><span class="pill <?= h($row['status']) ?>"><?= h(ucfirst($row['status'])) ?></span></td>
              <td><?= h($row['created_at']) ?></td>
              <td class="row-actions">
                <?php if ($row['status'] === 'pending' || $row['status'] === 'approved'): ?>
                <div class="dropdown">
                  <button type="button" class="btn-sm btn-edit dropdown-toggle" data-bs-toggle="dropdown" data-bs-boundary="viewport" aria-expanded="false">
                    Manage
                  </button>
                  <ul class="dropdown-menu dropdown-menu-end">
                    <?php if ($row['status'] === 'pending'): ?>
                      <li>
                        <form method="post">
                          <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                          <input type="hidden" name="id_number" value="<?= h($row['id_number']) ?>">
                          <input type="hidden" name="action" value="approve">
                          <button type="submit" class="dropdown-item">Approve</button>
                        </form>
                      </li>
                      <li>
                        <form method="post" data-confirm="Reject this registration?">
                          <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                          <input type="hidden" name="id_number" value="<?= h($row['id_number']) ?>">
                          <input type="hidden" name="action" value="reject_registration">
                          <button type="submit" class="dropdown-item">Reject</button>
                        </form>
                      </li>
                      <li><hr class="dropdown-divider"></li>
                      <li>
                        <form method="post" data-confirm="Block this registration instead of approving it?">
                          <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                          <input type="hidden" name="id_number" value="<?= h($row['id_number']) ?>">
                          <input type="hidden" name="action" value="block_registration">
                          <button type="submit" class="dropdown-item">Block</button>
                        </form>
                      </li>
                    <?php else: ?>
                      <li>
                        <button type="button" class="dropdown-item" data-bs-toggle="modal" data-bs-target="#blockAccountModal"
                                data-id="<?= h($row['id_number']) ?>"
                                data-name="<?= h(trim("{$row['first_name']} {$row['middle_name']} {$row['last_name']}") ?: $row['username']) ?>">
                          Block
                        </button>
                      </li>
                    <?php endif; ?>
                    <!-- Registration Approval only ever lists role='user' accounts
                         (self-registered Instructors) — never Admin/Superadmin —
                         so there is deliberately no Delete action here at all. -->
                  </ul>
                </div>
                <?php else: ?>
                  <span class="panel__empty" style="margin:0;">—</span>
                <?php endif; ?>
              </td>
            </tr>
          <?php endwhile; ?>
          </tbody>
        </table>
        </div>
      <?php endif; ?>
    </div>
  </div>
  <?php endif; ?>

  <!-- PENDING DELETE REQUESTS -->
  <?php if ($view === 'requests'): ?>
  <p class="module-desc"><i class="bi bi-info-circle-fill"></i> Admins can't delete accounts directly — they submit a request here for you to review. Approving permanently deletes the account; rejecting dismisses the request and leaves the account untouched.</p>
  <div class="panel">
    <div class="panel__header"><h2><i class="bi bi-exclamation-triangle-fill icon-danger"></i> Pending Delete Requests</h2></div>
    <div class="panel__body">
      <?php if ($deleteRequests->num_rows === 0): ?>
        <p class="panel__empty">No pending delete requests.</p>
      <?php else: ?>
        <div class="table-scroll">
        <table class="console-table">
          <thead><tr><th>Target</th><th>Employee ID</th><th>Requested By</th><th>Reason</th><th>Submitted</th><th>Actions</th></tr></thead>
          <tbody>
          <?php while ($row = $deleteRequests->fetch_assoc()): ?>
            <tr>
              <td><?= h($row['target_name']) ?> (<?= h($row['target_username']) ?>)</td>
              <td><?= h($row['target_id_number']) ?></td>
              <td><?= h($row['requested_by_username']) ?></td>
              <td style="max-width:280px; white-space:normal;"><?= nl2br(h($row['reason'])) ?></td>
              <td><?= h($row['created_at']) ?></td>
              <td class="row-actions">
                <div class="dropdown">
                  <button type="button" class="btn-sm btn-edit dropdown-toggle" data-bs-toggle="dropdown" data-bs-boundary="viewport" aria-expanded="false">
                    Manage
                  </button>
                  <ul class="dropdown-menu dropdown-menu-end">
                    <li>
                      <form method="post">
                        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="request_id" value="<?= (int)$row['id'] ?>">
                        <input type="hidden" name="action" value="review_delete_request">
                        <input type="hidden" name="decision" value="reject">
                        <button type="submit" class="dropdown-item">Reject</button>
                      </form>
                    </li>
                    <li><hr class="dropdown-divider"></li>
                    <li>
                      <!-- A delete request can never target a Superadmin — Admins
                           can only request deletion of a user/admin account
                           (see request_delete in admin_dashboard.php), and this
                           handler independently refuses a Superadmin target too. -->
                      <form method="post" data-confirm="This will permanently delete the account. Continue?">
                        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="request_id" value="<?= (int)$row['id'] ?>">
                        <input type="hidden" name="action" value="review_delete_request">
                        <input type="hidden" name="decision" value="approve">
                        <button type="submit" class="dropdown-item text-danger">Approve &amp; Delete</button>
                      </form>
                    </li>
                  </ul>
                </div>
              </td>
            </tr>
          <?php endwhile; ?>
          </tbody>
        </table>
        </div>
      <?php endif; ?>
    </div>
  </div>
  <?php endif; ?>

  <?php if ($view === 'accounts'): ?>
  <p class="module-desc"><i class="bi bi-info-circle-fill"></i> Every account in the system, any role. Search by Employee ID, edit a profile, change a role, block/unblock access, or delete an account — except another Superadmin, which only that account holder can remove.</p>

  <div class="stat-grid" style="margin-bottom:18px;">
    <div class="stat-tile stat-tile--instructor"><div class="stat-tile__icon"><i class="bi bi-mortarboard-fill"></i></div><div><div class="num"><?= (int)$instructorCount ?></div><div class="label">User</div></div></div>
    <div class="stat-tile stat-tile--admin"><div class="stat-tile__icon"><i class="bi bi-shield-fill"></i></div><div><div class="num"><?= (int)$adminOnlyCount ?></div><div class="label">Admin</div></div></div>
    <div class="stat-tile stat-tile--superadmin"><div class="stat-tile__icon"><i class="bi bi-shield-fill-check"></i></div><div><div class="num"><?= (int)$superadminOnlyCount ?></div><div class="label">Superadmin</div></div></div>
    <div class="stat-tile"><div class="stat-tile__icon"><i class="bi bi-people-fill"></i></div><div><div class="num"><?= (int)$totalAccounts ?></div><div class="label">Total Users</div></div></div>
  </div>

  <!-- EDIT FORM -->
  <?php if ($editTarget): ?>
  <div class="panel">
    <div class="panel__header"><h2><i class="bi bi-pencil-square icon-info"></i> Edit Account — <?= h($editTarget['id_number']) ?></h2></div>
    <div class="panel__body">
      <form method="post">
        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
        <input type="hidden" name="action" value="save_edit">
        <input type="hidden" name="id_number" value="<?= h($editTarget['id_number']) ?>">
        <div class="form-grid">
          <div class="form-field">
            <label>First Name</label>
            <input type="text" name="first_name" value="<?= h($editValues['first_name'] ?? '') ?>">
            <?php if (!empty($editErrors['first_name'])): ?><div class="err"><?= h($editErrors['first_name']) ?></div><?php endif; ?>
          </div>
          <div class="form-field">
            <label>Middle Name</label>
            <input type="text" name="middle_name" value="<?= h($editValues['middle_name'] ?? '') ?>">
            <?php if (!empty($editErrors['middle_name'])): ?><div class="err"><?= h($editErrors['middle_name']) ?></div><?php endif; ?>
          </div>
          <div class="form-field">
            <label>Last Name</label>
            <input type="text" name="last_name" value="<?= h($editValues['last_name'] ?? '') ?>">
            <?php if (!empty($editErrors['last_name'])): ?><div class="err"><?= h($editErrors['last_name']) ?></div><?php endif; ?>
          </div>
          <div class="form-field">
            <label>Extension</label>
            <input type="text" name="extension" value="<?= h($editValues['extension'] ?? '') ?>">
            <?php if (!empty($editErrors['extension'])): ?><div class="err"><?= h($editErrors['extension']) ?></div><?php endif; ?>
          </div>
          <div class="form-field">
            <label>Sex</label>
            <select name="sex">
              <option value="">-- Select --</option>
              <option value="Male" <?= ($editValues['sex'] ?? '') === 'Male' ? 'selected' : '' ?>>Male</option>
              <option value="Female" <?= ($editValues['sex'] ?? '') === 'Female' ? 'selected' : '' ?>>Female</option>
            </select>
            <?php if (!empty($editErrors['sex'])): ?><div class="err"><?= h($editErrors['sex']) ?></div><?php endif; ?>
          </div>
          <div class="form-field">
            <label>Birthdate</label>
            <input type="date" name="birthdate" value="<?= h($editValues['birthdate'] ?? '') ?>">
            <?php if (!empty($editErrors['birthdate'])): ?><div class="err"><?= h($editErrors['birthdate']) ?></div><?php endif; ?>
          </div>
          <div class="form-field">
            <label>Street/Purok</label>
            <input type="text" name="street" value="<?= h($editValues['street'] ?? '') ?>">
            <?php if (!empty($editErrors['street'])): ?><div class="err"><?= h($editErrors['street']) ?></div><?php endif; ?>
          </div>
          <div class="form-field">
            <label>Barangay</label>
            <input type="text" name="barangay" value="<?= h($editValues['barangay'] ?? '') ?>">
            <?php if (!empty($editErrors['barangay'])): ?><div class="err"><?= h($editErrors['barangay']) ?></div><?php endif; ?>
          </div>
          <div class="form-field">
            <label>City</label>
            <input type="text" name="city" value="<?= h($editValues['city'] ?? '') ?>">
            <?php if (!empty($editErrors['city'])): ?><div class="err"><?= h($editErrors['city']) ?></div><?php endif; ?>
          </div>
          <div class="form-field">
            <label>Province</label>
            <input type="text" name="province" value="<?= h($editValues['province'] ?? '') ?>">
            <?php if (!empty($editErrors['province'])): ?><div class="err"><?= h($editErrors['province']) ?></div><?php endif; ?>
          </div>
          <div class="form-field">
            <label>Region</label>
            <select name="region">
              <option value="">-- Select Region --</option>
              <?php foreach (REGION_OPTIONS as $regionOpt): ?>
                <option value="<?= h($regionOpt) ?>" <?= ($editValues['region'] ?? '') === $regionOpt ? 'selected' : '' ?>><?= h($regionOpt) ?></option>
              <?php endforeach; ?>
            </select>
            <?php if (!empty($editErrors['region'])): ?><div class="err"><?= h($editErrors['region']) ?></div><?php endif; ?>
          </div>
          <div class="form-field">
            <label>Zip</label>
            <input type="text" name="zip" value="<?= h($editValues['zip'] ?? $editValues['zip_code'] ?? '') ?>">
            <?php if (!empty($editErrors['zip'])): ?><div class="err"><?= h($editErrors['zip']) ?></div><?php endif; ?>
          </div>
          <div class="form-field">
            <label>Email</label>
            <input type="email" name="email" value="<?= h($editValues['email'] ?? '') ?>">
            <?php if (!empty($editErrors['email'])): ?><div class="err"><?= h($editErrors['email']) ?></div><?php endif; ?>
          </div>
        </div>
        <div class="form-actions">
          <button type="submit" class="btn-primary">Save Changes</button>
          <a href="?view=accounts" class="btn-ghost">Cancel</a>
        </div>
      </form>
    </div>
  </div>

  <!-- CHANGE PASSWORD (on the account holder's behalf, e.g. they personally
       requested it) — never shown for your own row or another Superadmin's. -->
  <?php if ($editTarget['id_number'] !== $myIdNumber && $editTarget['role'] !== 'superadmin'): ?>
  <div class="panel">
    <div class="panel__header"><h2><i class="bi bi-key-fill icon-purple"></i> Change Password</h2></div>
    <div class="panel__body">
      <p class="module-desc"><i class="bi bi-info-circle-fill"></i> Use this only when <?= h($editTarget['username']) ?> has personally asked you to change their password for them.</p>
      <?php if (!empty($pwErrors['_form'])): ?><div class="err" style="margin-bottom:10px;"><?= h($pwErrors['_form']) ?></div><?php endif; ?>
      <form method="post">
        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
        <input type="hidden" name="action" value="change_password">
        <input type="hidden" name="id_number" value="<?= h($editTarget['id_number']) ?>">
        <div class="form-grid">
          <div class="form-field">
            <label>New Password</label>
            <input type="password" name="new_password" autocomplete="new-password" minlength="8" maxlength="72">
          </div>
          <div class="form-field">
            <label>Confirm New Password</label>
            <input type="password" name="confirm_new_password" autocomplete="new-password" minlength="8" maxlength="72">
          </div>
        </div>
        <div class="form-actions">
          <button type="submit" class="btn-sm btn-danger">Change Password</button>
        </div>
      </form>
    </div>
  </div>
  <?php endif; ?>
  <?php endif; ?>

  <!-- ACCOUNTS -->
  <div class="panel">
    <div class="panel__header"><h2><i class="bi bi-people-fill icon-info"></i> All Accounts</h2></div>
    <div class="panel__body">
      <!-- Role filter as a dropdown (still instant-click on each option, same
           as before — just a tidier, single-row container instead of a
           separate row of pill tabs above the search bar). -->
      <?php $acctTabSuffix = $search !== '' ? '&q=' . urlencode($search) : ''; ?>
      <?php $acctRoleLabels = ['all' => 'All', 'user' => 'User', 'admin' => 'Admin', 'superadmin' => 'Superadmin']; ?>
      <form method="get" class="filter-bar">
        <input type="hidden" name="view" value="accounts">
        <input type="hidden" name="role" value="<?= h($roleFilter) ?>">
        <div class="dropdown role-filter-dropdown">
          <button type="button" class="btn-sm btn-edit dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false">
            Role: <?= h($acctRoleLabels[$roleFilter] ?? 'All') ?>
          </button>
          <ul class="dropdown-menu">
            <?php foreach ($acctRoleLabels as $val => $lbl): ?>
              <li><a class="dropdown-item <?= $roleFilter === $val ? 'active' : '' ?>" href="?view=accounts&amp;role=<?= $val ?><?= $acctTabSuffix ?>"><?= $lbl ?></a></li>
            <?php endforeach; ?>
          </ul>
        </div>
        <input type="text" name="q" placeholder="Filter by Employee ID (e.g. INR-2026-0001)" value="<?= h($search) ?>">
        <button type="submit" class="btn-sm btn-edit">Search</button>
        <?php if ($search !== '' || $roleFilter !== 'all'): ?><a href="?view=accounts" class="btn-sm btn-ghost">Clear</a><?php endif; ?>
      </form>

      <?php if ($accounts->num_rows === 0): ?>
        <p class="panel__empty">No accounts found.</p>
      <?php else: ?>
        <div class="table-scroll">
        <table class="console-table">
          <thead><tr><th>Employee ID</th><th>Name</th><th>Username</th><th>Role</th><th>Status</th><th>Activity</th><th>Actions</th></tr></thead>
          <tbody>
          <?php while ($row = $accounts->fetch_assoc()): $isSelf = $row['id_number'] === $myIdNumber; ?>
            <tr>
              <td><?= h($row['id_number']) ?></td>
              <td><?= h(trim("{$row['first_name']} {$row['middle_name']} {$row['last_name']}")) ?></td>
              <td><?= h($row['username']) ?></td>
              <td>
                <span class="pill role-<?= h($row['role']) ?>"><?= h(ucfirst($row['role'])) ?></span>
              </td>
              <td><span class="pill <?= h($row['status']) ?>"><?= h(ucfirst($row['status'])) ?></span></td>
              <td>
                <span class="activity-indicator <?= is_account_active($row['seconds_since_activity']) ? 'is-active' : '' ?>">
                  <span class="activity-indicator__dot"></span><?= h(activity_status_label($row['role'], $row['seconds_since_activity'])) ?>
                </span>
              </td>
              <td class="row-actions">
                <div class="dropdown">
                  <button type="button" class="btn-sm btn-edit dropdown-toggle" data-bs-toggle="dropdown" data-bs-boundary="viewport" aria-expanded="false">
                    Manage
                  </button>
                  <?php $rowTargetName = trim("{$row['first_name']} {$row['middle_name']} {$row['last_name']}") ?: $row['username']; ?>
                  <ul class="dropdown-menu dropdown-menu-end">
                    <li><a class="dropdown-item" href="?view=accounts&amp;action=edit&amp;id=<?= urlencode($row['id_number']) ?>">Edit</a></li>
                    <?php if (!$isSelf): ?>
                      <li>
                        <?php if ($row['status'] === 'approved'): ?>
                          <button type="button" class="dropdown-item" data-bs-toggle="modal" data-bs-target="#blockAccountModal"
                                  data-id="<?= h($row['id_number']) ?>" data-name="<?= h($rowTargetName) ?>">
                            Block
                          </button>
                        <?php elseif ($row['status'] === 'blocked' && in_array($row['role'], ['admin', 'superadmin'], true)): ?>
                          <button type="button" class="dropdown-item" data-bs-toggle="modal" data-bs-target="#reactivateModal"
                                  data-id="<?= h($row['id_number']) ?>" data-name="<?= h($rowTargetName) ?>" data-prev-role="<?= h(ucfirst($row['role'])) ?>">
                            Unblock
                          </button>
                        <?php else: ?>
                          <button type="button" class="dropdown-item" data-bs-toggle="modal" data-bs-target="#unblockAccountModal"
                                  data-id="<?= h($row['id_number']) ?>" data-name="<?= h($rowTargetName) ?>">
                            Unblock
                          </button>
                        <?php endif; ?>
                      </li>
                      <?php
                        // "Change Role" covers both directions (Admin -> Superadmin
                        // and Superadmin -> Admin) through one shared modal — see
                        // #changeRoleModal below. Hidden entirely for the last
                        // active Superadmin, since the only possible change for
                        // that row (-> Admin) would always be rejected server-side
                        // anyway; hiding it here is just a nicety on top of that
                        // real guard, never a substitute for it.
                        $canChangeRole = $row['status'] === 'approved'
                            && (($row['role'] === 'admin') || ($row['role'] === 'superadmin' && $activeSuperadminCount > 1));
                        $newRoleForRow = $row['role'] === 'admin' ? 'superadmin' : 'admin';
                      ?>
                      <?php if ($canChangeRole): ?>
                      <li>
                        <button type="button" class="dropdown-item" data-bs-toggle="modal" data-bs-target="#changeRoleModal"
                                data-id="<?= h($row['id_number']) ?>" data-name="<?= h($rowTargetName) ?>"
                                data-current-role="<?= h(ucfirst($row['role'])) ?>" data-new-role="<?= h($newRoleForRow) ?>"
                                data-new-role-label="<?= h(ucfirst($newRoleForRow)) ?>">
                          Change Role
                        </button>
                      </li>
                      <?php endif; ?>
                      <?php if ($row['role'] !== 'superadmin'): ?>
                      <li><hr class="dropdown-divider"></li>
                      <li>
                        <button type="button" class="dropdown-item text-danger" data-bs-toggle="modal" data-bs-target="#deleteRequestModal"
                                data-id="<?= h($row['id_number']) ?>" data-name="<?= h($rowTargetName) ?>">
                          Delete
                        </button>
                      </li>
                      <?php endif; ?>
                    <?php endif; ?>
                  </ul>
                </div>
              </td>
            </tr>
          <?php endwhile; ?>
          </tbody>
        </table>
        </div>
      <?php endif; ?>
    </div>
  </div>
  <?php endif; ?>

  <!-- ADMIN PRIVILEGES -->
  <?php if ($view === 'permissions'): ?>
  <div class="console-header">
    <div class="console-title"><div><h1>Admin Privileges</h1></div></div>
  </div>
  <p class="module-desc"><i class="bi bi-info-circle-fill"></i> Admins get none of these Superadmin-only modules by default. Grant a module/action here to delegate it temporarily, and revoke it just as easily — every change is recorded below and in Recent Activity.</p>

  <?php if (!$selectedAdminAccount): ?>
    <div class="panel">
      <div class="panel__header"><h2><i class="bi bi-people-fill icon-info"></i> Select an Admin</h2></div>
      <div class="panel__body">
        <p class="panel__empty" style="margin-bottom:14px;">
          Grant an Admin temporary access to Superadmin-only modules (delete-request
          review, account creation) — useful while you're unavailable. Nothing is
          granted by default; pick an Admin below to manage their privileges.
        </p>
        <?php if ($adminAccountsList->num_rows === 0): ?>
          <p class="panel__empty">No Admin accounts exist yet.</p>
        <?php else: ?>
          <div class="table-scroll">
          <table class="console-table">
            <thead><tr><th>Employee ID</th><th>Name</th><th>Username</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody>
            <?php while ($row = $adminAccountsList->fetch_assoc()): ?>
              <tr>
                <td><?= h($row['id_number']) ?></td>
                <td><?= h(trim("{$row['first_name']} {$row['middle_name']} {$row['last_name']}")) ?></td>
                <td><?= h($row['username']) ?></td>
                <td><span class="pill <?= h($row['status']) ?>"><?= h(ucfirst($row['status'])) ?></span></td>
                <td class="row-actions">
                  <a href="?view=permissions&amp;admin=<?= urlencode($row['id_number']) ?>" class="btn-sm btn-edit">Manage Privileges</a>
                </td>
              </tr>
            <?php endwhile; ?>
            </tbody>
          </table>
          </div>
        <?php endif; ?>
      </div>
    </div>
  <?php else: ?>
    <div class="panel">
      <div class="panel__header">
        <h2><i class="bi bi-key-fill icon-purple"></i> Privileges for <?= h(trim("{$selectedAdminAccount['first_name']} {$selectedAdminAccount['last_name']}")) ?>
          (<?= h($selectedAdminAccount['username']) ?>)</h2>
      </div>
      <div class="panel__body">
        <form method="post" class="perm-matrix">
          <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
          <input type="hidden" name="action" value="save_permissions">
          <input type="hidden" name="id_number" value="<?= h($selectedAdminAccount['id_number']) ?>">

          <?php
            // Split into ungrouped modules (full view+action checkbox matrix,
            // e.g. Registration Management) and modules that belong to a
            // PERMISSION_GROUPS parent (rendered as a single bundled checkbox
            // per sub-feature under that parent's card, e.g. Account Requests).
            $ungroupedModules = [];
            $groupedModules = [];
            foreach (PERMISSION_MODULES as $moduleKey => $module) {
                if (!empty($module['group'])) {
                    $groupedModules[$module['group']][$moduleKey] = $module;
                } else {
                    $ungroupedModules[$moduleKey] = $module;
                }
            }
          ?>

          <?php foreach ($ungroupedModules as $moduleKey => $module):
            $hasView = !empty($adminPermissions[$moduleKey]['view']); ?>
            <div class="perm-module">
              <label class="perm-module__toggle">
                <input type="checkbox" class="perm-module-checkbox" name="perm[<?= h($moduleKey) ?>][view]" value="1" <?= $hasView ? 'checked' : '' ?>>
                <strong><?= h($module['label']) ?></strong>
              </label>
              <p class="perm-module__desc"><?= h($module['description']) ?></p>
              <div class="perm-module__actions">
                <?php foreach ($module['actions'] as $actionKey => $actionLabel): ?>
                  <label class="perm-action">
                    <input type="checkbox" class="perm-action-checkbox" name="perm[<?= h($moduleKey) ?>][<?= h($actionKey) ?>]" value="1"
                           <?= !empty($adminPermissions[$moduleKey][$actionKey]) ? 'checked' : '' ?>>
                    <?= h($actionLabel) ?>
                  </label>
                <?php endforeach; ?>
              </div>
            </div>
          <?php endforeach; ?>

          <?php foreach (PERMISSION_GROUPS as $groupKey => $group):
            if (empty($groupedModules[$groupKey])) continue; ?>
            <div class="perm-module perm-group">
              <div class="perm-group__header">
                <strong><i class="bi bi-folder2-open"></i> <?= h($group['label']) ?></strong>
                <p class="perm-module__desc"><?= h($group['description']) ?></p>
              </div>
              <div class="perm-group__children">
                <?php foreach ($groupedModules[$groupKey] as $moduleKey => $module):
                  $hasView = !empty($adminPermissions[$moduleKey]['view']); ?>
                  <label class="perm-group__child">
                    <input type="checkbox" class="perm-module-checkbox" name="perm[<?= h($moduleKey) ?>][view]" value="1" <?= $hasView ? 'checked' : '' ?>>
                    <span>
                      <strong><?= h($module['label']) ?></strong>
                      <small><?= h($module['description']) ?></small>
                    </span>
                  </label>
                <?php endforeach; ?>
              </div>
            </div>
          <?php endforeach; ?>

          <div class="form-actions">
            <button type="submit" class="btn-primary">Save Permissions</button>
            <a href="?view=permissions" class="btn-ghost">Cancel</a>
          </div>
        </form>

        <form method="post" data-confirm="Revoke every delegated privilege from this Admin?" style="margin-top:10px;">
          <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
          <input type="hidden" name="action" value="revoke_all_permissions">
          <input type="hidden" name="id_number" value="<?= h($selectedAdminAccount['id_number']) ?>">
          <button type="submit" class="btn-sm btn-danger">Revoke All</button>
        </form>
      </div>
    </div>

    <div class="panel">
      <div class="panel__header"><h2><i class="bi bi-clock-history icon-purple"></i> Recent Privilege Changes</h2></div>
      <div class="panel__body">
        <?php if (!$permissionAuditLog || $permissionAuditLog->num_rows === 0): ?>
          <p class="panel__empty">No privilege changes recorded yet for this Admin.</p>
        <?php else: ?>
          <div class="table-scroll">
          <table class="console-table">
            <thead><tr><th>When</th><th>Superadmin</th><th>Module</th><th>Action</th><th>Change</th></tr></thead>
            <tbody>
            <?php while ($log = $permissionAuditLog->fetch_assoc()):
              $moduleLabel = PERMISSION_MODULES[$log['module']]['label'] ?? $log['module'];
              $actionLabel = $log['action'] === 'view' ? 'View' : (PERMISSION_MODULES[$log['module']]['actions'][$log['action']] ?? $log['action']); ?>
              <tr>
                <td><?= h($log['created_at']) ?></td>
                <td><?= h($log['superadmin_username']) ?></td>
                <td><?= h($moduleLabel) ?></td>
                <td><?= h($actionLabel) ?></td>
                <td><span class="pill <?= $log['change_type'] === 'granted' ? 'approved' : 'blocked' ?>"><?= h(ucfirst($log['change_type'])) ?></span></td>
              </tr>
            <?php endwhile; ?>
            </tbody>
          </table>
          </div>
        <?php endif; ?>
      </div>
    </div>
  <?php endif; ?>
  <?php endif; ?>

  <!-- ACTIVITY LOGS -->
  <?php if ($view === 'activity_logs'):
    $alSource = $_GET['source'] ?? 'all';
    if (!in_array($alSource, ['all', 'recent', 'registration', 'permission', 'otp'], true)) {
        $alSource = 'all';
    }
    $alSearch = trim((string)($_GET['q'] ?? ''));
    $alDateFrom = trim((string)($_GET['from'] ?? ''));
    $alDateTo = trim((string)($_GET['to'] ?? ''));
    $alPage = max(1, (int)($_GET['page'] ?? 1));

    // "Recent" is a time-window shortcut layered on top of the normal
    // filters, not a real log source (get_activity_log_entries only knows
    // registration/permission/otp, so passing it through as-is already
    // behaves like "all"). It only supplies a default start date — an
    // explicit From/To picked in the filter bar still wins. The cutoff is
    // computed in MySQL, never PHP's date(), per this app's usual
    // now-vs-server-clock rule.
    $alQueryDateFrom = $alDateFrom;
    if ($alSource === 'recent' && $alQueryDateFrom === '') {
        $alQueryDateFrom = $conn->query("SELECT DATE_SUB(CURDATE(), INTERVAL 7 DAY) AS d")->fetch_assoc()['d'];
    }

    $activityLog = get_activity_log_entries($conn, [
        'source' => $alSource,
        'search' => $alSearch,
        'date_from' => $alQueryDateFrom,
        'date_to' => $alDateTo,
    ], $alPage, 25);

    $alFilterQuery = 'source=' . urlencode($alSource)
        . ($alSearch !== '' ? '&q=' . urlencode($alSearch) : '')
        . ($alDateFrom !== '' ? '&from=' . urlencode($alDateFrom) : '')
        . ($alDateTo !== '' ? '&to=' . urlencode($alDateTo) : '');
  ?>
  <div class="console-header">
    <div class="console-title"><div><h1>Activity Logs</h1></div></div>
  </div>
  <p class="module-desc"><i class="bi bi-info-circle-fill"></i> A single, searchable record of every registration decision, privilege change, and OTP/security event across the system.</p>

  <div class="panel">
    <div class="panel__header"><h2><i class="bi bi-clock-history icon-info"></i> All Activity</h2></div>
    <div class="panel__body">
      <?php $alTabSuffix = ($alSearch !== '' ? '&q=' . urlencode($alSearch) : '') . ($alDateFrom !== '' ? '&from=' . urlencode($alDateFrom) : '') . ($alDateTo !== '' ? '&to=' . urlencode($alDateTo) : ''); ?>
      <?php $alSourceLabels = ['all' => 'All', 'recent' => 'Recent', 'registration' => 'Registration', 'permission' => 'Permission', 'otp' => 'OTP / Security']; ?>
      <form method="get" class="filter-bar">
        <input type="hidden" name="view" value="activity_logs">
        <input type="hidden" name="source" value="<?= h($alSource) ?>">
        <div class="dropdown role-filter-dropdown">
          <button type="button" class="btn-sm btn-edit dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false">
            Source: <?= h($alSourceLabels[$alSource] ?? 'All') ?>
          </button>
          <ul class="dropdown-menu">
            <?php foreach ($alSourceLabels as $val => $lbl): ?>
              <li><a class="dropdown-item <?= $alSource === $val ? 'active' : '' ?>" href="?view=activity_logs&amp;source=<?= $val ?><?= $alTabSuffix ?>" <?= $val === 'recent' ? 'title="Last 7 days"' : '' ?>><?= $lbl ?></a></li>
            <?php endforeach; ?>
          </ul>
        </div>
        <input type="text" name="q" placeholder="Search actor or target" value="<?= h($alSearch) ?>">
        <input type="date" name="from" value="<?= h($alDateFrom) ?>" title="From date">
        <input type="date" name="to" value="<?= h($alDateTo) ?>" title="To date">
        <button type="submit" class="btn-sm btn-edit">Search</button>
        <?php if ($alSearch !== '' || $alDateFrom !== '' || $alDateTo !== ''): ?><a href="?view=activity_logs&amp;source=<?= h($alSource) ?>" class="btn-sm btn-ghost">Clear</a><?php endif; ?>
      </form>

      <?php if (empty($activityLog['rows'])): ?>
        <p class="panel__empty">No activity found for these filters.</p>
      <?php else: ?>
        <div class="table-scroll">
        <table class="console-table">
          <thead><tr><th>When</th><th>Source</th><th>Actor</th><th>Role</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead>
          <tbody>
          <?php foreach ($activityLog['rows'] as $log):
            $srcMeta = ACTIVITY_LOG_SOURCE_META[$log['source']] ?? ['label' => ucfirst($log['source']), 'icon' => 'bi-info-circle-fill', 'class' => 'icon-muted']; ?>
            <tr>
              <td><?= h(date('M j, Y g:i A', strtotime($log['created_at']))) ?></td>
              <td><i class="bi <?= h($srcMeta['icon']) ?> <?= h($srcMeta['class']) ?>"></i> <?= h($srcMeta['label']) ?></td>
              <td><?= h($log['actor']) ?></td>
              <td><?= h($log['actor_role'] !== '' ? ucfirst($log['actor_role']) : '—') ?></td>
              <td><span class="pill <?= h(activity_log_badge_class($log['source'], $log['action'])) ?>"><?= h(ucfirst(str_replace('_', ' ', $log['action']))) ?></span></td>
              <td><?= h($log['target'] !== '' ? $log['target'] : '—') ?></td>
              <td><?= h($log['detail'] ?? '—') ?></td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
        </div>

        <?php if ($activityLog['total_pages'] > 1): ?>
        <div class="row-actions" style="justify-content:flex-end; margin-top:14px;">
          <span class="form-text" style="margin-right:8px;">Page <?= (int)$activityLog['page'] ?> of <?= (int)$activityLog['total_pages'] ?> (<?= (int)$activityLog['total'] ?> total)</span>
          <?php if ($activityLog['page'] > 1): ?>
            <a href="?view=activity_logs&amp;<?= $alFilterQuery ?>&amp;page=<?= $activityLog['page'] - 1 ?>" class="btn-sm btn-ghost">Previous</a>
          <?php endif; ?>
          <?php if ($activityLog['page'] < $activityLog['total_pages']): ?>
            <a href="?view=activity_logs&amp;<?= $alFilterQuery ?>&amp;page=<?= $activityLog['page'] + 1 ?>" class="btn-sm btn-ghost">Next</a>
          <?php endif; ?>
        </div>
        <?php endif; ?>
      <?php endif; ?>
    </div>
  </div>
  <?php endif; ?>

  <?php if ($view === 'login_logs'):
    $llStatus = $_GET['status'] ?? 'all';
    if (!in_array($llStatus, ['all', 'active', 'ended'], true)) {
        $llStatus = 'all';
    }
    $llRole = $_GET['role'] ?? 'all';
    if (!in_array($llRole, ['all', 'user', 'admin', 'superadmin'], true)) {
        $llRole = 'all';
    }
    $llSearch = trim((string)($_GET['q'] ?? ''));
    $llDateFrom = trim((string)($_GET['from'] ?? ''));
    $llDateTo = trim((string)($_GET['to'] ?? ''));
    $llPage = max(1, (int)($_GET['page'] ?? 1));

    $loginLog = get_login_logs($conn, [
        'status' => $llStatus,
        'role' => $llRole,
        'search' => $llSearch,
        'date_from' => $llDateFrom,
        'date_to' => $llDateTo,
    ], $llPage, 25);

    $llTabSuffix = ($llRole !== 'all' ? '&role=' . urlencode($llRole) : '')
        . ($llSearch !== '' ? '&q=' . urlencode($llSearch) : '')
        . ($llDateFrom !== '' ? '&from=' . urlencode($llDateFrom) : '')
        . ($llDateTo !== '' ? '&to=' . urlencode($llDateTo) : '');
    $llFilterQuery = 'status=' . urlencode($llStatus) . $llTabSuffix;
  ?>
  <div class="console-header">
    <div class="console-title"><div><h1>Login Logs</h1></div></div>
  </div>
  <p class="module-desc"><i class="bi bi-info-circle-fill"></i> Every login to the system — when, from what IP address and device, whether the session is still active, and the last page each person touched. Separate from Activity Logs, which tracks management actions rather than sessions.</p>

  <div class="panel">
    <div class="panel__header"><h2><i class="bi bi-shield-lock-fill icon-info"></i> Login History</h2></div>
    <div class="panel__body">
      <!-- Status and Role are two independent facets, each its own dropdown
           (still instant-click on each option) — a tidier, single-row
           container instead of two separate rows of pill tabs. -->
      <?php $llRoleTabSuffix = '&status=' . urlencode($llStatus) . ($llSearch !== '' ? '&q=' . urlencode($llSearch) : '') . ($llDateFrom !== '' ? '&from=' . urlencode($llDateFrom) : '') . ($llDateTo !== '' ? '&to=' . urlencode($llDateTo) : ''); ?>
      <?php $llStatusLabels = ['all' => 'All', 'active' => 'Active Now', 'ended' => 'Logged Out']; ?>
      <?php $llRoleLabels = ['all' => 'All Roles', 'user' => 'User', 'admin' => 'Admin', 'superadmin' => 'Superadmin']; ?>
      <form method="get" class="filter-bar">
        <input type="hidden" name="view" value="login_logs">
        <input type="hidden" name="status" value="<?= h($llStatus) ?>">
        <input type="hidden" name="role" value="<?= h($llRole) ?>">
        <div class="dropdown role-filter-dropdown">
          <button type="button" class="btn-sm btn-edit dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false">
            Status: <?= h($llStatusLabels[$llStatus] ?? 'All') ?>
          </button>
          <ul class="dropdown-menu">
            <?php foreach ($llStatusLabels as $val => $lbl): ?>
              <li><a class="dropdown-item <?= $llStatus === $val ? 'active' : '' ?>" href="?view=login_logs&amp;status=<?= $val ?><?= $llTabSuffix ?>"><?= $lbl ?></a></li>
            <?php endforeach; ?>
          </ul>
        </div>
        <div class="dropdown role-filter-dropdown">
          <button type="button" class="btn-sm btn-edit dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false">
            Role: <?= h($llRoleLabels[$llRole] ?? 'All Roles') ?>
          </button>
          <ul class="dropdown-menu">
            <?php foreach ($llRoleLabels as $val => $lbl): ?>
              <li><a class="dropdown-item <?= $llRole === $val ? 'active' : '' ?>" href="?view=login_logs&amp;role=<?= $val ?><?= $llRoleTabSuffix ?>"><?= $lbl ?></a></li>
            <?php endforeach; ?>
          </ul>
        </div>
        <input type="text" name="q" placeholder="Search name, username, or Employee ID" value="<?= h($llSearch) ?>">
        <input type="date" name="from" value="<?= h($llDateFrom) ?>" title="From date">
        <input type="date" name="to" value="<?= h($llDateTo) ?>" title="To date">
        <button type="submit" class="btn-sm btn-edit">Search</button>
        <?php if ($llRole !== 'all' || $llSearch !== '' || $llDateFrom !== '' || $llDateTo !== ''): ?><a href="?view=login_logs&amp;status=<?= h($llStatus) ?>" class="btn-sm btn-ghost">Clear</a><?php endif; ?>
      </form>

      <?php if (empty($loginLog['rows'])): ?>
        <p class="panel__empty">No login history found for these filters.</p>
      <?php else: ?>
        <div class="table-scroll">
        <table class="console-table">
          <thead><tr><th>User</th><th>Role</th><th>Login Time</th><th>Logout Time</th><th>Status</th><th>Actions</th></tr></thead>
          <tbody>
          <?php foreach ($loginLog['rows'] as $ll): $llStatusMeta = login_log_status($ll); ?>
            <tr>
              <td><?= h($ll['full_name'] !== '' ? $ll['full_name'] : $ll['username']) ?> <span class="form-text">(<?= h($ll['username']) ?>)</span></td>
              <td><?= h(ucfirst($ll['role'])) ?></td>
              <td><?= h(date('M j, Y g:i A', strtotime($ll['login_time']))) ?></td>
              <td><?= $ll['logout_time'] ? h(date('M j, Y g:i A', strtotime($ll['logout_time']))) : '—' ?></td>
              <td><span class="pill <?= h($llStatusMeta['class']) ?>"><?= h($llStatusMeta['label']) ?></span></td>
              <td>
                <button type="button" class="btn-sm btn-edit" data-bs-toggle="modal" data-bs-target="#loginLogModal"
                  data-user="<?= h($ll['full_name'] !== '' ? $ll['full_name'] : $ll['username']) ?>"
                  data-username="<?= h($ll['username']) ?>"
                  data-role="<?= h(ucfirst($ll['role'])) ?>"
                  data-device="<?= h($ll['device_label'] !== '' ? $ll['device_label'] : '—') ?>"
                  data-login="<?= h(date('M j, Y g:i A', strtotime($ll['login_time']))) ?>"
                  data-logout="<?= $ll['logout_time'] ? h(date('M j, Y g:i A', strtotime($ll['logout_time']))) : 'Still active / no explicit logout' ?>"
                  data-duration="<?= h(format_duration($ll['duration_seconds'])) ?><?= $ll['logout_time'] ? '' : ' (so far)' ?>"
                  data-lastaction="<?= h($ll['last_action'] !== null && $ll['last_action'] !== '' ? $ll['last_action'] : '—') ?>"
                  data-status="<?= h($llStatusMeta['label']) ?>"
                ><i class="bi bi-eye-fill"></i> View</button>
              </td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
        </div>

        <?php if ($loginLog['total_pages'] > 1): ?>
        <div class="row-actions" style="justify-content:flex-end; margin-top:14px;">
          <span class="form-text" style="margin-right:8px;">Page <?= (int)$loginLog['page'] ?> of <?= (int)$loginLog['total_pages'] ?> (<?= (int)$loginLog['total'] ?> total)</span>
          <?php if ($loginLog['page'] > 1): ?>
            <a href="?view=login_logs&amp;<?= $llFilterQuery ?>&amp;page=<?= $loginLog['page'] - 1 ?>" class="btn-sm btn-ghost">Previous</a>
          <?php endif; ?>
          <?php if ($loginLog['page'] < $loginLog['total_pages']): ?>
            <a href="?view=login_logs&amp;<?= $llFilterQuery ?>&amp;page=<?= $loginLog['page'] + 1 ?>" class="btn-sm btn-ghost">Next</a>
          <?php endif; ?>
        </div>
        <?php endif; ?>
      <?php endif; ?>
    </div>
  </div>
  <?php endif; ?>

  </div><!-- /.console-wrap -->
  </main>
</div><!-- /.app-shell -->

<!-- DELETE ACCOUNT — shared modal, populated from whichever row's "Delete"
     button opened it (data-id/data-name). Reuses the exact same element IDs
     as admin_dashboard.php's "Request Delete" modal (deleteRequestModal/
     deleteRequestId/deleteRequestTarget/deleteRequestReason/
     deleteRequestCount) so the existing admin_console.js population/
     character-counter logic wires this one up too, with no extra JS —
     only the wording and the hidden action value differ: a Superadmin
     deletes immediately (no Superadmin review step above them), but still
     has to leave a reason behind, same as an Admin's delete request does. -->
<div class="modal fade" id="deleteRequestModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <form method="post" id="deleteRequestForm">
        <div class="modal-header">
          <h5 class="modal-title"><i class="bi bi-exclamation-triangle-fill icon-danger"></i> Delete Account</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
          <input type="hidden" name="action" value="delete">
          <input type="hidden" name="id_number" id="deleteRequestId">
          <p style="margin:0 0 16px; color:var(--ink-muted); font-size:0.88rem;">
            You are permanently deleting <strong id="deleteRequestTarget" style="color:var(--ink);"></strong>.
            This cannot be undone.
          </p>
          <div class="form-field">
            <label for="deleteRequestReason">Reason for deletion <span style="color:var(--danger);">*</span></label>
            <textarea name="reason" id="deleteRequestReason" rows="4" maxlength="500" minlength="5" required
                      placeholder="Explain why this account is being deleted (kept in the Activity Logs)..."></textarea>
            <div class="form-text" id="deleteRequestCount">0 / 500 characters</div>
          </div>
          <input type="hidden" name="current_password" id="deleteRequestPassword">
        </div>
        <div class="modal-footer">
          <button type="button" class="btn-ghost" data-bs-dismiss="modal">Cancel</button>
          <button type="submit" class="btn-sm btn-danger">Delete Account</button>
        </div>
      </form>
    </div>
  </div>
</div>

<!-- PASSWORD CONFIRMATION — the single shared modal every sensitive
     Superadmin action on this page funnels through (Create Account, Block,
     Delete, Change Role, Change Username, Change Password). Entering the
     acting Superadmin's own password is always this one dedicated modal, not
     a field embedded inside whichever action's own modal — clicking that
     action's Confirm/Submit button hides that modal and opens this one
     instead (see js/admin_console.js's requirePasswordConfirm()); confirming
     here copies the typed password into the originating form's hidden
     current_password field and resubmits it for real. -->
<div class="modal fade" id="pwConfirmModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title"><i class="bi bi-shield-lock-fill icon-info"></i> Password Confirmation</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <div class="form-field">
          <label for="pwConfirmInput">Enter Your Password to Confirm <span style="color:var(--danger);">*</span></label>
          <input type="password" id="pwConfirmInput" autocomplete="current-password" required>
          <div class="err" id="pwConfirmError" style="display:none;"></div>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn-ghost" data-bs-dismiss="modal">Cancel</button>
        <button type="button" class="btn-sm btn-primary" id="pwConfirmBtn">Confirm</button>
      </div>
    </div>
  </div>
</div>

<!-- CHANGE ROLE (Promote/Demote, merged into one action) — shared modal,
     populated from whichever row's "Change Role" button opened it
     (data-id/data-name/data-current-role/data-new-role/data-new-role-label).
     The target role is fixed (a 2-role hierarchy has only one possible
     direction per row — computed server-side, never client-editable), but
     proceeding always requires the ACTING Superadmin's own current
     password as a fresh re-authentication step before the change applies. -->
<div class="modal fade" id="changeRoleModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <form method="post" id="changeRoleForm">
        <div class="modal-header">
          <h5 class="modal-title" id="changeRoleTitle"><i class="bi bi-arrow-left-right icon-info"></i> Change Role</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
          <input type="hidden" name="action" value="change_role">
          <input type="hidden" name="id_number" id="changeRoleId">
          <input type="hidden" name="new_role" id="changeRoleNewRole">
          <p style="margin:0 0 10px; color:var(--ink-muted); font-size:0.88rem;">
            Account: <strong id="changeRoleTarget" style="color:var(--ink);"></strong><br>
            Current role: <strong id="changeRoleCurrentRole" style="color:var(--ink);"></strong>
            &nbsp;→&nbsp; New role: <strong id="changeRoleNewRoleLabel" style="color:var(--ink);"></strong>
          </p>
          <p id="changeRoleWarning" class="err" style="display:none; margin-bottom:14px;"></p>
          <div class="form-field">
            <label for="changeRoleReason">Reason for this role change <span style="color:var(--danger);">*</span></label>
            <textarea name="reason" id="changeRoleReason" rows="4" maxlength="500" minlength="5" required
                      placeholder="Explain why this account's role is being changed (kept in the Activity Logs)..."></textarea>
            <div class="form-text" id="changeRoleReasonCount">0 / 500 characters</div>
          </div>
          <input type="hidden" name="current_password" id="changeRolePassword">
        </div>
        <div class="modal-footer">
          <button type="button" class="btn-ghost" data-bs-dismiss="modal">Cancel</button>
          <button type="submit" class="btn-sm btn-primary" id="changeRoleSubmit">Change Role</button>
        </div>
      </form>
    </div>
  </div>
</div>

<!-- BLOCK ACCOUNT — shared modal, populated from whichever row's "Block"
     button opened it (data-id/data-name), used from both the Accounts view
     and the Registration Approval view's already-decided rows (same backend
     action either way). Blocking is powerful enough to require the acting
     Superadmin to re-enter their own current password here before it
     proceeds, same security-confirmation pattern as Change Role. -->
<div class="modal fade" id="blockAccountModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <form method="post" id="blockAccountForm">
        <div class="modal-header">
          <h5 class="modal-title"><i class="bi bi-slash-circle-fill icon-warning"></i> Block Account</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
          <input type="hidden" name="action" value="block">
          <input type="hidden" name="id_number" id="blockAccountId">
          <p style="margin:0 0 14px; color:var(--ink-muted); font-size:0.88rem;">
            This will immediately block <strong id="blockAccountTarget" style="color:var(--ink);"></strong> from logging in.
          </p>
          <div class="form-field">
            <label for="blockAccountReason">Reason for blocking <span style="color:var(--danger);">*</span></label>
            <textarea name="reason" id="blockAccountReason" rows="4" maxlength="500" minlength="5" required
                      placeholder="Explain why this account is being blocked (kept in the Activity Logs)..."></textarea>
            <div class="form-text" id="blockAccountReasonCount">0 / 500 characters</div>
          </div>
          <input type="hidden" name="current_password" id="blockAccountPassword">
        </div>
        <div class="modal-footer">
          <button type="button" class="btn-ghost" data-bs-dismiss="modal">Cancel</button>
          <button type="submit" class="btn-sm btn-danger">Block Account</button>
        </div>
      </form>
    </div>
  </div>
</div>

<!-- UNBLOCK ACCOUNT — shared modal, populated from whichever row's
     "Unblock" button opened it (data-id/data-name). No password confirmation
     (unblocking only restores access, never removes it), but a reason is
     still required so it's traceable in the Activity Logs, same as Block. -->
<div class="modal fade" id="unblockAccountModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <form method="post" id="unblockAccountForm">
        <div class="modal-header">
          <h5 class="modal-title"><i class="bi bi-unlock-fill icon-success"></i> Unblock Account</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
          <input type="hidden" name="action" value="unblock">
          <input type="hidden" name="id_number" id="unblockAccountId">
          <p style="margin:0 0 14px; color:var(--ink-muted); font-size:0.88rem;">
            This will immediately restore login access for <strong id="unblockAccountTarget" style="color:var(--ink);"></strong>.
          </p>
          <div class="form-field">
            <label for="unblockAccountReason">Reason for unblocking <span style="color:var(--danger);">*</span></label>
            <textarea name="reason" id="unblockAccountReason" rows="4" maxlength="500" minlength="5" required
                      placeholder="Explain why this account is being unblocked (kept in the Activity Logs)..."></textarea>
            <div class="form-text" id="unblockAccountReasonCount">0 / 500 characters</div>
          </div>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn-ghost" data-bs-dismiss="modal">Cancel</button>
          <button type="submit" class="btn-sm btn-primary">Unblock Account</button>
        </div>
      </form>
    </div>
  </div>
</div>

<!-- UNBLOCK ACCOUNT (Admin/Superadmin) — shared modal, populated from
     whichever row's "Unblock" button opened it (data-id/data-name/
     data-prev-role), same pattern as admin_dashboard.php's Request Delete
     modal. The role choice has no default selected — the Superadmin must
     explicitly pick one. Unblocking an Admin/Superadmin is powerful enough
     to require a written reason and the acting Superadmin's own password,
     same security-confirmation pattern as every other sensitive action here
     (collected via the shared #pwConfirmModal, not a field in this modal). -->
<div class="modal fade" id="reactivateModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <form method="post" id="reactivateForm">
        <div class="modal-header">
          <h5 class="modal-title"><i class="bi bi-person-check-fill icon-success"></i> Unblock Account</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
          <input type="hidden" name="action" value="reactivate_account">
          <input type="hidden" name="id_number" id="reactivateId">
          <p style="margin:0 0 16px; color:var(--ink-muted); font-size:0.88rem;">
            Unblocking <strong id="reactivateTarget" style="color:var(--ink);"></strong>
            (previously <span id="reactivatePrevRole"></span>). Choose the role this account
            will have going forward — status becomes Active immediately.
          </p>
          <div class="form-field">
            <label for="reactivateRole">New role <span style="color:var(--danger);">*</span></label>
            <select name="new_role" id="reactivateRole" required>
              <option value="" selected disabled>-- Select a role --</option>
              <option value="superadmin">Superadmin — full system access</option>
              <option value="admin">Admin — access only to explicitly granted modules</option>
            </select>
          </div>
          <div class="form-field" style="margin-top:14px;">
            <label for="reactivateReason">Reason for unblocking <span style="color:var(--danger);">*</span></label>
            <textarea name="reason" id="reactivateReason" rows="4" maxlength="500" minlength="5" required
                      placeholder="Explain why this account is being unblocked (kept in the Activity Logs)..."></textarea>
            <div class="form-text" id="reactivateReasonCount">0 / 500 characters</div>
          </div>
          <input type="hidden" name="current_password" id="reactivatePassword">
        </div>
        <div class="modal-footer">
          <button type="button" class="btn-ghost" data-bs-dismiss="modal">Cancel</button>
          <button type="submit" class="btn-sm btn-primary">Unblock</button>
        </div>
      </form>
    </div>
  </div>
</div>

<!-- LOGIN LOG DETAIL — read-only, populated entirely from the triggering
     "View" button's data-* attributes (see the Login Logs table above), same
     pattern as the other shared modals in this file. No server round-trip
     needed since the row already carries everything the modal shows. -->
<div class="modal fade" id="loginLogModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title"><i class="bi bi-shield-lock-fill icon-info"></i> Login Session Detail</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <dl class="detail-list">
          <dt>User</dt><dd id="loginLogUser"></dd>
          <dt>Username</dt><dd id="loginLogUsername"></dd>
          <dt>Role</dt><dd id="loginLogRole"></dd>
          <dt>Status</dt><dd id="loginLogStatus"></dd>
          <dt>Device</dt><dd id="loginLogDevice"></dd>
          <dt>Login Time</dt><dd id="loginLogLoginTime"></dd>
          <dt>Logout Time</dt><dd id="loginLogLogoutTime"></dd>
          <dt>Duration</dt><dd id="loginLogDuration"></dd>
          <dt>Last Activity</dt><dd id="loginLogLastAction"></dd>
        </dl>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn-ghost" data-bs-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>

<!-- CHANGE USERNAME (self-service, My Profile) — always "my own account", so
     the form is rendered straight from $myAccount, no data-* population/JS
     needed like the target-account modals above. Requires the acting
     Superadmin's current password, same security-confirmation pattern as
     Change Role. -->
<?php if (!empty($myAccount) && $myAccount['id_number'] !== DEFAULT_SUPERADMIN_ID): ?>
<div class="modal fade" id="changeUsernameModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <form method="post" id="changeUsernameForm" novalidate>
        <div class="modal-header">
          <h5 class="modal-title"><i class="bi bi-person-badge-fill icon-info"></i> Change Username</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
          <input type="hidden" name="action" value="change_own_username">
          <div class="form-field">
            <label>New Username</label>
            <input type="text" name="new_username" id="changeUsernameInput" value="<?= h($myAccount['username']) ?>" minlength="5" maxlength="30" required autocomplete="username">
            <div class="form-text">Must start with a letter and include at least one uppercase letter, one number, and one special character (_ or .).</div>
          </div>
          <input type="hidden" name="current_password" id="changeUsernamePassword">
        </div>
        <div class="modal-footer">
          <button type="button" class="btn-ghost" data-bs-dismiss="modal">Cancel</button>
          <button type="submit" class="btn-sm btn-primary">Update Username</button>
        </div>
      </form>
    </div>
  </div>
</div>

<!-- CHANGE PASSWORD (self-service, My Profile) — same fields it always had
     (current password was already required), just moved into a modal. -->
<div class="modal fade" id="changePasswordModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <form method="post" id="changePasswordForm" novalidate>
        <div class="modal-header">
          <h5 class="modal-title"><i class="bi bi-key-fill icon-info"></i> Change Password</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
          <input type="hidden" name="action" value="change_own_password">
          <input type="hidden" name="current_password" id="changePasswordCurrent">
          <div class="form-field">
            <label>New Password</label>
            <input type="password" name="new_password" id="changePasswordNew" autocomplete="new-password" minlength="8" maxlength="72" required>
          </div>
          <div class="form-field" style="margin-top:14px;">
            <label>Confirm New Password</label>
            <input type="password" name="confirm_new_password" id="changePasswordConfirm" autocomplete="new-password" minlength="8" maxlength="72" required>
          </div>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn-ghost" data-bs-dismiss="modal">Cancel</button>
          <button type="submit" class="btn-sm btn-primary">Update Password</button>
        </div>
      </form>
    </div>
  </div>
</div>

<!-- CONFIRM USERNAME CHANGE — STEP 2. Auto-opened (see script below) whenever
     a code is pending; the Cancel button is a real submit so the pending
     session state actually clears, not just the modal closing. -->
<div class="modal fade" id="confirmUsernameOtpModal" tabindex="-1" aria-hidden="true" data-bs-backdrop="static">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title"><i class="bi bi-envelope-check-fill icon-info"></i> Enter Verification Code</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <!-- Two independent forms (Confirm vs Cancel post different `action`
           values) linked to their buttons via the HTML `form=""` attribute,
           rather than one form with two submit buttons sharing a name — that
           approach is fragile (relies on DOM-order tie-breaking for which
           value PHP sees). -->
      <form method="post" id="confirmUsernameOtpForm" novalidate>
        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
        <input type="hidden" name="action" value="confirm_username_change">
      </form>
      <form method="post" id="cancelUsernameChangeForm">
        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
        <input type="hidden" name="action" value="cancel_username_change">
      </form>
      <div class="modal-body">
        <p class="form-text" style="margin:0 0 14px;">We emailed a 6-digit code to confirm this username change. It expires in 5 minutes.</p>
        <div class="form-field">
          <label>Verification Code</label>
          <input type="text" name="otp" id="confirmUsernameOtpInput" form="confirmUsernameOtpForm" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="one-time-code" required autofocus>
        </div>
      </div>
      <div class="modal-footer">
        <button type="submit" form="cancelUsernameChangeForm" class="btn-ghost">Cancel</button>
        <button type="submit" form="confirmUsernameOtpForm" class="btn-sm btn-primary">Confirm</button>
      </div>
    </div>
  </div>
</div>

<!-- CONFIRM PASSWORD CHANGE — STEP 2, same pattern as username. -->
<div class="modal fade" id="confirmPasswordOtpModal" tabindex="-1" aria-hidden="true" data-bs-backdrop="static">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title"><i class="bi bi-envelope-check-fill icon-info"></i> Enter Verification Code</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <form method="post" id="confirmPasswordOtpForm" novalidate>
        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
        <input type="hidden" name="action" value="confirm_password_change">
      </form>
      <form method="post" id="cancelPasswordChangeForm">
        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
        <input type="hidden" name="action" value="cancel_password_change">
      </form>
      <div class="modal-body">
        <p class="form-text" style="margin:0 0 14px;">We emailed a 6-digit code to confirm this password change. It expires in 5 minutes.</p>
        <div class="form-field">
          <label>Verification Code</label>
          <input type="text" name="otp" id="confirmPasswordOtpInput" form="confirmPasswordOtpForm" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="one-time-code" required autofocus>
        </div>
      </div>
      <div class="modal-footer">
        <button type="submit" form="cancelPasswordChangeForm" class="btn-ghost">Cancel</button>
        <button type="submit" form="confirmPasswordOtpForm" class="btn-sm btn-primary">Confirm</button>
      </div>
    </div>
  </div>
</div>
<?php endif; ?>

<script>
  window.AWAITING_USERNAME_OTP = <?= json_encode($awaitingUsernameOtp) ?>;
  window.AWAITING_PASSWORD_OTP = <?= json_encode($awaitingPasswordOtp) ?>;
  window.USERNAME_CHANGE_PASSWORD_ERROR = <?= json_encode($usernameChangePasswordError) ?>;
  window.PASSWORD_CHANGE_PASSWORD_ERROR = <?= json_encode($passwordChangePasswordError) ?>;
</script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="js/admin_console.js"></script>
<script src="js/create_account_validate.js"></script>
</body>
</html>
