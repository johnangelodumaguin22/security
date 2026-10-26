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
include '../include/login_logs.php'; // heartbeats this session's Login Logs row (viewed from Superadmin)

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
ini_set('display_errors', '0');

require_role(['admin']);

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$myIdNumber = $_SESSION['id_number'];
$flash = null;
$editErrors = [];
$editValues = null;
$editTarget = null;
$pwErrors = [];
$forceAccountsView = false;
$ownProfileErrors = [];
$ownProfileValues = null;
$reopenChangeUsernameModal = false;
$reopenChangePasswordModal = false;
$createErrors = [];
$createValues = null;

// Every bare Admin account created via Create Account starts on this exact,
// fixed password — never an Admin-chosen one, and never editable in the form
// (the field is locked/readonly; the server also never reads $_POST for it,
// so a tampered request can't override it either). Safe specifically because
// completeStaffProfile() forces the account owner to set a real, self-chosen
// replacement password on first login before they can reach any dashboard.
// Same value as superadmin_dashboard.php's own copy of this constant.
const DEFAULT_STAFF_PASSWORD = '@Abcde12345';

function csrf_ok() {
    return !empty($_POST['csrf_token']) && !empty($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']);
}

// Rate limiting for account creation — same escalating lockout used on
// superadmin_dashboard.php's own copy, scoped to its own session key so it
// never interferes with the rest of this dashboard's actions.
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

function fetch_account($conn, $idNumber, array $allowedRoles) {
    $stmt = $conn->prepare("SELECT * FROM users WHERE id_number = ?");
    $stmt->bind_param("s", $idNumber);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    if (!$row || !in_array($row['role'], $allowedRoles, true)) {
        return null;
    }
    return $row;
}

// Unrestricted lookup (any role) — used only for the delegated delete-request
// review guard below, which must be able to *see* a superadmin row in order
// to refuse to delete it.
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
            if (!require_module_permission($conn, 'registration_management', $moduleAction)) {
                $flash = ['type' => 'err', 'text' => 'Access denied: you do not have permission to perform this action.'];
            } else {
                $newStatus = ['approve' => 'approved', 'reject_registration' => 'rejected', 'block_registration' => 'blocked'][$action];
                $pendingAccount = $action === 'reject_registration'
                    ? discardPendingRegistration($conn, $targetId)
                    : promotePendingRegistration($conn, $targetId, $newStatus);

                if (!$pendingAccount) {
                    $flash = ['type' => 'err', 'text' => 'That registration is no longer pending.'];
                } else {
                    $targetName = trim($pendingAccount['first_name'] . ' ' . $pendingAccount['last_name']);
                    log_registration_action($conn, $moduleAction, 'admin', $_SESSION['username'], "registration_management.$moduleAction", $targetId, $targetName, 'pending', $newStatus);
                    if ($action === 'approve' && !empty($pendingAccount['email'])) {
                        send_approval_email($pendingAccount['email'], $pendingAccount['first_name']);
                    }
                    $labels = ['approve' => 'Registration approved.', 'reject_registration' => 'Registration rejected.', 'block_registration' => 'Registration blocked.'];
                    $flash = ['type' => 'ok', 'text' => $labels[$action]];
                }
            }

        } elseif ($action === 'block' || $action === 'unblock') {
            $account = fetch_account($conn, $targetId, ['user', 'admin']);
            $reason = trim((string)($_POST['reason'] ?? ''));
            if (!$account) {
                $flash = ['type' => 'err', 'text' => 'Account not found.'];
            } elseif ($targetId === $myIdNumber) {
                $flash = ['type' => 'err', 'text' => 'You cannot block your own account.'];
            } elseif ($reason === '' || mb_strlen($reason) < 5 || mb_strlen($reason) > 500 || hasHtmlOrScript($reason)) {
                $flash = ['type' => 'err', 'text' => 'Please provide a reason (5-500 characters, no HTML).'];
            } else {
                $newStatus = $action === 'block' ? 'blocked' : 'approved';
                $fromStatus = $action === 'block' ? 'approved' : 'blocked';
                $stmt = $conn->prepare("UPDATE users SET status = ? WHERE id_number = ? AND status = ?");
                $stmt->bind_param("sss", $newStatus, $targetId, $fromStatus);
                $stmt->execute();
                if ($stmt->affected_rows > 0) {
                    $targetName = trim(($account['first_name'] ?? '') . ' ' . ($account['last_name'] ?? '')) ?: $account['username'];
                    log_registration_action($conn, $action, 'admin', $_SESSION['username'], null, $targetId, $targetName, $fromStatus, $newStatus, $reason);
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

        } elseif ($action === 'save_edit') {
            if (!require_module_permission($conn, 'edit_user_info', 'edit')) {
                $flash = ['type' => 'err', 'text' => 'Access denied: you do not have permission to perform this action.'];
                $forceAccountsView = true;
            } else {
                $account = fetch_account($conn, $targetId, ['user', 'admin']);
                if (!$account) {
                    $flash = ['type' => 'err', 'text' => 'Account not found.'];
                } else {
                    [$errors, $clean] = validateProfileEdit($conn, $_POST, $targetId);
                    if (!empty($errors)) {
                        $editErrors = $errors;
                        $editValues = $_POST;
                        $editTarget = $account;
                    } else {
                        // Employee ID and Email are fixed at creation and were
                        // never part of this form (no name="email"/"id_number"
                        // input) — the UPDATE below never touches either
                        // column, regardless of what a tampered request sends.
                        $stmt = $conn->prepare("UPDATE users SET
                            username=?, first_name=?, middle_name=?, last_name=?, extension=?, sex=?, birthdate=?, age=?,
                            street=?, barangay=?, city=?, province=?, region=?, zip_code=?
                            WHERE id_number=?");
                        $stmt->bind_param(
                            "sssssssssssssss",
                            $clean['username'], $clean['first_name'], $clean['middle_name'], $clean['last_name'], $clean['extension'],
                            $clean['sex'], $clean['birthdate'], $clean['age'],
                            $clean['street'], $clean['barangay'], $clean['city'], $clean['province'], $clean['region'],
                            $clean['zip'], $targetId
                        );
                        $stmt->execute();
                        // Editing your own row's username (Admin accounts also
                        // appear in this Accounts table) must update the live
                        // session too, or the sidebar/require_role() checks
                        // would keep showing the stale pre-edit username.
                        if ($targetId === $myIdNumber) {
                            $_SESSION['username'] = $clean['username'];
                        }
                        $flash = ['type' => 'ok', 'text' => 'Account info updated.'];
                    }
                }
            }

        // Self-service "Edit Profile" (My Profile) — unlike save_edit above,
        // this never needs the delegated edit_user_info permission (an
        // Admin can always edit their own profile), but it DOES require
        // re-entering their own current password first, collected via the
        // shared #pwConfirmModal, same pattern as every sensitive
        // self-service action on the Superadmin side. Employee ID and Email
        // are fixed and were never part of this form either.
        } elseif ($action === 'save_own_profile') {
            $currentPassword = (string)($_POST['current_password'] ?? '');
            $me = resolve_self_account($conn, $myIdNumber);
            if ($currentPassword === '' || !$me || !verify_login_password($myIdNumber, $currentPassword, $me['password'])) {
                $flash = ['type' => 'err', 'text' => 'Incorrect password. Profile changes were not saved.'];
                $ownProfileValues = $_POST;
            } else {
                [$errors, $clean] = validateProfileEdit($conn, $_POST, $myIdNumber);
                if (!empty($errors)) {
                    $ownProfileErrors = $errors;
                    $ownProfileValues = $_POST;
                } else {
                    $stmt = $conn->prepare("UPDATE users SET
                        username=?, first_name=?, middle_name=?, last_name=?, extension=?, sex=?, birthdate=?, age=?,
                        street=?, barangay=?, city=?, province=?, region=?, zip_code=?
                        WHERE id_number=?");
                    $stmt->bind_param(
                        "sssssssssssssss",
                        $clean['username'], $clean['first_name'], $clean['middle_name'], $clean['last_name'], $clean['extension'],
                        $clean['sex'], $clean['birthdate'], $clean['age'],
                        $clean['street'], $clean['barangay'], $clean['city'], $clean['province'], $clean['region'],
                        $clean['zip'], $myIdNumber
                    );
                    $stmt->execute();
                    $_SESSION['username'] = $clean['username'];
                    $flash = ['type' => 'ok', 'text' => 'Your profile has been updated.'];
                }
            }

        // Self-service Change Username (My Profile > Account Security) —
        // same validation rules and password-confirm requirement as
        // superadmin_dashboard.php's own copy, just applied immediately
        // instead of behind an email-OTP step (that extra step was
        // deliberately left Superadmin-only).
        } elseif ($action === 'change_own_username') {
            $me = resolve_self_account($conn, $myIdNumber);
            $newUsernameRaw = (string)($_POST['new_username'] ?? '');
            $newUsername = trim($newUsernameRaw);
            $currentPassword = (string)($_POST['current_password'] ?? '');

            if (!$me || $currentPassword === '' || !verify_login_password($myIdNumber, $currentPassword, $me['password'])) {
                $flash = ['type' => 'err', 'text' => 'Incorrect password. Username change cancelled.'];
                $reopenChangeUsernameModal = true;
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
                    $stmt = $conn->prepare("UPDATE users SET username = ? WHERE id_number = ?");
                    $stmt->bind_param("ss", $newUsername, $myIdNumber);
                    $stmt->execute();
                    $_SESSION['username'] = $newUsername;
                    log_otp_action($conn, $myIdNumber, $me['email'] ?? '', 'username_changed_by_self', $me['role']);
                    $flash = ['type' => 'ok', 'text' => 'Username updated to ' . $newUsername . '.'];
                }
            }

        // Self-service Change Password (My Profile > Account Security) —
        // same validation rules and password-confirm requirement as
        // superadmin_dashboard.php's own copy, applied immediately (no
        // email-OTP step, Superadmin-only there).
        } elseif ($action === 'change_own_password') {
            $me = resolve_self_account($conn, $myIdNumber);
            $currentPassword = (string)($_POST['current_password'] ?? '');
            $newPassword = (string)($_POST['new_password'] ?? '');
            $confirmPassword = (string)($_POST['confirm_new_password'] ?? '');

            if (!$me || $currentPassword === '' || !verify_login_password($myIdNumber, $currentPassword, $me['password'])) {
                $flash = ['type' => 'err', 'text' => 'Incorrect current password.'];
                $reopenChangePasswordModal = true;
            } elseif ($newPassword === '' || $confirmPassword === '') {
                $flash = ['type' => 'err', 'text' => 'Please fill in both new-password fields.'];
            } elseif ($newPassword !== $confirmPassword) {
                $flash = ['type' => 'err', 'text' => 'New passwords do not match.'];
            } elseif (!is_strong_password($newPassword)) {
                $flash = ['type' => 'err', 'text' => 'Password must be 8-72 characters and not a commonly used password.'];
            } elseif (password_verify($newPassword, $me['password'])) {
                $flash = ['type' => 'err', 'text' => 'New password must be different from your current password.'];
            } else {
                $hashed = password_hash($newPassword, PASSWORD_DEFAULT);
                $stmt = $conn->prepare("UPDATE users SET password = ? WHERE id_number = ?");
                $stmt->bind_param("ss", $hashed, $myIdNumber);
                $stmt->execute();
                log_otp_action($conn, $myIdNumber, $me['email'] ?? '', 'password_changed_by_self', $me['role']);
                $flash = ['type' => 'ok', 'text' => 'Password updated successfully.'];
            }

        // Lets an Admin set a new password on someone else's behalf — e.g.
        // the account holder personally asked for their password to be
        // changed. Never available for your own row (use Forgot Password
        // for that); scoped to user/admin accounts only, same as every
        // other Accounts-table action on this page — Superadmin accounts
        // never appear here at all.
        } elseif ($action === 'change_password') {
            $account = fetch_account($conn, $targetId, ['user', 'admin']);
            if (!$account) {
                $flash = ['type' => 'err', 'text' => 'Account not found.'];
            } elseif ($targetId === $myIdNumber) {
                $flash = ['type' => 'err', 'text' => 'You cannot change your own password here.'];
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

        } elseif ($action === 'request_delete') {
            $account = fetch_account($conn, $targetId, ['user', 'admin']);
            $reason = trim((string)($_POST['reason'] ?? ''));
            if (!$account) {
                $flash = ['type' => 'err', 'text' => 'Account not found.'];
            } elseif ($targetId === $myIdNumber) {
                $flash = ['type' => 'err', 'text' => 'You cannot request deletion of your own account.'];
            } elseif ($reason === '' || mb_strlen($reason) < 5 || mb_strlen($reason) > 500 || hasHtmlOrScript($reason)) {
                $flash = ['type' => 'err', 'text' => 'Please provide a reason (5-500 characters, no HTML).'];
            } else {
                $targetName = trim($account['first_name'] . ' ' . $account['last_name']);
                $stmt = $conn->prepare("INSERT INTO delete_requests (target_id_number, target_name, target_username, requested_by_username, reason) VALUES (?, ?, ?, ?, ?)");
                $stmt->bind_param("sssss", $targetId, $targetName, $account['username'], $_SESSION['username'], $reason);
                $stmt->execute();
                log_registration_action($conn, 'delete_request_submitted', 'admin', $_SESSION['username'], null, $targetId, $targetName, $account['status'], 'pending');
                $flash = ['type' => 'ok', 'text' => 'Delete request submitted to the Superadmin for review.'];
            }

        } elseif ($action === 'review_delete_request') {
            $decision = $_POST['decision'] ?? '';
            $moduleAction = $decision === 'reject' ? 'reject' : 'approve';
            if (!require_module_permission($conn, 'delete_requests', $moduleAction)) {
                $flash = ['type' => 'err', 'text' => 'Access denied: you do not have permission to perform this action.'];
            } else {
                $requestId = (int)($_POST['request_id'] ?? 0);
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
                            $flash = ['type' => 'err', 'text' => 'Cannot delete a Superadmin account.'];
                        } elseif ($reqRow['target_id_number'] === $myIdNumber) {
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
                            log_registration_action($conn, 'delete_request_approved', 'admin', $_SESSION['username'], 'delete_requests.approve', $reqRow['target_id_number'], $reqRow['target_name'], 'pending', 'deleted');
                            $flash = ['type' => 'ok', 'text' => $target ? 'Account deleted and request approved.' : 'Account was already gone; request marked approved.'];
                        }
                    } else {
                        $upd = $conn->prepare("UPDATE delete_requests SET status = ?, reviewed_by_username = ?, reviewed_at = NOW() WHERE id = ?");
                        $upd->bind_param("ssi", $newStatus, $_SESSION['username'], $requestId);
                        $upd->execute();
                        log_registration_action($conn, 'delete_request_rejected', 'admin', $_SESSION['username'], 'delete_requests.reject', $reqRow['target_id_number'], $reqRow['target_name'], 'pending', 'rejected');
                        $flash = ['type' => 'ok', 'text' => 'Delete request rejected.'];
                    }
                }
            }

        } elseif ($action === 'create_account') {
            if (!require_module_permission($conn, 'create_account', 'create')) {
                $flash = ['type' => 'err', 'text' => 'Access denied: you do not have permission to perform this action.'];
            } else {
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
                        // Role is never read from $_POST — an Admin can only ever
                        // create an Admin account, never a Superadmin, regardless
                        // of what a tampered request might send.
                        $role = 'admin';
                        try {
                            [$errors, $clean] = validateBareAccountCreation($conn, $_POST);
                            if (!empty($errors)) {
                                $createErrors = $errors;
                                $createValues = $_POST;
                            } else {
                                // Never read $_POST['password'] here — the field is
                                // locked/readonly client-side specifically so this
                                // can't drift, and the server independently never
                                // trusts it even if a tampered request sends one.
                                $rawPassword = DEFAULT_STAFF_PASSWORD;
                                $result = createBareStaffAccount($conn, $clean['username'], $rawPassword, $role, $clean['email']);
                                if ($result['status']) {
                                    create_account_rate_limit_reset();
                                    log_registration_action($conn, 'create_account', 'admin', $_SESSION['username'], null, $result['id_number'], $clean['username'], '', $role);
                                    $emailSent = send_account_created_email($clean['email'], $clean['username'], $rawPassword, $role);
                                    $flash = ['type' => 'ok', 'text' => 'Admin account created: ' . $result['id_number'] . '. '
                                        . ($emailSent ? 'Their username and password were emailed to ' . $clean['email'] . '.' : 'The account was created, but the credentials email could not be sent — please share them with the new admin manually.')
                                        . ' They must complete their profile on first login before they can access the dashboard.'];
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
            }

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

        } elseif ($action === 'remove_profile_picture') {
            $me = fetch_any_account($conn, $myIdNumber);
            deleteProfilePictureFile($me['profile_picture'] ?? null);
            $stmt = $conn->prepare("UPDATE users SET profile_picture = NULL WHERE id_number = ?");
            $stmt->bind_param("s", $myIdNumber);
            $stmt->execute();
            $flash = ['type' => 'ok', 'text' => 'Profile picture removed.'];
        }
    }
}

// -----------------------------------------------------------------
// My own profile row — used by the "My Profile" view/sidebar avatar.
// -----------------------------------------------------------------
$myAccount = fetch_any_account($conn, $myIdNumber);

// -----------------------------------------------------------------
// Edit form pre-fill (GET ?action=edit&id=...)
// -----------------------------------------------------------------
if ($editTarget === null && ($_GET['action'] ?? '') === 'edit' && !empty($_GET['id'])) {
    if (!require_module_permission($conn, 'edit_user_info', 'edit')) {
        $flash = ['type' => 'err', 'text' => 'Access denied: you do not have permission to perform this action.'];
    } else {
        $account = fetch_account($conn, trim($_GET['id']), ['user', 'admin']);
        if ($account) {
            $editTarget = $account;
            $editValues = $account;
        } else {
            $flash = ['type' => 'err', 'text' => 'Account not found.'];
        }
    }
}

// -----------------------------------------------------------------
// Data for the two tables
// -----------------------------------------------------------------
// A pending self-registration is never a `users` row (see
// registration_helpers.php / pending_registration).
$pending = $conn->query("SELECT id_number, first_name, middle_name, last_name, username, created_at
                          FROM pending_registration ORDER BY created_at DESC");

$search = trim((string)($_GET['q'] ?? ''));
if ($search !== '') {
    $like = '%' . $search . '%';
    $stmt = $conn->prepare("SELECT id_number, first_name, middle_name, last_name, username, role, status,
                                    TIMESTAMPDIFF(SECOND, last_activity, NOW()) AS seconds_since_activity
                             FROM users WHERE role IN ('user','admin') AND id_number LIKE ?
                             ORDER BY created_at DESC");
    $stmt->bind_param("s", $like);
    $stmt->execute();
    $accounts = $stmt->get_result();
} else {
    $accounts = $conn->query("SELECT id_number, first_name, middle_name, last_name, username, role, status,
                                      TIMESTAMPDIFF(SECOND, last_activity, NOW()) AS seconds_since_activity
                               FROM users WHERE role IN ('user','admin')
                               ORDER BY created_at DESC");
}

$pendingCount = $pending->num_rows;

// -----------------------------------------------------------------
// Delegated-permission modules — visible to every Admin for awareness,
// but each view/action below is re-checked here AND inside its POST
// handler above. The sidebar/UI state below never substitutes for that.
// -----------------------------------------------------------------
$canEditUserInfo = require_module_permission($conn, 'edit_user_info', 'edit');
$canCreateAccount = require_module_permission($conn, 'create_account', 'create');
$canViewDeleteRequests = require_module_permission($conn, 'delete_requests', 'view');
$canApproveDeleteRequests = require_module_permission($conn, 'delete_requests', 'approve');
$canRejectDeleteRequests = require_module_permission($conn, 'delete_requests', 'reject');
$canApproveRegistration = require_module_permission($conn, 'registration_management', 'approve');
$canRejectRegistration = require_module_permission($conn, 'registration_management', 'reject');
$canBlockRegistration = require_module_permission($conn, 'registration_management', 'block');

$deleteRequestCount = $conn->query("SELECT COUNT(*) c FROM delete_requests WHERE status = 'pending'")->fetch_assoc()['c'];
$deleteRequestsQueue = null;
if ($canViewDeleteRequests) {
    $deleteRequestsQueue = $conn->query("SELECT * FROM delete_requests WHERE status = 'pending' ORDER BY created_at ASC");
}

$view = $_GET['view'] ?? 'overview';
if ($editTarget) {
    $view = 'accounts';
}
if ($forceAccountsView) {
    $view = 'accounts';
}
if (!in_array($view, ['overview', 'pending', 'accounts', 'create_account', 'delete_requests', 'activity_logs', 'my_profile'], true)) {
    $view = 'overview';
}

// Preview only — the id_number actually assigned is (re-)generated inside
// createBareStaffAccount()'s own transaction at submit time, same pattern as
// superadmin_dashboard.php's own Create Account preview.
$nextIdPreview = ($view === 'create_account') ? generateNextId($conn) : '';

$totalAccounts = $conn->query("SELECT COUNT(*) c FROM users WHERE role IN ('user','admin')")->fetch_assoc()['c'];
$blockedCount = $conn->query("SELECT COUNT(*) c FROM users WHERE role IN ('user','admin') AND status = 'blocked'")->fetch_assoc()['c'];
$activeNowCount = $conn->query("SELECT COUNT(*) c FROM users WHERE role IN ('user','admin') AND last_activity >= (NOW() - INTERVAL " . ACTIVE_WINDOW_MINUTES . " MINUTE)")->fetch_assoc()['c'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Dashboard | CSU Instructor Registration and Management</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="../CSS/admin_console.css">
</head>
<body class="role-admin">

<div class="app-shell">
  <aside class="sidebar">
    <div class="sidebar__brand">
      <div class="console-icon"><i class="bi bi-mortarboard-fill"></i></div>
      <div>
        <p class="sidebar__eyebrow">CSU IRM</p>
        <p class="sidebar__title">Admin Panel</p>
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
      <span class="role-tag"><i class="bi bi-shield-fill"></i> Admin</span>
    </div>
    <nav class="sidebar__nav">
      <p class="sidebar__section-label">Main</p>
      <a href="?view=overview" class="sidebar__link <?= $view === 'overview' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-grid-fill"></i> Overview</span>
      </a>

      <p class="sidebar__section-label">Account Management</p>
      <a href="?view=pending" class="sidebar__link <?= $view === 'pending' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-hourglass-split"></i> Pending Registrations</span>
        <?php if ($pendingCount > 0): ?><span class="sidebar__badge"><?= (int)$pendingCount ?></span><?php endif; ?>
      </a>
      <a href="?view=accounts" class="sidebar__link <?= $view === 'accounts' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-people-fill"></i> Accounts</span>
      </a>
      <a href="?view=activity_logs" class="sidebar__link <?= $view === 'activity_logs' ? 'active' : '' ?>">
        <span class="label"><i class="bi bi-clock-history"></i> Activity Logs</span>
      </a>

      <p class="sidebar__section-label sidebar__section-label--delegated"><i class="bi bi-shield-fill-check"></i> Superadmin Modules</p>
      <a href="?view=create_account" class="sidebar__link <?= $view === 'create_account' ? 'active' : '' ?> <?= $canCreateAccount ? '' : 'locked' ?>">
        <span class="label"><i class="bi bi-person-plus-fill"></i> Create Account</span>
        <?php if (!$canCreateAccount): ?><i class="bi bi-lock-fill sidebar__lock" title="Requires Superadmin-granted access"></i><?php endif; ?>
      </a>
      <a href="?view=delete_requests" class="sidebar__link <?= $view === 'delete_requests' ? 'active' : '' ?> <?= $canViewDeleteRequests ? '' : 'locked' ?>">
        <span class="label"><i class="bi bi-exclamation-triangle-fill"></i> Delete Requests</span>
        <?php if (!$canViewDeleteRequests): ?><i class="bi bi-lock-fill sidebar__lock" title="Requires Superadmin-granted access"></i>
        <?php elseif ($deleteRequestCount > 0): ?><span class="sidebar__badge"><?= (int)$deleteRequestCount ?></span><?php endif; ?>
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
  <p class="module-desc"><i class="bi bi-info-circle-fill"></i> Your workspace at a glance — items waiting on your review, account totals, and a log of the actions you've personally taken.</p>

  <div class="stat-grid">
    <div class="stat-tile"><div class="stat-tile__icon stat-tile__icon--live"><i class="bi bi-broadcast"></i></div><div><div class="num"><?= (int)$activeNowCount ?></div><div class="label">Active right now</div></div></div>
    <div class="stat-tile"><div class="stat-tile__icon"><i class="bi bi-hourglass-split"></i></div><div><div class="num"><?= (int)$pendingCount ?></div><div class="label">Pending registrations</div></div></div>
    <div class="stat-tile"><div class="stat-tile__icon"><i class="bi bi-people-fill"></i></div><div><div class="num"><?= (int)$totalAccounts ?></div><div class="label">Total accounts</div></div></div>
    <div class="stat-tile"><div class="stat-tile__icon"><i class="bi bi-slash-circle-fill"></i></div><div><div class="num"><?= (int)$blockedCount ?></div><div class="label">Blocked accounts</div></div></div>
  </div>

  <div class="panel">
    <div class="panel__header"><h2><i class="bi bi-activity icon-info"></i> My Recent Activity</h2></div>
    <div class="panel__body">
      <?php $recentActivity = get_recent_activity($conn, 15, $_SESSION['username']); ?>
      <?php if (empty($recentActivity)): ?>
        <p class="panel__empty">No activity recorded yet.</p>
      <?php else: ?>
        <ul class="activity-feed">
          <?php foreach ($recentActivity as $item): ?>
            <li class="activity-feed__item">
              <span class="activity-feed__icon <?= h($item['class']) ?>"><i class="bi <?= h($item['icon']) ?>"></i></span>
              <span class="activity-feed__text"><?= $item['text'] ?></span>
              <span class="activity-feed__time"><?= h(date('M j, g:i A', strtotime($item['created_at']))) ?></span>
            </li>
          <?php endforeach; ?>
        </ul>
      <?php endif; ?>
    </div>
  </div>
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
        </div>
        <p class="form-text" style="margin-top:6px; width:100%;">JPG, PNG, or WEBP. Max 2 MB.</p>
      </div>
    </div>
  </div>

  <div class="panel">
    <div class="panel__header">
      <h2><i class="bi bi-person-lines-fill"></i> Profile Information</h2>
      <button type="button" class="btn-sm btn-edit" data-bs-toggle="modal" data-bs-target="#editMyProfileModal">
        <i class="bi bi-pencil-square"></i> Edit Profile
      </button>
    </div>
    <div class="panel__body">
      <?php
        $myFullAddress = implode(', ', array_filter([
            $myAccount['street'] ?? '', $myAccount['barangay'] ?? '', $myAccount['city'] ?? '',
            $myAccount['province'] ?? '', $myAccount['region'] ?? '', $myAccount['zip_code'] ?? '',
        ], fn($part) => trim((string)$part) !== ''));
      ?>
      <div class="form-grid">
        <div class="form-field">
          <label>Employee ID</label>
          <div class="profile-value"><?= h($myAccount['id_number']) ?></div>
        </div>
        <div class="form-field">
          <label>Role</label>
          <div class="profile-value"><?= h(ucfirst($myAccount['role'])) ?></div>
        </div>
        <div class="form-field">
          <label>Full Name</label>
          <div class="profile-value"><?= h(trim("{$myAccount['first_name']} {$myAccount['middle_name']} {$myAccount['last_name']} {$myAccount['extension']}")) ?></div>
        </div>
        <div class="form-field">
          <label>Username</label>
          <div class="profile-value"><?= h($myAccount['username']) ?></div>
        </div>
        <div class="form-field">
          <label>Email</label>
          <div class="profile-value"><?= h($myAccount['email'] ?: 'Not provided') ?></div>
        </div>
        <div class="form-field">
          <label>Sex</label>
          <div class="profile-value"><?= h($myAccount['sex'] ?: '—') ?></div>
        </div>
        <div class="form-field">
          <label>Birthdate</label>
          <div class="profile-value"><?= $myAccount['birthdate'] ? h(date('M j, Y', strtotime($myAccount['birthdate']))) : '—' ?></div>
        </div>
        <div class="form-field">
          <label>Member Since</label>
          <div class="profile-value"><?= h(date('M j, Y', strtotime($myAccount['created_at']))) ?></div>
        </div>
        <div class="form-field full">
          <label>Address</label>
          <div class="profile-value"><?= h($myFullAddress ?: '—') ?></div>
        </div>
      </div>
    </div>
  </div>

  <!-- ACCOUNT SECURITY — same concept as superadmin_dashboard.php's own My
       Profile: Change Username / Change Password, each opening its own
       modal, each requiring the acting Admin's own current password before
       it applies (collected via the shared #pwConfirmModal, never a field
       inline in these two modals). No email-OTP confirmation step here —
       that extra layer is intentionally Superadmin-only. -->
  <div class="panel">
    <div class="panel__header"><h2><i class="bi bi-shield-lock-fill icon-purple"></i> Account Security</h2></div>
    <div class="panel__body">
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
    </div>
  </div>

  <!-- EDIT MY PROFILE (self-service) — Employee ID and Email are fixed, same
       rule as editing a co-admin/user; everything else here is editable.
       Submitting requires the shared password-confirm modal (#pwConfirmModal)
       before it actually posts, same as every sensitive Superadmin-side
       self-service action. -->
  <div class="modal fade" id="editMyProfileModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered modal-lg">
      <div class="modal-content">
        <form method="post" id="editMyProfileForm" novalidate>
          <div class="modal-header">
            <h5 class="modal-title"><i class="bi bi-pencil-square icon-info"></i> Edit Profile</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
          </div>
          <div class="modal-body">
            <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
            <input type="hidden" name="action" value="save_own_profile">
            <input type="hidden" name="current_password" id="editMyProfilePassword">
            <div class="form-grid">
              <div class="form-field">
                <label>Employee ID</label>
                <input type="text" value="<?= h($myAccount['id_number']) ?>" readonly>
                <div class="form-text">Assigned at creation — not editable.</div>
              </div>
              <div class="form-field">
                <label>Email</label>
                <input type="email" value="<?= h($myAccount['email'] ?? '') ?>" readonly>
                <div class="form-text">Fixed at creation — not editable.</div>
              </div>
              <div class="form-field">
                <label>Username</label>
                <input type="text" name="username" value="<?= h($ownProfileValues['username'] ?? $myAccount['username']) ?>" minlength="5" maxlength="30">
                <div class="form-text">Must start with a letter and include at least one uppercase letter, one number, and one special character (_ or .).</div>
                <?php if (!empty($ownProfileErrors['username'])): ?><div class="err"><?= h($ownProfileErrors['username']) ?></div><?php endif; ?>
              </div>
              <div class="form-field">
                <label>First Name</label>
                <input type="text" name="first_name" value="<?= h($ownProfileValues['first_name'] ?? $myAccount['first_name']) ?>">
                <?php if (!empty($ownProfileErrors['first_name'])): ?><div class="err"><?= h($ownProfileErrors['first_name']) ?></div><?php endif; ?>
              </div>
              <div class="form-field">
                <label>Middle Name</label>
                <input type="text" name="middle_name" value="<?= h($ownProfileValues['middle_name'] ?? $myAccount['middle_name']) ?>">
                <?php if (!empty($ownProfileErrors['middle_name'])): ?><div class="err"><?= h($ownProfileErrors['middle_name']) ?></div><?php endif; ?>
              </div>
              <div class="form-field">
                <label>Last Name</label>
                <input type="text" name="last_name" value="<?= h($ownProfileValues['last_name'] ?? $myAccount['last_name']) ?>">
                <?php if (!empty($ownProfileErrors['last_name'])): ?><div class="err"><?= h($ownProfileErrors['last_name']) ?></div><?php endif; ?>
              </div>
              <div class="form-field">
                <label>Extension</label>
                <input type="text" name="extension" value="<?= h($ownProfileValues['extension'] ?? $myAccount['extension']) ?>">
                <?php if (!empty($ownProfileErrors['extension'])): ?><div class="err"><?= h($ownProfileErrors['extension']) ?></div><?php endif; ?>
              </div>
              <div class="form-field">
                <label>Sex</label>
                <select name="sex">
                  <option value="">-- Select --</option>
                  <option value="Male" <?= ($ownProfileValues['sex'] ?? $myAccount['sex']) === 'Male' ? 'selected' : '' ?>>Male</option>
                  <option value="Female" <?= ($ownProfileValues['sex'] ?? $myAccount['sex']) === 'Female' ? 'selected' : '' ?>>Female</option>
                </select>
                <?php if (!empty($ownProfileErrors['sex'])): ?><div class="err"><?= h($ownProfileErrors['sex']) ?></div><?php endif; ?>
              </div>
              <div class="form-field">
                <label>Birthdate</label>
                <input type="date" name="birthdate" value="<?= h($ownProfileValues['birthdate'] ?? $myAccount['birthdate']) ?>">
                <?php if (!empty($ownProfileErrors['birthdate'])): ?><div class="err"><?= h($ownProfileErrors['birthdate']) ?></div><?php endif; ?>
              </div>
              <div class="form-field">
                <label>Street/Purok</label>
                <input type="text" name="street" value="<?= h($ownProfileValues['street'] ?? $myAccount['street']) ?>">
                <?php if (!empty($ownProfileErrors['street'])): ?><div class="err"><?= h($ownProfileErrors['street']) ?></div><?php endif; ?>
              </div>
              <div class="form-field">
                <label>Barangay</label>
                <input type="text" name="barangay" value="<?= h($ownProfileValues['barangay'] ?? $myAccount['barangay']) ?>">
                <?php if (!empty($ownProfileErrors['barangay'])): ?><div class="err"><?= h($ownProfileErrors['barangay']) ?></div><?php endif; ?>
              </div>
              <div class="form-field">
                <label>City</label>
                <input type="text" name="city" value="<?= h($ownProfileValues['city'] ?? $myAccount['city']) ?>">
                <?php if (!empty($ownProfileErrors['city'])): ?><div class="err"><?= h($ownProfileErrors['city']) ?></div><?php endif; ?>
              </div>
              <div class="form-field">
                <label>Province</label>
                <input type="text" name="province" value="<?= h($ownProfileValues['province'] ?? $myAccount['province']) ?>">
                <?php if (!empty($ownProfileErrors['province'])): ?><div class="err"><?= h($ownProfileErrors['province']) ?></div><?php endif; ?>
              </div>
              <div class="form-field">
                <label>Region</label>
                <select name="region">
                  <option value="">-- Select Region --</option>
                  <?php foreach (REGION_OPTIONS as $regionOpt): ?>
                    <option value="<?= h($regionOpt) ?>" <?= ($ownProfileValues['region'] ?? $myAccount['region']) === $regionOpt ? 'selected' : '' ?>><?= h($regionOpt) ?></option>
                  <?php endforeach; ?>
                </select>
                <?php if (!empty($ownProfileErrors['region'])): ?><div class="err"><?= h($ownProfileErrors['region']) ?></div><?php endif; ?>
              </div>
              <div class="form-field">
                <label>Zip</label>
                <input type="text" name="zip" value="<?= h($ownProfileValues['zip'] ?? $myAccount['zip_code']) ?>">
                <?php if (!empty($ownProfileErrors['zip'])): ?><div class="err"><?= h($ownProfileErrors['zip']) ?></div><?php endif; ?>
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn-ghost" data-bs-dismiss="modal">Cancel</button>
            <button type="submit" class="btn-primary">Save Changes</button>
          </div>
        </form>
      </div>
    </div>
  </div>

  <!-- CHANGE USERNAME (self-service, My Profile) — always "my own account",
       rendered straight from $myAccount. Requires the acting Admin's current
       password, collected via the shared #pwConfirmModal, same as
       superadmin_dashboard.php's own copy. -->
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

  <!-- CHANGE PASSWORD (self-service, My Profile) — same password-confirm
       pattern as Change Username above. -->
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
  <?php endif; ?>

  <!-- PENDING REGISTRATIONS -->
  <?php if ($view === 'pending'): ?>
  <div class="console-header">
    <div class="console-title"><div><h1>Pending Registrations</h1></div></div>
  </div>
  <p class="module-desc"><i class="bi bi-info-circle-fill"></i> New Instructor/User sign-ups waiting on a decision. Approve, reject, or block — each action needs the Registration Management permission and is recorded in your activity log.</p>
  <div class="panel">
    <div class="panel__body">
      <?php if ($pending->num_rows === 0): ?>
        <p class="panel__empty">No pending registrations.</p>
      <?php else: ?>
        <div class="table-scroll">
        <table class="console-table">
          <thead><tr><th>Employee ID</th><th>Name</th><th>Username</th><th>Registered</th><th>Actions</th></tr></thead>
          <tbody>
          <?php while ($row = $pending->fetch_assoc()): ?>
            <tr>
              <td><?= h($row['id_number']) ?></td>
              <td><?= h(trim("{$row['first_name']} {$row['middle_name']} {$row['last_name']}")) ?></td>
              <td><?= h($row['username']) ?></td>
              <td><?= h($row['created_at']) ?></td>
              <td class="row-actions">
                <?php if ($canApproveRegistration || $canRejectRegistration || $canBlockRegistration): ?>
                <div class="dropdown">
                  <button type="button" class="btn-sm btn-edit dropdown-toggle" data-bs-toggle="dropdown" data-bs-boundary="viewport" aria-expanded="false">
                    Manage
                  </button>
                  <ul class="dropdown-menu dropdown-menu-end">
                    <?php if ($canApproveRegistration): ?>
                    <li>
                      <form method="post">
                        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="id_number" value="<?= h($row['id_number']) ?>">
                        <input type="hidden" name="action" value="approve">
                        <button type="submit" class="dropdown-item">Approve</button>
                      </form>
                    </li>
                    <?php endif; ?>
                    <?php if ($canRejectRegistration): ?>
                    <li>
                      <form method="post" data-confirm="Reject this registration?">
                        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="id_number" value="<?= h($row['id_number']) ?>">
                        <input type="hidden" name="action" value="reject_registration">
                        <button type="submit" class="dropdown-item">Reject</button>
                      </form>
                    </li>
                    <?php endif; ?>
                    <?php if ($canBlockRegistration): ?>
                    <?php if ($canApproveRegistration || $canRejectRegistration): ?><li><hr class="dropdown-divider"></li><?php endif; ?>
                    <li>
                      <form method="post" data-confirm="Block this registration instead of approving it?">
                        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="id_number" value="<?= h($row['id_number']) ?>">
                        <input type="hidden" name="action" value="block_registration">
                        <button type="submit" class="dropdown-item">Block</button>
                      </form>
                    </li>
                    <?php endif; ?>
                  </ul>
                </div>
                <?php else: ?>
                  <span class="panel__empty" style="padding:0;">View only</span>
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

  <?php if ($view === 'accounts'): ?>
  <div class="console-header">
    <div class="console-title"><div><h1>Accounts</h1></div></div>
  </div>
  <p class="module-desc"><i class="bi bi-info-circle-fill"></i> Instructor/User and fellow Admin accounts. You can edit a profile or block/unblock access directly — deleting one requires a request the Superadmin must approve.</p>

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
            <label>Employee ID</label>
            <input type="text" value="<?= h($editTarget['id_number']) ?>" readonly>
            <div class="form-text">Assigned at creation — not editable.</div>
          </div>
          <div class="form-field">
            <label>Username</label>
            <input type="text" name="username" value="<?= h($editValues['username'] ?? $editTarget['username']) ?>" minlength="5" maxlength="30">
            <div class="form-text">Must start with a letter and include at least one uppercase letter, one number, and one special character (_ or .).</div>
            <?php if (!empty($editErrors['username'])): ?><div class="err"><?= h($editErrors['username']) ?></div><?php endif; ?>
          </div>
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
            <input type="email" value="<?= h($editTarget['email']) ?>" readonly>
            <div class="form-text">Fixed at creation — not editable.</div>
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
       requested it) — never shown for your own row. -->
  <?php if ($editTarget['id_number'] !== $myIdNumber): ?>
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
    <div class="panel__body">
      <form method="get" class="filter-bar">
        <input type="hidden" name="view" value="accounts">
        <input type="text" name="q" placeholder="Filter by Employee ID (e.g. INR-2026-0001)" value="<?= h($search) ?>">
        <button type="submit" class="btn-sm btn-edit">Search</button>
        <?php if ($search !== ''): ?><a href="?view=accounts" class="btn-sm btn-ghost">Clear</a><?php endif; ?>
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
              <td><span class="pill role-<?= h($row['role']) ?>"><?= h(ucfirst($row['role'])) ?></span></td>
              <td><span class="pill <?= h($row['status']) ?>"><?= h(ucfirst($row['status'])) ?></span></td>
              <td>
                <span class="activity-indicator <?= is_account_active($row['seconds_since_activity']) ? 'is-active' : '' ?>">
                  <span class="activity-indicator__dot"></span><?= h(format_last_seen($row['seconds_since_activity'])) ?>
                </span>
              </td>
              <td class="row-actions">
                <div class="dropdown">
                  <button type="button" class="btn-sm btn-edit dropdown-toggle" data-bs-toggle="dropdown" data-bs-boundary="viewport" aria-expanded="false">
                    Manage
                  </button>
                  <ul class="dropdown-menu dropdown-menu-end">
                    <?php if ($canEditUserInfo): ?>
                    <li><a class="dropdown-item" href="?view=accounts&amp;action=edit&amp;id=<?= urlencode($row['id_number']) ?>">Edit</a></li>
                    <?php endif; ?>
                    <?php if (!$isSelf): ?>
                      <?php $rowTargetName = trim("{$row['first_name']} {$row['middle_name']} {$row['last_name']}") ?: $row['username']; ?>
                      <li>
                        <?php if ($row['status'] === 'approved'): ?>
                          <button type="button" class="dropdown-item" data-bs-toggle="modal" data-bs-target="#blockAccountModal"
                                  data-id="<?= h($row['id_number']) ?>" data-name="<?= h($rowTargetName) ?>">
                            Block
                          </button>
                        <?php else: ?>
                          <button type="button" class="dropdown-item" data-bs-toggle="modal" data-bs-target="#unblockAccountModal"
                                  data-id="<?= h($row['id_number']) ?>" data-name="<?= h($rowTargetName) ?>">
                            Unblock
                          </button>
                        <?php endif; ?>
                      </li>
                      <li><hr class="dropdown-divider"></li>
                      <li>
                        <button type="button" class="dropdown-item text-danger" data-bs-toggle="modal" data-bs-target="#deleteRequestModal"
                                data-id="<?= h($row['id_number']) ?>"
                                data-name="<?= h(trim("{$row['first_name']} {$row['last_name']}") . " ({$row['username']})") ?>">
                          Request Delete
                        </button>
                      </li>
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

  <!-- CREATE ACCOUNT (delegated Superadmin module, Admin role only) -->
  <?php if ($view === 'create_account'): ?>
  <div class="console-header">
    <div class="console-title"><div><h1>Create Account</h1></div></div>
  </div>
  <p class="module-desc"><i class="bi bi-info-circle-fill"></i> A Superadmin-only module, delegable to Admins. Only a login identity and email are set here — the new Admin fills in their own profile on first login. This can only ever create an Admin account, never a Superadmin.</p>
  <?php if (!$canCreateAccount): ?>
    <div class="panel access-denied">
      <div class="panel__body">
        <i class="bi bi-lock-fill"></i>
        <h3>Access Denied</h3>
        <p>You do not have permission to access this module. Ask your Superadmin to grant you access under Admin Privileges.</p>
      </div>
    </div>
  <?php else: ?>
  <?php if (($caLockRemaining = create_account_rate_limit_status()) > 0): ?>
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
            <input type="text" value="Admin" readonly>
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
            <label>Password</label>
            <input type="text" value="<?= h(DEFAULT_STAFF_PASSWORD) ?>" readonly>
          </div>
        </div>
        <div class="form-field" style="margin-top:14px; max-width:340px;">
          <label>Enter YOUR password to confirm <span style="color:var(--danger);">*</span></label>
          <input type="password" name="current_password" autocomplete="current-password" required>
        </div>
        <p class="panel__empty" style="margin-top:14px;"><i class="bi bi-shield-lock-fill icon-purple"></i> No confidential personal information is collected here. This account must complete its own profile (name, address, birthdate, and a new password) on first login before it can access the dashboard.</p>
        <div class="form-actions">
          <button type="submit" class="btn-primary">Create Account</button>
          <a href="?view=overview" class="btn-ghost">Cancel</a>
        </div>
      </form>
    </div>
  </div>
  <?php endif; ?>
  <?php endif; ?>

  <!-- DELETE REQUESTS (delegated Superadmin module) -->
  <?php if ($view === 'delete_requests'): ?>
  <div class="console-header">
    <div class="console-title"><div><h1>Delete Requests</h1></div></div>
  </div>
  <p class="module-desc"><i class="bi bi-info-circle-fill"></i> A Superadmin-only module, delegable to Admins. Review account-deletion requests submitted by fellow Admins and approve or reject them.</p>
  <?php if (!$canViewDeleteRequests): ?>
    <div class="panel access-denied">
      <div class="panel__body">
        <i class="bi bi-lock-fill"></i>
        <h3>Access Denied</h3>
        <p>You do not have permission to access this module. Ask your Superadmin to grant you access under Admin Privileges.</p>
      </div>
    </div>
  <?php else: ?>
  <div class="panel">
    <div class="panel__header"><h2><i class="bi bi-exclamation-triangle-fill icon-danger"></i> Pending Delete Requests</h2></div>
    <div class="panel__body">
      <?php if ($deleteRequestsQueue->num_rows === 0): ?>
        <p class="panel__empty">No pending delete requests.</p>
      <?php else: ?>
        <div class="table-scroll">
        <table class="console-table">
          <thead><tr><th>Target</th><th>Employee ID</th><th>Requested By</th><th>Reason</th><th>Submitted</th><th>Actions</th></tr></thead>
          <tbody>
          <?php while ($row = $deleteRequestsQueue->fetch_assoc()): ?>
            <tr>
              <td><?= h($row['target_name']) ?> (<?= h($row['target_username']) ?>)</td>
              <td><?= h($row['target_id_number']) ?></td>
              <td><?= h($row['requested_by_username']) ?></td>
              <td style="max-width:280px; white-space:normal;"><?= nl2br(h($row['reason'])) ?></td>
              <td><?= h($row['created_at']) ?></td>
              <td class="row-actions">
                <?php if ($canApproveDeleteRequests || $canRejectDeleteRequests): ?>
                <div class="dropdown">
                  <button type="button" class="btn-sm btn-edit dropdown-toggle" data-bs-toggle="dropdown" data-bs-boundary="viewport" aria-expanded="false">
                    Manage
                  </button>
                  <ul class="dropdown-menu dropdown-menu-end">
                    <?php if ($canRejectDeleteRequests): ?>
                    <li>
                      <form method="post">
                        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="request_id" value="<?= (int)$row['id'] ?>">
                        <input type="hidden" name="action" value="review_delete_request">
                        <input type="hidden" name="decision" value="reject">
                        <button type="submit" class="dropdown-item">Reject</button>
                      </form>
                    </li>
                    <?php endif; ?>
                    <?php if ($canApproveDeleteRequests): ?>
                    <?php if ($canRejectDeleteRequests): ?><li><hr class="dropdown-divider"></li><?php endif; ?>
                    <li>
                      <!-- A delete request can never target a Superadmin — Admins
                           can only request deletion of a user/admin account, and
                           this handler independently refuses a Superadmin target. -->
                      <form method="post" data-confirm="This will permanently delete the account. Continue?">
                        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="request_id" value="<?= (int)$row['id'] ?>">
                        <input type="hidden" name="action" value="review_delete_request">
                        <input type="hidden" name="decision" value="approve">
                        <button type="submit" class="dropdown-item text-danger">Approve &amp; Delete</button>
                      </form>
                    </li>
                    <?php endif; ?>
                  </ul>
                </div>
                <?php else: ?>
                  <span class="panel__empty" style="padding:0;">View only</span>
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
  <?php endif; ?>

  <!-- ACTIVITY LOGS — this Admin's own actions (registration decisions,
       account creation, edits) plus 'user'-role security/OTP events they may
       need for helpdesk purposes. Other Admins' and Superadmin's own
       permission grants and security events stay out of scope — see
       get_activity_log_entries()'s admin_scope filter in include/permissions.php. -->
  <?php if ($view === 'activity_logs'):
    $alSource = $_GET['source'] ?? 'all';
    if (!in_array($alSource, ['all', 'recent', 'registration', 'permission', 'otp'], true)) {
        $alSource = 'all';
    }
    $alSearch = trim((string)($_GET['q'] ?? ''));
    $alDateFrom = trim((string)($_GET['from'] ?? ''));
    $alDateTo = trim((string)($_GET['to'] ?? ''));
    $alPage = max(1, (int)($_GET['page'] ?? 1));

    $alQueryDateFrom = $alDateFrom;
    if ($alSource === 'recent' && $alQueryDateFrom === '') {
        $alQueryDateFrom = $conn->query("SELECT DATE_SUB(CURDATE(), INTERVAL 7 DAY) AS d")->fetch_assoc()['d'];
    }

    $activityLog = get_activity_log_entries($conn, [
        'source' => $alSource,
        'search' => $alSearch,
        'date_from' => $alQueryDateFrom,
        'date_to' => $alDateTo,
        'admin_scope' => $_SESSION['username'],
    ], $alPage, 25);

    $alFilterQuery = 'source=' . urlencode($alSource)
        . ($alSearch !== '' ? '&q=' . urlencode($alSearch) : '')
        . ($alDateFrom !== '' ? '&from=' . urlencode($alDateFrom) : '')
        . ($alDateTo !== '' ? '&to=' . urlencode($alDateTo) : '');
  ?>
  <div class="console-header">
    <div class="console-title"><div><h1>Activity Logs</h1></div></div>
  </div>
  <p class="module-desc"><i class="bi bi-info-circle-fill"></i> Your own account-management actions, plus Instructor/User security events (OTP, password resets). Other staff accounts' activity is not shown here.</p>

  <div class="panel">
    <div class="panel__header"><h2><i class="bi bi-clock-history icon-info"></i> My Activity</h2></div>
    <div class="panel__body">
      <div class="role-filter-tabs">
        <?php $alTabSuffix = ($alSearch !== '' ? '&q=' . urlencode($alSearch) : '') . ($alDateFrom !== '' ? '&from=' . urlencode($alDateFrom) : '') . ($alDateTo !== '' ? '&to=' . urlencode($alDateTo) : ''); ?>
        <a href="?view=activity_logs&amp;source=all<?= $alTabSuffix ?>" class="role-filter-tab <?= $alSource === 'all' ? 'active' : '' ?>">All</a>
        <a href="?view=activity_logs&amp;source=recent<?= $alTabSuffix ?>" class="role-filter-tab <?= $alSource === 'recent' ? 'active' : '' ?>" title="Last 7 days">Recent</a>
        <a href="?view=activity_logs&amp;source=registration<?= $alTabSuffix ?>" class="role-filter-tab <?= $alSource === 'registration' ? 'active' : '' ?>">Registration</a>
        <a href="?view=activity_logs&amp;source=permission<?= $alTabSuffix ?>" class="role-filter-tab <?= $alSource === 'permission' ? 'active' : '' ?>">Permission</a>
        <a href="?view=activity_logs&amp;source=otp<?= $alTabSuffix ?>" class="role-filter-tab <?= $alSource === 'otp' ? 'active' : '' ?>">OTP / Security</a>
      </div>

      <form method="get" class="filter-bar">
        <input type="hidden" name="view" value="activity_logs">
        <input type="hidden" name="source" value="<?= h($alSource) ?>">
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

  </div><!-- /.console-wrap -->
  </main>
</div><!-- /.app-shell -->

<!-- PASSWORD CONFIRMATION — the single shared modal every sensitive
     self-service action on this page funnels through (currently: Edit
     Profile). Entering your own current password is always this one
     dedicated modal, not a field embedded inside whichever action's own
     modal — submitting that action's form hides it (if it's a modal) and
     opens this one instead (see js/admin_console.js's
     requirePasswordConfirm()); confirming here copies the typed password
     into the originating form's hidden current_password field and
     resubmits it for real. Same shared modal/JS as superadmin_dashboard.php. -->
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

<!-- DELETE REQUEST MODAL — shared by every row's "Request Delete" button -->
<div class="modal fade" id="deleteRequestModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <form method="post" id="deleteRequestForm">
        <div class="modal-header">
          <h5 class="modal-title"><i class="bi bi-exclamation-triangle-fill icon-danger"></i> Request Account Deletion</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
          <input type="hidden" name="action" value="request_delete">
          <input type="hidden" name="id_number" id="deleteRequestId">
          <p style="margin:0 0 16px; color:var(--ink-muted); font-size:0.88rem;">
            You are requesting deletion of <strong id="deleteRequestTarget" style="color:var(--ink);"></strong>.
            This is sent to the Superadmin for review — the account is <u>not</u> deleted immediately.
          </p>
          <div class="form-field">
            <label for="deleteRequestReason">Reason for deletion <span style="color:var(--danger);">*</span></label>
            <textarea name="reason" id="deleteRequestReason" rows="4" maxlength="500" minlength="5" required
                      placeholder="Explain why this account should be deleted (visible to the Superadmin)..."></textarea>
            <div class="form-text" id="deleteRequestCount">0 / 500 characters</div>
          </div>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn-ghost" data-bs-dismiss="modal">Cancel</button>
          <button type="submit" class="btn-sm btn-danger">Submit Request</button>
        </div>
      </form>
    </div>
  </div>
</div>

<!-- BLOCK ACCOUNT MODAL — shared by every row's "Block" button. Same modal
     ID/field IDs as superadmin_dashboard.php's copy so the shared
     js/admin_console.js wiring works unchanged here too; no password field
     (that confirmation is Superadmin-only), just a required reason. -->
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
        </div>
        <div class="modal-footer">
          <button type="button" class="btn-ghost" data-bs-dismiss="modal">Cancel</button>
          <button type="submit" class="btn-sm btn-danger">Block Account</button>
        </div>
      </form>
    </div>
  </div>
</div>

<!-- UNBLOCK ACCOUNT MODAL — shared by every row's "Unblock" button. Same
     shared IDs/JS wiring as above. -->
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

<script>
  window.REOPEN_EDIT_PROFILE_MODAL = <?= json_encode($ownProfileValues !== null) ?>;
  window.REOPEN_CHANGE_USERNAME_MODAL = <?= json_encode($reopenChangeUsernameModal) ?>;
  window.REOPEN_CHANGE_PASSWORD_MODAL = <?= json_encode($reopenChangePasswordModal) ?>;
</script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="js/admin_console.js"></script>
<script src="js/create_account_validate.js"></script>
</body>
</html>
