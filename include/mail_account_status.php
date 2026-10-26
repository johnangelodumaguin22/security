<?php
// Sends ONLY account status-change notifications (blocked / unblocked /
// deleted). Deliberately self-contained, same as include/mail_approval.php
// and include/mail_account_created.php — this must never be able to trigger
// or be triggered by an OTP, approval, or account-created email, so it gets
// its own PHPMailer setup instead of sharing one.
require_once __DIR__ . '/phpmailer/Exception.php';
require_once __DIR__ . '/phpmailer/PHPMailer.php';
require_once __DIR__ . '/phpmailer/SMTP.php';

// Shared low-level sender for this file's three notifications — kept private
// (not called from outside this file) so every other mailer file still gets
// its own fully independent PHPMailer setup, matching this codebase's
// established one-file-per-notification-family pattern.
function _send_account_status_email($email, $subject, $body) {
    $config = require __DIR__ . '/mail_config.php';
    $mail = new \PHPMailer\PHPMailer\PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host = $config['host'];
        $mail->Port = $config['port'];
        $mail->SMTPAuth = true;
        $mail->Username = $config['username'];
        $mail->Password = $config['password'];
        $mail->SMTPSecure = $config['encryption'];
        // See include/mail_otp.php for why this exists: this machine's
        // antivirus (Norton Web/Mail Shield) intercepts outbound SMTP TLS
        // with its own locally-generated root — Windows trusts it, PHP's
        // separate CA bundle doesn't. This bundle adds that one root on
        // top of the standard CA list; verification itself stays fully on.
        $caBundle = __DIR__ . '/smtp_cacert.pem';
        if (is_file($caBundle)) {
            $mail->SMTPOptions = [
                'ssl' => [
                    'cafile' => $caBundle,
                    'verify_peer' => true,
                    'verify_peer_name' => true,
                    'allow_self_signed' => false,
                ],
            ];
        }
        $mail->setFrom($config['from_email'], $config['from_name']);
        $mail->addAddress($email);
        $mail->isHTML(false);
        $mail->Subject = $subject;
        $mail->Body = $body;
        $mail->send();
        return true;
    } catch (\Exception $e) {
        // Never block the block/unblock/delete action itself on a delivery
        // failure — just log it, outside the webroot, to its own error log.
        $errorPath = dirname(__DIR__, 3) . '/account_status_mail_errors.log';
        file_put_contents($errorPath, sprintf("[%s] SEND FAILED to=%s error=%s\n", date('Y-m-d H:i:s'), $email, $mail->ErrorInfo), FILE_APPEND | LOCK_EX);
        return false;
    }
}

// Sent when a Superadmin/Admin blocks a User/Admin account.
function send_account_blocked_email($email, $firstName, $reason) {
    $greetingName = $firstName !== '' ? $firstName : 'Instructor';
    $subject = 'Your Account Has Been Blocked — CSU Instructor Registration and Management';
    $body = "Hi {$greetingName},\n\n"
          . "Your account on the CSU Instructor Registration and Management system has been blocked. "
          . "You will not be able to log in while your account remains in this state.\n\n"
          . "Reason: {$reason}\n\n"
          . "If you believe this was done in error, please contact the system administrator.";
    return _send_account_status_email($email, $subject, $body);
}

// Sent when a Superadmin/Admin unblocks a previously blocked User/Admin
// account, restoring their access.
function send_account_unblocked_email($email, $firstName, $reason) {
    $greetingName = $firstName !== '' ? $firstName : 'Instructor';
    $subject = 'Your Account Has Been Unblocked — CSU Instructor Registration and Management';
    $body = "Hi {$greetingName},\n\n"
          . "Good news — your account on the CSU Instructor Registration and Management system has been unblocked. "
          . "You can now log in again using your existing username and password.\n\n"
          . "Reason: {$reason}\n\n"
          . "If you were not expecting this email or believe this was sent in error, please contact the system administrator.";
    return _send_account_status_email($email, $subject, $body);
}

// Sent right before a User/Admin account is permanently deleted (whether
// deleted directly by a Superadmin or approved through the delete-request
// queue) — must be called while the row (and its email) still exists.
function send_account_deleted_email($email, $firstName, $reason) {
    $greetingName = $firstName !== '' ? $firstName : 'Instructor';
    $subject = 'Your Account Has Been Deleted — CSU Instructor Registration and Management';
    $body = "Hi {$greetingName},\n\n"
          . "Your account on the CSU Instructor Registration and Management system has been permanently deleted. "
          . "This cannot be undone, and you will no longer be able to log in with these credentials.\n\n"
          . "Reason: {$reason}\n\n"
          . "If you believe this was done in error, please contact the system administrator.";
    return _send_account_status_email($email, $subject, $body);
}
