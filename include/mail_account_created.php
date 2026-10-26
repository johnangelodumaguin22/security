<?php
// Sends ONLY the "here are your new account credentials" notification.
// Deliberately self-contained, same as include/mail_approval.php — this
// must never be able to trigger or be triggered by an OTP or approval
// email, so it gets its own PHPMailer setup instead of sharing one.
require_once __DIR__ . '/phpmailer/Exception.php';
require_once __DIR__ . '/phpmailer/PHPMailer.php';
require_once __DIR__ . '/phpmailer/SMTP.php';

// Sent once, right after a Superadmin creates a new Admin/Superadmin
// account, so the new account holder learns their username and initial
// password. $rawPassword is the plaintext password set at creation time —
// this is the only place it's ever available outside the submitting
// browser, since it's hashed before being stored.
function send_account_created_email($email, $username, $rawPassword, $role) {
    $config = require __DIR__ . '/mail_config.php';
    $roleLabel = ucfirst($role);
    $subject = "Your {$roleLabel} Account Has Been Created — CSU Instructor Registration and Management";
    $body = "Hi,\n\n"
          . "A {$roleLabel} account has been created for you on the CSU Instructor Registration and Management system.\n\n"
          . "Username: {$username}\n"
          . "Temporary Password: {$rawPassword}\n\n"
          . "Please log in and complete your profile. For your security, change this password as soon as you sign in.\n\n"
          . "If you were not expecting this email or believe this was sent in error, please contact the system administrator.";

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
        // Never block the account creation itself on a delivery failure —
        // just log it, outside the webroot, to its own error log.
        $errorPath = dirname(__DIR__, 3) . '/account_created_mail_errors.log';
        file_put_contents($errorPath, sprintf("[%s] SEND FAILED to=%s error=%s\n", date('Y-m-d H:i:s'), $email, $mail->ErrorInfo), FILE_APPEND | LOCK_EX);
        return false;
    }
}
