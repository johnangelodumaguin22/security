<?php
// Sends ONLY the account-approval notification. Deliberately self-contained
// (its own PHPMailer setup, no shared sender function) and does not include,
// reference, or call anything from include/mail_otp.php — approving an
// account must never be able to trigger an OTP email, and vice versa.
require_once __DIR__ . '/phpmailer/Exception.php';
require_once __DIR__ . '/phpmailer/PHPMailer.php';
require_once __DIR__ . '/phpmailer/SMTP.php';

// Sent when a Superadmin/Admin approves a pending public registration.
function send_approval_email($email, $firstName) {
    $config = require __DIR__ . '/mail_config.php';
    $subject = 'Your Account Has Been Approved — CSU Instructor Registration and Management';
    $greetingName = $firstName !== '' ? $firstName : 'Instructor';
    $body = "Hi {$greetingName},\n\n"
          . "Good news — your registration has been reviewed and your account is now approved.\n\n"
          . "You can log in now using the username and password you registered with.\n\n"
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
        // Never block the approval itself on a delivery failure — just log
        // it, outside the webroot, to its own approval-only error log.
        $errorPath = dirname(__DIR__, 3) . '/approval_mail_errors.log';
        file_put_contents($errorPath, sprintf("[%s] SEND FAILED to=%s error=%s\n", date('Y-m-d H:i:s'), $email, $mail->ErrorInfo), FILE_APPEND | LOCK_EX);
        return false;
    }
}
