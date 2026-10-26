<?php
// Sends ONLY one-time-PIN emails (email verification at registration/first
// login, and the email-based password-reset flow). Deliberately
// self-contained (its own PHPMailer setup, no shared sender function) and
// does not include, reference, or call anything from
// include/mail_approval.php — requesting an OTP must never be able to
// trigger an account-approval email, and vice versa.
require_once __DIR__ . '/phpmailer/Exception.php';
require_once __DIR__ . '/phpmailer/PHPMailer.php';
require_once __DIR__ . '/phpmailer/SMTP.php';

// Real delivery via SMTP (PHPMailer), configured from include/mail_config.php.
// Falls back to a local, outside-the-webroot log file if the send fails
// (network/auth issues) so the OTP flow never gets fully blocked and there's
// still a way to retrieve the code for debugging.
function send_otp_email($email, $otp, $purpose) {
    $config = require __DIR__ . '/mail_config.php';
    $subject = 'Your One-Time PIN (OTP)';
    $minutes = (int)(OTP_TTL_SECONDS / 60);
    $purposeLine = match ($purpose) {
        'password_reset' => 'This code was requested to reset your password.',
        'change_username' => 'This code was requested to confirm a username change on your account.',
        'change_password' => 'This code was requested to confirm a password change on your account.',
        default => 'This code was requested to verify your email address.',
    };
    $body = "Your One-Time PIN is:\n\n{$otp}\n\n"
          . "{$purposeLine}\n"
          . "This OTP will expire in {$minutes} minutes.\n\n"
          . "Do not share this code with anyone.\n"
          . "If you did not request this OTP, please ignore this email.";

    $mail = new \PHPMailer\PHPMailer\PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host = $config['host'];
        $mail->Port = $config['port'];
        $mail->SMTPAuth = true;
        $mail->Username = $config['username'];
        $mail->Password = $config['password'];
        $mail->SMTPSecure = $config['encryption'];
        // This machine's antivirus (Norton Web/Mail Shield) intercepts
        // outbound SMTP TLS and re-signs it with its own locally-generated
        // root certificate — Windows trusts it (Norton installed it into
        // the Windows root store), but PHP's separate CA bundle doesn't
        // know about it, so plain verification fails. include/smtp_cacert.pem
        // is the standard CA bundle plus that one locally-trusted root
        // appended; verification itself stays fully on.
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
        $errorPath = dirname(__DIR__, 3) . '/otp_mail_errors.log';
        file_put_contents($errorPath, sprintf("[%s] SEND FAILED to=%s error=%s\n", date('Y-m-d H:i:s'), $email, $mail->ErrorInfo), FILE_APPEND | LOCK_EX);

        // Fallback so the flow still works while SMTP delivery is being fixed —
        // never put the OTP anywhere web-accessible.
        $outboxPath = dirname(__DIR__, 3) . '/otp_dev_outbox.log';
        $line = sprintf("[%s] TO=%s PURPOSE=%s OTP=%s (expires in %d min) [SMTP SEND FAILED, see otp_mail_errors.log]\n", date('Y-m-d H:i:s'), $email, $purpose, $otp, $minutes);
        file_put_contents($outboxPath, $line, FILE_APPEND | LOCK_EX);
        return false;
    }
}
