<?php
// Shared OTP system: 6-digit codes for email verification (post-registration
// / first login of any role) and for the email-based password-reset flow.
// Codes are always stored hashed (password_hash), never plaintext, and are
// single-use, time-limited, and attempt-limited.

const OTP_TTL_SECONDS = 300;          // 5 minutes
const OTP_MAX_ATTEMPTS = 5;
const OTP_RESEND_COOLDOWN_SECONDS = 60;
const OTP_RATE_LIMIT_WINDOW_SECONDS = 1800; // 30 minutes
const OTP_RATE_LIMIT_MAX_REQUESTS = 5;

function generate_otp() {
    return str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
}

function hash_otp($otp) {
    return password_hash($otp, PASSWORD_DEFAULT);
}

function otp_matches($otp, $hash) {
    return password_verify($otp, $hash);
}

// send_otp_email() lives in its own dedicated file, include/mail_otp.php —
// kept separate from include/mail_approval.php's send_approval_email() so
// neither email path can ever be triggered by the other's code.
require_once __DIR__ . '/mail_otp.php';

function log_otp_action($conn, $idNumber, $email, $action, $role = null) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? null;
    $stmt = $conn->prepare("INSERT INTO otp_audit_log (id_number, email, action, role, ip_address) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("sssss", $idNumber, $email, $action, $role, $ip);
    $stmt->execute();
    $stmt->close();
}

// Returns ['ok' => true] on success, or ['ok' => false, 'error' => 'cooldown'|'rate_limited', 'retry_after' => seconds] on failure.
function create_otp($conn, $idNumber, $email, $purpose, $role = null) {
    $stmt = $conn->prepare("SELECT created_at, TIMESTAMPDIFF(SECOND, created_at, NOW()) AS age
                             FROM otp_verifications WHERE id_number = ? AND purpose = ?
                             ORDER BY created_at DESC LIMIT 1");
    $stmt->bind_param("ss", $idNumber, $purpose);
    $stmt->execute();
    $last = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if ($last && (int)$last['age'] < OTP_RESEND_COOLDOWN_SECONDS) {
        return ['ok' => false, 'error' => 'cooldown', 'retry_after' => OTP_RESEND_COOLDOWN_SECONDS - (int)$last['age']];
    }

    $stmt = $conn->prepare("SELECT COUNT(*) c FROM otp_verifications
                             WHERE id_number = ? AND purpose = ? AND created_at > (NOW() - INTERVAL " . (int)OTP_RATE_LIMIT_WINDOW_SECONDS . " SECOND)");
    $stmt->bind_param("ss", $idNumber, $purpose);
    $stmt->execute();
    $count = (int)$stmt->get_result()->fetch_assoc()['c'];
    $stmt->close();

    if ($count >= OTP_RATE_LIMIT_MAX_REQUESTS) {
        return ['ok' => false, 'error' => 'rate_limited'];
    }

    // Only the latest OTP for this (id_number, purpose) is ever valid.
    $inv = $conn->prepare("UPDATE otp_verifications SET used_at = NOW() WHERE id_number = ? AND purpose = ? AND used_at IS NULL");
    $inv->bind_param("ss", $idNumber, $purpose);
    $inv->execute();
    $inv->close();

    $otp = generate_otp();
    $hash = hash_otp($otp);
    $ip = $_SERVER['REMOTE_ADDR'] ?? null;
    $ins = $conn->prepare("INSERT INTO otp_verifications (id_number, email, otp_hash, purpose, expires_at, requested_ip)
                            VALUES (?, ?, ?, ?, NOW() + INTERVAL " . (int)OTP_TTL_SECONDS . " SECOND, ?)");
    $ins->bind_param("sssss", $idNumber, $email, $hash, $purpose, $ip);
    $ins->execute();
    $ins->close();

    send_otp_email($email, $otp, $purpose);
    log_otp_action($conn, $idNumber, $email, $last ? 'OTP_RESENT' : 'OTP_REQUESTED', $role);

    return ['ok' => true];
}

// Returns ['ok' => true] or ['ok' => false, 'error' => 'invalid'|'locked', 'attempts_left' => n]
function verify_otp($conn, $idNumber, $purpose, $submittedOtp, $email = null, $role = null) {
    // Expiry is computed in SQL (expires_at < NOW()), never via PHP's
    // strtotime()/time() against a MySQL timestamp string — this server's
    // PHP date.timezone and MySQL's own (OS-following) timezone are
    // configured independently, so comparing them in PHP silently skews
    // the result by however many hours the two clocks disagree by.
    $stmt = $conn->prepare("SELECT *, (expires_at < NOW()) AS is_expired FROM otp_verifications
                             WHERE id_number = ? AND purpose = ? AND used_at IS NULL
                             ORDER BY created_at DESC LIMIT 1");
    $stmt->bind_param("ss", $idNumber, $purpose);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    $email = $email ?? ($row['email'] ?? '');

    if (!$row || (int)$row['is_expired'] === 1) {
        log_otp_action($conn, $idNumber, $email, 'OTP_EXPIRED', $role);
        return ['ok' => false, 'error' => 'invalid'];
    }

    if ((int)$row['attempts'] >= (int)$row['max_attempts']) {
        $upd = $conn->prepare("UPDATE otp_verifications SET used_at = NOW() WHERE id = ?");
        $upd->bind_param("i", $row['id']);
        $upd->execute();
        log_otp_action($conn, $idNumber, $email, 'OTP_FAILED', $role);
        return ['ok' => false, 'error' => 'locked'];
    }

    if (!otp_matches($submittedOtp, $row['otp_hash'])) {
        $newAttempts = (int)$row['attempts'] + 1;
        if ($newAttempts >= (int)$row['max_attempts']) {
            $upd = $conn->prepare("UPDATE otp_verifications SET attempts = ?, used_at = NOW() WHERE id = ?");
        } else {
            $upd = $conn->prepare("UPDATE otp_verifications SET attempts = ? WHERE id = ?");
        }
        $upd->bind_param("ii", $newAttempts, $row['id']);
        $upd->execute();
        log_otp_action($conn, $idNumber, $email, 'OTP_FAILED', $role);
        return ['ok' => false, 'error' => $newAttempts >= (int)$row['max_attempts'] ? 'locked' : 'invalid', 'attempts_left' => max(0, (int)$row['max_attempts'] - $newAttempts)];
    }

    $upd = $conn->prepare("UPDATE otp_verifications SET used_at = NOW(), verified_at = NOW() WHERE id = ?");
    $upd->bind_param("i", $row['id']);
    $upd->execute();
    log_otp_action($conn, $idNumber, $email, 'OTP_VERIFIED', $role);

    return ['ok' => true];
}
