<?php
// SMTP credentials for sending real OTP/notification emails.
// Copy this file to mail_config.php (same folder) and fill in real values —
// mail_config.php itself is gitignored and must never be committed.
//
// For Gmail: use an App Password (not your normal account password) —
// https://myaccount.google.com/apppasswords — Gmail requires 2-Step
// Verification to be enabled first.
return [
    'host' => 'smtp.gmail.com',
    'port' => 587,
    'encryption' => 'tls',
    'username' => 'your-address@example.com',
    'password' => 'your-app-password',
    'from_email' => 'your-address@example.com',
    'from_name' => 'CSU Instructor Registration and Management',
];
