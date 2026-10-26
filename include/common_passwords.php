<?php
// Shared safety-net blacklist for any password-creation flow (registration,
// password reset). Deliberately small and literal — this is a backstop
// against the most obvious weak passwords, not a complexity policy.
if (!defined('COMMON_WEAK_PASSWORDS')) {
    define('COMMON_WEAK_PASSWORDS', [
        'password', 'password1', 'password123', '12345678', '123456789', '1234567890',
        'qwerty123', 'qwertyuiop', 'letmein123', 'iloveyou123', 'admin1234', 'welcome123',
        'changeme123', '00000000', '11111111', 'abc123456', 'passw0rd', 'p@ssw0rd123',
        'trustno1', 'football123', 'baseball123', 'dragon1234', 'monkey1234', 'master1234',
    ]);
}

function isCommonWeakPassword($pwd) {
    return in_array(strtolower($pwd), COMMON_WEAK_PASSWORDS, true);
}
