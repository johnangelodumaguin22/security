<?php
// Hardcoded "break-glass" recovery Superadmin account. Lives ENTIRELY in
// this file — there is no row for it in the `users` table — so it keeps
// working even if the database is wiped, restored from an old backup, or
// every real Superadmin account is ever locked out/deleted.
//
// Copy this file to default_superadmin.php (same folder) and set a real
// username/password — default_superadmin.php itself is gitignored and must
// never be committed. The password is compared as a PLAIN STRING (see
// auth_guard.php's verify_login_password()), never hashed, so editing this
// file is the entire process — no separate re-hash script to run.
return [
    // Deliberately outside the normal "INR-<year>-<seq>" format that
    // generateNextId() produces, so a real registration/account-creation can
    // never collide with it.
    'id_number'  => 'INR-0000-9999',
    'username'   => 'change-me',
    'password'   => 'change-me-too', // plaintext by design — see note above
    'first_name' => 'System',
    'last_name'  => 'Recovery',
    'middle_name' => '',
    'extension'  => '',
    'email'      => null,
    'role'       => 'superadmin',
    'status'     => 'approved',
    'profile_status' => 'complete',
    'profile_picture' => null,
    'created_at' => 'N/A',
    // Non-empty so require_role()'s "set your security questions" gate
    // never triggers for this account — it has no security-question flow
    // (Forgot Password can't look it up either, since it's not in `users`).
    'question1' => 'n/a',
];
