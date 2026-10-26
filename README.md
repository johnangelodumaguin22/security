# CSU Instructor Registration and Management

A PHP/MySQL registration and account-management system (XAMPP, mysqli
prepared statements, session-based auth) with three roles: User, Admin, and
Superadmin.

## Setup

1. Serve this folder with XAMPP (Apache + MySQL) as `SECURITY/`.
2. Import a database named `security_system` (schema only — no seed dump is
   included in this repo; create your own tables by reviewing `include/*.php`
   for the expected structure, or restore from your own backup).
3. Copy the two example config files and fill in real values:
   - `include/mail_config.example.php` → `include/mail_config.php`
   - `include/default_superadmin.example.php` → `include/default_superadmin.php`
4. Adjust `include/db_connect.php` if your MySQL credentials differ from the
   XAMPP defaults (`root` / no password).

## Notes

- `include/mail_config.php` and `include/default_superadmin.php` are
  gitignored on purpose — they hold live credentials. Never commit real
  values for either.
- `uploads/` holds user-uploaded profile pictures and is gitignored aside
  from a `.gitkeep` placeholder.
