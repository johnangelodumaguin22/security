// Client-side hardening for the Superadmin "Create Admin/Superadmin Account"
// form. Mirrors the email/username rules enforced server-side by
// validateBareAccountCreation() in include/registration_helpers.php, and the
// password composition rules enforced inline in superadmin_dashboard.php's
// create_account handler (that check lives there, not in the shared
// validateBareAccountCreation(), because admin_dashboard.php's own Create
// Account still uses its own fixed default password and has no password
// field at all — these password validators simply no-op there since
// field('password') is null on that page).
// Scoped to #registerForm specifically (via form.elements) so it can never
// touch the separate "Edit Account" form that shares some of the same
// field names on this same page.
document.addEventListener('contextmenu', e => e.preventDefault());

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('registerForm');
  if (!form) return;

  // -----------------------------
  // Shared error box helpers (scoped to this form's fields only)
  // -----------------------------
  function getErrorBox(name, input) {
    const id = `${name}_ca_error`;
    let box = document.getElementById(id);
    if (box) return box;
    box = document.createElement('div');
    box.id = id;
    box.className = 'err';
    input.insertAdjacentElement('afterend', box);
    return box;
  }

  function showError(name, input, message) {
    const box = getErrorBox(name, input);
    box.textContent = message;
    box.style.display = 'block';
    input.classList.add('is-invalid');
    input.classList.remove('is-valid');
  }

  function clearError(name, input) {
    const box = getErrorBox(name, input);
    box.textContent = '';
    box.style.display = 'none';
    input.classList.remove('is-invalid');
    input.classList.add('is-valid');
  }

  function field(name) {
    return form.elements[name] || null;
  }

  // -----------------------------
  // Email
  // -----------------------------
  const EMAIL_DOMAIN = 'csucc.edu.ph';

  function validateEmail() {
    const input = field('email');
    if (!input) return true;
    const value = input.value;
    if (!value) { showError('email', input, '❌ Email is required.'); return false; }
    if (/^\s|\s$/.test(value)) { showError('email', input, '❌ Email cannot have leading, trailing, or repeated spaces.'); return false; }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) { showError('email', input, '❌ Please enter a valid email address.'); return false; }
    if (!value.toLowerCase().endsWith('@' + EMAIL_DOMAIN)) { showError('email', input, `❌ Email must be a valid @${EMAIL_DOMAIN} address.`); return false; }
    clearError('email', input);

    fetch('../include/check_email.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'email=' + encodeURIComponent(value)
    }).then(res => res.json()).then(data => {
      if (data.exists) showError('email', input, data.message || '❌ Email already registered.');
    }).catch(() => {});

    return true;
  }

  // -----------------------------
  // Username
  // -----------------------------
  function validateUsername() {
    const input = field('username');
    if (!input) return true;
    const value = input.value;
    if (!value) { showError('username', input, '❌ Username is required.'); return false; }
    // Spaces are not allowed anywhere — checked on the raw value (not
    // trimmed) so a space is caught and rejected, not silently stripped.
    if (/\s/.test(value)) { showError('username', input, '❌ Username: Spaces are not allowed.'); return false; }
    // Structural rules split out and ordered most-specific-first — a stray
    // symbol is named directly instead of surfacing as a generic length/format
    // message.
    if (/[^A-Za-z0-9_.]/.test(value)) {
      showError('username', input, '❌ Username: Special characters are not allowed.');
      return false;
    }
    if (!/^[A-Za-z]/.test(value)) {
      showError('username', input, '❌ Username must start with a letter.');
      return false;
    }
    if (value.length < 5 || value.length > 30) {
      showError('username', input, '❌ Username must be between 5 and 30 characters.');
      return false;
    }
    if (!/[A-Z]/.test(value)) {
      showError('username', input, '❌ Username must contain at least one uppercase letter.');
      return false;
    }
    if (!/[0-9]/.test(value)) {
      showError('username', input, '❌ Username must contain at least one number.');
      return false;
    }
    if (!/[_.]/.test(value)) {
      showError('username', input, '❌ Username must contain at least one special character (_ or .).');
      return false;
    }
    clearError('username', input);

    fetch('../include/check_username.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'username=' + encodeURIComponent(value)
    }).then(res => res.json()).then(data => {
      if (data.exists) showError('username', input, data.message || '❌ Username already exists.');
    }).catch(() => {});

    return true;
  }

  // -----------------------------
  // Password / Re-enter Password
  // -----------------------------
  const COMMON_WEAK_PASSWORDS = ['password', '12345678', 'qwerty123', 'password123', 'admin123', 'letmein1'];

  function validatePassword() {
    const input = field('password');
    if (!input) return true;
    const value = input.value;
    const usernameVal = (field('username') && field('username').value) || '';
    if (!value) { showError('password', input, '❌ Password is required.'); return false; }
    if (/^\s|\s$/.test(value)) { showError('password', input, '❌ Password cannot have leading or trailing spaces.'); return false; }
    if (value.length < 8 || value.length > 72) { showError('password', input, '❌ Password must be between 8 and 72 characters.'); return false; }
    if (!/[A-Z]/.test(value)) { showError('password', input, '❌ Password must contain at least one uppercase letter.'); return false; }
    if (!/[a-z]/.test(value)) { showError('password', input, '❌ Password must contain at least one lowercase letter.'); return false; }
    if (!/[0-9]/.test(value)) { showError('password', input, '❌ Password must contain at least one number.'); return false; }
    if (!/[!@#$%^&*()_\-+=?]/.test(value)) { showError('password', input, '❌ Password must contain at least one special character (! @ # $ % ^ & * ( ) _ - + = ?).'); return false; }
    if (COMMON_WEAK_PASSWORDS.includes(value.toLowerCase())) { showError('password', input, '❌ This password is too common. Please choose a stronger one.'); return false; }
    if (usernameVal && value.toLowerCase().includes(usernameVal.toLowerCase())) { showError('password', input, '❌ Password must not contain the username.'); return false; }
    clearError('password', input);
    return true;
  }

  function validateRepassword() {
    const input = field('repassword');
    if (!input) return true;
    const pwInput = field('password');
    const value = input.value;
    if (!value) { showError('repassword', input, '❌ Please re-enter the password.'); return false; }
    if (pwInput && value !== pwInput.value) { showError('repassword', input, '❌ Passwords do not match.'); return false; }
    clearError('repassword', input);
    return true;
  }

  // -----------------------------
  // Wire up live validation
  // -----------------------------
  const liveChecks = [
    ['email', validateEmail],
    ['username', validateUsername],
    ['password', validatePassword],
    ['repassword', validateRepassword],
  ];

  liveChecks.forEach(([name, fn]) => {
    const input = field(name);
    if (!input) return;
    input.addEventListener('input', fn);
    input.addEventListener('blur', fn);
    input.addEventListener('change', fn);
  });

  // Re-check the match as soon as either password field changes, not just
  // whichever one the user is currently typing in.
  const pwField = field('password');
  const repwField = field('repassword');
  if (pwField && repwField) {
    pwField.addEventListener('input', () => { if (repwField.value) validateRepassword(); });
  }

  // -----------------------------
  // Password confirmation — the acting Superadmin's own password is always
  // collected via the single shared "Enter Your Password to Confirm" modal
  // (#pwConfirmModal, wired up in js/admin_console.js — window.
  // openPasswordConfirmModal), never as a field inline on this page. Once
  // every other field here passes validation, submit is intercepted and
  // that shared modal opens; confirming there copies the typed password
  // into this form's hidden current_password field and resubmits it for
  // real (form.dataset.pwConfirmed flag skips re-validation the second time).
  // -----------------------------
  form.addEventListener('submit', (e) => {
    if (form.dataset.pwConfirmed === '1') {
      delete form.dataset.pwConfirmed;
      return;
    }

    const results = liveChecks.map(([name, fn]) => ({ name, ok: fn() }));
    const firstFailed = results.find(r => !r.ok);

    if (firstFailed) {
      e.preventDefault();
      const target = field(firstFailed.name);
      if (target) setTimeout(() => target.focus(), 10);
      return;
    }

    if (typeof window.openPasswordConfirmModal === 'function') {
      e.preventDefault();
      window.openPasswordConfirmModal(form, field('current_password'));
    }
    // Shared modal helper unavailable (shouldn't happen) — let the form
    // submit as-is rather than silently blocking account creation.
  });
});
