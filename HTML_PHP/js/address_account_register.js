// Address & Account fields (Street, Barangay, City, Province, Region, Zip,
// Email, Username). Error-box helpers and shared casing/character helpers
// live in register_shared.js, loaded before this file.
//
// This file only defines field-level validators + their live/blur wiring.
// The single submit-time validation pass lives in password_register.js.

// -----------------------------
// Live space hygiene: strips a leading space and collapses any run of
// spaces down to one AS THE USER TYPES, so repeatedly pressing Space can
// never produce more than a single space.
// -----------------------------
function attachLiveSpaceCollapse(input) {
  input.addEventListener('input', () => {
    const caret = input.selectionStart;
    const before = input.value;
    const value = before.replace(/^\s+/, '').replace(/ {2,}/g, ' ');
    if (value !== before) {
      input.value = value;
      const newCaret = Math.max(0, caret - (before.length - value.length));
      input.setSelectionRange(newCaret, newCaret);
    }
  });
}

// -----------------------------
// Shared validator for address lines (Street, Barangay, Municipality/City,
// Province) — mirrors validateAddressLine() in registration_helpers.php,
// including the 100-char cap (was 60 here, stricter than the server and the
// actual `users` column width) and Ñ/ñ support.
// -----------------------------
function validateAddressLine(fieldName, label, pattern, rejectDigitsOnly = false, maxLen = 100, allowDigits = true) {
  const input = document.getElementsByName(fieldName)[0];
  if (!input) return true;

  const raw = input.value;

  if (raw === '') {
    showSingleError(fieldName, input, `❌ ${label}: This field is required.`);
    return false;
  }
  if (/^\s|\s$/.test(raw) || /\s{2,}/.test(raw)) {
    showSingleError(fieldName, input, `❌ ${label}: Cannot have leading, trailing, or repeated spaces.`);
    return false;
  }

  const trimmed = raw.trim();
  if (!allowDigits && /[0-9]/.test(trimmed)) {
    showSingleError(fieldName, input, `❌ ${label}: Numbers are not allowed.`);
    return false;
  }
  if (/[<>]/.test(trimmed) || !pattern.test(trimmed)) {
    showSingleError(fieldName, input, `❌ ${label}: Special characters are not allowed.`);
    return false;
  }
  if (trimmed.length < 2 || trimmed.length > maxLen) {
    showSingleError(fieldName, input, `❌ ${label}: Must be between 2 and ${maxLen} characters.`);
    return false;
  }
  if (rejectDigitsOnly && /^[0-9\s]+$/.test(trimmed)) {
    showSingleError(fieldName, input, `❌ ${label}: Cannot contain only numbers.`);
    return false;
  }
  if (!hasProperWordCasing(trimmed)) {
    showSingleError(fieldName, input, `❌ ${label}: Each word must start with an uppercase letter, rest lowercase.`);
    return false;
  }

  clearError(fieldName, input);
  return true;
}

function validateStreetField() {
  return validateAddressLine('street', 'Street/Purok', /^[A-Za-z0-9][A-Za-z0-9Ññ\s.,\-\/']*$/, false, 100);
}
function validateBarangay() {
  return validateAddressLine('barangay', 'Barangay', /^[A-Za-z0-9][A-Za-z0-9Ññ\s.\-']*$/, true, 100);
}
function validateCity() {
  return validateAddressLine('city', 'Municipality/City', /^[A-Za-zÑñ][A-Za-zÑñ\s.\-']*$/, false, 100, false);
}
function validateProvince() {
  return validateAddressLine('province', 'Province', /^[A-Za-zÑñ][A-Za-zÑñ\s.\-']*$/, false, 100, false);
}
function validateRegion() {
  const select = document.getElementsByName('region')[0];
  if (!select) return true;
  if (!select.value) {
    showSingleError('region', select, '❌ Please select a region.');
    return false;
  }
  clearError('region', select);
  return true;
}

// -----------------------------
// ZIP CODE — dedicated error box (showZipError/clearZipError), referenced by
// name from password_register.js's server-error handler.
// -----------------------------
const ZIP_LENGTH = 4;

function getErrorBoxForZip(inputElem) {
  const id = `zip_error_${inputElem.name}`;
  let box = document.getElementById(id);
  if (box) return box;
  box = document.createElement('div');
  box.id = id;
  box.className = 'error-box';
  box.style.cssText = 'background:#ffe5e5;border:1px solid #ff6b6b;color:#b30000;padding:6px 10px;margin-top:6px;font-size:12px;border-radius:5px;display:none;';
  inputElem.parentNode.appendChild(box);
  inputElem.setAttribute('aria-describedby', box.id);
  return box;
}

function showZipError(inputElem, message) {
  const box = getErrorBoxForZip(inputElem);
  box.textContent = message;
  box.style.display = 'block';
  inputElem.classList.add('is-invalid');
  inputElem.classList.remove('is-valid');
}

function clearZipError(inputElem) {
  const box = getErrorBoxForZip(inputElem);
  box.textContent = '';
  box.style.display = 'none';
  inputElem.classList.remove('is-invalid');
  inputElem.classList.add('is-valid');
}

function validateZipField(input, checkEmpty = false) {
  if (!input) return true;
  const value = input.value;

  if (value === '') {
    if (checkEmpty) {
      showZipError(input, '❌ Zip Code is required.');
      return false;
    }
    clearZipError(input);
    return true;
  }
  if (/\s/.test(value)) { showZipError(input, '❌ Zip Code: Spaces are not allowed.'); return false; }
  if (/[A-Za-z]/.test(value)) { showZipError(input, '❌ Zip Code: Letters are not allowed.'); return false; }
  if (/[^0-9]/.test(value)) { showZipError(input, '❌ Zip Code: Special characters are not allowed.'); return false; }
  if (value.length !== ZIP_LENGTH) { showZipError(input, `❌ Zip Code must be exactly ${ZIP_LENGTH} digits.`); return false; }

  clearZipError(input);
  return true;
}

// -----------------------------
// EMAIL — required, strict @csucc.edu.ph format. Deliberately does NOT
// auto-append a domain to whatever the user typed — silently rewriting the
// value they typed is surprising and doesn't match how the server validates
// it (a plain, strict format check with no auto-completion).
// -----------------------------
function getErrorBoxForEmail(inputElem) {
  const id = `email_error_${inputElem.name}`;
  let box = document.getElementById(id);
  if (box) return box;
  box = document.createElement('div');
  box.id = id;
  box.className = 'error-box';
  box.style.cssText = 'background:#ffe5e5;border:1px solid #ff6b6b;color:#b30000;padding:6px 10px;margin-top:6px;font-size:12px;border-radius:5px;display:none;';
  inputElem.parentNode.appendChild(box);
  inputElem.setAttribute('aria-describedby', box.id);
  return box;
}

function showEmailError(inputElem, message) {
  const box = getErrorBoxForEmail(inputElem);
  box.textContent = message;
  box.style.display = 'block';
  box.style.background = '#ffe5e5';
  box.style.border = '1px solid #ff6b6b';
  box.style.color = '#b30000';
  inputElem.classList.add('is-invalid');
  inputElem.classList.remove('is-valid');
  inputElem.setAttribute('aria-invalid', 'true');
}

function clearEmailError(inputElem) {
  const box = getErrorBoxForEmail(inputElem);
  box.textContent = '';
  box.style.display = 'none';
  inputElem.classList.remove('is-invalid');
  inputElem.classList.add('is-valid');
  inputElem.removeAttribute('aria-invalid');
}

const REGISTER_EMAIL_DOMAIN = 'csucc.edu.ph';

function validateEmailField() {
  const input = document.querySelector("input[name='email']");
  if (!input) return true;

  const raw = input.value;
  if (!raw) { showEmailError(input, '❌ Email is required.'); return false; }
  if (/^\s|\s$/.test(raw) || /\s{2,}/.test(raw)) {
    showEmailError(input, '❌ Email cannot have leading, trailing, or repeated spaces.');
    return false;
  }

  const value = raw.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) { showEmailError(input, '❌ Please enter a valid email address.'); return false; }
  if (value.length > 100) { showEmailError(input, '❌ Email must be at most 100 characters.'); return false; }
  if (!value.endsWith('@' + REGISTER_EMAIL_DOMAIN)) {
    showEmailError(input, `❌ Email must be a valid @${REGISTER_EMAIL_DOMAIN} address.`);
    return false;
  }

  clearEmailError(input);
  checkEmailAvailability(input, value);
  return true;
}

function checkEmailAvailability(input, value) {
  const box = getErrorBoxForEmail(input);
  box.textContent = '⏳ Checking availability...';
  box.style.display = 'block';
  box.style.background = '#fff3cd';
  box.style.border = '1px solid #ffeeba';
  box.style.color = '#856404';

  fetch('../include/check_email.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'email=' + encodeURIComponent(value)
  })
    .then(res => res.json())
    .then(data => {
      if (data.exists) {
        showEmailError(input, data.message || '❌ Email already registered.');
      } else if (data.message) {
        box.textContent = data.message;
        box.style.display = 'block';
        box.style.background = '#e8f5e9';
        box.style.border = '1px solid #4caf50';
        box.style.color = '#256029';
      }
    })
    .catch(() => {});
}

// -----------------------------
// USERNAME — required, letters/digits/_/. only, starts with a letter,
// 5-30 chars, at least one uppercase letter, one number, and one special
// character (_ or .). Mirrors validateRegistration()'s username block.
// -----------------------------
function validateUsernameField() {
  const fieldName = 'username';
  const input = document.getElementsByName(fieldName)[0];
  if (!input) return true;

  const rawValue = input.value;
  if (!rawValue) { showSingleError(fieldName, input, '❌ Username is required.'); return false; }
  if (/\s/.test(rawValue)) { showSingleError(fieldName, input, '❌ Username must not contain spaces.'); return false; }

  const value = rawValue;
  if (/[^A-Za-z0-9_.]/.test(value)) { showSingleError(fieldName, input, '❌ Username: Special characters are not allowed.'); return false; }
  if (!/^[A-Za-z]/.test(value)) { showSingleError(fieldName, input, '❌ Username must start with a letter.'); return false; }
  if (value.length < 5 || value.length > 30) { showSingleError(fieldName, input, '❌ Username must be between 5 and 30 characters.'); return false; }
  if (!/[A-Z]/.test(value)) { showSingleError(fieldName, input, '❌ Username must contain at least one uppercase letter.'); return false; }
  if (!/[0-9]/.test(value)) { showSingleError(fieldName, input, '❌ Username must contain at least one number.'); return false; }
  if (!/[_.]/.test(value)) { showSingleError(fieldName, input, '❌ Username must contain at least one special character (_ or .).'); return false; }

  clearError(fieldName, input);

  const box = getErrorBox(fieldName, input);
  box.textContent = '⏳ Checking availability...';
  box.style.display = 'block';
  box.style.background = '#fff3cd';
  box.style.border = '1px solid #ffeeba';
  box.style.color = '#856404';
  input.classList.remove('is-valid', 'is-invalid');

  fetch('../include/check_username.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'username=' + encodeURIComponent(value)
  })
    .then(res => res.json())
    .then(data => {
      if (data.exists) {
        showSingleError(fieldName, input, data.message || '❌ Username already exists.');
      } else {
        clearError(fieldName, input);
        box.textContent = data.message || '✅ Username is available.';
        box.style.display = 'block';
        box.style.background = '#e8f5e9';
        box.style.border = '1px solid #4caf50';
        box.style.color = '#256029';
      }
    })
    .catch(() => {
      showSingleError(fieldName, input, '⚠️ Error checking username. Please try again.');
    });

  return true;
}

// -----------------------------
// Wiring: live/blur validation + sessionStorage persistence for the whole
// form (every field, not just this file's — this block owns the single
// persistence pass so values survive a refresh or a server round-trip).
// -----------------------------
document.addEventListener('DOMContentLoaded', () => {
  const addressMappings = [
    { name: 'street', func: validateStreetField },
    { name: 'barangay', func: validateBarangay },
    { name: 'city', func: validateCity },
    { name: 'province', func: validateProvince },
  ];
  addressMappings.forEach(({ name, func }) => {
    const el = document.getElementsByName(name)[0];
    if (!el) return;
    attachLiveSpaceCollapse(el);
    el.addEventListener('input', func);
    el.addEventListener('blur', func);
  });

  const region = document.getElementsByName('region')[0];
  if (region) {
    region.addEventListener('change', validateRegion);
    region.addEventListener('blur', validateRegion);
  }

  const zip = document.getElementsByName('zip')[0];
  if (zip) {
    zip.addEventListener('input', () => validateZipField(zip));
    zip.addEventListener('blur', () => validateZipField(zip, true));
  }

  const email = document.getElementsByName('email')[0];
  if (email) {
    email.addEventListener('input', validateEmailField);
    email.addEventListener('blur', validateEmailField);
  }

  const username = document.getElementsByName('username')[0];
  if (username) {
    let timer;
    username.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(() => validateUsernameField(), 400);
    });
    username.addEventListener('blur', validateUsernameField);
  }

  // -------------------------
  // FORM-WIDE PERSISTENCE
  // -------------------------
  const fieldsToPersist = [
    'id_number', 'first_name', 'middle_name', 'last_name', 'extension', 'sex', 'birthdate', 'age',
    'street', 'barangay', 'city', 'province', 'region', 'zip', 'email', 'username', 'password', 'repassword',
    'a1_question', 'a1_answer', 'a2_question', 'a2_answer', 'a3_question', 'a3_answer',
  ];
  fieldsToPersist.forEach((name) => {
    const field = document.getElementsByName(name)[0];
    if (!field) return;
    const saved = sessionStorage.getItem(name);
    if (saved !== null) field.value = saved;
    field.addEventListener('input', () => sessionStorage.setItem(name, field.value));
    field.addEventListener('change', () => sessionStorage.setItem(name, field.value));
  });

  const form = document.getElementById('registerForm');
  if (form) {
    form.addEventListener('submit', () => {
      if (!form.querySelector('.is-invalid')) {
        fieldsToPersist.forEach((name) => sessionStorage.removeItem(name));
      }
    });
  }
});
