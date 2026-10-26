// Client-side hardening for the mandatory first-login "Complete Your
// Profile" form. This mirrors validateProfileCompletion() in
// include/registration_helpers.php field-for-field so a mistake is caught
// immediately, but the server is what actually enforces every rule — this
// file is UX sugar only, never the source of truth.
document.addEventListener('contextmenu', e => e.preventDefault());

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('completeProfileForm');
  if (!form) return;

  function getErrorBox(name, input) {
    const id = `${name}_cp_error`;
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

  function hasProperWordCasing(trimmed) {
    return trimmed.split(/\s+/).every(word => {
      if (!word || /\d/.test(word)) return true;
      const first = word[0];
      const rest = word.slice(1);
      return first === first.toUpperCase() && rest === rest.toLowerCase();
    });
  }

  function validateNameField(name, label, required) {
    const input = field(name);
    if (!input) return true;
    const value = input.value;

    if (/^\s/.test(value)) { showError(name, input, `❌ ${label}: Cannot start with a space.`); return false; }
    if (/\s$/.test(value)) { showError(name, input, `❌ ${label}: Cannot end with a space.`); return false; }

    const trimmed = value.trim();
    if (!trimmed) {
      if (required) { showError(name, input, `❌ ${label}: This field is required.`); return false; }
      clearError(name, input);
      return true;
    }
    if (/\d/.test(value)) { showError(name, input, `❌ ${label}: Numbers are not allowed.`); return false; }
    if (/[^A-Za-z\s]/.test(value)) { showError(name, input, `❌ ${label}: Special characters are not allowed.`); return false; }
    if (!hasProperWordCasing(trimmed)) { showError(name, input, `❌ ${label}: First letter must be uppercase, rest lowercase.`); return false; }
    if (/\s{2,}/.test(value)) { showError(name, input, `❌ ${label}: No double spaces allowed.`); return false; }
    if (trimmed.length < 2 || trimmed.length > 50) { showError(name, input, `❌ ${label}: Must be between 2 and 50 characters.`); return false; }

    clearError(name, input);
    return true;
  }

  function validateExtension() {
    const input = field('extension');
    if (!input) return true;
    const raw = input.value;
    if (/^\s|\s$/.test(raw) || /\s{2,}/.test(raw)) { showError('extension', input, '❌ Extension cannot have leading, trailing, or repeated spaces.'); return false; }
    const trimmed = raw.trim();
    if (trimmed === '') { clearError('extension', input); return true; }
    if (/\d/.test(trimmed)) { showError('extension', input, '❌ Extension: Numbers are not allowed.'); return false; }
    if (!/^[A-Za-z]+$/.test(trimmed)) { showError('extension', input, '❌ Extension: Special characters are not allowed.'); return false; }
    const clean = trimmed.toUpperCase();
    if (!/^(JR|SR|II|III|IV|V)$/.test(clean)) { showError('extension', input, '❌ Extension must be one of: Jr, Sr, II, III, IV, V.'); return false; }
    clearError('extension', input);
    return true;
  }

  function validateSex() {
    const select = field('sex');
    if (!select) return true;
    if (!select.value) { showError('sex', select, '❌ Please select a valid sex.'); return false; }
    clearError('sex', select);
    return true;
  }

  function validateBirthdate() {
    const input = field('birthdate');
    if (!input) return true;
    if (!input.value) { showError('birthdate', input, '❌ Please enter a valid birthdate.'); return false; }

    const bday = new Date(input.value);
    const today = new Date();
    if (bday > today) { showError('birthdate', input, '❌ Birthdate cannot be in the future.'); return false; }

    let years = today.getFullYear() - bday.getFullYear();
    const m = today.getMonth() - bday.getMonth();
    if (m < 0 || (m === 0 && today.getDate() < bday.getDate())) years--;

    if (years < 18) { showError('birthdate', input, '❌ Must be at least 18 years old.'); return false; }
    clearError('birthdate', input);
    return true;
  }

  function validateAddressLine(name, label, pattern, rejectDigitsOnly, maxLen, allowDigits) {
    const input = field(name);
    if (!input) return true;
    const raw = input.value;

    if (raw === '') { showError(name, input, `❌ ${label}: This field is required.`); return false; }
    if (/^\s|\s$/.test(raw) || /\s{2,}/.test(raw)) { showError(name, input, `❌ ${label}: Cannot have leading, trailing, or repeated spaces.`); return false; }
    const trimmed = raw.trim();
    if (!allowDigits && /[0-9]/.test(trimmed)) { showError(name, input, `❌ ${label}: Numbers are not allowed.`); return false; }
    if (!pattern.test(trimmed)) { showError(name, input, `❌ ${label}: Special characters are not allowed.`); return false; }
    if (trimmed.length < 2 || trimmed.length > maxLen) { showError(name, input, `❌ ${label}: Must be between 2 and ${maxLen} characters.`); return false; }
    if (rejectDigitsOnly && /^[0-9\s]+$/.test(trimmed)) { showError(name, input, `❌ ${label}: Cannot contain only numbers.`); return false; }
    if (!hasProperWordCasing(trimmed)) { showError(name, input, `❌ ${label}: Each word must start with an uppercase letter, rest lowercase.`); return false; }
    clearError(name, input);
    return true;
  }

  function validateStreet() { return validateAddressLine('street', 'Street/Purok', /^[A-Za-z0-9][A-Za-z0-9\s.,\-\/']*$/, false, 60, true); }
  function validateBarangay() { return validateAddressLine('barangay', 'Barangay', /^[A-Za-z0-9][A-Za-z0-9\s.\-']*$/, true, 60, true); }
  function validateCity() { return validateAddressLine('city', 'Municipality/City', /^[A-Za-z][A-Za-z\s.\-']*$/, false, 60, false); }
  function validateProvince() { return validateAddressLine('province', 'Province', /^[A-Za-z][A-Za-z\s.\-']*$/, false, 60, false); }

  function validateRegion() {
    const select = field('region');
    if (!select) return true;
    if (!select.value) { showError('region', select, '❌ Please select a valid region.'); return false; }
    clearError('region', select);
    return true;
  }

  function validateZip() {
    const input = field('zip');
    if (!input) return true;
    const value = input.value;
    if (value === '') { showError('zip', input, '❌ Zip Code is required.'); return false; }
    if (/\s/.test(value)) { showError('zip', input, '❌ Zip Code: Spaces are not allowed.'); return false; }
    if (/[A-Za-z]/.test(value)) { showError('zip', input, '❌ Zip Code: Letters are not allowed.'); return false; }
    if (/[^0-9]/.test(value)) { showError('zip', input, '❌ Zip Code: Special characters are not allowed.'); return false; }
    if (!/^\d{4}$/.test(value)) { showError('zip', input, '❌ Zip Code must be exactly 4 digits.'); return false; }
    clearError('zip', input);
    return true;
  }

  function validateEmail() {
    const input = field('email');
    if (!input) return true;
    const raw = input.value;
    if (!raw) { showError('email', input, '❌ Email is required.'); return false; }
    if (/^\s|\s$/.test(raw) || /\s{2,}/.test(raw)) { showError('email', input, '❌ Email cannot have leading, trailing, or repeated spaces.'); return false; }
    const value = raw.trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) { showError('email', input, '❌ Please enter a valid email address.'); return false; }
    if (value.length > 100) { showError('email', input, '❌ Email must be at most 100 characters.'); return false; }
    if (!value.toLowerCase().endsWith('@csucc.edu.ph')) { showError('email', input, '❌ Email must be a valid @csucc.edu.ph address.'); return false; }
    clearError('email', input);
    return true;
  }

  const COMMON_WEAK_PASSWORDS = [
    'password', 'password1', 'password123', '12345678', '123456789', '1234567890',
    'qwerty123', 'qwertyuiop', 'letmein123', 'iloveyou123', 'admin1234', 'welcome123',
    'changeme123', '00000000', '11111111', 'abc123456', 'passw0rd', 'p@ssw0rd123',
    'trustno1', 'football123', 'baseball123', 'dragon1234', 'monkey1234', 'master1234',
  ];

  window.togglePassword = function (fieldId, iconElem) {
    const input = document.getElementById(fieldId);
    if (!input) return;
    input.type = input.type === 'password' ? 'text' : 'password';
    iconElem.textContent = input.type === 'password' ? '👁️' : '🙈';
  };

  window.checkPasswordStrength = function () {
    const password = field('new_password') ? field('new_password').value : '';
    const strengthText = document.getElementById('strengthText');
    const strengthBar = document.getElementById('strengthBar');
    if (!strengthText || !strengthBar) return;

    let strength = 0;
    if (password.length >= 6) strength++;
    if (password.length >= 10) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;

    const strengths = ['Very Weak', 'Weak', 'Moderate', 'Strong', 'Very Strong'];
    const colors = ['#ff0000', '#ff7f00', '#ffcc00', '#3399ff', '#00cc44'];
    const widths = ['20%', '40%', '60%', '80%', '100%'];

    if (strength > 0) {
      strengthText.textContent = strengths[strength - 1];
      strengthText.style.color = colors[strength - 1];
      strengthBar.style.width = widths[strength - 1];
      strengthBar.style.background = colors[strength - 1];
    } else {
      strengthText.textContent = '';
      strengthBar.style.width = '0%';
      strengthBar.style.background = 'transparent';
    }
  };

  window.checkMatchPassword = function () {
    const pass = field('new_password') ? field('new_password').value : '';
    const repass = field('confirm_new_password') ? field('confirm_new_password').value : '';
    const matchText = document.getElementById('matchText');
    if (!matchText) return;
    if (!repass) { matchText.textContent = ''; return; }
    if (pass === repass) {
      matchText.textContent = '✅ Passwords match';
      matchText.style.color = '#3ddc84';
    } else {
      matchText.textContent = '❌ Passwords do not match';
      matchText.style.color = '#ff6b6b';
    }
  };

  function validateNewPassword() {
    const input = field('new_password');
    if (!input) return true;
    const password = input.value;
    if (!password) { showError('new_password', input, '❌ Password is required.'); return false; }
    if (/^\s|\s$/.test(password)) { showError('new_password', input, '❌ Password cannot start or end with a space.'); return false; }
    if (password.length < 8 || password.length > 72) { showError('new_password', input, '❌ Password must be between 8 and 72 characters.'); return false; }
    if (COMMON_WEAK_PASSWORDS.includes(password.toLowerCase())) { showError('new_password', input, '❌ This password is too common. Please choose another.'); return false; }
    clearError('new_password', input);
    return true;
  }

  function validateConfirmNewPassword() {
    const input = field('confirm_new_password');
    const password = field('new_password');
    if (!input || !password) return true;
    if (!input.value) { showError('confirm_new_password', input, '❌ Please re-enter your new password.'); return false; }
    if (input.value !== password.value) { showError('confirm_new_password', input, '❌ Passwords do not match.'); return false; }
    clearError('confirm_new_password', input);
    return true;
  }

  function validateQuestionSelect(name, label) {
    const select = field(name);
    if (!select) return true;
    if (!select.value) { showError(name, select, `❌ Please select a ${label}.`); return false; }
    clearError(name, select);
    return true;
  }

  function validateQuestionsDistinct() {
    const q1 = field('a1_question'), q2 = field('a2_question'), q3 = field('a3_question');
    if (!q1 || !q2 || !q3) return true;
    let ok = true;
    if (q1.value && q1.value === q2.value) { showError('a2_question', q2, '❌ Question 2 must be different from Question 1.'); ok = false; }
    if (q1.value && q1.value === q3.value) { showError('a3_question', q3, '❌ Question 3 must be different from Question 1.'); ok = false; }
    if (ok && q2.value && q2.value === q3.value) { showError('a3_question', q3, '❌ Question 3 must be different from Question 2.'); ok = false; }
    return ok;
  }

  function validateAnswer(name, label) {
    const input = field(name);
    if (!input) return true;
    const raw = input.value;
    if (raw === '') { showError(name, input, `❌ ${label}: This answer is required.`); return false; }
    if (/^\s|\s$/.test(raw) || /\s{2,}/.test(raw)) { showError(name, input, `❌ ${label}: Cannot have leading, trailing, or repeated spaces.`); return false; }
    const trimmed = raw.trim();
    if (/[<>&"'`]/.test(trimmed)) { showError(name, input, `❌ ${label}: Special characters are not allowed.`); return false; }
    if (trimmed.length < 2 || trimmed.length > 100) { showError(name, input, `❌ ${label}: Must be between 2 and 100 characters.`); return false; }
    clearError(name, input);
    return true;
  }

  const liveChecks = [
    ['first_name', () => validateNameField('first_name', 'First Name', true)],
    ['middle_name', () => validateNameField('middle_name', 'Middle Name', false)],
    ['last_name', () => validateNameField('last_name', 'Last Name', true)],
    ['extension', validateExtension],
    ['sex', validateSex],
    ['birthdate', validateBirthdate],
    ['street', validateStreet],
    ['barangay', validateBarangay],
    ['city', validateCity],
    ['province', validateProvince],
    ['region', validateRegion],
    ['zip', validateZip],
    ['email', validateEmail],
    ['new_password', validateNewPassword],
    ['confirm_new_password', validateConfirmNewPassword],
    ['a1_question', () => validateQuestionSelect('a1_question', 'question') && validateQuestionsDistinct()],
    ['a1_answer', () => validateAnswer('a1_answer', 'Answer 1')],
    ['a2_question', () => validateQuestionSelect('a2_question', 'question') && validateQuestionsDistinct()],
    ['a2_answer', () => validateAnswer('a2_answer', 'Answer 2')],
    ['a3_question', () => validateQuestionSelect('a3_question', 'question') && validateQuestionsDistinct()],
    ['a3_answer', () => validateAnswer('a3_answer', 'Answer 3')],
  ];

  liveChecks.forEach(([name, fn]) => {
    const input = field(name);
    if (!input) return;
    input.addEventListener('input', fn);
    input.addEventListener('blur', fn);
    input.addEventListener('change', fn);
  });

  form.addEventListener('submit', (e) => {
    const results = liveChecks.map(([name, fn]) => ({ name, ok: fn() }));
    const firstFailed = results.find(r => !r.ok);

    if (firstFailed) {
      e.preventDefault();
      const target = field(firstFailed.name);
      if (target) setTimeout(() => target.focus(), 10);
    }
  });
});
