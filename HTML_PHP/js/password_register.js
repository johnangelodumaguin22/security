// Password/Re-enter Password fields, plus the ONE consolidated submit
// handler for the whole registration form.
//
// Previously this file, personal_information_register.js,
// address_account_register.js, and security_question_register.js EACH
// attached their own 'submit' listener to #registerForm — up to 5 separate
// listeners firing on every click, none of them aware of what the others
// had already found invalid. Since only this file's listener actually
// performs the fetch() submission, an error an EARLIER listener had already
// flagged (and called preventDefault() for) didn't stop this one from still
// running its own narrower checks and submitting anyway if those happened to
// pass — the server would still catch it, but only after a round-trip, and
// the UX (which field gets focused) was unpredictable. Now this is the only
// listener that submits; the other files only define field validators.

// Toggle password/answer visibility — used by the eye icons in register.php.
function togglePassword(fieldId, iconElem) {
  const field = document.getElementById(fieldId);
  if (!field) return;
  field.type = field.type === 'password' ? 'text' : 'password';
  iconElem.textContent = field.type === 'password' ? '👁️' : '🙈';
}

function checkPasswordStrength() {
  const password = document.getElementById('password').value;
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
}

function checkMatchPassword() {
  const pass = document.getElementById('password').value;
  const repass = document.getElementById('repassword').value;
  const matchText = document.getElementById('matchText');
  if (!matchText) return;
  if (!repass) { matchText.textContent = ''; return; }
  if (pass === repass) {
    matchText.textContent = '✅ Passwords match';
    matchText.style.color = 'green';
  } else {
    matchText.textContent = '❌ Passwords do not match';
    matchText.style.color = 'red';
  }
}

const COMMON_WEAK_PASSWORDS = [
  'password', 'password1', 'password123', '12345678', '123456789', '1234567890',
  'qwerty123', 'qwertyuiop', 'letmein123', 'iloveyou123', 'admin1234', 'welcome123',
  'changeme123', '00000000', '11111111', 'abc123456', 'passw0rd', 'p@ssw0rd123',
  'trustno1', 'football123', 'baseball123', 'dragon1234', 'monkey1234', 'master1234',
];

function isCommonWeakPassword(pwd) {
  return COMMON_WEAK_PASSWORDS.includes(pwd.toLowerCase());
}

// Mirrors validateRegistration()'s password block: length, character-class
// composition, common-password blacklist, then rejects the account's own
// username/first/last name as a substring — in that exact priority order.
function validatePasswordField() {
  const fieldName = 'password';
  const input = document.getElementById('password');
  if (!input) return true;

  const password = input.value;
  const username = (document.getElementsByName('username')[0] || {}).value || '';
  const firstName = (document.getElementsByName('first_name')[0] || {}).value || '';
  const lastName = (document.getElementsByName('last_name')[0] || {}).value || '';

  if (!password) { showSingleError(fieldName, input, '❌ Password is required.'); return false; }
  if (/^\s|\s$/.test(password)) { showSingleError(fieldName, input, '❌ Password cannot start or end with a space.'); return false; }
  if (password.length < 8 || password.length > 72) { showSingleError(fieldName, input, '❌ Password must be between 8 and 72 characters.'); return false; }
  if (!/[A-Z]/.test(password)) { showSingleError(fieldName, input, '❌ Password must contain at least one uppercase letter.'); return false; }
  if (!/[a-z]/.test(password)) { showSingleError(fieldName, input, '❌ Password must contain at least one lowercase letter.'); return false; }
  if (!/[0-9]/.test(password)) { showSingleError(fieldName, input, '❌ Password must contain at least one number.'); return false; }
  if (!/[!@#$%^&*()_\-+=?]/.test(password)) { showSingleError(fieldName, input, '❌ Password must contain at least one special character (! @ # $ % ^ & * ( ) _ - + = ?).'); return false; }
  if (isCommonWeakPassword(password)) { showSingleError(fieldName, input, '❌ This password is too common. Please choose another.'); return false; }
  if (username && password.toLowerCase().includes(username.toLowerCase())) { showSingleError(fieldName, input, '❌ Password must not contain your username.'); return false; }
  if (firstName && password.toLowerCase().includes(firstName.toLowerCase())) { showSingleError(fieldName, input, '❌ Password must not contain your first name.'); return false; }
  if (lastName && password.toLowerCase().includes(lastName.toLowerCase())) { showSingleError(fieldName, input, '❌ Password must not contain your last name.'); return false; }

  clearError(fieldName, input);
  return true;
}

function validateRepasswordField() {
  const fieldName = 'repassword';
  const input = document.getElementById('repassword');
  const password = document.getElementById('password');
  if (!input || !password) return true;
  if (!input.value) { showSingleError(fieldName, input, '❌ Please re-enter your password.'); return false; }
  if (input.value !== password.value) { showSingleError(fieldName, input, '❌ Passwords do not match.'); return false; }
  clearError(fieldName, input);
  return true;
}

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('registerForm');
  if (!form) return;

  const password = document.getElementById('password');
  const repassword = document.getElementById('repassword');
  if (password) {
    password.addEventListener('input', () => { checkPasswordStrength(); checkMatchPassword(); validatePasswordField(); });
    password.addEventListener('blur', validatePasswordField);
  }
  if (repassword) {
    repassword.addEventListener('input', () => { checkMatchPassword(); validateRepasswordField(); });
    repassword.addEventListener('blur', validateRepasswordField);
  }

  // Every field validator across all 4 files, run in the order they appear
  // on the form — first invalid one wins the focus, exactly like every
  // other multi-field form built in this app since.
  const allChecks = [
    () => validateNameField('first_name', 'First Name', true),
    () => validateNameField('middle_name', 'Middle Name', false),
    () => validateNameField('last_name', 'Last Name', true),
    () => validateExtensionField(),
    () => validateSex(),
    () => validateBirthdateField(),
    () => validateStreetField(),
    () => validateBarangay(),
    () => validateCity(),
    () => validateProvince(),
    () => validateRegion(),
    () => validateZipField(document.getElementsByName('zip')[0], true),
    () => validateEmailField(),
    () => validateUsernameField(),
    () => validatePasswordField(),
    () => validateRepasswordField(),
    () => validateSecurityAnswers(),
  ];
  const fieldNamesInOrder = [
    'first_name', 'middle_name', 'last_name', 'extension', 'sex', 'birthdate',
    'street', 'barangay', 'city', 'province', 'region', 'zip', 'email', 'username',
    'password', 'repassword', 'a1_answer',
  ];

  let submitting = false;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (submitting) return;

    const results = allChecks.map((fn) => {
      try { return fn(); } catch (err) { console.error(err); return true; }
    });
    const firstFailedIndex = results.findIndex((ok) => !ok);
    if (firstFailedIndex !== -1) {
      const el = document.getElementsByName(fieldNamesInOrder[firstFailedIndex])[0];
      if (el) setTimeout(() => el.focus(), 10);
      return;
    }

    submitting = true;
    const submitBtn = form.querySelector('.register-card__submit');
    if (submitBtn) submitBtn.disabled = true;

    const formData = new FormData(form);
    try {
      const res = await fetch('', { method: 'POST', body: formData });
      const data = await res.json();

      if (data.success) {
        alert(`✅ ${data.message}\nYour ID: ${data.id_number}`);
        window.location.href = 'login.php';
        return;
      }

      // Field-specific errors returned by the server. A few fields keep
      // their own dedicated error box (email/zip/security answers) so we
      // don't render two overlapping boxes for the same field.
      const dedicatedHandlers = {
        email: typeof showEmailError === 'function' ? showEmailError : null,
        zip: typeof showZipError === 'function' ? showZipError : null,
        a1_answer: typeof showAnswerError === 'function' ? showAnswerError : null,
        a2_answer: typeof showAnswerError === 'function' ? showAnswerError : null,
        a3_answer: typeof showAnswerError === 'function' ? showAnswerError : null,
      };

      const errors = data.errors || {};
      let firstField = null;
      Object.keys(errors).forEach((name) => {
        const field = form.elements[name];
        if (!field) return;
        if (!firstField) firstField = field;
        const handler = dedicatedHandlers[name];
        if (handler) {
          handler(field, `❌ ${errors[name]}`);
        } else {
          showSingleError(name, field, `❌ ${errors[name]}`);
        }
      });

      if (firstField) {
        firstField.focus();
      } else {
        alert(`❌ Registration Failed!\n${data.message}`);
      }
    } catch (err) {
      console.error(err);
      alert('❌ An unexpected error occurred. Please try again.');
    } finally {
      submitting = false;
      if (submitBtn) submitBtn.disabled = false;
    }
  });
});
