// Personal Info fields (First/Middle/Last Name, Extension, Sex, Birthdate).
// Error-box helpers (getErrorBox/showSingleError/clearError) and the shared
// casing/character helpers live in register_shared.js, loaded before this
// file — see that file's header comment for why they're centralized.
//
// This file only defines field-level validators + their live/blur wiring.
// The single submit-time validation pass (running every field's validator,
// focusing the first invalid one, and only then submitting) lives in
// password_register.js — see that file for why it's the one central place.

// NAME priority: required -> leading/trailing space -> numbers -> special
// chars -> repeated chars -> casing -> length. Mirrors validateRegistration()'s
// name block in include/registration_helpers.php exactly, including the
// Ñ/ñ, hyphen, and apostrophe allowance ("Mary-Jane", "O'Connor", "Peña").
function validateNameField(fieldName, label, required = true) {
  const input = document.getElementsByName(fieldName)[0];
  if (!input) return true;

  const value = input.value;

  if (/^\s/.test(value)) {
    showSingleError(fieldName, input, `❌ ${label}: Cannot start with a space.`);
    return false;
  }
  if (/\s$/.test(value)) {
    showSingleError(fieldName, input, `❌ ${label}: Cannot end with a space.`);
    return false;
  }

  const trimmed = value.trim();

  if (!trimmed) {
    if (required) {
      showSingleError(fieldName, input, `❌ ${label}: This field is required.`);
      return false;
    }
    clearError(fieldName, input);
    return true;
  }

  // Invalid-character check first — a digit or unsupported symbol is caught
  // the instant it's typed, before any length/casing check can mask it
  // behind a more generic message.
  if (/\d/.test(trimmed)) {
    showSingleError(fieldName, input, `❌ ${label}: Numbers are not allowed.`);
    return false;
  }
  if (/\s{2,}/.test(value)) {
    showSingleError(fieldName, input, `❌ ${label}: No double spaces allowed.`);
    return false;
  }
  if (!isNamePart(trimmed)) {
    showSingleError(fieldName, input, `❌ ${label}: Special characters are not allowed.`);
    return false;
  }
  if (hasRepeatedChars(trimmed)) {
    showSingleError(fieldName, input, `❌ ${label}: The same character cannot repeat 3 or more times in a row.`);
    return false;
  }
  if (!hasProperWordCasing(trimmed)) {
    showSingleError(fieldName, input, `❌ ${label}: First letter must be uppercase, rest lowercase.`);
    return false;
  }
  if (trimmed.length < 2 || trimmed.length > 50) {
    showSingleError(fieldName, input, `❌ ${label}: Must be between 2 and 50 characters.`);
    return false;
  }

  clearError(fieldName, input);
  return true;
}

// EXTENSION validator — optional; Jr, Sr, II through X. Mirrors the extended
// map in include/registration_helpers.php (previously capped at V here,
// which rejected a server-valid VI/VII/VIII/IX/X).
function validateExtensionField() {
  const fieldName = 'extension';
  const input = document.getElementsByName(fieldName)[0];
  if (!input) return true;

  const raw = input.value;
  if (/^\s|\s$/.test(raw) || /\s{2,}/.test(raw)) {
    showSingleError(fieldName, input, '❌ Extension cannot have leading, trailing, or repeated spaces.');
    return false;
  }

  const trimmed = raw.trim();
  if (trimmed === '') {
    clearError(fieldName, input);
    return true;
  }

  if (/\d/.test(trimmed)) {
    showSingleError(fieldName, input, '❌ Extension: Numbers are not allowed.');
    return false;
  }
  if (!/^[A-Za-z]+$/.test(trimmed)) {
    showSingleError(fieldName, input, '❌ Extension: Special characters are not allowed.');
    return false;
  }

  const clean = trimmed.toUpperCase();
  const map = {
    JR: 'Jr', SR: 'Sr',
    II: 'II', III: 'III', IV: 'IV', V: 'V',
    VI: 'VI', VII: 'VII', VIII: 'VIII', IX: 'IX', X: 'X',
  };
  if (!map[clean]) {
    showSingleError(fieldName, input, '❌ Extension must be one of: Jr, Sr, II, III, IV, V, VI, VII, VIII, IX, X.');
    return false;
  }

  input.value = map[clean];
  clearError(fieldName, input);
  return true;
}

// SEX — a plain required-select check. "Touched" gating (don't flash an
// error before the user has interacted with it) is handled by only wiring
// this to 'change'/'blur', never 'input'-on-load.
function validateSex() {
  const inputName = 'sex';
  const select = document.getElementsByName(inputName)[0];
  if (!select) return true;

  if (!select.value) {
    showSingleError(inputName, select, '❌ Please select your sex.');
    return false;
  }
  clearError(inputName, select);
  return true;
}

// BIRTHDATE & AGE — valid date, not in the future, minimum age 18 (mirrors
// MIN_AGE in include/registration_helpers.php).
const REGISTER_MIN_AGE = 18;

function validateBirthdateField() {
  const fieldName = 'birthdate';
  const input = document.getElementsByName(fieldName)[0];
  const ageInput = document.getElementsByName('age')[0];
  if (!input) return true;

  const raw = input.value;
  if (!raw) {
    showSingleError(fieldName, input, '❌ Please enter your birthdate.');
    if (ageInput) ageInput.value = '';
    return false;
  }

  const bday = new Date(raw + 'T00:00:00');
  if (isNaN(bday.getTime())) {
    showSingleError(fieldName, input, '❌ Please enter a valid birthdate.');
    if (ageInput) ageInput.value = '';
    return false;
  }

  const today = new Date();
  today.setHours(0, 0, 0, 0);
  if (bday > today) {
    showSingleError(fieldName, input, '❌ Birthdate cannot be in the future.');
    if (ageInput) ageInput.value = '';
    return false;
  }

  let years = today.getFullYear() - bday.getFullYear();
  const m = today.getMonth() - bday.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < bday.getDate())) years--;
  if (ageInput) ageInput.value = years;

  if (years < REGISTER_MIN_AGE) {
    showSingleError(fieldName, input, `❌ You must be at least ${REGISTER_MIN_AGE} years old to register.`);
    if (ageInput) ageInput.value = '';
    return false;
  }

  clearError(fieldName, input);
  return true;
}

// -----------------------------
// Wiring: readonly fields, live/blur validation, sessionStorage persistence
// (so a page refresh or a server-side round-trip doesn't lose what was typed).
// -----------------------------
document.addEventListener('DOMContentLoaded', () => {
  const ageInput = document.getElementsByName('age')[0];
  if (ageInput) {
    ageInput.readOnly = true;
    ageInput.style.pointerEvents = 'none';
  }
  const idInput = document.getElementsByName('id_number')[0];
  if (idInput) {
    idInput.readOnly = true;
    idInput.style.pointerEvents = 'none';
  }

  const fn = document.getElementsByName('first_name')[0];
  const mn = document.getElementsByName('middle_name')[0];
  const ln = document.getElementsByName('last_name')[0];
  const ext = document.getElementsByName('extension')[0];
  const sex = document.getElementsByName('sex')[0];
  const bd = document.getElementsByName('birthdate')[0];

  if (fn) {
    fn.addEventListener('input', () => validateNameField('first_name', 'First Name', true));
    fn.addEventListener('blur', () => validateNameField('first_name', 'First Name', true));
  }
  if (mn) {
    mn.addEventListener('input', () => validateNameField('middle_name', 'Middle Name', false));
    mn.addEventListener('blur', () => validateNameField('middle_name', 'Middle Name', false));
  }
  if (ln) {
    ln.addEventListener('input', () => validateNameField('last_name', 'Last Name', true));
    ln.addEventListener('blur', () => validateNameField('last_name', 'Last Name', true));
  }
  if (ext) {
    ext.addEventListener('input', () => validateExtensionField());
    ext.addEventListener('blur', () => validateExtensionField());
  }
  if (sex) {
    sex.addEventListener('change', () => validateSex());
    sex.addEventListener('blur', () => validateSex());
  }
  if (bd) {
    bd.addEventListener('change', () => validateBirthdateField());
    bd.addEventListener('blur', () => validateBirthdateField());
    bd.addEventListener('input', () => validateBirthdateField());
  }

  // -------------------------
  // PERSONAL INFO PERSISTENCE — restore on load, save as the user types.
  // -------------------------
  const personalFields = ['first_name', 'middle_name', 'last_name', 'extension', 'sex', 'birthdate'];
  personalFields.forEach((f) => {
    const el = document.getElementsByName(f)[0];
    if (!el) return;
    const saved = sessionStorage.getItem(f);
    if (saved !== null) el.value = saved;
  });
  if (bd && ageInput && bd.value) {
    validateBirthdateField(); // fills in age from the restored birthdate
  }
  personalFields.forEach((f) => {
    const el = document.getElementsByName(f)[0];
    if (!el) return;
    const save = () => sessionStorage.setItem(f, el.value);
    el.addEventListener('input', save);
    el.addEventListener('change', save);
  });
});
