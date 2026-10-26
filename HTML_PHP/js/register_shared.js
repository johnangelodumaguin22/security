// Shared by every register.php validation file (personal_information_register.js,
// address_account_register.js, password_register.js, security_question_register.js).
// Must load FIRST — the other files call these directly instead of each
// redefining their own getErrorBox/showSingleError/clearError, which is what
// used to happen here: multiple same-named function declarations across
// files silently collide (the last script tag's definition wins globally),
// so which error-box style actually rendered depended on script load order
// rather than which field was being validated.
document.addEventListener('contextmenu', e => e.preventDefault());

function getErrorBox(inputName, inputElem) {
  const id = `${inputName}_error`;
  let box = document.getElementById(id);
  if (box) return box;

  box = document.createElement('div');
  box.id = id;
  box.className = 'error-box';
  box.style.cssText = 'background:#ffe5e5;border:1px solid #ff6b6b;color:#b30000;padding:6px 10px;margin-top:3px;font-size:12px;border-radius:5px;';

  inputElem.insertAdjacentElement('afterend', box);
  return box;
}

function showSingleError(inputName, inputElem, message) {
  const box = getErrorBox(inputName, inputElem);
  box.textContent = message;
  box.style.display = 'block';
  box.style.background = '#ffe5e5';
  box.style.border = '1px solid #ff6b6b';
  box.style.color = '#b30000';
  inputElem.classList.add('is-invalid');
  inputElem.classList.remove('is-valid');
}

function clearError(inputName, inputElem) {
  const box = getErrorBox(inputName, inputElem);
  box.textContent = '';
  box.style.display = 'none';
  inputElem.classList.remove('is-invalid');
  inputElem.classList.add('is-valid');
}

// Lowercase Spanish/Filipino connector words that legitimately stay
// lowercase inside an otherwise Title Case place name — "Agusan del Norte",
// "Surigao del Sur" — same list as PLACE_NAME_CONNECTORS in
// include/registration_helpers.php. Without this exception, a real,
// server-valid province/city name gets rejected client-side before the
// request is ever sent.
const PLACE_NAME_CONNECTORS = ['de', 'del', 'dela', 'la', 'las', 'los', 'y'];

// Word-by-word Title Case check (first letter uppercase, rest lowercase),
// same rule as hasProperWordCasing() in registration_helpers.php. Splits on
// space, hyphen, AND apostrophe so each name/address *part* is checked on
// its own — "O'Connor" is "O" + "Connor", "Mary-Jane" is "Mary" + "Jane".
function hasProperWordCasing(trimmed) {
  return trimmed.split(/[\s'\-]+/).every(word => {
    if (!word || /\d/.test(word)) return true;
    if (PLACE_NAME_CONNECTORS.includes(word.toLowerCase())) return true;
    const first = word[0];
    const rest = word.slice(1);
    return first === first.toUpperCase() && rest === rest.toLowerCase();
  });
}

// Letters (incl. Ñ/ñ) in runs separated by a single space, hyphen, or
// apostrophe — same rule as isNamePart() server-side. Covers "John",
// "Mary-Jane", "O'Connor", "Peña"; rejects a leading/trailing/doubled
// separator since every separator must be followed by another letter run.
function isNamePart(trimmed) {
  return /^[A-Za-zÑñ]+(?:['\- ][A-Za-zÑñ]+)*$/.test(trimmed);
}

function hasRepeatedChars(trimmed) {
  return /(.)\1\1/.test(trimmed);
}
