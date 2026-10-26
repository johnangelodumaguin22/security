// Client-side hardening for the one-time "Set Your Security Questions" gate.
// Mirrors validateSecurityQuestionFields() in
// include/registration_helpers.php field-for-field, but the server is what
// actually enforces every rule — this file is UX sugar only.
document.addEventListener('contextmenu', e => e.preventDefault());

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('setQuestionsForm');
  if (!form) return;

  function getErrorBox(name, input) {
    const id = `${name}_sq_error`;
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

  window.togglePassword = function (fieldId, iconElem) {
    const input = document.getElementById(fieldId);
    if (!input) return;
    input.type = input.type === 'password' ? 'text' : 'password';
    iconElem.textContent = input.type === 'password' ? '👁️' : '🙈';
  };

  function validateQuestionSelect(name) {
    const select = field(name);
    if (!select) return true;
    if (!select.value) { showError(name, select, '❌ Please select a valid question.'); return false; }
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
    ['a1_question', () => validateQuestionSelect('a1_question') && validateQuestionsDistinct()],
    ['a1_answer', () => validateAnswer('a1_answer', 'Answer 1')],
    ['a2_question', () => validateQuestionSelect('a2_question') && validateQuestionsDistinct()],
    ['a2_answer', () => validateAnswer('a2_answer', 'Answer 2')],
    ['a3_question', () => validateQuestionSelect('a3_question') && validateQuestionsDistinct()],
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
