document.addEventListener('contextmenu', e => e.preventDefault());

// ========================== SECURITY QUESTION WITH INPUT PERSISTENCE =========================

// Create or get error box (uniform style)
function getErrorBoxForAnswer(inputElem) {
  const id = `answer_error_${inputElem.name}`; // unique per input
  let box = document.getElementById(id);
  if (box) return box;

  box = document.createElement("div");
  box.id = id;
  box.className = "error-box";
  box.style.cssText = `
    background:#ffe5e5;
    border:1px solid #ff6b6b;
    color:#b30000;
    padding:6px 10px;
    margin-top:6px;
    font-size:12px;
    border-radius:5px;
    display:none;
  `;
  inputElem.parentNode.appendChild(box);
  inputElem.setAttribute("aria-describedby", box.id);
  return box;
}

// Show error message
function showAnswerError(inputElem, message) {
  const box = getErrorBoxForAnswer(inputElem);
  box.textContent = message;
  box.style.display = "block";
  inputElem.classList.add("is-invalid");
  inputElem.classList.remove("is-valid");
  inputElem.setAttribute("aria-invalid", "true");
}

// Clear error message
function clearAnswerError(inputElem) {
  const box = getErrorBoxForAnswer(inputElem);
  box.textContent = "";
  box.style.display = "none";
  inputElem.classList.remove("is-invalid");
  inputElem.classList.add("is-valid");
  inputElem.removeAttribute("aria-invalid");
}

// Ensure Question 1, 2, and 3 are not the same
function validateSecurityQuestionsDistinct() {
  const values = [1, 2, 3].map(i => document.querySelector(`select[name="a${i}_question"]`)?.value || "");
  let valid = true;

  for (let i = 1; i <= 3; i++) {
    const question = document.querySelector(`select[name="a${i}_question"]`);
    const answer = document.querySelector(`input[name="a${i}_answer"]`);
    if (!question || !answer) continue;

    const value = values[i - 1];
    const duplicatesEarlier = value && values.slice(0, i - 1).includes(value);
    if (duplicatesEarlier) {
      showAnswerError(answer, `❌ Question ${i} must be different from the other questions.`);
      valid = false;
    }
  }
  return valid;
}

// Validate all 3 security questions
function validateSecurityAnswers() {
  let valid = true;
  for (let i = 1; i <= 3; i++) {
    const question = document.querySelector(`select[name="a${i}_question"]`);
    const answer = document.querySelector(`input[name="a${i}_answer"]`);

    if (!question.value) {
      showAnswerError(answer, "❌ Please select a question.");
      valid = false;
    } else if (!answer.value) {
      showAnswerError(answer, "❌ Please enter your answer.");
      valid = false;
    } else if (/^\s|\s$/.test(answer.value) || /\s{2,}/.test(answer.value)) {
      // Checked on the raw value (not trimmed) so a space is caught and
      // rejected, not silently stripped — same rule used on every other field.
      showAnswerError(answer, "❌ Answer cannot have leading, trailing, or repeated spaces.");
      valid = false;
    } else if (/[<>]/.test(answer.value)) {
      // Same rule/wording as the server and the Superadmin create-account form.
      showAnswerError(answer, "❌ Answer: Special characters are not allowed.");
      valid = false;
    } else {
      clearAnswerError(answer);
    }

    // Save current values in sessionStorage
    sessionStorage.setItem(`a${i}_question`, question.value);
    sessionStorage.setItem(`a${i}_answer`, answer.value);
  }

  if (valid && !validateSecurityQuestionsDistinct()) {
    valid = false;
  }

  return valid;
}

// Restore input values on page load
function restoreSecurityAnswers() {
  for (let i = 1; i <= 3; i++) {
    const question = document.querySelector(`select[name="a${i}_question"]`);
    const answer = document.querySelector(`input[name="a${i}_answer"]`);
    if (!question || !answer) continue;

    const savedQ = sessionStorage.getItem(`a${i}_question`);
    const savedA = sessionStorage.getItem(`a${i}_answer`);

    if (savedQ) question.value = savedQ;
    if (savedA) answer.value = savedA;
  }
}

// Submit-time validation for these fields runs from password_register.js's
// single consolidated submit handler (it calls validateSecurityAnswers()
// directly) — this file only restores/wires the live behavior.
document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("registerForm");
  if (!form) return;

  restoreSecurityAnswers(); // Restore saved values

    // Live save + auto-clear "please select question" error
    for (let i = 1; i <= 3; i++) {
    const question = document.querySelector(`select[name="a${i}_question"]`);
    const answer = document.querySelector(`input[name="a${i}_answer"]`);
    if (!question || !answer) continue;

    // When question changes
    question.addEventListener("change", () => {
      sessionStorage.setItem(`a${i}_question`, question.value);

      // Clear only question-related error
      if (question.value) {
        const box = document.getElementById(`answer_error_${answer.name}`);
        if (box && box.textContent.includes("Please select a question")) {
          box.textContent = ""; 
          box.style.display = "none";
          question.classList.add("is-valid");
          question.classList.remove("is-invalid");
        }
      }
    });

    // When answer is typed
    answer.addEventListener("input", () => {
      sessionStorage.setItem(`a${i}_answer`, answer.value);

      // Spacing/special-character checks run immediately on every keystroke,
      // wherever they appear in the field — same rule/wording used everywhere else.
      if (/^\s|\s$/.test(answer.value) || /\s{2,}/.test(answer.value)) {
        showAnswerError(answer, "❌ Answer cannot have leading, trailing, or repeated spaces.");
        return;
      }
      if (/[<>]/.test(answer.value)) {
        showAnswerError(answer, "❌ Answer: Special characters are not allowed.");
        return;
      }

      // Clear only answer-related error
      if (answer.value.trim()) {
        const box = document.getElementById(`answer_error_${answer.name}`);
        if (box && (box.textContent.includes("Please enter your answer") || box.textContent.includes("Special characters are not allowed") || box.textContent.includes("leading, trailing, or repeated spaces"))) {
          box.textContent = "";
          box.style.display = "none";
          answer.classList.add("is-valid");
          answer.classList.remove("is-invalid");
        }
      }
    });
  }


});
