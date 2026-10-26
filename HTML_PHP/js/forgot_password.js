// JS/forgot_password.js
// Handles the reset-flow modal, asterisk-only masking for every typed field,
// disables paste, and password strength UI.

// -----------------------------------------------------------------
// Asterisk-only masking by default. Every character typed into a `.fp-mask`
// field is shown on screen only as "*" unless its paired eye icon
// (.toggle-eye[data-target]) is clicked to reveal it in plain text. The real
// text is tracked in memory (via getRealValue/setRealValue/toggleReveal on
// the element) and is swapped back into the field's .value right before its
// form actually submits, so the backend still receives the real typed value
// unchanged regardless of masked/revealed display state.
//
// Built on `beforeinput` (not `input`) so we fully control what lands in
// the field, including mid-string edits (caret not always at the end) and
// pasted text (fires as inputType "insertFromPaste" with the pasted text in
// e.data on current browsers) — a plain `input` listener can only react
// after the browser already changed .value, which is exactly what we can't
// allow here.
// -----------------------------------------------------------------
function maskifyInput(input) {
  if (!input || input._maskified) return;
  input._maskified = true;
  input.type = 'text';
  input.autocomplete = 'off';
  input.setAttribute('autocapitalize', 'off');
  input.setAttribute('autocorrect', 'off');
  input.setAttribute('spellcheck', 'false');

  let real = input.value || '';
  let revealed = false;
  const maxLen = (input.maxLength && input.maxLength > 0) ? input.maxLength : Infinity;
  const render = () => { input.value = revealed ? real : '*'.repeat(real.length); };
  render();

  input.addEventListener('beforeinput', (e) => {
    e.preventDefault();
    const start = input.selectionStart ?? real.length;
    const end = input.selectionEnd ?? real.length;
    const type = e.inputType || '';
    let caret = start;

    if (type.startsWith('insert')) {
      const insert = (e.data != null) ? e.data : '';
      if (!insert) return;
      const room = maxLen - (real.length - (end - start));
      const toInsert = insert.slice(0, Math.max(0, room));
      real = real.slice(0, start) + toInsert + real.slice(end);
      caret = start + toInsert.length;
    } else if (type === 'deleteContentBackward') {
      if (start !== end) { real = real.slice(0, start) + real.slice(end); caret = start; }
      else if (start > 0) { real = real.slice(0, start - 1) + real.slice(start); caret = start - 1; }
      else return;
    } else if (type === 'deleteContentForward') {
      if (start !== end) { real = real.slice(0, start) + real.slice(end); caret = start; }
      else if (start < real.length) { real = real.slice(0, start) + real.slice(start + 1); caret = start; }
      else return;
    } else if (type.startsWith('delete')) {
      if (start === end) return;
      real = real.slice(0, start) + real.slice(end);
      caret = start;
    } else {
      return;
    }

    render();
    input.setSelectionRange(caret, caret);
    // .value assigned by script never fires a native "input" event, so any
    // existing/future listener relying on it (e.g. the strength meter below)
    // would silently stop seeing keystrokes — replay one so they still do.
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });

  input.getRealValue = () => real;
  input.setRealValue = (v) => { real = String(v ?? ''); render(); };
  // Flips masked/plain-text display without touching `real` or the caret
  // logic above (both operate on `real`'s length/positions either way).
  // Returns the new state so the calling eye-icon click handler knows which
  // icon to show. Each field reverts to masked on its own next re-render —
  // nothing auto-hides it again, matching how the icon is normally expected
  // to behave (stays revealed until clicked again).
  input.toggleReveal = () => { revealed = !revealed; render(); return revealed; };
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.fp-mask').forEach(maskifyInput);

  // Show/Hide eye icon paired with each masked field via data-target. Only
  // flips that field's own display — never reveals any other field on the
  // same step.
  document.querySelectorAll('.toggle-eye[data-target]').forEach(btn => {
    btn.addEventListener('click', () => {
      const input = document.getElementById(btn.getAttribute('data-target'));
      if (!input || typeof input.toggleReveal !== 'function') return;
      const isRevealed = input.toggleReveal();
      btn.textContent = isRevealed ? '🙈' : '👁️';
      input.focus();
    });
  });

  // Swap each masked field's visible asterisks back to its real value right
  // before the form actually submits — the backend must keep receiving the
  // real typed text, only the on-screen display is masked.
  document.querySelectorAll('#requestResetForm, #verifyForm, #resetForm').forEach(form => {
    form.addEventListener('submit', () => {
      form.querySelectorAll('.fp-mask').forEach(input => {
        if (typeof input.getRealValue === 'function') input.value = input.getRealValue();
      });
    });
  });
});

document.addEventListener('DOMContentLoaded', () => {
  // The whole reset flow lives inside #fpModal. It opens when the "Reset
  // Password" button is clicked (via data-bs-toggle) and must reopen itself
  // automatically after a PHP POST-back (validation error or step change),
  // since the page reload would otherwise silently drop the visitor back on
  // the bare landing view.
  const fpModalEl = document.getElementById('fpModal');
  let fpModal;
  if (fpModalEl && typeof bootstrap !== 'undefined') {
    fpModal = bootstrap.Modal.getOrCreateInstance(fpModalEl, { backdrop: 'static' });
    if (typeof AUTO_OPEN_MODAL !== 'undefined' && AUTO_OPEN_MODAL) {
      fpModal.show();
    }
    fpModalEl.addEventListener('shown.bs.modal', () => {
      const firstInput = fpModalEl.querySelector('input:not([disabled])');
      if (firstInput) firstInput.focus();
    });

    // Closing the modal (the X button, or Escape) before finishing must not
    // leave a resumable session behind — reopening later (or reloading) has
    // to start over from Step 1. `hidden.bs.modal` only fires from an actual
    // user-initiated close during this page view, never from the PHP-driven
    // auto-reopen on the next load, so this can't misfire on a normal step
    // transition. Skipped entirely on the very first step (nothing to cancel
    // yet) and after a successful reset (session is already clear by then).
    fpModalEl.addEventListener('hidden.bs.modal', () => {
      if (typeof PHP_STAGE === 'undefined') return;
      if (PHP_STAGE === 'enter_id' || PHP_STAGE === 'enter_email' || PHP_STAGE === 'done') return;

      const csrfInput = fpModalEl.querySelector('input[name="csrf_token"]');
      const fd = new FormData();
      fd.append('action', 'cancel_reset');
      fd.append('csrf_token', csrfInput ? csrfInput.value : '');
      fetch('', { method: 'POST', body: fd, keepalive: true }).catch(() => {});
    });
  }

  // Disable paste & right-click into password-style inputs (answers and new password fields)
  const blockPasteSelectors = ['#a1', '#a2', '#a3', '#newPassword', '#confirmPassword'];
  blockPasteSelectors.forEach(sel => {
    const el = document.querySelector(sel);
    if (!el) return;
    el.addEventListener('paste', (ev) => {
      ev.preventDefault();
      Swal.fire({
        icon: 'info',
        title: 'Pasting is disabled for security.',
        timer: 1400,
        showConfirmButton: false,
        toast: true,
        position: 'top'
      });
    });
    el.addEventListener('contextmenu', (ev) => ev.preventDefault());
    el.addEventListener('keydown', (ev) => {
      if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'v') ev.preventDefault();
    });
  });

  // PASSWORD STRENGTH UI (for reset step) — kept light: length + not-a-known-
  // weak-password, no forced character-class mix.
  const newPass = document.getElementById('newPassword');
  const confirmPass = document.getElementById('confirmPassword');
  const resetBtn = document.getElementById('resetBtn');
  const chLen = document.getElementById('chLen');
  const chCommon = document.getElementById('chCommon');
  const strengthFill = document.getElementById('strengthFill');
  const strengthText = document.getElementById('strengthText');

  const COMMON_WEAK_PASSWORDS = [
    'password', 'password1', 'password123', '12345678', '123456789', '1234567890',
    'qwerty123', 'qwertyuiop', 'letmein123', 'iloveyou123', 'admin1234', 'welcome123',
    'changeme123', '00000000', '11111111', 'abc123456', 'passw0rd', 'p@ssw0rd123',
    'trustno1', 'football123', 'baseball123', 'dragon1234', 'monkey1234', 'master1234',
  ];

  function hasLength(p) { return p.length >= 8; }
  function isNotCommon(p) { return p.length > 0 && !COMMON_WEAK_PASSWORDS.includes(p.toLowerCase()); }

  // Reads the real typed text, never the on-screen asterisks — newPass/
  // confirmPass are masked via maskifyInput() above, so .value is always
  // just "*" repeated and would make every one of these checks meaningless.
  function realOf(input) {
    if (!input) return '';
    return (typeof input.getRealValue === 'function') ? input.getRealValue() : (input.value || '');
  }

  function updateStrength() {
    if (!newPass) return;
    const p = realOf(newPass);

    if (chLen) chLen.textContent = (hasLength(p) ? '✅' : '❌') + ' At least 8 characters';
    if (chCommon) chCommon.textContent = (isNotCommon(p) ? '✅' : '❌') + ' Not a commonly used password';

    let score = 0;
    if (hasLength(p)) score++;
    if (isNotCommon(p)) score++;

    const percent = (score / 2) * 100;
    if (strengthFill) strengthFill.style.width = percent + '%';

    if (score <= 0) strengthFill.style.background = '#ff4d4f';
    else if (score === 1) strengthFill.style.background = '#ffa940';
    else strengthFill.style.background = '#52c41a';

    if (score <= 0) strengthText.textContent = 'Too short';
    else if (score === 1) strengthText.textContent = 'Not allowed';
    else strengthText.textContent = 'Looks good';

    // enable reset only when all rules satisfied and both fields match
    const confirmVal = realOf(confirmPass);
    const allGood = (score === 2) && (confirmPass && p === confirmVal && p.length > 0);
    if (resetBtn) resetBtn.disabled = !allGood;
  }

  if (newPass) newPass.addEventListener('input', updateStrength);
  if (confirmPass) confirmPass.addEventListener('input', updateStrength);

  // If the page started in reset stage, ensure strength computed
  if (typeof PHP_STAGE !== 'undefined' && PHP_STAGE === 'reset_password') {
    updateStrength();
  }
});



document.addEventListener('DOMContentLoaded',()=>{
  if(PHP_DONE){
    Swal.fire({icon:'success',title:'Password reset successful',text:'Redirecting to login...',timer:3000,showConfirmButton:false})
      .then(()=>window.location.href='login.php');
    setTimeout(()=>window.location.href='login.php',3500);
  }
});
