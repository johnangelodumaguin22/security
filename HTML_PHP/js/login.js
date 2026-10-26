// ===== Fully Enhanced login.js (Username Version) =====
document.addEventListener("DOMContentLoaded", () => {
  const loginForm = document.getElementById("loginForm");
  const loginBtn = document.getElementById("loginBtn");
  const attemptsBox = document.getElementById("attemptsBox");
  const usernameInput = document.getElementById("username");
  const pwInput = document.getElementById("password");
  const togglePassword = document.getElementById("togglePassword");

  // Server-side variables fallback
  let serverAttempts = (typeof SERVER_ATTEMPTS !== "undefined") ? Number(SERVER_ATTEMPTS) : 0;
  let lockoutUntil = (typeof SERVER_LOCKOUT_UNTIL !== "undefined") ? Number(SERVER_LOCKOUT_UNTIL) : 0;
  const serverTime = (typeof SERVER_TIME !== "undefined") ? Number(SERVER_TIME) : Math.floor(Date.now() / 1000);
  let serverMessage = (typeof SERVER_MESSAGE !== "undefined") ? String(SERVER_MESSAGE) : "";

  // Ensure attemptsBox
  const attemptsBoxEl = attemptsBox || (() => {
    const a = document.createElement("div");
    a.id = "attemptsBox";
    a.style.color = "#b30000";
    a.style.marginBottom = "6px";
    a.style.display = "none";
    if (loginForm) loginForm.insertBefore(a, loginForm.firstChild);
    else document.body.appendChild(a);
    return a;
  })();

  // Ensure Forgot Password link
  const forgotBox = document.getElementById("forgotBox") || (() => {
    const fb = document.createElement("div");
    fb.id = "forgotBox";
    fb.style.display = 'none';
    fb.style.marginTop = '6px';
    
    if (pwInput && pwInput.parentNode) pwInput.parentNode.insertAdjacentElement('afterend', fb);
    else document.body.appendChild(fb);
    return fb;
  })();

  // Ensure countdown text
  const countdownText = document.getElementById("countdownText") || (() => {
    const ct = document.createElement("div");
    ct.id = "countdownText";
    ct.style.marginTop = "8px";
    ct.style.fontSize = "14px";
    ct.style.color = "#b30000";
    if (loginBtn && loginBtn.parentNode) loginBtn.parentNode.insertBefore(ct, loginBtn.nextSibling);
    else document.body.appendChild(ct);
    return ct;
  })();

  // Show server message once
  if (serverMessage) {
    Swal.fire({
      icon: serverMessage.startsWith("🚫") ? 'warning' : (serverMessage.startsWith("❌") ? 'error' : 'info'),
      title: serverMessage,
      toast: true,
      position: 'top',
      timer: 2200,
      showConfirmButton: false
    });
    serverMessage = "";
  }

  // Refresh attempts display
  function refreshAttemptsDisplay() {
    if (serverAttempts > 0) {
      attemptsBoxEl.textContent = `⚠️ Attempts: ${serverAttempts}`;
      attemptsBoxEl.style.display = 'block';
    } else {
      attemptsBoxEl.style.display = 'none';
    }
  }

  // Refresh Forgot Password visibility (visible on 2nd attempt)
  function refreshForgotUI() {
    if (serverAttempts === 2) {
      forgotBox.style.display = 'block';
    } else {
      forgotBox.style.display = 'none';
    }
  }
// Countdown / Lock manager
let countdownInterval = null;
function setLockUI(untilTs) {
  const now = Math.floor(Date.now() / 1000);

  // Grab elements
  const loginBtn = document.getElementById("loginBtn");        // existing login button
  const usernameInput = document.getElementsByName("username")[0];
  const pwInput = document.getElementsByName("password")[0];
  const registerHere = document.getElementById("registerHere"); // <a> link
  const countdownText = document.getElementById("countdownText"); // existing countdown display

  // Helper to disable / enable register link
  const toggleRegister = (disable) => {
    if (!registerHere) return;
    if (disable) {
      registerHere.style.pointerEvents = "none"; // prevent click
      registerHere.style.opacity = "0.5";        // visual cue
    } else {
      registerHere.style.pointerEvents = "auto";
      registerHere.style.opacity = "1";
    }
  };

  if (!untilTs || untilTs <= now) {
    if (countdownInterval) clearInterval(countdownInterval);
    countdownInterval = null;

    // ENABLE everything
    if (loginBtn) loginBtn.disabled = false;
    if (usernameInput) usernameInput.disabled = false;
    if (pwInput) pwInput.disabled = false;
    toggleRegister(false);
    if (countdownText) countdownText.textContent = "";
    refreshForgotUI();
    return;
  }

  // DISABLE all during countdown
    if (loginBtn) loginBtn.disabled = true;
    if (usernameInput) usernameInput.disabled = true;
    if (pwInput) pwInput.disabled = true;
    toggleRegister(true);
    refreshForgotUI();

    const update = () => {
      const now2 = Math.floor(Date.now() / 1000);
      const left = Math.max(0, untilTs - now2);
      if (countdownText) countdownText.innerHTML = `⏳ Try again in <strong>${left} seconds</strong>…`;

      if (left <= 0) {
        clearInterval(countdownInterval);
        countdownInterval = null;

        // ENABLE everything again
        if (loginBtn) loginBtn.disabled = false;
        if (usernameInput) usernameInput.disabled = false;
        if (pwInput) pwInput.disabled = false;
        toggleRegister(false);
        if (countdownText) countdownText.textContent = "";
        refreshForgotUI();
      }
    };

    if (countdownInterval) clearInterval(countdownInterval);
    countdownInterval = setInterval(update, 500);
    update();
  }


  // Initialize UI
  refreshAttemptsDisplay();
  refreshForgotUI();
  const now = Math.floor(Date.now() / 1000);
  if (lockoutUntil && lockoutUntil > now) setLockUI(lockoutUntil);
  else if (loginBtn) loginBtn.disabled = false;

  // Toggle password visibility
  if (togglePassword && pwInput) {
    togglePassword.addEventListener('click', e => {
      e.preventDefault();
      const type = pwInput.getAttribute('type') === 'password' ? 'text' : 'password';
      pwInput.setAttribute('type', type);
      togglePassword.textContent = type === 'password' ? '👁️' : '🙈';
    });
  }

  // Disable paste / Ctrl+V
  if (pwInput) {
    pwInput.addEventListener('paste', e => {
      e.preventDefault();
      Swal.fire({ icon: 'info', title: 'Pasting into the password field is disabled for security.', showConfirmButton: false, timer: 1600, toast: true, position: 'top' });
    });
    pwInput.addEventListener('contextmenu', e => e.preventDefault());
    pwInput.addEventListener('keydown', e => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'v') e.preventDefault();
    });
  }

  // Clear invalid highlight
  if (usernameInput) usernameInput.addEventListener('input', () => usernameInput.classList.remove('is-invalid'));
  if (pwInput) pwInput.addEventListener('input', () => pwInput.classList.remove('is-invalid'));

  // Form submit
  if (loginForm) {
    loginForm.addEventListener('submit', e => {
      const now2 = Math.floor(Date.now() / 1000);
      if (lockoutUntil && now2 < lockoutUntil) {
        e.preventDefault();
        const left = lockoutUntil - now2;
        Swal.fire({ icon: 'warning', title: `Locked. Try again in ${left}s`, toast: true, position: 'top', timer: 1500, showConfirmButton: false });
        return;
      }

      const usernameVal = usernameInput ? usernameInput.value.trim() : '';
      if (usernameVal === '') {
        e.preventDefault();
        if (usernameInput) usernameInput.classList.add('is-invalid');
        Swal.fire({ icon: 'warning', title: 'Username cannot be empty.', toast: true, position: 'top', timer: 1500, showConfirmButton: false });
        return;
      }

      if (loginBtn) {
        loginBtn.disabled = true;
        setTimeout(() => { if (loginBtn) loginBtn.disabled = false; }, 1200);
      }
    });
  }

  // Helper API for dynamic update
  window.loginUI = {
    refreshFromServer: function(newAttempts, newLockoutUntil) {
      serverAttempts = Number(newAttempts || 0);
      lockoutUntil = Number(newLockoutUntil || 0);
      refreshAttemptsDisplay();
      refreshForgotUI();
      setLockUI(lockoutUntil > Math.floor(Date.now()/1000) ? lockoutUntil : 0);
    }
  };
});


