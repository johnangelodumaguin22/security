// Progressive enhancement only — every action in the admin/superadmin
// dashboards is a plain <form method="post"> and works with JS disabled.
// This just adds a confirmation prompt before the more destructive ones.
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('form[data-confirm]').forEach(form => {
    form.addEventListener('submit', (e) => {
      const message = form.getAttribute('data-confirm');
      if (message && !confirm(message)) {
        e.preventDefault();
      }
    });
  });
});

// Shared by both dashboards' "Request Delete"/"Delete Account" modal —
// populated from whichever row's button opened it (data-id/data-name), so
// there's one modal in the DOM instead of one per row. The password field
// (deleteRequestPassword) only exists on superadmin_dashboard.php's copy
// (an immediate delete needs it; admin_dashboard.php's is just a request for
// Superadmin review, so it has no such field) — passwordField is simply null
// there and every reference below is guarded, so this same script handles
// both pages safely.
document.addEventListener('DOMContentLoaded', () => {
  const modalEl = document.getElementById('deleteRequestModal');
  if (!modalEl || typeof bootstrap === 'undefined') return;

  const idField = document.getElementById('deleteRequestId');
  const targetLabel = document.getElementById('deleteRequestTarget');
  const reasonField = document.getElementById('deleteRequestReason');
  const countLabel = document.getElementById('deleteRequestCount');
  const passwordField = document.getElementById('deleteRequestPassword');

  modalEl.addEventListener('show.bs.modal', (event) => {
    const btn = event.relatedTarget;
    if (!btn) return;
    if (idField) idField.value = btn.getAttribute('data-id') || '';
    if (targetLabel) targetLabel.textContent = btn.getAttribute('data-name') || '';
    if (reasonField) reasonField.value = '';
    if (countLabel) countLabel.textContent = '0 / 500 characters';
    if (passwordField) passwordField.value = '';
  });

  modalEl.addEventListener('shown.bs.modal', () => {
    if (reasonField) reasonField.focus();
  });

  if (reasonField && countLabel) {
    reasonField.addEventListener('input', () => {
      countLabel.textContent = `${reasonField.value.length} / 500 characters`;
    });
  }
});

// Superadmin dashboard only: the single shared "Change Role" modal (covers
// both Promote and Demote) is populated from whichever row's "Change Role"
// button opened it. The target role and its label are fixed server-side
// (data-new-role/data-new-role-label) — never computed or editable in the
// browser — this JS only displays them and resets the password field so a
// previous row's typed password can never carry over into this one.
document.addEventListener('DOMContentLoaded', () => {
  const modalEl = document.getElementById('changeRoleModal');
  if (!modalEl || typeof bootstrap === 'undefined') return;

  const idField = document.getElementById('changeRoleId');
  const newRoleField = document.getElementById('changeRoleNewRole');
  const targetLabel = document.getElementById('changeRoleTarget');
  const currentRoleLabel = document.getElementById('changeRoleCurrentRole');
  const newRoleLabel = document.getElementById('changeRoleNewRoleLabel');
  const titleEl = document.getElementById('changeRoleTitle');
  const warningEl = document.getElementById('changeRoleWarning');
  const submitBtn = document.getElementById('changeRoleSubmit');
  const passwordField = document.getElementById('changeRolePassword');
  const reasonField = document.getElementById('changeRoleReason');
  const countLabel = document.getElementById('changeRoleReasonCount');

  modalEl.addEventListener('show.bs.modal', (event) => {
    const btn = event.relatedTarget;
    if (!btn) return;
    const newRole = btn.getAttribute('data-new-role') || '';
    const newRoleDisplay = btn.getAttribute('data-new-role-label') || '';

    if (idField) idField.value = btn.getAttribute('data-id') || '';
    if (newRoleField) newRoleField.value = newRole;
    if (targetLabel) targetLabel.textContent = btn.getAttribute('data-name') || '';
    if (currentRoleLabel) currentRoleLabel.textContent = btn.getAttribute('data-current-role') || '';
    if (newRoleLabel) newRoleLabel.textContent = newRoleDisplay;
    if (passwordField) passwordField.value = '';
    if (reasonField) reasonField.value = '';
    if (countLabel) countLabel.textContent = '0 / 500 characters';

    const isDemote = newRole === 'admin';
    if (titleEl) {
      titleEl.innerHTML = isDemote
        ? '<i class="bi bi-arrow-down-circle-fill icon-warning"></i> Demote to Admin?'
        : '<i class="bi bi-arrow-up-circle-fill icon-success"></i> Promote to Superadmin?';
    }
    if (submitBtn) submitBtn.textContent = isDemote ? 'Demote to Admin' : 'Promote to Superadmin';
    if (warningEl) {
      warningEl.style.display = 'block';
      warningEl.textContent = isDemote
        ? 'This will immediately remove ALL Superadmin privileges from this account.'
        : 'This will immediately grant full Superadmin access to every module.';
    }
  });

  if (reasonField && countLabel) {
    reasonField.addEventListener('input', () => {
      countLabel.textContent = `${reasonField.value.length} / 500 characters`;
    });
  }
});

// Superadmin dashboard only: the single shared "Block Account" modal is
// populated from whichever row's "Block" button opened it (data-id/
// data-name), used from both the Accounts view and the Registration
// Approval view. Resets the password and reason fields every time it opens
// so a previous row's typed values can never carry over into this one.
document.addEventListener('DOMContentLoaded', () => {
  const modalEl = document.getElementById('blockAccountModal');
  if (!modalEl || typeof bootstrap === 'undefined') return;

  const idField = document.getElementById('blockAccountId');
  const targetLabel = document.getElementById('blockAccountTarget');
  const passwordField = document.getElementById('blockAccountPassword');
  const reasonField = document.getElementById('blockAccountReason');
  const countLabel = document.getElementById('blockAccountReasonCount');

  modalEl.addEventListener('show.bs.modal', (event) => {
    const btn = event.relatedTarget;
    if (!btn) return;
    if (idField) idField.value = btn.getAttribute('data-id') || '';
    if (targetLabel) targetLabel.textContent = btn.getAttribute('data-name') || '';
    if (passwordField) passwordField.value = '';
    if (reasonField) reasonField.value = '';
    if (countLabel) countLabel.textContent = '0 / 500 characters';
  });

  modalEl.addEventListener('shown.bs.modal', () => {
    if (reasonField) reasonField.focus();
  });

  if (reasonField && countLabel) {
    reasonField.addEventListener('input', () => {
      countLabel.textContent = `${reasonField.value.length} / 500 characters`;
    });
  }
});

// Superadmin dashboard only: the single shared "Unblock Account" modal is
// populated from whichever row's "Unblock" button opened it (data-id/
// data-name), same pattern as Block Account above but without a password
// field (unblocking only restores access).
document.addEventListener('DOMContentLoaded', () => {
  const modalEl = document.getElementById('unblockAccountModal');
  if (!modalEl || typeof bootstrap === 'undefined') return;

  const idField = document.getElementById('unblockAccountId');
  const targetLabel = document.getElementById('unblockAccountTarget');
  const reasonField = document.getElementById('unblockAccountReason');
  const countLabel = document.getElementById('unblockAccountReasonCount');

  modalEl.addEventListener('show.bs.modal', (event) => {
    const btn = event.relatedTarget;
    if (!btn) return;
    if (idField) idField.value = btn.getAttribute('data-id') || '';
    if (targetLabel) targetLabel.textContent = btn.getAttribute('data-name') || '';
    if (reasonField) reasonField.value = '';
    if (countLabel) countLabel.textContent = '0 / 500 characters';
  });

  modalEl.addEventListener('shown.bs.modal', () => {
    if (reasonField) reasonField.focus();
  });

  if (reasonField && countLabel) {
    reasonField.addEventListener('input', () => {
      countLabel.textContent = `${reasonField.value.length} / 500 characters`;
    });
  }
});

// Superadmin dashboard only: the single shared "Unblock Account" modal
// (Admin/Superadmin) is populated from whichever row's button opened it
// (data-id/data-name/data-prev-role), same pattern as the Request Delete
// modal above. The role <select> and reason are reset every time it opens,
// so a leftover choice/text from a previous row can never carry over.
document.addEventListener('DOMContentLoaded', () => {
  const modalEl = document.getElementById('reactivateModal');
  if (!modalEl || typeof bootstrap === 'undefined') return;

  const idField = document.getElementById('reactivateId');
  const targetLabel = document.getElementById('reactivateTarget');
  const prevRoleLabel = document.getElementById('reactivatePrevRole');
  const roleSelect = document.getElementById('reactivateRole');
  const reasonField = document.getElementById('reactivateReason');
  const countLabel = document.getElementById('reactivateReasonCount');
  const passwordField = document.getElementById('reactivatePassword');

  modalEl.addEventListener('show.bs.modal', (event) => {
    const btn = event.relatedTarget;
    if (!btn) return;
    if (idField) idField.value = btn.getAttribute('data-id') || '';
    if (targetLabel) targetLabel.textContent = btn.getAttribute('data-name') || '';
    if (prevRoleLabel) prevRoleLabel.textContent = btn.getAttribute('data-prev-role') || '';
    if (roleSelect) roleSelect.value = '';
    if (reasonField) reasonField.value = '';
    if (countLabel) countLabel.textContent = '0 / 500 characters';
    if (passwordField) passwordField.value = '';
  });

  if (reasonField && countLabel) {
    reasonField.addEventListener('input', () => {
      countLabel.textContent = `${reasonField.value.length} / 500 characters`;
    });
  }
});

// Superadmin dashboard only: Login Logs' "View" modal is entirely read-only
// and entirely populated from the triggering row's data-* attributes — no
// server round-trip needed, the row already has everything the modal shows.
document.addEventListener('DOMContentLoaded', () => {
  const modalEl = document.getElementById('loginLogModal');
  if (!modalEl || typeof bootstrap === 'undefined') return;

  const fields = {
    user: document.getElementById('loginLogUser'),
    username: document.getElementById('loginLogUsername'),
    role: document.getElementById('loginLogRole'),
    status: document.getElementById('loginLogStatus'),
    device: document.getElementById('loginLogDevice'),
    login: document.getElementById('loginLogLoginTime'),
    logout: document.getElementById('loginLogLogoutTime'),
    duration: document.getElementById('loginLogDuration'),
    lastaction: document.getElementById('loginLogLastAction'),
  };

  modalEl.addEventListener('show.bs.modal', (event) => {
    const btn = event.relatedTarget;
    if (!btn) return;
    Object.keys(fields).forEach((key) => {
      if (fields[key]) fields[key].textContent = btn.getAttribute('data-' + key) || '—';
    });
  });
});

// Admin Privileges matrix (superadmin_dashboard.php): checking a module's
// top-level checkbox is a convenience that auto-checks its action checkboxes;
// the server only ever looks at whichever checkboxes actually get submitted.
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.perm-module').forEach(module => {
    const moduleCheckbox = module.querySelector('.perm-module-checkbox');
    const actionCheckboxes = module.querySelectorAll('.perm-action-checkbox');
    if (!moduleCheckbox) return;

    moduleCheckbox.addEventListener('change', () => {
      if (!moduleCheckbox.checked) {
        actionCheckboxes.forEach(cb => { cb.checked = false; });
      }
    });
    actionCheckboxes.forEach(cb => {
      cb.addEventListener('change', () => {
        if (cb.checked) moduleCheckbox.checked = true;
      });
    });
  });
});

// Change Username / Change Password modals (My Profile, self-service):
// replaces the browser's native "Please fill out this field" bubble with the
// app's own inline error styling, and gives the New Username field the same
// live format check as the Create Account form (see create_account_validate.js
// / validateBareAccountCreation() in registration_helpers.php) — required,
// no spaces, letters/digits/._ only, must start with a letter, 5-30 chars.
document.addEventListener('DOMContentLoaded', () => {
  function wireForm(formId, checks) {
    const form = document.getElementById(formId);
    if (!form) return;

    function errorBoxFor(input) {
      const id = input.id + '_secError';
      let box = document.getElementById(id);
      if (box) return box;
      box = document.createElement('div');
      box.id = id;
      box.className = 'err';
      input.insertAdjacentElement('afterend', box);
      return box;
    }
    function showError(input, message) {
      const box = errorBoxFor(input);
      box.textContent = message;
      box.style.display = 'block';
      input.classList.add('is-invalid');
      input.classList.remove('is-valid');
    }
    function clearError(input) {
      const box = errorBoxFor(input);
      box.textContent = '';
      box.style.display = 'none';
      input.classList.remove('is-invalid');
      input.classList.add('is-valid');
    }

    const runners = [];
    checks.forEach(({ id, validate }) => {
      const input = document.getElementById(id);
      if (!input) return;
      const run = () => {
        const result = validate(input.value, form);
        if (result === true) { clearError(input); return true; }
        showError(input, result);
        return false;
      };
      input.addEventListener('input', run);
      input.addEventListener('blur', run);
      runners.push(run);
    });

    form.addEventListener('submit', (e) => {
      const results = runners.map(run => run());
      if (results.includes(false)) {
        e.preventDefault();
      }
    });

    // Re-run validation fresh each time the modal opens, and clear any
    // leftover error state from a previous open (e.g. a cancelled attempt).
    const modalEl = form.closest('.modal');
    if (modalEl) {
      modalEl.addEventListener('show.bs.modal', () => {
        checks.forEach(({ id }) => {
          const input = document.getElementById(id);
          if (!input) return;
          input.classList.remove('is-invalid', 'is-valid');
          const box = document.getElementById(id + '_secError');
          if (box) box.style.display = 'none';
        });
      });
    }
  }

  function validateUsernameFormat(value) {
    if (!value) return '❌ Username is required.';
    if (/\s/.test(value)) return '❌ Username: Spaces are not allowed.';
    if (/[^A-Za-z0-9_.]/.test(value)) return '❌ Username: Special characters are not allowed.';
    if (!/^[A-Za-z]/.test(value)) return '❌ Username must start with a letter.';
    if (value.length < 5 || value.length > 30) return '❌ Username must be between 5 and 30 characters.';
    if (!/[A-Z]/.test(value)) return '❌ Username must contain at least one uppercase letter.';
    if (!/[0-9]/.test(value)) return '❌ Username must contain at least one number.';
    if (!/[_.]/.test(value)) return '❌ Username must contain at least one special character (_ or .).';
    return true;
  }

  wireForm('changeUsernameForm', [
    { id: 'changeUsernameInput', validate: validateUsernameFormat },
  ]);

  wireForm('changePasswordForm', [
    { id: 'changePasswordNew', validate: (value) => {
        if (!value) return '❌ New password is required.';
        if (value.length < 8 || value.length > 72) return '❌ Password must be between 8 and 72 characters.';
        return true;
      } },
    { id: 'changePasswordConfirm', validate: (value) => {
        if (!value) return '❌ Please confirm your new password.';
        const newPw = document.getElementById('changePasswordNew');
        if (newPw && value !== newPw.value) return '❌ Passwords do not match.';
        return true;
      } },
  ]);
});

// -----------------------------------------------------------------
// Shared "Enter Your Password to Confirm" modal (#pwConfirmModal) — every
// sensitive Superadmin action on this page (Create Account, Block, Delete,
// Change Role, Change Username, Change Password) funnels its own password
// field through this single dedicated modal instead of embedding a password
// input inside that action's own modal. Clicking an action's Confirm/Submit
// button hides that action's modal (if any) and opens this one; confirming
// here copies the typed password into the originating form's hidden
// current_password field and resubmits that form for real.
// -----------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  const modalEl = document.getElementById('pwConfirmModal');
  if (!modalEl || typeof bootstrap === 'undefined') return;

  const pwInput = document.getElementById('pwConfirmInput');
  const errBox = document.getElementById('pwConfirmError');
  const confirmBtn = document.getElementById('pwConfirmBtn');
  let pendingForm = null;
  let pendingField = null;

  modalEl.addEventListener('shown.bs.modal', () => {
    if (pwInput) pwInput.focus();
  });

  // Reset on every open, whichever action triggered it — a previous action's
  // typed password (or leftover error) must never carry over into this one.
  modalEl.addEventListener('show.bs.modal', () => {
    if (pwInput) pwInput.value = '';
    if (errBox) { errBox.style.display = 'none'; errBox.textContent = ''; }
  });

  if (confirmBtn) {
    confirmBtn.addEventListener('click', () => {
      const value = pwInput ? pwInput.value : '';
      if (!value) {
        if (errBox) { errBox.textContent = '❌ Please enter your password.'; errBox.style.display = 'block'; }
        if (pwInput) pwInput.focus();
        return;
      }
      if (pendingField) pendingField.value = value;
      const modal = bootstrap.Modal.getInstance(modalEl);
      if (modal) modal.hide();
      if (pendingForm) {
        pendingForm.dataset.pwConfirmed = '1';
        if (pendingForm.requestSubmit) pendingForm.requestSubmit(); else pendingForm.submit();
      }
    });
  }

  // Exposed so any form on this page (including create_account_validate.js,
  // a separate file) can gate its own submit behind this same shared modal.
  // `form` is the form to eventually submit; `hiddenField` is that form's
  // own hidden current_password input the typed value gets copied into.
  window.openPasswordConfirmModal = function (form, hiddenField) {
    pendingForm = form;
    pendingField = hiddenField;
    bootstrap.Modal.getOrCreateInstance(modalEl).show();
  };
});

// Gates a form's submit behind the shared password-confirm modal above.
// Runs the form's own native validity check first (required/minlength/etc.
// on its other fields) — an earlier custom validator (e.g. wireForm() above)
// that already called preventDefault() short-circuits this via
// e.defaultPrevented, so the two never fight over the same submit event.
document.addEventListener('DOMContentLoaded', () => {
  function requirePasswordConfirm(formId, hiddenFieldId) {
    const form = document.getElementById(formId);
    const hiddenField = document.getElementById(hiddenFieldId);
    if (!form || !hiddenField) return;

    form.addEventListener('submit', (e) => {
      if (form.dataset.pwConfirmed === '1') {
        delete form.dataset.pwConfirmed;
        return;
      }
      if (e.defaultPrevented) return;
      if (typeof window.openPasswordConfirmModal !== 'function') return;
      if (!form.checkValidity()) {
        e.preventDefault();
        form.reportValidity();
        return;
      }
      e.preventDefault();

      const actionModalEl = form.closest('.modal');
      if (actionModalEl && typeof bootstrap !== 'undefined') {
        const actionModal = bootstrap.Modal.getInstance(actionModalEl);
        if (actionModal) {
          actionModalEl.addEventListener('hidden.bs.modal', () => {
            window.openPasswordConfirmModal(form, hiddenField);
          }, { once: true });
          actionModal.hide();
          return;
        }
      }
      window.openPasswordConfirmModal(form, hiddenField);
    });
  }

  requirePasswordConfirm('blockAccountForm', 'blockAccountPassword');
  requirePasswordConfirm('deleteRequestForm', 'deleteRequestPassword');
  requirePasswordConfirm('changeRoleForm', 'changeRolePassword');
  requirePasswordConfirm('changeUsernameForm', 'changeUsernamePassword');
  requirePasswordConfirm('changePasswordForm', 'changePasswordCurrent');
  requirePasswordConfirm('reactivateForm', 'reactivatePassword');
  requirePasswordConfirm('editMyProfileForm', 'editMyProfilePassword');
});

// admin_dashboard.php only: reopen the "Edit Profile" modal automatically
// after a failed save_own_profile submission (wrong password or a field
// validation error) — otherwise the page reload would silently drop the
// Admin back on the bare My Profile view with no visible way to see which
// field needs fixing. Set by the server in window.REOPEN_EDIT_PROFILE_MODAL.
document.addEventListener('DOMContentLoaded', () => {
  if (typeof window.REOPEN_EDIT_PROFILE_MODAL === 'undefined' || !window.REOPEN_EDIT_PROFILE_MODAL) return;
  const modalEl = document.getElementById('editMyProfileModal');
  if (modalEl && typeof bootstrap !== 'undefined') {
    bootstrap.Modal.getOrCreateInstance(modalEl).show();
  }
});

// admin_dashboard.php only: same reopen-on-wrong-password behavior for
// Change Username / Change Password (My Profile > Account Security) — set
// by the server in window.REOPEN_CHANGE_USERNAME_MODAL/
// REOPEN_CHANGE_PASSWORD_MODAL only when current_password was wrong, so the
// Admin doesn't have to re-navigate and re-click the button to try again.
document.addEventListener('DOMContentLoaded', () => {
  if (typeof window.REOPEN_CHANGE_USERNAME_MODAL !== 'undefined' && window.REOPEN_CHANGE_USERNAME_MODAL) {
    const modalEl = document.getElementById('changeUsernameModal');
    if (modalEl && typeof bootstrap !== 'undefined') bootstrap.Modal.getOrCreateInstance(modalEl).show();
  }
  if (typeof window.REOPEN_CHANGE_PASSWORD_MODAL !== 'undefined' && window.REOPEN_CHANGE_PASSWORD_MODAL) {
    const modalEl = document.getElementById('changePasswordModal');
    if (modalEl && typeof bootstrap !== 'undefined') bootstrap.Modal.getOrCreateInstance(modalEl).show();
  }
});

// Change Username/Password's email-verification-code modals: digits-only
// input, and auto-open whichever one has a code pending (set by the server
// in window.AWAITING_USERNAME_OTP/AWAITING_PASSWORD_OTP) so the flow
// continues straight to "enter the code" instead of just showing a flash
// message the user has to notice and act on themselves.
document.addEventListener('DOMContentLoaded', () => {
  ['confirmUsernameOtpInput', 'confirmPasswordOtpInput'].forEach((id) => {
    const input = document.getElementById(id);
    if (!input) return;
    input.addEventListener('input', () => {
      input.value = input.value.replace(/\D/g, '').slice(0, 6);
    });
  });

  if (typeof bootstrap === 'undefined') return;

  if (window.AWAITING_USERNAME_OTP) {
    const el = document.getElementById('confirmUsernameOtpModal');
    if (el) new bootstrap.Modal(el).show();
  }
  if (window.AWAITING_PASSWORD_OTP) {
    const el = document.getElementById('confirmPasswordOtpModal');
    if (el) new bootstrap.Modal(el).show();
  }
});

// Wrong "Current Password" on Change Username/Password: reopen that modal
// instead of leaving the visitor to spot a generic banner at the top of the
// page. current_password is a hidden field (collected via the shared
// #pwConfirmModal, not inline here), so there's no field to mark invalid or
// focus directly — reopening the modal is the whole fix; the flash banner
// above already states the reason.
document.addEventListener('DOMContentLoaded', () => {
  if (window.USERNAME_CHANGE_PASSWORD_ERROR) {
    const modalEl = document.getElementById('changeUsernameModal');
    if (modalEl && typeof bootstrap !== 'undefined') bootstrap.Modal.getOrCreateInstance(modalEl).show();
  }
  if (window.PASSWORD_CHANGE_PASSWORD_ERROR) {
    const modalEl = document.getElementById('changePasswordModal');
    if (modalEl && typeof bootstrap !== 'undefined') bootstrap.Modal.getOrCreateInstance(modalEl).show();
  }
});
