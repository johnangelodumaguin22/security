// Shared by otp_verify.php and forgot_password_otp.php: 6-box OTP input
// auto-advance (each box also works standalone without JS — this is purely
// a convenience layer), plus a client-side resend countdown that mirrors
// the server's cooldown (the server enforces the real limit regardless).
document.addEventListener('DOMContentLoaded', () => {
  const boxes = Array.from(document.querySelectorAll('.otp-box'));
  boxes.forEach((box, i) => {
    box.addEventListener('input', () => {
      box.value = box.value.replace(/\D/g, '').slice(0, 1);
      if (box.value && boxes[i + 1]) boxes[i + 1].focus();
    });
    box.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !box.value && boxes[i - 1]) {
        boxes[i - 1].focus();
      }
    });
    box.addEventListener('paste', (e) => {
      const text = (e.clipboardData || window.clipboardData).getData('text').replace(/\D/g, '');
      if (text.length > 1) {
        e.preventDefault();
        text.split('').slice(0, boxes.length).forEach((ch, idx) => {
          if (boxes[idx]) boxes[idx].value = ch;
        });
        const next = boxes[Math.min(text.length, boxes.length - 1)];
        if (next) next.focus();
      }
    });
  });
  if (boxes[0]) boxes[0].focus();

  const resendBtn = document.getElementById('resendBtn');
  const resendForm = document.getElementById('resendForm');
  if (resendBtn && resendForm) {
    let seconds = 60;
    const originalLabel = resendBtn.textContent;
    const tick = () => {
      if (seconds <= 0) {
        resendBtn.disabled = false;
        resendBtn.textContent = originalLabel;
        return;
      }
      resendBtn.disabled = true;
      resendBtn.textContent = `Resend OTP in ${seconds}s`;
      seconds--;
      setTimeout(tick, 1000);
    };
    tick();
    resendForm.addEventListener('submit', () => {
      seconds = 60;
    });
  }
});
