const roleButtons = document.querySelectorAll('.role-btn');
const panels = document.querySelectorAll('.panel');
const threatPill = document.getElementById('threat-pill');
const trustScore = document.getElementById('trust-score');
const consentResult = document.getElementById('consent-result');

roleButtons.forEach((btn) => {
  btn.addEventListener('click', () => {
    roleButtons.forEach((b) => b.classList.remove('active'));
    panels.forEach((panel) => panel.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(btn.dataset.role).classList.add('active');
  });
});

document.getElementById('simulate-fix').addEventListener('click', () => {
  alert('VICT Co-pilot applied policy patch suggestions and generated least-privilege IAM diff.');
});

document.getElementById('kill-switch').addEventListener('click', () => {
  threatPill.textContent = 'Threat Level: Contained';
  trustScore.textContent = '100.0';
  alert('RBI Kill-Switch activated: all non-India payment data paths have been revoked.');
});

document.querySelectorAll('.revoke').forEach((btn) => {
  btn.addEventListener('click', () => {
    btn.textContent = 'Revoked';
    btn.disabled = true;
    btn.style.opacity = '0.7';
  });
});

document.getElementById('agree').addEventListener('click', () => {
  consentResult.textContent = 'Consent granted. Function execution allowed by gateway.';
  consentResult.style.color = '#71ebb4';
});

document.getElementById('deny').addEventListener('click', () => {
  consentResult.textContent = 'Consent denied. Function blocked before runtime invocation.';
  consentResult.style.color = '#ff8b7c';
});
