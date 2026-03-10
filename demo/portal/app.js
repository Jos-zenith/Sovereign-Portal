const roleButtons = document.querySelectorAll('.role-btn');
const panels = document.querySelectorAll('.panel');
const threatPill = document.getElementById('threat-pill');
const trustScore = document.getElementById('trust-score');
const consentResult = document.getElementById('consent-result');
const auditFeed = document.getElementById('audit-feed');
const invokeResult = document.getElementById('invoke-result');
const hbAllow = document.getElementById('hb-allow');
const hbDeny = document.getElementById('hb-deny');
const hbTotal = document.getElementById('hb-total');
const breachBanner = document.getElementById('breach-banner');

const API_BASE = 'http://127.0.0.1:8080';
const DEMO_PRINCIPAL = 'citizen-001';
const DEMO_PURPOSE = 'gst-location';

async function postJson(path, body) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `HTTP ${response.status}`);
  }

  return response.json();
}

async function refreshAuditFeed() {
  try {
    const response = await fetch(`${API_BASE}/audit/recent?limit=10`);
    if (!response.ok) {
      throw new Error('audit endpoint unavailable');
    }

    const payload = await response.json();
    const events = payload.events || [];

    if (!events.length) {
      auditFeed.innerHTML = '<p>No audit events yet for this session.</p>';
      hbAllow.textContent = '0';
      hbDeny.textContent = '0';
      hbTotal.textContent = '0';
      return;
    }

    const allowCount = events.filter((event) => event.decision === 'allow').length;
    const denyCount = events.filter((event) => event.decision === 'deny').length;
    hbAllow.textContent = String(allowCount);
    hbDeny.textContent = String(denyCount);
    hbTotal.textContent = String(events.length);

    auditFeed.innerHTML = events
      .map((event) => `<p class="${event.decision}">#${event.id} principal=${event.principal_id} purpose=${event.purpose} decision=${event.decision} reason=${event.reason} at=${event.recorded_at}</p>`)
      .join('');
  } catch (error) {
    auditFeed.innerHTML = '<p>Gateway not reachable. Start FastAPI on :8080 for live feed.</p>';
    hbAllow.textContent = '-';
    hbDeny.textContent = '-';
    hbTotal.textContent = '-';
  }
}

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

document.getElementById('invoke-demo').addEventListener('click', async () => {
  try {
    const tokenRes = await fetch(`${API_BASE}/identity/token/${DEMO_PRINCIPAL}`);
    if (!tokenRes.ok) {
      throw new Error('Failed to fetch identity token');
    }
    const tokenData = await tokenRes.json();

    const response = await postJson('/invoke', {
      principal_id: DEMO_PRINCIPAL,
      purpose: DEMO_PURPOSE,
      data_classification: 'personal',
      auth_method: 'passkey',
      assertion_token: tokenData.assertion_token,
      payload: { aadhaar: 'XXXX-XXXX-1234', amount: 5000 },
    });

    invokeResult.textContent = `ALLOWED - ${JSON.stringify(response.result)}`;
    invokeResult.style.color = '#3de489';
  } catch (error) {
    invokeResult.textContent = `BLOCKED - ${error.message}`;
    invokeResult.style.color = '#ff7667';
  }

  await refreshAuditFeed();
});

document.getElementById('simulate-breach').addEventListener('click', async () => {
  breachBanner.classList.remove('show');
  try {
    const tokenRes = await fetch(`${API_BASE}/identity/token/${DEMO_PRINCIPAL}`);
    if (!tokenRes.ok) {
      throw new Error('Failed to fetch identity token');
    }
    const tokenData = await tokenRes.json();

    await postJson('/invoke', {
      principal_id: DEMO_PRINCIPAL,
      purpose: DEMO_PURPOSE,
      data_classification: 'payment',
      auth_method: 'passkey',
      assertion_token: tokenData.assertion_token,
      egress_region: 'us-east-1',
      payload: { account_ref: 'masked-acct', amount: 5000 },
    });

    invokeResult.textContent = 'Unexpected allow: localization guardrail did not trigger';
    invokeResult.style.color = '#ff7667';
  } catch (error) {
    invokeResult.textContent = `BLOCKED - ${error.message}`;
    invokeResult.style.color = '#ff7667';
    breachBanner.classList.add('show');
    setTimeout(() => breachBanner.classList.remove('show'), 2200);
  }

  await refreshAuditFeed();
});

document.getElementById('kill-switch').addEventListener('click', () => {
  threatPill.textContent = 'Threat Level: Contained';
  trustScore.textContent = '100.0';
  alert('RBI Kill-Switch activated: all non-India payment data paths have been revoked.');
});

document.querySelectorAll('.revoke').forEach((btn) => {
  btn.addEventListener('click', async () => {
    try {
      await postJson('/consent/revoke', {
        principal_id: btn.dataset.principal,
        purpose: btn.dataset.purpose,
      });
      btn.textContent = 'Revoked';
      btn.disabled = true;
      btn.style.opacity = '0.7';
      await refreshAuditFeed();
    } catch (error) {
      alert(`Revoke failed: ${error.message}`);
    }
  });
});

document.getElementById('agree').addEventListener('click', async () => {
  try {
    await postJson('/consent/grant', {
      principal_id: DEMO_PRINCIPAL,
      purpose: DEMO_PURPOSE,
    });
    consentResult.textContent = 'Consent granted in vault. Gateway will allow invocation.';
    consentResult.style.color = '#71ebb4';
    await refreshAuditFeed();
  } catch (error) {
    consentResult.textContent = `Consent grant failed: ${error.message}`;
    consentResult.style.color = '#ff8b7c';
  }
});

document.getElementById('deny').addEventListener('click', async () => {
  try {
    await postJson('/consent/revoke', {
      principal_id: DEMO_PRINCIPAL,
      purpose: DEMO_PURPOSE,
    });
    consentResult.textContent = 'Consent denied/revoked. Function blocked before runtime invocation.';
    consentResult.style.color = '#ff8b7c';
    await refreshAuditFeed();
  } catch (error) {
    consentResult.textContent = `Consent revoke failed: ${error.message}`;
    consentResult.style.color = '#ff8b7c';
  }
});

setInterval(refreshAuditFeed, 3000);
refreshAuditFeed();
