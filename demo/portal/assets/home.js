/* Home page: the loan-file simulator, run against the live gateway. */
(function () {
  const { el, post, api, stamp, route, REASONS } = window.VICT;
  const out = document.getElementById('sim-out');
  const list = document.getElementById('sim-choices');
  if (!out || !list) return;

  const BASE = { principal_id: 'borrower-001', purpose: 'loan-eligibility', token_host: 'bureau.example.in', target_host: 'bureau.example.in' };

  const CHOICES = [
    {
      title: 'Pull the credit score',
      note: 'Bureau, for the loan check the borrower agreed to',
      call: BASE,
      why: 'Consent covers loan-eligibility, the bureau is approved, and the token names it. The proxy opens an encrypted tunnel it cannot read.',
    },
    {
      title: 'Hand the profile to marketing',
      note: 'Same borrower, purpose: marketing',
      call: { ...BASE, purpose: 'marketing' },
      why: 'Consent was given for a loan check. Reusing it for a cross-sell is a different purpose, so no token is issued and nothing touches the network.',
    },
    {
      title: 'Let the analytics SDK send it',
      note: 'Valid consent, but the code connects to analytics.example.com',
      call: { ...BASE, target_host: 'analytics.example.com' },
      why: 'The token was genuine. The code went somewhere else. The proxy checks the destination, not the developer\'s intent.',
      danger: true,
    },
    {
      title: 'Consent says bureau, code calls the AA',
      note: 'Token for bureau.example.in, connection to aa.example.in',
      call: { ...BASE, target_host: 'aa.example.in' },
      why: 'Both hosts are approved vendors, but this token only names the bureau. Consent is bound to the vendor as well as the purpose.',
      danger: true,
    },
  ];

  let busy = false;

  function waking() {
    out.replaceChildren(el('div', { class: 'sim-placeholder' },
      el('span', { class: 'big' }, 'Waking the demo server…'),
      'It runs on a free instance that sleeps when idle. The first call can take about a minute.'));
  }

  function render(choice, result, latest) {
    const allowed = result.allowed;
    const host = choice.call.target_host;
    const title = allowed
      ? `Sent to ${host}.`
      : (result.stage === 'consent-authority' ? 'Stopped before any network call.' : `Stopped before reaching ${host}.`);
    out.replaceChildren(
      el('div', { class: 'verdict-row' },
        allowed ? stamp('good', 'Allowed', 'स्वीकृत') : stamp('bad', 'Blocked', 'अस्वीकृत'),
        el('p', { class: 'verdict-title' }, title)),
      route(result.stage, allowed, host),
      el('div', { class: 'reason-box' },
        el('code', {}, result.reason),
        el('p', {}, REASONS[result.reason] || '')),
      el('p', { class: 'muted', style: 'margin:0' }, choice.why),
      el('p', { class: 'small faint', style: 'margin:0' },
        latest ? `Written to the ledger as entry #${latest.seq}, hash ${latest.hash.slice(0, 12)}…  ` : '',
        el('a', { href: 'demo.html' }, 'Try all seven missions →')),
    );
  }

  async function run(choice, button) {
    if (busy) return;
    busy = true;
    list.querySelectorAll('.choice').forEach((b) => b.setAttribute('aria-pressed', String(b === button)));
    const slow = setTimeout(waking, 1500);
    try {
      const result = await post('/egress/call', choice.call);
      clearTimeout(slow);
      let latest = null;
      try {
        latest = (await api('/egress/audit?limit=1')).records[0];
      } catch { /* the stamp is what matters */ }
      render(choice, result, latest);
    } catch (error) {
      clearTimeout(slow);
      out.replaceChildren(el('div', { class: 'sim-placeholder' },
        el('span', { class: 'big' }, 'The demo gateway didn\'t answer.'),
        `${error.message}. It may still be waking up; try again in a moment.`));
    } finally {
      busy = false;
    }
  }

  list.replaceChildren(...CHOICES.map((choice, i) => {
    const button = el('button', {
      type: 'button',
      class: `choice ${choice.danger ? 'choice-danger' : ''}`,
      'aria-pressed': 'false',
    },
    el('span', { class: 'choice-n' }, String(i + 1)),
    el('span', { class: 'choice-title' }, choice.title),
    el('span', { class: 'choice-note' }, choice.note));
    button.addEventListener('click', () => run(choice, button));
    return button;
  }));
})();
