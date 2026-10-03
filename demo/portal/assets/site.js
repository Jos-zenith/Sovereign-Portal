/* Shared by every page: API access, nav, live ticker, countdown, code tabs, reveal. */
(function () {
  document.documentElement.classList.add('js');
  const VICT = (window.VICT = window.VICT || {});

  // ---------- API ----------

  function resolveApiBase() {
    const override = new URLSearchParams(window.location.search).get('api');
    if (override) return override.replace(/\/$/, '');
    if (['localhost', '127.0.0.1'].includes(window.location.hostname)) return 'http://127.0.0.1:8080';
    const configured = document.querySelector('meta[name="vict-api-base"]')?.content?.trim();
    return configured ? configured.replace(/\/$/, '') : '';
  }

  VICT.API_BASE = resolveApiBase();

  VICT.api = async function api(path, options = {}) {
    const response = await fetch(`${VICT.API_BASE}${path}`, {
      ...options,
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    });
    const type = response.headers.get('content-type') || '';
    const body = type.includes('application/json') ? await response.json() : null;
    if (!response.ok) throw new Error(body?.detail || `HTTP ${response.status}`);
    if (body === null) throw new Error('The API did not return JSON. Check the vict-api-base meta tag.');
    return body;
  };

  VICT.post = (path, data) => VICT.api(path, { method: 'POST', body: JSON.stringify(data ?? {}) });

  // ---------- DOM helpers ----------

  VICT.el = function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    Object.entries(attrs).forEach(([key, value]) => {
      if (value === undefined || value === null || value === false) return;
      if (key === 'class') node.className = value;
      else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? '' : value);
    });
    children.flat().forEach((child) => {
      if (child === undefined || child === null || child === false) return;
      node.append(child instanceof Node ? child : String(child));
    });
    return node;
  };
  const el = VICT.el;

  VICT.time = (ts) => new Date(typeof ts === 'number' ? ts * 1000 : ts)
    .toLocaleTimeString('en-IN', { hour12: false, timeZone: 'Asia/Kolkata' });

  // Plain-language meaning of every reason code the gateway can return.
  VICT.REASONS = {
    allowed: 'Every check passed. The connection opened, end-to-end encrypted.',
    'consent-record-not-found': 'The borrower never gave consent for this purpose.',
    'consent-withdrawn': 'The borrower withdrew consent.',
    'consent-expired': 'The consent has expired.',
    'host-not-allow-listed': "This host isn't on the LSP's approved vendor list.",
    'host-not-in-token': 'The consent token names a different host from the one the code tried to reach.',
    'port-not-allowed': 'Only HTTPS on port 443 is allowed.',
    'raw-ip-target': 'Raw IP addresses are refused. Every call must name an approved host.',
    'token-missing': 'The code tried to connect without a consent token.',
    'token-expired': 'The consent token is more than 60 seconds old.',
    'token-bad-signature': "The token wasn't signed by the consent authority. Apps cannot mint their own.",
    'token-malformed': "The token couldn't be read.",
    'token-tunnel-limit': 'One token opens at most four connections, so a leaked token cannot fan out.',
    'method-not-allowed': 'Only encrypted CONNECT tunnels are allowed. Plain HTTP is refused.',
    'upstream-unreachable': 'The vendor did not answer.',
    'proxy-error': 'The proxy failed closed: no audit record, no connection.',
    'policy-unavailable': 'The policy engine was unreachable, so the call was refused.',
  };

  VICT.stamp = function stamp(kind, text, deva) {
    const cls = { good: '', bad: 'stamp-bad', warn: 'stamp-warn', neutral: 'stamp-neutral' }[kind] ?? '';
    return el('span', { class: `stamp stamp-in ${cls}` }, text, deva ? el('span', { class: 'deva', lang: 'hi' }, deva) : null);
  };

  // The four places a call can stop: the code, the consent authority, the proxy, the host.
  VICT.route = function route(stage, allowed, host) {
    const steps = ['Your code', 'Consent authority', 'Egress proxy', host];
    const stopAt = allowed ? -1 : (stage === 'consent-authority' ? 1 : 2);
    return el('ol', { class: 'route', 'aria-label': 'Path of the call' }, steps.map((label, i) => {
      let state = '';
      if (allowed || i < stopAt) state = 'passed';
      else if (i === stopAt) state = 'stopped';
      const content = i === 3 ? el('span', { class: 'route-host' }, label) : label;
      return el('li', { class: state }, content);
    }));
  };

  // ---------- Nav ----------

  const toggle = document.querySelector('.nav-toggle');
  const nav = document.getElementById('site-nav');
  if (toggle && nav) {
    toggle.addEventListener('click', () => {
      const open = nav.classList.toggle('open');
      toggle.setAttribute('aria-expanded', String(open));
    });
  }

  // ---------- Live ticker ----------

  const tickerText = document.getElementById('ticker-text');
  const tickerDot = document.getElementById('ticker-dot');

  VICT.updateTicker = function updateTicker(state, latest) {
    if (!tickerText) return;
    if (!state) {
      tickerDot?.setAttribute('data-state', 'down');
      tickerText.textContent = 'Waking the free demo server. This can take about a minute…';
      return;
    }
    tickerDot?.setAttribute('data-state', 'live');
    const chain = state.chain.ok ? 'chain intact' : `chain broken at #${state.chain.first_bad_seq}`;
    const witness = state.witness.alarm
      ? `NBFC witness ALARM: ${state.witness.alarm.reason}`
      : `NBFC witness verified to #${state.witness.seq}`;
    const parts = [];
    if (latest) {
      parts.push(el('b', {}, `#${latest.seq}`), ` ${latest.event} · ${latest.reason || '–'} · ${VICT.time(latest.ts)} · `);
    } else {
      parts.push('No calls yet · ');
    }
    parts.push(`${chain} · ${witness}`);
    tickerText.replaceChildren(...parts);
  };

  async function pollTicker() {
    if (document.hidden) return;
    try {
      const [state, audit] = await Promise.all([VICT.api('/egress/state'), VICT.api('/egress/audit?limit=1')]);
      VICT.updateTicker(state, audit.records[0]);
    } catch {
      VICT.updateTicker(null);
    }
  }

  if (tickerText && document.body.dataset.ownPoll === undefined) {
    pollTicker();
    setInterval(pollTicker, 10000);
  }

  // ---------- DPDP countdown ----------

  document.querySelectorAll('[data-countdown]').forEach((node) => {
    const target = new Date(`${node.dataset.countdown}T00:00:00+05:30`);
    const days = Math.ceil((target - Date.now()) / 86400000);
    node.textContent = days > 0 ? days.toLocaleString('en-IN') : '0';
  });

  // ---------- Code tabs and copy ----------

  document.querySelectorAll('.code').forEach((block) => {
    const tabs = [...block.querySelectorAll('[role="tab"]')];
    tabs.forEach((tab) => tab.addEventListener('click', () => {
      tabs.forEach((other) => {
        const selected = other === tab;
        other.setAttribute('aria-selected', String(selected));
        document.getElementById(other.getAttribute('aria-controls')).hidden = !selected;
      });
    }));
    const copy = block.querySelector('.copy-btn');
    if (copy) {
      copy.addEventListener('click', async () => {
        const visible = [...block.querySelectorAll('pre')].find((pre) => !pre.closest('[hidden]'));
        try {
          await navigator.clipboard.writeText(visible.innerText);
          copy.textContent = 'Copied';
        } catch {
          copy.textContent = 'Select & copy';
        }
        setTimeout(() => { copy.textContent = 'Copy'; }, 1600);
      });
    }
  });

  // ---------- Reveal on scroll ----------

  const revealables = document.querySelectorAll('[data-reveal]');
  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        }
      });
    }, { rootMargin: '0px 0px -8% 0px' });
    revealables.forEach((node) => observer.observe(node));
  } else {
    revealables.forEach((node) => node.classList.add('is-visible'));
  }
})();
