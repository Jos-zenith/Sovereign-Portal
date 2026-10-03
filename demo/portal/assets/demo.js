/* Live demo: seven missions against the real gateway, plus the borrower, NBFC and ledger views. */
(function () {
  const { el, api, post, stamp, route, REASONS, time } = window.VICT;
  const $ = (id) => document.getElementById(id);

  const FOREIGN_HOST = 'analytics.example.com';
  const RAW_IP = '10.0.0.5';
  const POLL_MS = 4000;
  const STORE_KEY = 'vict-missions-v1';
  const WITNESS_WAIT_MS = 12000;

  const BASE = { principal_id: 'borrower-001', purpose: 'loan-eligibility', token_host: 'bureau.example.in', target_host: 'bureau.example.in' };

  const MISSIONS = [
    {
      id: 'legit',
      title: 'Pull a credit score, the right way',
      story: 'borrower-001 agreed to a loan-eligibility check. The app asks the bureau for a score.',
      expectText: 'Expect: allowed',
      expect: { allowed: true },
      call: BASE,
      why: "Consent covers the purpose, the bureau is an approved vendor and the token names it. The proxy opens a tunnel it can't read, so the bureau's mTLS works unchanged.",
    },
    {
      id: 'marketing',
      title: 'Reuse the loan consent for a cross-sell',
      story: "Growth wants to push the same borrower's profile into a marketing campaign.",
      expectText: 'Expect: stopped by the consent authority',
      expect: { stage: 'consent-authority' },
      call: { ...BASE, purpose: 'marketing' },
      why: 'Consent was given for a loan check. Marketing is a different purpose and needs its own consent. No token is issued, so there is no network call at all.',
    },
    {
      id: 'no-consent',
      title: 'Score a borrower who never said yes',
      story: 'borrower-002 installed the app but never consented. The app pulls a score anyway.',
      expectText: 'Expect: stopped by the consent authority',
      expect: { stage: 'consent-authority' },
      call: { ...BASE, principal_id: 'borrower-002' },
      why: 'Without a consent record the authority refuses to issue a token. The request dies inside your own servers.',
    },
    {
      id: 'leak',
      title: 'Let an analytics SDK ship data abroad',
      story: `The token is genuine and names the bureau, but a bundled SDK connects to ${FOREIGN_HOST}.`,
      expectText: 'Expect: stopped at the egress proxy',
      expect: { stage: 'egress-proxy', reason: 'host-not-allow-listed' },
      call: { ...BASE, target_host: FOREIGN_HOST },
      why: 'The proxy checks where the connection actually goes. A host outside the vendor list is refused before a single byte leaves.',
      danger: true,
    },
    {
      id: 'switch',
      title: 'Consent for the bureau, connection to the AA',
      story: 'Both are approved vendors. The token only names the bureau.',
      expectText: 'Expect: stopped at the egress proxy',
      expect: { stage: 'egress-proxy', reason: 'host-not-in-token' },
      call: { ...BASE, target_host: 'aa.example.in' },
      why: "Each token is bound to the hosts it names, so consent for one vendor can't be spent at another.",
      danger: true,
    },
    {
      id: 'stream',
      kind: 'stream',
      title: 'Withdraw consent while statements stream',
      story: "The app pulls bank-statement pages from the Account Aggregator. Start the fetch, then withdraw borrower-001's consent while pages are flowing.",
      expectText: 'Expect: connection cut within a second',
      why: "The proxy tracks every open connection by borrower and purpose. A withdrawal closes them at once; it doesn't wait for a token to expire.",
    },
    {
      id: 'rewrite',
      kind: 'rewrite',
      title: 'Be the dishonest LSP: erase a blocked call',
      story: 'Delete the latest blocked call from your own log and rebuild every hash after it. The chain will still verify. Will the NBFC notice?',
      expectText: 'Expect: NBFC witness alarm',
      why: 'The NBFC holds a signed checkpoint of your log. A rebuilt chain no longer extends it, and the alarm stays raised until someone investigates.',
      danger: true,
    },
  ];

  const ALARM_TEXT = {
    rollback: 'Entries the NBFC already witnessed have disappeared from the log.',
    'does-not-extend-witnessed-head': 'The log no longer extends the head the NBFC holds. History was rewritten.',
    fork: 'The LSP signed two different heads for the same entry.',
    'bad-signature': "The checkpoint was not signed with the LSP's pinned key.",
    'wrong-lsp': 'The checkpoint names a different LSP.',
    'digest-count-mismatch': 'The LSP sent the wrong number of digests.',
    'time-went-backwards': 'The checkpoint is older than one already accepted.',
  };

  // ---------- Progress (per viewer, best effort) ----------

  let done = new Set();
  try {
    done = new Set(JSON.parse(localStorage.getItem(STORE_KEY) || '[]'));
  } catch { /* storage unavailable: progress lives for this visit only */ }

  function markDone(id) {
    done.add(id);
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify([...done]));
    } catch { /* ignore */ }
    renderProgress();
  }

  function renderProgress() {
    const n = MISSIONS.filter((m) => done.has(m.id)).length;
    $('progress-fill').style.width = `${(n / MISSIONS.length) * 100}%`;
    $('progress-text').textContent = n === MISSIONS.length ? 'All 7 tried. Nothing got through.' : `${n} of ${MISSIONS.length} tried`;
    MISSIONS.forEach((m) => $(`mission-${m.id}`)?.classList.toggle('done', done.has(m.id)));
  }

  // ---------- Desk ----------

  function setDesk(meta, ...children) {
    $('desk-meta').textContent = meta;
    $('desk').replaceChildren(...children);
  }

  function setActive(id) {
    document.querySelectorAll('.mission').forEach((node) => node.classList.toggle('active', node.id === `mission-${id}`));
  }

  function deskMeta(mission) {
    return mission ? `mission ${MISSIONS.indexOf(mission) + 1} of ${MISSIONS.length}` : 'free play';
  }

  function narrowViewport() {
    return window.matchMedia('(max-width: 1080px)').matches;
  }

  function showDesk() {
    if (narrowViewport()) document.querySelector('.desk').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function matches(expect, result) {
    if (expect.allowed) return result.allowed;
    return !result.allowed && result.stage === expect.stage && (!expect.reason || result.reason === expect.reason);
  }

  function waiting(text) {
    return el('div', { class: 'sim-placeholder' }, el('span', { class: 'big' }, text), 'The free demo server can take about a minute to wake up.');
  }

  async function latestEntry() {
    try {
      return (await api('/egress/audit?limit=1')).records[0];
    } catch {
      return null;
    }
  }

  async function runCall(mission, call) {
    setActive(mission?.id);
    const slow = setTimeout(() => setDesk(deskMeta(mission), waiting('Sending…')), 900);
    let result;
    try {
      result = await post('/egress/call', call);
    } catch (error) {
      clearTimeout(slow);
      setDesk(deskMeta(mission), el('p', {}, `The call could not be run: ${error.message}`));
      return;
    }
    clearTimeout(slow);
    const latest = await latestEntry();
    const host = `${call.target_host}${call.target_port && Number(call.target_port) !== 443 ? `:${call.target_port}` : ''}`;
    const allowed = result.allowed;
    const title = allowed
      ? `Sent to ${call.target_host}.`
      : (result.stage === 'consent-authority' ? 'Stopped before any network call.' : `Stopped before reaching ${call.target_host}.`);

    const children = [
      el('div', { class: 'verdict-row' },
        allowed ? stamp('good', 'Allowed', 'स्वीकृत') : stamp('bad', 'Blocked', 'अस्वीकृत'),
        el('p', { class: 'verdict-title' }, title)),
      route(result.stage, allowed, host),
      el('div', { class: 'reason-box' }, el('code', {}, result.reason), el('p', {}, REASONS[result.reason] || '')),
    ];
    if (mission) children.push(el('p', { class: 'muted', style: 'margin:0' }, mission.why));
    if (mission && !matches(mission.expect, result)) {
      children.push(el('p', { class: 'note' },
        el('strong', {}, 'Not the expected result. '),
        'This demo is shared, so another visitor may have changed a consent. Check the vault below, or reset the demo.'));
    }
    if (latest) {
      children.push(el('p', { class: 'small faint', style: 'margin:0' },
        `Ledger entry #${latest.seq} · hash ${latest.hash.slice(0, 16)}… `, el('a', { href: '#ledger' }, 'see it')));
    }
    setDesk(deskMeta(mission), ...children);
    if (mission && matches(mission.expect, result)) markDone(mission.id);
    showDesk();
    refresh();
  }

  // ---------- Mission 6: withdraw mid-stream ----------

  let stream = { id: null, timer: null, revokedAt: null };

  function streamNodes() {
    return {
      start: $('stream-start'),
      withdraw: $('stream-withdraw'),
      pages: $('stream-pages'),
      label: $('stream-label'),
    };
  }

  function stopStreamPolling() {
    clearInterval(stream.timer);
    stream.timer = null;
  }

  function restoreConsentButton() {
    return el('button', {
      class: 'btn btn-ghost btn-small',
      type: 'button',
      onclick: async (event) => {
        event.target.disabled = true;
        await changeConsent('grant', 'borrower-001', 'loan-eligibility');
        event.target.textContent = 'Consent restored';
      },
    }, "Give borrower-001's consent back");
  }

  async function startStream() {
    const mission = MISSIONS.find((m) => m.id === 'stream');
    const nodes = streamNodes();
    setActive('stream');
    stopStreamPolling();
    stream = { id: null, timer: null, revokedAt: null };
    nodes.start.disabled = true;
    nodes.withdraw.disabled = true;
    nodes.pages.className = 'meter-pages';
    nodes.pages.replaceChildren();
    nodes.label.textContent = 'Opening an encrypted tunnel to aa.example.in…';
    setDesk(deskMeta(mission), waiting('Opening the tunnel…'));

    let started;
    try {
      started = await post('/egress/stream', { principal_id: 'borrower-001' });
    } catch (error) {
      nodes.start.disabled = false;
      nodes.label.textContent = `Could not start: ${error.message}`;
      return;
    }
    if (started.state === 'blocked') {
      nodes.start.disabled = false;
      nodes.label.textContent = 'The fetch never opened.';
      setDesk(deskMeta(mission),
        el('div', { class: 'verdict-row' }, stamp('bad', 'Blocked', 'अस्वीकृत'), el('p', { class: 'verdict-title' }, 'No consent, so no fetch.')),
        route(started.stage, false, 'aa.example.in'),
        el('div', { class: 'reason-box' }, el('code', {}, started.reason), el('p', {}, REASONS[started.reason] || '')),
        el('p', { class: 'muted', style: 'margin:0' }, "borrower-001's consent is already withdrawn. Give it back, then start the fetch and withdraw it mid-stream."),
        el('div', { class: 'desk-actions' }, restoreConsentButton()));
      showDesk();
      return;
    }
    stream.id = started.id;
    stream.timer = setInterval(pollStream, 300);
  }

  async function pollStream() {
    if (!stream.id) return;
    let s;
    try {
      s = await api(`/egress/stream/${stream.id}`);
    } catch {
      stopStreamPolling();
      return;
    }
    const nodes = streamNodes();
    const shown = nodes.pages.childElementCount;
    for (let i = shown; i < Math.min(s.pages, 64); i += 1) nodes.pages.append(el('i'));
    nodes.label.textContent = `${s.pages} page${s.pages === 1 ? '' : 's'} of bank statement received`;
    const mission = MISSIONS.find((m) => m.id === 'stream');

    if (s.state === 'open') {
      nodes.withdraw.disabled = false;
      if (shown === 0) {
        setDesk(deskMeta(mission),
          el('div', { class: 'verdict-row' }, stamp('good', 'Streaming'), el('p', { class: 'verdict-title' }, 'Pages are flowing through the proxy.')),
          route('egress-proxy', true, 'aa.example.in'),
          el('p', { class: 'muted', style: 'margin:0' }, 'Now press “Withdraw consent” on the mission card, as the borrower would in their app.'));
      }
      return;
    }

    stopStreamPolling();
    nodes.start.disabled = false;
    nodes.withdraw.disabled = true;
    if (s.state === 'cut') {
      nodes.pages.classList.add('cut');
      const ms = stream.revokedAt ? Math.max(0, Math.round((s.ended_at - stream.revokedAt) * 1000)) : null;
      setDesk(deskMeta(mission),
        el('div', { class: 'verdict-row' }, stamp('bad', 'Cut', 'रद्द'),
          el('p', { class: 'verdict-title' }, ms !== null ? `Connection cut ${ms} ms after the withdrawal.` : 'Connection cut. Someone withdrew this consent.')),
        route('egress-proxy', false, 'aa.example.in'),
        el('div', { class: 'reason-box' }, el('code', {}, s.reason), el('p', {}, REASONS[s.reason] || '')),
        el('p', { class: 'muted', style: 'margin:0' }, `${s.pages} pages got through before the withdrawal. Nothing after it. ${mission.why}`),
        el('div', { class: 'desk-actions' }, restoreConsentButton()));
      if (s.reason === 'consent-withdrawn') markDone('stream');
    } else if (s.state === 'finished') {
      setDesk(deskMeta(mission),
        el('div', { class: 'verdict-row' }, stamp('neutral', 'Finished'), el('p', { class: 'verdict-title' }, 'The fetch completed before you withdrew.')),
        el('p', { class: 'muted', style: 'margin:0' }, 'Start it again and press “Withdraw consent” while pages are still flowing.'));
    } else {
      setDesk(deskMeta(mission), el('p', {}, `The fetch ended: ${s.reason || s.state}.`));
    }
    showDesk();
    refresh();
  }

  async function withdrawMidStream() {
    const nodes = streamNodes();
    nodes.withdraw.disabled = true;
    try {
      const response = await post('/egress/consent/revoke', { principal_id: 'borrower-001', purpose: 'loan-eligibility' });
      stream.revokedAt = response.revoked_at ?? Date.now() / 1000;
    } catch (error) {
      nodes.label.textContent = `Withdrawal failed: ${error.message}`;
    }
  }

  // ---------- Mission 7: rewrite history ----------

  async function rewriteHistory(button) {
    const mission = MISSIONS.find((m) => m.id === 'rewrite');
    setActive('rewrite');
    button.disabled = true;
    let result;
    try {
      result = await post('/egress/simulate/rewrite-history');
    } catch (error) {
      button.disabled = false;
      setDesk(deskMeta(mission),
        el('div', { class: 'verdict-row' }, stamp('neutral', 'Nothing to hide'), el('p', { class: 'verdict-title' }, 'There is no blocked call to erase yet.')),
        el('p', { class: 'muted', style: 'margin:0' }, 'Run a mission that gets blocked first (3, 4 or 5), then come back and try to make it disappear.'),
        el('p', { class: 'small faint', style: 'margin:0' }, error.message));
      showDesk();
      return;
    }

    const removed = result.removed;
    const status = el('p', { class: 'muted', style: 'margin:0' }, "Waiting for the NBFC's next poll…");
    setDesk(deskMeta(mission),
      el('div', { class: 'verdict-row' }, stamp('warn', 'Rewritten'), el('p', { class: 'verdict-title' }, `Entry #${removed.seq} is gone.`)),
      el('p', { style: 'margin:0' },
        `You deleted the ${removed.reason} call to ${removed.target || 'the vendor'} and rebuilt every hash after it. `,
        'Your own chain still verifies: ', el('strong', {}, result.chain_still_verifies ? 'yes.' : 'no.')),
      status);
    showDesk();

    const started = Date.now();
    while (Date.now() - started < WITNESS_WAIT_MS) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      status.textContent = `Waiting for the NBFC's next poll… ${Math.round((Date.now() - started) / 1000)} s`;
      const state = await refresh();
      if (state?.witness?.alarm) {
        const alarm = state.witness.alarm;
        $('desk').append(
          el('div', { class: 'verdict-row' }, stamp('bad', 'Caught', 'पकड़ा गया'),
            el('p', { class: 'verdict-title' }, `NBFC alarm after ${Math.round((Date.now() - started) / 1000)} s.`)),
          el('div', { class: 'reason-box' }, el('code', {}, alarm.reason), el('p', {}, ALARM_TEXT[alarm.reason] || "The LSP's log failed a witness check.")),
          el('p', { class: 'muted', style: 'margin:0' }, `${mission.why} Reset the demo to clear it.`));
        status.remove();
        markDone('rewrite');
        button.disabled = false;
        return;
      }
    }
    status.textContent = "The witness hasn't polled yet. Watch the Evidence panel below; the alarm appears on its next check.";
    button.disabled = false;
  }

  // ---------- Missions list ----------

  function renderMissions() {
    $('missions').replaceChildren(...MISSIONS.map((mission, i) => {
      const foot = el('div', { class: 'mission-foot' });
      const extra = [];
      if (mission.kind === 'stream') {
        foot.append(
          el('button', { class: 'btn btn-small', type: 'button', id: 'stream-start', onclick: startStream }, 'Start the AA fetch'),
          el('button', { class: 'btn btn-danger btn-small', type: 'button', id: 'stream-withdraw', disabled: true, onclick: withdrawMidStream }, 'Withdraw consent'),
          el('span', { class: 'mission-expect' }, mission.expectText));
        extra.push(el('div', { class: 'meter', style: 'grid-column: 2' },
          el('div', { class: 'meter-pages', id: 'stream-pages', 'aria-hidden': 'true' }),
          el('span', { class: 'meter-label', id: 'stream-label', 'aria-live': 'polite' }, 'Not started.')));
      } else if (mission.kind === 'rewrite') {
        const button = el('button', { class: 'btn btn-danger btn-small', type: 'button' }, 'Erase the last blocked call');
        button.addEventListener('click', () => rewriteHistory(button));
        foot.append(button, el('span', { class: 'mission-expect' }, mission.expectText));
      } else {
        foot.append(
          el('button', { class: `btn btn-small ${mission.danger ? 'btn-danger' : ''}`, type: 'button', onclick: () => runCall(mission, mission.call) }, 'Run'),
          el('span', { class: 'mission-expect' }, mission.expectText));
      }
      return el('li', { class: `mission ${mission.danger ? 'mission-danger' : ''}`, id: `mission-${mission.id}` },
        el('span', { class: 'mission-n' }, String(i + 1)),
        el('span', { class: 'stamp done-mark' }, 'Tried'),
        el('h3', {}, mission.title),
        el('p', {}, mission.story),
        foot,
        ...extra);
    }));
    renderProgress();
  }

  // ---------- Borrower, NBFC and ledger views ----------

  function setTag(id, text, tone) {
    const node = $(id);
    node.textContent = text;
    node.className = `tag ${tone ? `tag-${tone}` : ''}`;
  }

  function showError(message) {
    const box = $('api-error');
    box.hidden = !message;
    box.textContent = message || '';
  }

  function consentStatus(entry) {
    if (!entry) return { text: 'No consent', tone: '', granted: false };
    if (entry.revoked_at) return { text: 'Withdrawn', tone: 'bad', granted: false };
    if (entry.expires_at && new Date(entry.expires_at) <= new Date()) return { text: 'Expired', tone: 'bad', granted: false };
    return { text: 'Granted', tone: 'good', granted: true };
  }

  async function changeConsent(action, principal_id, purpose) {
    try {
      await post(`/egress/consent/${action}`, { principal_id, purpose });
    } catch (error) {
      showError(`Consent change failed: ${error.message}`);
    }
    await refresh();
  }

  function renderVault(state) {
    const rows = [];
    state.borrowers.forEach((borrower) => state.purposes.forEach((purpose) => {
      const status = consentStatus(state.consents.find((c) => c.principal_id === borrower && c.purpose === purpose));
      rows.push(el('tr', {},
        el('td', {}, el('span', { class: 'cell-main' }, borrower), el('span', { class: 'cell-sub' }, purpose)),
        el('td', {}, el('span', { class: `tag ${status.tone ? `tag-${status.tone}` : ''}` }, status.text)),
        el('td', {}, el('button', {
          class: `btn btn-small ${status.granted ? 'btn-ghost' : ''}`,
          type: 'button',
          onclick: () => changeConsent(status.granted ? 'revoke' : 'grant', borrower, purpose),
        }, status.granted ? 'Withdraw' : 'Grant'))));
    }));
    $('consent-rows').replaceChildren(...rows);
  }

  function renderEvidence(state) {
    const { counts } = state;
    $('c-tokens').textContent = counts.tokens_issued;
    $('c-allowed').textContent = counts.tunnels_allowed;
    $('c-before').textContent = counts.blocked_before_network;
    $('c-proxy').textContent = counts.blocked_at_proxy;
    const reasons = Object.entries(counts.blocked_by_reason);
    $('reasons').replaceChildren(...(reasons.length
      ? reasons.map(([reason, n]) => el('li', {}, el('span', {}, reason), el('b', {}, n)))
      : [el('li', { class: 'muted' }, 'Nothing blocked yet.')]));

    const { chain, witness } = state;
    setTag('pill-chain', chain.ok ? `Audit chain: intact · ${chain.records} entries` : `Audit chain: broken at #${chain.first_bad_seq}`, chain.ok ? 'good' : 'bad');
    if (witness.alarm) setTag('pill-witness', `NBFC witness: ALARM (${witness.alarm.reason})`, 'bad');
    else if (witness.ok) setTag('pill-witness', `NBFC witness: verified to #${witness.seq}`, 'good');
    else setTag('pill-witness', 'NBFC witness: LSP not answering', 'warn');

    const box = $('witness');
    const held = el('p', { class: 'small' }, 'NBFC holds checkpoint ', el('code', {}, `#${witness.seq} · ${witness.head.slice(0, 16)}…`));
    if (witness.alarm) {
      box.className = 'witness-box alarm';
      box.replaceChildren(
        el('p', { class: 'verdict' }, `Alarm: ${witness.alarm.reason}`),
        el('p', {}, ALARM_TEXT[witness.alarm.reason] || "The LSP's log failed a witness check."),
        held,
        el('p', { class: 'small faint' }, `Raised ${time(witness.alarm.at)}. It stays raised until someone investigates.`));
    } else if (witness.reason === 'lsp-unreachable') {
      box.className = 'witness-box warn';
      box.replaceChildren(el('p', { class: 'verdict' }, 'LSP not answering. The witness keeps trying.'), held);
    } else {
      box.className = 'witness-box';
      box.replaceChildren(
        el('p', { class: 'verdict' }, 'Signed checkpoint verified. The log only grew.'),
        held,
        el('p', { class: 'small faint' }, `Checked ${time(witness.checked_at)}, every ${witness.interval_seconds} s.`));
    }
  }

  let topSeq = null;

  function eventTone(record) {
    if (['egress-allowed', 'token-issued', 'consent-granted'].includes(record.event)) return 'good';
    if (record.event === 'egress-blocked' || record.event === 'token-denied') return 'bad';
    if (record.event === 'tunnel-cut' || record.event === 'consent-withdrawn') return 'warn';
    if (record.event === 'audit-recovered') return 'info';
    return '';
  }

  function renderLedger(records) {
    if (!records.length) {
      $('log-rows').replaceChildren(el('tr', {}, el('td', { colspan: '8', class: 'muted' }, 'No entries yet. Run a mission.')));
      topSeq = 0;
      return;
    }
    const previousTop = topSeq;
    $('log-rows').replaceChildren(...records.map((r) => {
      const tone = eventTone(r);
      return el('tr', { class: previousTop !== null && r.seq > previousTop ? 'row-new' : '' },
        el('td', { class: 'seq' }, r.seq),
        el('td', {}, time(r.ts)),
        el('td', {}, el('span', { class: `tag ${tone ? `tag-${tone}` : ''}` }, r.event)),
        el('td', {}, r.principal_id || '–'),
        el('td', {}, r.purpose || '–'),
        el('td', {}, r.target || (r.hosts || []).join(', ') || '–'),
        el('td', {}, r.reason || '–'),
        el('td', { class: 'chainlink', title: `prev ${r.prev}\nhash ${r.hash}` }, `${r.prev.slice(0, 6)} → `, el('b', {}, r.hash.slice(0, 6))));
    }));
    topSeq = records[0].seq;
  }

  async function refresh() {
    try {
      const [state, audit] = await Promise.all([api('/egress/state'), api('/egress/audit?limit=40')]);
      setTag('pill-gateway', 'Gateway: connected', 'good');
      showError('');
      renderVault(state);
      renderEvidence(state);
      renderLedger(audit.records);
      window.VICT.updateTicker(state, audit.records[0]);
      return state;
    } catch (error) {
      setTag('pill-gateway', 'Gateway: not reachable', 'bad');
      setTag('pill-chain', 'Audit chain: –', '');
      setTag('pill-witness', 'NBFC witness: –', '');
      window.VICT.updateTicker(null);
      showError(`Can't reach the demo gateway at ${window.VICT.API_BASE || '(no API configured)'}: ${error.message}. `
        + 'It runs on a free instance that sleeps when idle and can take about a minute to wake. This page keeps retrying. '
        + 'To run it yourself: uvicorn src.gateway.consent_gateway:app --port 8080, then open this page with ?api=http://127.0.0.1:8080');
      return null;
    }
  }

  // ---------- Free play ----------

  function fillSelect(select, values) {
    select.replaceChildren(...values.map(([value, label]) => el('option', { value }, label ?? value)));
  }

  function setupForm(state) {
    fillSelect($('f-borrower'), state.borrowers.map((b) => [b]));
    fillSelect($('f-purpose'), state.purposes.map((p) => [p]));
    fillSelect($('f-token-host'), [...state.allowed_hosts, FOREIGN_HOST].map((h) => [h]));
    fillSelect($('f-target-host'), [...state.allowed_hosts.map((h) => [h]), [FOREIGN_HOST], [RAW_IP, `${RAW_IP} (raw IP)`]]);
    $('custom-form').addEventListener('submit', (event) => {
      event.preventDefault();
      const call = Object.fromEntries(new FormData(event.target).entries());
      call.target_port = Number(call.target_port);
      runCall(null, call);
    });
  }

  $('btn-reset').addEventListener('click', async (event) => {
    event.target.disabled = true;
    stopStreamPolling();
    try {
      await post('/egress/reset');
      topSeq = null;
      setDesk('waiting', el('div', { class: 'sim-placeholder' }, el('span', { class: 'big' }, 'Fresh start.'), 'Consents, ledger and witness are back to their initial state.'));
      renderMissions();
    } catch (error) {
      showError(`Reset failed: ${error.message}`);
    }
    event.target.disabled = false;
    await refresh();
  });

  async function start() {
    renderMissions();
    let state = await refresh();
    while (!state) {
      await new Promise((resolve) => setTimeout(resolve, POLL_MS));
      state = await refresh();
    }
    setupForm(state);
    setInterval(() => {
      if (!document.hidden) refresh();
    }, POLL_MS);
  }

  start();
})();
