/* TNT — tools/portforward.js
   The "Port forward" card of the Tools view: one TCP port tested from the internet (POST /api/netcheck/portforward)
   against this site's public IP. A TCP port field, a "Test from the internet" button, the green/red/yellow result, an
   always-shown muted note and, after a reachable or unanswered result, the hints. A verdict-specific hint ("… :
   forwarding may not work here") is shown only when the answer carries a NAT verdict of its own (there is no NAT
   result on the Tools page). A new network generation clears the result and the hints at once; the typed port stays.
   Whatever comes from the internet is inserted as text, never as markup.
   Loaded before app.js: TNT.util / TNT.ui / TNT.state are only touched inside functions. */
(function () {
  'use strict';
  window.TNT = window.TNT || {};
  const TNT = window.TNT;
  TNT.tools = TNT.tools || {};

  const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;   // (kept in step with netcheck)
  const PORTCHECK_VPN_TEXT = 'This PC\'s internet goes through a VPN, so the test would check the VPN\'s address, not this site\'s: disconnect the VPN first';
  /** Verdicts that make a port forward on this network's router unlikely to work (the hint names them): verdict -> title. */
  const FORWARDING_RISK = {
    cgnat: 'Carrier-grade NAT (CGNAT)', double_nat: 'Double NAT', upstream_nat: 'NAT beyond the router',
    nat_unclear_private_wan: 'Probably behind another NAT',
  };

  const TEXTS = {
    PORTCHECK_VPN_TEXT,
    portLabel: 'TCP port',
    portPlaceholder: '8000',
    portButton: 'Test from the internet',
    portBusy: 'Testing…',
    portHint: 'Something must answer on that TCP port (the camera/NVR must be on and the forward must point at it). No answer can also mean the ISP or a firewall blocks the port.',
    portRisk: ': forwarding may not work here',
    portNote: 'TCP only: UDP forwards (SIP, VPN) cannot be tested from outside. Uses portchecker.io (or Globalping), which sees this site\'s public IP.',
    portTimeout: 'Still testing on the service, try again in a minute',
    portInvalid: 'port must be a whole number from 1 to 65535',
    portUnavailable: 'The port-forward test is not available on this service',
    intro: 'Ask a public port checker to connect to one TCP port on this site\'s public address, the way a device on the internet would. Forward the port on the router first (to the camera, NVR or server that should answer).',
  };

  /* ------------------------------------------------ pure helpers (tests) */
  const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

  /** Pure: the port typed in the form -> { ok: true, port } or { ok: false, error } with the service's message. */
  function validPort(text) {
    const s = String(text == null ? '' : text).trim();
    const n = /^\d{1,5}$/.test(s) ? Number(s) : NaN;
    return n >= 1 && n <= 65535 ? { ok: true, port: n } : { ok: false, error: TEXTS.portInvalid };
  }

  /** Pure: what the port-forward card shows -> { label, placeholder, button, disabled, blocked, cls, text, detail, hints, note }.
   *  result: PORTCHECK_RESULT or null; ctx: { testing, error ({status, code, message} of a failed request), natVerdict (a NAT
   *  verdict from the status, else the result's own) }. cls 'ok' (reachable), 'bad' (did not answer) or 'warn' (an error); the
   *  hints only come with a reachable or unanswered result; blocked is PORTCHECK_VPN_TEXT while the verdict is vpn. */
  function portView(result, ctx) {
    const c = ctx || {};
    const r = isObj(result) ? result : null;
    const verdict = c.natVerdict || (r && r.nat_verdict) || null;
    const vpn = verdict === 'vpn';
    const out = { label: TEXTS.portLabel, placeholder: TEXTS.portPlaceholder, button: c.testing ? TEXTS.portBusy : TEXTS.portButton,
      disabled: vpn || !!c.testing, blocked: vpn ? PORTCHECK_VPN_TEXT : '', cls: '', text: '', detail: '', hints: [], note: TEXTS.portNote };
    if (c.testing) return out;
    const e = c.error;
    if (e) {
      const status = e.status || 0;
      out.cls = 'warn';
      if (e.code === 'timeout') out.text = TEXTS.portTimeout;
      else if (status === 404) out.text = TEXTS.portUnavailable;
      else if ([400, 403, 409, 429, 503].includes(status)) out.text = String(e.message || TEXTS.portUnavailable);
      else out.text = 'Could not test the port: ' + (e.message || 'unknown error');
      return out;
    }
    if (!r) return out;
    const port = r.port != null ? r.port : '?';
    if (r.reachable === true) { out.cls = 'ok'; out.text = 'TCP port ' + port + ' is reachable from the internet'; }
    else if (r.reachable === false) { out.cls = 'bad'; out.text = 'TCP port ' + port + ' did not answer from the internet'; }
    else { out.cls = 'warn'; out.text = String(r.error || 'The port checkers could not be reached'); return out; }
    out.detail = r.detail ? String(r.detail) : '';
    out.hints.push(TEXTS.portHint);
    if (FORWARDING_RISK[verdict]) out.hints.push(FORWARDING_RISK[verdict] + TEXTS.portRisk);
    return out;
  }

  /** The NAT verdict of this network from the status, when one is there (there is no NAT result on the Tools page). */
  function statusVerdict() {
    const st = TNT.state && TNT.state.status;
    const nat = st && isObj(st.nat) ? st.nat : null;
    const res = nat && isObj(nat.result) ? nat.result : null;
    return res && res.verdict ? String(res.verdict) : null;
  }

  /** This network's generation, or null when the status has none yet. */
  function currentGen() {
    const st = TNT.state && TNT.state.status;
    return st && st.net && st.net.generation != null ? st.net.generation : null;
  }

  /* ------------------------------------------------------------- card */
  function create() {
    const { h } = TNT.util;
    let mounted = false;
    let gen = currentGen();          // the network on screen
    let result = null;               // the PORTCHECK_RESULT on screen, this network's
    let err = null;                  // { status, code, message } of the last test that failed
    let testing = false;
    let seq = 0, key = null;
    const els = {};
    /** An answer about this network (or one that does not say which). */
    const sameGen = (x) => gen == null || !x || x.generation == null || x.generation === gen;

    els.port = h('input', { class: 'input', type: 'number', min: '1', max: '65535', step: '1', placeholder: TEXTS.portPlaceholder, 'aria-label': TEXTS.portLabel });
    els.port.addEventListener('keydown', (e) => { if (e.key === 'Enter') test(); });
    els.btn = h('button', { class: 'btn btn-primary', type: 'button', on: { click: test },
      title: 'A public port checker connects to this TCP port on this site\'s public IP' }, TNT.ui.icon('target'), TEXTS.portButton);
    els.blocked = h('div', { class: 'tool-summary warn pf-blocked', hidden: true });
    els.result = h('div', { class: 'tool-summary pf-result', role: 'status', 'aria-live': 'polite', hidden: true });
    els.hints = h('ul', { class: 'pf-hints', hidden: true });
    const form = h('div', { class: 'form-row tool-form pf-form' },
      h('div', { class: 'field' }, h('label', null, TEXTS.portLabel), els.port), els.btn);
    const body = h('div', { class: 'tool-body' },
      h('div', { class: 'tool-intro' }, TEXTS.intro), form, els.blocked, els.result, els.hints,
      h('div', { class: 'tool-note pf-note' }, TEXTS.portNote));

    function render() {
      if (!mounted) return;
      const v = portView(result, { testing, error: err, natVerdict: statusVerdict() });
      TNT.ui.busy(els.btn, testing, TEXTS.portBusy);
      if (!testing) els.btn.disabled = v.disabled;
      const k = JSON.stringify(v);
      if (k === key) return;
      key = k;
      els.blocked.innerHTML = '';
      els.blocked.hidden = !v.blocked;
      if (v.blocked) { els.blocked.appendChild(TNT.ui.icon('warning')); els.blocked.appendChild(h('span', null, v.blocked)); }
      els.result.innerHTML = '';
      els.result.hidden = !v.text;
      if (v.text) {
        els.result.className = 'tool-summary pf-result ' + v.cls;
        els.result.appendChild(TNT.ui.icon(v.cls === 'ok' ? 'check' : 'warning'));
        els.result.appendChild(h('span', null, v.text));
        if (v.detail) els.result.appendChild(h('span', { class: 'muted' }, '· ' + v.detail));
      }
      els.hints.innerHTML = '';
      els.hints.hidden = !v.hints.length;
      for (const t of v.hints) els.hints.appendChild(h('li', null, t));
    }

    async function test() {
      if (!mounted || testing || statusVerdict() === 'vpn') return;
      const p = validPort(els.port.value);
      const mine = ++seq;
      result = null;
      if (!p.ok) {
        err = { status: 400, code: 'bad_request', message: p.error };
        render();
        try { els.port.focus(); } catch (e) { /* ignore */ }
        return;
      }
      err = null;
      testing = true;
      render();
      try {
        const r = await TNT.api.portForwardTest(p.port);
        if (!mounted || mine !== seq) return;
        result = isObj(r) && sameGen(r) ? r : null;        // an answer about the network this PC left is ignored
      } catch (e) {
        if (!mounted || mine !== seq) return;
        err = { status: e.status || 0, code: e.code || '', message: e.message || '' };
      } finally {
        if (mounted && mine === seq) { testing = false; render(); }
      }
    }

    return {
      body,
      head: null,
      mount() { mounted = true; gen = currentGen(); render(); },
      update(state) {
        if (!mounted) return;
        const st = state && state.status;
        const g = st && st.net && st.net.generation != null ? st.net.generation : null;
        if (g != null && gen == null) gen = g;
        render();          // the VPN block follows the status's NAT verdict (when one is there)
      },
      /* This PC changed networks: the result, an error and the hints go at once; the typed port stays. */
      netChanged(info, state) {
        seq++;
        const st = state && state.status;
        gen = st && st.net && st.net.generation != null ? st.net.generation : currentGen();
        result = null; err = null; testing = false;
        render();
      },
      unmount() { mounted = false; seq++; result = null; err = null; testing = false; },
    };
  }

  TNT.tools.portforward = { create, portView, validPort, TEXTS };
})();
