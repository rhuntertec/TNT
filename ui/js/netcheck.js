/* TNT — netcheck.js
   The "NAT & switch port" card of Network info: one cell of the adapter grid that views/ipinfo.js puts right after the
   live link map (create() -> { el, update(state), unmount() }). Two sections:
   * NAT: GET /api/netcheck/nat when the card is made and on every new status.net.generation. A result of this network
     under 10 min old is shown; otherwise the check is POSTed once the link map has this network's public address (or 120 s
     after the change). While a check runs (ours, another window's, a 409 or a request that timed out on this side) the
     badge reads "Checking…" and GET is polled every 2 s. Details (folded): the router's own internet address, the public
     address, UPnP, the forwards the router shares over UPnP (a "Show" table) and the self-traceroute path.
   * Switch port - LLDP: "Find switch port" (with a select when two or more wired adapters are up) asks the service to
     listen for LLDP / CDP (POST /api/netcheck/switch). While it listens a fuse counts the seconds down, and GET is polled
     every 2 s besides the netcheck.switch events. The result line names the switch, the port, its manufacturer and the
     VLAN; Details (folded) the rest.
   The port-forward test moved to its own Tools card (js/tools/portforward.js). A new network generation clears every
   result on screen at once and starts over. Whatever comes from the router or the switch is inserted as text, never as markup.
   Loaded before app.js: TNT.util / TNT.ui / TNT.state are only touched inside functions. */
(function () {
  'use strict';
  window.TNT = window.TNT || {};
  const TNT = window.TNT;

  const FRESH_S = 600;                  // a NAT result of this network younger than this is shown instead of a new check
  const WAN_WAIT_S = 120;               // after a network change the check waits at most this long for the public address
  const POLL_MS = 2000;                 // GET while a NAT check runs or the switch is being listened for
  const TICK_MS = 1000;                 // the listening fuse's countdown
  const NO_PUBLIC_IP = 'no public address yet';
  const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  let seq = 0;                          // ids for aria-controls, one set per card

  /** The service's NAT_TEXT (tnt/natcheck.py): verdict -> [title, explanation], shown as they are. */
  const NAT_TEXT = {
    no_nat: ['No NAT', 'This PC has the public address itself. Nothing to forward: Windows Firewall decides what gets in.'],
    single_nat: ['Single NAT', 'One router holds the public address. Port forwards on it work, unless the ISP blocks the port.'],
    double_nat: ['Double NAT', 'Another NAT sits between this network\'s router and the internet (usually the ISP modem or gateway, sometimes the ISP itself). Forward ports on both, or put the ISP box in bridge / IP-passthrough mode.'],
    cgnat: ['Carrier-grade NAT (CGNAT)', 'The ISP shares one public address between customers, so port forwarding from the internet cannot work on IPv4. Ask the ISP for a public or static IP, or use the device\'s cloud/P2P service or a VPN.'],
    upstream_nat: ['NAT beyond the router', 'Websites see an address the router does not have, so something beyond it translates again (ISP NAT, an upstream firewall, a second line or a VPN).'],
    nat_unclear_private_wan: ['Probably behind another NAT', 'The router reports no usable public address although the internet works. That usually means it sits behind another NAT.'],
    vpn: ['Traffic leaves through a VPN', 'This PC\'s internet traffic goes through a VPN, so a check would describe the VPN, not this site\'s router. Disconnect it and check again.'],
    offline: ['Could not check', 'No internet connection (or no public address yet), so NAT cannot be checked.'],
    unknown: ['Could not tell', 'The router does not answer UPnP or NAT-PMP and the path gave no clear sign.'],
  };
  const VERDICT_CLASS = { no_nat: 'green', single_nat: 'green', double_nat: 'yellow', upstream_nat: 'yellow', nat_unclear_private_wan: 'yellow',
    unknown: 'yellow', vpn: 'yellow', cgnat: 'red', offline: 'grey' };
  const SWITCH_RESULT_NOTE = 'If a small switch or a phone sits between this PC and the wall jack, this is the port that switch or phone is plugged into.';

  const TEXTS = {
    NAT_TEXT, SWITCH_RESULT_NOTE,
    title: 'NAT & switch port',
    checking: 'Checking…',
    waiting: 'Waiting for this network\'s public address',
    checkAgain: 'Check again',
    natBusy: 'A NAT check is already running',
    natUnavailable: 'The NAT check is not available on this service',
    forwardsNote: 'Only forwards the router shares over UPnP; ones made in its own settings page may be missing.',
    findSwitch: 'Find switch port',
    switchLabel: 'Switch port - LLDP',
    listening: 'Listening for the switch…',
    stop: 'Stop',
    tryAgain: 'Try again',
    noWired: 'Needs a wired (Ethernet) connection',
    switchUnavailable: 'Finding the switch port is not available on this service',
  };

  /* ------------------------------------------------ pure helpers (tests) */
  const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
  const isNum = (v) => typeof v === 'number' && isFinite(v);

  /* The service's address ranges (tnt/natcheck.py range_of), checked in this order: explicit networks, never a library's idea
     of "private" or "global". Everything else is public, the documentation ranges included. */
  const RANGES = [
    ['private', '10.0.0.0', 8], ['private', '172.16.0.0', 12], ['private', '192.168.0.0', 16],
    ['shared', '100.64.0.0', 10], ['shared', '192.0.0.0', 29],
    ['reserved', '0.0.0.0', 8], ['reserved', '127.0.0.0', 8], ['reserved', '169.254.0.0', 16], ['reserved', '192.0.0.0', 24],
    ['reserved', '198.18.0.0', 15], ['reserved', '224.0.0.0', 4], ['reserved', '240.0.0.0', 4],
  ];
  function ipv4Number(text) {
    if (typeof text !== 'string' || !IPV4_RE.test(text)) return null;
    return text.split('.').reduce((n, octet) => n * 256 + Number(octet), 0);
  }

  /** Pure: 'private' | 'shared' | 'reserved' | 'public' for a dotted-quad IPv4 address, null for anything else. */
  function rangeOf(ip) {
    const n = ipv4Number(ip);
    if (n == null) return null;
    for (const [name, net, prefix] of RANGES) {
      const base = ipv4Number(net);
      if (n >= base && n < base + Math.pow(2, 32 - prefix)) return name;
    }
    return 'public';
  }

  /** Whether the link map has looked this network's public address up (status.map.public_ip.ts at or after
   *  status.net.changed_ts), there is no change or no map to wait for, or WAN_WAIT_S have passed since the change. */
  function addressReady(status, now) {
    const st = isObj(status) ? status : {};
    const changed = isObj(st.net) && isNum(st.net.changed_ts) ? st.net.changed_ts : null;
    if (changed == null || !isObj(st.map)) return true;
    const pip = isObj(st.map.public_ip) ? st.map.public_ip : null;
    if (pip && isNum(pip.ts) && pip.ts >= changed) return true;
    return isNum(now) && now - changed >= WAN_WAIT_S;
  }

  /** Whether status.map.public_ip carries an address found on this network (its ts at or after the change). */
  function addressFound(status) {
    const st = isObj(status) ? status : {};
    const changed = isObj(st.net) && isNum(st.net.changed_ts) ? st.net.changed_ts : null;
    const pip = isObj(st.map) && isObj(st.map.public_ip) ? st.map.public_ip : null;
    return !!(pip && pip.ip && isNum(pip.ts) && (changed == null || pip.ts >= changed));
  }

  /** Pure: what the NAT section shows for a NAT_RESULT (or null) -> { verdict, cls, badge, confidence, explanation, waiting,
   *  error, rows, mappings, forwardsNote }. ctx: { running, error, status (state.status), now }.
   *  * Without a result, or while a check runs: a grey "Checking…" badge; `waiting` when no check runs and the link map has no
   *    public address for this network yet (the card checks once it has).
   *  * A failed request (ctx.error): a grey "Could not check" badge with the reason as the explanation.
   *  * A result: its verdict's title as the badge (coloured by verdict), "· high confidence" and the explanation. `rows` are the
   *    Details rows, each { k, v, copy, suffix, muted, lines, count }; `mappings` the "Show" table's rows. */
  function natView(result, ctx) {
    const c = ctx || {};
    const r = isObj(result) && result.verdict ? result : null;
    const base = { verdict: 'checking', cls: 'grey', badge: TEXTS.checking, confidence: '', explanation: '', waiting: false, error: '',
      rows: [], mappings: [], forwardsNote: '' };
    if (c.running) return base;
    if (!r && c.error) return Object.assign(base, { verdict: 'error', badge: NAT_TEXT.offline[0], explanation: String(c.error), error: String(c.error) });
    if (!r) return Object.assign(base, { waiting: !addressReady(c.status, c.now) });
    const verdict = String(r.verdict);
    const text = NAT_TEXT[verdict] || [String(r.title || verdict), String(r.explanation || '')];
    const router = isObj(r.router) ? r.router : {};
    const upnp = isObj(router.upnp) ? router.upnp : {};
    const rows = [];
    const source = router.wan_source === 'upnp' ? ' (UPnP)' : router.wan_source === 'natpmp' ? ' (NAT-PMP)' : '';
    rows.push(router.wan_ip ? { k: 'Router\'s own internet address', v: String(router.wan_ip), copy: true, suffix: source }
      : { k: 'Router\'s own internet address', v: 'none reported', muted: true });
    rows.push(r.public_ip ? { k: 'Public address', v: String(r.public_ip), copy: true, suffix: ' (WAN on the map)' }
      : { k: 'Public address', v: '—', muted: true });
    const model = upnp.model || upnp.server;
    rows.push({ k: 'UPnP', v: upnp.found ? 'on' + (model ? ' · ' + String(model) : '') : 'no answer' });
    const pm = isObj(r.port_mappings) ? r.port_mappings : null;
    const entries = pm && Array.isArray(pm.entries) ? pm.entries.filter(isObj) : [];
    if (pm) {
      rows.push(entries.length ? { k: 'UPnP forwards', v: entries.length + ' listed', count: entries.length }
        : { k: 'UPnP forwards', v: pm.error ? String(pm.error) : 'none listed', muted: !pm.error });
    }
    const dash = (x) => (x == null || x === '' ? '?' : String(x));
    const mappings = entries.map((m) => ({ protocol: dash(m.protocol), forward: dash(m.external_port) + ' → ' + dash(m.internal_client) + ':' + dash(m.internal_port),
      description: m.description ? String(m.description) : '' }));
    if (isObj(r.trace)) {
      const hops = Array.isArray(r.trace.hops) ? r.trace.hops.filter(isObj) : [];
      rows.push({ k: 'Path', lines: hops.map((hp) => {
        const range = hp.ip ? (hp.range || rangeOf(hp.ip)) : null;
        return dash(hp.ttl) + ' ' + (hp.ip ? String(hp.ip) : '*') + (range ? ' (' + range + ')' : '');
      }) });
    }
    return { verdict, cls: VERDICT_CLASS[verdict] || 'yellow', badge: text[0], confidence: r.confidence ? '· ' + r.confidence + ' confidence' : '',
      explanation: text[1], waiting: false, error: '', rows, mappings, forwardsNote: upnp.found ? TEXTS.forwardsNote : '' };
  }

  /** Pure: one neighbour of a switch-port job (NEIGHBOR) -> { line, rows, via, note }. line: "LAB-SW-01 · Port 7 · Example
   *  Networks · VLAN 10", where the vendor (the switch manufacturer) and the VLAN appear only when known; rows: the Details
   *  rows that are known, each { k, v } (v a list for the management addresses, copy chips); via: "via LLDP · 2 min ago"
   *  (opts.ago, the card's relTime of the job); note: SWITCH_RESULT_NOTE. The vendor is an untrusted string (a text node). */
  function neighborView(n, opts) {
    const o = opts || {};
    const nb = isObj(n) ? n : {};
    const known = (v) => v != null && v !== '';
    const name = known(nb.switch_name) ? String(nb.switch_name) : 'Unknown switch';
    const port = known(nb.port_description) ? String(nb.port_description) : known(nb.port_id) ? String(nb.port_id) : 'unknown port';
    const line = name + ' · ' + port + (known(nb.vendor) ? ' · ' + String(nb.vendor) : '') + (known(nb.vlan) ? ' · VLAN ' + nb.vlan : '');
    const rows = [];
    const add = (k, v) => { if (known(v)) rows.push({ k, v: String(v) }); };
    add('Switch description', nb.switch_description);
    add('Port ID', nb.port_id);
    add('VLAN', nb.vlan);
    add('Voice VLAN', nb.voice_vlan);
    const poe = isObj(nb.poe) ? nb.poe : null;
    if (poe && (known(poe.class) || isNum(poe.allocated_w))) {
      add('PoE', [known(poe.class) ? 'class ' + poe.class : '', isNum(poe.allocated_w) ? poe.allocated_w.toFixed(1) + ' W' : ''].filter(Boolean).join(' · '));
    }
    if (isObj(nb.link)) add('Link', nb.link.text);
    const ips = Array.isArray(nb.management_ips) ? nb.management_ips.filter(known).map(String) : [];
    if (ips.length) rows.push({ k: 'Management IP', v: ips, copy: true });
    const proto = known(nb.protocol) ? String(nb.protocol).toUpperCase() : '';
    const via = proto ? 'via ' + proto + (o.ago ? ' · ' + o.ago : '') : (o.ago || '');
    return { line, rows, via, note: SWITCH_RESULT_NOTE };
  }

  /* ------------------------------------------------------------- card */
  function create() {
    const { h } = TNT.util;
    const id = 'nc-' + (++seq);
    const st0 = TNT.state && TNT.state.status;
    let alive = true;
    let gen = st0 && st0.net && st0.net.generation != null ? st0.net.generation : null;   // the network on screen
    let unsubs = [];
    const els = {};
    const status = () => (TNT.state && TNT.state.status) || null;
    /** An answer about this network (or one that does not say which). */
    const sameGen = (x) => gen == null || !x || x.generation == null || x.generation === gen;

    /* ============================================================ NAT */
    let nat = null;                 // the NAT_RESULT on screen, always this network's
    let natRunning = false;         // a check runs: the service says so, or our request got a 409 or timed out here
    let natPosting = false;         // our POST is in flight
    let natError = '';              // why the section cannot check (a request that failed)
    let natLoaded = false;          // this network's first GET answered
    let natPosted = false;          // this network's automatic POST went out
    let natAgain = false;           // ... and met a run already going: once that run ends without a result, POST once more
    let natRetried = false;         // the one more POST after "no public address yet"
    let natOpen = false, forwardsOpen = false, natKey = null;
    let natSeq = 0, natPollTimer = null, natWaitTimer = null;

    els.natBadge = h('span', { class: 'badge grey' }, TEXTS.checking);
    els.natConfidence = h('span', { class: 'muted small' });
    els.checkBtn = h('button', { class: 'btn btn-sm', type: 'button', on: { click: () => natPost(true) },
      title: 'Ask this network\'s router again (NAT-PMP and UPnP) and look at the path to the internet' }, TNT.ui.icon('refresh'), TEXTS.checkAgain);
    els.natExplain = h('div', { class: 'nc-explain muted', hidden: true });
    els.natWaiting = h('div', { class: 'nc-waiting muted small', hidden: true }, TEXTS.waiting);
    els.natDetailsBtn = h('button', { class: 'btn btn-sm nc-details-btn', type: 'button', 'aria-expanded': 'false', 'aria-controls': id + '-nat', hidden: true,
      title: 'What the router answered and the path the check took', on: { click: () => { natOpen = !natOpen; renderNat(); } } },
      TNT.ui.icon('chevron'), h('span', null, 'Details'));
    els.natDetails = h('div', { class: 'nc-details', id: id + '-nat', hidden: true });
    const natSection = h('div', { class: 'nc-section nc-nat' },
      h('div', { class: 'nc-head' }, h('span', { class: 'label' }, 'NAT'),
        h('span', { class: 'nc-verdict', role: 'status', 'aria-live': 'polite' }, els.natBadge, els.natConfidence),
        h('span', { class: 'spacer' }), els.checkBtn),
      els.natExplain, els.natWaiting, els.natDetailsBtn, els.natDetails);

    function renderNat() {
      if (!alive) return;
      const { copyCode } = TNT.util;
      const busy = natRunning || natPosting;
      const v = natView(nat, { running: busy, error: natError, status: status(), now: TNT.util.nowS() });
      els.checkBtn.disabled = natPosting;
      const key = JSON.stringify(v) + '|' + busy + '|' + natOpen + '|' + forwardsOpen;
      if (key === natKey) return;
      natKey = key;
      els.natBadge.className = 'badge ' + v.cls + (busy ? ' pulse' : '');
      els.natBadge.textContent = v.badge;
      els.natConfidence.textContent = v.confidence;
      els.natExplain.textContent = v.explanation;
      els.natExplain.hidden = !v.explanation;
      els.natWaiting.hidden = !v.waiting;
      const rows = v.rows;
      els.natDetailsBtn.hidden = !rows.length;
      els.natDetailsBtn.setAttribute('aria-expanded', String(natOpen && rows.length > 0));
      const refocus = document.activeElement && document.activeElement.classList && document.activeElement.classList.contains('nc-show-btn')
        && els.natDetails.contains(document.activeElement);
      els.natDetails.innerHTML = '';
      els.natDetails.hidden = !(natOpen && rows.length);
      if (!rows.length) return;
      const kv = h('div', { class: 'kv' });
      let showBtn = null;
      for (const row of rows) {
        let value;
        if (row.lines) value = row.lines.length ? h('span', { class: 'nc-path' }, row.lines.map((t) => h('span', null, t))) : h('span', { class: 'muted' }, '—');
        else if (row.copy) value = [copyCode(row.v), row.suffix ? h('span', { class: 'muted' }, row.suffix) : null];
        else if (row.count) {
          showBtn = h('button', { class: 'btn btn-sm nc-show-btn', type: 'button', 'aria-expanded': String(forwardsOpen), 'aria-controls': id + '-forwards',
            on: { click: () => { forwardsOpen = !forwardsOpen; renderNat(); } } }, forwardsOpen ? 'Hide' : 'Show');
          value = [h('span', null, row.v), showBtn];
        } else value = h('span', row.muted ? { class: 'muted' } : null, row.v);
        kv.appendChild(h('span', { class: 'k' }, row.k));
        kv.appendChild(h('span', { class: 'v' }, value));
      }
      els.natDetails.appendChild(kv);
      if (v.mappings.length && forwardsOpen) {
        els.natDetails.appendChild(h('div', { class: 'table-wrap nc-forwards', id: id + '-forwards' },
          h('table', { class: 'table' },
            h('thead', null, h('tr', null, h('th', null, 'Protocol'), h('th', null, 'Forward'), h('th', null, 'Description'))),
            h('tbody', null, v.mappings.map((m) => h('tr', null, h('td', null, m.protocol), h('td', null, m.forward),
              h('td', { class: 'wrap' }, m.description || h('span', { class: 'muted' }, '—'))))))));
      }
      if (v.forwardsNote) els.natDetails.appendChild(h('div', { class: 'nc-note muted small' }, v.forwardsNote));
      if (refocus && showBtn) { try { showBtn.focus(); } catch (e) { /* ignore */ } }
    }

    function stopNatPoll() {
      if (natPollTimer) { clearTimeout(natPollTimer); natPollTimer = null; }
      if (natWaitTimer) { clearTimeout(natWaitTimer); natWaitTimer = null; }
    }
    function scheduleNatPoll() {
      if (natPollTimer || !alive) return;
      natPollTimer = setTimeout(() => { natPollTimer = null; if (alive) natLoad(); }, POLL_MS);
    }

    /** GET: follows a check that runs, and shows a result of this network under FRESH_S old. */
    async function natLoad() {
      const mine = natSeq;
      let r;
      try {
        r = await TNT.api.natGet();
      } catch (err) {
        if (!alive || mine !== natSeq) return;
        natLoaded = true;
        if (err.status === 404 || err.status === 503) {
          natError = err.status === 503 && err.message ? err.message : TEXTS.natUnavailable;
          natRunning = false;
          stopNatPoll();
        } else if (natRunning) scheduleNatPoll();          // a poll that failed: try again in a moment
        renderNat();
        natDecide();
        return;
      }
      if (!alive || mine !== natSeq) return;
      natLoaded = true;
      if (!natPosting) natError = '';
      const res = r && isObj(r.result) ? r.result : null;
      natRunning = !!(r && r.running);
      if (res && sameGen(res) && isNum(res.ts) && TNT.util.nowS() - res.ts < FRESH_S) nat = res;
      renderNat();
      natDecide();
    }

    /** What happens next once this network's GET has answered: poll while a check runs; otherwise POST once the link map has
     *  this network's public address (and once more after an offline "no public address yet" answer, when it appears). */
    function natDecide() {
      if (!alive || !natLoaded || natPosting) return;
      if (natRunning) { scheduleNatPoll(); return; }
      stopNatPoll();
      const st = status();
      if (nat) {
        if (nat.verdict === 'offline' && nat.error === NO_PUBLIC_IP && !natRetried && addressFound(st)) { natRetried = true; natPost(false); }
        return;
      }
      if (natError || (natPosted && !natAgain)) return;
      if (addressReady(st, TNT.util.nowS())) {
        natPosted = true;
        natAgain = false;
        natPost(false);
      } else if (!natWaitTimer) {
        // waiting for the link map's public address: look again in a moment (a status snapshot may bring it sooner)
        natWaitTimer = setTimeout(() => { natWaitTimer = null; if (alive) { renderNat(); natDecide(); } }, POLL_MS);
      }
    }

    /** POST: the automatic check, or "Check again" (manual: a 409 says so in a toast). */
    async function natPost(manual) {
      if (!alive || natPosting) return;
      const mine = natSeq;
      natPosting = true;
      natError = '';
      stopNatPoll();
      renderNat();
      try {
        const r = await TNT.api.natRun();
        if (!alive || mine !== natSeq) return;
        const res = r && isObj(r.result) ? r.result : null;
        natRunning = false;
        // an answer about another network is dropped: the status snapshot that names that network restarts the check
        if (res && sameGen(res)) nat = res;
      } catch (err) {
        if (!alive || mine !== natSeq) return;
        if (err.status === 409 || err.code === 'timeout') {
          // a check runs already (another window), or ours is still running on the service: follow it
          if (manual && err.status === 409) TNT.ui.toast(TEXTS.natBusy, 'warn');
          natRunning = true;
          natAgain = true;
        } else {
          natRunning = false;
          natError = err.status === 404 ? TEXTS.natUnavailable : err.status === 503 && err.message ? err.message : 'Could not check NAT: ' + (err.message || 'unknown error');
          // nothing was checked: once a GET answers again ('hello' after the service is back) the automatic check runs again
          natPosted = false;
          // the verdict on screen stays (natView shows a result before an error): say that "Check again" failed
          if (manual && nat) TNT.ui.toast(natError, 'error');
        }
      } finally {
        if (alive && mine === natSeq) { natPosting = false; renderNat(); natDecide(); }
      }
    }

    /** The NAT section of a new network: nothing on screen, "Checking…", then GET. */
    function natReset() {
      natSeq++;
      stopNatPoll();
      nat = null; natRunning = false; natPosting = false; natError = ''; natLoaded = false; natPosted = false; natAgain = false; natRetried = false;
      forwardsOpen = false;
    }
    /* ==================================================== switch port */
    let sw = null;                  // SWITCH_STATUS: { job, adapters, available, reason }
    let swError = '';               // why the section cannot look (a request that failed)
    let swBusy = false;             // a start or stop request is in flight
    let swAdapter = '';             // the adapter picked in the select (two or more wired adapters)
    let swOpen = false, swKey = null;
    let swSeq = 0, swPollTimer = null, swTickTimer = null;

    els.swBody = h('div', { class: 'nc-switch-body' });
    els.swFuse = TNT.ui.fuse();
    const swSection = h('div', { class: 'nc-section nc-switch' },
      h('div', { class: 'nc-head' }, h('span', { class: 'label' }, TEXTS.switchLabel)), els.swBody);

    const swJob = () => (sw && isObj(sw.job) ? sw.job : null);
    const listening = () => { const j = swJob(); return !!j && j.state === 'listening'; };
    /** The job worth showing: one that listens (a listen carries on across a network change) or this network's finished one. */
    function shownJob() {
      const j = swJob();
      if (!j || j.state === 'idle' || j.state === 'cancelled') return null;
      return j.state === 'listening' || sameGen(j) ? j : null;
    }
    /** How far a listen is: the service's elapsed_s moved on by the time since that snapshot (at most 5 s, so a stalled poll
     *  does not run the countdown out) -> { left (whole seconds), pct }. */
    function listenTime(j) {
      const total = isNum(j.listen_s) ? j.listen_s : 0;
      const since = isNum(j.ts) ? Math.min(5, Math.max(0, TNT.util.nowS() - j.ts)) : 0;
      const elapsed = (isNum(j.elapsed_s) ? j.elapsed_s : 0) + since;
      return { left: Math.max(0, Math.ceil(total - elapsed)), pct: total > 0 ? Math.min(1, elapsed / total) : 0 };
    }

    function renderSwitch() {
      if (!alive) return;
      const { copyCode, relTime } = TNT.util;
      const j = shownJob();
      const adapters = sw && Array.isArray(sw.adapters) ? sw.adapters.filter(isObj) : [];
      if (j && j.state === 'listening') {
        const t = listenTime(j);
        els.swFuse.set(t.pct, 'running', TEXTS.listening + ' ' + t.left + ' s', '');
      }
      // the fuse moves every second; everything else is rebuilt only when it changed (a focused button stays put)
      const ago = j && j.state !== 'listening' && isNum(j.ts) ? relTime(j.ts) : '';
      const key = JSON.stringify([swError, !!sw, sw && sw.available, sw && sw.reason, adapters, j && Object.assign({}, j, { elapsed_s: null, ts: null }),
        ago, swBusy, swOpen, swAdapter]);
      if (key === swKey) return;
      swKey = key;
      const focused = document.activeElement;
      const role = focused && els.swBody.contains(focused) && focused.dataset ? focused.dataset.nc : null;
      els.swBody.innerHTML = '';
      const add = (el) => { els.swBody.appendChild(el); return el; };
      if (swError) { add(h('div', { class: 'muted small' }, swError)); return; }
      if (!sw) { add(h('div', { class: 'muted small' }, 'Loading…')); return; }
      if (j && j.state === 'listening') {
        add(els.swFuse);
        add(h('div', { class: 'nc-actions' }, h('button', { class: 'btn btn-sm', type: 'button', disabled: swBusy, data: { nc: 'stop' }, on: { click: switchStop },
          title: 'Stop listening for the switch' }, TNT.ui.icon('stop'), TEXTS.stop)));
      } else if (sw.available === false) {
        add(h('div', { class: 'muted small' }, String(sw.reason || TEXTS.switchUnavailable)));
      } else {
        const found = j && j.state === 'done' && Array.isArray(j.neighbors) ? j.neighbors.filter(isObj) : [];
        if (found.length) {
          const views = found.map((n) => neighborView(n, { ago }));
          for (const v of views) add(h('div', { class: 'nc-result strong' }, v.line));
          add(h('button', { class: 'btn btn-sm nc-details-btn', type: 'button', 'aria-expanded': String(swOpen), 'aria-controls': id + '-switch', data: { nc: 'details' },
            title: 'Everything the switch said about this port', on: { click: () => { swOpen = !swOpen; renderSwitch(); } } },
            TNT.ui.icon('chevron'), h('span', null, 'Details')));
          const box = add(h('div', { class: 'nc-details', id: id + '-switch', hidden: !swOpen }));
          for (const v of views) {
            const kv = h('div', { class: 'kv' });
            for (const row of v.rows) {
              kv.appendChild(h('span', { class: 'k' }, row.k));
              kv.appendChild(h('span', { class: 'v' }, Array.isArray(row.v) ? row.v.map((x) => copyCode(x)) : row.v));
            }
            box.appendChild(kv);
            if (v.via) box.appendChild(h('div', { class: 'muted small' }, v.via));
          }
          box.appendChild(h('div', { class: 'nc-note muted small' }, views[0].note));
        } else if (j && (j.state === 'done' || j.state === 'error')) {
          const why = j.state === 'done' ? j.reason : j.error;
          add(h('div', { class: 'tool-summary warn nc-reason' }, TNT.ui.icon('warning'), h('span', null, String(why || 'No switch answered'))));
        }
        if (!adapters.length) {
          add(h('div', { class: 'muted small' }, TEXTS.noWired));
        } else {
          const retry = !!j && !found.length && (j.state === 'done' || j.state === 'error');
          const row = add(h('div', { class: 'nc-actions' }));
          if (adapters.length >= 2) {
            const names = adapters.map((a) => String(a.name || ''));
            if (!names.includes(swAdapter)) swAdapter = String((adapters.find((a) => a.is_internet) || adapters[0]).name || '');
            const sel = h('select', { class: 'input sm', 'aria-label': 'Wired adapter', disabled: swBusy, data: { nc: 'adapter' },
              on: { change: (e) => { swAdapter = e.target.value; } } },
              adapters.map((a) => h('option', { value: String(a.name || '') }, String(a.name || '?') + (a.is_internet ? ' (internet)' : ''))));
            sel.value = swAdapter;
            row.appendChild(sel);
          }
          row.appendChild(h('button', { class: 'btn btn-sm', type: 'button', disabled: swBusy, data: { nc: 'find' }, on: { click: switchStart },
            title: 'Listen for the switch\'s LLDP or CDP announcement on this wired adapter (about a minute at most)' },
            TNT.ui.icon('search'), retry ? TEXTS.tryAgain : TEXTS.findSwitch));
        }
      }
      if (role) {
        const next = els.swBody.querySelector('[data-nc="' + role + '"]') || els.swBody.querySelector('button');
        if (next) { try { next.focus(); } catch (e) { /* ignore */ } }
      }
    }

    function stopSwitchTimers() {
      if (swPollTimer) { clearTimeout(swPollTimer); swPollTimer = null; }
      if (swTickTimer) { clearInterval(swTickTimer); swTickTimer = null; }
    }
    /** While the service listens: GET every POLL_MS (besides the netcheck.switch events) and a one-second countdown. */
    function followSwitch() {
      if (!alive) return;
      if (!listening()) { stopSwitchTimers(); return; }
      if (!swPollTimer) swPollTimer = setTimeout(() => { swPollTimer = null; if (alive) switchLoad(); }, POLL_MS);
      if (!swTickTimer) swTickTimer = setInterval(() => { if (alive && listening()) renderSwitch(); }, TICK_MS);
    }

    async function switchLoad() {
      const mine = swSeq;
      try {
        const r = await TNT.api.switchGet();
        if (!alive || mine !== swSeq) return;
        sw = isObj(r) ? r : null;
        swError = '';
      } catch (err) {
        if (!alive || mine !== swSeq) return;
        if (err.status === 404 || err.status === 503) { sw = null; swError = err.status === 503 && err.message ? err.message : TEXTS.switchUnavailable; }
        else if (!sw) swError = 'Could not read the switch port: ' + (err.message || 'unknown error');
        // a failed poll keeps what is on screen and tries again
      }
      renderSwitch();
      followSwitch();
    }

    async function switchStart() {
      if (!alive || swBusy) return;
      const mine = swSeq;
      swBusy = true;
      renderSwitch();
      try {
        const r = await TNT.api.switchStart({ adapter: swAdapter || null, seconds: null });
        if (!alive || mine !== swSeq) return;
        if (r && isObj(r.job)) sw = Object.assign({}, sw || {}, { job: r.job });
        swOpen = false;
      } catch (err) {
        if (!alive || mine !== swSeq) return;
        if (err.status === 404 || err.status === 503) swError = err.status === 503 && err.message ? err.message : TEXTS.switchUnavailable;
        else TNT.ui.toast(err.message || 'Could not start listening for the switch', 'warn');
        if (err.status === 409) switchLoad();            // Packet Monitor is busy or cannot run: read the status again
      } finally {
        if (alive && mine === swSeq) { swBusy = false; renderSwitch(); followSwitch(); }
      }
    }

    async function switchStop() {
      if (!alive || swBusy) return;
      const mine = swSeq;
      swBusy = true;
      renderSwitch();
      try {
        const r = await TNT.api.switchStop();
        if (!alive || mine !== swSeq) return;
        if (r && isObj(r.job)) sw = Object.assign({}, sw || {}, { job: r.job });
      } catch (err) {
        if (!alive || mine !== swSeq) return;
        TNT.ui.toast(err.message || 'Could not stop listening for the switch', 'warn');
      } finally {
        if (alive && mine === swSeq) { swBusy = false; renderSwitch(); followSwitch(); }
      }
    }

    function onSwitchEvent(d) {
      if (!alive || !sw || !d || !isObj(d.job)) return;
      sw = Object.assign({}, sw, { job: d.job });
      renderSwitch();
      followSwitch();
    }

    /** The switch section of a new network: the result goes at once, then GET (a listen that carries on comes back with it). */
    function switchReset() {
      swSeq++;
      stopSwitchTimers();
      swBusy = false; swOpen = false;
      if (sw) sw = Object.assign({}, sw, { job: null });
    }

    /* =========================================================== card */
    const el = h('div', { class: 'card netcheck-card' }, h('div', { class: 'card-title' }, TEXTS.title), natSection, swSection);

    /** This PC is on another network: every result goes at once, the NAT badge reads "Checking…", the switch status is read
     *  again and the NAT check starts over. */
    function networkChanged() {
      natReset();
      switchReset();
      renderNat();
      renderSwitch();
      switchLoad();
      natLoad();
    }

    unsubs.push(TNT.api.events.on('netcheck.switch', onSwitchEvent));
    // the service restarted: its switch job and NAT result may be gone
    unsubs.push(TNT.api.events.on('hello', () => { if (!alive) return; switchLoad(); if (natLoaded && !natPosting) natLoad(); }));
    renderNat();
    renderSwitch();
    switchLoad();
    natLoad();

    return {
      el,
      update(state) {
        if (!alive) return;
        const st = state && state.status;
        const g = st && st.net && st.net.generation != null ? st.net.generation : null;
        if (g != null && gen != null && g !== gen) { gen = g; networkChanged(); return; }
        if (g != null && gen == null) gen = g;
        renderNat();          // the waiting line follows the link map's public address
        renderSwitch();       // "via LLDP · 2 min ago"
        natDecide();
      },
      unmount() {
        alive = false;
        for (const u of unsubs) { try { u(); } catch (e) { /* ignore */ } }
        unsubs = [];
        stopNatPoll();
        stopSwitchTimers();
        natSeq++; swSeq++;
      },
    };
  }

  TNT.netcheck = { create, natView, neighborView, rangeOf, TEXTS };
})();
