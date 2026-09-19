/* TNT — views/sip.js
   The SIP page: would calls work on this network, and if they don't, why not.

   Four questions, in the order a tech asks them:

     1. Qualify the line. The rating is read out of what TNT has already been collecting — the ping history for
        this network and the last speed test — and split into a LAN leg and a WAN leg, because one number would
        hide the distinction that decides who fixes it. A bad gateway is the switch or the Wi-Fi and it is in the
        building; a bad internet leg with a clean gateway is a call to the provider. Name the PBX and it is graded
        as a third leg, on the path the calls actually take. The call-quality lines and the Zoom/Teams checks live
        here rather than on the Speed page: they are about calls, and this is the calls page. The bufferbloat grade
        stays on Speed, where the measurement is made, and is repeated here only when it is bad enough to break a
        call.
     2. Is something rewriting the SIP? The ALG check sends an OPTIONS to the customer's own server from two source
        ports and compares what comes back with what went out. It is honest about what it can prove: "clean" is not
        "there is no ALG", and silence is its own verdict.
     3. Will the audio get back? The STUN test asks two servers from one socket. Two different external ports is
        the classic one-way-audio NAT. The binding-lifetime test has its own button because it sits idle for
        minutes and is never what somebody wants by accident.
     4. What actually happened on the call? Load one capture, or two from both sides of the network, and every call
        is laddered — INVITE, ringing, answer, the RTP, the BYE. Click a call for the ladder, click any row in the
        ladder for that packet's headers, read back out of the file when it is asked for. Two captures are merged
        on Call-ID and the clock skew between them is measured, not assumed.

   GET /api/sip/qualifier on mount and when the network changes; the three checks are POSTs that block while they
   run, and each keeps its last result so the page has something to show after a reload. Loaded after the other
   views; TNT.util / TNT.ui are only touched inside functions. */
(function () {
  'use strict';
  window.TNT = window.TNT || {};
  const TNT = window.TNT;
  TNT.views = TNT.views || {};

  const isObj = (v) => !!v && typeof v === 'object';
  const isNum = (v) => typeof v === 'number' && isFinite(v);

  const LEVEL_BADGE = { bad: 'red', warn: 'yellow', info: 'blue', good: 'green' };
  const LEVEL_TEXT = { bad: 'Problem', warn: 'Worth checking', info: 'Note', good: 'Good' };
  const LEVEL_ORDER = ['bad', 'warn', 'info', 'good'];
  const GRADE_BADGE = {
    excellent: 'green', good: 'green', fair: 'yellow', poor: 'red', bad: 'red', unknown: 'grey',
  };
  const LEG_TITLE = { lan: 'LAN', wan: 'Internet', sip: 'SIP trunk' };
  const ALG_BADGE = { alg: 'red', clean: 'green', inconclusive: 'grey', moot: 'blue' };
  const ALG_TEXT = {
    alg: 'A SIP ALG is rewriting your SIP',
    clean: 'Nothing rewrote what TNT sent',
    inconclusive: 'Nothing came back to compare',
    moot: 'Encrypted end to end: nothing in the path can read it',
  };
  const MAPPING_BADGE = {
    'endpoint-independent': 'green', 'address-dependent': 'red', none: 'green', unknown: 'grey',
  };
  const MAPPING_TEXT = {
    'endpoint-independent': 'One mapping for every destination',
    'address-dependent': 'A different port per destination — the one-way-audio NAT',
    none: 'Not behind NAT',
    unknown: 'Could not be determined',
  };
  const WINDOWS = [
    { value: '1', label: '1 h' }, { value: '6', label: '6 h' },
    { value: '24', label: '24 h' }, { value: '168', label: '7 d' },
  ];
  //: what a ladder row is coloured by — the things that actually go wrong show up at a glance
  const LADDER_CLASS = (row) => {
    if (row.kind === 'request') return row.method === 'BYE' || row.method === 'CANCEL' ? 'end' : 'req';
    const s = isNum(row.status) ? row.status : 0;
    if (s >= 400) return 'fail';
    if (s >= 300) return 'redirect';
    if (s >= 200) return 'ok';
    return 'prog';
  };

  /* ------------------------------------------------------------- pure views */

  /** Pure: a findings list (FINDING_KEYS) sorted worst first, each as { id, level, cls, what, title, detail,
   *  advice }. Anything without an id or a level TNT knows is left out rather than shown with a blank badge. */
  function findingViews(findings) {
    return (Array.isArray(findings) ? findings : [])
      .filter((f) => isObj(f) && LEVEL_BADGE[f.level])
      .map((f) => ({
        id: String(f.id || ''), level: String(f.level), cls: LEVEL_BADGE[f.level],
        what: LEVEL_TEXT[f.level], title: String(f.title || ''),
        detail: f.detail ? String(f.detail) : '', advice: f.advice ? String(f.advice) : '',
      }))
      .sort((a, b) => LEVEL_ORDER.indexOf(a.level) - LEVEL_ORDER.indexOf(b.level));
  }

  /** Pure: one leg of the rating (LEG_KEYS) -> { kind, title, label, grade, cls, numbers, mos, reason }.
   *  A leg with too little history behind it carries its reason instead of numbers: an ungraded leg must not
   *  look like a graded one. */
  function legView(leg) {
    const l = isObj(leg) ? leg : {};
    const grade = String(l.grade || 'unknown');
    const bits = [];
    if (isNum(l.avg_ms)) bits.push(l.avg_ms + ' ms');
    if (isNum(l.jitter_ms)) bits.push('± ' + l.jitter_ms + ' ms');
    if (isNum(l.loss_pct)) bits.push(l.loss_pct + ' % loss');
    return {
      kind: String(l.kind || ''), title: LEG_TITLE[l.kind] || String(l.kind || ''),
      label: String(l.label || ''), target: String(l.target || ''),
      grade, cls: GRADE_BADGE[grade] || 'grey',
      numbers: grade === 'unknown' ? '' : bits.join(' · '),
      samples: isNum(l.samples) ? l.samples : null,
      mos: isNum(l.mos) ? 'MOS ' + l.mos.toFixed(2) + (l.call_label ? ' (' + l.call_label + ')' : '') : '',
      reason: l.reason ? String(l.reason) : '',
    };
  }

  /** Pure: the last speed test's call block -> { idle, busy, checks: [{label, ok, title}] }. This is the part
   *  of the Speed page's "Latency under load" card that is about calls; the bufferbloat grade stays there. */
  function callQualityView(last) {
    const out = { idle: '', busy: '', checks: [], state: 'none' };
    if (!isObj(last)) return out;
    if (!last.ok) return Object.assign(out, { state: 'failed' });
    const q = isObj(last.quality) ? last.quality : null;
    if (!q || q.available === false) return Object.assign(out, { state: 'missing' });
    const call = isObj(q.call) ? q.call : {};
    const mos = (x) => (isNum(x.mos) ? x.mos.toFixed(2) : '—');
    out.state = 'measured';
    if (isObj(call.idle) && call.idle.label) out.idle = call.idle.label + ' (MOS ' + mos(call.idle) + ')';
    if (isObj(call.loaded) && call.loaded.label) out.busy = call.loaded.label + ' (MOS ' + mos(call.loaded) + ')';
    out.checks = (Array.isArray(call.checks) ? call.checks : []).filter((c) => isObj(c) && c.key)
      .map((c) => ({ label: ({ zoom: 'Zoom', teams: 'Teams' }[c.key] || String(c.key)) + (c.ok ? ' ✓' : ' ✗'),
        ok: !!c.ok, title: c.detail ? String(c.detail) : '' }));
    return out;
  }

  /** Pure: one ladder row (LADDER_KEYS) -> what a line of the flow shows. `rel` is seconds from the first
   *  message of the call, which is the number that matters when reading a flow. */
  function ladderView(row) {
    const r = isObj(row) ? row : {};
    return {
      index: isNum(r.index) ? r.index : 0,
      rel: isNum(r.rel) ? r.rel.toFixed(2) + ' s' : '',
      side: String(r.side || 'a'),
      src: String(r.src || ''), dst: String(r.dst || ''),
      label: String(r.label || (r.method || (r.status ? r.status + ' ' + (r.reason || '') : '?'))),
      kind: String(r.kind || ''), method: r.method ? String(r.method) : null,
      status: isNum(r.status) ? r.status : null,
      sdp: !!r.has_sdp, where: isNum(r.where) ? r.where : null,
      note: r.note ? String(r.note) : '',
      cls: LADDER_CLASS({ kind: r.kind, method: r.method, status: r.status }),
    };
  }

  /** Pure: a merged call (FLOWCALL_KEYS) -> the row the calls list shows. */
  function flowCallView(call) {
    const c = isObj(call) ? call : {};
    const state = String(c.state || '');
    const worst = findingViews(c.findings)[0];
    const sides = Array.isArray(c.sides) ? c.sides : [];
    return {
      id: String(c.id || ''),
      title: String(c.from_uri || 'unknown') + ' → ' + String(c.to_uri || 'unknown'),
      state, cls: state === 'answered' ? 'green' : state === 'ended' ? 'grey'
        : state === 'failed' ? 'red' : state === 'cancelled' ? 'yellow' : 'blue',
      status: isNum(c.status) ? c.status : null,
      when: isNum(c.start_ts) && TNT.util.fmtTime ? TNT.util.fmtTime(c.start_ts) : '',
      duration: isNum(c.duration_s) ? Math.round(c.duration_s) + ' s' : '',
      sides: sides.join(' + '),
      bothSides: sides.length > 1,
      matched: String(c.matched_by || ''),
      worst: worst || null,
      streams: Array.isArray(c.streams) ? c.streams : [],
      ladder: (Array.isArray(c.ladder) ? c.ladder : []).map(ladderView),
      findings: findingViews(c.findings),
      playable: (Array.isArray(c.streams) ? c.streams : []).some((s) => isObj(s) && s.decodable),
    };
  }

  /* ------------------------------------------------------------- the page */
  let root = null;
  let els = {};
  let data = { rating: null, alg: null, stun: null, flow: null, speed: null };
  let running = { alg: false, stun: false, lifetime: false, flow: false };
  let callModal = null, packetModal = null;
  let windowH = '24';

  function refused(err) {
    return !!err && (err.code === 'unavailable' || err.status === 503);
  }

  function fail(what, err) {
    if (!root) return;
    TNT.ui.toast(what + ': ' + ((err && err.message) || 'unknown error'), refused(err) ? 'warn' : 'error');
  }

  /* ---- the qualifier */
  async function loadRating(showBusy) {
    if (!root) return;
    if (showBusy) TNT.ui.busy(els.ratingBtn, true, 'Reading…');
    try {
      const got = await TNT.api.sipQualifier(windowH, (els.host && els.host.value.trim()) || null);
      if (!root) return;
      data.rating = got && got.rating;
      // the last speed test is already in /api/status, which the page has: no second request for it
      const sp = TNT.state.status && TNT.state.status.speed;
      data.speed = sp && sp.last ? sp.last : null;
    } catch (err) {
      fail('Could not read the rating', err);
    } finally {
      TNT.ui.busy(els.ratingBtn, false);
    }
    renderRating();
  }

  function renderRating() {
    const { h } = TNT.util;
    if (!els.ratingBody) return;
    const r = data.rating;
    els.ratingBody.innerHTML = '';
    const add = (el) => els.ratingBody.appendChild(el);
    if (!r) { add(TNT.ui.emptyState('Reading the ping history for this network…')); return; }

    const verdict = String(r.verdict || 'unknown');
    els.ratingChip.className = 'badge lg ' + (GRADE_BADGE[verdict] || 'grey');
    els.ratingChip.textContent = verdict === 'unknown' ? 'not rated' : verdict;

    // the three numbers a call is judged by, first and biggest: everything under them says where they came
    // from and what to do about them
    add(headlineCard(r.headline));

    const legs = (Array.isArray(r.legs) ? r.legs : []).map(legView);
    const table = h('div', { class: 'sip-legs' });
    for (const leg of legs) {
      table.appendChild(h('div', { class: 'sip-leg' },
        h('div', { class: 'sip-leg-head' },
          h('span', { class: 'badge ' + leg.cls }, leg.grade),
          h('span', { class: 'strong' }, leg.title),
          h('span', { class: 'muted small sip-leg-target', title: leg.label }, leg.target || leg.label)),
        h('div', { class: 'sip-leg-numbers' + (leg.numbers ? '' : ' muted small') },
          leg.numbers || leg.reason),
        h('div', { class: 'muted small' },
          [leg.mos, isNum(leg.samples) ? leg.samples + ' pings' : ''].filter(Boolean).join(' · '))));
    }
    if (legs.length) add(table);
    // the cap is stated, never silent: a rating that graded three of a site's twenty targets and said nothing
    // would read as a rating of the site
    if (r.note) add(h('div', { class: 'muted small sip-note' }, TNT.ui.icon('info'), h('span', null, String(r.note))));

    // the call-quality lines that used to sit on the Speed page: they are about calls, so they live here
    const cq = callQualityView(data.speed);
    if (cq.state === 'measured' && (cq.idle || cq.busy || cq.checks.length)) {
      const box = h('div', { class: 'sip-callq' },
        h('div', { class: 'strong small' }, 'From the last speed test'));
      if (cq.idle) box.appendChild(h('div', null, 'Call quality: ' + cq.idle + ' ', h('span', { class: 'muted small' }, 'estimate')));
      if (cq.busy) box.appendChild(h('div', null, 'While the line is busy: ' + cq.busy));
      if (cq.checks.length) {
        box.appendChild(h('div', { class: 'row sip-checks' }, cq.checks.map((c) =>
          h('span', { class: 'badge ' + (c.ok ? 'green' : 'red'), title: c.title || null }, c.label))));
      }
      add(box);
    }

    add(findingList(r.findings));
  }

  /** The headline: MOS, mean round trip and mean jitter, off the leg that limits the call.
   *
   *  Three numbers rather than one verdict because they are what a phone system's support desk asks for, and
   *  the leg they came from is named under them: a MOS with no idea which hop produced it is a number to argue
   *  about rather than act on. Nothing graded shows the reason in their place — a rating with four minutes of
   *  history behind it must not put a confident 4.40 on screen. */
  function headlineCard(head) {
    const { h, fmtMs } = TNT.util;
    const v = isObj(head) ? head : {};
    const cls = GRADE_BADGE[String(v.grade || 'unknown')] || 'grey';
    if (!isNum(v.mos) && !isNum(v.avg_ms)) {
      return h('div', { class: 'sip-headline none' },
        h('div', { class: 'muted' }, String(v.reason || 'Not enough history on this network to rate it yet.')));
    }
    const cell = (value, unit, what, title) => h('div', { class: 'sip-hl', title: title || null },
      h('div', { class: 'sip-hl-value' }, value, unit ? h('span', { class: 'sip-hl-unit' }, unit) : null),
      h('div', { class: 'sip-hl-what' }, what));
    return h('div', { class: 'sip-headline ' + cls },
      h('div', { class: 'sip-hl-row' },
        cell(isNum(v.mos) ? v.mos.toFixed(2) : '—', null, 'MOS',
          v.call_label ? 'Estimated call quality: ' + v.call_label : null),
        cell(isNum(v.avg_ms) ? fmtMs(v.avg_ms) : '—', 'ms', 'Delay', 'Mean round trip over the window'),
        cell(isNum(v.jitter_ms) ? fmtMs(v.jitter_ms) : '—', 'ms', 'Jitter', 'Mean variation between round trips')),
      h('div', { class: 'muted small sip-hl-from' },
        (v.label ? 'From ' + String(v.label).replace(/^The /, 'the ') : 'From the weakest leg')
        + (isNum(v.loss_pct) ? ' · ' + v.loss_pct + ' % loss' : '')
        + (isNum(v.samples) ? ' · ' + v.samples + ' pings' : '')));
  }

  /** The findings list every card on this page shares. */
  function findingList(findings) {
    const { h } = TNT.util;
    const views = findingViews(findings);
    const box = h('div', { class: 'sip-findings' });
    if (!views.length) { box.appendChild(h('div', { class: 'muted small' }, 'Nothing to report.')); return box; }
    for (const f of views) {
      box.appendChild(h('div', { class: 'sip-finding ' + f.level },
        h('div', { class: 'sip-finding-head' },
          h('span', { class: 'badge ' + f.cls, title: f.what }, f.what),
          h('span', { class: 'strong' }, f.title)),
        f.detail ? h('div', { class: 'sip-finding-detail' }, f.detail) : null,
        f.advice ? h('div', { class: 'sip-finding-advice' }, TNT.ui.icon('info'), h('span', null, f.advice)) : null));
    }
    return box;
  }

  /* ---- the ALG check */
  async function loadAlg() {
    try {
      const got = await TNT.api.sipAlg();
      if (!root) return;
      data.alg = got && got.result;
      running.alg = !!(got && got.running);
    } catch (err) {
      if (!refused(err)) console.warn('sip alg', err);
    }
    renderAlg();
  }

  async function runAlg() {
    if (running.alg) return;
    const host = (els.algHost.value || '').trim();
    if (!host) { TNT.ui.toast('Name your PBX, SBC or registrar first', 'warn'); els.algHost.focus(); return; }
    const port = parseInt(els.algPort.value, 10);
    running.alg = true;
    TNT.ui.busy(els.algBtn, true, 'Checking…');
    try {
      const got = await TNT.api.sipAlgRun(host, isFinite(port) ? port : null);
      if (!root) return;
      data.alg = got && got.result;
    } catch (err) {
      fail('The ALG check could not run', err);
    } finally {
      running.alg = false;
      TNT.ui.busy(els.algBtn, false);
    }
    renderAlg();
  }

  function renderAlg() {
    const { h } = TNT.util;
    if (!els.algBody) return;
    const a = data.alg;
    els.algBody.innerHTML = '';
    const add = (el) => els.algBody.appendChild(el);
    if (!a) {
      els.algChip.className = 'badge lg grey';
      els.algChip.textContent = 'not checked';
      add(h('p', { class: 'muted' },
        'Point this at the phone system this site actually registers to. TNT sends it an OPTIONS from port 5060 '
        + 'and again from an ordinary port, and compares what the server echoes back with what went out — a SIP '
        + 'server has to echo Via, Call-ID, CSeq and From exactly as it received them, so any difference was made '
        + 'by something in between.'));
      return;
    }
    const verdict = String(a.verdict || 'inconclusive');
    els.algChip.className = 'badge lg ' + (ALG_BADGE[verdict] || 'grey');
    els.algChip.textContent = verdict;
    add(h('div', { class: 'strong' }, ALG_TEXT[verdict] || ''));
    // when a SIP domain was given, say which server the SRV record sent this to: the answer is that server's
    const srv = isObj(a.via_srv) ? a.via_srv : null;
    add(h('div', { class: 'muted small' },
      (srv ? String(srv.domain) + ' → ' : '')
      + String(a.host || '') + ':' + String(a.port || '') + ' over ' + String(a.transport || 'udp')
      + (a.ts ? ' · ' + TNT.util.relTime(a.ts, TNT.state.now) : '')));

    const probes = Array.isArray(a.probes) ? a.probes : [];
    if (probes.length) {
      const box = h('div', { class: 'sip-probes' });
      for (const p of probes) {
        const wanted = isNum(p.requested_port) && p.requested_port ? 'from port ' + p.requested_port : 'from any port';
        box.appendChild(h('div', { class: 'sip-probe' },
          h('span', { class: 'badge ' + (p.answered ? 'green' : 'grey') }, p.answered ? 'answered' : 'no answer'),
          h('span', null, wanted + (isNum(p.port) && p.port !== p.requested_port ? ' (got ' + p.port + ')' : '')),
          h('span', { class: 'muted small' },
            p.answered ? [isNum(p.status) ? p.status + ' ' + (p.reason || '') : '',
              isNum(p.elapsed_ms) ? p.elapsed_ms + ' ms' : '',
              (Array.isArray(p.changes) ? p.changes.length : 0) + ' header(s) changed'].filter(Boolean).join(' · ')
              : String(p.error || ''))));
      }
      add(box);
    }

    const changes = Array.isArray(a.changes) ? a.changes : [];
    if (changes.length) {
      const box = h('div', { class: 'sip-changes' },
        h('div', { class: 'strong small' }, 'What came back different'));
      for (const c of changes) {
        box.appendChild(h('div', { class: 'sip-change' },
          h('div', { class: 'strong small' }, String(c.header || '')),
          h('div', { class: 'sip-change-line' }, h('span', { class: 'muted small' }, 'sent'),
            h('code', null, String(c.sent == null ? '—' : c.sent))),
          h('div', { class: 'sip-change-line' }, h('span', { class: 'muted small' }, 'seen'),
            h('code', { class: 'bad' }, String(c.seen == null ? '—' : c.seen)))));
      }
      add(box);
    }
    add(findingList(a.findings));
  }

  /* ---- STUN */
  async function loadStun() {
    try {
      const got = await TNT.api.sipStun();
      if (!root) return;
      data.stun = got && got.result;
    } catch (err) {
      if (!refused(err)) console.warn('sip stun', err);
    }
    renderStun();
  }

  async function runStun() {
    if (running.stun) return;
    running.stun = true;
    TNT.ui.busy(els.stunBtn, true, 'Asking…');
    try {
      const got = await TNT.api.sipStunRun(null);
      if (!root) return;
      data.stun = got && got.result;
    } catch (err) {
      fail('The STUN test could not run', err);
    } finally {
      running.stun = false;
      TNT.ui.busy(els.stunBtn, false);
    }
    renderStun();
  }

  async function runLifetime() {
    if (running.lifetime) return;
    const ok = await TNT.ui.confirm({
      title: 'Test how long a NAT mapping lives?',
      message: 'TNT gets a mapping and then goes quiet, asking again after 15, 30, 60, 120 and 240 seconds. It '
        + 'stops at the first idle period the mapping does not survive, so a mean NAT is quick and a generous one '
        + 'takes up to about eight minutes. Nothing else on this page runs while it does.',
      okLabel: 'Run it',
    });
    if (!ok || !root) return;
    running.lifetime = true;
    TNT.ui.busy(els.lifeBtn, true, 'Waiting…');
    try {
      const got = await TNT.api.sipStunLifetime(null);
      if (!root) return;
      renderLifetime(got && got.result);
    } catch (err) {
      fail('The binding lifetime test could not run', err);
    } finally {
      running.lifetime = false;
      TNT.ui.busy(els.lifeBtn, false);
    }
  }

  function renderLifetime(life) {
    const { h } = TNT.util;
    if (!els.lifeBody || !isObj(life)) return;
    els.lifeBody.hidden = false;
    els.lifeBody.innerHTML = '';
    const steps = Array.isArray(life.steps) ? life.steps : [];
    els.lifeBody.appendChild(h('div', { class: 'row sip-life-steps' }, steps.map((s) =>
      h('span', { class: 'badge ' + (s.kept ? 'green' : 'red'), title: s.kept ? 'the mapping was still there'
        : 'the mapping was gone' }, s.idle_s + ' s'))));
    els.lifeBody.appendChild(findingList(life.findings));
  }

  function renderStun() {
    const { h } = TNT.util;
    if (!els.stunBody) return;
    const s = data.stun;
    els.stunBody.innerHTML = '';
    const add = (el) => els.stunBody.appendChild(el);
    if (!s) {
      els.stunChip.className = 'badge lg grey';
      els.stunChip.textContent = 'not tested';
      add(h('p', { class: 'muted' },
        'TNT asks two public STUN servers what address and port they see, from one local socket. If they see two '
        + 'different ports, this NAT gives every destination its own mapping — a phone system told about one of '
        + 'them sends its audio to the other, and that is one-way audio.'));
      return;
    }
    const mapping = String(s.mapping || 'unknown');
    els.stunChip.className = 'badge lg ' + (MAPPING_BADGE[mapping] || 'grey');
    els.stunChip.textContent = mapping;
    add(h('div', { class: 'strong' }, MAPPING_TEXT[mapping] || ''));
    const rows = Array.isArray(s.servers) ? s.servers : [];
    const box = h('div', { class: 'sip-stun-servers' });
    for (const r of rows) {
      box.appendChild(h('div', { class: 'sip-stun-server' },
        h('span', { class: 'badge ' + (r.answered ? 'green' : 'grey') }, r.answered ? 'answered' : 'silent'),
        h('span', { class: 'tile-ellipsis' }, String(r.host || '') + ':' + String(r.port || '')),
        h('code', null, r.answered ? String(r.mapped_ip || '?') + ':' + String(r.mapped_port || '?')
          : String(r.error || 'no answer'))));
    }
    if (rows.length) add(box);
    if (isNum(s.local_port)) {
      add(h('div', { class: 'muted small' },
        'Local port ' + s.local_port + (s.port_preserved ? ' — kept on the way out' : ' — translated on the way out')));
    }
    add(findingList(s.findings));
  }

  /* ---- the call flows */
  async function loadFlow() {
    try {
      const got = await TNT.api.sipFlow();
      if (!root) return;
      data.flow = got && got.flow;
    } catch (err) {
      if (!refused(err)) console.warn('sip flow', err);
    }
    renderFlow();
  }

  /** Is the TNT window's native file picker there? In a plain browser tab it is not, and the path is typed in.
   *  The same bridge method the Packet capture page's Browse… uses: one dialog, one definition. */
  function hasPicker() {
    return !!(window.pywebview && window.pywebview.api && typeof window.pywebview.api.pick_capture_file === 'function');
  }

  /** Pick a capture off this PC and read it into *slot*. Nothing is read in the window: the picker hands back a
   *  path and the service is what opens the file, exactly as the typed path would. */
  async function browseCapture(slot) {
    const button = slot === 'b' ? els.browseB : els.browseA;
    let picked;
    try {
      picked = await window.pywebview.api.pick_capture_file();
    } catch (e) {
      TNT.ui.toast('The file picker could not be opened', 'warn');
      return;
    }
    if (!picked) return;                    // cancelled
    await openCapture(slot, String(picked), button);
  }

  async function openCapture(slot, path, button) {
    const input = slot === 'b' ? els.pathB : els.pathA;
    const btn = button || (slot === 'b' ? els.openB : els.openA);
    const wanted = String(path === undefined || path === null ? (input ? input.value : '') : path).trim();
    if (!wanted) {
      TNT.ui.toast('Give the full path of a capture file', 'warn');
      if (input) input.focus();
      return;
    }
    TNT.ui.busy(btn, true, 'Reading…');
    try {
      const got = await TNT.api.sipFlowOpen(wanted, slot);
      if (!root) return;
      data.flow = got && got.flow;
    } catch (err) {
      fail('That capture could not be read', err);
    } finally {
      TNT.ui.busy(btn, false);
    }
    renderFlow();
  }

  async function closeCapture(slot) {
    try {
      const got = await TNT.api.sipFlowClose(slot);
      if (!root) return;
      data.flow = got && got.flow;
    } catch (err) {
      fail('That capture could not be closed', err);
    }
    renderFlow();
  }

  function renderFlow() {
    const { h } = TNT.util;
    if (!els.flowBody) return;
    const f = data.flow;
    const sources = isObj(f) && Array.isArray(f.sources) ? f.sources : [];
    // the slot inputs show what is loaded there, so a second visit does not look empty
    for (const slot of ['a', 'b']) {
      const up = slot.toUpperCase();
      const src = sources.find((s) => s && s.slot === slot);
      els['loaded' + up].textContent = src ? src.name + ' · ' + TNT.util.fmtBytes(src.size) + ' · '
        + (src.packets || 0) + ' packets · ' + (src.calls || 0) + ' call' + (src.calls === 1 ? '' : 's') : '';
      els['close' + up].hidden = !src;
      // a loaded slot says the button swaps it rather than adding a third capture
      const browse = els['browse' + up];
      if (browse && !browse.hidden) {
        browse.textContent = '';
        browse.appendChild(TNT.ui.icon('search'));
        browse.appendChild(document.createTextNode(src ? 'Replace…' : 'Browse…'));
      }
    }

    els.flowBody.innerHTML = '';
    const add = (el) => els.flowBody.appendChild(el);
    if (!sources.length) {
      add(TNT.ui.emptyState('Load a capture and every SIP call in it is laddered here'));
      return;
    }
    const skew = isObj(f.skew) ? f.skew : {};
    if (sources.length > 1) {
      add(h('div', { class: 'sip-skew' + (skew.confident ? '' : ' muted') },
        TNT.ui.icon('info'),
        h('span', null, isNum(skew.seconds)
          ? 'The two captures\u2019 clocks differ by ' + skew.seconds.toFixed(1) + ' s, measured from '
            + (skew.samples || 0) + ' message(s) seen in both. The ladder is shown on one timeline.'
          : 'No call was seen in both captures yet, so the clocks could not be lined up. Each side is shown on '
            + 'its own clock.')));
    }
    const calls = (Array.isArray(f.calls) ? f.calls : []).map(flowCallView);
    if (!calls.length) { add(TNT.ui.emptyState('No SIP call was found in these captures')); return; }
    const list = h('div', { class: 'sip-calls' });
    for (const c of calls) {
      list.appendChild(h('button', { class: 'sip-call', type: 'button', on: { click: () => showCall(c) } },
        h('div', { class: 'sip-call-head' },
          h('span', { class: 'badge ' + c.cls }, c.state || 'unknown'),
          h('span', { class: 'strong sip-call-title', title: c.title }, c.title),
          c.bothSides ? h('span', { class: 'badge blue', title: 'seen from both captures, matched on '
            + c.matched }, 'both sides') : null),
        h('div', { class: 'sip-call-meta muted small' },
          [c.when ? 'Started ' + c.when : '', c.duration, c.ladder.length + ' messages',
            c.playable ? 'audio' : ''].filter(Boolean).join(' · ')),
        c.worst ? h('div', { class: 'sip-call-worst' },
          h('span', { class: 'badge ' + c.worst.cls }, c.worst.what),
          h('span', null, c.worst.title)) : null));
    }
    add(list);
    add(findingList(f.findings));
  }

  /** The call-flow popup: the ladder, the streams, and a player per side. Any row opens that packet's headers. */
  function showCall(c) {
    const { h } = TNT.util;
    const body = h('div', { class: 'sip-flow-modal' });

    if (c.findings.length) body.appendChild(findingList(c.findings));

    const ladder = h('div', { class: 'sip-ladder' });
    for (const row of c.ladder) {
      const side = h('span', { class: 'sip-ladder-side' }, row.side.toUpperCase());
      ladder.appendChild(h('button', {
        class: 'sip-ladder-row ' + row.cls, type: 'button',
        title: row.where ? 'Packet ' + row.where + ' in capture ' + row.side.toUpperCase() + ' — click for its headers'
          : 'No packet behind this row',
        disabled: !row.where,
        on: { click: () => showPacket(row) },
      },
        h('span', { class: 'sip-ladder-time muted small' }, row.rel),
        c.bothSides ? side : null,
        h('span', { class: 'sip-ladder-from' }, row.src),
        h('span', { class: 'sip-ladder-arrow' }, '→'),
        h('span', { class: 'sip-ladder-to' }, row.dst),
        h('span', { class: 'sip-ladder-label strong' }, row.label),
        row.sdp ? h('span', { class: 'badge teal', title: 'carries an SDP body: this is where the audio '
          + 'addresses and codecs are agreed' }, 'SDP') : null,
        row.note ? h('span', { class: 'muted small' }, row.note) : null));
    }
    body.appendChild(ladder);

    if (c.streams.length) {
      const box = h('div', { class: 'sip-streams' }, h('div', { class: 'strong small' }, 'Audio'));
      // the whole call first, the way the Packet capture page offers it, then each direction on its own: a
      // one-way-audio call sounds fine mixed and obviously wrong once the silent direction is played alone
      const callHolder = h('div', { class: 'sip-stream-player' });
      const callPlay = h('button', { class: 'btn btn-sm btn-primary', type: 'button', disabled: !c.playable,
        title: c.playable ? 'Rebuild this call and play it' : 'There is nothing in this call TNT can decode',
        on: { click: () => loadAudio(c.id, null, callPlay, callHolder) } }, TNT.ui.icon('play'), 'Listen to the call');
      box.appendChild(h('div', { class: 'sip-stream' },
        h('div', { class: 'sip-stream-head' }, h('span', { class: 'strong' }, 'The whole call')),
        h('div', { class: 'sip-stream-actions' }, callPlay, callHolder)));
      for (const s of c.streams) {
        const holder = h('div', { class: 'sip-stream-player' });
        const play = h('button', { class: 'btn btn-sm', type: 'button', disabled: !s.decodable,
          title: s.decodable ? 'Rebuild this direction and play it'
            : 'TNT cannot decode ' + (s.codec || 'this codec'),
          on: { click: () => loadAudio(c.id, s, play, holder) } }, TNT.ui.icon('play'), 'Listen');
        box.appendChild(h('div', { class: 'sip-stream' },
          h('div', { class: 'sip-stream-head' },
            h('code', null, String(s.src || '') + ':' + String(s.sport || '') + ' → '
              + String(s.dst || '') + ':' + String(s.dport || '')),
            s.side ? h('span', { class: 'badge grey' }, String(s.side).toUpperCase()) : null),
          h('div', { class: 'muted small' },
            [String(s.codec || ''), isNum(s.packets) ? s.packets + ' packets' : '',
              isNum(s.lost) && s.lost ? s.lost + ' lost' : '',
              isNum(s.jitter_ms) ? s.jitter_ms + ' ms jitter' : ''].filter(Boolean).join(' · ')),
          h('div', { class: 'sip-stream-actions' }, play, holder)));
      }
      body.appendChild(box);
    }

    callModal = TNT.ui.modal({
      title: c.title, body, wide: true, onClose: () => { callModal = null; },
    });
  }

  /** One packet's headers, read back out of the file now rather than kept in memory since it was loaded. */
  async function showPacket(row) {
    const { h } = TNT.util;
    let packet;
    try {
      const got = await TNT.api.sipFlowPacket(row.side, row.where);
      packet = got && got.packet;
    } catch (err) {
      fail('Could not read that packet', err);
      return;
    }
    if (!packet || !root) return;
    const headers = Array.isArray(packet.headers) ? packet.headers : [];
    const body = h('div', { class: 'sip-packet' },
      h('code', { class: 'sip-packet-start' }, String(packet.start || '')),
      h('div', { class: 'sip-headers' }, headers.map((hh) => h('div', { class: 'sip-header' },
        h('span', { class: 'sip-header-name' }, String(hh.name || '')),
        h('code', { class: 'sip-header-value' }, String(hh.value == null ? '' : hh.value))))));
    if (packet.body) {
      body.appendChild(h('div', { class: 'sip-packet-body' },
        h('div', { class: 'strong small' }, packet.is_sdp ? 'SDP body — the addresses and codecs offered' : 'Body'),
        h('pre', null, String(packet.body))));
    }
    if (packet.length_ok === false) {
      body.appendChild(h('div', { class: 'sip-finding bad' },
        h('div', { class: 'sip-finding-head' }, h('span', { class: 'badge red' }, 'Problem'),
          h('span', { class: 'strong' }, 'The Content-Length does not match the body')),
        h('div', { class: 'sip-finding-detail' },
          'Something rewrote the body without fixing the length, which is what a SIP ALG does when it edits SDP. '
          + 'Many stacks drop a message like this outright.')));
    }
    packetModal = TNT.ui.modal({
      title: 'Packet ' + row.where + ' — capture ' + row.side.toUpperCase(),
      body, wide: true, onClose: () => { packetModal = null; },
    });
  }

  /** The audio, fetched as a blob so a 404 never navigates the page. `stream` null is the whole call. */
  async function loadAudio(callId, stream, button, holder) {
    const { h } = TNT.util;
    const what = stream ? 'this direction' : 'this call';
    TNT.ui.busy(button, true, 'Rebuilding…');
    try {
      const res = await fetch(TNT.api.sipFlowAudioUrl(callId, stream ? { stream: stream.id } : {}),
        { credentials: 'same-origin' });
      if (!res.ok) throw new Error(res.status === 404 ? 'TNT could not rebuild ' + what : 'HTTP ' + res.status);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      holder.innerHTML = '';
      holder.appendChild(h('audio', { controls: 'controls', src: url, preload: 'metadata' }));
      holder.appendChild(h('a', { class: 'btn btn-sm',
        href: url, download: 'TNT-' + String(stream ? stream.id : callId).replace(/[^\w.-]+/g, '-') + '.wav' },
        TNT.ui.icon('download'), 'Save WAV'));
      button.hidden = true;
    } catch (err) {
      TNT.ui.toast('Could not play ' + what + ': ' + ((err && err.message) || 'unknown error'), 'warn');
    } finally {
      TNT.ui.busy(button, false);
    }
  }

  /* ------------------------------------------------------------- mount */
  /** One capture slot. In the TNT window that is a Browse… button and nothing to type; in a plain browser tab,
   *  where there is no native picker, it falls back to the path field the service has always taken. */
  function captureSlot(slot, label, picker) {
    const { h } = TNT.util;
    const up = slot.toUpperCase();
    const loaded = h('div', { class: 'muted small sip-loaded' });
    const close = h('button', { class: 'btn btn-sm', type: 'button', hidden: true, title: 'Close this capture',
      'aria-label': 'Close capture ' + up, on: { click: () => closeCapture(slot) } }, TNT.ui.icon('close'));
    const browse = h('button', { class: 'btn btn-sm', type: 'button', hidden: !picker,
      title: 'Pick a capture file from this PC', on: { click: () => browseCapture(slot) } },
      TNT.ui.icon('search'), 'Browse…');
    const path = picker ? null : h('input', { class: 'input mono', type: 'text', spellcheck: 'false',
      autocomplete: 'off', 'aria-label': 'Full path of capture ' + up,
      placeholder: 'C:\\Users\\…\\' + (slot === 'b' ? 'server-side' : 'client-side') + '.pcapng' });
    const open = picker ? null : h('button', { class: 'btn btn-sm', type: 'button',
      on: { click: () => openCapture(slot) } }, 'Load');
    if (path) path.addEventListener('keydown', (e) => { if (e.key === 'Enter') open.click(); });

    els['path' + up] = path;
    els['open' + up] = open;
    els['browse' + up] = browse;
    els['close' + up] = close;
    els['loaded' + up] = loaded;
    return h('div', { class: 'sip-slot' },
      h('div', { class: 'sip-slot-label' }, label),
      h('div', { class: 'sip-slot-row' }, path, open, browse, close),
      loaded);
  }

  function card(title, chip, bodyEl, actions) {
    const { h } = TNT.util;
    return h('section', { class: 'card sip-card' },
      h('div', { class: 'section-head' },
        h('h2', null, h('span', { class: 'section-accent', style: { '--accent': 'var(--sand)' } }), title, chip),
        actions ? h('div', { class: 'actions' }, actions) : null),
      bodyEl);
  }

  TNT.views.sip = {
    mount(el) {
      const { h } = TNT.util;
      root = el;
      els = {};
      data = { rating: null, alg: null, stun: null, flow: null, speed: null };
      running = { alg: false, stun: false, lifetime: false, flow: false };

      const settings = (TNT.state.settings && TNT.state.settings.sip) || {};
      windowH = String(settings.window_h || 24);

      /* the qualifier */
      els.host = h('input', { class: 'input', type: 'text', placeholder: 'pbx.example.net',
        value: String(settings.host || ''),
        title: 'The PBX, SBC or registrar this site registers to. Named, it is graded as its own leg — the path '
          + 'the calls actually take, which is not the path to a general internet host.' });
      els.host.addEventListener('change', () => { saveHost(); loadRating(true); });
      els.windowSel = TNT.ui.segmented(WINDOWS, windowH, (v) => { windowH = v; loadRating(true); });
      els.ratingBtn = h('button', { class: 'btn btn-sm', type: 'button', on: { click: () => loadRating(true) } },
        TNT.ui.icon('refresh'), 'Re-read');
      els.ratingChip = h('span', { class: 'badge lg grey' }, 'reading…');
      els.ratingBody = h('div', { class: 'sip-body' });
      const qualifier = card('SIP qualifier', els.ratingChip, h('div', null,
        h('div', { class: 'form-row' },
          h('div', { class: 'field', style: { flex: '2 1 240px' } },
            h('label', null, 'Your SIP host (optional)'), els.host),
          h('div', { class: 'field', style: { flex: '0 0 auto' } },
            h('label', null, 'History'), els.windowSel)),
        els.ratingBody), els.ratingBtn);

      /* the ALG check */
      els.algHost = h('input', { class: 'input', type: 'text', placeholder: 'pbx.example.net',
        value: String(settings.host || '') });
      els.algPort = h('input', { class: 'input', type: 'number', min: '1', max: '65535',
        value: String(settings.port || 5060), style: { width: '110px' } });
      els.algBtn = h('button', { class: 'btn btn-primary btn-sm', type: 'button', on: { click: runAlg } },
        TNT.ui.icon('search'), 'Check');
      els.algChip = h('span', { class: 'badge lg grey' }, 'not checked');
      els.algBody = h('div', { class: 'sip-body' });
      const alg = card('SIP ALG check', els.algChip, h('div', null,
        h('div', { class: 'form-row' },
          h('div', { class: 'field', style: { flex: '2 1 240px' } }, h('label', null, 'SIP server'), els.algHost),
          h('div', { class: 'field', style: { flex: '0 0 auto' } }, h('label', null, 'Port'), els.algPort)),
        els.algBody), els.algBtn);

      /* STUN */
      els.stunBtn = h('button', { class: 'btn btn-primary btn-sm', type: 'button', on: { click: runStun } },
        TNT.ui.icon('search'), 'Test');
      els.lifeBtn = h('button', { class: 'btn btn-sm', type: 'button', on: { click: runLifetime },
        title: 'Slow: it sits idle for up to about eight minutes' }, 'Binding lifetime');
      els.stunChip = h('span', { class: 'badge lg grey' }, 'not tested');
      els.stunBody = h('div', { class: 'sip-body' });
      els.lifeBody = h('div', { class: 'sip-body', hidden: true });
      const stun = card('NAT and audio (STUN)', els.stunChip,
        h('div', null, els.stunBody, els.lifeBody), [els.stunBtn, els.lifeBtn]);

      /* the call flows: one slot each, picked off disk rather than typed */
      els.flowBody = h('div', { class: 'sip-body' });
      const picker = hasPicker();
      const flow = card('Call flows', null, h('div', null,
        h('p', { class: 'muted small' },
          'One capture is the ordinary case. Two — one from the client side and one from the server side — are '
          + 'merged on Call-ID, and the difference between them is the only conclusive proof that something in '
          + 'the middle rewrote the SIP.'),
        captureSlot('a', 'Capture A (client side)', picker),
        captureSlot('b', 'Capture B (server side, optional)', picker),
        picker ? null : h('p', { class: 'muted small sip-slot-hint' },
          'A browser tab cannot open this PC\'s file picker, so the path is typed here. The TNT window has a '
          + 'Browse button instead.'),
        els.flowBody), null);

      root.appendChild(h('div', { class: 'sip-page' }, qualifier, alg, stun, flow));

      loadRating(false);
      loadAlg();
      loadStun();
      loadFlow();
    },

    /** /api/status arrived. The rating is its own request, but the call-quality lines come out of the last
     *  speed test the status carries, so they follow a test finishing without one. */
    update(st) {
      if (!root) return;
      const last = st && st.status && st.status.speed ? st.status.speed.last : null;
      if (last === data.speed) return;
      data.speed = last;
      renderRating();
    },

    unmount() {
      if (callModal) { try { callModal.close(); } catch (e) { /* ignore */ } callModal = null; }
      if (packetModal) { try { packetModal.close(); } catch (e) { /* ignore */ } packetModal = null; }
      root = null;
      els = {};
      data = { rating: null, alg: null, stun: null, flow: null, speed: null };
    },

    /** This PC moved to another network: the rating described the old one, and so did both checks. */
    netChanged() {
      if (!root) return;
      data.alg = null;
      data.stun = null;
      renderAlg();
      renderStun();
      loadRating(false);
    },

    onEvent(name) {
      if (!root) return;
      if (name === 'hello') { loadRating(false); loadAlg(); loadStun(); loadFlow(); return; }
      if (name === 'speedtest.done') loadRating(false);
    },

    // exposed for tests
    findingViews, legView, callQualityView, ladderView, flowCallView,
  };

  /** The named SIP host is a setting, so the tile and the next visit agree with what was typed here. */
  function saveHost() {
    const host = (els.host.value || '').trim();
    els.algHost.value = host;
    TNT.api.updateSettings({ sip: { host } }).catch((err) => console.warn('sip host save failed', err));
  }
})();
