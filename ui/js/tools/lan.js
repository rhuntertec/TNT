/* TNT — tools/lan.js
   The "LAN throughput" card of the Tools view: other PCs running TNT on the same LAN announce
   themselves and are listed as sticker peers (hostname, ip, version, "seen 3 s ago", a Test
   button); a test shows a live fuse per phase (connect / upload / download) from the
   lan.throughput.progress events and then two big Mbps numbers. The peer list refreshes on
   mount, every 10 s and on lan.peers events; the last result is restored from /last.
   Loaded before app.js: TNT.util / TNT.ui are only touched inside functions. */
(function () {
  'use strict';
  window.TNT = window.TNT || {};
  const TNT = window.TNT;
  TNT.tools = TNT.tools || {};

  const PHASES = ['connect', 'upload', 'download'];
  const PHASE_LABEL = { connect: 'Connect', upload: 'Upload', download: 'Download' };
  const SECONDS = [3, 5, 10];
  const DEFAULT_SECONDS = 5;
  const PEER_REFRESH_MS = 10000;
  const EMPTY_TEXT = 'No other TNT machines seen yet — they appear within ~10 s of starting TNT on the same LAN';

  /* ------------------------------------------------ pure helpers (tests) */
  /** "just now" / "12 s ago" / relTime for older sightings. */
  function seenText(lastSeenTs, now, ageS) {
    let age = ageS;
    if (lastSeenTs != null && now != null) age = Math.max(0, now - lastSeenTs);
    if (age == null || !isFinite(age)) return 'seen —';
    if (age < 1.5) return 'seen just now';
    if (age < 60) return 'seen ' + Math.round(age) + ' s ago';
    if (age < 3600) return 'seen ' + Math.round(age / 60) + ' min ago';
    return 'seen ' + Math.floor(age / 3600) + ' h ago';
  }
  /** Fuse states for the three phases given the current progress event. */
  /* Pure: how much data a test of `seconds` moves in each direction. The test streams at
     line speed for the whole time, so the volume is the link rate x the seconds -- worth
     saying out loud before someone runs a 10 s test over a metered or radio link. */
  function volumeText(seconds) {
    const mb = (mbps) => {
      const bytes = mbps * 1e6 / 8 * seconds;
      return bytes >= 1e9 ? (bytes / 1e9).toFixed(bytes >= 1e10 ? 0 : 1) + ' GB' : Math.round(bytes / 1e6) + ' MB';
    };
    return 'A ' + seconds + ' s test streams at line speed: about ' + mb(1000) + ' each way on gigabit, '
      + mb(100) + ' on 100 Mbit. It is generated in memory and never written to disk.';
  }

  /* Pure: "moved 610 MB up · 595 MB down" for a finished result, or '' when it cannot be known. */
  function movedText(result) {
    if (!result || result.error || !result.seconds) return '';
    const fmt = (mbps) => {
      if (mbps == null || !isFinite(mbps)) return null;
      const bytes = mbps * 1e6 / 8 * result.seconds;
      return bytes >= 1e9 ? (bytes / 1e9).toFixed(1) + ' GB' : Math.round(bytes / 1e6) + ' MB';
    };
    const up = fmt(result.upload_mbps), down = fmt(result.download_mbps);
    if (!up && !down) return '';
    return 'moved ' + [up ? up + ' up' : null, down ? down + ' down' : null].filter(Boolean).join(' · ');
  }

  function phaseStates(progress) {
    const cur = progress ? PHASES.indexOf(progress.phase) : -1;
    return PHASES.map((p, i) => {
      if (!progress) return { phase: p, pct: 0, state: 'idle' };
      if (i < cur) return { phase: p, pct: 100, state: 'done' };
      if (i === cur) return { phase: p, pct: Math.max(0, Math.min(100, Number(progress.pct) || 0)), state: 'running', mbps: progress.mbps };
      return { phase: p, pct: 0, state: 'idle' };
    });
  }

  /* ------------------------------------------------------------- card */
  function create() {
    const { h } = TNT.util;
    let peersData = null;      // GET /api/tools/lan/peers
    let running = false;       // a test runs (ours or another window's)
    let busyPeer = null;       // ip of the peer we are testing
    let progress = null;
    let result = null;         // RESULT DICT
    let seconds = DEFAULT_SECONDS;
    let mounted = false;
    let switching = false;     // a PUT /tools/lan/settings is in flight
    let unsubs = [];
    let refreshTimer = null, tickTimer = null;
    let loading = false;
    const els = {};

    // ---- header row
    els.self = h('div', { class: 'lan-self' }, h('span', { class: 'muted' }, 'This PC:'), h('span', { class: 'muted' }, 'loading…'));
    els.seg = TNT.ui.segmented(SECONDS.map((s) => ({ value: s, label: s + ' s' })), DEFAULT_SECONDS,
      (v) => { seconds = v; els.volume.textContent = volumeText(seconds); renderList(); });
    els.seg.setAttribute('aria-label', 'Seconds per direction');
    els.refreshBtn = h('button', { class: 'btn btn-sm', type: 'button', title: 'Look for TNT peers again', on: { click: () => loadPeers() } }, TNT.ui.icon('refresh'), 'Refresh');
    const intro = h('div', { class: 'tool-intro' }, 'Other PCs running TNT on this LAN find each other automatically. Pick one and run a test: this PC uploads to it, then downloads from it, for the chosen number of seconds each way.');
    els.volume = h('div', { class: 'tool-note' }, volumeText(DEFAULT_SECONDS));
    const controls = h('div', { class: 'row lan-controls' }, h('span', { class: 'label' }, 'Test length'), els.seg, h('span', { class: 'spacer' }), els.refreshBtn);
    // the switch lives in the card title; off stops announcing, listening and answering tests
    els.switch = TNT.ui.toggle({ checked: true, on: 'On', off: 'Off', accent: 'var(--green)',
      onChange: (v) => setEnabled(v) });
    els.head = h('div', { class: 'tool-head-right' },
      h('span', { class: 'muted small', title: 'Announce this PC to other TNT machines and answer their throughput tests' }, 'Discovery'), els.switch);
    els.off = h('div', { class: 'dhcp-info', hidden: true });

    // ---- peers
    els.list = h('ul', { class: 'peer-list', hidden: true });
    els.empty = h('div', { class: 'peer-empty' }, TNT.ui.emptyState(EMPTY_TEXT));
    els.error = h('div', { class: 'dhcp-info warn', hidden: true });

    // ---- progress
    els.fuses = {};
    const rows = PHASES.map((p) => {
      const f = TNT.ui.fuse();
      f.set(0, 'idle', '', '');
      els.fuses[p] = f;
      return h('div', { class: 'lan-phase' }, h('span', { class: 'lan-phase-name' }, PHASE_LABEL[p]), f);
    });
    els.progressTitle = h('div', { class: 'lan-progress-title' });
    els.progress = h('div', { class: 'lan-progress', hidden: true, role: 'status', 'aria-live': 'polite' }, els.progressTitle, rows);

    // ---- result
    els.result = h('div', { class: 'lan-result', hidden: true });

    const body = h('div', { class: 'tool-body' }, intro, els.self, controls, els.volume, els.off, els.error,
      els.list, els.empty, els.progress, els.result);

    // ---- rendering
    function peerName(p) { return p ? (p.hostname || p.ip || '?') : '?'; }
    /* The service's persisted switch. Optimistic (true) until the first peers call answers, so
       the toggle does not flash off on mount. */
    function isEnabled() { return !peersData || peersData.enabled !== false; }
    function renderSelf() {
      const { copyCode } = TNT.util;
      els.self.innerHTML = '';
      els.self.appendChild(h('span', { class: 'muted' }, 'This PC:'));
      if (!peersData) { els.self.appendChild(h('span', { class: 'muted' }, 'loading…')); return; }
      const me = peersData.self || {};
      els.self.appendChild(h('span', { class: 'strong', style: { color: 'var(--ink)' } }, me.hostname || '?'));
      if (me.ip) els.self.appendChild(copyCode(me.ip));
      if (me.version) els.self.appendChild(h('span', { class: 'muted small' }, 'v' + me.version));
      if (me.port) els.self.appendChild(h('span', { class: 'muted small' }, 'port ' + me.port));
      els.self.appendChild(!isEnabled()
        ? h('span', { class: 'badge grey', title: 'Turn the switch on to announce this PC again' }, 'discovery off')
        : peersData.listening === false
          ? h('span', { class: 'badge red', title: peersData.error || 'The service is not listening for peers' }, 'not listening')
          : h('span', { class: 'badge green' }, 'listening'));
    }
    function renderSwitch() {
      const on = isEnabled();
      if (els.switch.input.checked !== on) els.switch.setChecked(on);
      // switching off mid-test would cut the transfer: leave it locked until the test ends
      els.switch.input.disabled = running || switching;
      els.volume.hidden = !on;
      if (on) { els.off.hidden = true; return; }
      els.off.innerHTML = '';
      els.off.className = 'dhcp-info';
      els.off.appendChild(TNT.ui.icon('info'));
      els.off.appendChild(h('span', null, 'Discovery is off: this PC is not announcing itself, does not list other TNT machines and will not answer their throughput tests. Nothing else on the Tools page is affected.'));
      els.off.hidden = false;
    }
    function renderError() {
      const err = peersData && peersData.error;
      // "disabled" is what the switch already says; do not repeat it in a warning box
      if (!err || !isEnabled()) { els.error.hidden = true; return; }
      els.error.innerHTML = '';
      els.error.appendChild(TNT.ui.icon('warning'));
      els.error.appendChild(h('span', null, String(err)));
      els.error.hidden = false;
    }
    let listKey = null;
    function renderList() {
      const { copyCode } = TNT.util;
      const now = TNT.util.nowS();
      const peers = (peersData && Array.isArray(peersData.peers)) ? peersData.peers.slice() : [];
      peers.sort((a, b) => String(a.hostname || a.ip).localeCompare(String(b.hostname || b.ip)));
      // the list is rebuilt only when a peer comes or goes (or a test starts / ends): the 10 s
      // refresh must not yank a hovered Test button or the focus away; only the "seen" texts move
      const key = peers.map((p) => [p.id, p.ip, p.hostname, p.version, p.adapter].join('|')).join(';')
        + '#' + running + '#' + busyPeer + '#' + seconds + '#' + isEnabled();
      if (key === listKey) {
        const seenEls = els.list.querySelectorAll('.peer-seen');
        peers.forEach((p, i) => { if (seenEls[i]) seenEls[i].dataset.ts = p.last_seen_ts != null ? String(p.last_seen_ts) : ''; });
        refreshSeen();
        return;
      }
      listKey = key;
      els.list.innerHTML = '';
      els.list.hidden = !peers.length;
      els.empty.hidden = !!peers.length || !isEnabled();      // the "off" note replaces the empty state
      for (const p of peers) {
        const testing = running && busyPeer === p.ip;
        const btn = h('button', { class: 'btn btn-sm' + (testing ? ' btn-primary' : ''), type: 'button', disabled: running,
          title: 'Run a ' + seconds + ' s upload and download test with ' + peerName(p), on: { click: () => test(p) } },
          TNT.ui.icon(testing ? 'spark' : 'speed'), testing ? 'Testing…' : 'Test');
        const seen = h('span', { class: 'peer-seen', data: { ts: p.last_seen_ts != null ? String(p.last_seen_ts) : '' } }, seenText(p.last_seen_ts, now, p.age_s));
        const meta = h('div', { class: 'peer-meta' }, p.ip ? copyCode(p.ip) : null,
          p.version ? h('span', { class: 'badge grey' }, 'v' + p.version) : null,
          p.adapter ? h('span', null, 'via ' + p.adapter) : null, seen);
        els.list.appendChild(h('li', { class: 'peer-item' + (testing ? ' testing' : '') },
          h('span', { class: 'peer-icon' }, TNT.ui.icon('computer')),
          h('div', { class: 'peer-text' }, h('div', { class: 'peer-name', title: peerName(p) }, peerName(p)), meta),
          btn));
      }
    }
    function refreshSeen() {
      const now = TNT.util.nowS();
      for (const el of els.list.querySelectorAll('.peer-seen[data-ts]')) {
        const ts = parseFloat(el.dataset.ts);
        if (!isFinite(ts)) continue;
        const t = seenText(ts, now);
        if (el.textContent !== t) el.textContent = t;
      }
    }
    function renderProgress() {
      const { fmtMbps } = TNT.util;
      els.progress.hidden = !running;
      if (!running) return;
      const who = busyPeer ? (peerByIp(busyPeer) ? peerName(peerByIp(busyPeer)) : busyPeer) : 'a peer';
      els.progressTitle.innerHTML = '';
      els.progressTitle.appendChild(h('span', { class: 'spark-icon' }, TNT.ui.icon('spark')));
      els.progressTitle.appendChild(h('span', null, 'Testing with ' + who + '…'));
      for (const ps of phaseStates(progress)) {
        const f = els.fuses[ps.phase];
        const right = ps.state === 'running' && ps.phase !== 'connect' && ps.mbps != null ? fmtMbps(ps.mbps) + ' Mbps' : ps.state === 'done' ? 'done' : '';
        f.set(ps.pct / 100, ps.state === 'idle' ? 'idle' : ps.state === 'done' ? 'done' : 'running', ps.state === 'running' ? Math.round(ps.pct) + '%' : '', right);
      }
    }
    function peerByIp(ip) { return ((peersData && peersData.peers) || []).find((p) => p.ip === ip) || null; }
    function renderResult() {
      const { fmtMbps, fmtMs, relTime, copyCode } = TNT.util;
      els.result.innerHTML = '';
      if (!result) { els.result.hidden = true; return; }
      els.result.hidden = false;
      const peer = result.peer || {};
      const who = peer.hostname || peer.ip || '?';
      if (result.error) {
        els.result.className = 'lan-result bad';
        els.result.appendChild(TNT.ui.icon('warning'));
        els.result.appendChild(h('span', null, 'Test with ' + who + ' failed: ' + result.error));
        return;
      }
      els.result.className = 'lan-result';
      const kpi = (arrow, cls, v, label) => h('div', { class: 'kpi' },
        h('span', { class: 'value' }, h('span', { class: 'arrow ' + cls }, arrow), fmtMbps(v), h('span', { class: 'unit' }, 'Mbps')),
        h('span', { class: 'label' }, label));
      els.result.appendChild(kpi('↑', 'up', result.upload_mbps, 'upload'));
      els.result.appendChild(kpi('↓', 'down', result.download_mbps, 'download'));
      els.result.appendChild(h('div', { class: 'kpi' }, h('span', { class: 'value sm' }, fmtMs(result.latency_ms), h('span', { class: 'unit' }, 'ms')), h('span', { class: 'label' }, 'latency')));
      const sub = h('div', { class: 'lan-result-sub' }, h('span', { class: 'muted' }, 'last test with'), h('span', { class: 'strong' }, who));
      if (peer.ip && peer.ip !== who) sub.appendChild(copyCode(peer.ip));
      sub.appendChild(h('span', { class: 'muted' }, '· ' + (result.seconds || '?') + ' s each way · ' + relTime(result.ts, TNT.util.nowS())));
      const moved = movedText(result);
      if (moved) sub.appendChild(h('span', { class: 'muted' }, '· ' + moved));
      els.result.appendChild(sub);
    }
    function render() {
      if (!mounted) return;
      renderSwitch(); renderSelf(); renderError(); renderList(); renderProgress(); renderResult();
    }

    // ---- actions
    async function loadPeers() {
      if (loading || !mounted) return;
      loading = true;
      TNT.ui.busy(els.refreshBtn, true);
      try {
        const r = await TNT.api.lanPeers();
        if (!mounted) return;
        peersData = r || { self: {}, peers: [], listening: false, error: null };
        render();
      } catch (err) {
        if (!mounted) return;
        if (err.status === 404 || err.status === 503) peersData = { self: {}, peers: [], listening: false, error: 'LAN peer discovery is not available on this service' };
        else peersData = Object.assign({}, peersData || { self: {}, peers: [] }, { error: 'Could not list peers: ' + err.message });
        render();
      } finally { loading = false; if (mounted) TNT.ui.busy(els.refreshBtn, false); }
    }
    async function setEnabled(on) {
      if (!mounted || switching) return;
      switching = true;
      renderSwitch();
      try {
        const view = await TNT.api.lanSettings({ enabled: !!on });
        if (!mounted) return;
        peersData = view || peersData;
        TNT.ui.toast(on ? 'LAN discovery is on' : 'LAN discovery is off — this PC is no longer announcing itself', on ? 'ok' : 'info');
        if (on) loadPeers();
      } catch (err) {
        if (!mounted) return;
        TNT.ui.toast('Could not change the setting: ' + err.message, 'error');
      } finally {
        switching = false;
        if (mounted) render();      // also snaps the switch back when the call failed
      }
    }
    async function loadLast() {
      try {
        const r = await TNT.api.lanThroughputLast();
        if (!mounted || !r) return;
        if (r.result) result = r.result;
        if (r.running && !running) { running = true; busyPeer = null; progress = progress || { phase: 'connect', pct: 0, mbps: 0 }; }
        render();
      } catch (err) { /* the peers call reports availability */ }
    }
    async function test(p) {
      if (!mounted || !p || !p.ip) return;
      if (running) { TNT.ui.toast('A throughput test is already running', 'warn'); return; }
      running = true; busyPeer = p.ip; progress = { phase: 'connect', pct: 0, mbps: 0 };
      render();
      try {
        const r = await TNT.api.lanThroughput({ peer: p.ip, seconds });
        if (!mounted) return;
        result = r || result;
        if (r && !r.error) TNT.ui.toast('↑ ' + TNT.util.fmtMbps(r.upload_mbps) + ' ↓ ' + TNT.util.fmtMbps(r.download_mbps) + ' Mbps with ' + peerName(p), 'ok');
        else if (r) TNT.ui.toast('Throughput test failed: ' + r.error, 'error');
      } catch (err) {
        if (!mounted) return;
        if (err.status === 409) TNT.ui.toast('A throughput test is already running on the service — wait for it to finish', 'warn');
        else {
          result = { ts: TNT.util.nowS(), peer: { ip: p.ip, hostname: p.hostname || null }, seconds, upload_mbps: null, download_mbps: null, latency_ms: null, duration_s: null, error: err.message || 'test failed' };
          TNT.ui.toast('Throughput test failed: ' + err.message, 'error');
        }
      } finally {
        if (mounted) { running = false; busyPeer = null; progress = null; render(); }
      }
    }

    // ---- events
    function onPeers(d) {
      if (!mounted || !d || !Array.isArray(d.peers)) return;
      peersData = Object.assign({}, peersData || { self: {}, listening: true, error: null }, { peers: d.peers });
      if (d.self) peersData.self = d.self;
      renderSelf(); renderList();
    }
    /* Another window (or the service) changed the switch: `lan.state` carries the whole view. */
    function onState(d) {
      if (!mounted || !d || typeof d !== 'object' || !('enabled' in d)) return;
      peersData = d;
      render();
    }
    function onProgress(d) {
      if (!mounted || !d) return;
      if (!running) { running = true; busyPeer = busyPeer || (d.peer && d.peer.ip) || null; renderList(); }
      progress = d;
      renderProgress();
    }
    function onDone(d) {
      if (!mounted) return;
      if (d && d.result) result = d.result;
      running = false; busyPeer = null; progress = null;
      render();
    }

    return {
      body,
      head: els.head,
      mount() {
        mounted = true;
        render();
        loadPeers();
        loadLast();
        unsubs.push(TNT.api.events.on('lan.peers', onPeers));
        unsubs.push(TNT.api.events.on('lan.state', onState));
        unsubs.push(TNT.api.events.on('lan.throughput.progress', onProgress));
        unsubs.push(TNT.api.events.on('lan.throughput.done', onDone));
        unsubs.push(TNT.api.events.on('hello', () => { if (mounted) { loadPeers(); loadLast(); } }));
        refreshTimer = setInterval(() => { if (mounted) loadPeers(); }, PEER_REFRESH_MS);
        tickTimer = setInterval(() => { if (mounted) refreshSeen(); }, 1000);
      },
      update() { /* nothing follows the status snapshot */ },
      unmount() {
        mounted = false;
        for (const u of unsubs) { try { u(); } catch (e) { /* ignore */ } }
        unsubs = [];
        if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
        if (tickTimer) { clearInterval(tickTimer); tickTimer = null; }
        peersData = null; running = false; busyPeer = null; progress = null; result = null; listKey = null; switching = false;
      },
    };
  }

  TNT.tools.lan = { create, seenText, phaseStates, volumeText, movedText, PHASES, SECONDS, DEFAULT_SECONDS, EMPTY_TEXT };
})();
