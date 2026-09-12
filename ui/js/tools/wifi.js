/* TNT — tools/wifi.js
   The "Saved Wi-Fi networks" card of the Tools view: every WLAN profile this PC has joined,
   with the key Windows stored for it (GET /api/tools/wifi/profiles). The keys are masked
   until the tech clicks "Show keys" — the first load asks for ?reveal=0, so a key is not even
   sent over the loopback API until it is wanted. Revealing keys needs a Windows administrator
   account (the service checks the calling process's token); a standard user gets a 403 and the
   card stays masked with a note. "Export CSV" only ever writes keys that were actually revealed
   — on a non-admin machine the file has an empty key column. No polling: Refresh only.
   Loaded before app.js: TNT.util / TNT.ui are only touched inside functions. */
(function () {
  'use strict';
  window.TNT = window.TNT || {};
  const TNT = window.TNT;
  TNT.tools = TNT.tools || {};

  const MASK = '••••••••';
  const CSV_COLUMNS = ['ssid', 'authentication', 'encryption', 'key', 'connection_mode'];
  const INTRO = 'Every Wi-Fi network this PC has joined, with the key Windows stored for it.';
  const EMPTY_TEXT = 'No saved Wi-Fi networks — this PC has never joined one, or the profiles were removed';
  const UNAVAILABLE_TEXT = 'No wireless adapter on this PC, so there are no saved Wi-Fi networks.';
  const ADMIN_TEXT = 'Showing saved Wi-Fi passwords needs a Windows administrator account.';
  const HELLO_QUIET_S = 5;      // a 'hello' this soon after a load is the stream connecting, not a restart

  /* ------------------------------------------------ pure helpers (tests) */
  /** What the Key cell shows: the key, the mask, or an em dash when there is none. */
  function maskKey(key, present, shown) {
    if (!present && !key) return '—';
    if (!shown) return MASK;
    return key ? String(key) : '—';
  }

  /** Badge class for an authentication value ("WPA2PSK", "WPA3-Personal", "open", …). */
  function securityClass(auth) {
    const a = String(auth == null ? '' : auth).toLowerCase();
    if (!a) return 'grey';
    if (a.includes('wpa3')) return 'green';
    if (a.includes('wpa2')) return 'green';
    if (a.includes('wpa')) return 'yellow';
    if (a.includes('wep')) return 'red';
    if (a.includes('open') || a === 'none') return 'red';
    return 'grey';
  }

  /** "WPA2PSK · AES", or "open" — the security column as one readable string. */
  function securityText(p) {
    p = p || {};
    const parts = [p.authentication, p.encryption].filter((v) => v != null && String(v).trim() !== '');
    return parts.length ? parts.join(' · ') : 'unknown';
  }

  /** The export: ssid,authentication,encryption,key,connection_mode (real keys, CRLF rows). */
  function rowsToCsv(profiles) {
    const cell = TNT.hosttable.csvCell;      // one CSV quoting implementation for the whole UI
    const rows = [CSV_COLUMNS.slice()];
    for (const p of profiles || []) {
      rows.push([p.ssid || p.name || '', p.authentication || '', p.encryption || '', p.key || '', p.connection_mode || '']);
    }
    return rows.map((r) => r.map(cell).join(',')).join('\r\n') + '\r\n';
  }

  /** "TNT-wifi-TEC-DESKTOP.csv", or "TNT-wifi-20260910.csv" when the hostname is unknown. */
  function csvName(hostname, nowS) {
    const clean = String(hostname == null ? '' : hostname).trim().replace(/[^0-9A-Za-z._-]+/g, '-').replace(/^-+|-+$/g, '');
    if (clean) return 'TNT-wifi-' + clean + '.csv';
    const d = new Date((nowS || 0) * 1000);
    const p2 = (n) => (n < 10 ? '0' : '') + n;
    return 'TNT-wifi-' + d.getFullYear() + p2(d.getMonth() + 1) + p2(d.getDate()) + '.csv';
  }

  /* ------------------------------------------------------------- card */
  function create() {
    const { h } = TNT.util;
    let data = null;           // GET /api/tools/wifi/profiles
    let shown = false;         // "Show keys" was clicked (keys are masked by default)
    let hasKeys = false;       // the loaded snapshot was fetched with reveal=1
    let keyNote = '';          // set when a reveal was refused (not an administrator): shown, stays masked
    let mounted = false;
    let loading = false;
    let lastLoadTs = 0;        // a 'hello' right after mounting would just repeat the first load
    let unsubs = [];
    const els = {};

    els.refreshBtn = h('button', { class: 'btn btn-sm', type: 'button', title: 'Read the saved Wi-Fi profiles again', on: { click: () => load(shown) } },
      TNT.ui.icon('refresh'), 'Refresh');
    els.keysBtn = h('button', { class: 'btn btn-sm', type: 'button', on: { click: () => toggleKeys() } }, TNT.ui.icon('search'), 'Show keys');
    els.count = h('span', { class: 'muted small' });
    els.exportBtn = h('button', { class: 'btn btn-sm', type: 'button', title: 'Save every network and its key as a CSV file', on: { click: () => exportCsv() } },
      TNT.ui.icon('download'), 'Export CSV');
    els.head = h('div', { class: 'tool-head-right' }, els.exportBtn);

    const intro = h('div', { class: 'tool-intro' }, INTRO);
    const controls = h('div', { class: 'row wifi-controls' }, els.keysBtn, els.count, h('span', { class: 'spacer' }), els.refreshBtn);
    els.note = h('div', { class: 'dhcp-info', hidden: true });
    els.tbody = h('tbody');
    const tableWrap = h('div', { class: 'table-wrap' },
      h('table', { class: 'table wifi-table' },
        h('thead', null, h('tr', null,
          h('th', null, 'Network'), h('th', null, 'Security'), h('th', null, 'Key'), h('th', null, 'Mode'))),
        els.tbody));
    const body = h('div', { class: 'tool-body' }, intro, controls, els.note, tableWrap);

    /* ---------------------------------------------------------- render */
    function profiles() { return (data && Array.isArray(data.profiles)) ? data.profiles : []; }

    function renderNote() {
      // a refused reveal (not an administrator) takes priority: the list is still shown, masked
      if (keyNote) {
        els.note.className = 'dhcp-info warn';
        els.note.innerHTML = '';
        els.note.appendChild(TNT.ui.icon('warning'));
        els.note.appendChild(h('span', null, keyNote));
        els.note.hidden = false;
        return;
      }
      const err = data && data.error ? String(data.error) : '';
      if (!data || (!err && data.available !== false)) { els.note.hidden = true; return; }
      // "this PC has no wireless adapter" is a fact, not a failure: a plain note, not a warning
      const info = data.available === false;
      els.note.className = 'dhcp-info' + (info ? '' : ' warn');
      els.note.innerHTML = '';
      els.note.appendChild(TNT.ui.icon(info ? 'info' : 'warning'));
      els.note.appendChild(h('span', null, err || UNAVAILABLE_TEXT));
      els.note.hidden = false;
    }

    function renderControls() {
      els.keysBtn.disabled = !profiles().length;
      els.exportBtn.disabled = !profiles().length;
      const label = shown ? 'Hide keys' : 'Show keys';
      if (els.keysBtn.lastChild && els.keysBtn.lastChild.nodeType === 3) els.keysBtn.lastChild.textContent = label;
      els.keysBtn.title = shown ? 'Mask the keys again' : 'Show the keys Windows saved (they stay on this PC)';
      const n = profiles().length;
      els.count.textContent = n ? n + (n === 1 ? ' network' : ' networks') : '';
    }

    function keyCell(p) {
      const { copyCode } = TNT.util;
      const text = maskKey(p.key, p.key_present, shown);
      if (text === '—') return h('td', null, h('span', { class: 'muted' }, '—'));
      // the chip copies the real key even while it is masked (data-copy drives the shared
      // click-to-copy handler): masking is against shoulder surfing, not against the tech
      const chip = copyCode(text, 'wifi-key');
      if (p.key) chip.dataset.copy = String(p.key);
      chip.title = shown ? 'Click to copy' : 'Hidden — click to copy anyway, or use "Show keys"';
      return h('td', null, chip);
    }

    function row(p) {
      const { copyCode } = TNT.util;
      const name = p.ssid || p.name || '—';
      const first = h('td', { class: 'wifi-name' }, copyCode(name),
        p.non_broadcast ? h('span', { class: 'badge grey', title: 'This network does not broadcast its name' }, 'hidden') : null,
        (p.name && p.ssid && p.name !== p.ssid) ? h('div', { class: 'muted small' }, 'profile: ' + p.name) : null,
        p.error ? h('div', { class: 'wifi-err small' }, String(p.error)) : null);
      const sec = h('td', { title: securityText(p) },
        h('span', { class: 'badge ' + securityClass(p.authentication) }, p.authentication || 'unknown'),
        p.encryption ? h('span', { class: 'badge grey' }, p.encryption) : null);
      const mode = h('td', null, p.connection_mode
        ? h('span', { class: 'badge grey', title: p.connection_mode === 'auto' ? 'Windows joins this network automatically' : 'Only joined when someone picks it' }, p.connection_mode)
        : h('span', { class: 'muted' }, '—'));
      return h('tr', null, first, sec, keyCell(p), mode);
    }

    function renderTable() {
      const list = profiles();
      els.tbody.innerHTML = '';
      if (!list.length) {
        els.tbody.appendChild(h('tr', { class: 'empty-row' }, h('td', { colspan: '4' },
          TNT.ui.emptyState(data && data.available === false ? UNAVAILABLE_TEXT : EMPTY_TEXT))));
        return;
      }
      for (const p of list) els.tbody.appendChild(row(p));
    }

    function render() {
      if (!mounted) return;
      renderNote();
      renderControls();
      renderTable();
    }

    /* --------------------------------------------------------- actions */
    async function load(reveal) {
      if (loading || !mounted) return;
      loading = true;
      TNT.ui.busy(els.refreshBtn, true);
      try {
        const r = await TNT.api.wifiProfiles(!!reveal);
        if (!mounted) return;
        data = r || { available: false, interfaces: [], profiles: [], error: null, source: null };
        hasKeys = !!reveal;
        keyNote = '';
        render();
      } catch (err) {
        if (!mounted) return;
        // a refused reveal (not an administrator) must not wipe the masked list we already
        // have: keep it, drop back to masked and explain why the keys stay hidden
        if (reveal && err.status === 403 && err.code === 'admin_required') {
          hasKeys = false;
          keyNote = err.message || ADMIN_TEXT;
          TNT.ui.toast(keyNote, 'warn');
          render();
          return;
        }
        const text = (err.status === 404 || err.status === 503)
          ? 'Saved Wi-Fi networks are not available on this service'
          : 'Could not read the saved Wi-Fi networks: ' + err.message;
        data = { available: false, interfaces: [], profiles: [], error: text, source: null };
        hasKeys = false;
        keyNote = '';
        render();
      } finally {
        loading = false;
        lastLoadTs = TNT.util.nowS();
        if (mounted) TNT.ui.busy(els.refreshBtn, false);
      }
    }

    async function toggleKeys() {
      if (!mounted) return;
      if (shown) { shown = false; keyNote = ''; render(); return; }
      if (!hasKeys) {
        await load(true);
        if (!mounted || !hasKeys) return;      // the reveal call failed or was refused: stay masked
      }
      shown = true;
      render();
    }

    function hostname() {
      const st = TNT.state && TNT.state.status;
      return (st && st.map && st.map.pc && st.map.pc.hostname) || '';
    }

    async function exportCsv() {
      if (!mounted) return;
      if (!profiles().length) { TNT.ui.toast('Nothing to export yet', 'warn'); return; }
      TNT.ui.busy(els.exportBtn, true, 'Exporting…');
      try {
        // try to include the keys, but only what the service actually reveals: a non-admin
        // caller gets a 403 here (handled in load, list stays masked) and the CSV then carries
        // an empty key column rather than the masks. Never write anything but real keys.
        if (!hasKeys) {
          await load(true);
          if (!mounted) return;
        }
        if (!hasKeys) TNT.ui.toast('Saved without keys — showing keys needs a Windows administrator account', 'warn');
        const name = csvName(hostname(), TNT.util.nowS());
        await TNT.app.saveBlob(new Blob([rowsToCsv(profiles())], { type: 'text/csv;charset=utf-8' }), name);
      } catch (err) {
        if (mounted) TNT.ui.toast('Export failed: ' + err.message, 'error');
      } finally {
        if (mounted) TNT.ui.busy(els.exportBtn, false);
      }
    }

    return {
      body,
      head: els.head,
      mount() {
        mounted = true;
        shown = false;
        hasKeys = false;
        keyNote = '';
        render();
        load(false);
        // a service restart means the list is worth re-reading; the 'hello' that arrives right
        // after the stream connects on page load would only repeat the load above
        unsubs.push(TNT.api.events.on('hello', () => {
          if (mounted && TNT.util.nowS() - lastLoadTs > HELLO_QUIET_S) load(shown);
        }));
      },
      update() { /* nothing here follows the status snapshot */ },
      /* Joining a Wi-Fi network makes Windows save a profile for it: re-read the list when a Wi-Fi
         adapter took part in the change. Masked only, and never while keys are shown (that list stays
         as the user asked for it until Refresh). */
      netChanged(info) {
        if (!mounted || shown || loading || !wifiInChange(info)) return;
        if (TNT.util.nowS() - lastLoadTs < HELLO_QUIET_S) return;
        load(false);
      },
      unmount() {
        mounted = false;
        for (const u of unsubs) { try { u(); } catch (e) { /* ignore */ } }
        unsubs = [];
        data = null; shown = false; hasKeys = false; keyNote = ''; loading = false;
      },
    };
  }

  /** Pure: whether a net.changed payload involves a Wi-Fi adapter (the adapter names in `changes`). */
  function wifiInChange(info) {
    const changes = info && Array.isArray(info.changes) ? info.changes : [];
    return changes.some((c) => !!c && /wi-?fi|wlan|wireless/i.test(String(c.adapter || '')));
  }

  TNT.tools.wifi = { create, maskKey, securityClass, securityText, rowsToCsv, csvName, wifiInChange, MASK, CSV_COLUMNS, EMPTY_TEXT, INTRO, ADMIN_TEXT };
})();
