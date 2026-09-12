/* TNT — hosttable.js
   Shared machinery for host-list tables (Discovery results, DHCP clients): column-driven
   sorting with a persisted sort per table, sortable <th> buttons, the "add as ping target"
   button on IP cells (one singleton mirrors the ping list into every mounted table), open-port
   pills that open in the browser / launch ssh, the Device Type badge, CSV export and the
   default cell renderers. The WiFi page's radio table uses only the sorting and headers, with
   custom columns and cells for access points.
   Loaded before the views; only touches TNT.util / TNT.ui / TNT.api inside functions because
   app.js (which defines them) loads last. */
(function () {
  'use strict';
  const TNT = window.TNT;

  // Chunky sticker-style triangle (ink outline, accent fill when active); rotated for descending.
  const ARROW_SVG = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 3 13.8 11.6H2.2z"/></svg>';
  const EXT_SVG = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M7 3.5H3.5v9h9V9"/><path d="M9.5 3h3.5v3.5M13 3 7.6 8.4"/></svg>';

  const ipKey = (ip) => TNT.util.ipKey(ip);
  const cmpNum = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  const cmpText = (a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }) || cmpNum(a, b);
  const dash = () => TNT.util.h('span', { class: 'muted' }, '—');

  /* --------------------------------------------------------- device type */
  /* The service classifies every host (tnt/discovery.py classify_device) and ships the answer
     as hst.device_type, so this file only has to render it. classifyDevice() below is a
     fallback for rows that predate the field (a cached run from an older service): same rules,
     same priority. Nothing else may duplicate the rule set. */
  const DEVICE_TYPES = ['Router', 'DW Server', 'Camera', 'Phone', 'Ubiquiti'];
  const DEVICE_TYPE_CLASS = { router: 'blue', 'dw server': 'purple', camera: 'orange', phone: 'green', ubiquiti: 'yellow' };
  /** Device types earlier versions stored (a cached run, a saved report) and what they are called now. */
  const LEGACY_DEVICE_TYPES = new Map([['Wifi', 'Ubiquiti']]);
  const DW_SERVER_PORT = 7001, CAMERA_PORT = 554, PHONE_PORT = 5060, UBIQUITI_PORT = 22;

  /** The current name of a device type (an older name is renamed; anything else is returned trimmed). */
  const currentType = (type) => { const t = String(type == null ? '' : type).trim(); return LEGACY_DEVICE_TYPES.get(t) || t; };

  /** Badge colour for a device type ('grey' for anything unknown). */
  const deviceTypeClass = (type) => DEVICE_TYPE_CLASS[currentType(type).toLowerCase()] || 'grey';

  /** Pure mirror of tnt/discovery.py classify_device: gateway → 7001 → 554 → 5060 → 22+Ubiquiti.
   *  `gateway` is one address or a list of them. Returns null when nothing matches. */
  function classifyDevice(hst, gateway) {
    if (!hst) return null;
    const ip = String(hst.ip == null ? '' : hst.ip).trim();
    const gws = Array.isArray(gateway) ? gateway : (gateway == null ? [] : [gateway]);
    if (ip && gws.some((g) => String(g == null ? '' : g).trim() === ip)) return 'Router';
    const ports = (Array.isArray(hst.open_ports) ? hst.open_ports : []).map(Number);
    if (ports.includes(DW_SERVER_PORT)) return 'DW Server';
    if (ports.includes(CAMERA_PORT)) return 'Camera';
    if (ports.includes(PHONE_PORT)) return 'Phone';
    if (ports.includes(UBIQUITI_PORT) && /ubiquiti/i.test(String(hst.vendor || ''))) return 'Ubiquiti';
    return null;
  }

  /** This PC's default gateway from the last /status snapshot (null when unknown). */
  function stateGateway() {
    try {
      const nic = window.TNT.state && window.TNT.state.status && window.TNT.state.status.netinfo
        && window.TNT.state.status.netinfo.internet_nic;
      return (nic && nic.gateway) || null;
    } catch (e) { return null; }
  }

  /** What to show for a host: the service's answer, or the fallback when the row has no field. */
  function deviceType(hst) {
    if (!hst) return null;
    if (hst.device_type != null && hst.device_type !== '') return currentType(hst.device_type);
    if ('device_type' in hst) return null;      // the service looked and found nothing
    return classifyDevice(hst, stateGateway());
  }

  /* ------------------------------------------------------------- columns */
  /* A column: { key, label, cls?, kind: 'ip'|'num'|'text'|'ports'|'custom', sortable?: false,
     sortValue?(hst) -> [empty, primary, secondary], numeric?: bool (custom: compare with <, not
     localeCompare), cell?(hst) -> Node, csv?: [{ header, value(hst) }] } */
  const BASE_COLUMNS = [
    { key: 'ip', label: 'IP', kind: 'ip', csv: [{ header: 'ip', value: (hst) => hst.ip }] },
    { key: 'hostname', label: 'Hostname', kind: 'text', csv: [{ header: 'hostname', value: (hst) => hst.hostname || '' }] },
    { key: 'mac', label: 'MAC', kind: 'text', csv: [{ header: 'mac', value: (hst) => hst.mac || '' }] },
    { key: 'device_type', label: 'Device Type', cls: 'device-type', kind: 'text',
      sortValue: (hst) => { const t = String(deviceType(hst) || '').toLowerCase(); return t ? [false, t, ''] : [true, '', '']; },
      csv: [{ header: 'device_type', value: (hst) => deviceType(hst) || '' }] },
    { key: 'vendor', label: 'Vendor', kind: 'text', csv: [{ header: 'vendor', value: (hst) => hst.vendor || '' }] },
    { key: 'rtt', label: 'Ping', cls: 'num', kind: 'num',
      csv: [{ header: 'ping_reply', value: (hst) => (hst.ping_ok ? 'yes' : 'no') },
        { header: 'rtt_ms', value: (hst) => (hst.ping_ok && hst.rtt_ms != null ? hst.rtt_ms : '') }] },
    { key: 'ports', label: 'Open ports', kind: 'ports', csv: [{ header: 'open_ports', value: (hst) => (hst.open_ports || []).join(' ') }] },
  ];
  const baseColumn = (key) => BASE_COLUMNS.find((c) => c.key === key) || null;

  /** Normalise a column list: strings and partial objects pick up the base definition. */
  function normalizeColumns(columns) {
    return (columns || BASE_COLUMNS).map((c) => {
      const spec = typeof c === 'string' ? { key: c } : c;
      const base = baseColumn(spec.key);
      const out = Object.assign({}, base || {}, spec);
      if (!out.kind) out.kind = base ? base.kind : (out.sortValue ? 'custom' : 'text');
      if (!out.label && out.label !== '') out.label = out.key;
      return out;
    });
  }

  /* ------------------------------------------------------------- sorting */
  /** [empty, primary, secondary] for one host and column. Empty cells ("—", "no reply", no
   *  open ports) always sink to the bottom whichever direction is active. */
  function sortValue(hst, col) {
    if (col.sortValue) return col.sortValue(hst);
    switch (col.kind) {
      case 'ip': return [false, ipKey(hst.ip), 0];
      case 'num': {
        const v = col.key === 'rtt' ? (hst.ping_ok && hst.rtt_ms != null ? Number(hst.rtt_ms) : NaN) : Number(hst[col.key]);
        return isFinite(v) ? [false, v, 0] : [true, 0, 0];
      }
      case 'ports': {
        const ports = (Array.isArray(hst.open_ports) ? hst.open_ports : []).map(Number).filter((p) => isFinite(p));
        return ports.length ? [false, ports.length, Math.min.apply(null, ports)] : [true, 0, 0];
      }
      default: {
        const s = String(hst[col.key] == null ? '' : hst[col.key]).trim().toLowerCase();
        return s ? [false, s, ''] : [true, '', ''];
      }
    }
  }
  const isNumeric = (col) => col.numeric === true || ['ip', 'num', 'ports'].includes(col.kind);

  /** Pure: returns a new array (the input is never reordered in place); ties broken by IP,
   *  then original position. `columns` defaults to the Discovery set; an unknown key sorts
   *  as text on hst[key]. */
  function sortHosts(hosts, key, dir, columns) {
    const cols = normalizeColumns(columns);
    const col = cols.find((c) => c.key === key) || { key, kind: 'text' };
    const sign = dir === 'desc' ? -1 : 1;
    const numeric = isNumeric(col);
    return (hosts || []).map((hst, i) => ({ hst, i, v: sortValue(hst, col) }))
      .sort((x, y) => {
        if (x.v[0] !== y.v[0]) return x.v[0] ? 1 : -1;
        const c = numeric ? (cmpNum(x.v[1], y.v[1]) || cmpNum(x.v[2], y.v[2])) : cmpText(String(x.v[1]), String(y.v[1]));
        return (sign * c) || cmpNum(ipKey(x.hst.ip), ipKey(y.hst.ip)) || (x.i - y.i);
      })
      .map((x) => x.hst);
  }

  function loadSort(storeKey, columns, fallback) {
    const cols = normalizeColumns(columns);
    const def = fallback || { key: 'ip', dir: 'asc' };
    try {
      const s = JSON.parse(localStorage.getItem(storeKey) || 'null');
      if (s && cols.some((c) => c.key === s.key && c.sortable !== false) && (s.dir === 'asc' || s.dir === 'desc')) return { key: s.key, dir: s.dir };
    } catch (e) { /* no storage: defaults */ }
    return { key: def.key, dir: def.dir };
  }
  function saveSort(storeKey, sort) { try { localStorage.setItem(storeKey, JSON.stringify(sort)); } catch (e) { /* ignore */ } }

  /* ------------------------------------------------------ ping targets */
  // One singleton for every table: both lists mirror the same ping targets.
  let targetKeys = new Set();       // lower-cased ip + host of every ping target (drives the check state)
  let targetsSig = '';
  const localAdded = new Set();     // ips added from a table; kept until the service lists them
  const tbodies = new Set();        // every mounted table body (add-target buttons are re-synced in all)

  function targetKeysFrom(targets) {
    const s = new Set();
    for (const t of targets || []) {
      if (t && t.ip) s.add(String(t.ip).toLowerCase());
      if (t && t.host) s.add(String(t.host).toLowerCase());
    }
    // An ip added from a table stays checked until the service lists it (a status snapshot
    // taken before the POST landed must not flip it back). Once listed, the service is the only
    // source of truth again, so removing the target in the Ping view clears the check here too.
    for (const ip of Array.from(localAdded)) { if (s.has(ip)) localAdded.delete(ip); else s.add(ip); }
    return s;
  }
  const isTarget = (ip) => targetKeys.has(String(ip || '').toLowerCase());
  const noteLocalAdd = (ip) => localAdded.add(String(ip).toLowerCase());

  function refreshButtons(tbody) {
    for (const btn of tbody.querySelectorAll('.add-target')) setAddState(btn, btn.dataset.ip, isTarget(btn.dataset.ip));
  }

  function syncTargets(targets, force) {
    if (!Array.isArray(targets)) return;
    const keys = targetKeysFrom(targets);
    const sig = Array.from(keys).sort().join(',');
    if (sig === targetsSig && !force) return;
    targetsSig = sig;
    targetKeys = keys;
    for (const tb of tbodies) refreshButtons(tb);
  }

  async function loadTargets() {
    try {
      const t = await TNT.api.targets();
      syncTargets(t);
    } catch (err) { /* TNT.state.targets (from /status) is the fallback */ }
  }

  function setAddState(btn, ip, added) {
    if ((btn.dataset.added === '1') === added && btn.firstChild) return;
    btn.dataset.added = added ? '1' : '0';
    btn.classList.toggle('is-target', added);
    btn.innerHTML = '';
    btn.appendChild(TNT.ui.icon(added ? 'check' : 'plus'));
    btn.title = added ? ip + ' is already a ping target' : 'Add ' + ip + ' as a ping target';
    btn.setAttribute('aria-label', btn.title);
    if (added) btn.setAttribute('aria-disabled', 'true'); else btn.removeAttribute('aria-disabled');
  }

  function addTargetButton(ip) {
    const { h } = TNT.util;
    const btn = h('button', { class: 'add-target', type: 'button', data: { ip } });
    setAddState(btn, ip, isTarget(ip));
    // A separate control: never let the click reach the copy-on-click cell underneath.
    btn.addEventListener('click', (e) => { e.stopPropagation(); e.preventDefault(); addAsTarget(btn, ip); });
    return btn;
  }

  async function addAsTarget(btn, ip) {
    if (btn.classList.contains('is-target')) { TNT.ui.toast(ip + ' is already a ping target', 'info', 1600); return; }
    if (btn.dataset.busy === '1') return;
    btn.dataset.busy = '1';
    btn.classList.add('busy');
    try {
      const t = await TNT.api.addTarget(ip);
      localAdded.add(ip.toLowerCase());
      targetKeys.add(ip.toLowerCase());
      if (t && t.ip) targetKeys.add(String(t.ip).toLowerCase());
      if (t && t.host) targetKeys.add(String(t.host).toLowerCase());
      // the same ip may sit in another mounted table too
      for (const tb of tbodies) refreshButtons(tb);
      setAddState(btn, ip, true);
      TNT.ui.toast('Added ' + ip + ' to Ping', 'ok');
      if (TNT.app && TNT.app.refreshStatus) TNT.app.refreshStatus();
    } catch (err) {
      TNT.ui.toast(err && err.message ? err.message : 'Could not add ' + ip, 'error');
    } finally {
      delete btn.dataset.busy;
      btn.classList.remove('busy');
    }
  }

  /* --------------------------------------------------------- port links */
  function portUrl(ip, port) {
    const host = String(ip).includes(':') ? '[' + ip + ']' : String(ip);
    return Number(port) === 80 ? 'http://' + host + '/' : 'https://' + host + ':' + port + '/';
  }

  // Which ports get an action when clicked: web ports open a browser tab (80 -> http, the
  // rest -> https), 22 opens a PowerShell ssh session through the TNT client, everything
  // else (554/RTSP, custom ports) is plain text.
  const WEB_PORTS = new Set([80, 443, 7001, 8000, 8080, 8443]);
  const SSH_PORT = 22;
  function portAction(port) {
    const p = Number(port);
    if (WEB_PORTS.has(p)) return 'web';
    if (p === SSH_PORT) return 'ssh';
    return 'none';
  }

  function sshBridge() {
    return window.pywebview && window.pywebview.api && typeof window.pywebview.api.open_ssh === 'function'
      ? window.pywebview.api.open_ssh : null;
  }

  function portLink(ip, port) {
    const { h } = TNT.util;
    const action = portAction(port);
    if (action === 'web') {
      const url = portUrl(ip, port);
      const a = h('a', { class: 'pill port-link', href: url, target: '_blank', rel: 'noopener', title: 'Open ' + url },
        String(port), h('span', { class: 'ext', html: EXT_SVG }));
      a.addEventListener('click', (e) => {
        if (e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;   // modified clicks keep their browser meaning
        // Inside the TNT client the bridge opens the default browser (and the default is prevented);
        // in a plain browser the anchor's own target=_blank navigation does the job.
        TNT.openExternal(url, e);
      });
      return a;
    }
    if (action === 'ssh') {
      const bridge = sshBridge();
      if (!bridge) return h('span', { class: 'pill', title: 'SSH - open the TNT app to launch a PowerShell ssh session' }, String(port));
      const b = h('button', { class: 'pill port-link', type: 'button', title: 'Open a PowerShell ssh session to ' + ip },
        String(port), h('span', { class: 'ext', html: EXT_SVG }));
      b.addEventListener('click', async (e) => {
        e.stopPropagation();
        try {
          const ok = await bridge(ip);
          TNT.ui.toast(ok ? 'Opening ssh ' + ip + ' in PowerShell' : 'Could not start ssh', ok ? 'ok' : 'error');
        } catch (err) { TNT.ui.toast('Could not start ssh: ' + err.message, 'error'); }
      });
      return b;
    }
    return h('span', { class: 'pill' }, String(port));
  }

  /* --------------------------------------------------------------- cells */
  function defaultCell(col, hst) {
    const { h, copyCode, fmtMs } = TNT.util;
    switch (col.key) {
      case 'ip': return h('td', { class: 'copy ip-cell' }, copyCode(hst.ip), addTargetButton(hst.ip));
      case 'hostname': return h('td', { class: 'copy' }, hst.hostname || dash());
      case 'mac': return h('td', { class: 'copy' }, hst.mac ? copyCode(hst.mac) : dash());
      case 'device_type': {
        const type = deviceType(hst);
        return h('td', { class: 'device-type' }, type ? h('span', { class: 'badge ' + deviceTypeClass(type) }, type) : dash());
      }
      case 'vendor': return h('td', { class: 'copy wrap' }, hst.vendor || dash());
      case 'rtt': return h('td', { class: 'copy num' }, hst.ping_ok ? fmtMs(hst.rtt_ms) + ' ms' : h('span', { class: 'muted' }, 'no reply'));
      case 'ports': {
        const td = h('td', { class: 'ports' });
        if (hst.open_ports && hst.open_ports.length) for (const p of hst.open_ports) td.appendChild(portLink(hst.ip, p));
        else td.appendChild(dash());
        return td;
      }
      default: {
        const v = hst[col.key];
        return h('td', { class: 'copy' + (col.cls ? ' ' + col.cls : '') }, v == null || v === '' ? dash() : String(v));
      }
    }
  }

  /* ----------------------------------------------------------------- CSV */
  function csvCell(v) {
    const s = v == null ? '' : String(v);
    return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }

  function toCsv(hosts, columns, sort) {
    const cols = normalizeColumns(columns);
    const fields = [];
    for (const c of cols) for (const f of (c.csv || [])) fields.push(f);
    const rows = [fields.map((f) => f.header)];
    const s = sort || { key: 'ip', dir: 'asc' };
    for (const hst of sortHosts(hosts || [], s.key, s.dir, cols)) rows.push(fields.map((f) => f.value(hst)));
    return rows.map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n';
  }

  /* -------------------------------------------------------------- factory */
  /** create({ columns, storeKey, onSort(sort), defaultSort }) -> instance
   *  { columns, sort, thead, tbody, setSort(key), updateHeaders(), sorted(hosts),
   *    render(hosts, emptyText) -> sorted hosts, toCsv(hosts), destroy() }.
   *  The sort is remembered in localStorage under storeKey so it survives re-renders, leaving
   *  the view and reloads. Row cells come from column.cell(hst) or the Discovery defaults. */
  function create(opts) {
    opts = opts || {};
    const { h } = TNT.util;
    const columns = normalizeColumns(opts.columns);
    const storeKey = opts.storeKey || 'tnt.hosttable.sort';
    const inst = { columns, sort: loadSort(storeKey, columns, opts.defaultSort), thead: null, tbody: h('tbody'), ths: {} };
    const tr = h('tr');
    for (const c of columns) {
      if (c.sortable === false) {
        tr.appendChild(h('th', { class: c.cls || null, scope: 'col' }, c.label ? h('span', { class: 'th-label' }, c.label) : h('span', { class: 'sr-only' }, c.srLabel || c.key)));
        continue;
      }
      const btn = h('button', { class: 'th-sort', type: 'button', data: { key: c.key }, title: 'Sort by ' + String(c.label).toLowerCase() },
        h('span', { class: 'th-label' }, c.label), h('span', { class: 'sort-arrow', html: ARROW_SVG }));
      btn.addEventListener('click', () => inst.setSort(c.key));
      const th = h('th', { class: 'sortable' + (c.cls ? ' ' + c.cls : ''), scope: 'col', 'aria-sort': 'none' }, btn);
      inst.ths[c.key] = th;
      tr.appendChild(th);
    }
    inst.thead = h('thead', null, tr);

    inst.updateHeaders = () => {
      for (const c of columns) {
        const th = inst.ths[c.key];
        if (!th) continue;
        const on = inst.sort.key === c.key;
        th.setAttribute('aria-sort', on ? (inst.sort.dir === 'asc' ? 'ascending' : 'descending') : 'none');
        th.classList.toggle('sorted', on);
        const btn = th.firstElementChild;
        if (on) btn.dataset.dir = inst.sort.dir; else delete btn.dataset.dir;
        btn.title = 'Sort by ' + String(c.label).toLowerCase() + (on ? (inst.sort.dir === 'asc' ? ' (ascending — click for descending)' : ' (descending — click for ascending)') : '');
      }
    };
    inst.setSort = (key) => {
      inst.sort = { key, dir: inst.sort.key === key && inst.sort.dir === 'asc' ? 'desc' : 'asc' };
      saveSort(storeKey, inst.sort);
      inst.updateHeaders();
      if (opts.onSort) { try { opts.onSort(inst.sort); } catch (e) { console.error(e); } }
    };
    inst.sorted = (hosts) => sortHosts(hosts || [], inst.sort.key, inst.sort.dir, columns);
    inst.render = (hosts, emptyText) => {
      const sorted = inst.sorted(hosts);
      inst.tbody.innerHTML = '';
      if (!sorted.length) {
        if (emptyText) inst.tbody.appendChild(h('tr', { class: 'empty-row' }, h('td', { colspan: String(columns.length) }, emptyText)));
        return sorted;
      }
      for (const hst of sorted) {
        const tr2 = h('tr', { data: { ip: hst.ip || '' } });
        for (const c of columns) tr2.appendChild(c.cell ? c.cell(hst) : defaultCell(c, hst));
        inst.tbody.appendChild(tr2);
      }
      return sorted;
    };
    inst.toCsv = (hosts) => toCsv(hosts, columns, inst.sort);
    inst.destroy = () => { tbodies.delete(inst.tbody); };
    inst.updateHeaders();
    tbodies.add(inst.tbody);
    targetsSig = '';   // a fresh table: the next syncTargets must not be skipped as "unchanged"
    return inst;
  }

  TNT.hosttable = {
    create, BASE_COLUMNS, normalizeColumns, sortHosts, sortValue, loadSort, saveSort,
    DEVICE_TYPES, deviceType, deviceTypeClass, classifyDevice,
    portUrl, portAction, portLink, targetKeysFrom, noteLocalAdd, isTarget, syncTargets, loadTargets,
    addTargetButton, defaultCell, csvCell, toCsv,
  };
})();
