/* TNT — reportsui.js
   The shared pieces of Reports (the Full Scan and the site reports it saves), loaded before the views and app.js:
   * pure helpers the node tests drive: site names and the ranking of suggestions, compact numbers with units, a
     report's sections, window (the site's network and its visits, or the time rule), network identity and key numbers,
     how a comparison row reads, the report pickers' options, the job's phases, its site (named, or suggested by an
     earlier report of the same network) and the Wi-Fi snapshot a full scan hands the service;
   * createFullScan(deps): the full-scan controller. app.js keeps its one instance, so moving between pages never
     breaks a scan. It follows the service's single job (report.progress events, else GET /api/reports/scan), and
     when the job reaches its Wi-Fi phase it runs the Wi-Fi scan through the TNT window's bridge
     (window.pywebview.api via TNT.wifiSurvey: the LocalSystem service may not list access points) and posts exactly
     one snapshot for that job, or one that says why there is none (a browser tab has no bridge, location access
     is off, ...);
   * siteCombo(opts): the site name field with suggestions of earlier sites (an ARIA combobox), used by the name
     modal, the progress card and Rename.
   Only touches TNT.util / TNT.ui inside functions: app.js, which defines them, loads last. */
(function () {
  'use strict';
  window.TNT = window.TNT || {};
  const TNT = window.TNT;

  const SITE_MAX = 80;               // characters in a site name (the service's limit)
  const WIFI_MAX_APS = 1000;         // access points in one posted snapshot (the service's limit)
  const SUGGESTIONS = 8;             // earlier sites listed under the name field
  const isNum = (v) => typeof v === 'number' && isFinite(v);
  const pad2 = (n) => (n < 10 ? '0' : '') + n;

  /* ============================================================== site names */
  /** A site name the way the service stores it: trimmed, inner whitespace collapsed, at most 80 characters. */
  function normalizeSite(text) {
    return String(text == null ? '' : text).replace(/\s+/g, ' ').trim().slice(0, SITE_MAX).trim();
  }

  /** The key reports of one site share: the normalised name in lower case (the service's casefolded site_key is
   *  the authority; this one only groups and ranks on the page). */
  function siteKey(text) { return normalizeSite(text).toLowerCase(); }

  /** Earlier sites for the typed text, best first: names starting with it, then names with a word starting with it,
   *  then any other name containing it; the most recently scanned first within each group. No text lists the most
   *  recent sites. `sites` are GET /api/reports/sites rows ({site, site_key, count, last_ts}); a repeated key is
   *  dropped; `limit` null keeps every match. */
  function rankSuggestions(sites, text, limit) {
    const q = siteKey(text);
    const seen = new Set();
    const ranked = [];
    (Array.isArray(sites) ? sites : []).forEach((s, i) => {
      if (!s || !s.site) return;
      const key = String(s.site_key || siteKey(s.site));
      if (seen.has(key)) return;
      const name = siteKey(s.site);
      let rank = 0;
      if (q) {
        const at = name.indexOf(q);
        if (at < 0) return;
        rank = at === 0 ? 0 : /[\s\-_.,/&()+'"]/.test(name.charAt(at - 1)) ? 1 : 2;
      }
      seen.add(key);
      ranked.push({ s, rank, i, last: Number(s.last_ts) || 0 });
    });
    ranked.sort((a, b) => a.rank - b.rank || b.last - a.last || String(a.s.site).localeCompare(String(b.s.site)) || a.i - b.i);
    return (limit == null ? ranked : ranked.slice(0, Math.max(0, limit))).map((x) => x.s);
  }

  /** [before, match, after] of a name around the first case-insensitive match of the typed text (for <mark>). */
  function matchParts(name, text) {
    const s = String(name == null ? '' : name);
    const q = normalizeSite(text).toLowerCase();
    const at = q ? s.toLowerCase().indexOf(q) : -1;
    if (at < 0) return [s, '', ''];
    return [s.slice(0, at), s.slice(at, at + q.length), s.slice(at + q.length)];
  }

  /* ========================================================= numbers & units */
  /** A duration in the compact form of the rest of TNT: "42 s", "3m 05s", "2h 04m", "3d 4h". */
  function durationText(s) {
    if (!isNum(s)) return '—';
    s = Math.max(0, Math.round(s));
    if (s < 60) return s + ' s';
    if (s < 3600) return Math.floor(s / 60) + 'm ' + pad2(s % 60) + 's';
    const hh = Math.floor(s / 3600), mm = Math.floor((s % 3600) / 60);
    if (s < 86400) return hh + 'h ' + pad2(mm) + 'm';
    return Math.floor(s / 86400) + 'd ' + (hh % 24) + 'h';
  }

  /** Rounded half away from zero, like the PDFs (tnt/report_pdf.py): −81.5 dBm is −82 on the page and on paper. */
  function roundAway(v) { return Math.sign(v) * Math.round(Math.abs(v)) || 0; }

  /** Counted units, with their singular. */
  const COUNT_UNITS = { devices: 'device', networks: 'network', APs: 'AP', outages: 'outage' };

  /** The number of a value in `unit`, the precision the PDFs use: Mbps whole from 100, else one decimal; ms two decimals below 1,
   *  one below 100, whole above; % "0", two decimals below 10, else one; dBm whole; per day two decimals below 10; minutes one
   *  decimal; counts whole; "s" a duration. "—" when missing. */
  function fmtNumber(v, unit) {
    if (!isNum(v)) return '—';
    if (v === 0 && unit !== 's') return '0';
    const a = Math.abs(v);
    const minus = (text) => text.replace(/^-/, '−');
    switch (unit) {
      case 'Mbps': return minus(a >= 100 ? String(roundAway(v)) : v.toFixed(1));
      case 'ms': return minus(a < 1 ? v.toFixed(2) : a < 100 ? v.toFixed(1) : String(roundAway(v)));
      case '%': return v === 0 ? '0' : minus(a < 10 ? v.toFixed(2) : v.toFixed(1));
      case 'dBm': case 'dB': return minus(String(roundAway(v)));
      case 'per day': return minus(a < 10 ? v.toFixed(2) : v.toFixed(1));
      case 'min': case 'min/day': return minus(v.toFixed(1));
      case 's': return durationText(v);
      default:
        if (COUNT_UNITS[unit] || Number.isInteger(v) || a >= 100) return minus(String(roundAway(v)));
        return minus(a >= 10 ? v.toFixed(1) : String(Math.round(v * 100) / 100));
    }
  }

  /** A value with its unit: "118 Mbps", "12.0 ms", "0.40%", "−52 dBm", "2h 05m", "24", "1 device", "0.43/day" (a unit of "per day"
   *  is written short: comparison tables are narrow). */
  function fmtValue(v, unit) {
    const n = fmtNumber(v, unit);
    if (n === '—' || !unit || unit === 's') return n;
    if (unit === '%') return n + '%';
    if (COUNT_UNITS[unit]) return n + ' ' + (Math.abs(roundAway(v)) === 1 ? COUNT_UNITS[unit] : unit);
    return unit === 'per day' ? n + '/day' : n + ' ' + unit;
  }

  /** "1 access point", "3 access points". */
  function plural(n, word, many) {
    const count = Math.round(Number(n) || 0);
    return count + ' ' + (count === 1 ? word : (many || word + 's'));
  }

  /** A link speed in bits per second: "2.5 Gbps", "866 Mbps"; "—" when unknown. */
  function bpsText(bps) {
    if (!isNum(bps) || bps <= 0) return '—';
    if (bps >= 1e9) return String(Math.round(bps / 1e8) / 10) + ' Gbps';
    if (bps >= 1e6) return String(Math.round(bps / 1e6)) + ' Mbps';
    return String(Math.round(bps / 1e3)) + ' kbps';
  }

  /* ================================================================= reports */
  const SECTIONS = [['network', 'Network'], ['speed', 'Speed test'], ['ping', 'Ping'], ['outages', 'Outages'], ['discovery', 'Discovery'], ['wifi', 'Wi-Fi']];

  /** Whether a report section has data -> {key, title, available, reason}. A section the report does not carry at
   *  all (a damaged or older report) counts as unavailable too. */
  function sectionState(report, key) {
    const data = report && report.data;
    const sec = data && typeof data === 'object' ? data[key] : null;
    const title = (SECTIONS.find((x) => x[0] === key) || [key, key])[1];
    if (!sec || typeof sec !== 'object') return { key, title, available: false, reason: 'Not in this report' };
    if (sec.available === false) return { key, title, available: false, reason: String(sec.reason || 'Not collected') };
    return { key, title, available: true, reason: null };
  }

  /** The window the ping and outage numbers cover, in words -> {text, title}, from the section's window_start,
   *  window_end and window_reason (which bound won: 7 days, this PC joining its network, the oldest data; site_network: only
   *  the pings and outages recorded on the site's network count, over every visit in the window). */
  function windowText(section) {
    const s = section || {};
    const len = isNum(s.window_start) && isNum(s.window_end) && s.window_end >= s.window_start ? durationText(s.window_end - s.window_start) : null;
    switch (s.window_reason) {
      case 'site_network': {
        const week = len != null && Math.abs(s.window_end - s.window_start - 7 * 86400) < 60;
        return { text: (len ? 'last ' + (week ? '7 days' : len) + ' ' : '') + 'on this network',
          title: 'Only the pings and outages recorded on this site\'s network count, from every visit in the 7 days before the report (less when the ping data begins later); time on other networks is left out' };
      }
      case 'seven_days': return { text: 'last 7 days', title: 'Pings and outages of the last 7 days before the report' };
      case 'network_change': return { text: 'last ' + len + ' (since this PC joined the network)', title: 'Pings and outages since this PC joined the network it was on for the report, less than 7 days before it' };
      case 'data_start': return { text: 'last ' + len + ' (all the data there was)', title: 'Pings and outages since the oldest ping data on this PC, less than 7 days before the report' };
      default: return { text: len ? 'last ' + len : '—', title: '' };
    }
  }

  /** The time a report's outage numbers cover, when part of its window was not monitored -> "monitored 2d 6h (8h 00m not
   *  monitoring)", else ''. */
  function monitoredText(outages) {
    const o = outages || {};
    if (o.available === false || !isNum(o.monitored_s) || !isNum(o.window_start) || !isNum(o.window_end)) return '';
    const off = o.window_end - o.window_start - o.monitored_s;
    return off >= 60 ? 'monitored ' + durationText(o.monitored_s) + ' (' + durationText(off) + ' not monitoring)' : '';
  }

  /** The visits to the site's network a report's pings and outages come from (ping.visits, ping.monitored_s) -> {text, title}:
   *  "2 visits, 1d 7h monitored" with every visit in the tooltip ("Sep 5 08:10 to Sep 5 17:40; Sep 11 07:37 to Sep 12 09:02"),
   *  "nothing monitored" without one, and '' for a report that has no visits (saved before networks were identified, or on a
   *  network that was not). `when(ts)` formats a time. */
  function visitsText(section, when) {
    const s = section || {};
    if (!Array.isArray(s.visits)) return { text: '', title: '' };
    const visits = s.visits.filter((v) => v && isNum(v.start) && isNum(v.end) && v.end >= v.start).sort((x, y) => x.start - y.start);
    if (!visits.length) return { text: 'nothing monitored', title: '' };
    const total = isNum(s.monitored_s) ? s.monitored_s : visits.reduce((sum, v) => sum + v.end - v.start, 0);
    const at = (ts) => (when ? when(ts) : String(ts));
    return { text: plural(visits.length, 'visit') + ', ' + durationText(total) + ' monitored', title: visits.map((v) => at(v.start) + ' to ' + at(v.end)).join('; ') };
  }

  /** What a report's pings and outages cover, for its meta line -> {text, title}: "last 7 days on this network, 2 visits, 1d 7h
   *  monitored" for a report of the site's network (never "not monitoring": the rest of its window may have been spent at other
   *  sites), "last 2d 14h (since this PC joined the network), monitored 2d 6h (8h 00m not monitoring)" for one made by the time
   *  rule, text '—' without a window. */
  function coverageText(data, when) {
    const d = data || {};
    const ping = d.ping && typeof d.ping === 'object' ? d.ping : {};
    const site = ping.window_reason === 'site_network';
    const win = windowText(site || ping.available !== false ? ping : d.outages);
    if (win.text === '—') return win;
    const extra = site ? visitsText(ping, when) : { text: monitoredText(d.outages), title: '' };
    return { text: win.text + (extra.text ? ', ' + extra.text : ''), title: win.title + (extra.title ? '. Visits: ' + extra.title : '') };
  }

  /** The window a running scan's report will read, from the job's window_start / window_reason -> "since Sep 9 07:37, when this
   *  PC joined this network", "on this network since Sep 5 08:10, earlier visits included", or '' before the service says.
   *  `when(ts)` formats the date. */
  function jobWindowText(job, when) {
    if (!job || !isNum(job.window_start)) return '';
    const at = when ? when(job.window_start) : String(job.window_start);
    switch (job.window_reason) {
      case 'site_network': return 'on this network since ' + at + ', earlier visits included';
      case 'network_change': return 'since ' + at + ', when this PC joined this network';
      case 'data_start': return 'since ' + at + ', when its ping data begins';
      case 'seven_days': return 'over the last 7 days, since ' + at;
      default: return 'since ' + at;
    }
  }

  /** Whether a MAC has the locally-administered bit set (a phone hotspot, a randomised or virtual interface): its OUI names no vendor. */
  function localMac(mac) {
    const m = /^([0-9a-f]{2})[:-]/i.exec(String(mac || ''));
    return !!m && (parseInt(m[1], 16) & 2) === 2;
  }

  /** How a report's site network was identified (data.meta.network, or a running job's network) -> {identity, mac, vendor, text, title,
   *  note, portable}, or null for a report without it (saved before networks were identified) or with an identity this page does not
   *  know. "mac": the router by its MAC and vendor ("likely <vendor>" for a locally administered MAC, whose OUI is only a guess);
   *  "fingerprint": the router's MAC could not be read, or it is a redundant gateway's virtual MAC (VRRP, HSRP, an HA firewall pair) that
   *  repeats at unrelated sites, so its gateway, subnet and DHCP server (in the tooltip) identify the network; "unknown": no router line,
   *  a note that the report fell back to the time rule instead. A portable network (a hotspot or travel router carried from site to
   *  site) notes that only the connection to it counts. */
  function networkIdentity(net) {
    if (!net || typeof net !== 'object') return null;
    const where = [net.gateway_ip ? 'gateway ' + net.gateway_ip : '', net.subnet ? 'subnet ' + net.subnet : '', net.dhcp_server ? 'DHCP server ' + net.dhcp_server : '']
      .filter(Boolean).join(', ');
    const portable = !!net.portable;
    const note = portable ? 'This network is carried from site to site (a hotspot or travel router), so only the connection to it counts, and no site is suggested for it.' : '';
    if (net.identity === 'mac' && net.mac) {
      const local = localMac(net.mac);
      const vendor = net.vendor ? (local ? 'likely ' : '') + String(net.vendor) : '';
      return { identity: 'mac', mac: String(net.mac), vendor, text: String(net.mac) + (vendor ? ' · ' + vendor : ''),
        title: 'The site\'s network is the one behind this router' + (where ? ' (' + where + ')' : '') +
          (local ? '. Its MAC is locally administered (a phone hotspot, a randomised or virtual interface), so the vendor is a guess from its base OUI' : ''),
        note, portable };
    }
    if (net.identity === 'fingerprint' && net.virtual_mac) {
      return { identity: 'fingerprint', mac: '', vendor: '', text: 'redundant gateway (virtual router MAC ' + net.virtual_mac + '), identified with its gateway and subnet',
        title: 'Redundant routers answer from a virtual MAC that repeats at unrelated sites, so the network is known by ' + (where || 'its gateway and subnet') + ' as well',
        note, portable };
    }
    if (net.identity === 'fingerprint') {
      return { identity: 'fingerprint', mac: '', vendor: '', text: 'identified by gateway and subnet',
        title: 'The router\'s MAC could not be read, so the network is known by ' + (where || 'its gateway and subnet'), note, portable };
    }
    if (net.identity !== 'unknown') return null;
    return { identity: 'unknown', mac: '', vendor: '', text: '', title: '',
      note: 'The network was not identified when the scan started, so the pings and outages are read by time (the window above).', portable: false };
  }

  /** A report's note on the pings recorded before this PC identified its networks (ping.untagged_since, left out before it) -> "Pings
   *  recorded before this PC identified its networks count only from Sep 9 07:37, when it joined this network.", or ''. */
  function untaggedText(ping, when) {
    const since = ping && isNum(ping.untagged_since) ? ping.untagged_since : null;
    return since == null ? '' : 'Pings recorded before this PC identified its networks count only from ' + (when ? when(since) : String(since)) + ', when it joined this network.';
  }

  /** The name modal's first sentence for a running job: what its report adds, by the window it reads (the line under it says since
   *  when): the pings and outages recorded on this network in the last 7 days (site_network), else this PC's since it joined the
   *  network (the time rule; a portable network's connection). */
  function modalIntro(job) {
    const adds = job && job.window_reason === 'site_network'
      ? 'The report adds the pings and outages recorded on this network in the last 7 days.'
      : 'The report adds this PC\'s pings and outages since it joined this network, at most 7 days.';
    return 'A speed test, a Discovery scan and a Wi-Fi scan are running. ' + adds + ' Which site is this?';
  }

  /** How good a number is, with the PDFs' thresholds (tnt/report_pdf.py key_levels): '' , 'warn' or 'bad'. */
  const LEVELS = {
    download: (v) => (!isNum(v) ? '' : v < 10 ? 'bad' : v < 25 ? 'warn' : ''),
    upload: (v) => (!isNum(v) ? '' : v < 2 ? 'bad' : v < 5 ? 'warn' : ''),
    loss: (v) => (!isNum(v) ? '' : v >= 5 ? 'bad' : v >= 1 ? 'warn' : ''),
    signal: (v) => (!isNum(v) ? '' : v < -75 ? 'bad' : v < -67 ? 'warn' : ''),
    crowd: (v) => (isNum(v) && v >= 4 ? 'warn' : ''),
  };
  const worse = (a, b) => (a === 'bad' || b === 'bad' ? 'bad' : a || b || '');

  /** The key numbers strip of a report from its summary (and data, for the channel crowding) -> [{key, label, value, sub, level}];
   *  level is '' or 'warn' / 'bad' for a number worth a second look: download below 25 / 10 Mbps, upload below 5 / 2, loss from
   *  1 % / 5 %, any outage, a connected signal below −67 / −75 dBm, four or more access points on the connected channel. */
  function keyNumbers(summary, data) {
    const s = summary || {};
    const wifi = data && data.wifi && data.wifi.available !== false ? data.wifi : null;
    const conn = wifi && wifi.connected ? wifi.connected : null;
    const loss = (v) => (isNum(v) ? fmtValue(v, '%') + ' loss' : '');
    const count = (v) => (isNum(v) ? String(Math.round(v)) : '—');
    const wifiSub = [isNum(s.wifi_networks) ? plural(s.wifi_networks, 'network') : '',
      isNum(s.wifi_connected_rssi) ? fmtValue(s.wifi_connected_rssi, 'dBm') + ' connected' : '',
      conn && isNum(conn.channel_aps) && conn.channel_aps >= 4 ? conn.channel_aps + ' on its channel' : ''].filter(Boolean).join(' · ');
    return [
      { key: 'download', label: 'Download', value: fmtValue(s.download_mbps, 'Mbps'), sub: '', level: LEVELS.download(s.download_mbps) },
      { key: 'upload', label: 'Upload', value: fmtValue(s.upload_mbps, 'Mbps'), sub: '', level: LEVELS.upload(s.upload_mbps) },
      { key: 'latency', label: 'Latency', value: fmtValue(s.latency_ms, 'ms'), sub: '', level: '' },
      { key: 'gateway', label: 'Gateway', value: fmtValue(s.gateway_avg_ms, 'ms'), sub: loss(s.gateway_loss_pct), level: LEVELS.loss(s.gateway_loss_pct) },
      { key: 'internet', label: 'Internet', value: fmtValue(s.internet_avg_ms, 'ms'), sub: loss(s.internet_loss_pct), level: LEVELS.loss(s.internet_loss_pct) },
      { key: 'outages', label: 'Outages', value: count(s.outages), sub: isNum(s.outages) && s.outages > 0 && isNum(s.downtime_s) && s.downtime_s > 0 ? durationText(s.downtime_s) + ' network down' : '',
        level: isNum(s.outages) && s.outages > 0 ? 'warn' : '' },
      { key: 'devices', label: 'Devices', value: count(s.hosts), sub: '', level: '' },
      { key: 'wifi', label: 'Wi-Fi APs', value: count(s.wifi_aps), sub: wifiSub,
        level: worse(LEVELS.signal(s.wifi_connected_rssi), LEVELS.crowd(conn && conn.channel_aps)) },
    ];
  }

  /** What an outage item of a report was: "Internet down: Public DNS (198.51.100.1), example.net", "NVR (172.16.40.20)",
   *  "Not monitoring" (tnt/report_pdf.py outage_what). */
  function outageWhat(item) {
    const o = item || {};
    if (o.kind === 'total_local' || o.kind === 'total_internet') {
      const members = (Array.isArray(o.targets) ? o.targets : []).filter(Boolean);
      return (o.kind === 'total_local' ? 'Local network down' : 'Internet down') + (members.length ? ': ' + members.join(', ') : '');
    }
    if (o.kind === 'gap') return 'Not monitoring';
    return String(o.name || o.host || 'A target');
  }

  /** One line of key numbers for a saved report in a list: "↓ 118 ↑ 31 Mbps · 14 ms · 24 devices · 38 APs". */
  function summaryLine(summary) {
    const s = summary || {};
    const parts = [];
    if (isNum(s.download_mbps) || isNum(s.upload_mbps)) parts.push('↓ ' + fmtNumber(s.download_mbps, 'Mbps') + ' ↑ ' + fmtNumber(s.upload_mbps, 'Mbps') + ' Mbps');
    if (isNum(s.latency_ms)) parts.push(fmtValue(s.latency_ms, 'ms'));
    if (isNum(s.hosts)) parts.push(s.hosts + (s.hosts === 1 ? ' device' : ' devices'));
    if (isNum(s.wifi_aps)) parts.push(s.wifi_aps + (s.wifi_aps === 1 ? ' AP' : ' APs'));
    return parts.join(' · ') || 'No numbers';
  }

  /** A file name for a saved PDF when the service sends none: "TNT-report-Acme-Dental-2026-09-09-1402.pdf". */
  function reportFilename(site, ts) {
    const safe = String(site == null ? '' : site).replace(/[^A-Za-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'site';
    const d = new Date((isNum(ts) ? ts : Date.now() / 1000) * 1000);
    return 'TNT-report-' + safe + '-' + d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) + '-' + pad2(d.getHours()) + pad2(d.getMinutes()) + '.pdf';
  }

  /** A file name for a saved comparison PDF when the service sends none: "TNT-compare-Acme-Dental-vs-Maple-Street.pdf". */
  function compareFilename(siteA, siteB) {
    const safe = (s) => String(s == null ? '' : s).replace(/[^A-Za-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 30) || 'site';
    return 'TNT-compare-' + safe(siteA) + '-vs-' + safe(siteB) + '.pdf';
  }

  /* ================================================================= compare */
  const MAX_REL_PCT = 500;           // beyond this a relative change reads as a ratio ("×33"), never "+71900%"

  /** How one comparison row reads -> {a, b, diff, arrow, aCls, bCls, diffCls, verdict}. The difference is A − B worked
   *  out from the two values, with the change relative to B, so it reads the same whatever sign the row's own delta
   *  has: loss in percentage points ("+2.42 pts"), signal in dB, no relative change beside a "same" verdict, a ratio beyond
   *  ±500 %, and "≈ 0" for a change too small to show. Colours follow the row's `better` side: 'better' (green) for the
   *  better value, 'worse' (red) for the other; 'same' within the service's tolerance; 'info' for an informational row
   *  (higher_is_better null) or an undecided one; nothing when a side is missing. */
  function compareCell(row) {
    const r = row || {};
    const unit = r.unit || '';
    const a = isNum(r.a) ? r.a : null, b = isNum(r.b) ? r.b : null;
    const out = { a: fmtValue(a, unit), b: fmtValue(b, unit), diff: '—', arrow: '', aCls: '', bCls: '', diffCls: '', verdict: '' };
    if (a == null || b == null) return out;
    const d = Math.round((a - b) * 1000) / 1000;
    const same = r.better === 'same';
    const magnitude = unit === '%' ? fmtNumber(Math.abs(d), '%') + ' pts' : unit === 'dBm' ? fmtValue(Math.abs(d), 'dB')
      : COUNT_UNITS[unit] ? String(roundAway(Math.abs(d))) : fmtValue(Math.abs(d), unit);
    if (d === 0) { out.diff = 'same'; out.arrow = '='; }
    else if (!/[1-9]/.test(magnitude)) { out.diff = '≈ 0'; out.arrow = '≈'; }
    else {
      const sign = d > 0 ? '+' : '−';
      out.arrow = d > 0 ? '▲' : '▼';
      const pct = b !== 0 ? Math.abs(d / b) * 100 : null;
      let rel = '';
      if (pct != null && pct >= 0.5 && unit !== '%' && unit !== 'dBm' && !same) {
        const hi = Math.max(Math.abs(a), Math.abs(b)), lo = Math.min(Math.abs(a), Math.abs(b));
        if (pct > MAX_REL_PCT && lo > 0) rel = ' (×' + (hi / lo >= 10 ? Math.round(hi / lo) : (hi / lo).toFixed(1)) + ')';
        else rel = ' (' + sign + (pct >= 10 ? Math.round(pct) : pct.toFixed(1)) + '%)';
      }
      out.diff = sign + magnitude + rel;
    }
    if (r.higher_is_better == null || r.better == null) { out.diffCls = 'info'; return out; }
    if (same) { out.diffCls = 'same'; out.verdict = 'about the same'; if (d !== 0) out.arrow = '≈'; return out; }
    out.aCls = r.better === 'a' ? 'better' : 'worse';
    out.bCls = r.better === 'b' ? 'better' : 'worse';
    out.diffCls = out.aCls;
    out.verdict = r.better === 'a' ? 'A is better' : 'B is better';
    return out;
  }

  /** Which side a comparison section has numbers for when only one does -> 'a', 'b' or null: every row with a value on one side
   *  only, the same side each time (one report did not scan Wi-Fi, say). The page then lists that side's values once instead
   *  of a column of dashes. */
  function oneSided(rows) {
    const list = (Array.isArray(rows) ? rows : []).filter(Boolean);
    if (!list.length) return null;
    const sides = new Set(list.map((r) => (isNum(r.a) && !isNum(r.b) ? 'a' : !isNum(r.a) && isNum(r.b) ? 'b' : 'both')));
    return sides.size === 1 && !sides.has('both') ? Array.from(sides)[0] : null;
  }

  /** The report pickers' options: saved reports grouped by site (the site with the newest report first, each site's
   *  reports newest first), narrowed by a typed text found in the site name or the date label. `label(ts)` formats a
   *  report's date; a partial report says so. -> [{site, key, items: [{id, label, created_ts}]}] */
  function reportOptions(reports, text, label) {
    const q = normalizeSite(text).toLowerCase();
    const groups = new Map();
    for (const r of Array.isArray(reports) ? reports : []) {
      if (!r || r.id == null) continue;
      const when = String(label ? label(r.created_ts) : r.created_ts);
      if (q && !String(r.site || '').toLowerCase().includes(q) && !when.toLowerCase().includes(q)) continue;
      const key = siteKey(r.site);
      if (!groups.has(key)) groups.set(key, { site: String(r.site || ''), key, newest: -Infinity, items: [] });
      const g = groups.get(key);
      g.items.push({ id: r.id, label: when + (r.status === 'partial' ? ' · partial' : ''), created_ts: Number(r.created_ts) || 0 });
      g.newest = Math.max(g.newest, Number(r.created_ts) || 0);
    }
    const out = Array.from(groups.values());
    for (const g of out) g.items.sort((x, y) => y.created_ts - x.created_ts);
    out.sort((x, y) => y.newest - x.newest);
    return out.map((g) => ({ site: g.site, key: g.key, items: g.items }));
  }

  /** Report B of a comparison nobody picked yet: the one picked last time (a technician's known good network) while it
   *  exists and is not A, else the previous report of A's site, else none (null). `reports` newest first or not. */
  function defaultCompareB(reports, aId, rememberedId) {
    const list = (Array.isArray(reports) ? reports : []).filter((r) => r && r.id != null);
    if (rememberedId != null && String(rememberedId) !== String(aId) && list.some((r) => String(r.id) === String(rememberedId))) {
      return list.find((r) => String(r.id) === String(rememberedId)).id;
    }
    const a = list.find((r) => String(r.id) === String(aId));
    if (!a) return null;
    const earlier = list.filter((r) => r.id !== a.id && siteKey(r.site) === siteKey(a.site) && (Number(r.created_ts) || 0) < (Number(a.created_ts) || 0))
      .sort((x, y) => (Number(y.created_ts) || 0) - (Number(x.created_ts) || 0));
    return earlier.length ? earlier[0].id : null;
  }

  /* ===================================================================== job */
  const PHASES = [
    { key: 'speed', label: 'Speed test' }, { key: 'discovery', label: 'Discovery scan' }, { key: 'wifi', label: 'Wi-Fi scan' },
    { key: 'history', label: 'Ping and outage history' }, { key: 'save', label: 'Save the report' },
  ];
  const PHASE_SHORT = { speed: 'Speed', discovery: 'Discovery', wifi: 'Wi-Fi', finalize: 'Finishing' };

  /** The short name of a job's phase, the same on every button and tile: "Speed", "Discovery", "Wi-Fi", and for the service's
   *  "finalize" the step the checklist shows running ("History" while the ping and outage history is read, "Saving" while the
   *  report is written), else "Finishing". */
  function phaseShort(job) {
    if (!job) return 'Scanning';
    if (job.phase === 'finalize' && Array.isArray(job.phases)) {
      const running = job.phases.find((p) => p && p.status === 'running');
      if (running && running.key === 'history') return 'History';
      if (running && running.key === 'save') return 'Saving';
    }
    return PHASE_SHORT[job.phase] || 'Scanning';
  }

  /** The Full Scan buttons for a job -> {running, label, phase, pct, title}: "Full Scan" when idle, "Wi-Fi 64%" while a
   *  scan runs (`phase` alone is for the accessible name, which should not change with every percent). */
  function jobButton(job) {
    if (!job || job.status !== 'running') {
      return { running: false, label: 'Full Scan', phase: '', pct: 0, title: 'Full Scan: a speed test, a Discovery scan and a Wi-Fi scan, saved with the last days of pings and outages as a site report' };
    }
    const pct = Math.max(0, Math.min(100, Math.round(Number(job.pct) || 0)));
    const phase = phaseShort(job);
    const site = jobSite(job).site;
    return { running: true, label: phase + ' ' + pct + '%', phase, pct, title: 'Full scan running: ' + phase + ', ' + pct + ' % done' + (site ? ' · ' + site : '') + '. Click to open Reports.' };
  }

  /** The earlier report of the network a job scans (job.suggested_site, the newest report with the same network id) ->
   *  {site, report_id, created_ts}, or null. */
  function suggestedSite(job) {
    const s = job && job.suggested_site && typeof job.suggested_site === 'object' ? job.suggested_site : null;
    const site = s ? normalizeSite(s.site) : '';
    return site ? { site, report_id: s.report_id != null ? s.report_id : null, created_ts: isNum(s.created_ts) ? s.created_ts : null } : null;
  }

  /** The site a job's report is (or will be) saved under -> {site, suggested}: the name given; else, while it runs or once saved,
   *  the suggested site (a scan nobody names is saved under it), with suggested true; else null. */
  function jobSite(job) {
    if (!job) return { site: null, suggested: false };
    if (job.site) return { site: String(job.site), suggested: false };
    const s = job.status === 'running' || job.status === 'saved' ? suggestedSite(job) : null;
    return { site: s ? s.site : null, suggested: !!s };
  }

  /** The name modal's hint for a network scanned before -> [lead, site, tail] (the page puts the site in bold): "This network (router
   *  02:00:5E:10:00:0A · Example Networks, gateway 192.168.1.1) was scanned as ", "Acme Dental", " on Sep 9, 14:02. Save name to add
   *  this scan to its reports, or type another site."; the network as the job describes it (job.network), so a phone hotspot or travel
   *  router brought from the last site is recognised; null without a suggestion. `when(ts)` formats the date. */
  function suggestionHint(job, when) {
    const s = suggestedSite(job);
    if (!s) return null;
    const on = s.created_ts != null ? ' on ' + (when ? when(s.created_ts) : String(s.created_ts)) : ' before';
    const net = job && job.network && typeof job.network === 'object' ? job.network : null;
    const ident = networkIdentity(net);
    const bits = [];
    if (ident && ident.identity === 'mac') bits.push('router ' + ident.text);
    else if (net && net.virtual_mac) bits.push('virtual router ' + net.virtual_mac);
    if (net && net.gateway_ip) bits.push('gateway ' + net.gateway_ip);
    return [bits.length ? 'This network (' + bits.join(', ') + ') was scanned as ' : 'This network was scanned as ', s.site,
      on + '. Save name to add this scan to its reports, or type another site.'];
  }

  /** The job's phases in their order, each with the status the job gives it ('pending' when it lists none) ->
   *  [{key, label, status, message, started_ts, finished_ts}]. */
  function jobPhases(job) {
    const listed = new Map((job && Array.isArray(job.phases) ? job.phases : []).filter((p) => p && p.key).map((p) => [p.key, p]));
    return PHASES.map((ph) => {
      const p = listed.get(ph.key) || {};
      return { key: ph.key, label: ph.label, status: String(p.status || 'pending'), message: p.message ? String(p.message) : '',
        started_ts: isNum(p.started_ts) ? p.started_ts : null, finished_ts: isNum(p.finished_ts) ? p.finished_ts : null };
    });
  }

  /* ====================================================== Wi-Fi snapshot post */
  const AP_FIELDS = ['bssid', 'ssid', 'hidden', 'rssi', 'quality', 'band', 'channel', 'center_channel', 'width_mhz', 'freq_mhz', 'phy', 'generation',
    'security', 'max_rate_mbps', 'connected', 'first_seen', 'last_seen'];
  const IFACE_FIELDS = ['guid', 'description', 'state', 'connected_bssid', 'connected_ssid'];
  const NO_BRIDGE = 'This page is not the TNT window: the Wi-Fi scan runs in the TNT app, not in a browser tab';
  const OUTDATED = 'This TNT window has no Wi-Fi survey: update TNT';

  function pickFields(obj, fields) {
    const o = {};
    for (const f of fields) if (obj[f] !== undefined) o[f] = obj[f];
    return o;
  }

  /** The snapshot a full scan posts, from a survey dict (window.pywebview.api.wifi_survey): the access points in
   *  range (stale ones and the signal history left out), strongest first, at most 1000, with the fields a report
   *  keeps (the service adds the vendors). available only for a survey in state "ok". */
  function wifiPayload(survey, nowTs) {
    const s = survey || {};
    const ok = s.state === 'ok';
    const rssi = (ap) => (isNum(ap.rssi) ? ap.rssi : -999);
    const aps = ok ? (Array.isArray(s.aps) ? s.aps : []).filter((ap) => ap && ap.bssid && !ap.stale)
      .sort((x, y) => rssi(y) - rssi(x)).slice(0, WIFI_MAX_APS).map((ap) => pickFields(ap, AP_FIELDS)) : [];
    return {
      available: ok, state: String(s.state || 'error'), error: ok ? null : String(s.error || 'The Wi-Fi survey is not available'),
      collected_ts: ok && isNum(s.last_read_ts) ? s.last_read_ts : nowTs,
      interfaces: (Array.isArray(s.interfaces) ? s.interfaces : []).filter((i) => i && typeof i === 'object').map((i) => pickFields(i, IFACE_FIELDS)),
      aps,
    };
  }

  /** A snapshot saying why there is no Wi-Fi data (state: no_bridge, outdated, the survey's own state, error). */
  function wifiUnavailable(state, error, nowTs) {
    return { available: false, state: String(state || 'error'), error: String(error || 'The Wi-Fi survey is not available'), collected_ts: nowTs, interfaces: [], aps: [] };
  }

  /** What the controller does with one survey read during a full scan's Wi-Fi part -> {action: 'wait'} or {action:
   *  'post', body}. `requestTs` is when wifi_scan_now was asked (s), `elapsedMs` how long it has been reading and
   *  `limitMs` how long it may (about 15 s). A read after the scan request is posted at once; a survey that cannot
   *  scan (switched off, location access off, no adapter, radio off, error) at once as unavailable, with its own state
   *  and words; past the limit the latest good read as it is, else an unavailable snapshot saying why. */
  function wifiDecision(survey, requestTs, elapsedMs, limitMs, nowTs, callError) {
    const late = elapsedMs >= limitMs;
    if (!survey) return late ? { action: 'post', body: wifiUnavailable('error', callError || 'The TNT window did not answer', nowTs) } : { action: 'wait' };
    const state = String(survey.state || '');
    if (state === 'ok') {
      const fresh = isNum(survey.last_read_ts) && survey.last_read_ts > requestTs;
      return fresh || late ? { action: 'post', body: wifiPayload(survey, nowTs) } : { action: 'wait' };
    }
    if (state === 'starting') return late ? { action: 'post', body: wifiUnavailable('starting', 'The Wi-Fi survey was still starting', nowTs) } : { action: 'wait' };
    return { action: 'post', body: wifiUnavailable(state || 'error', survey.error || 'The Wi-Fi survey is not available', nowTs) };
  }

  /* ==================================================== full-scan controller */
  /** deps: {api (TNT.api), survey (TNT.wifiSurvey, or null without one), live() -> whether the event stream is live,
   *  nowS(), nowMs(), wifiLimitMs (15000), wifiPollMs (1000), bridgeWaitMs (3000), pollMs (2000), livePollMs (10000)}
   *  -> {job, running(), start(site), refresh(), setSite(site), cancel(), apply(job), subscribe(fn), posts, stop()}.
   *  The job is followed from apply() (report.progress, or the answer of a request) and polled every `pollMs` while it
   *  runs and the stream is down (every `livePollMs` while it is up, in case an event was missed: SSE has no replay).
   *  The Wi-Fi part runs once per job id whatever number of progress events or polls announce the phase. */
  function createFullScan(deps) {
    const d = Object.assign({ wifiLimitMs: 15000, wifiPollMs: 1000, bridgeWaitMs: 3000, pollMs: 2000, livePollMs: 10000,
      live: () => false, nowS: () => Date.now() / 1000, nowMs: () => Date.now(), survey: null }, deps || {});
    const listeners = new Set();
    const taken = new Set();              // ids of the jobs whose Wi-Fi part this page ran: one snapshot each
    const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    let job = null, pollTimer = null, stopped = false;

    const ctl = {
      posts: [],                          // every snapshot posted: {job_id, body, ok, error}
      get job() { return job; },
      running() { return !!job && job.status === 'running'; },
      subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); },
      apply, refresh, start, setSite, cancel, stop,
    };

    function schedulePoll() {
      if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
      if (stopped || !ctl.running()) return;
      pollTimer = setTimeout(() => { pollTimer = null; refresh(); }, d.live() ? d.livePollMs : d.pollMs);
    }

    function apply(next) {
      if (stopped) return job;
      next = next && typeof next === 'object' && next.id != null ? next : null;
      // a poll that left before the event that finished this job must not set it running again
      if (next && job && next.id === job.id && job.status !== 'running' && next.status === 'running') return job;
      const prev = job;
      job = next;
      schedulePoll();
      if (job && job.status === 'running' && job.phase === 'wifi' && !taken.has(job.id)) runWifi(job);
      for (const fn of Array.from(listeners)) { try { fn(job, prev); } catch (e) { console.error(e); } }
      return job;
    }

    function refresh() {
      return Promise.resolve().then(() => d.api.fullScanJob()).then((r) => apply(r ? r.job : null), () => { schedulePoll(); return job; });
    }

    /** POST /api/reports/scan -> {job, started}; a scan already running (409 busy) is adopted, started false. */
    function start(site) {
      const name = normalizeSite(site);
      return Promise.resolve().then(() => d.api.fullScanStart(name || null)).then((r) => ({ job: apply(r && r.job), started: true }), (err) => {
        if (err && err.status === 409 && err.body && err.body.job) return { job: apply(err.body.job), started: false };
        throw err;
      });
    }
    function setSite(site) { return d.api.fullScanName(normalizeSite(site)).then((r) => apply(r && r.job)); }
    function cancel() { return d.api.fullScanCancel().then((r) => apply(r && r.job)); }
    function stop() { stopped = true; if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; } listeners.clear(); }

    async function runWifi(j) {
      taken.add(j.id);
      let body;
      try { body = await collectWifi(); }
      catch (err) { body = wifiUnavailable('error', (err && err.message) || String(err), d.nowS()); }
      const entry = { job_id: j.id, body, ok: false, error: null };
      ctl.posts.push(entry);
      // the job may have moved on meanwhile (cancelled, or the service stopped waiting): it answers 409 then
      try { await d.api.fullScanWifi(body); entry.ok = true; }
      catch (err) { entry.error = (err && err.message) || String(err); }
      return entry;
    }

    async function collectWifi() {
      const s = d.survey;
      if (!s || typeof s.bridgeState !== 'function') return wifiUnavailable('no_bridge', NO_BRIDGE, d.nowS());
      // pywebview injects its bridge a moment after the page loads
      const t0 = d.nowMs();
      while (s.bridgeState() === 'waiting' && d.nowMs() - t0 < d.bridgeWaitMs) await sleep(Math.min(250, d.bridgeWaitMs));
      const bridge = s.bridgeState();
      if (bridge === 'outdated') return wifiUnavailable('outdated', OUTDATED, d.nowS());
      if (bridge !== 'ready') return wifiUnavailable('no_bridge', NO_BRIDGE, d.nowS());
      const requestTs = d.nowS();
      // refused within 5 s of another scan request: the survey's own reads carry on, so the page just keeps reading
      await s.call('wifi_scan_now');
      const started = d.nowMs();
      for (;;) {
        const snap = await s.fetch({ active: true, history_s: 60 });
        const v = wifiDecision(snap, requestTs, d.nowMs() - started, d.wifiLimitMs, d.nowS(), s.error);
        if (v.action === 'post') return v.body;
        await sleep(d.wifiPollMs);
      }
    }

    return ctl;
  }

  /* ======================================================= site name combobox */
  let comboSeq = 0;

  /** The site name field: an input with a list of earlier sites that narrows as the user types (the ARIA combobox
   *  pattern with a listbox: Down / Up move through the list, Enter picks the highlighted site or else submits the
   *  text, Escape closes the list, a click picks). The list sits in the normal flow under the input, so a modal body
   *  never clips it. Until the user types, the text in it is the page's (an old name, a suggested site): Down / Up then
   *  list the most recent sites, not only the ones matching that text. opts: {value, placeholder, label, describedBy (the
   *  id of a hint), fetchSites(text) -> Promise<sites>, onEnter(value), onPick(site), debounceMs} -> {el, input, value(),
   *  setValue(text), touched(), isOpen(), close(), focus(), destroy()}. */
  function siteCombo(opts) {
    opts = opts || {};
    const { h, relTime } = TNT.util;
    const id = 'site-combo-' + (++comboSeq);
    const input = h('input', { class: 'input site-combo-input', type: 'text', id: id + '-input', role: 'combobox', 'aria-autocomplete': 'list',
      'aria-expanded': 'false', 'aria-controls': id + '-list', 'aria-label': opts.label || 'Site name', 'aria-describedby': opts.describedBy || null,
      autocomplete: 'off', spellcheck: 'false', maxlength: String(SITE_MAX), placeholder: opts.placeholder || '', value: opts.value || '' });
    const list = h('ul', { class: 'site-combo-list', role: 'listbox', id: id + '-list', 'aria-label': 'Earlier sites', hidden: true });
    const el = h('div', { class: 'site-combo' }, input, list);
    let items = [], active = -1, timer = null, seq = 0, destroyed = false, typed = false;

    const isOpen = () => !list.hidden;
    function setOpen(on) {
      on = !!on && items.length > 0 && !destroyed;
      list.hidden = !on;
      input.setAttribute('aria-expanded', String(on));
      if (!on) { active = -1; input.removeAttribute('aria-activedescendant'); }
    }
    function highlight(i) {
      active = i;
      Array.from(list.children).forEach((li, k) => li.setAttribute('aria-selected', String(k === i)));
      const li = list.children[i];
      if (li) {
        input.setAttribute('aria-activedescendant', li.id);
        try { li.scrollIntoView({ block: 'nearest' }); } catch (e) { /* not laid out */ }
      } else input.removeAttribute('aria-activedescendant');
    }
    function render(text) {
      list.innerHTML = '';
      items.forEach((s, i) => {
        const [pre, hit, post] = matchParts(s.site, text);
        const n = Number(s.count) || 0;
        const meta = (n ? n + (n === 1 ? ' scan' : ' scans') : '') + (s.last_ts ? (n ? ' · ' : '') + relTime(s.last_ts) : '');
        const li = h('li', { role: 'option', id: id + '-opt-' + i, 'aria-selected': 'false', class: 'site-combo-option' },
          h('span', { class: 'site-combo-name' }, pre, hit ? h('mark', null, hit) : null, post),
          meta ? h('span', { class: 'site-combo-meta' }, meta) : null);
        // mousedown, not click: the input keeps the focus, so the list is still there when the button comes up
        li.addEventListener('mousedown', (e) => { e.preventDefault(); pick(i); });
        list.appendChild(li);
      });
    }
    function load(text, open) {
      const mine = ++seq;
      Promise.resolve().then(() => (opts.fetchSites ? opts.fetchSites(normalizeSite(text)) : [])).then((sites) => {
        if (destroyed || mine !== seq) return;          // an answer to an older text
        items = rankSuggestions(sites, text, SUGGESTIONS);
        render(text);
        setOpen(open && document.activeElement === input);
      }, () => { if (!destroyed && mine === seq) { items = []; setOpen(false); } });
    }
    function pick(i) {
      const s = items[i];
      if (!s) return;
      input.value = s.site;
      setOpen(false);
      try { input.focus(); } catch (e) { /* ignore */ }
      if (opts.onPick) opts.onPick(s.site);
    }

    input.addEventListener('input', () => {
      typed = true;
      active = -1;
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => { timer = null; load(input.value, true); }, opts.debounceMs == null ? 180 : opts.debounceMs);
    });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        if (!isOpen()) {
          // a name the page put there (an old name, a suggested site) lists the recent sites: they are what could replace it
          if (items.length && typed) { setOpen(true); highlight(e.key === 'ArrowDown' ? 0 : items.length - 1); } else load(typed ? input.value : '', true);
          return;
        }
        const n = items.length;
        highlight(e.key === 'ArrowDown' ? (active + 1) % n : (active <= 0 ? n - 1 : active - 1));
      } else if (e.key === 'Enter') {
        if (isOpen() && active >= 0) { e.preventDefault(); pick(active); return; }
        if (opts.onEnter) { e.preventDefault(); setOpen(false); opts.onEnter(normalizeSite(input.value)); }
      } else if (e.key === 'Escape') {
        if (isOpen()) { e.preventDefault(); e.stopPropagation(); setOpen(false); }
      } else if (e.key === 'Tab') setOpen(false);
    });
    input.addEventListener('blur', () => setOpen(false));

    return {
      el, input,
      value: () => normalizeSite(input.value),
      setValue(text) { input.value = text == null ? '' : String(text); typed = false; setOpen(false); },
      touched: () => typed,
      isOpen, close: () => setOpen(false),
      focus() { try { input.focus(); } catch (e) { /* ignore */ } },
      destroy() { destroyed = true; seq++; if (timer) { clearTimeout(timer); timer = null; } },
    };
  }

  TNT.reportsui = {
    SITE_MAX, WIFI_MAX_APS, PHASES, SECTIONS,
    normalizeSite, siteKey, rankSuggestions, matchParts,
    durationText, fmtNumber, fmtValue, bpsText, plural,
    sectionState, windowText, monitoredText, visitsText, coverageText, jobWindowText, networkIdentity, localMac, untaggedText, modalIntro,
    keyNumbers, outageWhat, summaryLine,
    reportFilename, compareFilename, compareCell, oneSided, reportOptions, defaultCompareB,
    jobButton, phaseShort, jobPhases, suggestedSite, jobSite, suggestionHint,
    wifiPayload, wifiUnavailable, wifiDecision,
    createFullScan, siteCombo,
  };
})();
