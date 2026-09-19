/* TNT — views/ipinfo.js
   The live link map, the realtime throughput card (js/throughput.js), the NAT, switch port & port forward
   card (js/netcheck.js), then one card per adapter (internet-facing first), grouped subnets,
   copy-on-click values. */
(function () {
  'use strict';
  const TNT = window.TNT;
  TNT.views = TNT.views || {};

  let root = null, gridEl = null, summaryEl = null, refreshBtn = null;
  let data = null, loading = false;
  let loadAgain = false;      // a reload asked for while one ran (a network change during Refresh)
  let renderedSig = null;     // netinfoSig() of the adapters on screen
  let mapEls = null, mapUnsub = null, netUnsub = null, lastMap = null;
  let renderedV6 = null;      // the show_ipv6 value the adapter cards were last drawn with
  let nc = null;              // the NAT, switch port & port forward card: made once per mount, every redraw re-appends its element
  let tp = null;              // the realtime throughput card: the same, and it holds its own half hour of samples

  /* ------------------------------------------------------------ IPv6 filter */
  // ui.show_ipv6 (Settings > Appearance, off by default): IPv6 subnet groups, addresses,
  // gateways and DNS servers are left out of the cards and never counted while it is off
  const isV6 = (s) => typeof s === 'string' && s.includes(':');
  function showIpv6(state) {
    const st = state || TNT.state;
    return !!(st && st.settings && st.settings.ui && st.settings.ui.show_ipv6);
  }
  /** Pure: the subnet groups of one adapter as they should be drawn (family-6 groups dropped, IPv6 entries stripped). */
  function visibleGroups(a, v6) {
    const groups = a && Array.isArray(a.subnets) ? a.subnets : [];
    const out = [];
    for (const g of groups) {
      if (!g) continue;
      if (!v6 && (g.family === 6 || isV6(g.network))) continue;
      const addresses = (g.addresses || []).filter((ip) => v6 || !isV6(ip));
      const gateways = (g.gateways || []).filter((ip) => v6 || !isV6(ip));
      out.push(Object.assign({}, g, { addresses, gateways }));
    }
    return out;
  }
  function visibleDns(a, v6) { return ((a && a.dns) || []).filter((d) => v6 || !isV6(d)); }
  function hiddenV6Count(a) {
    const groups = a && Array.isArray(a.subnets) ? a.subnets : [];
    return groups.filter((g) => g && (g.family === 6 || isV6(g.network))).length;
  }

  /* ------------------------------------------------------------- link map */
  // this PC -> gateway -> internet, fed by status.map (every status refresh) and the
  // per-second map.sample events from the service's always-on probes
  const STATE_COLOR = { up: 'green', degraded: 'yellow', down: 'red', unknown: 'grey' };
  const WAN_RECHECK_S = 120;  // after a network change the WAN chip says "checking…" until a newer lookup, at most this long
  function stateText(p) {
    if (!p) return '…';
    if (p.state === 'up') return TNT.util.fmtMs(p.last && p.last.rtt_ms) + ' ms';
    if (p.state === 'degraded') return p.last && !p.last.ok ? 'missed a reply' : (p.loss_pct != null ? p.loss_pct + '% loss' : 'flaky');
    if (p.state === 'down') return p.ip ? 'no reply' : (p.resolve_error || 'unreachable');
    return 'waiting…';
  }
  /** Pure: colour and text of a link bar -> { color, text }. A gateway probe with no address to ping is
   *  this PC having no default gateway (grey, said so), not a router that stopped answering. */
  function linkView(p, probe) {
    if (probe === 'gateway' && p && !p.ip && p.resolve_error && p.state !== 'up') return { color: 'grey', text: 'no default gateway' };
    return { color: STATE_COLOR[(p && p.state) || 'unknown'] || 'grey', text: stateText(p) };
  }

  function buildMapCard() {
    const { h } = TNT.util;
    // Every node is one fixed-height grid row: icon | name | the address chips, stacked, in a
    // column that starts at the same x on all three rows. Fixed heights keep the icons and the
    // link bars between them from shifting when the window (or the chip text) changes.
    const node = (icon, title) => {
      const chips = h('div', { class: 'lm-chips' });
      const el = h('div', { class: 'lm-node' },
        h('span', { class: 'lm-icon' }, TNT.ui.icon(icon)),
        h('div', { class: 'lm-name' }, title),
        chips);
      return { el, chips };
    };
    const link = (name) => {
      const line = h('span', { class: 'lm-line grey' });
      const txt = h('span', { class: 'lm-rtt muted' }, 'waiting…');
      return { el: h('div', { class: 'lm-link', title: name }, line, txt), line, txt };
    };
    const pc = node('computer', 'This PC');
    const gw = node('router', 'Gateway');
    const inet = node('cloud', 'Internet');
    const l1 = link('PC to gateway'), l2 = link('Gateway to internet');
    const body = h('div', { class: 'linkmap-body' }, pc.el, l1.el, gw.el, l2.el, inet.el);
    // the CC BY 4.0 credit for DB-IP, shown while the Internet node carries a looked-up ISP or location
    const attrib = h('div', { class: 'lm-attrib', hidden: true }, TNT.ui.geoAttribution ? TNT.ui.geoAttribution() : null);
    const card = h('div', { class: 'card linkmap' },
      h('div', { class: 'card-title' }, 'Live link map'),
      body,
      attrib);
    mapEls = { card, pc, gw, inet, l1, l2, attrib };
    return card;
  }

  /* One chip per line inside a node: an optional fixed-width tag ("LAN" / "WAN") then the
     value, so the addresses line up under each other. Rebuilt only when the values change:
     the map is repainted every second from map.sample events. A row's optional `sr` is a
     screen-reader sentence read after the value (the Internet node's ISP and Location). */
  function fillChips(el, rows) {
    const { h, copyCode } = TNT.util;
    const clean = (rows || []).filter((r) => r && r.value);
    const key = clean.map((r) => (r.tag || '') + ' ' + r.value + (r.sr ? ' ' + r.sr : '')).join('|');
    if (el.dataset.key !== key) {
      el.dataset.key = key;
      el.innerHTML = '';
      for (const r of clean) {
        const row = h('div', { class: 'lm-sub' + (r.cls ? ' ' + r.cls : '') });
        if (r.tag) row.appendChild(h('span', { class: 'lm-tag muted' }, r.tag));
        row.appendChild(r.plain ? h('span', { class: 'muted' }, r.value) : copyCode(r.value));
        if (r.sr) row.appendChild(h('span', { class: 'sr-only' }, r.sr));
        el.appendChild(row);
      }
    }
    // a title can change while the value does not (the WAN chip's "checked 3 min ago")
    clean.forEach((r, i) => { const row = el.children[i]; if (row && r.title && row.title !== r.title) row.title = r.title; });
  }

  /** Pure: what the WAN chip shows for map.public_ip -> { ip, title } | { error, title } | { checking, title }
   *  | null (nothing). Within WAN_RECHECK_S of a network change (`changedTs`, status.net.changed_ts) an
   *  answer from before that change is not presented as current: "checking…" until a lookup made after it
   *  has come back. That is `checked_ts` (every attempt, a failed one too; the service keeps the `ts` of the
   *  last address it found), else `ts`. */
  function wanChip(p, now, changedTs) {
    if (!p || typeof p !== 'object') p = null;
    const seen = p ? (p.checked_ts != null ? p.checked_ts : p.ts) : null;
    if (changedTs && now != null && now - changedTs < WAN_RECHECK_S && !(seen && seen >= changedTs)) {
      return { checking: true, title: 'Looking up the public address again after the network change' };
    }
    if (!p) return null;
    const { relTime, fmtDateTime } = TNT.util;
    if (p.ip) {
      const when = p.ts ? 'checked ' + relTime(p.ts, now) + ' (' + fmtDateTime(p.ts) + ')' : 'not checked yet';
      // behind double NAT or CGNAT the address the internet sees is not the router's own (the NAT card below says which)
      return { ip: String(p.ip), title: "This network's public address as the internet sees it (behind double NAT or CGNAT this is not the router's own address) · "
        + when + ' · refreshed every 10 min' };
    }
    if (p.error) return { error: String(p.error), title: 'Public address unknown: ' + p.error };
    return null;
  }
  /** Pure: the chip rows of the gateway node -> [{tag:'LAN'...}, {tag:'WAN'...}]. */
  function gatewayRows(map, now, changedTs) {
    const rows = [{ tag: 'LAN', value: (map.gateway && map.gateway.ip) || null }];
    const c = wanChip(map.public_ip, now, changedTs);
    if (c) rows.push({ tag: 'WAN', value: c.checking ? 'checking…' : (c.ip || c.error), plain: !c.ip, title: c.title, cls: 'lm-wan' });
    return rows;
  }

  /* IP location (status.geoip, map.public_geo): the Internet node's ISP and Location chips and the
     Settings › IP location status line. Lookups happen on the service, from DB-IP Lite data. */
  const MONTH_NAMES = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
  /** Pure: "2026-09" -> "September 2026"; anything else -> the input as text ('' for null). */
  function monthLabel(month) {
    const m = /^(\d{4})-(\d{2})$/.exec(String(month == null ? '' : month));
    const n = m ? Number(m[2]) : 0;
    if (!m || n < 1 || n > 12) return month == null ? '' : String(month);
    return MONTH_NAMES[n - 1] + ' ' + m[1];
  }

  /** Pure: a coarse, slowly changing "when is the next attempt" for status lines (a role="status" region must not
   *  re-announce every minute). '' when ts or now is not a number; d = ts - now:
   *  d <= 3600 -> 'within the hour'; d < 172800 -> 'in about ' + Math.ceil(d / 3600) + ' h';
   *  else 'on ' + UTC day of month + ' ' + English month name (e.g. 'on 1 October'). */
  function nextTryText(ts, now) {
    if (typeof ts !== 'number' || typeof now !== 'number' || !isFinite(ts) || !isFinite(now)) return '';
    const d = ts - now;
    if (d <= 3600) return 'within the hour';
    if (d < 172800) return 'in about ' + Math.ceil(d / 3600) + ' h';
    const day = new Date(ts * 1000);
    return 'on ' + day.getUTCDate() + ' ' + MONTH_NAMES[day.getUTCMonth()];
  }

  /** Pure: the Internet node's chip rows: the ISP and "City, ST" of this network's public address.
   *  geoip = status.geoip, map = status.map. Nothing (today's chip-less node) when IP location is off or missing,
   *  while the public address is unknown or being checked again after a network change, or when nothing is known. */
  function internetRows(map, now, changedTs, geoip) {
    const g = geoip && typeof geoip === 'object' ? geoip : null;
    if (!map || !g || !g.enabled) return [];
    const c = wanChip(map.public_ip, now, changedTs);
    if (!c || c.checking || !c.ip) return [];
    const geo = map.public_geo && typeof map.public_geo === 'object' ? map.public_geo : null;
    const vpn = ' (a VPN or proxy shows its own)';
    if (geo && geo.ip === c.ip && (geo.isp || geo.place)) {
      const rows = [];
      const as = geo.asn != null ? 'AS' + geo.asn + (geo.as_org ? ' ' + geo.as_org : '') : '';
      if (geo.isp) rows.push({ tag: 'ISP', value: geo.isp, plain: true, cls: 'lm-geo', data: true,
        title: (as ? as + ' · internet provider' : 'Internet provider') + ' of the public address' + vpn,
        sr: 'Internet provider of the public address: ' + geo.isp + (as ? ', ' + as : '') });
      if (geo.place) rows.push({ tag: 'Location', value: geo.place, plain: true, cls: 'lm-geo', data: true,
        title: (geo.place_full || geo.place) + ' · approximate location of the public address' + vpn,
        sr: 'Approximate location of the public address: ' + (geo.place_full || geo.place) });
      return rows;
    }
    if (!g.available && g.state === 'downloading') return [{ tag: 'Location', value: 'downloading data…', plain: true, cls: 'lm-geo',
      title: 'The service is downloading the IP location data (about 65 MB)' }];
    if (!g.available && g.state === 'error') return [{ tag: 'Location', value: 'unavailable', plain: true, cls: 'lm-geo',
      title: 'The IP location data could not be downloaded: see Settings › IP location' }];
    return [];
  }

  /** Pure: the Settings › IP location status line for status.geoip at time `now` (seconds). It only changes on a
   *  state change, a 10 % download step or an hour boundary, so its role="status" region stays quiet. */
  function geoStatusText(geoip, now) {
    const g = geoip;
    if (!g || typeof g !== 'object') return 'Not available on this service';
    if (!g.enabled) return 'Off: nothing is downloaded and no addresses are looked up';
    const next = nextTryText(g.next_check_ts, now);
    const N = next ? ' · next try ' + next : '';
    const dl = g.download && typeof g.download === 'object' ? g.download : {};
    if (g.state === 'downloading' && dl.phase === 'verify') return 'Checking the ' + monthLabel(dl.month) + ' data…';
    if (g.state === 'downloading') {
      const received = Number(dl.received) || 0, total = Number(dl.total) || 0;
      const pct = total > 0 ? Math.min(100, Math.floor(10 * received / total) * 10) + '%' : Math.floor(received / 10485760) * 10 + ' MB';
      return 'Downloading the ' + monthLabel(dl.month) + ' ' + (dl.file === 'asn' ? 'ISP' : 'city') + ' data… ' + pct;
    }
    if (g.available) return 'Installed: ' + monthLabel(g.month) + ' data' + (g.error ? ' · ' + g.error + N : '');
    if (g.state === 'error') return 'Download failed: ' + (g.error || 'unknown error') + N;
    return 'No data yet: the service downloads it shortly';
  }

  function updateMap(map) {
    if (!mapEls || !map) return;
    lastMap = map;
    const pc = map.pc || {};
    const net = TNT.state && TNT.state.status && TNT.state.status.net;
    fillChips(mapEls.pc.chips, [{ tag: 'Hostname', value: pc.hostname }, { tag: 'LAN', value: pc.ip }]);
    fillChips(mapEls.gw.chips, gatewayRows(map, TNT.state && TNT.state.now, net && net.changed_ts));
    // the internet node's chips are the ISP and the approximate location of the public address (IP location
    // data, gated like the WAN chip); the host being pinged is a setting, not a finding, so it stays on hover
    const inetRows = internetRows(map, TNT.state && TNT.state.now, net && net.changed_ts, TNT.state && TNT.state.status && TNT.state.status.geoip);
    fillChips(mapEls.inet.chips, inetRows);
    const showAttrib = inetRows.some((r) => r.data);
    if (mapEls.attrib && mapEls.attrib.hidden === showAttrib) mapEls.attrib.hidden = !showAttrib;
    const host = map.internet_host || (map.internet && map.internet.host);
    const ip = map.internet && map.internet.ip;
    const tip = host ? host + (ip ? ' (' + ip + ')' : '') : '';
    if (tip && mapEls.inet.el.title !== tip) mapEls.inet.el.title = tip;
    const paint = (l, p, probe) => {
      const v = linkView(p, probe);
      const cls = 'lm-line ' + v.color;
      if (l.line.className !== cls) l.line.className = cls;
      if (l.txt.textContent !== v.text) l.txt.textContent = v.text;
      l.txt.className = 'lm-rtt ' + (v.color === 'green' || v.color === 'grey' ? 'muted' : 'strong ' + v.color);
    };
    paint(mapEls.l1, map.gateway, 'gateway');
    paint(mapEls.l2, map.internet, 'internet');
  }

  function onMapSample(d) {
    if (!lastMap || !d || !d.probe) return;
    const p = lastMap[d.probe];
    if (!p) return;
    p.state = d.state || p.state;
    if ('ip' in d) p.ip = d.ip;          // a sample without an address (no gateway any more) clears the old one
    p.last = { ts: d.ts, ok: d.ok, rtt_ms: d.rtt_ms };
    updateMap(lastMap);
  }

  /* net.changed: both link bars straddle two networks until the service's first samples on the new one
     arrive ("waiting…"), and the gateway chip shows the new default gateway, or none, straight away */
  function onNetChanged(d) {
    if (!lastMap || !d || !(d.gateway_changed || d.internet_nic_changed)) return;
    const gw = d.default_gateway || null;
    const reset = { state: 'unknown', last: null, loss_pct: null };
    lastMap.gateway = Object.assign({}, lastMap.gateway || {}, reset, { ip: gw, resolve_error: gw ? null : 'no default gateway' });
    lastMap.internet = Object.assign({}, lastMap.internet || {}, reset);
    updateMap(lastMap);
  }

  function fmtSpeed(bps) {
    if (bps == null || !isFinite(bps) || bps <= 0) return null;
    if (bps >= 1e9) return (bps / 1e9 % 1 === 0 ? bps / 1e9 : (bps / 1e9).toFixed(1)) + ' Gbps';
    if (bps >= 1e6) return Math.round(bps / 1e6) + ' Mbps';
    return Math.round(bps / 1e3) + ' kbps';
  }

  function statusBadge(status) {
    const { h } = TNT.util;
    const s = String(status || 'unknown');
    const color = s === 'up' ? 'green' : (s === 'down' || s === 'not_present') ? 'grey' : 'yellow';
    return h('span', { class: 'badge ' + color }, s.replace(/_/g, ' '));
  }

  /* Adapter warnings (netinfo adapters[].warnings, worked out by the service from the live state): a short
     badge in the card head and the plain-language message in a callout under it. */
  const WARNINGS = {
    apipa: ['yellow', 'self-assigned IP'],       // no DHCP server answered (DHCP itself is on)
    duplicate_address: ['red', 'duplicate IP'],
    gateway_outside_subnet: ['red', 'gateway off subnet'],
    no_dns: ['yellow', 'no DNS'],
    multiple_default_gateways: ['grey', 'multiple gateways'],   // two or more up adapters have one
  };
  const WARNING_RANK = { red: 0, yellow: 1, grey: 2 };
  /** Pure: one warning -> { code, cls, label, message }; an unknown code is a yellow badge named after it. */
  function warningView(w) {
    if (!w || typeof w !== 'object' || !w.code) return null;
    const code = String(w.code);
    const known = WARNINGS[code];
    const label = known ? known[1] : code.replace(/_/g, ' ');
    return { code, cls: known ? known[0] : 'yellow', label, message: String(w.message || label) };
  }
  /** Pure: an adapter's warnings as drawn, the most serious first (red, yellow, then the informational grey). */
  function adapterWarnings(a) {
    return (a && Array.isArray(a.warnings) ? a.warnings : []).map(warningView).filter(Boolean)
      .sort((x, y) => WARNING_RANK[x.cls] - WARNING_RANK[y.cls]);
  }

  function adapterCard(a, internetIndex, v6) {
    const { h, copyCode } = TNT.util;
    const isInternet = a.index === internetIndex;
    const dns = visibleDns(a, v6);
    const warnings = adapterWarnings(a);
    const head = h('div', { class: 'adapter-head' },
      h('span', { class: 'name' }, a.name || ('Adapter ' + a.index)),
      isInternet ? h('span', { class: 'badge blue' }, 'internet') : null,
      statusBadge(a.status),
      warnings.map((w) => h('span', { class: 'badge ' + w.cls, title: w.message }, w.label)),
      a.type_name ? h('span', { class: 'badge grey' }, a.type_name) : null,
      a.is_physical === false && !a.is_loopback ? h('span', { class: 'badge grey' }, 'virtual') : null,
    );
    const kv = h('div', { class: 'kv' });
    const row = (k, v) => { kv.appendChild(h('span', { class: 'k' }, k)); kv.appendChild(h('span', { class: 'v' }, v)); };
    row('MAC', a.mac ? copyCode(a.mac) : h('span', { class: 'muted' }, '—'));
    const speed = fmtSpeed(a.speed_bps);
    row('Link', h('span', null, (speed || 'speed unknown') + (a.mtu ? ' · MTU ' + a.mtu : '')));
    row('DHCP', a.dhcp_enabled ? (a.dhcp_server ? h('span', { class: 'row', style: { gap: '6px' } }, 'on · server ', copyCode(a.dhcp_server)) : h('span', null, 'on')) : h('span', null, 'off (static)'));
    if (a.dns_suffix) row('Suffix', copyCode(a.dns_suffix));
    if (dns.length) row('DNS', h('span', { class: 'v' }, dns.map((d) => copyCode(d))));
    if (a.metric_v4 != null) row('Metric', h('span', null, String(a.metric_v4)));

    const subnets = h('div', { class: 'stack', style: { gap: '10px' } });
    const groups = visibleGroups(a, v6);
    if (groups.length) {
      for (const g of groups) {
        const title = h('div', { class: 'subnet-title' },
          h('span', { class: 'badge ' + (g.family === 6 ? 'purple' : 'blue') }, g.family === 6 ? 'IPv6' : 'IPv4'),
          g.network ? copyCode(g.network) : h('span', { class: 'muted' }, 'no subnet'));
        const skv = h('div', { class: 'kv' });
        const srow = (k, v) => { skv.appendChild(h('span', { class: 'k' }, k)); skv.appendChild(h('span', { class: 'v' }, v)); };
        srow(g.addresses.length > 1 ? 'Addresses' : 'Address', g.addresses.length ? g.addresses.map((ip) => copyCode(ip)) : h('span', { class: 'muted' }, '—'));
        if (g.mask) srow('Mask', copyCode(g.mask));
        if (g.gateways.length) srow('Gateway', g.gateways.map((gw) => copyCode(gw)));
        subnets.appendChild(h('div', { class: 'panel subnet' }, title, skv));
      }
    } else {
      const hiddenV6 = v6 ? 0 : hiddenV6Count(a);
      subnets.appendChild(h('div', { class: 'panel muted small' }, hiddenV6
        ? 'No IPv4 address on this adapter (' + hiddenV6 + ' IPv6 subnet' + (hiddenV6 === 1 ? '' : 's') + ' hidden — turn on IPv6 in Settings).'
        : 'No IP addresses on this adapter.'));
    }
    return h('div', { class: 'card adapter' + (isInternet ? ' internet' : '') },
      head,
      a.description && a.description !== a.name ? h('div', { class: 'adapter-desc' }, a.description) : null,
      warnings.length ? h('div', { class: 'adapter-warnings' }, warnings.map((w) => h('div', { class: 'adapter-warn ' + w.cls, data: { code: w.code } },
        TNT.ui.icon(w.cls === 'grey' ? 'info' : 'warning'), h('span', null, w.message)))) : null,
      kv,
      subnets);
  }

  /** Pure: what decides whether a fresh /api/netinfo needs the cards redrawn: all of it but the timestamp. */
  function netinfoSig(n) { return JSON.stringify(Object.assign({}, n || {}, { ts: null })); }

  function renderSummary(count) {
    const { h, copyCode, fmtDateTime } = TNT.util;
    summaryEl.innerHTML = '';
    summaryEl.appendChild(h('span', { class: 'muted' }, count + (count === 1 ? ' adapter' : ' adapters')));
    if (data.default_gateway) summaryEl.appendChild(h('span', { class: 'row', style: { gap: '6px' } }, h('span', { class: 'muted' }, 'Default gateway'), copyCode(data.default_gateway)));
    if (data.ts) summaryEl.appendChild(h('span', { class: 'muted small' }, 'as of ' + fmtDateTime(data.ts)));
    if (!renderedV6) summaryEl.appendChild(h('span', { class: 'muted small', title: 'IPv6 addresses are hidden — turn them on under Settings > Appearance' }, 'IPv6 hidden'));
  }

  function render() {
    if (!root) return;
    const { h } = TNT.util;
    gridEl.innerHTML = '';
    summaryEl.innerHTML = '';
    if (!data) {
      renderedSig = null;
      gridEl.appendChild(buildMapCard());
      const st0 = TNT.app && TNT.app.state && TNT.app.state.status;
      if (st0 && st0.map) updateMap(st0.map);
      // the live cards come first here too: they have their own data and are worth drawing while
      // the adapter list loads, rather than appearing a moment later and pushing the page down
      if (tp) gridEl.appendChild(tp.el);
      if (nc) gridEl.appendChild(nc.el);
      gridEl.appendChild(h('div', { class: 'card' }, TNT.ui.emptyState('Loading adapters…')));
      return;
    }
    renderedSig = netinfoSig(data);
    const adapters = Array.isArray(data.adapters) ? data.adapters.slice() : [];
    const inet = data.internet_nic_index;
    adapters.sort((a, b) => {
      const ai = a.index === inet ? 0 : 1, bi = b.index === inet ? 0 : 1;
      if (ai !== bi) return ai - bi;
      const au = a.status === 'up' ? 0 : 1, bu = b.status === 'up' ? 0 : 1;
      if (au !== bu) return au - bu;
      const ap = a.is_physical ? 0 : 1, bp = b.is_physical ? 0 : 1;
      return ap - bp;
    });
    const v6 = showIpv6();
    renderedV6 = v6;
    renderSummary(adapters.length);
    // the link map is always the first card, throughput the second and the NAT, switch port & port
    // forward card the third; the adapters follow
    gridEl.appendChild(buildMapCard());
    const st = TNT.app && TNT.app.state && TNT.app.state.status;
    if (st && st.map) updateMap(st.map); else if (lastMap) updateMap(lastMap);
    if (tp) gridEl.appendChild(tp.el);
    if (nc) gridEl.appendChild(nc.el);
    if (!adapters.length) { gridEl.appendChild(h('div', { class: 'card' }, TNT.ui.emptyState('No network adapters found.'))); return; }
    for (const a of adapters) gridEl.appendChild(adapterCard(a, inet, v6));
  }

  /* Adapters are read on mount, on Refresh and when this PC changes networks. A quiet reload (the network
     change) keeps the cards on screen while it runs and redraws them only when the answer differs apart
     from its timestamp, so the scroll position and a text selection survive it; a reload asked for while
     one runs follows it. */
  async function load(quiet) {
    if (loading) { loadAgain = true; return; }
    loading = true;
    if (!quiet) TNT.ui.busy(refreshBtn, true);
    try {
      const next = await TNT.api.netinfo();
      if (!root) return;
      data = next;
      if (netinfoSig(next) !== renderedSig || showIpv6() !== renderedV6) render();
      else renderSummary((Array.isArray(next.adapters) ? next.adapters : []).length);
    } catch (err) {
      // a failed quiet reload keeps what is on screen
      if (root && (!quiet || !data)) {
        renderedSig = null;
        gridEl.innerHTML = '';
        // the two live cards stay: the adapter list failing says nothing about the counters the
        // throughput card reads, or about a NAT result and a switch-port listen already in hand
        if (tp) gridEl.appendChild(tp.el);
        if (nc) gridEl.appendChild(nc.el);
        gridEl.appendChild(TNT.util.h('div', { class: 'card' }, TNT.ui.emptyState('Could not load adapters: ' + err.message)));
      }
    } finally {
      loading = false;
      if (refreshBtn) TNT.ui.busy(refreshBtn, false);
      if (loadAgain && root) { loadAgain = false; load(true); }
    }
  }

  TNT.views.ipinfo = {
    mount(el) {
      const { h } = TNT.util;
      root = el;
      refreshBtn = h('button', { class: 'btn btn-sm', type: 'button', on: { click: () => load(false) } }, TNT.ui.icon('refresh'), 'Refresh');
      summaryEl = h('div', { class: 'row', style: { gap: '14px' } });
      const head = h('div', { class: 'section-head' },
        h('h2', null, h('span', { class: 'section-accent' }), 'Network info'),
        h('div', { class: 'actions' }, summaryEl, refreshBtn));
      gridEl = h('div', { class: 'adapter-grid' });
      root.appendChild(head);
      root.appendChild(gridEl);
      data = null; renderedSig = null; loadAgain = false;
      // both live cards exist before the first render, which is what puts them right after the link map
      try { tp = TNT.throughput.create(); } catch (e) { console.error('throughput card failed', e); tp = null; }
      try { nc = TNT.netcheck.create(); } catch (e) { console.error('netcheck card failed', e); nc = null; }
      render();
      load();
      mapUnsub = TNT.api.events.on('map.sample', onMapSample);
      netUnsub = TNT.api.events.on('net.changed', onNetChanged);
    },
    update(state) {
      if (!root) return;
      // the IPv6 switch was flipped (saveSettings notifies the view): redraw the cached adapters, no refetch
      if (data && renderedV6 !== null && showIpv6(state) !== renderedV6) render();
      // adapters are read on demand and on a network change; the link map follows every status snapshot
      if (state && state.status && state.status.map) updateMap(state.status.map);
      // the NAT card follows status.net.generation (a new network clears its results) and the link map's public address
      if (nc) nc.update(state);
      if (tp) tp.update(state);
    },
    // this PC changed networks (app.js calls it once a burst of changes settles): read the adapters again
    netChanged() { if (root) load(true); },
    unmount() {
      if (tp) { try { tp.unmount(); } catch (e) { /* ignore */ } tp = null; }
      if (nc) { try { nc.unmount(); } catch (e) { /* ignore */ } nc = null; }
      if (mapUnsub) { try { mapUnsub(); } catch (e) { /* ignore */ } mapUnsub = null; }
      if (netUnsub) { try { netUnsub(); } catch (e) { /* ignore */ } netUnsub = null; }
      root = null; gridEl = null; summaryEl = null; refreshBtn = null; data = null; mapEls = null; renderedV6 = null; renderedSig = null; loadAgain = false;
    },
    // exposed for tests
    visibleGroups,
    visibleDns,
    wanChip,
    gatewayRows,
    monthLabel,
    nextTryText,
    internetRows,
    geoStatusText,
    linkView,
    warningView,
    adapterWarnings,
    netinfoSig,
  };
})();
