/* TNT — views/ipinfo.js
   One card per adapter (internet-facing first), grouped subnets, copy-on-click values. */
(function () {
  'use strict';
  const TNT = window.TNT;
  TNT.views = TNT.views || {};

  let root = null, gridEl = null, summaryEl = null, refreshBtn = null;
  let data = null, loading = false;
  let mapEls = null, mapUnsub = null, lastMap = null;
  let renderedV6 = null;      // the show_ipv6 value the adapter cards were last drawn with

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
  function stateText(p) {
    if (!p) return '…';
    if (p.state === 'up') return TNT.util.fmtMs(p.last && p.last.rtt_ms) + ' ms';
    if (p.state === 'degraded') return p.last && !p.last.ok ? 'missed a reply' : (p.loss_pct != null ? p.loss_pct + '% loss' : 'flaky');
    if (p.state === 'down') return p.ip ? 'no reply' : (p.resolve_error || 'unreachable');
    return 'waiting…';
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
    const card = h('div', { class: 'card linkmap' },
      h('div', { class: 'card-title' }, 'Live link map'),
      body);
    mapEls = { card, pc, gw, inet, l1, l2 };
    return card;
  }

  /* One chip per line inside a node: an optional fixed-width tag ("LAN" / "WAN") then the
     value, so the addresses line up under each other. Rebuilt only when the values change:
     the map is repainted every second from map.sample events. */
  function fillChips(el, rows) {
    const { h, copyCode } = TNT.util;
    const clean = (rows || []).filter((r) => r && r.value);
    const key = clean.map((r) => (r.tag || '') + ' ' + r.value).join('|');
    if (el.dataset.key !== key) {
      el.dataset.key = key;
      el.innerHTML = '';
      for (const r of clean) {
        const row = h('div', { class: 'lm-sub' + (r.cls ? ' ' + r.cls : '') });
        if (r.tag) row.appendChild(h('span', { class: 'lm-tag muted' }, r.tag));
        row.appendChild(r.plain ? h('span', { class: 'muted' }, r.value) : copyCode(r.value));
        el.appendChild(row);
      }
    }
    // a title can change while the value does not (the WAN chip's "checked 3 min ago")
    clean.forEach((r, i) => { const row = el.children[i]; if (row && r.title && row.title !== r.title) row.title = r.title; });
  }

  /** Pure: what the WAN chip shows for map.public_ip -> { ip, title } | { error, title } | null (nothing). */
  function wanChip(p, now) {
    if (!p || typeof p !== 'object') return null;
    const { relTime, fmtDateTime } = TNT.util;
    if (p.ip) {
      const when = p.ts ? 'checked ' + relTime(p.ts, now) + ' (' + fmtDateTime(p.ts) + ')' : 'not checked yet';
      return { ip: String(p.ip), title: "The router's public address as seen from the internet · " + when + ' · refreshed every 10 min' };
    }
    if (p.error) return { error: String(p.error), title: 'Public address unknown: ' + p.error };
    return null;
  }
  /** Pure: the chip rows of the gateway node -> [{tag:'LAN'...}, {tag:'WAN'...}]. */
  function gatewayRows(map, now) {
    const rows = [{ tag: 'LAN', value: (map.gateway && map.gateway.ip) || null }];
    const c = wanChip(map.public_ip, now);
    if (c) rows.push({ tag: 'WAN', value: c.ip || c.error, plain: !c.ip, title: c.title, cls: 'lm-wan' });
    return rows;
  }

  function updateMap(map) {
    if (!mapEls || !map) return;
    lastMap = map;
    const pc = map.pc || {};
    fillChips(mapEls.pc.chips, [{ tag: 'Hostname', value: pc.hostname }, { tag: 'LAN', value: pc.ip }]);
    fillChips(mapEls.gw.chips, gatewayRows(map, TNT.state && TNT.state.now));
    // the internet node carries no chips: the host being pinged is a setting, not a finding.
    // It stays available on hover so the map keeps its meaning without the clutter.
    const host = map.internet_host || (map.internet && map.internet.host);
    const ip = map.internet && map.internet.ip;
    const tip = host ? host + (ip ? ' (' + ip + ')' : '') : '';
    if (tip && mapEls.inet.el.title !== tip) mapEls.inet.el.title = tip;
    const paint = (l, p) => {
      const color = STATE_COLOR[(p && p.state) || 'unknown'] || 'grey';
      const cls = 'lm-line ' + color;
      if (l.line.className !== cls) l.line.className = cls;
      const txt = stateText(p);
      if (l.txt.textContent !== txt) l.txt.textContent = txt;
      l.txt.className = 'lm-rtt ' + (color === 'green' ? 'muted' : color === 'grey' ? 'muted' : 'strong ' + color);
    };
    paint(mapEls.l1, map.gateway);
    paint(mapEls.l2, map.internet);
  }

  function onMapSample(d) {
    if (!lastMap || !d || !d.probe) return;
    const p = lastMap[d.probe];
    if (!p) return;
    p.state = d.state || p.state;
    p.ip = d.ip || p.ip;
    p.last = { ts: d.ts, ok: d.ok, rtt_ms: d.rtt_ms };
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

  function adapterCard(a, internetIndex, v6) {
    const { h, copyCode } = TNT.util;
    const isInternet = a.index === internetIndex;
    const dns = visibleDns(a, v6);
    const head = h('div', { class: 'adapter-head' },
      h('span', { class: 'name' }, a.name || ('Adapter ' + a.index)),
      isInternet ? h('span', { class: 'badge blue' }, 'internet') : null,
      statusBadge(a.status),
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
      kv,
      subnets);
  }

  function render() {
    if (!root) return;
    const { h, copyCode, fmtDateTime } = TNT.util;
    gridEl.innerHTML = '';
    summaryEl.innerHTML = '';
    if (!data) {
      gridEl.appendChild(buildMapCard());
      const st0 = TNT.app && TNT.app.state && TNT.app.state.status;
      if (st0 && st0.map) updateMap(st0.map);
      gridEl.appendChild(h('div', { class: 'card' }, TNT.ui.emptyState('Loading adapters…')));
      return;
    }
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
    summaryEl.appendChild(h('span', { class: 'muted' }, adapters.length + (adapters.length === 1 ? ' adapter' : ' adapters')));
    if (data.default_gateway) summaryEl.appendChild(h('span', { class: 'row', style: { gap: '6px' } }, h('span', { class: 'muted' }, 'Default gateway'), copyCode(data.default_gateway)));
    if (data.ts) summaryEl.appendChild(h('span', { class: 'muted small' }, 'as of ' + fmtDateTime(data.ts)));
    const v6 = showIpv6();
    renderedV6 = v6;
    if (!v6) summaryEl.appendChild(h('span', { class: 'muted small', title: 'IPv6 addresses are hidden — turn them on under Settings > Appearance' }, 'IPv6 hidden'));
    // the live link map is always the first card; the adapters follow
    gridEl.appendChild(buildMapCard());
    const st = TNT.app && TNT.app.state && TNT.app.state.status;
    if (st && st.map) updateMap(st.map); else if (lastMap) updateMap(lastMap);
    if (!adapters.length) { gridEl.appendChild(h('div', { class: 'card' }, TNT.ui.emptyState('No network adapters found.'))); return; }
    for (const a of adapters) gridEl.appendChild(adapterCard(a, inet, v6));
  }

  async function load() {
    if (loading) return;
    loading = true;
    TNT.ui.busy(refreshBtn, true);
    try {
      data = await TNT.api.netinfo();
      render();
    } catch (err) {
      if (root) { gridEl.innerHTML = ''; gridEl.appendChild(TNT.util.h('div', { class: 'card' }, TNT.ui.emptyState('Could not load adapters: ' + err.message))); }
    } finally { loading = false; TNT.ui.busy(refreshBtn, false); }
  }

  TNT.views.ipinfo = {
    mount(el) {
      const { h } = TNT.util;
      root = el;
      refreshBtn = h('button', { class: 'btn btn-sm', type: 'button', on: { click: load } }, TNT.ui.icon('refresh'), 'Refresh');
      summaryEl = h('div', { class: 'row', style: { gap: '14px' } });
      const head = h('div', { class: 'section-head' },
        h('h2', null, h('span', { class: 'section-accent' }), 'Network info'),
        h('div', { class: 'actions' }, summaryEl, refreshBtn));
      gridEl = h('div', { class: 'adapter-grid' });
      root.appendChild(head);
      root.appendChild(gridEl);
      data = null;
      render();
      load();
      mapUnsub = TNT.api.events.on('map.sample', onMapSample);
    },
    update(state) {
      if (!root) return;
      // the IPv6 switch was flipped (saveSettings notifies the view): redraw the cached adapters, no refetch
      if (data && renderedV6 !== null && showIpv6(state) !== renderedV6) render();
      // adapters are fetched on demand; the link map follows every status snapshot
      if (state && state.status && state.status.map) updateMap(state.status.map);
    },
    unmount() {
      if (mapUnsub) { try { mapUnsub(); } catch (e) { /* ignore */ } mapUnsub = null; }
      root = null; gridEl = null; summaryEl = null; refreshBtn = null; data = null; mapEls = null; renderedV6 = null;
    },
    // exposed for tests
    visibleGroups,
    visibleDns,
    wanChip,
    gatewayRows,
  };
})();
