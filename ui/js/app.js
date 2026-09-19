/* TNT — app.js
   Owns application state, hash routing, the top tiles and their shortcut strip, the header status pill,
   the Settings modal, the Diagnostics panel, toasts, the confirm modal and the SSE wiring,
   including following this PC onto another network (net.changed / status.net.generation).
   Also provides the shared helpers views use at runtime: TNT.util, TNT.ui, TNT.icons. */
(function () {
  'use strict';
  const TNT = window.TNT;
  const api = TNT.api;

  /* ================================================================ icons */
  const S = 'class="icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"';
  const ICONS = {
    network: '<svg ' + S + '><rect x="3" y="5" width="18" height="11" rx="3"/><path d="M8 16v3.2h8V16"/><path d="M7 10.5h2.6M14.4 10.5H17"/></svg>',
    ping: '<svg ' + S + '><circle cx="12" cy="12" r="2.2" fill="currentColor" stroke="none"/><path d="M7 7.2a7 7 0 0 0 0 9.6"/><path d="M17 7.2a7 7 0 0 1 .2 9.6"/><path d="M3.8 3.8a11.5 11.5 0 0 0 0 16.4"/><path d="M20.2 3.8a11.5 11.5 0 0 1 .2 16.4"/></svg>',
    outage: '<svg ' + S + '><path d="M13.5 2.8 6 13.2h5.2l-1.2 8 7.6-10.8h-5.3l1.2-7.6z"/></svg>',
    speed: '<svg ' + S + '><path d="M4 16.8a8.4 8.4 0 1 1 16 0"/><path d="M12 16.8l3.6-6.4"/><circle cx="12" cy="16.8" r="1.7" fill="currentColor" stroke="none"/><path d="M4.4 16.8h1.6M18 16.8h1.6"/></svg>',
    discovery: '<svg ' + S + '><circle cx="10.5" cy="10.5" r="6.6"/><path d="M15.6 15.6 21 21"/><circle cx="8.6" cy="9.2" r="1.1" fill="currentColor" stroke="none"/><circle cx="12.6" cy="8.4" r="1.1" fill="currentColor" stroke="none"/><circle cx="10.6" cy="12.6" r="1.1" fill="currentColor" stroke="none"/></svg>',
    // a cog (8 teeth + hub), not a sun
    gear: '<svg ' + S + '><path d="M21.8 10.4 L21.8 13.6 L19.3 13.66 L18.35 15.94 L20.07 17.75 L17.75 20.07 L15.94 18.35 L13.66 19.3 L13.6 21.8 L10.4 21.8 L10.34 19.3 L8.06 18.35 L6.25 20.07 L3.93 17.75 L5.65 15.94 L4.7 13.66 L2.2 13.6 L2.2 10.4 L4.7 10.34 L5.65 8.06 L3.93 6.25 L6.25 3.93 L8.06 5.65 L10.34 4.7 L10.4 2.2 L13.6 2.2 L13.66 4.7 L15.94 5.65 L17.75 3.93 L20.07 6.25 L18.35 8.06 L19.3 10.34 Z" stroke-linejoin="round"/><circle cx="12" cy="12" r="3.3"/></svg>',
    close: '<svg ' + S + '><path d="M6.2 6.2l11.6 11.6M17.8 6.2 6.2 17.8"/></svg>',
    plus: '<svg ' + S + '><path d="M12 5v14M5 12h14"/></svg>',
    trash: '<svg ' + S + '><path d="M4 7h16M9.5 7V4.6h5V7M6.6 7l.8 12.6h9.2L17.4 7M10 11v5.2M14 11v5.2"/></svg>',
    refresh: '<svg ' + S + '><path d="M20 12a8 8 0 1 1-2.7-6"/><path d="M20 3.6V9h-5.4"/></svg>',
    download: '<svg ' + S + '><path d="M12 3.6v11M7.6 10.6 12 15l4.4-4.4"/><path d="M4.6 17.4v2A1.6 1.6 0 0 0 6.2 21h11.6a1.6 1.6 0 0 0 1.6-1.6v-2"/></svg>',
    copy: '<svg ' + S + '><rect x="9" y="9" width="11" height="11" rx="2.6"/><path d="M15 9V5.6A1.6 1.6 0 0 0 13.4 4H5.6A1.6 1.6 0 0 0 4 5.6v7.8A1.6 1.6 0 0 0 5.6 15H9"/></svg>',
    spark: '<svg ' + S + '><path d="M12 2.4c.7 4.7 3 7 9.6 9.6-6.6 2.6-8.9 4.9-9.6 9.6-.7-4.7-3-7-9.6-9.6 6.6-2.6 8.9-4.9 9.6-9.6z"/></svg>',
    pause: '<svg ' + S + '><path d="M8.2 5.5v13M15.8 5.5v13"/></svg>',
    play: '<svg ' + S + '><path d="M8 5.4v13.2l10.4-6.6z"/></svg>',
    check: '<svg ' + S + '><path d="M5 12.6l4.4 4.4L19 7.4"/></svg>',
    back: '<svg ' + S + '><path d="M19 12H5.6M11.2 5.4 4.8 12l6.4 6.6"/></svg>',
    stop: '<svg ' + S + '><rect x="6" y="6" width="12" height="12" rx="3"/></svg>',
    computer: '<svg ' + S + '><rect x="3" y="4.5" width="18" height="12" rx="2.6"/><path d="M9 20h6M12 16.5V20"/><path d="M6.5 8.5h6"/></svg>',
    router: '<svg ' + S + '><rect x="3" y="12" width="18" height="7.5" rx="2.6"/><path d="M7 15.8h.01M10.5 15.8h.01M14 15.8h.01"/><path d="M7.5 12V7.2M16.5 12V5"/><circle cx="7.5" cy="6" r="1.2" fill="currentColor" stroke="none"/><circle cx="16.5" cy="4" r="1.2" fill="currentColor" stroke="none"/></svg>',
    cloud: '<svg ' + S + '><path d="M7.2 18.5h9.6a4 4 0 0 0 .6-7.95A5.5 5.5 0 0 0 6.9 9.4 4.6 4.6 0 0 0 7.2 18.5z"/></svg>',
    grip: '<svg ' + S + ' style="fill:currentColor;stroke:none"><circle cx="9" cy="6" r="2"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="15" cy="12" r="2"/><circle cx="9" cy="18" r="2"/><circle cx="15" cy="18" r="2"/></svg>',
    search: '<svg ' + S + '><circle cx="10.5" cy="10.5" r="6.6"/><path d="M15.6 15.6 21 21"/></svg>',
    info: '<svg ' + S + '><circle cx="12" cy="12" r="9"/><path d="M12 11v5.4M12 7.6v.4"/></svg>',
    edit: '<svg ' + S + '><path d="M4 20l1-4L15.5 5.5l3 3L8 19l-4 1z"/><path d="M13.5 7.5l3 3"/></svg>',
    expand: '<svg ' + S + '><path d="M9 4H4v5"/><path d="M15 20h5v-5"/><path d="M4.4 4.4l6 6"/><path d="M19.6 19.6l-6-6"/></svg>',
    // a chunky open-end wrench, head top-right, handle to the bottom-left
    tools: '<svg ' + S + '><path d="M14.2 3.6a5.2 5.2 0 0 1 6.2 6.2l-1.9-1.9-2.5.7-.7 2.5 1.9 1.9a5.2 5.2 0 0 1-6.2-6.2L4.4 13.4a2.4 2.4 0 0 0 3.4 3.4l6.4-6.6" stroke-linejoin="round"/><path d="M6 17.6h.01"/></svg>',
    // a router-ish box handing out addresses: the DHCP badge in the Tools view
    dhcp: '<svg ' + S + '><rect x="3" y="9" width="18" height="9" rx="2.6"/><path d="M7 13.5h.01M10.5 13.5h.01"/><path d="M12 9V5.2M8.4 5.2h7.2"/><path d="M16.5 13.5h1.5"/></svg>',
    // warning triangle for the danger modal
    warning: '<svg ' + S + '><path d="M12 3.6 21.2 19.4H2.8z" stroke-linejoin="round"/><path d="M12 9.4v4.6M12 16.8v.4"/></svg>',
    // a small switch with three cables hanging off it: LAN peers and private traceroute hops
    lan: '<svg ' + S + '><rect x="3" y="3.6" width="18" height="6.6" rx="2.2"/><path d="M7 6.9h.01M10.4 6.9h.01"/><path d="M6.5 10.2v4.6M12 10.2v4.6M17.5 10.2v4.6"/><circle cx="6.5" cy="17.4" r="2.1"/><circle cx="12" cy="17.4" r="2.1"/><circle cx="17.5" cy="17.4" r="2.1"/></svg>',
    // three broadcast arcs over a dot: the WiFi tile and the saved Wi-Fi networks card
    wifi: '<svg ' + S + '><path d="M2.4 8.4a14 14 0 0 1 19.2 0"/><path d="M5.6 11.9a9.4 9.4 0 0 1 12.8 0"/><path d="M8.8 15.4a4.8 4.8 0 0 1 6.4 0"/><circle cx="12" cy="19.1" r="1.3" fill="currentColor" stroke="none"/></svg>',
    // two overlapping channel shapes standing on a baseline: the WiFi page's spectrum charts
    activity: '<svg ' + S + '><path d="M2.6 13.4h4L9 7.2l3.4 10 2.6-5.2h6.4"/></svg>',
    spectrum: '<svg ' + S + '><path d="M2.6 20.2h18.8"/><path d="M4 20.2 6.6 7.4h4.6l2.6 12.8"/><path d="M11.2 20.2 13.6 12.6h4.2l2.4 7.6"/></svg>',
    // crosshair target: the last hop of a traceroute
    target: '<svg ' + S + '><circle cx="12" cy="12" r="8.4"/><circle cx="12" cy="12" r="3.8"/><circle cx="12" cy="12" r="1.1" fill="currentColor" stroke="none"/><path d="M12 2.4v2.6M12 19v2.6M2.4 12H5M19 12h2.6"/></svg>',
    // question mark in a ring: a hop that never answered
    question: '<svg ' + S + '><circle cx="12" cy="12" r="9"/><path d="M9.2 9.5a2.8 2.8 0 1 1 4 2.5c-.9.5-1.2 1.1-1.2 2"/><path d="M12 17v.4"/></svg>',
    // a winding route between two dots: the Traceroute card / Run button
    route: '<svg ' + S + '><circle cx="5" cy="18" r="2.2"/><circle cx="19" cy="5" r="2.2"/><path d="M7.2 18H13.5a3.5 3.5 0 0 0 0-7h-3a3 3 0 0 1 0-6h6.3"/></svg>',
    // a clipboard with three bars: the Reports tile and the Full Scan button
    report: '<svg ' + S + '><path d="M9 3.6h6v2.8H9z" stroke-linejoin="round"/><path d="M9 5H6.6A1.6 1.6 0 0 0 5 6.6v12.8A1.6 1.6 0 0 0 6.6 21h10.8a1.6 1.6 0 0 0 1.6-1.6V6.6A1.6 1.6 0 0 0 17.4 5H15"/><path d="M8.6 16.6v-2.4M12 16.6v-5M15.4 16.6v-3.4"/></svg>',
    // two opposite arrows: swap the two reports of a comparison
    swap: '<svg ' + S + '><path d="M4 8.2h14.6M15 4.6l3.6 3.6-3.6 3.6"/><path d="M20 15.8H5.4M9 12.2l-3.6 3.6L9 19.4"/></svg>',
    // a globe with a meridian and the equator: the DNS card (names on the internet)
    dns: '<svg ' + S + '><circle cx="12" cy="12" r="8.8"/><path d="M3.2 12h17.6"/><path d="M12 3.2c2.5 2.4 3.7 5.3 3.7 8.8s-1.2 6.4-3.7 8.8c-2.5-2.4-3.7-5.3-3.7-8.8s1.2-6.4 3.7-8.8z"/></svg>',
    // a broom with two specks of dust: Flush DNS in the top bar
    flush: '<svg ' + S + '><path d="M20 3.2l-7.4 7.4"/><path d="M10.5 9.3l3.4 3.4-3.7 6.2-5.9-5.9z" stroke-linejoin="round"/><path d="M8.3 10.6l4.3 4.3"/><path d="M3.2 17.4h.01M6.2 20.4h.01"/></svg>',
    // two arrows chasing each other round: IP Release/Renew in the top bar
    renew: '<svg ' + S + '><path d="M19.6 10.2A7.8 7.8 0 0 0 5.4 7.4"/><path d="M5 3.6v4.2h4.2"/><path d="M4.4 13.8a7.8 7.8 0 0 0 14.2 2.8"/><path d="M19 20.4v-4.2h-4.2"/></svg>',
    // a chevron pointing right, turned down while its card is open: the collapsible Tools cards and the DNS card's Details
    chevron: '<svg ' + S + '><path d="M9.2 5.4 15.8 12l-6.6 6.6"/></svg>',
    // a file with a folded corner and an arrow up and an arrow down on it: the TFTP server card (files to and from devices)
    tftp: '<svg ' + S + '><path d="M7 3.4h6.8l5 5V19a1.6 1.6 0 0 1-1.6 1.6H7A1.6 1.6 0 0 1 5.4 19V5A1.6 1.6 0 0 1 7 3.4z" stroke-linejoin="round"/><path d="M13.6 3.6v5h5"/><path d="M9.8 17.8v-6.4M7.9 13.3l1.9-1.9 1.9 1.9"/><path d="M14.4 11.4v6.4M12.5 15.9l1.9 1.9 1.9-1.9"/></svg>',
    // a handset: the SIP calls found in a packet capture
    phone: '<svg ' + S + '><path d="M7.5 3.5 10 6.4l-2 2.4a12 12 0 0 0 5.2 5.2l2.4-2 2.9 2.5-1.3 2.2a2.4 2.4 0 0 1-2.6 1.1C9.7 16.9 7.1 14.3 5.3 9.4A2.4 2.4 0 0 1 6.4 6.8z"/></svg>',
    // a magnifier over a waveform: the Packet capture tile and page (the space after <svg matters: without it the
    // markup names an element "svgclass" and nothing draws)
    proav: '<svg ' + S + '><path d="M3.6 9.2h3.4L11.6 5.2v13.6L7 14.8H3.6z" stroke-linejoin="round"/><path d="M15.2 9.3a4 4 0 0 1 0 5.4"/><path d="M18 6.6a8 8 0 0 1 0 10.8"/></svg>',
    // a handset lifted off a phone, with a call arc: the SIP tile and page
    sip: '<svg ' + S + '><path d="M5.6 4.2h3.1l1.5 3.6-2 1.4a10.6 10.6 0 0 0 4.6 4.6l1.4-2 3.6 1.5v3.1a1.8 1.8 0 0 1-2 1.8C9.5 17.6 6.4 14.5 3.8 6.2a1.8 1.8 0 0 1 1.8-2z" stroke-linejoin="round"/><path d="M15.4 3.6a6.6 6.6 0 0 1 5 5"/></svg>',
    capture: '<svg ' + S + '><circle cx="10.5" cy="10.5" r="6.6"/><path d="M15.6 15.6 21 21"/><path d="M6.2 10.8h1.6l1.2-2.6 1.8 5.2 1.4-3.8.9 1.2h1.5" stroke-width="2"/></svg>',
    // the same cylinder stick the easter egg throws: curved far end, elliptical cap with the
    // wick hole, curved seams and label band, fuse out of the cap, spark at the tip
    dynamite: '<svg viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">' +
      '<g transform="rotate(-32 22 29)">' +
      '<path d="M7 21.5 H34 V36.5 H7 A3.6 7.5 0 0 1 7 21.5 Z" fill="#FF5C5C" stroke="#2B2438" stroke-width="2.6" stroke-linejoin="round"/>' +
      '<path d="M9 34.5 H32" stroke="#2B2438" stroke-width="2.4" stroke-linecap="round" opacity="0.16"/>' +
      '<path d="M9 24 H29" stroke="#fff" stroke-width="1.6" stroke-linecap="round" opacity="0.5"/>' +
      '<path d="M14 21.5 A3.6 7.5 0 0 0 14 36.5 M27 21.5 A3.6 7.5 0 0 0 27 36.5" stroke="#2B2438" stroke-width="1.6" opacity="0.35" fill="none"/>' +
      '<path d="M17 21.5 H24 A3.6 7.5 0 0 0 24 36.5 H17 A3.6 7.5 0 0 1 17 21.5 Z" fill="#FFF7E8" stroke="#2B2438" stroke-width="1.8" stroke-linejoin="round"/>' +
      '<ellipse cx="34" cy="29" rx="3.6" ry="7.5" fill="#C93B3B" stroke="#2B2438" stroke-width="2.6"/>' +
      '<circle cx="34" cy="29" r="1.6" fill="#2B2438"/>' +
      '</g>' +
      '<path d="M36.5 18.5c2.2-3.3 5.8-3 7.4-8" stroke="#2B2438" stroke-width="3" fill="none" stroke-linecap="round"/>' +
      '<path d="M43.5 3c.4 2.9 1.8 4.3 4.6 4.9-2.8.6-4.2 2-4.6 4.9-.4-2.9-1.8-4.3-4.6-4.9 2.8-.6 4.2-2 4.6-4.9z" fill="#FFA45C" stroke="#2B2438" stroke-width="1.6" stroke-linejoin="round"/></svg>',
  };
  function iconEl(name) {
    const tpl = document.createElement('template');
    tpl.innerHTML = ICONS[name] || ICONS.info;
    return tpl.content.firstElementChild;
  }
  TNT.icons = { svg: (n) => ICONS[n] || '', el: iconEl, names: Object.keys(ICONS) };

  /* ================================================================= util */
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  }
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === null || v === undefined || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
        else if (k === 'html') el.innerHTML = v;
        else if (k === 'style' && typeof v === 'object') {
          // custom properties ('--accent') are not properties of CSSStyleDeclaration, so
          // Object.assign silently dropped them: they need setProperty
          for (const [sk, sv] of Object.entries(v)) {
            if (sv === null || sv === undefined) continue;
            if (sk.startsWith('--')) el.style.setProperty(sk, String(sv));
            else el.style[sk] = sv;
          }
        }
        else if (k === 'on') for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
        else if (k === 'data') for (const [dk, dv] of Object.entries(v)) el.dataset[dk] = dv;
        else if (k in el && (k === 'value' || k === 'checked' || k === 'disabled' || k === 'hidden' || k === 'selected' || k === 'readOnly')) el[k] = v;
        else el.setAttribute(k, v === true ? '' : v);
      }
    }
    const add = (c) => {
      if (c === null || c === undefined || c === false) return;
      if (Array.isArray(c)) { c.forEach(add); return; }
      el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
    };
    children.forEach(add);
    return el;
  }
  const pad2 = (n) => (n < 10 ? '0' : '') + n;
  const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const nowS = () => Date.now() / 1000;
  function fmtMs(v) { if (v == null || !isFinite(v)) return '—'; return v < 10 ? v.toFixed(1) : String(Math.round(v)); }
  function fmtNum(v, d) { if (v == null || !isFinite(v)) return '—'; return d ? Number(v).toFixed(d) : String(Math.round(v)); }
  function fmtPct(v) { if (v == null || !isFinite(v)) return '—'; return (v === 0 ? '0' : v < 0.1 ? v.toFixed(2) : v < 10 ? v.toFixed(1) : String(Math.round(v))) + '%'; }
  function fmtMbps(v) { if (v == null || !isFinite(v)) return '—'; return v >= 100 ? String(Math.round(v)) : v.toFixed(1); }
  function fmtClock(ts) { const d = new Date(ts * 1000); return pad2(d.getHours()) + ':' + pad2(d.getMinutes()); }
  function fmtTime(ts) { const d = new Date(ts * 1000); return fmtClock(ts) + ':' + pad2(d.getSeconds()); }
  function fmtDate(ts) { const d = new Date(ts * 1000); return MONTHS[d.getMonth()] + ' ' + d.getDate() + ', ' + d.getFullYear(); }
  function fmtDateTime(ts) {
    if (ts == null) return '—';
    const d = new Date(ts * 1000), n = new Date();
    const sameDay = d.toDateString() === n.toDateString();
    return (sameDay ? 'Today' : MONTHS[d.getMonth()] + ' ' + d.getDate()) + ', ' + fmtClock(ts);
  }
  // like fmtDateTime but the clock carries seconds (the Outages list's start time, to match the end time)
  function fmtDateTimeSec(ts) {
    if (ts == null) return '—';
    const d = new Date(ts * 1000), n = new Date();
    const sameDay = d.toDateString() === n.toDateString();
    return (sameDay ? 'Today' : MONTHS[d.getMonth()] + ' ' + d.getDate()) + ', ' + fmtTime(ts);
  }
  function fmtStamp(ts) { const d = new Date(ts * 1000); return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) + ' ' + fmtTime(ts); }
  function fmtDuration(s) {
    if (s == null || !isFinite(s)) return '—';
    s = Math.max(0, Math.round(s));
    if (s < 60) return s + ' s';
    if (s < 3600) return Math.floor(s / 60) + 'm ' + pad2(s % 60) + 's';
    const hh = Math.floor(s / 3600), mm = Math.floor((s % 3600) / 60);
    if (s < 86400) return hh + 'h ' + pad2(mm) + 'm';
    return Math.floor(s / 86400) + 'd ' + (hh % 24) + 'h';
  }
  function relTime(ts, now) {
    if (ts == null) return '—';
    const d = Math.max(0, (now || nowS()) - ts);
    if (d < 5) return 'just now';
    if (d < 60) return Math.round(d) + ' s ago';
    if (d < 3600) return Math.round(d / 60) + ' min ago';
    if (d < 86400) { const hh = Math.floor(d / 3600), mm = Math.round((d % 3600) / 60); return hh + ' h' + (mm && hh < 6 ? ' ' + mm + ' min' : '') + ' ago'; }
    if (d < 172800) return 'yesterday';
    return Math.round(d / 86400) + ' d ago';
  }
  function untilText(ts, now) {
    if (ts == null) return '—';
    const d = ts - (now || nowS());
    if (d <= 0) return 'any moment';
    if (d < 60) return 'in ' + Math.round(d) + ' s';
    if (d < 3600) return 'in ' + Math.round(d / 60) + ' min';
    return 'in ' + Math.floor(d / 3600) + ' h ' + Math.round((d % 3600) / 60) + ' min';
  }
  function fmtBytes(n) {
    if (n == null || !isFinite(n)) return '—';
    const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; let v = n;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v : v.toFixed(1)) + ' ' + u[i];
  }
  function ipKey(ip) {
    const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip || '');
    if (!m) return Number.MAX_SAFE_INTEGER;
    return ((+m[1]) * 16777216) + ((+m[2]) * 65536) + ((+m[3]) * 256) + (+m[4]);
  }
  function copyCode(text, extraClass) {
    return h('code', { class: 'copy' + (extraClass ? ' ' + extraClass : ''), title: 'Click to copy' }, text == null ? '—' : String(text));
  }
  function pop(el) {
    if (!el) return;
    el.classList.remove('pop');
    void el.offsetWidth;
    el.classList.add('pop');
  }
  // the display name: a custom name the user set wins, then the built-in label (e.g. "Gateway"), then the host
  function targetName(t) { return t ? (t.name || t.label || t.host) : ''; }
  // what the name reverts to when the custom name is cleared (the built-in label, else the host)
  function originalTargetName(t) { return t ? (t.label || t.host) : ''; }
  TNT.util = { h, esc, nowS, fmtMs, fmtNum, fmtPct, fmtMbps, fmtClock, fmtTime, fmtDate, fmtDateTime, fmtDateTimeSec, fmtStamp, fmtDuration, relTime, untilText, fmtBytes, ipKey, copyCode, pop, targetName, originalTargetName, pad2 };

  /* ================================================================== ui */
  const $ = (sel, root) => (root || document).querySelector(sel);
  const toastsEl = $('#toasts');
  function toast(msg, kind, ms) {
    kind = kind || 'info';
    const el = h('div', { class: 'toast ' + kind, role: 'status' }, msg);
    toastsEl.appendChild(el);
    while (toastsEl.children.length > 5) toastsEl.firstElementChild.remove();
    const ttl = ms || (kind === 'error' ? 6000 : 3200);
    setTimeout(() => { el.classList.add('leaving'); setTimeout(() => el.remove(), 220); }, ttl);
    return el;
  }

  let modalStack = [];
  function modal(opts) {
    opts = opts || {};
    const prevFocus = document.activeElement;
    let closed = false;
    const closeBtn = h('button', { class: 'btn btn-round-sm', type: 'button', 'aria-label': 'Close' }, iconEl('close'));
    const head = h('div', { class: 'modal-head' }, h('h2', null, opts.title || ''), closeBtn);
    const body = h('div', { class: 'modal-body' });
    if (typeof opts.body === 'string') body.innerHTML = '<p>' + esc(opts.body) + '</p>';
    else if (opts.body instanceof Node) body.appendChild(opts.body);
    else if (typeof opts.body === 'function') opts.body(body);
    const foot = opts.foot ? h('div', { class: 'modal-foot' }, opts.foot) : null;
    const card = h('div', { class: 'modal' + (opts.narrow ? ' narrow' : '') + (opts.wide ? ' wide' : ''), role: 'dialog', 'aria-modal': 'true', 'aria-label': opts.title || 'Dialog' }, head, body, foot);
    const backdrop = h('div', { class: 'modal-backdrop' }, card);
    // Escape closes the modal on top only (a confirm over another modal closes alone: the one under it registered its
    // listener first and sees it is not on top). opts.onEscape() returning true leaves it open and lets the key through
    // to the focused control, such as a site name field closing its list of suggestions.
    const onKey = (e) => {
      if (e.key !== 'Escape' || modalStack[modalStack.length - 1] !== ctl) return;
      if (opts.onEscape && opts.onEscape(e)) return;
      e.stopPropagation();
      close(undefined);
    };
    function close(result) {
      if (closed) return;
      closed = true;
      document.removeEventListener('keydown', onKey, true);
      backdrop.remove();
      modalStack = modalStack.filter((m) => m !== ctl);
      if (opts.onClose) { try { opts.onClose(result); } catch (e) { console.error(e); } }
      if (prevFocus && prevFocus.focus) { try { prevFocus.focus(); } catch (e) { /* ignore */ } }
    }
    closeBtn.addEventListener('click', () => close(undefined));
    backdrop.addEventListener('mousedown', (e) => { if (e.target === backdrop) close(undefined); });
    document.addEventListener('keydown', onKey, true);
    $('#modal-root').appendChild(backdrop);
    const ctl = { close, el: card, body };
    modalStack.push(ctl);
    // a control marked data-autofocus wins: a danger confirm starts on its safe button, so one stray Enter destroys nothing
    const first = card.querySelector('[data-autofocus]') || card.querySelector('input:not([type=hidden]), select, button.btn-primary, button.btn-danger');
    setTimeout(() => { try { (first || closeBtn).focus(); } catch (e) { /* ignore */ } }, 0);
    return ctl;
  }

  function confirmDialog(opts) {
    opts = opts || {};
    return new Promise((resolve) => {
      let done = false;
      const finish = (v) => { if (!done) { done = true; resolve(!!v); } };
      const cancel = h('button', { class: 'btn', type: 'button', 'data-autofocus': opts.danger ? '' : null, on: { click: () => m.close(false) } }, opts.cancel || 'Cancel');
      const ok = h('button', { class: 'btn ' + (opts.danger ? 'btn-danger' : 'btn-primary'), type: 'button', on: { click: () => m.close(true) } }, opts.ok || 'OK');
      const m = modal({ title: opts.title || 'Are you sure?', body: opts.message || '', narrow: true, foot: [cancel, ok], onClose: finish });
    });
  }

  async function copyText(text) {
    text = String(text == null ? '' : text);
    if (!text) return false;
    let ok = false;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) { await navigator.clipboard.writeText(text); ok = true; }
    } catch (e) { ok = false; }
    if (!ok) {
      try {
        const ta = h('textarea', { style: { position: 'fixed', left: '-9999px', top: '0' }, 'aria-hidden': 'true' }, text);
        document.body.appendChild(ta);
        ta.select();
        ok = document.execCommand('copy');
        ta.remove();
      } catch (e) { ok = false; }
    }
    const short = text.length > 42 ? text.slice(0, 40) + '…' : text;
    toast(ok ? 'Copied ' + short : 'Could not copy', ok ? 'ok' : 'error', 1800);
    return ok;
  }

  /** Disable a button while work runs; an optional label temporarily replaces its content
   *  (icon included) and the original content is restored on busy(btn, false). */
  function busy(btn, on, label) {
    if (!btn) return;
    if (on) {
      if (btn.dataset.busy === '1') return;
      btn.dataset.busy = '1';
      btn.classList.add('busy');
      btn.disabled = true;
      if (label) { btn.dataset.busyHtml = btn.innerHTML; btn.textContent = label; }
    } else {
      if (btn.dataset.busy !== '1') return;
      delete btn.dataset.busy;
      btn.classList.remove('busy');
      btn.disabled = false;
      if (btn.dataset.busyHtml !== undefined) { btn.innerHTML = btn.dataset.busyHtml; delete btn.dataset.busyHtml; }
    }
  }

  function toggle(opts) {
    // opts: {checked, on, off, onChange(checked), accent}
    const input = h('input', { type: 'checkbox', checked: !!opts.checked, role: 'switch', 'aria-checked': String(!!opts.checked) });
    const track = h('span', { class: 'toggle-track' }, h('span', { class: 'toggle-knob' }));
    const labels = h('span', { class: 'toggle-labels' }, h('span', { class: 'off' }, opts.off || 'Off'), h('span', { class: 'on' }, opts.on || 'On'));
    const label = h('label', { class: 'toggle', style: opts.accent ? { '--accent': opts.accent } : null }, input, track, labels);
    input.addEventListener('change', () => {
      input.setAttribute('aria-checked', String(input.checked));
      if (opts.onChange) opts.onChange(input.checked, input);
    });
    label.setChecked = (v) => { input.checked = !!v; input.setAttribute('aria-checked', String(!!v)); };
    label.input = input;
    return label;
  }

  function fuse() {
    const fill = h('div', { class: 'fuse-fill' });
    const spark = h('div', { class: 'fuse-spark' }, iconEl('spark'));
    const bar = h('div', { class: 'fuse idle', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': '0' }, fill, spark);
    const left = h('span', { class: 'l' }, '');
    const right = h('span', { class: 'r' }, '');
    const label = h('div', { class: 'fuse-label' }, left, right);
    const el = h('div', { class: 'fuse-wrap' }, bar, label);
    el.set = (pct, state, leftText, rightText) => {
      const p = Math.max(0, Math.min(100, Math.round((pct || 0) * 100)));
      fill.style.width = p + '%';
      spark.style.left = p + '%';
      bar.setAttribute('aria-valuenow', String(p));
      bar.classList.toggle('idle', state === 'idle');
      bar.classList.toggle('done', state === 'done');
      left.textContent = leftText || '';
      right.textContent = rightText || '';
    };
    return el;
  }

  function segmented(options, value, onChange) {
    const el = h('div', { class: 'seg', role: 'tablist' });
    for (const o of options) {
      const b = h('button', { type: 'button', role: 'tab', class: o.value === value ? 'on' : '', 'aria-selected': String(o.value === value) }, o.label);
      b.addEventListener('click', () => {
        for (const c of el.children) { c.classList.toggle('on', c === b); c.setAttribute('aria-selected', String(c === b)); }
        onChange(o.value);
      });
      el.appendChild(b);
    }
    return el;
  }

  function emptyState(text) {
    return h('div', { class: 'empty' }, h('span', { class: 'spark-icon' }, iconEl('spark')), ' ', text);
  }

  function lightEl(color, large) {
    return h('span', { class: 'light ' + (color || 'grey') + (large ? ' lg' : ''), title: color || 'unknown' });
  }

  /** An external link opened outside the app like every external link (a plain left click goes to TNT.openExternal). */
  function geoLink(url, text) {
    const a = h('a', { class: 'geo-attrib', href: url, target: '_blank', rel: 'noopener', title: 'Open ' + url }, text);
    a.addEventListener('click', (e) => {
      if (e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
      TNT.openExternal(url, e);
    });
    return a;
  }
  /** The CC BY 4.0 attribution for DB-IP's IP location data. */
  function geoAttribution() { return geoLink('https://db-ip.com', 'IP Geolocation by DB-IP'); }
  /** The licence of that data (CC BY 4.0), shown in Settings. */
  function geoLicence() { return geoLink('https://creativecommons.org/licenses/by/4.0/', 'CC BY 4.0'); }

  TNT.ui = { toast, modal, confirm: confirmDialog, copy: copyText, busy, toggle, fuse, segmented, emptyState, light: lightEl, icon: iconEl, geoAttribution, geoLicence };

  /** Open an http(s) URL outside the app. Inside the TNT client the pywebview bridge
   *  (`open_url`) hands it to the default browser and true is returned — when the click event of
   *  an <a target=_blank> is passed as `ev` its default is prevented so the WebView never
   *  navigates. Without the bridge a plain browser tab is used: window.open for bare calls, or
   *  the anchor's own target=_blank navigation when `ev` is given (so a link never opens twice). */
  function openExternal(url, ev) {
    url = String(url || '');
    if (!/^https?:\/\//i.test(url)) return false;
    const bridge = window.pywebview && window.pywebview.api && typeof window.pywebview.api.open_url === 'function';
    if (bridge) {
      if (ev && ev.preventDefault) ev.preventDefault();
      const fail = () => toast('Could not open ' + url, 'error');
      try {
        const r = window.pywebview.api.open_url(url);
        if (r && r.then) r.then((ok) => { if (ok === false) fail(); }, fail);
      } catch (e) { fail(); }
      return true;
    }
    if (!ev) window.open(url, '_blank', 'noopener');
    return false;
  }
  TNT.openExternal = openExternal;

  /* ================================================================ state */
  const state = {
    status: null, targets: [], settings: null, theme: 'light',
    live: 'connecting', apiOk: true, now: nowS(), view: null,
  };
  TNT.state = state;
  const ACCENT = { ipinfo: 'var(--blue)', ping: 'var(--green)', outages: 'var(--yellow)', speed: 'var(--purple)', discovery: 'var(--orange)', tools: 'var(--red)', wifi: 'var(--teal)', reports: 'var(--grey)', capture: 'var(--pink)', proav: 'var(--lime)', sip: 'var(--sand)' };
  const VIEW_NAMES = ['ipinfo', 'ping', 'outages', 'speed', 'discovery', 'wifi', 'tools', 'reports', 'capture', 'proav', 'sip'];   // the tile order of index.html
  //: the tiles under the four full-height ones, half height with a two-line body (.tile.half in css/tnt.css)
  //: the main tools Settings can switch off, in tile order (tnt.config.TOOLS). A tool that is off has no tile
  //: and no page, and its service side takes no automated action either — the switch is one setting, not two.
  //: this project's page, for the link in Settings. A constant, never a setting.
  const TNT_REPO_URL = 'https://github.com/rhuntertec/TNT';
  //: the icon each tile's settings section wears, so a section is recognisably that page's
  const TILE_ICONS = { ipinfo: 'network', ping: 'ping', outages: 'outage', speed: 'speed',
                       discovery: 'discovery', wifi: 'wifi', tools: 'tools', reports: 'report',
                       capture: 'capture', proav: 'proav', sip: 'sip' };
  const TOOLS = ['speed', 'discovery', 'wifi', 'capture', 'proav', 'sip'];
  const TOOL_NAMES = { speed: 'Speed', discovery: 'Discovery', wifi: 'WiFi', capture: 'Packet capture',
                       proav: 'Pro AV', sip: 'SIP' };
  const TOOL_WHAT = {
    speed: 'Scheduled internet speed tests, the history charts and the patterns. Off, no test runs by itself.',
    discovery: 'The on-demand LAN scan that finds what is on the network.',
    wifi: 'The Wi-Fi survey: access points, channels, signal over time and the spectrum chart.',
    capture: 'The packet analyser on its own page. Off, no capture can be started.',
    proav: 'Dante, AES67, Ravenna, ST 2110 and Q-LAN: what is streaming and what clock it follows.',
    sip: 'The SIP qualifier, the ALG check, the STUN test and the call flows.',
  };
  /** Pure: whether a tool is switched on, from status.tools. Anything unknown is on — a tile that vanished
   *  because a status read failed would be worse than one that stayed. */
  function toolOn(name) {
    if (!TOOLS.includes(name)) return true;
    const t = state.status && state.status.tools;
    return !t || t[name] !== false;
  }
  /** The tiles that exist right now, in markup order. */
  function liveViews() { return VIEW_NAMES.filter(toolOn); }

  //: every tile is half height now — the four that used to be tall said more than a glance needs
  const HALF_TILES = ['ipinfo', 'ping', 'outages', 'speed', 'discovery', 'wifi', 'tools', 'reports', 'capture', 'proav', 'sip'];

  /* ================================================================ theme */
  function setTheme(theme, opts) {
    opts = opts || {};
    theme = theme === 'dark' ? 'dark' : 'light';
    const changed = state.theme !== theme || document.documentElement.getAttribute('data-theme') !== theme;
    document.documentElement.setAttribute('data-theme', theme);
    state.theme = theme;
    try { localStorage.setItem('tnt.theme', theme); } catch (e) { /* ignore */ }
    if (changed && TNT.charts) TNT.charts.rerenderAll();
    if (opts.save !== false) api.updateSettings({ ui: { theme } }).catch((err) => console.warn('theme save failed', err));
    if (opts.bridge !== false && window.pywebview && window.pywebview.api && window.pywebview.api.set_theme) {
      try { const r = window.pywebview.api.set_theme(theme); if (r && r.catch) r.catch(() => {}); } catch (e) { /* ignore */ }
    }
    const t = $('#settings-theme-toggle');
    if (t && t.setChecked) t.setChecked(theme === 'dark');
  }
  TNT.setTheme = (theme, opts) => setTheme(theme, opts);
  TNT.getTheme = () => state.theme;

  /* ============================================================== status */
  let lastStatusTs = 0;
  let refreshing = false, refreshAgain = false, statusRetryTimer = null;
  async function refreshStatus() {
    // asked for while a request is in flight: run once more when it lands, so a network change (or an
    // outage event) is never answered with the snapshot requested before it
    if (refreshing) { refreshAgain = true; return; }
    refreshing = true;
    try {
      const st = await api.status();
      applyStatus(st);
    } catch (err) {
      state.apiOk = false;
      renderHeader();
    } finally {
      refreshing = false;
      if (refreshAgain) { refreshAgain = false; refreshStatus(); }
    }
  }
  function applyStatus(st) {
    if (!st) return;
    lastStatusTs = Date.now();
    const net = api.net.compare(lastNet, st, Date.now());
    if (net.stale) {
      // a snapshot from before the net.changed event this page already applied: ask again shortly
      state.apiOk = true;
      if (!statusRetryTimer) statusRetryTimer = setTimeout(() => { statusRetryTimer = null; refreshStatus(); }, 1000);
      return;
    }
    lastNet = net.next;
    state.status = st;
    syncTools();   // a tool switched off elsewhere takes its tile with it
    state.targets = Array.isArray(st.targets) ? st.targets : [];
    state.apiOk = true;
    adoptStatusJob(st.reports && st.reports.job);
    if (st.settings && st.settings.theme && !state._themeSynced) {
      state._themeSynced = true;
      let local = null;
      try { local = localStorage.getItem('tnt.theme'); } catch (e) { /* ignore */ }
      if (!local && st.settings.theme !== state.theme) setTheme(st.settings.theme, { save: false });
    }
    renderAll();
    notifyView();
    renderSettingsGateway();
    renderSettingsGeoip();
    renderSettingsUpdate();
    // a newer network generation than this page has seen (the event was missed: stream down, PC asleep,
    // window hidden) or a restarted service: the same refresh as the event, the toast only for a change
    if (net.changed) {
      networkChanged({ source: 'status', generation: st.net.generation, default_gateway: st.net.default_gateway || null,
        internet_nic: st.net.internet_nic || null, summary: api.net.summaryFromStatus(st) }, !net.restarted);
    }
  }
  /** Replace the target list (a ping.targets event, or the answer of Load Default Tiles). */
  function setTargets(list) {
    state.targets = list;
    if (state.status) state.status.targets = list;
    renderAll();
    notifyView();
  }

  /* ===================================================== network changes */
  // net.changed, or a status snapshot with a newer status.net.generation, means this PC is on another
  // network (or an adapter's configuration changed): one coalesced toast, the tiles repainted, a fresh
  // status, and the open view's netChanged(info, state) hook once a burst of changes has settled.
  const NET_SETTLE_MS = 500;       // views reload once changes stop arriving for this long
  const NET_RECHECK_MS = 3000;     // then one more status read: what the service re-resolves a moment later
  const NET_TOAST_MS = 7000;
  let lastNet = null;              // { started, generation, eventMs } (api.net.compare)
  let netInfo = null, netSettleTimer = null, netRecheckTimer = null;
  let netToast = null, netToastTimer = null, netToastDeferTimer = null, netToastInfo = null;

  function networkChanged(info, withToast) {
    const showIpv6 = !!(state.settings && state.settings.ui && state.settings.ui.show_ipv6);
    if (withToast && info.summary && api.net.toastWanted(info, showIpv6)) showNetToast(info);
    renderAll();
    renderSettingsGateway();
    renderSettingsGeoip();
    refreshStatus();
    netInfo = api.net.merge(netInfo, info);
    if (netSettleTimer) clearTimeout(netSettleTimer);
    netSettleTimer = setTimeout(() => {
      netSettleTimer = null;
      const merged = netInfo;
      netInfo = null;
      if (current.view && current.view.netChanged) {
        try { current.view.netChanged(merged, state); } catch (e) { console.error('view netChanged failed', e); }
      }
    }, NET_SETTLE_MS);
    if (netRecheckTimer) clearTimeout(netRecheckTimer);
    netRecheckTimer = setTimeout(() => { netRecheckTimer = null; refreshStatus(); }, NET_RECHECK_MS);
  }

  /** The one network toast: a change while it is still up rewrites it and restarts its timer; once it
   *  has gone, the next one waits out api.net.TOAST_GAP_MS since the last and carries the latest summary. */
  function showNetToast(info) {
    netToastInfo = info;
    const visible = !!(netToast && netToast.el.isConnected && !netToast.el.classList.contains('leaving'));
    const plan = api.net.toastPlan(netToast ? { shownMs: netToast.shownMs, visible } : null, Date.now());
    if (plan.action === 'defer') {
      if (!netToastDeferTimer) netToastDeferTimer = setTimeout(() => { netToastDeferTimer = null; showNetToast(netToastInfo); }, plan.waitMs);
      return;
    }
    const { text, kind } = api.net.toastText(info);
    let el;
    if (plan.action === 'update') {
      el = netToast.el;
      el.className = 'toast ' + kind;
      el.textContent = text;
      pop(el);
    } else {
      el = h('div', { class: 'toast ' + kind, role: 'status' }, text);
      toastsEl.appendChild(el);
      while (toastsEl.children.length > 5) toastsEl.firstElementChild.remove();
      netToast = { el, shownMs: Date.now() };
    }
    if (netToastTimer) clearTimeout(netToastTimer);
    netToastTimer = setTimeout(() => { netToastTimer = null; el.classList.add('leaving'); setTimeout(() => el.remove(), 220); }, NET_TOAST_MS);
  }

  /** "default gateway · 10.0.0.251" in Settings > Default targets, kept current while the modal is open. */
  function gatewayChipText() {
    const net = state.status && state.status.net;
    return net ? 'default gateway · ' + (net.default_gateway || 'none right now') : 'default gateway';
  }
  function renderSettingsGateway() {
    const chip = $('#settings-gateway');
    const text = gatewayChipText();
    if (chip && chip.textContent !== text) chip.textContent = text;
  }
  /** Settings › IP location: the live status line (views/ipinfo.js geoStatusText) and whether Retry now shows. */
  function geoipStatusText() {
    const v = TNT.views && TNT.views.ipinfo;
    return v && v.geoStatusText ? v.geoStatusText(state.status && state.status.geoip, state.now) : '';
  }
  function geoipRetryVisible() {
    const g = state.status && state.status.geoip;
    return !!(g && g.enabled && g.error && g.state !== 'downloading');
  }
  function renderSettingsGeoip() {
    const el = $('#settings-geoip');
    const text = geoipStatusText();
    if (el && el.textContent !== text) el.textContent = text;
    const btn = $('#settings-geoip-retry');
    const show = geoipRetryVisible();
    if (btn && btn.hidden === show) btn.hidden = !show;
  }

  /* ---- auto-update (GitHub releases): a dismissible banner + the Settings › Updates section ---- */
  const UPDATE_DISMISS_KEY = 'tnt.update.dismissed';   // per-viewer: a version they chose to hide the banner for
  const UPDATE_BUSY_STATES = ['checking', 'downloading', 'verifying', 'installing'];
  function updateState() { return (state.status && state.status.update) || null; }
  /** Pure: what the top banner shows for an update STATUS -> { show, version, notesUrl, installing, text, hasAsset }. */
  function updateBannerView(u) {
    if (!u || !u.enabled || !u.latest_version) return { show: false };
    const busyNow = u.state === 'downloading' || u.state === 'verifying' || u.state === 'installing';
    if (!(u.state === 'available' || u.state === 'ready' || busyNow)) return { show: false };
    let dismissed = null;
    try { dismissed = localStorage.getItem(UPDATE_DISMISS_KEY); } catch (e) { /* storage may be unavailable */ }
    if (!busyNow && dismissed === u.latest_version) return { show: false };
    const dl = u.download || null;
    const pct = dl && dl.total ? Math.min(100, Math.round(100 * (dl.received || 0) / dl.total)) : null;
    const text = u.state === 'downloading' ? (pct != null ? 'Downloading… ' + pct + '%' : 'Downloading…')
      : u.state === 'verifying' ? 'Verifying…'
      : u.state === 'installing' ? 'Installing… TNT will close and reopen' : '';
    return { show: true, version: u.latest_version, notesUrl: u.notes_url || null, installing: busyNow,
             text, hasAsset: !!(u.asset && u.asset.name) };
  }
  function renderUpdateBanner() {
    const el = $('#update-banner');
    if (!el) return;
    const v = updateBannerView(updateState());
    if (!v.show) { if (!el.hidden) { el.hidden = true; el.innerHTML = ''; el.dataset.sig = ''; } return; }
    const sig = v.version + '|' + v.installing + '|' + (v.text || '') + '|' + v.hasAsset + '|' + !!v.notesUrl;
    if (el.dataset.sig === sig && !el.hidden) return;   // spare the button's focus/hover on unrelated repaints
    el.dataset.sig = sig;
    el.hidden = false;
    el.innerHTML = '';
    el.appendChild(h('div', { class: 'update-banner-msg' }, iconEl('download'),
      h('span', null, h('strong', null, 'Update available'), ' — TNT ', h('strong', null, v.version))));
    const right = h('div', { class: 'update-banner-actions' });
    if (v.installing) {
      right.appendChild(h('span', { class: 'muted' }, v.text || 'Working…'));
    } else {
      if (v.notesUrl) right.appendChild(h('a', { class: 'update-banner-link', href: v.notesUrl,
        on: { click: (e) => openExternal(v.notesUrl, e) } }, 'Release notes'));
      const install = h('button', { class: 'btn btn-primary btn-sm', type: 'button', disabled: !v.hasAsset,
        title: v.hasAsset ? '' : 'This release has no installer to download' }, 'Install');
      install.addEventListener('click', () => startUpdateInstall(v.version));
      right.appendChild(install);
      const dismiss = h('button', { class: 'btn btn-icon btn-sm', type: 'button', 'aria-label': 'Dismiss', title: 'Dismiss' }, iconEl('close'));
      dismiss.addEventListener('click', () => {
        try { localStorage.setItem(UPDATE_DISMISS_KEY, v.version); } catch (e) { /* ignore */ }
        el.hidden = true; el.innerHTML = ''; el.dataset.sig = '';
      });
      right.appendChild(dismiss);
    }
    el.appendChild(right);
  }
  async function startUpdateInstall(version) {
    const ok = await confirmDialog({ title: 'Install update?',
      message: 'TNT ' + version + ' will download and verify, then TNT closes and reopens to install it. '
        + 'Background monitoring resumes on its own. Continue?', ok: 'Install', cancel: 'Not now' });
    if (!ok) return;
    // arm the client to reopen its window after the installer replaces it (a no-op outside the TNT client)
    try {
      const b = window.pywebview && window.pywebview.api;
      if (b && typeof b.arm_relaunch === 'function') { const r = b.arm_relaunch(); if (r && r.catch) r.catch(() => {}); }
    } catch (e) { /* ignore */ }
    try {
      await api.updateInstall();
      toast('Downloading the update…', 'ok');
      renderUpdateBanner();
      renderSettingsUpdate();
    } catch (err) {
      toast('Could not start the update: ' + (err && err.message ? err.message : err), 'error');
    }
  }
  /** Pure: the Settings › Updates status line for an update STATUS at time `now`. */
  function updateSettingsText(u, now) {
    if (!u) return '';
    if (!u.enabled) return 'Off: TNT does not check for updates.';
    const cur = 'This build: TNT ' + (u.current_version || '?');
    const when = u.checked_ts ? ' · checked ' + relTime(u.checked_ts, now) : '';
    switch (u.state) {
      case 'checking': return 'Checking for updates…';
      case 'downloading': { const dl = u.download || {}; const pct = dl.total ? ' ' + Math.round(100 * (dl.received || 0) / dl.total) + '%' : ''; return 'Downloading TNT ' + (u.latest_version || '') + pct; }
      case 'verifying': return 'Verifying TNT ' + (u.latest_version || '') + '…';
      case 'installing': return 'Installing TNT ' + (u.latest_version || '') + '… TNT will close and reopen.';
      case 'available': case 'ready': return 'Update available: TNT ' + (u.latest_version || '') + (u.error ? ' · ' + u.error : '');
      case 'error': return 'Last check failed: ' + (u.error || 'unknown error') + '.';
      case 'up_to_date': return 'Up to date. ' + cur + when + '.';
      default: return cur + when + '.';
    }
  }
  function renderSettingsUpdate() {
    const u = updateState();
    const el = $('#settings-update');
    if (el) { const t = updateSettingsText(u, state.now); if (el.textContent !== t) el.textContent = t; }
    const btn = $('#settings-update-check');
    const busyNow = !!(u && UPDATE_BUSY_STATES.indexOf(u.state) >= 0);
    if (btn) btn.disabled = busyNow || !(u && u.enabled);
  }
  async function loadSettings() {
    try {
      state.settings = await api.settings();
      notifyView();
    } catch (err) { /* status carries the important bits */ }
  }

  /* ============================================================== render */
  function renderAll() { renderHeader(); renderTiles(); renderUpdateBanner(); }

  function overallText() {
    const st = state.status;
    if (!state.apiOk) return { color: 'grey', text: 'Service not reachable' };
    if (!st) return { color: 'grey', text: 'Connecting…' };
    if (st.paused) return { color: 'grey', text: 'Monitoring paused' };
    const outs = st.outages || {};
    const total = outs.total_active;
    if (total) return { color: 'red', text: total.kind === 'total_local' ? 'Local network outage' : 'Internet outage' };
    const t = state.targets;
    if (!t.length) return { color: 'grey', text: 'No targets yet' };
    // red is reserved for a full (local or internet) outage above; individual targets
    // that are down only turn the pill yellow
    const reds = t.filter((x) => x.light === 'red');
    const yellows = t.filter((x) => x.light === 'yellow');
    if (reds.length === 1) return { color: 'yellow', text: targetName(reds[0]) + ' is down' };
    if (reds.length > 1) return { color: 'yellow', text: reds.length + ' targets down' };
    // "sluggish" is reserved for a real round-trip problem (>= SLUGGISH_MS over the last
    // minute); a yellow light for other reasons is described as what it is
    const avg = (x) => (x.window && x.window.avg_ms != null ? x.window.avg_ms : null);
    const slow = yellows.filter((x) => avg(x) != null && avg(x) >= SLUGGISH_MS);
    const lossy = yellows.filter((x) => !slow.includes(x) && x.window && x.window.loss_pct > 0);
    if (slow.length === 1) return { color: 'yellow', text: targetName(slow[0]) + ' looking sluggish' };
    if (slow.length > 1) return { color: 'yellow', text: slow.length + ' targets sluggish' };
    if (lossy.length === 1) return { color: 'yellow', text: targetName(lossy[0]) + ' dropping packets' };
    if (lossy.length > 1) return { color: 'yellow', text: lossy.length + ' targets dropping packets' };
    if (yellows.length === 1) return { color: 'yellow', text: targetName(yellows[0]) + ' a little slow' };
    if (yellows.length > 1) return { color: 'yellow', text: yellows.length + ' targets a little slow' };
    if (t.every((x) => x.light === 'grey')) return { color: 'grey', text: 'Warming up…' };
    return { color: 'green', text: 'All good' };
  }

  function renderHeader() {
    const o = overallText();
    const pill = $('#status-pill');
    pill.className = 'status-pill ' + o.color;
    $('#status-light').className = 'light ' + o.color;
    $('#status-text').textContent = o.text;
    pill.title = o.text;   // the text ellipsizes when the window is too narrow for a long host name
    const badge = $('#live-badge');
    badge.className = 'live-badge ' + state.live;
    $('#live-text').textContent = state.live === 'live' ? 'LIVE' : state.live === 'connecting' ? 'CONNECTING' : 'OFFLINE';
    badge.title = state.live === 'live'
      ? 'LIVE: this page is receiving real-time updates (pings, outages, speed tests) from the TNT service'
      : state.live === 'connecting'
        ? 'Connecting to the TNT service event stream…'
        : 'OFFLINE: not connected to the TNT service. Showing the last known data and polling every 5 s.';
  }

  const tileEls = {};
  const PING_TILE_MAX = 3;   // lights shown on the Ping tile: one row, and nothing else on it
  const SLUGGISH_MS = 100;   // header says "looking sluggish" only from this 1-minute average up
  // the Tools tile names the tools under the DHCP server, in the order of their cards on the Tools page
  const TOOLS_TILE_ITEMS = ['LAN throughput', 'Port forward check', 'Traceroute', 'TFTP server', 'Subnet calc', 'DNS', 'WiFi passwords'];
  function line(html, cls, title) { return '<div class="tile-line ' + (cls || '') + '"' + (title ? ' title="' + esc(title) + '"' : '') + '>' + html + '</div>'; }
  /** The most serious problem of a status.netinfo adapter (its `warnings` codes, labelled like the Network info
   *  page) as a badge for the Network info tile; '' without one. The informational grey ones stay on the page. */
  function warningBadge(nic) {
    const view = TNT.views.ipinfo && TNT.views.ipinfo.warningView;
    const shown = (nic && Array.isArray(nic.warnings) && view ? nic.warnings : []).map((code) => view({ code })).filter((w) => w && w.cls !== 'grey');
    if (!shown.length) return '';
    const w = shown.find((x) => x.cls === 'red') || shown[0];
    return '<span class="badge ' + w.cls + '" title="Details on the Network info page">' + esc(w.label) + '</span>';
  }

  function renderTiles() {
    const st = state.status;
    const now = state.now;
    // IP info
    {
      const el = tileEls.ipinfo;
      const nic = st && st.netinfo && st.netinfo.internet_nic;
      const local = st && st.netinfo && st.netinfo.local_nic;
      let html;
      if (!st) html = line('Loading…', 'muted');
      else if (nic) {
        // the adapter and its IPv4. The gateway is one line down on the page itself, with the live link map
        // beside it; on a two-line tile it was the least useful of the three.
        html = line('<span class="strong">' + esc(nic.name) + '</span><span class="badge blue" style="--accent:var(--blue)">internet</span>' + warningBadge(nic)) +
          line('<span class="muted">IPv4</span> <code>' + esc(api.net.nicCidr(nic) || nic.ipv4 || '—') + '</code>');
      } else if (local) {
        // no adapter faces the internet: the one that is connected anyway (a bench cable, the DHCP server tool, no DHCP server)
        html = line('<span class="strong">' + esc(local.name) + '</span><span class="badge grey">no internet</span>' + warningBadge(local)) +
          line('<span class="muted">IPv4</span> <code>' + esc(api.net.nicCidr(local) || local.ipv4 || '—') + '</code>');
      } else {
        html = line('<span class="strong">No internet adapter</span>') + line((st.netinfo && st.netinfo.adapter_count || 0) + ' adapters found', 'muted');
      }
      if (el.dataset.html !== html) { el.innerHTML = html; el.dataset.html = html; }
    }
    // Ping (keyed lights so the colour transition survives)
    {
      const el = tileEls.ping;
      const t = state.targets;
      // the first three targets as a row of lights, and nothing else. The counts, the average and the rest of
      // the targets are the page's job; the tile is the glance.
      const shown = t.slice(0, PING_TILE_MAX);
      const key = shown.map((x) => x.id).join(',');
      if (el.dataset.key !== key) {
        el.innerHTML = '';
        el.dataset.key = key;
        if (!t.length) el.appendChild(h('div', { class: 'tile-line muted' }, st ? 'No targets — load the defaults' : 'Loading…'));
        else {
          const row = h('div', { class: 'tile-lights' });
          for (const x of shown) row.appendChild(h('div', { class: 'tl', title: x.host }, lightEl(x.light), h('span', null, targetName(x))));
          el.appendChild(row);
        }
      }
      if (t.length) {
        const lights = el.querySelectorAll('.tl .light');
        shown.forEach((x, i) => { const l = lights[i]; if (l && l.className !== 'light ' + x.light) l.className = 'light ' + x.light; });
        const names = el.querySelectorAll('.tl span:last-child');
        shown.forEach((x, i) => { if (names[i] && names[i].textContent !== targetName(x)) names[i].textContent = targetName(x); });
      }
    }
    // Outages
    {
      const el = tileEls.outages;
      const o = st && st.outages;
      let html;
      if (!o) html = line('Loading…', 'muted');
      else {
        const n = o.count_24h || 0;
        const ongoing = (o.active || []).length;
        // yellow while only some targets are down, red only during a full outage
        const ongoingCls = o.total_active ? 'red' : 'yellow';
        html = line('<span class="num">' + n + '</span><span class="muted">in the last 24 h</span>' + (ongoing ? ' <span class="badge ' + ongoingCls + ' pulse">ongoing</span>' : ''));
        if (o.last) {
          // when and how long, on one line. Which target it was is on the page, and on a two-line tile the name
          // crowded out the two numbers somebody actually glances for.
          const l = o.last;
          html += line('<span class="muted">Last:</span> ' + esc(relTime(l.start_ts, now)) + '. '
            + (l.open ? '<span class="ongoing strong">Still going</span>'
              : '<span class="muted">Lasted</span> ' + esc(fmtDuration(l.duration_s))));
        } else html += line(n ? '' : 'Nice and quiet', 'muted');
      }
      if (el.dataset.html !== html) { el.innerHTML = html; el.dataset.html = html; }
    }
    // Speed
    {
      const el = tileEls.speed;
      const sp = st && st.speed;
      let html;
      if (!sp) html = line('Loading…', 'muted');
      else {
        const last = sp.last;
        if (last && last.ok) {
          html = line('<span class="strong">↓ <span class="num">' + fmtMbps(last.download_mbps) + '</span></span><span class="strong">↑ <span class="num">' + fmtMbps(last.upload_mbps) + '</span></span><span class="muted">Mbps</span>');
        } else if (last) {
          html = line('<span class="strong">Last test failed</span>');
        } else html = line('No results yet', 'muted');
        // the second line is what the last test measured, or the run that is happening instead. When the next one
        // is due is on the page: on a two-line tile it was taking the room the result needed.
        if (sp.running) {
          const p = sp.progress || {};
          html += line('<span class="spark-icon">' + ICONS.spark + '</span> Testing… ' + esc(p.phase || '') + ' ' + Math.round((p.pct || 0) * 100) + '%');
        } else if (last) {
          html += line('<span class="muted">' + (last.ok ? fmtMs(last.latency_ms) + ' ms · ' : '') + esc(relTime(last.ts, now))
            + (sp.enabled === false ? ' · auto off' : '') + '</span>');
        } else html += line(sp.enabled === false ? 'Automatic tests off' : 'Runs every ' + (sp.interval_min || 15) + ' min', 'muted');
      }
      if (el.dataset.html !== html) { el.innerHTML = html; el.dataset.html = html; }
    }
    // Discovery (half height: two lines)
    {
      const el = tileEls.discovery;
      const d = st && st.discovery;
      let html;
      if (!d) html = line('Loading…', 'muted');
      else if (d.running) {
        const p = d.progress || {};
        const pct = p.total ? Math.round((p.done / p.total) * 100) : 0;
        html = line('<span class="spark-icon">' + ICONS.spark + '</span> <span class="strong">Scanning…</span> ' + esc(p.phase || '') + ' ' + pct + '%') +
          line((p.found || 0) + ' found so far', 'muted');
      } else if (d.last_run) {
        const r = d.last_run;
        // the last scan is history: one of a network this PC is not on any more says so
        const other = api.net.runElsewhere(r.cidr, st.netinfo && st.netinfo.internet_nic, st.net && st.net.networks);
        html = line('<span class="num">' + (r.found || 0) + '</span><span class="muted">devices ·</span><code>' + esc(r.cidr) + '</code>' +
          (other ? '<span class="badge grey" title="This PC is on another network now">other network</span>' : '')) +
          line(esc(relTime(r.ts, now)) + ' · ' + esc(fmtDuration(r.duration_s)), 'muted');
      } else html = line('Nothing found yet — hit Scan', 'muted');
      if (el.dataset.html !== html) { el.innerHTML = html; el.dataset.html = html; }
    }
    // Tools (half height): the DHCP server's state with the TFTP server's badge beside it, then the tool names on one line
    {
      const el = tileEls.tools;
      const d = st && st.dhcp;
      let html;
      if (!st) html = line('Loading…', 'muted');
      else {
        // the TFTP server (status.tftp, its summary) only earns room while it runs or has an error: green "on", yellow
        // "uploads on", red "error" with the error as the hover title, until the server starts again
        const t = st.tftp;
        const tftp = t && (t.running || t.error)
          ? ' <span class="badge ' + (t.error ? 'red">TFTP error' : t.uploads ? 'yellow">TFTP uploads' : 'green">TFTP on') + '</span>'
          : '';
        if (!d || d.available === false) html = line('<span class="strong">DHCP server</span> <span class="muted">unavailable</span>' + tftp);
        else if (d.error) html = line('<span class="strong">DHCP server</span> <span class="badge red">error</span>' + tftp, '', String(d.error));
        else if (d.running) {
          const p = d.pool || {};
          const n = d.bound || 0;
          html = line('<span class="num">' + n + '</span><span class="muted">DHCP client' + (n === 1 ? '' : 's') + '</span>' +
            (d.offered ? ' <span class="badge yellow">' + d.offered + ' offered</span>' : '') + tftp,
            '', 'Pool ' + (p.start || '?') + '–' + (p.end || '?'));
        } else html = line('<span class="strong">DHCP server</span> <span class="muted">off</span>' + tftp);
        // the tools by name on one ellipsized line: the half-height tile has no room for the old grid of names
        html += line('<span class="tile-ellipsis muted" title="' + esc(TOOLS_TILE_ITEMS.join(', ')) + '">' + esc(TOOLS_TILE_ITEMS.join(' · ')) + '</span>');
      }
      if (el.dataset.html !== html) { el.innerHTML = html; el.dataset.html = html; }
    }
    // WiFi: the survey runs inside the TNT window and arrives through the pywebview bridge
    // (TNT.wifiSurvey in views/wifi.js), never through the service status
    {
      const el = tileEls.wifi;
      const ws = TNT.wifiSurvey, wv = TNT.views.wifi, wc = TNT.wifichart;
      const sum = ws && wv && wc ? wv.tileSummary(ws.last, ws.bridgeState(), ws.error) : { kind: 'nobridge', headline: 'Open in the TNT window', detail: '' };
      let html;
      if (sum.kind === 'ok') {
        const t = sum.top;
        // two spans so a narrow tile wraps "30 APs" onto its own line instead of the whole phrase
        html = line('<span class="num">' + sum.networks + '</span><span class="muted">' + (sum.networks === 1 ? 'network' : 'networks') + ' ·</span><span class="muted">' + sum.aps + (sum.aps === 1 ? ' AP' : ' APs') + '</span>');
        if (t) {
          let bars = '<span class="survey-bars ' + t.cls + '" aria-hidden="true">';
          for (let i = 1; i <= 4; i++) bars += '<span' + (i <= t.bars ? ' class="on"' : '') + '></span>';
          bars += '</span>';
          // half height: the strongest (or connected) network, its bars and its signal share one line
          html += line(bars + '<span class="strong tile-ellipsis" title="' + esc(t.name) + (t.connected ? ' (connected)' : '') + '">' + esc(t.name) + '</span>' +
            '<span class="strong">' + esc(wc.dbmText(t.rssi)) + '</span>');
        } else html += line('Nothing in range right now', 'muted');
      } else if (sum.kind === 'waiting' || sum.kind === 'starting') {
        html = line(esc(sum.headline), 'muted');
      } else {
        html = line('<span class="strong">' + esc(sum.headline) + '</span>') + (sum.detail ? line(esc(sum.detail), 'muted') : '');
      }
      if (el.dataset.html !== html) { el.innerHTML = html; el.dataset.html = html; }
    }
    // Reports: the saved site reports (counts cached by loadReportsInfo, never fetched here) and, while one runs, the
    // full scan's phase and percentage in place of the last report's age
    {
      const el = tileEls.reports;
      const info = reportsInfo;
      const job = fullScan.job;
      let html;
      if (!info.loaded) html = line('Loading…', 'muted');
      else if (info.error && !info.total) html = line('<span class="strong">Reports</span> <span class="muted">unavailable</span>') + line(esc(info.error), 'muted');
      else if (!info.total) html = line('<span class="strong">No reports yet</span>') + line('Full Scan saves the first one', 'muted');
      else {
        html = line('<span class="num">' + info.total + '</span><span class="muted">' + (info.total === 1 ? 'report' : 'reports') + ' ·</span><span class="muted">' +
          info.sites + (info.sites === 1 ? ' site' : ' sites') + '</span>');
      }
      // half height: the second line is the running scan, else the newest report's site and age
      if (job && job.status === 'running') {
        html += line('<span class="spark-icon">' + ICONS.spark + '</span> <span class="strong">Full scan</span> ' + esc(RU.jobButton(job).label));
      } else if (info.loaded && info.last) {
        html += line('<span class="strong tile-ellipsis" title="' + esc(info.last.site) + '">' + esc(info.last.site) + '</span><span class="muted">' +
          esc(relTime(info.last.created_ts, now)) + '</span>');
      }
      if (el.dataset.html !== html) { el.innerHTML = html; el.dataset.html = html; }
    }
    // Packet capture (half height): the live capture's state and count, else the saved files
    {
      const el = tileEls.capture;
      const c = st && st.capture;
      let html;
      if (!st) html = line('Loading…', 'muted');
      else if (!c || c.available === false) html = line('<span class="strong">Packet capture</span>') + line(esc((c && c.reason) || 'Unavailable'), 'muted');
      else if (c.running) {
        html = line('<span class="spark-icon">' + ICONS.spark + '</span> <span class="strong">Capturing</span> <span class="muted">on</span> ' +
          '<span class="tile-ellipsis">' + esc(c.adapter || '') + '</span>') +
          line('<span class="num">' + (c.packets || 0) + '</span><span class="muted">packets</span>' +
            (c.calls ? ' <span class="badge yellow">' + c.calls + ' SIP call' + (c.calls === 1 ? '' : 's') + '</span>' : ''));
      } else {
        const n = c.files || 0;
        html = line('<span class="strong">Not capturing</span>') +
          line(n ? '<span class="num">' + n + '</span><span class="muted">saved capture' + (n === 1 ? '' : 's') + '</span>' : 'Pick an adapter and start', 'muted');
      }
      if (el.dataset.html !== html) { el.innerHTML = html; el.dataset.html = html; }
    }
    // Pro AV (half height): the worst finding of the last scan, or what it found
    {
      const el = tileEls.proav;
      const p = st && st.proav;
      const WORST = { bad: ['red', 'to fix'], warn: ['yellow', 'to check'], info: ['blue', 'noted'], good: ['green', 'all good'] };
      let html;
      if (!st) html = line('Loading…', 'muted');
      else if (!p || p.available === false) html = line('<span class="strong">Pro AV</span>') + line(esc((p && p.reason) || 'Unavailable'), 'muted');
      else if (p.running) {
        html = line('<span class="spark-icon">' + ICONS.spark + '</span> <span class="strong">Listening…</span> ' +
          Math.round((p.pct || 0) * 100) + '%') + line('Dante, AES67 and the clock', 'muted');
      } else if (!p.last_run_ts) {
        html = line('<span class="strong">Not scanned</span>') + line('Find Dante, AES67 and the clock', 'muted');
      } else {
        const worst = WORST[p.worst] || ['grey', 'no findings'];
        html = line('<span class="num">' + (p.devices || 0) + '</span><span class="muted">device' + ((p.devices === 1) ? '' : 's') + '</span>' +
          (p.streams ? ' <span class="num">' + p.streams + '</span><span class="muted">stream' + (p.streams === 1 ? '' : 's') + '</span>' : '')) +
          line('<span class="badge ' + worst[0] + '">' + worst[1] + '</span>' +
            (p.clock ? ' <span class="tile-ellipsis muted">clock: ' + esc(p.clock) + '</span>' : ' <span class="muted">no clock heard</span>'));
      }
      if (el.dataset.html !== html) { el.innerHTML = html; el.dataset.html = html; }
    }
    // SIP (half height): the qualifier's verdict, the leg that decides it and how many calls the line carries
    {
      const el = tileEls.sip;
      const s = st && st.sip;
      const VERDICT = {
        excellent: ['green', 'excellent'], good: ['green', 'good'], fair: ['yellow', 'fair'],
        poor: ['red', 'poor'], bad: ['red', 'bad'], unknown: ['grey', 'not rated'],
      };
      let html;
      if (!st) html = line('Loading…', 'muted');
      else if (!s || s.available === false) html = line('<span class="strong">SIP</span>') + line(esc((s && s.reason) || 'Unavailable'), 'muted');
      else {
        const v = VERDICT[s.verdict] || VERDICT.unknown;
        // the grade and the three numbers a call is judged by, off the leg that limits it - and
        // nothing else. Which leg that was is on the SIP page, where there is room to act on it;
        // on a tile it only ever appeared for some verdicts, so the line moved as the grade changed.
        const nums = [];
        if (typeof s.mos === 'number') nums.push('<span class="num">' + s.mos.toFixed(2) + '</span><span class="muted">MOS</span>');
        if (typeof s.avg_ms === 'number') nums.push('<span class="num">' + fmtMs(s.avg_ms) + '</span><span class="muted">ms</span>');
        if (typeof s.jitter_ms === 'number') nums.push('<span class="num">' + fmtMs(s.jitter_ms) + '</span><span class="muted">jitter</span>');
        html = line('<span class="badge ' + v[0] + '">' + v[1] + '</span>');
        html += nums.length ? line(nums.join(' ')) : '';
        if (!nums.length) {
          // no graded leg: the checks' verdicts, or the invitation, rather than an empty second line
          const bits = [];
          if (s.alg === 'alg') bits.push('<span class="badge red">SIP ALG</span>');
          else if (s.alg === 'clean') bits.push('<span class="badge green">no ALG</span>');
          if (s.nat === 'address-dependent') bits.push('<span class="badge red">symmetric NAT</span>');
          html += line(bits.length ? bits.join(' ')
            : (s.sip_host ? '<span class="tile-ellipsis muted">' + esc(s.sip_host) + '</span>' : 'Qualify the line for calls'),
            bits.length ? '' : 'muted');
        }
      }
      if (el.dataset.html !== html) { el.innerHTML = html; el.dataset.html = html; }
    }
  }

  /** Hide the tiles of tools that are switched off, and leave the page if the open one just went. Called on
   *  every status read: the switch can be flipped in another window, or by another TNT on the same service. */
  function syncTools() {
    const tiles = $('#tiles');
    if (!tiles) return;
    let changed = false;
    for (const name of TOOLS) {
      const tile = tiles.querySelector('a.tile[data-view="' + name + '"]');
      if (!tile) continue;
      const on = toolOn(name);
      if (tile.hidden !== !on) { tile.hidden = !on; changed = true; }
    }
    if (changed) {
      // the squares are hidden, not rebuilt: buildJumps() appends its row and registers the scroll listeners,
      // so calling it again would leave two rows and two listeners behind
      for (const [view, a] of Object.entries(jumps.items || {})) a.hidden = !toolOn(view);
      syncJumps();
    }
    if (current.name && !toolOn(current.name)) {
      toast(TOOL_NAMES[current.name] + ' is switched off in Settings', 'warn');
      location.hash = '#ipinfo';
    }
  }

  /* ===================================================== tile shortcuts */
  /* One small square per tile, in the tile's own colour, in the header's own row between the wordmark
     and the status pill. They ride up into view as the last tile scrolls up behind the header and sink
     back down when the page returns to the tiles or one of them is clicked, so there is always a way
     back to another section without scrolling up first. Built from the tiles themselves: a new tile in
     index.html gets a shortcut for free. */
  //: the one word under the icon where the tile's own title is two (everything else uses its first word)
  const JUMP_NAMES = { ipinfo: 'Network', capture: 'Capture', proav: 'ProAV' };
  const JUMP_HIDE_PX = 12;   //: they go back down once this much of the tiles is under the header again
  const jumps = { root: null, items: {}, on: false };

  function buildJumps() {
    const root = $('#tile-jumps'), tiles = $('#tiles');
    if (!root || !tiles) return;
    const row = h('div', { class: 'tile-jumps-row' });
    for (const tile of tiles.querySelectorAll('a.tile:not([hidden])')) {
      const name = tile.dataset.view;
      const titleEl = tile.querySelector('.tile-title'), iconHost = tile.querySelector('.tile-icon');
      const title = titleEl ? titleEl.textContent.trim() : name;
      const a = h('a', {
        class: 'tile-jump', href: tile.getAttribute('href') || '#' + name, title: title,
        data: { view: name }, style: { '--accent': ACCENT[name] || 'var(--blue)' },
      }, iconEl(iconHost && iconHost.dataset.icon ? iconHost.dataset.icon : 'info'),
         h('span', { class: 'tile-jump-label' }, JUMP_NAMES[name] || title.split(/\s+/)[0]));
      jumps.items[name] = a;
      row.appendChild(a);
    }
    root.appendChild(row);
    jumps.root = root;
    // a shortcut takes the page back to the top, where the tiles themselves are in view again
    root.addEventListener('click', (e) => {
      if (!e.target.closest('a.tile-jump')) return;
      setJumps(false);
      window.scrollTo({ top: 0 });
    });
    // a scroll event already arrives at most once a frame, so this reads the two edges and nothing more
    window.addEventListener('scroll', syncJumps, { passive: true });
    window.addEventListener('resize', syncJumps, { passive: true });
  }
  /** Show the squares exactly while the tiles are out of sight — their bottom edge up behind the
   *  sticky header. A few pixels of hysteresis so a scroll that stops on the line cannot flicker. */
  function syncJumps() {
    if (!jumps.root) return;
    const tiles = $('#tiles'), bar = $('#topbar');
    if (!tiles || tiles.hidden) { setJumps(false); return; }
    const gone = tiles.getBoundingClientRect().bottom - (bar ? bar.getBoundingClientRect().bottom : 0);
    if (gone <= 0) setJumps(true);
    else if (gone >= JUMP_HIDE_PX) setJumps(false);
  }
  function setJumps(on) {
    if (!jumps.root || jumps.on === on) return;
    jumps.on = on;
    jumps.root.classList.toggle('on', on);
  }
  //: the shortcut of the section being shown wears the tile's own active tint
  function markJumps(name) {
    for (const [view, a] of Object.entries(jumps.items)) {
      const on = view === name;
      a.classList.toggle('active', on);
      if (on) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    }
  }

  /* ============================================================== router */
  let current = { name: null, view: null };
  function notifyView() {
    if (current.view && current.view.update) { try { current.view.update(state); } catch (e) { console.error('view update failed', e); } }
  }
  /** Scroll position for a freshly shown view: the top of the page, except after a tile click on
   *  a short window (1366x768 at 125 % is 1093x614 CSS px, 1280x720 at 150 % is 853x480) where the
   *  tiles fill most of the screen and the click would change nothing visible. Then the
   *  section heading comes up under the sticky header; the view gets a min-height so the page is
   *  tall enough to scroll there before its data arrives. The first route on load, the brand
   *  link and Diagnostics' Back keep the top of the page. */
  let tileNav = false;   // set by a click on a tile, consumed by the hashchange it causes
  function revealView(view, fromTile) {
    view.style.minHeight = '';
    window.scrollTo({ top: 0 });
    if (!fromTile) return;
    const vh = window.innerHeight;
    const top = view.getBoundingClientRect().top;
    if (vh - top >= vh / 3) return;
    const bar = $('#topbar');
    const barH = bar ? bar.getBoundingClientRect().height : 0;
    view.style.minHeight = Math.max(0, vh - barH - 12) + 'px';
    window.scrollTo({ top: Math.max(0, top - barH - 12) });
  }

  function showView(name, fromTile) {
    const tiles = $('#tiles'), view = $('#view'), diag = $('#diagnostics');
    tiles.hidden = false; view.hidden = false; diag.hidden = true;
    for (const t of tiles.querySelectorAll('.tile')) {
      const on = t.dataset.view === name;
      t.classList.toggle('active', on);
      if (on) t.setAttribute('aria-current', 'page'); else t.removeAttribute('aria-current');
    }
    markJumps(name);
    syncJumps();
    if (current.name === name) return;
    if (current.view && current.view.unmount) { try { current.view.unmount(); } catch (e) { console.error('unmount failed', e); } }
    view.innerHTML = '';
    view.style.setProperty('--accent', ACCENT[name] || 'var(--blue)');
    const v = TNT.views[name];
    current = { name, view: v };
    state.view = name;
    if (!v) { view.appendChild(h('div', { class: 'card' }, emptyState('This section is not available.'))); return; }
    try { v.mount(view); v.update(state); }
    catch (e) { console.error('mount failed', e); view.appendChild(h('div', { class: 'card' }, emptyState('This section failed to load. See the console.'))); }
    revealView(view, fromTile);
  }
  function route() {
    const fromTile = tileNav;
    tileNav = false;
    const hash = (location.hash || '').replace(/^#/, '').split('?')[0];
    if (hash === 'diagnostics') { showDiagnostics(); return; }
    // Network info is the landing page, and it is also where a tool that has been switched off sends you
    const name = VIEW_NAMES.includes(hash) && toolOn(hash) ? hash : 'ipinfo';
    if (hash !== name) { history.replaceState(null, '', '#' + name); }
    showView(name, fromTile);
  }

  /* ========================================================= diagnostics */
  let diagText = '';
  function showDiagnostics() {
    $('#tiles').hidden = true; $('#view').hidden = true; $('#diagnostics').hidden = false;
    for (const t of $('#tiles').querySelectorAll('.tile')) t.classList.remove('active');
    markJumps(null);
    setJumps(false);   // no tiles on this page, so nothing to jump back to
    if (current.view && current.view.unmount) { try { current.view.unmount(); } catch (e) { console.error(e); } }
    current = { name: 'diagnostics', view: null };
    state.view = 'diagnostics';
    $('#view').innerHTML = '';
    loadDiagnostics();
    window.scrollTo({ top: 0 });
  }
  function fmtValue(k, v) {
    if (v == null) return '—';
    if (typeof v === 'number' && /(_ts|^ts)$/.test(k) && v > 1e9) return fmtStamp(v) + '  (' + v + ')';
    if (typeof v === 'number' && /bytes/.test(k)) return fmtBytes(v) + '  (' + v + ')';
    if (typeof v === 'number' && /_s$/.test(k) && v > 90) return fmtDuration(v) + '  (' + v + ')';
    if (typeof v === 'boolean') return v ? 'yes' : 'no';
    if (Array.isArray(v) || typeof v === 'object') return JSON.stringify(v, null, 2);
    return String(v);
  }
  function objectText(obj, indent) {
    indent = indent || '';
    if (obj == null) return indent + '—';
    if (typeof obj !== 'object') return indent + String(obj);
    const keys = Object.keys(obj);
    const width = Math.min(22, Math.max.apply(null, keys.map((k) => k.length).concat([4])));
    const out = [];
    for (const k of keys) {
      const v = obj[k];
      if (v && typeof v === 'object' && !Array.isArray(v)) {
        out.push(indent + k + ':');
        out.push(objectText(v, indent + '  '));
      } else if (Array.isArray(v) && v.length && typeof v[0] === 'object') {
        out.push(indent + k + ': (' + v.length + ')');
        for (const item of v) out.push(indent + '  - ' + Object.entries(item).map(([ik, iv]) => ik + '=' + (typeof iv === 'object' ? JSON.stringify(iv) : fmtValue(ik, iv).split('  (')[0])).join('  '));
      } else {
        out.push(indent + (k + ':').padEnd(width + 2) + fmtValue(k, v).replace(/\n/g, '\n' + indent + ' '.repeat(width + 2)));
      }
    }
    return out.join('\n');
  }
  async function loadDiagnostics() {
    const body = $('#diag-body');
    const btn = $('#diag-refresh');
    busy(btn, true);
    body.innerHTML = '';
    body.appendChild(h('div', { class: 'empty' }, 'Collecting diagnostics…'));
    const [d, l] = await Promise.allSettled([api.diagnostics(), api.diagnosticsLog(200)]);
    busy(btn, false);
    body.innerHTML = '';
    const parts = [];
    const section = (title, text, scroll) => {
      parts.push('== ' + title + ' ==\n' + text);
      return h('div', { class: 'diag-section' }, h('h3', null, title), h('pre', { class: 'diag-pre' + (scroll ? ' scroll' : '') }, text));
    };
    if (d.status === 'fulfilled' && d.value) {
      const diag = d.value;
      const grid = h('div', { class: 'diag-grid' });
      const order = ['service', 'os', 'api', 'db', 'logs', 'ping', 'outages', 'speedtest', 'discovery'];
      for (const k of order) if (diag[k] !== undefined) grid.appendChild(section(k, objectText(diag[k])));
      const misc = {};
      for (const k of Object.keys(diag)) if (!order.includes(k) && !['threads', 'recent_log', 'recent_events'].includes(k)) misc[k] = diag[k];
      if (Object.keys(misc).length) grid.appendChild(section('process', objectText(misc)));
      body.appendChild(grid);
      if (Array.isArray(diag.threads)) {
        const rows = diag.threads.map((t) => (t.name || '').padEnd(34) + (t.alive ? 'alive ' : 'dead  ') + (t.daemon ? 'daemon' : '')).join('\n');
        body.appendChild(section('threads (' + diag.threads.length + ')', rows, true));
      }
      if (Array.isArray(diag.recent_events)) {
        const rows = diag.recent_events.map((e) => fmtStamp(e.ts) + ' ' + String(e.level || '').toUpperCase().padEnd(8) + String(e.category || '').padEnd(10) + ' ' + e.message).join('\n') || '(none)';
        body.appendChild(section('recent events', rows, true));
      }
      if (Array.isArray(diag.recent_log)) {
        const rows = diag.recent_log.map((r) => fmtStamp(r.ts) + ' ' + String(r.level || '').padEnd(8) + r.message).join('\n') || '(none)';
        body.appendChild(section('recent log (in-memory ring)', rows, true));
      }
    } else {
      const err = d.status === 'rejected' ? d.reason : null;
      body.appendChild(h('div', { class: 'card' }, emptyState('Could not load diagnostics' + (err && err.message ? ': ' + err.message : ''))));
    }
    if (l.status === 'fulfilled' && l.value) {
      const lines = (l.value.lines || []).join('\n') || '(empty)';
      body.appendChild(section('log tail — ' + (l.value.file || ''), lines, true));
    } else if (l.status === 'rejected') {
      body.appendChild(section('log tail', 'Could not read the log: ' + (l.reason && l.reason.message)));
    }
    diagText = 'TNT diagnostics — ' + fmtStamp(nowS()) + '\n\n' + parts.join('\n\n');
  }

  /* ============================================================ settings */
  function settingRow(title, sub, control) {
    return h('div', { class: 'setting' }, h('div', { class: 'desc' }, h('span', { class: 't' }, title), sub ? h('span', { class: 's' }, sub) : null),
      h('div', { class: 'setting-control' }, control));
  }
  function group(title, children) {
    return h('div', { class: 'setting-group' }, h('h3', null, title), children);
  }
  /** A section of settings that belong to one main tile: the tile's own accent, icon and name, so there is
   *  never a question which page a setting is about. The accent is set on the section, so every toggle and
   *  button inside it picks the tile's colour up from --accent rather than naming a colour of its own. */
  function tileGroup(view, title, children) {
    const box = h('div', { class: 'setting-group tile-group', style: { '--accent': ACCENT[view] || 'var(--blue)' } },
      h('h3', null, h('span', { class: 'tg-icon' }, iconEl(TILE_ICONS[view] || 'info')), title), children);
    box.dataset.view = view;
    return box;
  }
  async function saveSettings(patch, okText) {
    try {
      const r = await api.updateSettings(patch);
      if (r && r.settings) state.settings = r.settings;
      toast(okText || 'Saved', 'ok', 1600);
      notifyView();
      refreshStatus();
      return true;
    } catch (err) { toast('Could not save: ' + err.message, 'error'); return false; }
  }
  async function openSettings() {
    if (!state.settings) await loadSettings();
    const s = state.settings || { ping: {}, speedtest: {}, targets: {}, ui: {} };
    const st = state.status || {};
    const body = h('div', { class: 'modal-body' });

    /* ---- Tools: what this site actually uses. First, because everything under it is a setting for something
       that may not be switched on at all. A tool that is off has no tile, no page and no automated action. */
    const toolRows = TOOLS.map((name) => {
      const on = toolOn(name);
      const t = toggle({ checked: on, on: 'On', off: 'Off', accent: ACCENT[name] || 'var(--blue)',
        onChange: (v, input) => saveSettings({ tools: { [name]: v } },
          TOOL_NAMES[name] + (v ? ' is on' : ' is off')).then((ok) => {
            if (!ok) { input.checked = !v; return; }
            if (state.status) state.status.tools = Object.assign({}, state.status.tools || {}, { [name]: v });
            syncTools();
            refreshStatus();
          }) });
      t.input.setAttribute('aria-label', TOOL_NAMES[name]);
      return h('div', { class: 'setting tool-row', style: { '--accent': ACCENT[name] || 'var(--blue)' } },
        h('div', { class: 'desc' },
          h('span', { class: 't' }, h('span', { class: 'tg-icon' }, iconEl(TILE_ICONS[name] || 'info')), TOOL_NAMES[name]),
          h('span', { class: 's' }, TOOL_WHAT[name])),
        h('div', { class: 'setting-control' }, t));
    });
    body.appendChild(group('Tools', [
      h('p', { class: 'muted small set-intro' },
        'Switch off what this site never uses. A tool that is off has no tile and no page, and its background '
        + 'work stops too — no scheduled speed tests, no section for it in a Full Scan.'),
      ...toolRows,
    ]));

    /* ---- App-wide, above the per-tile sections. */
    const themeT = toggle({ checked: state.theme === 'dark', on: 'Dark', off: 'Light', onChange: (v) => setTheme(v ? 'dark' : 'light') });
    themeT.id = 'settings-theme-toggle';
    const pausedT = toggle({ checked: !st.paused, on: 'Running', off: 'Paused',
      onChange: async (v, input) => {
        try { await (v ? api.resume() : api.pause()); toast(v ? 'Monitoring resumed' : 'Monitoring paused', v ? 'ok' : 'warn'); refreshStatus(); }
        catch (err) { toast(err.message, 'error'); input.checked = !v; }
      } });
    body.appendChild(group('General', [
      settingRow('Theme', 'Remembered on this PC and in the service settings.', themeT),
      settingRow('Monitoring', 'Pause all pinging. Outages are not detected while paused.', pausedT),
    ]));

    // Updates (GitHub releases): check, notify and self-install; the download is verified (SHA-256) before it runs
    const up = s.update || {};
    const upT = toggle({ checked: up.enabled !== false, on: 'On', off: 'Off',
      onChange: (v, input) => saveSettings({ update: { enabled: v } }, v ? 'Update checks on' : 'Update checks off').then((ok) => { if (!ok) input.checked = !v; }) });
    upT.input.setAttribute('aria-label', 'Check for updates');
    const upAutoT = toggle({ checked: up.auto_install === true, on: 'Auto', off: 'Ask',
      onChange: (v, input) => saveSettings({ update: { auto_install: v } }, v ? 'Updates install automatically' : 'Updates ask before installing').then((ok) => { if (!ok) input.checked = !v; }) });
    upAutoT.input.setAttribute('aria-label', 'Install updates automatically');
    const upEvery = h('input', { class: 'input', type: 'number', min: '1', max: '168', step: '1', value: String(up.check_interval_h || 24), 'aria-label': 'Check interval in hours' });
    upEvery.addEventListener('change', () => {
      const v = Math.max(1, Math.min(168, parseInt(upEvery.value, 10) || 24));
      upEvery.value = String(v);
      saveSettings({ update: { check_interval_h: v } }, 'Checking every ' + v + ' h');
    });
    const upChannel = h('select', { class: 'input', 'aria-label': 'Update channel' },
      [['stable', 'Stable releases'], ['prerelease', 'Include pre-releases']].map(([v, l]) => h('option', { value: v, selected: (up.channel || 'stable') === v }, l)));
    upChannel.addEventListener('change', () => saveSettings({ update: { channel: upChannel.value } }, 'Channel: ' + upChannel.options[upChannel.selectedIndex].text));
    const upCheck = h('button', { class: 'btn', id: 'settings-update-check', type: 'button' }, 'Check now');
    upCheck.addEventListener('click', () => {
      upCheck.disabled = true;
      api.updateCheck().then(() => renderSettingsUpdate(), () => toast('Could not check for updates', 'error'))
        .then(() => renderSettingsUpdate());
    });
    body.appendChild(group('Updates', [
      settingRow('Check for updates', 'Watches this project’s GitHub releases page. When a newer release is out, a banner offers to install it. The installer is verified against the release’s SHA-256 checksum before it runs.', upT),
      settingRow('When an update is found', 'Ask (show the banner and wait for you) or install automatically at the next check.', upAutoT),
      settingRow('Check every', 'Hours between checks (1–168).', h('div', { class: 'row inline-unit' }, upEvery, h('span', { class: 'muted small' }, 'h'))),
      settingRow('Channel', 'Stable releases only, or include pre-releases for early builds.', upChannel),
      h('div', { class: 'geo-status' }, h('span', { id: 'settings-update', role: 'status' }, updateSettingsText(updateState(), state.now)), upCheck),
    ]));

    /* ---- One section per tile, in the tile's own colour, for the settings that belong to that page. */

    // Network info (blue): what its page shows, and the IP location data behind its WAN chip and Traceroute
    const ipv6T = toggle({ checked: !!(s.ui && s.ui.show_ipv6), on: 'Shown', off: 'Hidden',
      onChange: (v, input) => saveSettings({ ui: { show_ipv6: v } }, v ? 'IPv6 addresses are shown' : 'IPv6 addresses are hidden').then((ok) => { if (!ok) input.checked = !v; }) });
    ipv6T.input.setAttribute('aria-label', 'Show IPv6 addresses');
    const geoT = toggle({ checked: !(s.geoip && s.geoip.enabled === false), on: 'On', off: 'Off',
      onChange: (v, input) => saveSettings({ geoip: { enabled: v } }, v ? 'IP location on' : 'IP location off').then((ok) => { if (!ok) input.checked = !v; }) });
    geoT.input.setAttribute('aria-label', 'Show IP location and ISP');
    const geoRetry = h('button', { class: 'btn', id: 'settings-geoip-retry', type: 'button', hidden: !geoipRetryVisible() }, 'Retry now');
    geoRetry.addEventListener('click', () => {
      geoRetry.disabled = true;
      api.geoipCheck().then(() => renderSettingsGeoip(), () => toast('Could not start the IP location check', 'error'))
        .then(() => { geoRetry.disabled = false; });
    });
    body.appendChild(tileGroup('ipinfo', 'Network info', [
      settingRow('IPv6 addresses', 'Show IPv6 addresses and subnets on the Network info page, and IPv6 addresses in DNS lookups on the Tools page.', ipv6T),
      settingRow('Location and ISP', 'Shows the internet provider and city of the public address on Network info and a Location column in Traceroute. The service downloads DB-IP’s free IP location data (CC BY 4.0): about 65 MB a month, about 140 MB on disk. Addresses are looked up on this PC only.', geoT),
      h('div', { class: 'geo-status' }, h('span', { id: 'settings-geoip', role: 'status' }, geoipStatusText()), geoRetry, geoAttribution(), geoLicence()),
    ]));

    // Ping (green): how it pings, and what Load Default Tiles resets to
    const loadedT = toggle({ checked: !!(s.ping && s.ping.loaded), on: 'Loaded', off: 'Unloaded',
      onChange: (v, input) => saveSettings({ ping: { loaded: v } }, v ? 'Pings are now loaded (' + (s.ping.loaded_bytes || 1200) + ' B)' : 'Pings are now unloaded (' + (s.ping.unloaded_bytes || 32) + ' B)').then((ok) => { if (!ok) input.checked = !v; }) });
    // the gateway chip names the address the gateway tile pings right now (renderSettingsGateway keeps it current)
    const chips = h('div', { class: 'chips' }, h('span', { class: 'badge blue', id: 'settings-gateway', style: { '--accent': 'var(--blue)' } }, gatewayChipText()),
      copyCode('1.1.1.1'), copyCode('totalelectronics.com'));
    body.appendChild(tileGroup('ping', 'Ping', [
      settingRow('Ping payload', 'Loaded sends ' + (s.ping && s.ping.loaded_bytes || 1200) + '-byte pings (stresses the link a little); unloaded sends ' + (s.ping && s.ping.unloaded_bytes || 32) + ' bytes.', loadedT),
      settingRow('Default targets', 'Load Default Tiles on the Ping page resets the tiles to these. Other tiles are removed (after a confirmation); their history stays in the database.', null),
      chips,
    ]));

    // Speed (purple): only while the tool is on — its settings are meaningless when nothing runs
    if (toolOn('speed')) {
      const sp = s.speedtest || {};
      const enabledT = toggle({ checked: sp.enabled !== false, on: 'On', off: 'Off',
        onChange: (v, input) => saveSettings({ speedtest: { enabled: v } }, v ? 'Automatic speed tests on' : 'Automatic speed tests off').then((ok) => { if (!ok) input.checked = !v; }) });
      enabledT.input.setAttribute('aria-label', 'Automatic speed tests');
      const interval = h('input', { class: 'input', type: 'number', min: '1', max: '1440', step: '1', value: String(sp.interval_min || 15), 'aria-label': 'Speed test interval in minutes' });
      interval.addEventListener('change', () => {
        const v = Math.max(1, Math.min(1440, parseInt(interval.value, 10) || 15));
        interval.value = String(v);
        saveSettings({ speedtest: { interval_min: v } }, 'Speed tests every ' + v + ' min');
      });
      const backend = h('select', { class: 'input', 'aria-label': 'Speed test backend' },
        [['auto', 'Auto (Cloudflare, else fast.com)'], ['cloudflare', 'Cloudflare'], ['fastcom', 'fast.com']].map(([v, l]) => h('option', { value: v, selected: (sp.backend || 'auto') === v }, l)));
      backend.addEventListener('change', () => saveSettings({ speedtest: { backend: backend.value } }, 'Backend: ' + backend.options[backend.selectedIndex].text));
      body.appendChild(tileGroup('speed', 'Speed', [
        settingRow('Automatic tests', 'Runs in the background even when this window is closed.', enabledT),
        settingRow('Interval', 'Minutes between tests (1–1440).', h('div', { class: 'row inline-unit' }, interval, h('span', { class: 'muted small' }, 'min'))),
        settingRow('Backend', 'Both are built in. If one refuses a test (rate limit), the other runs instead.', backend),
      ]));
    }

    // SIP (sand): the host every part of that page defaults to
    if (toolOn('sip')) {
      const sip = s.sip || {};
      const sipHost = h('input', { class: 'input', type: 'text', value: String(sip.host || ''), placeholder: 'pbx.example.net', 'aria-label': 'SIP host' });
      sipHost.addEventListener('change', () => saveSettings({ sip: { host: sipHost.value.trim() } },
        sipHost.value.trim() ? 'SIP host: ' + sipHost.value.trim() : 'SIP host cleared'));
      const sipPort = h('input', { class: 'input', type: 'number', min: '1', max: '65535', step: '1', value: String(sip.port || 5060), 'aria-label': 'SIP port' });
      sipPort.addEventListener('change', () => {
        const v = Math.max(1, Math.min(65535, parseInt(sipPort.value, 10) || 5060));
        sipPort.value = String(v);
        saveSettings({ sip: { port: v } }, 'SIP port ' + v);
      });
      body.appendChild(tileGroup('sip', 'SIP', [
        settingRow('Your SIP host', 'The PBX, SBC or registrar this site registers to. Named, it is graded as its own leg in the qualifier and is what the ALG check probes.', sipHost),
        settingRow('SIP port', 'The port that host answers SIP on (5060 unless somebody moved it).', sipPort),
      ]));
    }

    /* ---- Service, last. */
    const diagBtn = h('button', { class: 'btn', type: 'button' }, iconEl('info'), 'Diagnostics');
    const repoLink = h('a', { class: 'btn', href: TNT_REPO_URL, rel: 'noreferrer' }, iconEl('spark'), 'TNT on GitHub');
    repoLink.addEventListener('click', (e) => openExternal(e, TNT_REPO_URL));
    const svcInfo = h('div', { class: 'kv' },
      h('span', { class: 'k' }, 'Version'), h('span', { class: 'v' }, copyCode(st.version || '—')),
      h('span', { class: 'k' }, 'Uptime'), h('span', { class: 'v' }, st.uptime_s != null ? fmtDuration(st.uptime_s) + ' (' + (st.mode || '') + ')' : '—'),
      h('span', { class: 'k' }, 'API'), h('span', { class: 'v' }, copyCode(location.origin)));
    body.appendChild(group('Service', [svcInfo, h('div', { class: 'row' }, repoLink), h('div', { class: 'row' }, diagBtn)]));

    const m = modal({ title: 'Settings', body });
    diagBtn.addEventListener('click', () => { m.close(); location.hash = '#diagnostics'; });
  }
  function blobToBase64(blob) {
    return new Promise((resolve, reject) => {
      const fr = new FileReader();
      fr.onload = () => { const s = String(fr.result || ''); resolve(s.slice(s.indexOf(',') + 1)); };
      fr.onerror = () => reject(fr.error || new Error('read failed'));
      fr.readAsDataURL(blob);
    });
  }
  async function saveBlob(blob, name) {
    const bridge = window.pywebview && window.pywebview.api && typeof window.pywebview.api.save_file === 'function';
    if (bridge) {
      const b64 = await blobToBase64(blob);
      const path = await window.pywebview.api.save_file(name, b64);
      if (path) toast('Saved ' + path, 'ok', 5000); else toast('Save cancelled', 'warn');
      return;
    }
    const url = URL.createObjectURL(blob);
    const a = h('a', { href: url, download: name, style: { display: 'none' } });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 20000);
    toast('Downloaded ' + name, 'ok');
  }

  /* =========================================================== full scan */
  // The page's one full-scan controller (its logic is TNT.reportsui.createFullScan in js/reportsui.js). It lives here
  // and not in the Reports view, so moving between pages never breaks a scan: it follows the service's job, runs the
  // Wi-Fi part through the TNT window's bridge and posts the one snapshot. The top bar's Full Scan button shows its
  // progress; the Reports tile shows the saved reports' counts, cached here from /api/reports and refreshed on the
  // report.* events (renderTiles never fetches).
  const RU = TNT.reportsui;
  const fullScan = RU.createFullScan({ api, survey: TNT.wifiSurvey || null, live: () => api.events.state === 'live' });
  const reportsInfo = { loaded: false, error: null, total: 0, sites: 0, last: null };
  let reportsInfoTimer = null, siteModal = null, fullScanStarting = false;

  async function loadReportsInfo() {
    try {
      // one row of each is enough: both answers carry a total that counts every report and every site
      const [list, sites] = await Promise.all([api.reports({ limit: 1 }), api.reportSites('', 1)]);
      reportsInfo.total = Number(list && list.total) || 0;
      reportsInfo.last = (list && Array.isArray(list.reports) && list.reports[0]) || null;
      reportsInfo.sites = Number(sites && sites.total) || 0;
      reportsInfo.error = null;
    } catch (err) {
      reportsInfo.error = err && err.status === 404 ? 'Not in this TNT version' : (err && err.message) || 'Could not load';
    }
    reportsInfo.loaded = true;
    renderTiles();
  }
  function scheduleReportsInfo() {
    if (reportsInfoTimer) clearTimeout(reportsInfoTimer);
    reportsInfoTimer = setTimeout(() => { reportsInfoTimer = null; loadReportsInfo(); }, 300);
  }

  /** The job a status snapshot carries (status.reports.job): without the event stream it is how this page hears of a scan started
   *  from another window, in time to run its Wi-Fi part. Only a job the controller does not follow yet, or the end of the one it
   *  follows, is taken: a snapshot can be older than the progress events already applied. */
  function adoptStatusJob(job) {
    if (!job || job.id == null) return;
    const mine = fullScan.job;
    if (!mine || mine.id !== job.id || (mine.status === 'running' && job.status !== 'running')) fullScan.apply(job);
  }

  function onFullScanJob(job, prev) {
    renderTiles();
    // the name modal's pre-filled site follows a suggestion that arrives late or changes, until the user types
    if (siteModal && job) siteModal.sync(job);
    // a scan that ended while the event stream was down reaches the page through a poll: the counts change too
    if (prev && prev.status === 'running' && (!job || job.id !== prev.id || job.status !== 'running')) scheduleReportsInfo();
  }

  /** Reports on screen: the hash change (like a tile click, so a short window scrolls to the view), or the progress
   *  card brought into view when the page is open already. */
  function goReports() {
    if (current.name === 'reports') { if (current.view && current.view.reveal) current.view.reveal(); return; }
    tileNav = true;
    location.hash = '#reports';
  }

  /** The Full Scan buttons (top bar and Reports page): while a scan runs they only open Reports; otherwise they open
   *  Reports, start a full scan and ask for the site name. A scan another window started (409 busy) is followed. */
  async function fullScanClick() {
    goReports();
    if (fullScan.running() || fullScanStarting) return;
    fullScanStarting = true;
    try {
      const r = await fullScan.start();
      if (!r.started) toast('A full scan is already running', 'warn');
      if (r.job && r.job.status === 'running' && !r.job.site) openSiteModal();
    } catch (err) {
      toast('Could not start the full scan: ' + err.message, 'error');
    } finally { fullScanStarting = false; }
  }

  /** Name the running scan's site; a scan that saved its report meanwhile gets that report renamed instead. */
  async function nameFullScan(site) {
    const job = fullScan.job;
    if (job && job.status === 'saved' && job.report_id != null) {
      await api.renameReport(job.report_id, site);
      toast('Report renamed to ' + site, 'ok');
      return;
    }
    try {
      await fullScan.setSite(site);
    } catch (err) {
      await fullScan.refresh();
      const j = fullScan.job;
      if (err.status === 409 && j && j.status === 'saved' && j.report_id != null) {
        await api.renameReport(j.report_id, site);
        toast('Report renamed to ' + site, 'ok');
        return;
      }
      throw err;
    }
  }

  /** The site name modal of a running full scan: the name field with earlier sites as suggestions, "Save name" and
   *  "Cancel scan" (after a confirm). On a network an earlier report was made on, the field starts with that report's site,
   *  selected. Closing it any other way keeps the scan running: the progress card on the Reports page offers the same field,
   *  and a report saved without a name goes under the suggested site, else "Unnamed site" until renamed. */
  function siteModalChanged() {
    if (current.name === 'reports' && current.view && current.view.siteModalChanged) {
      try { current.view.siteModalChanged(); } catch (e) { console.error(e); }
    }
  }

  function openSiteModal() {
    if (siteModal) { siteModal.combo.focus(); return; }
    const job = fullScan.job;
    // a network an earlier report was made on: its site fills the field (Save name confirms it, typing replaces it)
    let suggested = RU.suggestedSite(job);
    const combo = RU.siteCombo({ label: 'Site name', placeholder: 'e.g. Acme Dental', value: (job && job.site) || (suggested ? suggested.site : ''),
      describedBy: 'site-modal-hint', fetchSites: (q) => api.reportSites(q, 50).then((r) => (r && r.sites) || []), onEnter: () => save() });
    const saveBtn = h('button', { class: 'btn btn-primary', type: 'button' }, iconEl('check'), 'Save name');
    const cancelBtn = h('button', { class: 'btn btn-danger', type: 'button' }, iconEl('stop'), 'Cancel scan');
    // what the report adds (its window's rule), and the window itself, so a wrong one (this PC not noticed moving) can be spotted
    const intro = h('p', { class: 'muted site-modal-intro' });
    const windowLine = h('p', { class: 'muted small site-modal-window' });
    const hint = h('p', { class: 'muted small site-modal-hint', id: 'site-modal-hint' });
    // a phone hotspot or travel router carried from site to site: nothing is suggested for it and only this connection counts
    const portable = h('input', { type: 'checkbox', id: 'site-modal-portable' });
    const portableRow = h('label', { class: 'site-modal-portable', for: 'site-modal-portable' }, portable,
      h('span', null, 'This network is my own hotspot or travel router, carried from site to site'));
    let hintText = null;
    const renderJob = (j) => {
      intro.textContent = RU.modalIntro(j);
      const since = RU.jobWindowText(j, (ts) => fmtDateTime(ts));
      windowLine.textContent = since ? 'Pings and outages ' + since + '.' : '';
      windowLine.hidden = !since;
      const net = j && j.network_id != null && j.network && typeof j.network === 'object' ? j.network : null;
      portableRow.hidden = !net;
      if (!portable.disabled) portable.checked = !!(net && net.portable);
      const parts = RU.suggestionHint(j, (ts) => fmtDate(ts) + ' (' + relTime(ts) + ')');
      const text = parts ? parts.join('') : 'Earlier sites are suggested as you type: pick one to add this scan to its reports.';
      if (text === hintText) return;
      hintText = text;
      hint.innerHTML = '';
      if (parts) hint.append(parts[0], h('strong', null, parts[1]), parts[2]);
      else hint.textContent = text;
    };
    renderJob(job);
    portable.addEventListener('change', async () => {
      const j = fullScan.job;
      if (!j || j.network_id == null) return;
      const want = portable.checked;
      portable.disabled = true;
      try {
        await api.setNetworkPortable(j.network_id, want);        // the service suggests again and publishes the job
        toast(want ? 'No site is suggested for this network any more' : 'This network is treated as a site\'s network again', 'ok');
      } catch (err) { portable.checked = !want; toast('Could not change the network: ' + err.message, 'error'); }
      finally { portable.disabled = false; }
    });
    const body = h('div', { class: 'site-modal-body' }, intro, windowLine,
      h('div', { class: 'field' }, h('label', { for: combo.input.id }, 'Site name'), combo.el),
      hint, portableRow);
    const m = modal({ title: 'Name this site', body, narrow: true, foot: [cancelBtn, saveBtn],
      onEscape: () => combo.isOpen(), onClose: () => { combo.destroy(); siteModal = null; siteModalChanged(); } });
    m.el.classList.add('site-modal');
    // the modal focuses the field first (a zero timer too): select a pre-filled site after it, so typing replaces it
    if (combo.value()) setTimeout(() => { try { combo.input.focus(); combo.input.select(); } catch (e) { /* closed already */ } }, 0);
    /** A later job: a suggestion that arrived late (the router's MAC read after the scan started) or changed (its report renamed
     *  or deleted) replaces the pre-filled site, never text the user typed. */
    function sync(j) {
      const was = suggested ? suggested.site : '';
      suggested = RU.suggestedSite(j);
      renderJob(j);
      const next = suggested ? suggested.site : '';
      if (next === was || j.site || combo.touched() || (combo.value() && combo.value() !== was)) return;
      const focused = document.activeElement === combo.input;
      combo.setValue(next);
      if (focused && next) { try { combo.input.select(); } catch (e) { /* ignore */ } }
    }
    siteModal = { m, combo, sync };
    siteModalChanged();
    async function save() {
      const site = combo.value();
      if (!site) { toast('Type the site name, or close this to name it later', 'warn'); combo.focus(); return; }
      busy(saveBtn, true, 'Saving…');
      try {
        await nameFullScan(site);
        m.close('saved');
      } catch (err) { toast('Could not save the name: ' + err.message, 'error'); }
      finally { busy(saveBtn, false); }
    }
    saveBtn.addEventListener('click', save);
    cancelBtn.addEventListener('click', async () => {
      const ok = await confirmDialog({ title: 'Cancel the full scan?', message: 'The scan stops and no report is saved.', ok: 'Cancel scan', cancel: 'Keep scanning', danger: true });
      if (!ok) return;
      busy(cancelBtn, true, 'Cancelling…');
      try { await fullScan.cancel(); toast('Full scan cancelled', 'warn'); m.close('cancelled'); }
      catch (err) { toast('Could not cancel the scan: ' + err.message, 'error'); }
      finally { busy(cancelBtn, false); }
    });
  }

  /* ========================================================= quick tools */
  // The Quick Tools row at the top of the Tools page (views/tools.js builds the buttons with these ids and calls
  // TNT.app.quickRun) holds IP Release/Renew and Flush DNS. They run their tool on the service with one click. While it runs the button is
  // disabled and says so ("Renewing…"); then its background flashes green (done) or red (failed or refused, with a toast:
  // api.quick.outcome). A release/renew changes this PC's addresses: the status and the open view's netChanged hook run as
  // soon as it answers, not after the settle delay of a net.changed event (the one the service publishes still comes).
  const QUICK_FLASH_MS = 1600;
  const QUICK_TOOLS = {
    // the service answers a release/renew once every DHCP adapter is done: a couple of minutes when a DHCP server does not answer
    renew: { id: 'btn-ip-renew', busyLabel: 'Renewing…', run: () => api.ipRenew(),
      busyTitle: "Releasing and renewing this PC's IP addresses… this can take a couple of minutes when a DHCP server does not answer" },
    flush: { id: 'btn-flush-dns', busyLabel: 'Flushing…', run: () => api.flushDns(), busyTitle: "Flushing this PC's DNS cache…" },
  };
  const quickState = { renew: { busy: false, timer: null }, flush: { busy: false, timer: null } };
  // the service pauses monitoring around a release/renew: its monitoring.paused events are part of the renew, not news, so they
  // show no toast while it runs and for a few seconds after it answers (the resume can arrive just after the reply)
  const RENEW_QUIET_MS = 5000;
  let quietPauseUntil = 0;

  /** A quick tool's button while it runs: disabled, aria-busy, the short label and a tooltip saying what it waits for, kept at
   *  the width it had. */
  function quickBusy(btn, tool, on) {
    const label = btn.querySelector('.quick-label');
    if (on) {
      btn.style.minWidth = btn.offsetWidth + 'px';
      if (label) { label.dataset.idle = label.textContent; label.textContent = QUICK_TOOLS[tool].busyLabel; }
      btn.title = QUICK_TOOLS[tool].busyTitle;
      btn.setAttribute('aria-busy', 'true');
    } else {
      btn.style.minWidth = '';
      if (label && label.dataset.idle !== undefined) { label.textContent = label.dataset.idle; delete label.dataset.idle; }
      btn.removeAttribute('aria-busy');
    }
    btn.disabled = on;
  }

  /** The green (done) or red (failed) flash of a button's background; another flash starts it over. */
  function quickFlash(btn, tool, ok) {
    const st = quickState[tool];
    btn.classList.remove('flash-ok', 'flash-bad');
    void btn.offsetWidth;
    btn.classList.add(ok ? 'flash-ok' : 'flash-bad');
    if (st.timer) clearTimeout(st.timer);
    st.timer = setTimeout(() => { st.timer = null; btn.classList.remove('flash-ok', 'flash-bad'); }, QUICK_FLASH_MS);
  }

  /** The Quick Tools row was just mounted (or re-mounted): show a tool that is still running as busy again. The row only
   *  exists while the Tools page is open, so a run started before leaving it finds a fresh button when it comes back. */
  function quickSync() {
    for (const tool of Object.keys(QUICK_TOOLS)) {
      const btn = $('#' + QUICK_TOOLS[tool].id);
      if (btn && quickState[tool].busy) quickBusy(btn, tool, true);
    }
  }

  /** Runs a quick tool ('renew' | 'flush'); a click while it runs is ignored. */
  async function quickRun(tool) {
    const q = QUICK_TOOLS[tool], st = quickState[tool];
    const started = q ? $('#' + q.id) : null;
    if (!started || st.busy) return;
    st.busy = true;
    if (started.dataset.idleTitle === undefined) started.dataset.idleTitle = started.title;
    const hadFocus = document.activeElement === started;
    quickBusy(started, tool, true);
    if (tool === 'renew') quietPauseUntil = Infinity;
    let result = null, error = null;
    try { result = await q.run(); } catch (err) { error = err; }
    st.busy = false;
    if (tool === 'renew') quietPauseUntil = Date.now() + RENEW_QUIET_MS;
    // the Tools page may have been left and opened again while the tool ran: finish on the button that is on the page now
    const btn = $('#' + q.id) || started;
    if (btn.dataset.idleTitle === undefined) btn.dataset.idleTitle = btn.title;
    quickBusy(btn, tool, false);
    if (hadFocus && document.activeElement === document.body) { try { btn.focus(); } catch (e) { /* ignore */ } }
    const o = api.quick.outcome(tool, result, error);
    quickFlash(btn, tool, o.ok);
    toast(o.text, o.kind, o.ok ? 4000 : 8000);
    const ts = result && typeof result.ts === 'number' ? result.ts : nowS();
    btn.title = btn.dataset.idleTitle + '\nLast run ' + fmtTime(ts) + (o.ok ? ': done' : ': failed');
    if (tool !== 'renew') return;
    // done or not, this PC's addresses may have changed: the header, the tiles and the open page read them now
    refreshStatus();
    if (current.view && current.view.netChanged) {
      try { current.view.netChanged({ source: 'renew', changes: [] }, state); } catch (e) { console.error('view netChanged failed', e); }
    }
  }

  /* ================================================================ SSE */
  let lightsDirty = false;
  function wireEvents() {
    const ev = api.events;
    ev.onState((s) => { state.live = s; renderHeader(); });
    ev.on('hello', () => { refreshStatus(); loadSettings(); });
    ev.on('status.poll', (st) => { if (st) applyStatus(st); else { state.apiOk = false; renderHeader(); } });
    ev.on('ping.sample', (d) => {
      if (!d) return;
      const t = state.targets.find((x) => x.id === d.target_id);
      if (!t) return;
      t.light = d.light || t.light;
      t.last = { ts: d.ts, ok: d.ok, rtt_ms: d.rtt_ms };
      if (!lightsDirty) { lightsDirty = true; requestAnimationFrame(() => { lightsDirty = false; renderHeader(); renderTiles(); }); }
    });
    ev.on('ping.targets', (d) => { if (d && Array.isArray(d.targets)) setTargets(d.targets); });
    // this PC moved to another network, or an adapter's configuration changed: patch the dashboard from the
    // payload at once, then the shared refresh (toast, status, the open view's netChanged)
    ev.on('net.changed', (d) => {
      if (!d || typeof d !== 'object') return;
      const r = api.net.fromEvent(lastNet, d, Date.now());
      lastNet = r.next;
      if (!r.fresh) return;                  // a status snapshot brought this generation already
      if (state.status) {
        // the adapter shown without an internet one is the old network's too: the status read below brings the new one
        state.status.netinfo = Object.assign({}, state.status.netinfo || {}, { internet_nic: api.net.nicFromEvent(d), local_nic: null });
        state.status.net = Object.assign({}, state.status.net || {}, { generation: d.generation, changed_ts: d.ts,
          default_gateway: d.default_gateway || null, internet_nic: d.internet_nic ? d.internet_nic.name : null });
      }
      networkChanged(Object.assign({ source: 'event' }, d), true);
    });
    const outageWho = (d) => {
      const o = (d && d.outage) || d || {};
      const kind = o.kind || 'target';
      if (kind === 'total_internet') return { kind, name: 'Internet' };
      if (kind === 'total_local') return { kind, name: 'Local network' };
      const t = state.targets.find((x) => x.id === o.target_id);
      return { kind, name: o.host || (t ? targetName(t) : 'A target') };
    };
    ev.on('outage.start', (d) => { const w = outageWho(d); const full = w.kind.startsWith('total'); toast(full ? w.name + ' outage!' : w.name + ' is down', full ? 'error' : 'warn'); refreshStatus(); });
    ev.on('outage.end', (d) => { const w = outageWho(d); toast(w.name + (w.kind.startsWith('total') ? ' is back' : ' recovered'), 'ok'); refreshStatus(); });
    ev.on('speedtest.start', () => { if (state.status && state.status.speed) { state.status.speed.running = true; state.status.speed.progress = { phase: 'starting', pct: 0 }; renderTiles(); } });
    ev.on('speedtest.progress', (d) => { if (state.status && state.status.speed && d) { state.status.speed.running = true; state.status.speed.progress = d; renderTiles(); } });
    // a full scan's own speed test and Discovery scan are on its progress card: no toasts over it
    ev.on('speedtest.done', (d) => {
      const r = d && d.result;
      if (r && !fullScan.running()) toast(r.ok ? 'Speed test: ↓ ' + fmtMbps(r.download_mbps) + ' ↑ ' + fmtMbps(r.upload_mbps) + ' Mbps' : 'Speed test failed: ' + (r.error || 'unknown error'), r.ok ? 'ok' : 'warn');
      if (state.status && state.status.speed) state.status.speed.running = false;
      refreshStatus();
    });
    ev.on('discovery.progress', (d) => { if (state.status && state.status.discovery && d) { state.status.discovery.progress = d; state.status.discovery.running = d.phase !== 'done'; renderTiles(); } });
    // network_changed: this PC changed networks while the scan ran, so it swept (part of) the network it left
    ev.on('discovery.done', (d) => {
      const moved = d && d.network_changed ? ' · this PC changed networks during the scan' : '';
      if (fullScan.running()) { /* on the full scan's progress card */ }
      else if (d && !d.cancelled) toast('Scan finished' + (d.found != null ? ': ' + d.found + ' devices' : '') + moved, moved ? 'warn' : 'ok');
      else if (d) toast('Scan cancelled' + moved, 'warn');
      refreshStatus();
    });
    ev.on('settings.changed', () => { loadSettings(); refreshStatus(); });
    // DHCP server (Tools tile): dhcp.state carries the /status summary fields, leases bump the counts
    ev.on('dhcp.state', (d) => { if (state.status && d) { state.status.dhcp = Object.assign({}, state.status.dhcp || {}, d); renderTiles(); } });
    // TFTP server (Tools tile): tftp.state carries its summary (running, uploads, error), merged the same way
    ev.on('tftp.state', (d) => { if (state.status && d) { state.status.tftp = Object.assign({}, state.status.tftp || {}, d); renderTiles(); } });
    // the Pro AV scan: the tile follows the job, and the open page is handed the same event
    // a speed test finishing changes the SIP page's capacity figure and its call-quality lines
    ev.on('speedtest.done', () => {
      const view = TNT.views.sip;
      if (current.name === 'sip' && view && view.onEvent) { try { view.onEvent('speedtest.done'); } catch (e) { console.error(e); } }
    });
    for (const name of ['proav.state', 'proav.progress']) {
      ev.on(name, (d) => {
        const job = d && d.job;
        if (state.status && job) {
          state.status.proav = Object.assign({}, state.status.proav || {}, {
            running: job.state === 'scanning', pct: job.pct,
          });
          renderTiles();
        }
        const view = TNT.views.proav;
        if (current.name === 'proav' && view && view.onEvent) { try { view.onEvent(name, d); } catch (e) { console.error(e); } }
      });
    }
    // IP location: geoip.state is STATUS (the service adds its bus ts to every SSE payload; the development server does not)
    ev.on('geoip.state', (d) => { if (state.status && d) { const { ts, ...st } = d; state.status.geoip = Object.assign({}, state.status.geoip || {}, st); renderSettingsGeoip(); notifyView(); } });
    // auto-update: update.state is STATUS (the service adds its bus ts; the development server does not)
    ev.on('update.state', (d) => { if (state.status && d) { const { ts, ...st } = d; state.status.update = Object.assign({}, state.status.update || {}, st); renderUpdateBanner(); renderSettingsUpdate(); } });
    ev.on('dhcp.lease', () => { if (state.status && state.status.dhcp && state.status.dhcp.running) refreshStatus(); });
    ev.on('monitoring.paused', (d) => { refreshStatus(); if (d && Date.now() >= quietPauseUntil) toast(d.paused ? 'Monitoring paused' : 'Monitoring resumed', d.paused ? 'warn' : 'ok'); });
    // Reports: the full scan's progress drives the controller (which runs the Wi-Fi part); saves, renames and deletions
    // refresh the tile's counts. The stream has no replay: a (re)connect reads the job again.
    ev.on('report.progress', (d) => { if (d && d.job) fullScan.apply(d.job); });
    ev.on('report.saved', (d) => {
      if (d) toast('Report saved: ' + (d.site || 'site') + (d.status === 'partial' ? ' (partial)' : ''), d.status === 'partial' ? 'warn' : 'ok');
      scheduleReportsInfo();
      fullScan.refresh();
    });
    ev.on('report.deleted', scheduleReportsInfo);
    // renaming the report the last scan saved renames that job too (the progress card shows its site): read it again
    ev.on('report.updated', (d) => { scheduleReportsInfo(); if (d && fullScan.job && fullScan.job.report_id === d.id) fullScan.refresh(); });
    ev.on('hello', () => { fullScan.refresh(); scheduleReportsInfo(); });
    ev.connect();
  }

  /* ================================================================ boot */
  function boot() {
    state.theme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    $('#brand-logo').appendChild(iconEl('dynamite'));
    $('#live-spark').appendChild(iconEl('spark'));
    $('#btn-settings').appendChild(iconEl('gear'));
    for (const el of document.querySelectorAll('[data-icon]')) { el.appendChild(iconEl(el.dataset.icon)); }
    for (const name of VIEW_NAMES) tileEls[name] = $('#tile-' + name);
    // index.html already carries `half` (so there is no flash of full-height tiles before this runs); setting it
    // again from HALF_TILES keeps the markup and the list that renderTiles reasons about from drifting apart
    for (const name of HALF_TILES) { const tile = $('a.tile[data-view="' + name + '"]'); if (tile) tile.classList.add('half'); }
    buildJumps();   // after the tiles carry their final classes: the strip is built from them

    $('#btn-settings').addEventListener('click', openSettings);
    fullScan.subscribe(onFullScanJob);
    $('#diag-refresh').addEventListener('click', loadDiagnostics);
    $('#diag-copy').addEventListener('click', () => copyText(diagText || 'No diagnostics loaded'));
    $('#diag-back').addEventListener('click', () => { location.hash = '#ipinfo'; });

    // click-to-copy for any value
    document.addEventListener('click', (e) => {
      const t = e.target.closest('code.copy, td.copy, [data-copy]');
      if (!t) return;
      if (e.target.closest('button, a[href], input, select')) return;
      const text = t.dataset.copy != null ? t.dataset.copy : t.textContent.trim();
      if (text && text !== '—') copyText(text);
    });
    // keyboard: "?" focuses nothing special; Escape handled by modals

    // a tile click that changes the hash may scroll its view into sight on a short window (revealView)
    $('#tiles').addEventListener('click', (e) => {
      const tile = e.target.closest('a.tile');
      if (tile && !e.defaultPrevented && tile.getAttribute('href') !== location.hash) tileNav = true;
    });
    window.addEventListener('hashchange', route);
    wireEvents();
    refreshStatus();
    loadSettings();
    loadReportsInfo();
    fullScan.refresh();
    route();
    // the WiFi tile's summary: a cheap bridge read every 15 s while the WiFi page is not open
    if (TNT.wifiSurvey) TNT.wifiSurvey.startTilePolling(() => renderTiles());

    setInterval(() => {
      state.now = nowS();
      renderTiles();
      if (state.live === 'live' && Date.now() - lastStatusTs > 10000) refreshStatus();
      if (state.live !== 'live' && !api.events._pollTimer && Date.now() - lastStatusTs > 5000) refreshStatus();
    }, 1000);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) { refreshStatus(); if (TNT.charts) TNT.charts.rerenderAll(); } });
  }

  TNT.app = { state, refreshStatus, loadSettings, showView, openSettings, showDiagnostics, setTheme, saveBlob, overallText, setTargets, quickRun,
    quickSync, QUICK_TOOL_IDS: { renew: QUICK_TOOLS.renew.id, flush: QUICK_TOOLS.flush.id },
    fullScan, fullScanClick, openSiteModal, nameFullScan, loadReportsInfo: scheduleReportsInfo, siteModalOpen: () => !!siteModal };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
