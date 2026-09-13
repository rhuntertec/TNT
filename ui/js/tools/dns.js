/* TNT — tools/dns.js
   The "DNS" card of the Tools view: a DNS name or IP address and, next to it, an optional DNS server, looked
   up the way "nslookup <name> [<server>]" does it (POST /api/tools/dns/lookup: the service asks the DNS server
   itself, never the hosts file or the Windows cache; this PC's own DNS server unless one is typed). The
   answer: a summary line (the answer name and how many addresses, or the error in red), the server that was
   asked with a "non-authoritative" badge, every address as a copy chip with an IPv4 / IPv6 badge, the aliases
   and a Details table of the answer records, unfolded with every new answer. An IP address as the name is a
   reverse (PTR) lookup. A Record type select right after the name asks for one type instead of Auto (A + AAAA),
   like "nslookup -type=MX": the summary then counts that type ("example.com has 2 mail servers", SOA names the
   primary name server and the serial) and its records show as copy chips. "All record types" (the second option, right
   below Auto) asks for every type at once and groups the answer by type. Picking SRV puts an SRV name in the
   name field's placeholder, and an SRV lookup that found nothing for a name without the service in front says how
   SRV names start. While Settings › Appearance hides IPv6 (ui.show_ipv6, off by default, the same switch as
   Network info) the IPv6 addresses and AAAA records are left out and the summary says how many were hidden, except
   in a reverse lookup and an AAAA lookup, where they are what was asked for.
   The name, the type and the server are checked here first with the service's rules (validName / validType /
   validServer), so a typo gets its message under the form without a round trip. Enter in either text field runs the
   lookup; Clear (next to Look up) empties the lookup (the name, the server and the type) and the answer.
   Loaded before app.js: TNT.util / TNT.ui are only touched inside functions. */
(function () {
  'use strict';
  window.TNT = window.TNT || {};
  const TNT = window.TNT;
  TNT.tools = TNT.tools || {};

  const NAME_MAX = 253;
  const LABEL_RE = /^[A-Za-z0-9_-]{1,63}$/;
  const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const IDLE_TEXT = 'No lookup yet — type a name or an IP address and hit Look up';
  const OWN_SERVER = "this PC's DNS server";
  const V6_HIDDEN_TITLE = 'IPv6 addresses are hidden — turn them on under Settings > Appearance';
  /** The record types a lookup can ask for, in the service's order (tnt/nettools.py DNS_TYPES); none is Auto. */
  const TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'CAA', 'PTR', 'NAPTR'];
  /** The Record type select, in this order: [value, label]. "All record types" (ALL) sits second, right below Auto. */
  const TYPE_OPTIONS = [['', 'Auto (A + AAAA)'], ['ALL', 'All record types'], ['A', 'A — IPv4 address'], ['AAAA', 'AAAA — IPv6 address'], ['CNAME', 'CNAME — alias'],
    ['MX', 'MX — mail servers'], ['TXT', 'TXT — text (SPF, verification)'], ['NS', 'NS — name servers'], ['SOA', 'SOA — zone serial'],
    ['SRV', 'SRV — services (SIP…)'], ['CAA', 'CAA — certificate authorities'], ['PTR', 'PTR — name of an address'], ['NAPTR', 'NAPTR — SIP routing']];
  const IP_TYPE_TEXT = 'An IP address is looked up as PTR: type a DNS name to ask for other record types';
  const SRV_HINT = 'SRV names start with the service, for example _sip._tcp.example.com';
  /** What a typed lookup counts in its summary ("example.com has 2 name servers"): [one, many]. */
  const TYPE_NOUNS = { A: ['IPv4 address', 'IPv4 addresses'], AAAA: ['IPv6 address', 'IPv6 addresses'], MX: ['mail server', 'mail servers'],
    TXT: ['TXT record', 'TXT records'], NS: ['name server', 'name servers'], SOA: ['SOA record', 'SOA records'], SRV: ['SRV record', 'SRV records'],
    CAA: ['CAA record', 'CAA records'], NAPTR: ['NAPTR record', 'NAPTR records'], CNAME: ['CNAME record', 'CNAME records'], PTR: ['PTR record', 'PTR records'] };
  let seq = 0;               // ids for aria-controls / aria-describedby, one set per card

  /* ------------------------------------------------ pure helpers (tests) */
  /** A dotted-quad IPv4 address (no leading zeros, like the service's parser). */
  function isIpv4(text) { return IPV4_RE.test(String(text)); }

  /** An IPv6 address: groups of 1-4 hex digits, eight of them or one "::" standing for the missing ones, an IPv4 tail
   *  (two groups) and a %zone allowed. */
  function isIpv6(text) {
    let s = String(text);
    const pct = s.indexOf('%');
    if (pct >= 0) {
      const zone = s.slice(pct + 1);
      if (!zone || zone.includes('%')) return false;
      s = s.slice(0, pct);
    }
    const colon = s.lastIndexOf(':');
    if (colon < 0) return false;
    const tail = s.slice(colon + 1);
    if (tail.includes('.')) {
      if (!isIpv4(tail)) return false;
      s = s.slice(0, colon + 1) + '0:0';
    }
    const halves = s.split('::');
    if (halves.length > 2) return false;
    const groups = halves.map((part) => (part === '' ? [] : part.split(':')));
    const all = groups[0].concat(groups[1] || []);
    if (!all.every((g) => /^[0-9A-Fa-f]{1,4}$/.test(g))) return false;
    return halves.length === 2 ? all.length <= 7 : all.length === 8;
  }

  /** A host name by the service's rules: labels of letters, digits, "_" and "-" (1-63 each, none starting or ending with
   *  "-") joined by single dots, 253 characters at most, one trailing dot allowed. A label with non-ASCII letters is let
   *  through: the service turns such a name into punycode first and checks that. */
  function isHostName(text) {
    let s = String(text);
    if (s.endsWith('.')) s = s.slice(0, -1);
    if (!s || s.length > NAME_MAX || s.startsWith('-')) return false;
    return s.split('.').every((label) => {
      if (!label || label.startsWith('-') || label.endsWith('-')) return false;
      if (/[^\x00-\x7F]/.test(label)) return /^[A-Za-z0-9_-]*$/.test(label.replace(/[^\x00-\x7F]/g, ''));
      return LABEL_RE.test(label);
    });
  }

  /** The first 80 characters of what was typed, for a message (whole characters, never half of one). */
  function cut(text) { return Array.from(String(text)).slice(0, 80).join(''); }

  /** An address or a host name by the service's rules (one trailing dot allowed on either). */
  function isNameOrAddress(s) {
    const body = s.endsWith('.') ? s.slice(0, -1) : s;
    return isIpv4(body) || isIpv6(body) || isHostName(s);
  }

  /** { ok: true, name } for a name the service looks up (trimmed), else { ok: false, error } with the service's message. */
  function validName(text) {
    const s = String(text == null ? '' : text).trim();
    if (!s) return { ok: false, error: 'Type a DNS name or IP address to look up' };
    if (isNameOrAddress(s)) return { ok: true, name: s };
    return { ok: false, error: '"' + cut(s) + '" is not a DNS name or IP address' };
  }

  /** { ok: true, server } ('' asks this PC's own DNS server), else { ok: false, error } with the service's message. */
  function validServer(text) {
    const s = String(text == null ? '' : text).trim();
    if (!s) return { ok: true, server: '' };
    if (isNameOrAddress(s)) return { ok: true, server: s };
    return { ok: false, error: '"' + cut(s) + '" is not a DNS server name or IP address' };
  }

  /** Settings › Appearance › IPv6 addresses (ui.show_ipv6): hidden until the settings say otherwise, like Network info. */
  function showIpv6(state) {
    const st = state || TNT.state;
    return !!(st && st.settings && st.settings.ui && st.settings.ui.show_ipv6);
  }

  /** { ok: true, type } for the Record type select ('' is Auto, else the type's upper-case name), else { ok: false, error } with
   *  the service's message: a value that is not one of TYPES, or an IP address (`name`, as validName returned it) with a type
   *  other than PTR. */
  function validType(text, name) {
    const s = String(text == null ? '' : text).trim();
    if (s && !TYPES.includes(s.toUpperCase()) && s.toUpperCase() !== 'ALL') {
      return { ok: false, error: '"' + cut(s) + '" is not a DNS record type (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA, PTR or NAPTR)' };
    }
    const type = s.toUpperCase();
    const body = String(name == null ? '' : name).trim().replace(/\.$/, '');
    // an IP address is a PTR lookup: Auto and ALL allow it, every other type does not
    if (type && type !== 'PTR' && type !== 'ALL' && (isIpv4(body) || isIpv6(body))) return { ok: false, error: IP_TYPE_TEXT };
    return { ok: true, type };
  }

  /** Pure: what the result block shows for one DNS_RESULT, as text: { ok, cls, reverse, type, summary, asked (null when no
   *  server was asked), nonAuthoritative, addresses: [{ address, family }], hiddenV6, aliases, values, groups, hint,
   *  records: [{ type, name, value, ttl }] }. type is the answer's record type ('' for Auto, 'ALL' for all record types).
   *  opts.showIpv6 false leaves out the IPv6 addresses and the AAAA records, except where they are what was asked for (the
   *  address of a reverse lookup, an AAAA lookup); hiddenV6 is how many addresses were left out. A typed lookup's summary
   *  counts its own type ("example.com has 1 mail server"; SOA names the primary name server and the serial, CNAME and PTR the
   *  name they point at); values are the records of that type as text (none for Auto, A and AAAA, which keep the address
   *  chips); an ALL lookup's summary is "<answer> — N records across M types" and groups are its records per non-address type
   *  (in TYPES order), A/AAAA still shown as addresses; hint is SRV_HINT after an SRV lookup that found none for a name whose
   *  first label does not start with "_". */
  function resultView(r, opts) {
    r = r || {};
    const v6 = !(opts && opts.showIpv6 === false);
    const name = String(r.name || '');
    const type = r.type ? String(r.type).toUpperCase() : '';
    const reverse = (!type || type === 'PTR' || type === 'ALL') && (isIpv4(name) || isIpv6(name));
    const exempt = reverse || type === 'AAAA';
    const all = (Array.isArray(r.addresses) ? r.addresses : []).filter((a) => a != null && a !== '')
      .map((a) => ({ address: String(a), family: String(a).includes(':') ? 'IPv6' : 'IPv4' }));
    const addresses = v6 || exempt ? all : all.filter((a) => a.family === 'IPv4');
    const hiddenV6 = all.length - addresses.length;
    const n = addresses.length;
    const records = (Array.isArray(r.records) ? r.records : []).filter((x) => x && (v6 || exempt || String(x.type).toUpperCase() !== 'AAAA')).map((x) => ({
      type: String(x.type || '?'), name: String(x.name || ''), value: String(x.value == null ? '' : x.value),
      ttl: typeof x.ttl === 'number' && isFinite(x.ttl) ? Math.round(x.ttl) + ' s' : '—',
    }));
    const ofType = type ? records.filter((x) => x.type.toUpperCase() === type) : [];
    const answer = r.answer_name || name || '?';
    const noun = TYPE_NOUNS[type] || [type + ' record', type + ' records'];
    const count = (k) => k + ' ' + (k === 1 ? noun[0] : noun[1]);
    const soa = type === 'SOA' && ofType.length ? ofType[0].value.split(/\s+/) : [];
    // "All record types": the answer grouped by type (in TYPES order), A/AAAA still shown as addresses; PTR is not asked for
    const groups = type === 'ALL' && !reverse
      ? TYPES.filter((t) => t !== 'A' && t !== 'AAAA' && t !== 'PTR')
          .map((t) => ({ type: t, values: records.filter((x) => x.type.toUpperCase() === t).map((x) => x.value).filter((val) => val !== '') }))
          .filter((g) => g.values.length)
      : [];
    let summary;
    if (!r.ok) summary = (name ? name + ' — ' : '') + (r.error ? String(r.error) : 'the lookup failed');
    else if (reverse) summary = name + ' is ' + (r.answer_name || 'unnamed');
    else if (type === 'ALL') {
      const m = new Set(records.map((x) => x.type.toUpperCase())).size;
      summary = answer + ' — ' + records.length + (records.length === 1 ? ' record' : ' records') + ' across ' + m + (m === 1 ? ' type' : ' types');
    } else if (!type) summary = answer + ' has ' + n + (n === 1 ? ' address' : ' addresses');
    else if (type === 'A' || type === 'AAAA') summary = answer + ' has ' + count(n);
    else if (type === 'CNAME') summary = name + ' is an alias of ' + (r.answer_name || (ofType.length ? ofType[ofType.length - 1].value : '?'));
    else if (type === 'PTR') summary = name + ' is ' + (r.answer_name || (ofType.length ? ofType[0].value : 'unnamed'));
    else if (soa.length >= 3) summary = answer + ': primary name server ' + soa[0] + ', serial ' + soa[2];
    else summary = answer + ' has ' + count(ofType.length);
    const res = r.resolver || {};
    const who = res.name && res.address && res.name !== res.address ? res.name + ' (' + res.address + ')' : (res.address || res.name || '');
    const asked = who
      ? ['Asked ' + who, r.server ? '' : OWN_SERVER, typeof r.duration_ms === 'number' ? Math.round(r.duration_ms) + ' ms' : ''].filter(Boolean).join(' · ')
      : null;
    const aliases = (Array.isArray(r.aliases) ? r.aliases : []).filter(Boolean).map(String);
    const values = !type || type === 'A' || type === 'AAAA' || reverse ? [] : ofType.map((x) => x.value).filter(Boolean);
    const hint = type === 'SRV' && !ofType.length && !name.split('.')[0].startsWith('_') ? SRV_HINT : '';
    return { ok: !!r.ok, cls: r.ok ? 'ok' : 'bad', reverse, type, summary, asked, nonAuthoritative: r.authoritative === false, addresses, hiddenV6, aliases,
      values, groups, hint, records };
  }

  /* ------------------------------------------------------------- card */
  function create() {
    const { h } = TNT.util;
    const id = 'dns-' + (++seq);
    let mounted = false;
    let running = false;
    let runGen = 0;
    let asking = null;         // { name, server } of the lookup in flight
    let result = null;         // the last DNS_RESULT
    let failure = null;        // the last request failed before any answer (not a DNS error): its text
    let detailsOpen = false;   // Details: unfolded with every new answer, folded by its button
    let shownV6 = false;       // Settings › Appearance › IPv6 addresses, as the answer on screen was drawn
    const els = {};

    els.name = h('input', { class: 'input', type: 'text', placeholder: 'www.example.com', 'aria-label': 'DNS name or IP address', spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off' });
    els.type = h('select', { class: 'input', 'aria-label': 'Record type' }, TYPE_OPTIONS.map(([value, label]) => h('option', { value }, label)));
    // SRV names start with the service: while SRV is picked the name field shows one as its example
    els.type.addEventListener('change', () => {
      els.name.placeholder = els.type.value === 'SRV' ? '_sip._tcp.example.com' : 'www.example.com';
      clearInvalid(els.type);
      syncClear();                    // the type is part of what Clear resets
    });
    els.server = h('input', { class: 'input', type: 'text', placeholder: "this PC's DNS server, or 1.1.1.1", 'aria-label': 'DNS server (optional)', spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off' });
    els.runBtn = h('button', { class: 'btn btn-primary', type: 'button', on: { click: () => run() },
      title: 'Ask the DNS server for this name (or the name of this IP address), like nslookup: the hosts file and the Windows cache are left out' }, TNT.ui.icon('search'), 'Look up');
    els.clearBtn = h('button', { class: 'btn dns-clear', type: 'button', on: { click: () => clear() },
      title: 'Clear the lookup and the answer' }, TNT.ui.icon('close'), 'Clear');
    for (const input of [els.name, els.server]) {
      input.addEventListener('keydown', (e) => { if (e.key === 'Enter') run(); });
      input.addEventListener('input', () => { clearInvalid(input); syncClear(); });
    }
    // an IP address with a record type is refused on the select: another name may settle it
    els.name.addEventListener('input', () => clearInvalid(els.type));
    const form = h('div', { class: 'form-row tool-form dns-form' },
      h('div', { class: 'field wide' }, h('label', null, 'DNS name / IP address'), els.name),
      h('div', { class: 'field dns-type' }, h('label', null, 'Record type'), els.type),
      h('div', { class: 'field' }, h('label', null, 'DNS server (optional)'), els.server),
      els.runBtn, els.clearBtn);
    els.invalid = h('div', { class: 'tool-summary bad dns-invalid', id: id + '-invalid', role: 'alert', hidden: true });
    els.summary = h('div', { class: 'tool-summary muted', role: 'status', 'aria-live': 'polite' });
    els.asked = h('div', { class: 'dns-asked', hidden: true });
    els.addresses = h('div', { class: 'dns-addresses', hidden: true });
    els.values = h('div', { class: 'dns-values', hidden: true });
    els.groups = h('div', { class: 'dns-groups', hidden: true });
    els.hint = h('div', { class: 'tool-note dns-hint', hidden: true });
    els.aliases = h('div', { class: 'dns-aliases', hidden: true });
    els.detailsBtn = h('button', { class: 'btn btn-sm dns-details-btn', type: 'button', 'aria-expanded': 'false', 'aria-controls': id + '-records',
      title: 'The answer records: type, name, value and how long they may be cached',
      on: { click: () => { detailsOpen = !detailsOpen; render(); } } }, TNT.ui.icon('chevron'), h('span', null, 'Details'));
    els.tbody = h('tbody');
    els.tableWrap = h('div', { class: 'table-wrap', id: id + '-records', hidden: true },
      h('table', { class: 'table dns-table' },
        h('thead', null, h('tr', null, h('th', null, 'Type'), h('th', null, 'Name'), h('th', null, 'Value'), h('th', { class: 'num' }, 'TTL'))),
        els.tbody));
    els.details = h('div', { class: 'dns-details', hidden: true }, els.detailsBtn, els.tableWrap);
    const body = h('div', { class: 'tool-body' }, form, els.invalid, els.summary, els.hint, els.asked, els.addresses, els.values, els.groups, els.aliases, els.details);

    /* ---------------------------------------------------- validation */
    // the message under the form, tied to the field it is about (none for a refusal from the service)
    function showInvalid(message, input) {
      els.invalid.innerHTML = '';
      els.invalid.appendChild(TNT.ui.icon('warning'));
      els.invalid.appendChild(h('span', null, message));
      els.invalid.hidden = false;
      for (const el of [els.name, els.type, els.server]) {
        if (el === input) { el.setAttribute('aria-invalid', 'true'); el.setAttribute('aria-describedby', els.invalid.id); }
        else { el.removeAttribute('aria-invalid'); el.removeAttribute('aria-describedby'); }
      }
      syncClear();
      if (input) { try { input.focus(); } catch (e) { /* ignore */ } }
    }
    // typing in (or picking for) the field a message is about clears it (a refusal from the service goes with any typing)
    function clearInvalid(input) {
      if (els.invalid.hidden) return;
      if (input) { input.removeAttribute('aria-invalid'); input.removeAttribute('aria-describedby'); }
      if (![els.name, els.type, els.server].some((el) => el.hasAttribute('aria-invalid'))) els.invalid.hidden = true;
      syncClear();
    }
    // Clear has work while a lookup runs, an answer or a failure is on screen, a message is under the form, or anything is
    // typed in (a name or a server) or the type is not Auto
    function syncClear() {
      const typed = !!(els.name.value || els.server.value) || els.type.value !== '';
      els.clearBtn.disabled = !running && !result && !failure && els.invalid.hidden && !typed;
    }

    /* -------------------------------------------------------- render */
    function render() {
      if (!mounted) return;
      const { copyCode } = TNT.util;
      TNT.ui.busy(els.runBtn, running, 'Looking up…');
      syncClear();
      const v = !running && !failure && result ? resultView(result, { showIpv6: shownV6 }) : null;
      // the summary: the lookup in flight, a request that failed, the answer, or the idle hint
      els.summary.innerHTML = '';
      if (running) {
        els.summary.className = 'tool-summary live';
        els.summary.appendChild(h('span', { class: 'spark-icon' }, TNT.ui.icon('spark')));
        els.summary.appendChild(h('span', null, 'Asking ' + (asking.server || OWN_SERVER) + ' for ' + (asking.type ? 'the ' + asking.type + ' records of ' : '') + asking.name + '…'));
      } else if (failure) {
        els.summary.className = 'tool-summary bad';
        els.summary.appendChild(TNT.ui.icon('warning'));
        els.summary.appendChild(h('span', null, failure));
      } else if (v) {
        els.summary.className = 'tool-summary ' + v.cls;
        if (!v.ok) els.summary.appendChild(TNT.ui.icon('warning'));
        els.summary.appendChild(h('span', null, v.summary));
        // the IPv6 addresses Settings › Appearance leaves out: how many, and where to show them
        if (v.hiddenV6) els.summary.appendChild(h('span', { class: 'muted dns-v6-hidden', title: V6_HIDDEN_TITLE }, '· ' + v.hiddenV6 + ' IPv6 hidden'));
      } else {
        els.summary.className = 'tool-summary muted';
        els.summary.textContent = IDLE_TEXT;
      }
      // the server that answered
      els.asked.innerHTML = '';
      els.asked.hidden = !(v && (v.asked || v.nonAuthoritative));
      if (v && v.asked) els.asked.appendChild(h('span', null, v.asked));
      if (v && v.nonAuthoritative) {
        els.asked.appendChild(h('span', { class: 'badge grey', title: 'Answered from the DNS server’s cache, not by a server that holds this name’s zone' }, 'non-authoritative'));
      }
      // every address, a copy chip with its family
      els.addresses.innerHTML = '';
      const addrs = v ? v.addresses : [];
      els.addresses.hidden = !addrs.length;
      for (const a of addrs) {
        els.addresses.appendChild(h('span', { class: 'dns-addr' }, copyCode(a.address), h('span', { class: 'badge ' + (a.family === 'IPv6' ? 'purple' : 'blue') }, a.family)));
      }
      // a typed lookup's records of its type (MX, TXT, SOA…), as the DNS server wrote them: copy chips, never markup
      els.values.innerHTML = '';
      const values = v ? v.values : [];
      els.values.hidden = !values.length;
      for (const x of values) els.values.appendChild(h('span', { class: 'dns-value' }, copyCode(x)));
      // an "All record types" answer: the records grouped by type, each a sub-heading over its value chips
      els.groups.innerHTML = '';
      const groups = v ? (v.groups || []) : [];
      els.groups.hidden = !groups.length;
      for (const g of groups) {
        const box = h('div', { class: 'dns-group' }, h('span', { class: 'label dns-group-type' }, g.type));
        for (const val of g.values) box.appendChild(h('span', { class: 'dns-value' }, copyCode(val)));
        els.groups.appendChild(box);
      }
      // an SRV lookup that found nothing for a name without the service in front
      els.hint.textContent = v && v.hint ? v.hint : '';
      els.hint.hidden = !(v && v.hint);
      // the aliases: the names the answer was reached through
      els.aliases.innerHTML = '';
      const aliases = v ? v.aliases : [];
      els.aliases.hidden = !aliases.length;
      if (aliases.length) {
        els.aliases.appendChild(h('span', { class: 'label' }, aliases.length === 1 ? 'Alias' : 'Aliases'));
        for (const a of aliases) els.aliases.appendChild(copyCode(a));
      }
      // Details: the answer records, folded away until asked for
      const records = v ? v.records : [];
      els.details.hidden = !records.length;
      els.detailsBtn.lastChild.textContent = 'Details (' + records.length + ')';
      els.detailsBtn.setAttribute('aria-expanded', String(detailsOpen && records.length > 0));
      els.tableWrap.hidden = !(detailsOpen && records.length);
      els.tbody.innerHTML = '';
      for (const x of records) {
        els.tbody.appendChild(h('tr', null,
          h('td', null, h('span', { class: 'badge grey' }, x.type)),
          h('td', { class: 'wrap' }, x.name),
          h('td', { class: 'wrap' }, x.value ? copyCode(x.value) : h('span', { class: 'muted' }, '—')),
          h('td', { class: 'num' }, x.ttl)));
      }
    }

    /* ------------------------------------------------------- actions */
    async function run() {
      if (!mounted || running) return;
      const n = validName(els.name.value);
      if (!n.ok) { showInvalid(n.error, els.name); return; }
      const s = validServer(els.server.value);
      if (!s.ok) { showInvalid(s.error, els.server); return; }
      const t = validType(els.type.value, n.name);
      if (!t.ok) { showInvalid(t.error, els.type); return; }
      clearInvalid(els.name);
      clearInvalid(els.type);
      clearInvalid(els.server);
      const gen = ++runGen;
      running = true;
      asking = { name: n.name, server: s.server, type: t.type };
      render();
      try {
        const r = await TNT.api.dnsLookup(n.name, s.server, t.type);
        if (!mounted || gen !== runGen) return;
        result = r || null;
        failure = null;
        detailsOpen = true;        // every new answer arrives with its records unfolded
      } catch (err) {
        if (!mounted || gen !== runGen) return;
        // the service's own validation message goes where ours does; the last answer stays on screen
        if (err.status === 400) showInvalid(err.message || 'The DNS lookup was refused', null);
        else {
          // the service's words as they are (a 503 says why); an older service without the route answers 404
          if (err.status === 404) failure = 'DNS lookup is not available on this service';
          else if (err.status === 503) failure = err.message || 'DNS lookup is not available on this service';
          else failure = 'Could not look up ' + n.name + ': ' + (err.message || 'unknown error');
          result = null;
        }
      } finally {
        if (mounted && gen === runGen) { running = false; asking = null; render(); }
      }
    }

    // Clear: the lookup (the name, the server and the type back to Auto) and the answer, a failure and any message under
    // the form all go. A lookup still running is dropped when it answers (the service's question cannot be taken back).
    function clear() {
      if (!mounted) return;
      runGen++;
      running = false; asking = null; result = null; failure = null; detailsOpen = false;
      els.invalid.hidden = true;
      els.name.value = '';
      els.server.value = '';
      els.type.value = '';
      els.name.placeholder = 'www.example.com';
      for (const el of [els.name, els.type, els.server]) { el.removeAttribute('aria-invalid'); el.removeAttribute('aria-describedby'); }
      render();
    }

    return {
      body,
      head: null,
      mount() { mounted = true; shownV6 = showIpv6(); render(); },
      // Settings › Appearance › IPv6 addresses changed: the answer on screen is drawn again, without a new lookup
      update(state) { const v6 = showIpv6(state); if (v6 !== shownV6) { shownV6 = v6; render(); } },
      unmount() { mounted = false; runGen++; running = false; asking = null; result = null; failure = null; },
    };
  }

  TNT.tools.dns = { create, resultView, validName, validServer, validType, TYPES };
})();
