/* TNT — tools/subnetcalc.js
   The "Subnet calculator" card of the Tools view (pure client side, the math is in tools/subnet.js):
   one input that takes "10.0.0.112/24", "10.0.0.112 255.255.255.0" or a bare "10.0.0.112" (/24),
   a grid of copyable results, the binary view with the network bits highlighted, a
   "does this subnet contain …" check and a "split into /N" list. Prefilled from the internet NIC.
   Loaded before app.js: TNT.util / TNT.ui are only touched inside functions. */
(function () {
  'use strict';
  window.TNT = window.TNT || {};
  const TNT = window.TNT;
  TNT.tools = TNT.tools || {};

  const SPLIT_SHOWN = 64;
  const SPLIT_MAX_STEP = 8;     // /N choices: prefix+1 … prefix+8 (256 subnets at most)
  const KIND_BADGE = { private: 'green', public: 'blue', loopback: 'grey', 'link-local': 'yellow', multicast: 'purple', cgnat: 'orange', reserved: 'grey' };

  /* ------------------------------------------------ pure helpers (tests) */
  /** "10.0.0.112/24" from a status snapshot's internet NIC, or null. */
  function prefillFrom(state) {
    const nic = state && state.status && state.status.netinfo && state.status.netinfo.internet_nic;
    if (!nic || !nic.ipv4) return null;
    const ipv4 = String(nic.ipv4);
    if (ipv4.includes('/')) return ipv4;
    const net = String(nic.network || '');
    if (net.includes('/')) return ipv4 + '/' + net.split('/')[1];
    return null;
  }
  /** "10.0.0.112/24" from a /api/netinfo payload (the internet adapter's first IPv4 with a prefix, else a connected
   *  adapter's before one that is down), or null. */
  function prefillFromNetinfo(n) {
    if (!n || !Array.isArray(n.adapters)) return null;
    const rank = (a) => (a.index === n.internet_nic_index ? 0 : 2) + (a.status === 'down' ? 1 : 0);
    const list = n.adapters.slice().sort((a, b) => rank(a) - rank(b));
    for (const a of list) {
      for (const e of a.ipv4 || []) if (e && e.address && e.prefix != null) return e.address + '/' + e.prefix;
      for (const g of a.subnets || []) if (g && g.family !== 6 && g.network && (g.addresses || []).length) return g.addresses[0] + '/' + String(g.network).split('/')[1];
    }
    return null;
  }

  /** Pure: the address the field should take from this PC now, or null to leave it. Only while the user
   *  has not typed, and only into an empty field or one still holding the address filled in before. */
  function autoFill(field, next) {
    field = field || {};
    const value = String(field.value || '').trim();
    if (field.touched || !next || next === value) return null;
    return !value || value === String(field.auto || '') ? next : null;
  }

  /** Pure: whether to fill the field from the adapters list (/api/netinfo) because the status names no internet
   *  adapter: the field is empty, or still holds the address filled in before (the PC moved to a network with no
   *  default route, a bench cable or no DHCP server, and that address was the old network's). Never once typed in. */
  function refillFromAdapters(field, fromStatus) {
    field = field || {};
    if (field.touched || fromStatus) return false;
    const value = String(field.value || '').trim();
    return !value || value === String(field.auto || '');
  }

  /* ------------------------------------------------------------- card */
  function create() {
    const { h } = TNT.util;
    const S = TNT.subnet;
    let current = null;        // last parse() result
    let touched = false;       // the user typed: never overwrite with a prefill
    let mounted = false;
    let prefillTried = false;
    let autoValue = null;      // the address last filled in for the user: replaced when the PC moves
    let splitChoice = null;
    const els = {};

    els.input = h('input', { class: 'input', type: 'text', placeholder: '10.0.0.112/24  ·  10.0.0.112 255.255.255.0  ·  10.0.0.112', 'aria-label': 'IP address with prefix or mask', spellcheck: 'false', autocomplete: 'off' });
    els.input.addEventListener('input', () => { touched = true; compute(); });
    els.useBtn = h('button', { class: 'btn btn-sm', type: 'button', title: "Fill in this PC's internet address", on: { click: () => useThisPc() } }, TNT.ui.icon('network'), 'This PC');
    const form = h('div', { class: 'form-row tool-form' }, h('div', { class: 'field wide' }, h('label', null, 'Address / prefix or mask'), els.input), els.useBtn);
    els.note = h('div', { class: 'tool-summary muted' });
    els.grid = h('div', { class: 'subnet-grid', hidden: true });
    els.bin = h('div', { class: 'bin-panel', hidden: true });

    els.checkIp = h('input', { class: 'input sm', type: 'text', placeholder: '10.0.0.200 or 10.0.1.0/25', 'aria-label': 'Address to check', spellcheck: 'false', autocomplete: 'off' });
    els.checkIp.addEventListener('input', renderCheck);
    els.checkOut = h('div', { class: 'sn-out' });
    els.splitSel = h('select', { class: 'input sm', 'aria-label': 'Split into' });
    els.splitSel.addEventListener('change', () => { splitChoice = parseInt(els.splitSel.value, 10); renderSplit(); });
    els.splitOut = h('div', { class: 'sn-split-list' });
    els.tools = h('div', { class: 'sn-tools', hidden: true },
      h('div', { class: 'panel sn-panel' }, h('div', { class: 'sn-title' }, 'Does this subnet contain…'), els.checkIp, els.checkOut),
      h('div', { class: 'panel sn-panel' }, h('div', { class: 'sn-title' }, 'Split into'), els.splitSel, els.splitOut));
    const body = h('div', { class: 'tool-body' }, form, els.note, els.grid, els.bin, els.tools);

    function item(label, value, extra) {
      const { copyCode } = TNT.util;
      return h('div', { class: 'sn-item' }, h('span', { class: 'label' }, label), h('div', { class: 'row', style: { gap: '6px' } }, value instanceof Node ? value : copyCode(value), extra || null));
    }
    function renderGrid() {
      const r = current;
      els.grid.innerHTML = '';
      if (!r || !r.ok) { els.grid.hidden = true; return; }
      els.grid.hidden = false;
      const fmtInt = (n) => n.toLocaleString();
      els.grid.appendChild(item('Network', r.cidr));
      els.grid.appendChild(item('Netmask', r.mask, h('span', { class: 'muted small' }, '/' + r.prefix)));
      els.grid.appendChild(item('Wildcard', r.wildcard));
      els.grid.appendChild(item('Broadcast', r.broadcast));
      els.grid.appendChild(item('First host', r.first_host));
      els.grid.appendChild(item('Last host', r.last_host));
      els.grid.appendChild(item('Hosts', h('span', { class: 'strong' }, fmtInt(r.usable)), h('span', { class: 'muted small' }, 'usable of ' + fmtInt(r.hosts))));
      els.grid.appendChild(item('Class', h('span', { class: 'badge grey' }, 'class ' + r.class), h('span', { class: 'badge ' + (KIND_BADGE[r.kind] || 'grey'), title: r.kind_label }, r.kind)));
    }
    function renderBin() {
      const r = current;
      els.bin.innerHTML = '';
      if (!r || !r.ok) { els.bin.hidden = true; return; }
      els.bin.hidden = false;
      const line = (key, bits, split) => {
        const row = h('div', { class: 'bl' }, h('span', { class: 'bk' }, key));
        const val = h('span', { class: 'bv' });
        // the first `split` bits (dots included) are the network part
        let seen = 0, i = 0;
        while (i < bits.length && seen < split) { if (bits[i] !== '.') seen++; i++; }
        if (i > 0) val.appendChild(h('span', { class: 'net', title: 'network bits' }, bits.slice(0, i)));
        if (i < bits.length) val.appendChild(h('span', { class: 'hostb', title: 'host bits' }, bits.slice(i)));
        row.appendChild(val);
        return row;
      };
      els.bin.appendChild(line('IP', r.binary.ip, r.prefix));
      els.bin.appendChild(line('Mask', r.binary.mask, r.prefix));
      els.bin.appendChild(h('div', { class: 'bl legend-line' }, h('span', { class: 'bk' }, ''), h('span', { class: 'muted' }, h('span', { class: 'net' }, ' network ' + r.prefix + ' bits '), ' · host ' + (32 - r.prefix) + ' bits')));
    }
    function renderCheck() {
      const r = current;
      els.checkOut.innerHTML = '';
      if (!r || !r.ok) return;
      const v = (els.checkIp.value || '').trim();
      if (!v) { els.checkOut.appendChild(h('span', { class: 'muted small' }, 'Type an address to check it against ' + r.cidr)); return; }
      const valid = v.includes('/') || v.includes(' ') ? S.parse(v).ok : S.ipToInt(v) != null;
      if (!valid) { els.checkOut.appendChild(h('span', { class: 'badge grey' }, 'not an address')); return; }
      const inside = S.contains(r.cidr, v);
      els.checkOut.appendChild(h('span', { class: 'badge ' + (inside ? 'green' : 'red') }, inside ? 'inside' : 'outside'));
      els.checkOut.appendChild(h('span', { class: 'small' }, v + (inside ? ' is in ' : ' is not in ') + r.cidr));
    }
    function renderSplitOptions() {
      const r = current;
      els.splitSel.innerHTML = '';
      if (!r || !r.ok) return;
      const opts = [];
      for (let p = r.prefix + 1; p <= Math.min(32, r.prefix + SPLIT_MAX_STEP); p++) opts.push(p);
      if (!opts.length) { els.splitSel.appendChild(h('option', { value: '' }, 'a /32 cannot be split')); els.splitSel.disabled = true; return; }
      els.splitSel.disabled = false;
      for (const p of opts) {
        const n = Math.pow(2, p - r.prefix);
        els.splitSel.appendChild(h('option', { value: String(p) }, '/' + p + ' — ' + n.toLocaleString() + (n === 1 ? ' subnet' : ' subnets') + ' of ' + Math.pow(2, 32 - p).toLocaleString()));
      }
      if (!opts.includes(splitChoice)) splitChoice = opts[0];
      els.splitSel.value = String(splitChoice);
    }
    function renderSplit() {
      const { copyCode } = TNT.util;
      const r = current;
      els.splitOut.innerHTML = '';
      if (!r || !r.ok || !splitChoice) return;
      const total = S.splitCount(r.cidr, splitChoice);
      const list = S.split(r.cidr, splitChoice, SPLIT_SHOWN);
      for (const c of list) els.splitOut.appendChild(copyCode(c));
      if (total > list.length) els.splitOut.appendChild(h('span', { class: 'muted small' }, '…and ' + (total - list.length).toLocaleString() + ' more'));
    }
    function renderNote() {
      const r = current;
      els.note.innerHTML = '';
      if (!r) { els.note.className = 'tool-summary muted'; els.note.textContent = 'Type an address to see its subnet.'; return; }
      if (!r.ok) { els.note.className = 'tool-summary bad'; els.note.appendChild(TNT.ui.icon('warning')); els.note.appendChild(h('span', null, r.error)); return; }
      els.note.className = 'tool-summary muted';
      const parts = [r.ip + ' is in ' + r.cidr + ' (' + r.kind_label + ')'];
      if (r.assumed_prefix) parts.push('no mask given, /24 assumed');
      els.note.textContent = parts.join(' · ');
    }
    function compute() {
      const text = (els.input.value || '').trim();
      current = text ? S.parse(text) : null;
      renderNote();
      renderGrid();
      renderBin();
      els.tools.hidden = !(current && current.ok);
      renderCheck();
      renderSplitOptions();
      renderSplit();
    }
    function fill(v) { els.input.value = v; autoValue = v; compute(); }
    /* Follows this PC's internet adapter until the user types: an empty field, or one still holding
       the address filled in before, takes the current one (the PC may have moved to another network). */
    function prefill(state) {
      const fromStatus = prefillFrom(state);
      const next = autoFill({ value: els.input.value, auto: autoValue, touched }, fromStatus);
      if (next) { fill(next); return; }
      // no internet adapter in the status: the adapters list, once per mount or network change
      if (prefillTried || !(state && state.status) || !refillFromAdapters({ value: els.input.value, auto: autoValue, touched }, fromStatus)) return;
      prefillTried = true;
      TNT.api.netinfo().then((n) => {
        if (!mounted || !refillFromAdapters({ value: els.input.value, auto: autoValue, touched }, prefillFrom(TNT.state))) return;
        const w = prefillFromNetinfo(n);
        if (w) fill(w);
      }).catch(() => { /* leave the field as it is */ });
    }
    /* "This PC": always this PC's current address, whatever the field holds. */
    function useThisPc() {
      touched = false;
      const v = prefillFrom(TNT.state);
      if (v) { fill(v); return; }
      TNT.api.netinfo().then((n) => {
        if (!mounted) return;
        const w = prefillFromNetinfo(n);
        if (w) fill(w); else TNT.ui.toast('This PC has no IPv4 address right now', 'warn');
      }).catch((err) => { if (mounted) TNT.ui.toast("Could not read this PC's address: " + err.message, 'error'); });
    }

    return {
      body,
      head: null,
      mount() { mounted = true; touched = false; prefillTried = false; compute(); prefill(TNT.state); },
      update(state) { if (mounted) prefill(state); },
      // the new address arrives with the status that follows the change (update() keeps up with it too)
      netChanged(info, state) { if (mounted) { prefillTried = false; prefill(state || TNT.state); } },
      unmount() { mounted = false; current = null; },
    };
  }

  TNT.tools.subnetcalc = { create, prefillFrom, prefillFromNetinfo, autoFill, refillFromAdapters, SPLIT_SHOWN, SPLIT_MAX_STEP };
})();
