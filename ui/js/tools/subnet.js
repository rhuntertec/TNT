/* TNT — tools/subnet.js
   Pure IPv4 subnet arithmetic for the Subnet calculator card. No DOM and no other TNT module
   is touched, so the whole file runs in node for the unit tests.
     TNT.subnet.parse(text)          "10.0.0.112/24", "10.0.0.112 255.255.255.0", "10.0.0.112/255.255.255.0"
                                     or a bare "10.0.0.112" (a /24 is assumed) -> every derived value
     TNT.subnet.contains(cidr, ip)   true when ip (or a whole cidr) lies inside the subnet
     TNT.subnet.split(cidr, prefix)  the subnets a network breaks into at the new prefix (first 256) */
(function () {
  'use strict';
  window.TNT = window.TNT || {};
  const TNT = window.TNT;

  const OCTET = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
  const CAP = 256;

  /** Dotted quad -> unsigned 32-bit number, or null when it is not an IPv4 address. */
  function ipToInt(text) {
    const parts = String(text == null ? '' : text).trim().split('.');
    if (parts.length !== 4) return null;
    let n = 0;
    for (const p of parts) {
      if (!OCTET.test(p)) return null;
      n = (n * 256) + Number(p);
    }
    return n;
  }
  function intToIp(n) {
    n = n >>> 0;
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  }
  function maskOf(prefix) { return prefix <= 0 ? 0 : ((0xFFFFFFFF << (32 - prefix)) >>> 0); }
  /** Prefix length of a contiguous mask, or null for a non-contiguous one such as 255.0.255.0. */
  function prefixOfMask(maskInt) {
    for (let p = 0; p <= 32; p++) if (maskOf(p) === maskInt) return p;
    return null;
  }
  function toBinary(n) {
    n = n >>> 0;
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].map((o) => o.toString(2).padStart(8, '0')).join('.');
  }

  // special-purpose ranges (RFC 6890); the longest matching prefix wins
  const RANGES = [
    ['0.0.0.0/8', 'reserved', '"this" network'],
    ['10.0.0.0/8', 'private', 'private (RFC 1918)'],
    ['100.64.0.0/10', 'cgnat', 'carrier-grade NAT (RFC 6598)'],
    ['127.0.0.0/8', 'loopback', 'loopback'],
    ['169.254.0.0/16', 'link-local', 'link-local (APIPA)'],
    ['172.16.0.0/12', 'private', 'private (RFC 1918)'],
    ['192.0.0.0/24', 'reserved', 'IETF protocol assignments'],
    ['192.0.2.0/24', 'reserved', 'TEST-NET-1 (documentation)'],
    ['192.88.99.0/24', 'reserved', '6to4 relay (deprecated)'],
    ['192.168.0.0/16', 'private', 'private (RFC 1918)'],
    ['198.18.0.0/15', 'reserved', 'benchmarking'],
    ['198.51.100.0/24', 'reserved', 'TEST-NET-2 (documentation)'],
    ['203.0.113.0/24', 'reserved', 'TEST-NET-3 (documentation)'],
    ['224.0.0.0/4', 'multicast', 'multicast'],
    ['240.0.0.0/4', 'reserved', 'reserved (class E)'],
    ['255.255.255.255/32', 'reserved', 'limited broadcast'],
  ].map(([cidr, kind, label]) => {
    const [ip, p] = cidr.split('/');
    return { net: ipToInt(ip), prefix: Number(p), kind, label };
  });

  function kindOf(ipInt) {
    let best = null;
    for (const r of RANGES) {
      if (((ipInt & maskOf(r.prefix)) >>> 0) !== r.net) continue;
      if (!best || r.prefix > best.prefix) best = r;
    }
    return best ? { kind: best.kind, label: best.label } : { kind: 'public', label: 'public (routable)' };
  }

  function parse(text) {
    const raw = String(text == null ? '' : text).trim().replace(/\s+/g, ' ');
    if (!raw) return { ok: false, error: 'Type an IPv4 address such as 10.0.0.112/24' };
    let ipText = raw, maskText = null;
    if (raw.includes('/')) {
      const i = raw.indexOf('/');
      ipText = raw.slice(0, i).trim();
      maskText = raw.slice(i + 1).trim();
    } else if (raw.includes(' ')) {
      const i = raw.indexOf(' ');
      ipText = raw.slice(0, i);
      maskText = raw.slice(i + 1).trim();
    }
    const ip = ipToInt(ipText);
    if (ip == null) return { ok: false, error: '"' + ipText + '" is not an IPv4 address' };
    let prefix;
    let assumed = false;
    if (maskText == null || maskText === '') { prefix = 24; assumed = true; }
    else if (/^\d{1,2}$/.test(maskText)) {
      prefix = Number(maskText);
      if (prefix > 32) return { ok: false, error: 'The prefix must be between /0 and /32' };
    } else {
      const m = ipToInt(maskText);
      if (m == null) return { ok: false, error: '"' + maskText + '" is neither a prefix length nor a subnet mask' };
      prefix = prefixOfMask(m);
      if (prefix == null) return { ok: false, error: maskText + ' is not a valid subnet mask (its ones must be contiguous)' };
    }
    const mask = maskOf(prefix);
    const wildcard = (~mask) >>> 0;
    const network = (ip & mask) >>> 0;
    const broadcast = (network | wildcard) >>> 0;
    const hosts = Math.pow(2, 32 - prefix);
    const usable = prefix <= 30 ? hosts - 2 : (prefix === 31 ? 2 : 1);
    const first = prefix <= 30 ? network + 1 : network;
    const last = prefix <= 30 ? broadcast - 1 : broadcast;
    const o1 = ip >>> 24;
    const cls = o1 < 128 ? 'A' : o1 < 192 ? 'B' : o1 < 224 ? 'C' : o1 < 240 ? 'D' : 'E';
    const k = kindOf(ip);
    return {
      ok: true, input: raw, assumed_prefix: assumed,
      ip: intToIp(ip), prefix, cidr: intToIp(network) + '/' + prefix,
      mask: intToIp(mask), wildcard: intToIp(wildcard),
      network: intToIp(network), broadcast: intToIp(broadcast),
      first_host: intToIp(first), last_host: intToIp(last),
      hosts, usable, class: cls, kind: k.kind, kind_label: k.label,
      binary: { ip: toBinary(ip), mask: toBinary(mask) },
    };
  }

  /** true when `ip` (an address, or a whole "a.b.c.d/n" subnet) lies inside `cidr`. */
  function contains(cidr, ip) {
    const net = parse(cidr);
    if (!net.ok) return false;
    const mask = maskOf(net.prefix);
    const netInt = ipToInt(net.network);
    const s = String(ip == null ? '' : ip).trim();
    if (!s) return false;
    if (s.includes('/') || s.includes(' ')) {
      const inner = parse(s);
      if (!inner.ok || inner.assumed_prefix) return false;
      return ((ipToInt(inner.network) & mask) >>> 0) === netInt && ((ipToInt(inner.broadcast) & mask) >>> 0) === netInt;
    }
    const a = ipToInt(s);
    if (a == null) return false;
    return ((a & mask) >>> 0) === netInt;
  }

  /** The subnets `cidr` splits into at `newPrefix`, capped at 256 entries (splitCount() has the real total). */
  function split(cidr, newPrefix, cap) {
    const net = parse(cidr);
    newPrefix = Number(newPrefix);
    if (!net.ok || !Number.isInteger(newPrefix) || newPrefix <= net.prefix || newPrefix > 32) return [];
    const limit = cap == null ? CAP : Math.max(0, cap);
    const count = Math.min(limit, Math.pow(2, newPrefix - net.prefix));
    const size = Math.pow(2, 32 - newPrefix);
    const base = ipToInt(net.network);
    const out = [];
    for (let i = 0; i < count; i++) out.push(intToIp(base + i * size) + '/' + newPrefix);
    return out;
  }
  function splitCount(cidr, newPrefix) {
    const net = parse(cidr);
    newPrefix = Number(newPrefix);
    if (!net.ok || !Number.isInteger(newPrefix) || newPrefix <= net.prefix || newPrefix > 32) return 0;
    return Math.pow(2, newPrefix - net.prefix);
  }

  TNT.subnet = { parse, contains, split, splitCount, ipToInt, intToIp, toBinary, maskOf, prefixOfMask, CAP };
})();
