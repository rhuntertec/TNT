/* TNT — egg.js
   Easter egg: clicking the dynamite logo throws a stick of TNT into the middle of the
   screen with a 5-second fuse. Every further click within the countdown adds a stick
   (100 max) and relights the fuse to full length. When the fuse runs out the pile goes
   up in a cartoon explosion sized by the number of sticks. The number of sticks ever
   detonated on this machine is kept by the service (/api/easter) and shown in very small
   text under the logo once it is at least 1. */
(function () {
  'use strict';
  const TNT = (window.TNT = window.TNT || {});

  const MAX_STICKS = 100;
  const FUSE_MS = 5000;
  const STORAGE_KEY = 'tnt.egg.detonated';   // fallback when the service cannot be reached
  const PILE_Y = 0.55;                          // pile centre as a fraction of the viewport height
  const FUSE_ANCHOR_DY = 34;                    // the fuse starts this many px above the pile centre

  const INK = '#2B2438', RED = '#FF5C5C', CREAM = '#FFF7E8', ORANGE = '#FFA45C', YELLOW = '#FFD166', DARK_RED = '#C93B3B';

  // A stick of dynamite drawn as a cylinder seen slightly from its right end: the far (left)
  // end is a curved edge, the near (right) end shows the full elliptical cap with the wick hole,
  // and the paper seams / label band curve around the body.
  const STICK_W = 92, STICK_H = 40, CAP_DX = 32;   // px; CAP_DX = cap centre offset from the stick centre
  const STICK_SVG =
    '<svg viewBox="0 0 92 40" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">' +
    '<path d="M15 8 H78 V32 H15 A7 12 0 0 1 15 8 Z" fill="' + RED + '" stroke="' + INK + '" stroke-width="3" stroke-linejoin="round"/>' +
    '<path d="M17 29 H76" stroke="' + INK + '" stroke-width="4" stroke-linecap="round" opacity="0.16"/>' +
    '<path d="M17 11.5 H70" stroke="#fff" stroke-width="2.2" stroke-linecap="round" opacity="0.5"/>' +
    '<path d="M30 8 A7 12 0 0 0 30 32 M62 8 A7 12 0 0 0 62 32" stroke="' + INK + '" stroke-width="2" opacity="0.35" fill="none"/>' +
    '<path d="M36 8 H56 A7 12 0 0 0 56 32 H36 A7 12 0 0 1 36 8 Z" fill="' + CREAM + '" stroke="' + INK + '" stroke-width="2.2" stroke-linejoin="round"/>' +
    '<text x="46" y="24.5" text-anchor="middle" font-family="Nunito, Segoe UI, sans-serif" font-size="11" font-weight="900" fill="' + INK + '">TNT</text>' +
    '<ellipse cx="78" cy="20" rx="7" ry="12" fill="' + DARK_RED + '" stroke="' + INK + '" stroke-width="3"/>' +
    '<ellipse cx="78" cy="20" rx="3.6" ry="6.5" fill="' + RED + '" opacity="0.7"/>' +
    '<circle cx="78" cy="20" r="2.4" fill="' + INK + '"/>' +
    '</svg>';

  // Once in about 500 throws the stick is a pixel-art TNT block instead (a nod to a certain
  // block game): a 16 x 16 face with a white band and a chunky "TNT" in it.
  const BLOCK_ODDS = 1 / 500;
  const BLOCK_ROWS = [
    'rrrdrrrrrdrrrrdr',
    'rdrrrrdrrrrrrrrr',
    'rrrrrdrrrrrrdrrr',
    'rrdrrrrrrdrrrrrd',
    'rrrrrrrrrrrrrrrr',
    'wwwwwwwwwwwwwwww',
    'wwkkkwkwkwkkkwww',
    'wwwkwwkkkwwkwwww',
    'wwwkwwkkkwwkwwww',
    'wwwkwwkwkwwkwwww',
    'wwwkwwkwkwwkwwww',
    'wwwwwwwwwwwwwwww',
    'rrrrrdrrrrrrrrrr',
    'rdrrrrrrrdrrrdrr',
    'rrrrdrrrrrrrrrrr',
    'rrdrrrrrdrrrrrdr',
  ];
  const BLOCK_PALETTE = { r: '#D63A3A', d: '#A82626', w: '#F3EEE4', k: INK };
  function blockSvg() {
    let px = '';
    BLOCK_ROWS.forEach((row, y) => {
      for (let x = 0; x < row.length; x++) px += '<rect x="' + x + '" y="' + y + '" width="1" height="1" fill="' + BLOCK_PALETTE[row[x]] + '"/>';
    });
    return '<svg viewBox="-1 -1 18 18" xmlns="http://www.w3.org/2000/svg" shape-rendering="crispEdges" aria-hidden="true">' +
      px + '<rect x="-0.5" y="-0.5" width="17" height="17" fill="none" stroke="' + INK + '" stroke-width="1"/></svg>';
  }

  // One fuse for the whole pile. It starts at (100,152) in this box - the wick hole of the
  // first stick - heads out along the stick's axis and curls up and away.
  const FUSE_SVG =
    '<svg class="egg-fuse-svg" viewBox="0 0 200 160" width="200" height="160" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">' +
    '<path class="egg-fuse-under" d="M100 152 C 120 132, 58 120, 62 78 S 152 48, 138 14" fill="none"/>' +
    '<path class="egg-fuse-path" d="M100 152 C 120 132, 58 120, 62 78 S 152 48, 138 14" fill="none"/>' +
    // Two groups on purpose: the outer one is moved along the fuse through its transform
    // ATTRIBUTE; the inner one flickers through a CSS animation. On SVG a CSS transform
    // replaces the transform attribute, so animating the outer group would throw the
    // position away and pin the spark to the box's top-left corner.
    '<g class="egg-spark" transform="translate(138 14)"><g class="egg-spark-flicker">' +
    '<circle r="11" fill="' + YELLOW + '" opacity="0.55"/>' +
    '<path d="M0-9c.6 4.4 2.8 6.6 9 9-6.2 2.4-8.4 4.6-9 9-.6-4.4-2.8-6.6-9-9 6.2-2.4 8.4-4.6 9-9z" fill="' + ORANGE + '" stroke="' + INK + '" stroke-width="1.6" stroke-linejoin="round"/>' +
    '<circle r="2.2" fill="#fff"/>' +
    '</g></g></svg>';

  let overlay = null, pileEl = null, fuseWrap = null, fusePath = null, fuseLen = 0, sparkEl = null;
  // The countdown is driven by a plain interval, not requestAnimationFrame: embedded
  // webviews throttle rAF when the window is hidden or busy, and a fuse that stops
  // burning while the window is minimised would be a very disappointing easter egg.
  const FUSE_TICK_MS = 40;
  let sticks = 0, fuseStart = 0, fuseTimer = 0, emberTimer = 0, exploding = false;
  let detonated = null;          // machine-wide total (null until known)
  let counterEl = null;

  /* ------------------------------------------------------------ helpers */
  function make(tag, cls, html) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html != null) e.innerHTML = html;
    return e;
  }
  const rnd = (a, b) => a + Math.random() * (b - a);
  const reducedMotion = () => !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);

  function pileCentre() { return { x: window.innerWidth / 2, y: window.innerHeight * PILE_Y }; }

  function ensureOverlay() {
    if (overlay) return;
    overlay = make('div', 'egg-overlay');
    overlay.setAttribute('aria-hidden', 'true');
    pileEl = make('div', 'egg-pile');
    fuseWrap = make('div', 'egg-fuse', FUSE_SVG);
    fuseWrap.hidden = true;
    overlay.appendChild(pileEl);
    overlay.appendChild(fuseWrap);
    document.body.appendChild(overlay);
    fusePath = fuseWrap.querySelector('.egg-fuse-path');
    sparkEl = fuseWrap.querySelector('.egg-spark');
    try { fuseLen = fusePath.getTotalLength(); } catch (e) { fuseLen = 260; }
    fusePath.style.strokeDasharray = String(fuseLen);
    fusePath.style.strokeDashoffset = '0';
    window.addEventListener('resize', layoutPile);
  }

  function layoutPile() {
    if (!pileEl) return;
    const c = pileCentre();
    pileEl.style.left = c.x + 'px';
    pileEl.style.top = c.y + 'px';
    // the fuse box is 200 x 160 with its path starting at (100,152): put that point at the anchor
    fuseWrap.style.left = c.x + 'px';
    fuseWrap.style.top = (c.y - FUSE_ANCHOR_DY + 8) + 'px';
  }

  /* ------------------------------------------------------------- sticks */
  function throwStick() {
    if (exploding) return;
    ensureOverlay();
    layoutPile();
    if (sticks < MAX_STICKS) {
      sticks++;
      addStick(sticks);
    } else {
      pulseFull();
    }
    // relight: full-length fuse, countdown restarts
    fuseStart = performance.now();
    fuseWrap.hidden = false;
    setBurn(0);
    if (!fuseTimer) fuseTimer = setInterval(tick, FUSE_TICK_MS);
    if (!emberTimer) emberTimer = setInterval(spawnEmber, 90);
  }

  function setBurn(frac) {
    const off = fuseLen * frac;
    fusePath.style.strokeDashoffset = String(off);
    fusePath.setAttribute('stroke-dashoffset', off.toFixed(2));
    let pt = null;
    try { pt = fusePath.getPointAtLength(fuseLen * (1 - frac)); } catch (e) { pt = null; }
    if (pt) sparkEl.setAttribute('transform', 'translate(' + pt.x.toFixed(1) + ' ' + pt.y.toFixed(1) + ')');
  }

  function addStick(i) {
    const c = pileCentre();
    const logo = document.getElementById('brand-logo');
    const r = logo ? logo.getBoundingClientRect() : { left: 24, top: 10, width: 44, height: 44 };
    const sx = r.left + r.width / 2 - c.x, sy = r.top + r.height / 2 - c.y;
    let tx, ty, rot;
    if (i === 1) {
      // the first stick lies under the fuse with its cap (wick hole) exactly on the fuse's
      // start point, which sits FUSE_ANCHOR_DY above the pile centre
      rot = -20;
      const th = (rot * Math.PI) / 180;
      tx = -CAP_DX * Math.cos(th);
      ty = -FUSE_ANCHOR_DY - CAP_DX * Math.sin(th);
    } else {
      // the rest scatter around it; the radius grows with the square root of the pile so
      // 100 sticks still fit on screen
      const rad = 10 + 13 * Math.sqrt(i - 1), ang = rnd(0, Math.PI * 2);
      tx = Math.cos(ang) * rad;
      ty = Math.sin(ang) * rad * 0.62;
      rot = rnd(-38, 38);
    }
    const stick = make('div', 'egg-stick');
    stick.style.setProperty('--sx', sx.toFixed(1) + 'px');
    stick.style.setProperty('--sy', sy.toFixed(1) + 'px');
    stick.style.setProperty('--tx', tx.toFixed(1) + 'px');
    stick.style.setProperty('--ty', ty.toFixed(1) + 'px');
    stick.style.setProperty('--rot', rot.toFixed(1) + 'deg');
    stick.style.zIndex = String(i);
    const block = TNT.egg && TNT.egg.forceBlock ? true : Math.random() < BLOCK_ODDS;
    if (block) stick.classList.add('egg-block');
    const arc = make('div', 'egg-stick-arc', block ? blockSvg() : STICK_SVG);
    stick.appendChild(arc);
    pileEl.appendChild(stick);
    if (i > 1) sparkleLabel(i);
  }

  // tiny "×N" that pops on the pile so you can see the count growing
  function sparkleLabel(i) {
    const old = pileEl.querySelector('.egg-count');
    if (old) old.remove();
    const lbl = make('div', 'egg-count', '×' + i);
    pileEl.appendChild(lbl);
  }

  function pulseFull() {
    const lbl = pileEl.querySelector('.egg-count');
    if (lbl) { lbl.textContent = '×' + MAX_STICKS + ' (max)'; lbl.classList.remove('egg-count'); void lbl.offsetWidth; lbl.classList.add('egg-count'); }
  }

  /* --------------------------------------------------------------- fuse */
  function tick() {
    if (!fuseWrap || fuseWrap.hidden || exploding) return;
    const frac = Math.min(1, (performance.now() - fuseStart) / FUSE_MS);
    setBurn(frac);   // the fuse burns from its free end back towards the sticks
    if (frac >= 1) explode();
  }

  function sparkPagePoint() {
    if (!fuseWrap || fuseWrap.hidden) return null;
    const svg = fuseWrap.firstElementChild;
    const box = svg.getBoundingClientRect();
    const m = /translate\(([-\d.]+) ([-\d.]+)\)/.exec(sparkEl.getAttribute('transform') || '');
    if (!m) return null;
    return { x: box.left + parseFloat(m[1]) * (box.width / 200), y: box.top + parseFloat(m[2]) * (box.height / 160) };
  }

  function spawnEmber() {
    if (!overlay || !fuseWrap || fuseWrap.hidden || document.hidden || reducedMotion()) return;
    const p = sparkPagePoint();
    if (!p) return;
    const e = make('div', 'egg-ember');
    e.style.left = p.x + 'px';
    e.style.top = p.y + 'px';
    e.style.setProperty('--dx', rnd(-22, 22).toFixed(0) + 'px');
    e.style.setProperty('--dy', rnd(-34, -12).toFixed(0) + 'px');
    e.style.background = Math.random() < 0.5 ? ORANGE : YELLOW;
    overlay.appendChild(e);
    e.addEventListener('animationend', () => e.remove());
    setTimeout(() => e.remove(), 900);
  }

  /* ---------------------------------------------------------- explosion */
  function starPoints(cx, cy, outer, inner, n, jitter) {
    const pts = [];
    for (let i = 0; i < n * 2; i++) {
      const a = (Math.PI * 2 * i) / (n * 2) - Math.PI / 2;
      const r = (i % 2 === 0 ? outer : inner) * rnd(1 - jitter, 1 + jitter);
      pts.push((cx + Math.cos(a) * r).toFixed(1) + ',' + (cy + Math.sin(a) * r).toFixed(1));
    }
    return pts.join(' ');
  }

  function burstSvg(size, fill, points, jitter) {
    const half = size / 2;
    return '<svg viewBox="0 0 ' + size + ' ' + size + '" width="' + size + '" height="' + size + '" xmlns="http://www.w3.org/2000/svg">' +
      '<polygon points="' + starPoints(half, half, half - 4, (half - 4) * 0.58, points, jitter) + '" fill="' + fill + '" stroke="' + INK + '" stroke-width="4" stroke-linejoin="round"/>' +
      '</svg>';
  }

  function boomText(n) {
    if (n <= 1) return 'BOOM!';
    if (n < 10) return 'BOOM!!';
    if (n < 40) return 'KABOOM!';
    if (n < 80) return 'KA-BOOM!!';
    return 'KA-BOOOOM!!!';
  }

  function explode() {
    if (exploding) return;
    exploding = true;
    if (fuseTimer) { clearInterval(fuseTimer); fuseTimer = 0; }
    if (emberTimer) { clearInterval(emberTimer); emberTimer = 0; }
    const n = Math.max(1, sticks);
    sticks = 0;
    // Size: a small cluster for one stick, the whole window for a hundred. k runs 0..1 on a
    // square-root curve (so 25 sticks already feel serious) and every dimension scales from it.
    const k = Math.sqrt((n - 1) / (MAX_STICKS - 1));
    const rMin = 55, rMax = 0.62 * Math.max(window.innerWidth, window.innerHeight);
    const R = Math.round(rMin + (rMax - rMin) * k);      // main burst radius in px
    const c = pileCentre();
    const quick = reducedMotion();

    pileEl.innerHTML = '';
    fuseWrap.hidden = true;
    for (const e of overlay.querySelectorAll('.egg-ember')) e.remove();

    const boom = make('div', 'egg-boom');
    boom.style.left = c.x + 'px';
    boom.style.top = c.y + 'px';

    // screen flash
    const flash = make('div', 'egg-flash');
    flash.style.setProperty('--a', (0.2 + 0.55 * k).toFixed(2));
    overlay.appendChild(flash);

    // layered starbursts, all centred on the pile: yellow, orange, red (+ an outer ring when big)
    const layers = [[R * 2, YELLOW, 14, 0.18, 0], [R * 1.45, ORANGE, 11, 0.2, 60], [R * 0.9, RED, 8, 0.22, 110]];
    if (k >= 0.6) layers.unshift([R * 2.7, ORANGE, 18, 0.15, 30]);
    for (const [size, fill, pts, jit, delay] of layers) {
      const b = make('div', 'egg-burst', burstSvg(Math.round(size), fill, pts, jit));
      b.style.setProperty('--delay', delay + 'ms');
      b.style.setProperty('--spin', rnd(-25, 25).toFixed(0) + 'deg');
      boom.appendChild(b);
    }

    // smoke: puffs in every direction that linger and drift for ~3 s, plus a slow cloud that
    // hangs over the centre
    const puffs = 14 + Math.round(44 * k);
    for (let i = 0; i < puffs; i++) {
      const a = (Math.PI * 2 * i) / puffs + rnd(-0.3, 0.3);
      const d = R * rnd(0.3, 1.1);
      const size = Math.round((40 + 40 * k) * rnd(0.75, 1.4));
      addPuff(boom, size, Math.cos(a) * d, Math.sin(a) * d, rnd(30, 380), 3.2 + rnd(-0.3, 0.5));
    }
    const cloud = 9 + Math.round(14 * k);
    for (let i = 0; i < cloud; i++) {
      const a = rnd(0, Math.PI * 2), d = R * rnd(0, 0.45);
      addPuff(boom, Math.round((60 + 60 * k) * rnd(0.85, 1.35)), Math.cos(a) * d, Math.sin(a) * d, rnd(120, 560), 3.5 + rnd(0, 0.6));
    }

    // debris: stick fragments and sparks flung out in every direction, then falling
    const debris = Math.min(120, 8 + Math.round(n * 1.1));
    for (let i = 0; i < debris; i++) {
      const frag = Math.random() < 0.55;
      const d = make('div', frag ? 'egg-frag' : 'egg-sparkle');
      const a = rnd(0, Math.PI * 2), v = R * rnd(0.8, 2.2);
      d.style.setProperty('--dx', (Math.cos(a) * v).toFixed(0) + 'px');
      d.style.setProperty('--dy', (Math.sin(a) * v).toFixed(0) + 'px');
      d.style.setProperty('--fall', Math.round(rnd(140, 300) + 120 * k) + 'px');
      d.style.setProperty('--rot', rnd(-720, 720).toFixed(0) + 'deg');
      d.style.setProperty('--delay', Math.round(rnd(0, 120)) + 'ms');
      if (frag) { d.style.width = Math.round(rnd(10, 22) + 8 * k) + 'px'; d.style.background = Math.random() < 0.8 ? RED : DARK_RED; }
      else d.style.background = Math.random() < 0.5 ? ORANGE : YELLOW;
      boom.appendChild(d);
    }

    // the word
    const word = make('div', 'egg-word', boomText(n));
    word.style.setProperty('--size', Math.round(36 + 96 * k) + 'px');
    boom.appendChild(word);
    if (n > 1) {
      const sub = make('div', 'egg-word-sub', n + ' sticks');
      sub.style.setProperty('--dy', Math.round(26 + 56 * k) + 'px');
      boom.appendChild(sub);
    }
    overlay.appendChild(boom);

    // shake the whole page
    if (!quick) {
      document.body.style.setProperty('--egg-amp', (1.5 + 14 * k).toFixed(1) + 'px');
      document.body.classList.add('egg-shake');
      setTimeout(() => document.body.classList.remove('egg-shake'), 650);
    }

    setTimeout(() => flash.remove(), quick ? 100 : 700);
    // the burst is over after ~1.2 s and the next stick may be thrown; the smoke keeps
    // drifting until it has cleared (~3.5 s)
    setTimeout(() => { exploding = false; }, quick ? 150 : 1200);
    setTimeout(() => boom.remove(), quick ? 200 : 4000);
    recordDetonation(n);
  }

  function addPuff(parent, size, dx, dy, delayMs, seconds) {
    const p = make('div', 'egg-puff');
    p.style.width = p.style.height = size + 'px';
    p.style.marginLeft = p.style.marginTop = (-size / 2) + 'px';    // centred on the pile
    p.style.setProperty('--dx', dx.toFixed(0) + 'px');
    p.style.setProperty('--dy', dy.toFixed(0) + 'px');
    p.style.setProperty('--delay', Math.round(delayMs) + 'ms');
    p.style.setProperty('--dur', seconds.toFixed(2) + 's');
    parent.appendChild(p);
  }

  /* ------------------------------------------------------------ counter */
  function ensureCounter() {
    if (counterEl) return counterEl;
    const brand = document.querySelector('.brand');
    if (!brand) return null;
    counterEl = make('span', 'brand-count');
    counterEl.id = 'brand-count';
    counterEl.hidden = true;
    brand.appendChild(counterEl);
    return counterEl;
  }

  function renderCounter() {
    const el = ensureCounter();
    if (!el) return;
    const n = detonated == null ? 0 : detonated;
    el.hidden = n < 1;
    if (n >= 1) {
      el.textContent = n.toLocaleString();   // just the number; the tooltip explains it
      el.title = n.toLocaleString() + ' stick' + (n === 1 ? '' : 's') + ' of TNT detonated on this machine';
    }
  }

  function readLocal() {
    try { const v = parseInt(localStorage.getItem(STORAGE_KEY), 10); return isFinite(v) && v > 0 ? v : 0; } catch (e) { return 0; }
  }
  function writeLocal(n) {
    try { localStorage.setItem(STORAGE_KEY, String(n)); } catch (e) { /* ignore */ }
  }

  async function loadCount() {
    try {
      if (TNT.api && TNT.api.easter) {
        const r = await TNT.api.easter();
        if (r && typeof r.detonated === 'number') { detonated = r.detonated; writeLocal(detonated); renderCounter(); return; }
      }
    } catch (e) { /* service unreachable: fall back below */ }
    detonated = readLocal();
    renderCounter();
  }

  async function recordDetonation(n) {
    try {
      if (TNT.api && TNT.api.detonate) {
        const r = await TNT.api.detonate(n);
        if (r && typeof r.detonated === 'number') { detonated = r.detonated; writeLocal(detonated); renderCounter(); return; }
      }
    } catch (e) { /* keep counting locally */ }
    detonated = (detonated == null ? readLocal() : detonated) + n;
    writeLocal(detonated);
    renderCounter();
  }

  /* --------------------------------------------------------------- boot */
  function boot() {
    document.addEventListener('click', (e) => {
      const logo = e.target.closest('#brand-logo');
      if (!logo) return;
      e.preventDefault();      // the logo is inside the brand link: do not navigate
      e.stopPropagation();
      throwStick();
    }, true);
    loadCount();
  }

  TNT.egg = {
    throwStick,
    forceBlock: false,    // testing aid: every stick becomes the block
    blockSvg,
    explodeNow() { if (sticks && !exploding) { fuseStart = -Infinity; tick(); } },
    get sticks() { return sticks; },
    get detonated() { return detonated; },
    MAX_STICKS, FUSE_MS,
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
