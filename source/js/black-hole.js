(() => {
  'use strict';
  if (window.blogBlackHole) return;
  window.blogBlackHole = true;

  const motion = matchMedia('(prefers-reduced-motion: reduce)');
  const finePointer = matchMedia('(hover: hover) and (pointer: fine)');
  const NS = 'http://www.w3.org/2000/svg';
  const targets = 'a,button,[role="button"],p,h1,h2,h3,h4,h5,h6,li,pre,td,img,' +
    '#site-subtitle,.flink-list-item,.recent-post-item,.card-widget';
  const excluded = 'input,textarea,select,[contenteditable="true"],video,iframe';
  const colors = ['#c5a2ff', '#8b65dd', '#f4e8ff', '#b4caff'];
  const slots = [];
  const point = { x: -500, y: -500, tx: -500, ty: -500 };
  let canvas, ctx, svg, defs, warpImage, holeImage;
  let frame = 0, lastMove = 0, lastScan = 0, burst = null, particles = [];
  let hovering = false;

  function node(tag, attrs, parent) {
    const element = document.createElementNS(NS, tag);
    for (const [key, value] of Object.entries(attrs)) element.setAttribute(key, value);
    parent.append(element);
    return element;
  }

  // An identity displacement is RGB(128,128,*). Only the circular lens differs.
  // Using an image primitive keeps the map small even on very long articles.
  function makeMaps() {
    const map = document.createElement('canvas');
    map.width = map.height = 192;
    const painter = map.getContext('2d');
    const pixels = painter.createImageData(192, 192);
    for (let y = 0; y < 192; y++) {
      for (let x = 0; x < 192; x++) {
        const dx = (x - 95.5) / 96, dy = (y - 95.5) / 96;
        const distance = Math.hypot(dx, dy);
        const pull = distance < 1 ? Math.sin(Math.PI * distance) ** 2 : 0;
        const offset = (y * 192 + x) * 4;
        pixels.data[offset] = 128 + (dx * .85 - dy * .38) * pull * 110;
        pixels.data[offset + 1] = 128 + (dy * .85 + dx * .38) * pull * 110;
        pixels.data[offset + 2] = 128;
        pixels.data[offset + 3] = 255;
      }
    }
    painter.putImageData(pixels, 0, 0);
    warpImage = map.toDataURL();
    painter.clearRect(0, 0, 192, 192);
    const fade = painter.createRadialGradient(96, 96, 0, 96, 96, 96);
    fade.addColorStop(0, 'rgba(255,255,255,1)');
    fade.addColorStop(.48, 'rgba(255,255,255,.95)');
    fade.addColorStop(1, 'rgba(255,255,255,0)');
    painter.fillStyle = fade;
    painter.fillRect(0, 0, 192, 192);
    holeImage = map.toDataURL();
  }

  function init() {
    if (canvas) return true;
    canvas = document.createElement('canvas');
    canvas.id = 'black-hole';
    canvas.setAttribute('aria-hidden', 'true');
    ctx = canvas.getContext('2d');
    if (!ctx) { canvas = null; return false; }
    svg = node('svg', { width: 0, height: 0, 'aria-hidden': 'true', focusable: 'false' }, document.body);
    svg.id = 'black-hole-filters';
    defs = node('defs', {}, svg);
    makeMaps();
    document.body.append(canvas);
    resize();
    return true;
  }

  function resize() {
    if (!canvas) return;
    const dpr = Math.min(devicePixelRatio || 1, 2);
    canvas.width = Math.round(innerWidth * dpr);
    canvas.height = Math.round(innerHeight * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    lastScan = 0;
  }

  function createSlot() {
    const filter = node('filter', {
      id: `gravity-lens-${slots.length}`, filterUnits: 'userSpaceOnUse',
      primitiveUnits: 'userSpaceOnUse', 'color-interpolation-filters': 'sRGB'
    }, defs);
    node('feFlood', { 'flood-color': 'rgb(128,128,128)', result: 'neutral' }, filter);
    const map = node('feImage', { href: warpImage, preserveAspectRatio: 'none', result: 'lens' }, filter);
    node('feComposite', { in: 'lens', in2: 'neutral', operator: 'over', result: 'map' }, filter);
    const displacement = node('feDisplacementMap', {
      in: 'SourceGraphic', in2: 'map', scale: 0,
      xChannelSelector: 'R', yChannelSelector: 'G', result: 'warped'
    }, filter);
    const hole = node('feImage', { href: holeImage, preserveAspectRatio: 'none', result: 'hole' }, filter);
    const transfer = node('feComponentTransfer', { in: 'hole', result: 'fade' }, filter);
    const alpha = node('feFuncA', { type: 'linear', slope: 0 }, transfer);
    node('feComposite', { in: 'warped', in2: 'fade', operator: 'out' }, filter);
    const slot = { filter, map, displacement, hole, alpha, element: null };
    slots.push(slot);
    return slot;
  }

  function release(slot) {
    if (!slot.element) return;
    // Restore the exact inline value (including priority) after the visual effect.
    if (slot.saved) slot.element.style.setProperty('filter', slot.saved, slot.priority);
    else slot.element.style.removeProperty('filter');
    slot.element.removeAttribute('data-gravity-lens');
    slot.element = null;
  }

  function scan(x, y, radius) {
    const found = new Set();
    for (const [dx, dy] of [[0, 0], [-.65, 0], [.65, 0], [0, -.65], [0, .65],
      [-.55, -.55], [.55, -.55], [-.55, .55], [.55, .55]]) {
      const px = x + dx * radius, py = y + dy * radius;
      if (px < 0 || px >= innerWidth || py < 0 || py >= innerHeight) continue;
      const hit = document.elementFromPoint(px, py);
      if (!hit || hit.closest(excluded)) continue;
      const target = hit.closest(targets);
      if (target && !target.closest('[data-gravity-ui]')) found.add(target);
    }
    // Never filter a parent and its child at once, or create a containing block
    // around navigation, fixed controls, a whole document, or an entire article.
    const nearby = [...found].filter(el => ![...found].some(other => other !== el && other.contains(el)));
    const background = document.querySelector('body.article-cover-background .article-wallpaper') || document.querySelector('#web_bg');
    if (background) nearby.push(background);
    for (const slot of slots) if (slot.element && !nearby.includes(slot.element)) release(slot);
    for (const element of nearby.slice(0, 10)) {
      let slot = slots.find(item => item.element === element);
      if (!slot) {
        slot = slots.find(item => !item.element) || createSlot();
        slot.element = element;
        slot.saved = element.style.getPropertyValue('filter');
        slot.priority = element.style.getPropertyPriority('filter');
        element.style.setProperty('filter', `url("#${slot.filter.id}")`);
        element.setAttribute('data-gravity-lens', '');
      }
    }
    for (const slot of slots) {
      if (!slot.element) continue;
      const rect = slot.element.getBoundingClientRect();
      slot.rect = rect;
      slot.filter.setAttribute('x', -64);
      slot.filter.setAttribute('y', -64);
      slot.filter.setAttribute('width', rect.width + 128);
      slot.filter.setAttribute('height', rect.height + 128);
    }
  }

  function deform(x, y, radius, strength, disappearance) {
    for (const slot of slots) {
      if (!slot.element) continue;
      const px = x - slot.rect.left, py = y - slot.rect.top;
      for (const image of [slot.map, slot.hole]) {
        image.setAttribute('x', px - radius);
        image.setAttribute('y', py - radius);
        image.setAttribute('width', radius * 2);
        image.setAttribute('height', radius * 2);
      }
      slot.displacement.setAttribute('scale', strength);
      slot.alpha.setAttribute('slope', disappearance);
    }
  }

  function seedParticles(x, y) {
    const hit = document.elementFromPoint(x, y);
    const text = (hit?.closest(targets)?.textContent || '').replace(/\s/g, '').slice(0, 24);
    particles = Array.from({ length: 38 }, (_, i) => {
      const angle = Math.random() * Math.PI * 2;
      return { angle, radius: 25 + Math.random() * 90, speed: 70 + Math.random() * 115,
        size: 2 + Math.random() * 3, glyph: i % 4 === 0 ? text[i % (text.length || 1)] : '',
        color: colors[i % colors.length], spin: Math.random() * 3 - 1.5 };
    });
  }

  function render(time) {
    frame = 0;
    const progress = burst ? (time - burst.start) / 1100 : 1;
    if (burst && progress >= 1) { burst = null; particles = []; }
    const activeBurst = !!burst;
    const idle = Math.max(0, 1 - (time - lastMove - 750) / 450);
    const visibility = hovering ? Math.min(1, idle) : 0;
    if (!activeBurst && visibility <= 0) { clear(); return; }
    point.x += (point.tx - point.x) * .38;
    point.y += (point.ty - point.y) * .38;
    const x = activeBurst ? burst.x : point.x, y = activeBurst ? burst.y : point.y;
    const pulse = activeBurst ? Math.sin(Math.PI * Math.min(1, progress / .85)) : 0;
    const radius = 112 + pulse * 54;
    if (time - lastScan > 70 || !lastScan) { scan(x, y, radius); lastScan = time; }
    deform(x, y, radius, activeBurst ? 28 + pulse * 125 : 36 * visibility,
      activeBurst ? Math.sin(Math.PI * Math.min(1, progress / .72)) * .88 : 0);
    ctx.clearRect(0, 0, innerWidth, innerHeight);
    ctx.save();
    ctx.translate(x, y);
    const opacity = activeBurst ? 1 - progress : visibility * .75;
    const glow = ctx.createRadialGradient(0, 0, 6, 0, 0, 65 + pulse * 35);
    glow.addColorStop(0, 'rgba(10,4,24,.64)');
    glow.addColorStop(.28, 'rgba(99,50,176,.2)');
    glow.addColorStop(.65, 'rgba(187,145,255,.1)');
    glow.addColorStop(1, 'rgba(154,100,250,0)');
    ctx.globalAlpha = opacity;
    ctx.fillStyle = glow;
    ctx.beginPath(); ctx.arc(0, 0, 110, 0, Math.PI * 2); ctx.fill();
    ctx.rotate(time * .0015);
    ctx.strokeStyle = '#cdb4ff'; ctx.lineWidth = 1.2;
    ctx.beginPath(); ctx.ellipse(0, 0, 23 + pulse * 12, 8 + pulse * 7, -.4, 0, Math.PI * 2); ctx.stroke();
    ctx.strokeStyle = 'rgba(164,120,239,.45)';
    ctx.beginPath(); ctx.ellipse(0, 0, 33 + pulse * 20, 13 + pulse * 8, .35, .5, Math.PI * 1.7); ctx.stroke();
    ctx.rotate(-time * .0015);
    ctx.fillStyle = '#10091c';
    ctx.beginPath(); ctx.arc(0, 0, 7 + pulse * 9, 0, Math.PI * 2); ctx.fill();
    if (activeBurst) {
      for (const particle of particles) {
        const contraction = Math.max(0, 1 - progress / .3);
        const expansion = Math.max(0, (progress - .3) / .7);
        const distance = particle.radius * contraction + particle.speed * expansion;
        const angle = particle.angle + Math.min(progress / .3, 1) * 2.5;
        ctx.save();
        ctx.translate(Math.cos(angle) * distance, Math.sin(angle) * distance);
        ctx.rotate(particle.spin * progress * 5);
        ctx.globalAlpha = (1 - expansion) ** 1.5;
        ctx.fillStyle = particle.color;
        if (particle.glyph) { ctx.font = '13px sans-serif'; ctx.fillText(particle.glyph, 0, 0); }
        else ctx.fillRect(-particle.size / 2, -particle.size / 2, particle.size, particle.size * .65);
        ctx.restore();
      }
      ctx.globalAlpha = (1 - progress) * .5;
      ctx.strokeStyle = '#d8c2ff';
      ctx.beginPath(); ctx.arc(0, 0, 15 + progress * 115, 0, Math.PI * 2); ctx.stroke();
    }
    ctx.restore();
    frame = requestAnimationFrame(render);
  }

  function start() {
    if (!frame && init()) frame = requestAnimationFrame(render);
  }

  function clear() {
    cancelAnimationFrame(frame);
    frame = 0; burst = null; particles = []; lastScan = 0;
    for (const slot of slots) release(slot);
    if (ctx) ctx.clearRect(0, 0, innerWidth, innerHeight);
  }

  document.addEventListener('pointermove', event => {
    if (motion.matches || !finePointer.matches || event.pointerType === 'touch' || document.hidden) return;
    if (event.buttons || event.target.closest?.(excluded) || !getSelection().isCollapsed) {
      hovering = false; clear(); return;
    }
    if (!hovering) { point.x = event.clientX; point.y = event.clientY; }
    point.tx = event.clientX; point.ty = event.clientY;
    hovering = true; lastMove = performance.now(); start();
  }, { passive: true });

  document.addEventListener('click', event => {
    if (motion.matches || document.hidden || !(event.target instanceof Element)) return;
    if (event.target.closest(excluded) || !getSelection().isCollapsed || event.target.closest(':disabled,[aria-disabled="true"]')) return;
    const control = event.target.closest('a,button,[role="button"]');
    if (!event.detail && !control) return;
    const rect = control?.getBoundingClientRect();
    const x = event.detail ? event.clientX : rect.left + rect.width / 2;
    const y = event.detail ? event.clientY : rect.top + rect.height / 2;
    burst = { x, y, start: performance.now() };
    lastScan = 0;
    seedParticles(x, y);
    // Native activation and navigation continue immediately.
    start();
  }, { passive: true, capture: true });

  document.addEventListener('pointerleave', () => { hovering = false; if (!burst) clear(); });
  document.addEventListener('visibilitychange', () => { if (document.hidden) { hovering = false; clear(); } });
  window.addEventListener('blur', () => { hovering = false; clear(); });
  window.addEventListener('resize', () => { clear(); resize(); }, { passive: true });
  window.addEventListener('scroll', () => { hovering = false; clear(); }, { passive: true });
  motion.addEventListener('change', () => { hovering = false; clear(); });
  document.addEventListener('pjax:send', () => { hovering = false; clear(); });
})();
