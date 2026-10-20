(() => {
  'use strict';

  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const controls = [
    'button', '[role="button"]', '#card-info-btn', '#pagination a',
    '.card-category-list-link', '#nav .menus_item a', '.social-icon', '.card-tag-cloud a'
  ].join(',');
  const colors = ['#b58ce9', '#dfc7ff', '#9864c5', '#f5e9ff', '#dca8e8'];
  let canvas, context, frame = 0, lastTime = 0;
  let particles = [];

  function resize() {
    if (!canvas) return;
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.ceil(window.innerWidth * ratio);
    canvas.height = Math.ceil(window.innerHeight * ratio);
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
  }

  function clear() {
    cancelAnimationFrame(frame);
    frame = 0;
    lastTime = 0;
    particles = [];
    if (context) context.clearRect(0, 0, window.innerWidth, window.innerHeight);
  }

  function draw(time) {
    const step = Math.min((time - (lastTime || time)) / 16.67, 2);
    lastTime = time;
    context.clearRect(0, 0, window.innerWidth, window.innerHeight);
    particles = particles.filter(particle => time - particle.start < particle.life);
    for (const particle of particles) {
      const progress = (time - particle.start) / particle.life;
      particle.x += particle.vx * step;
      particle.y += particle.vy * step;
      particle.vy += .065 * step;
      particle.vx *= Math.pow(.98, step);
      context.globalAlpha = (1 - progress) ** 2;
      context.strokeStyle = particle.color;
      context.lineWidth = particle.size * (1 - progress * .5);
      context.lineCap = 'round';
      context.beginPath();
      context.moveTo(particle.x, particle.y);
      context.lineTo(particle.x - particle.vx * 1.8, particle.y - particle.vy * 1.8);
      context.stroke();
    }
    context.globalAlpha = 1;
    if (particles.length) frame = requestAnimationFrame(draw);
    else clear();
  }

  document.addEventListener('click', event => {
    if (reducedMotion.matches || document.hidden || !(event.target instanceof Element)) return;
    const control = event.target.closest(controls);
    if (!control || control.matches(':disabled, [aria-disabled="true"]')) return;
    if (!canvas) {
      canvas = document.createElement('canvas');
      canvas.id = 'button-fireworks';
      canvas.setAttribute('aria-hidden', 'true');
      canvas.style.cssText = 'position:fixed;inset:0;z-index:3000;pointer-events:none;width:100%;height:100%;';
      context = canvas.getContext('2d');
      if (!context) { canvas = undefined; return; }
      document.body.append(canvas);
      resize();
    }
    const rect = control.getBoundingClientRect();
    const x = event.detail ? event.clientX : rect.left + rect.width / 2;
    const y = event.detail ? event.clientY : rect.top + rect.height / 2;
    const start = performance.now();
    // Keep quick repeated clicks bounded and stop drawing once the burst fades.
    particles = particles.slice(-70);
    for (let i = 0; i < 26; i++) {
      const angle = Math.PI * 2 * i / 26 + Math.random() * .15;
      const speed = 1.4 + Math.random() * 3;
      particles.push({
        x, y, vx: Math.cos(angle) * speed, vy: Math.sin(angle) * speed - .6,
        start, life: 550 + Math.random() * 300,
        size: 1.2 + Math.random() * 1.4, color: colors[i % colors.length]
      });
    }
    if (!frame) frame = requestAnimationFrame(draw);
  }, { capture: true, passive: true });

  window.addEventListener('resize', resize, { passive: true });
  document.addEventListener('visibilitychange', () => { if (document.hidden) clear(); });
  reducedMotion.addEventListener('change', () => { if (reducedMotion.matches) clear(); });
})();
