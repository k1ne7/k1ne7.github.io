(() => {
  'use strict';
  // Keep Butterfly's counter markup; replace the unavailable legacy JSONP API.
  if (window.blogViewCountersLoaded) return;
  window.blogViewCountersLoaded = true;

  async function load() {
    const counters = ['page_pv', 'site_pv', 'site_uv'].map(key => ({
      key, element: document.getElementById(`busuanzi_value_${key}`)
    })).filter(item => item.element);
    if (!counters.length) return;

    function status(text, title) {
      for (const { element } of counters) {
        element.textContent = text;
        element.title = title;
        element.setAttribute('aria-busy', 'false');
      }
    }

    if (location.hostname !== 'k1ne7.github.io') {
      status('—', '本地预览不计入线上访问统计');
      return;
    }
    for (const { element } of counters) element.setAttribute('aria-busy', 'true');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    try {
      const canonical = document.querySelector('link[rel="canonical"]')?.href || location.href;
      const page = new URL(canonical);
      page.hash = '';
      page.search = '';
      const response = await fetch('https://bsz.dusays.com:9001/api', {
        method: 'POST',
        headers: { 'x-bsz-referer': page.href },
        signal: controller.signal
      });
      if (!response.ok) throw new Error('Counter unavailable');
      const result = await response.json();
      if (result.success !== true || counters.some(({ key }) =>
        !Number.isSafeInteger(result.data?.[key]) || result.data[key] < 0)) {
        throw new Error('Invalid counter response');
      }
      for (const { key, element } of counters) {
        element.textContent = String(result.data[key]);
        element.title = '访问统计仅供参考';
        element.setAttribute('aria-busy', 'false');
      }
    } catch {
      status('暂不可用', '统计服务暂时无法连接，请稍后刷新重试');
    } finally {
      clearTimeout(timer);
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', load, { once: true });
  else load();
})();
