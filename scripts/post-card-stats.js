'use strict';

// Reuse Butterfly's word-count helpers in listing cards without editing the theme.
let statsByPath = new Map();

function routePath(value) {
  return decodeURI(new URL(value, hexo.config.url).pathname)
    .replace(/index\.html$/, '').replace(/\/?$/, '/');
}

hexo.extend.filter.register('before_generate', () => {
  statsByPath = new Map();
  const settings = hexo.theme.config.wordcount;
  if (!settings || !settings.enable) return;
  const wordcount = hexo.extend.helper.get('wordcount');
  const min2read = hexo.extend.helper.get('min2read');
  if (!wordcount || !min2read) return;

  hexo.locals.get('posts').forEach(post => {
    const parts = [];
    if (settings.post_wordcount) {
      parts.push(`<span class="post-card-stat"><span class="article-meta-separator" aria-hidden="true">|</span><i class="far fa-file-word" aria-hidden="true"></i><span>字数：${wordcount(post.content)}</span></span>`);
    }
    if (settings.min2read) {
      parts.push(`<span class="post-card-stat"><span class="article-meta-separator" aria-hidden="true">|</span><i class="far fa-clock" aria-hidden="true"></i><span>预计阅读：${min2read(post.content, { cn: 350, en: 160 })} 分钟</span></span>`);
    }
    statsByPath.set(routePath('/' + post.path), parts.join(''));
  });
});

hexo.extend.filter.register('after_render:html', html => {
  if (!html.includes('article-meta-wrap') || !statsByPath.size) return html;
  return html.replace(
    /(<a\b[^>]*class="article-title"[^>]*href="([^"]+)"[^>]*>[\s\S]*?<\/a>\s*<div class="article-meta-wrap">)([\s\S]*?)(<\/div>)/g,
    (match, opening, href, metadata, closing) => {
      const stats = statsByPath.get(routePath(href));
      if (!stats || metadata.includes('post-card-stat')) return match;
      return opening + metadata + stats + closing;
    }
  );
});
