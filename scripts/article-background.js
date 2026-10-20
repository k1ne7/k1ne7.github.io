'use strict';

// Reuse the cover rendered by Butterfly for each post, without changing theme files.
// Missing covers keep the theme's normal page background.
hexo.extend.filter.register('after_render:html', html => {
  if (!/<div\b[^>]*class="post(?:\s[^"]*)?"[^>]*id="body-wrap"/.test(html)) return html;
  const header = html.match(/<header\b[^>]*id="page-header"[^>]*style="([^"]*)"/);
  if (!header || !header[1].includes('background-image:')) return html;
  return html.replace(
    '<body>',
    `<body class="article-cover-background"><div class="article-wallpaper" aria-hidden="true" style="${header[1]}"></div>`
  );
});
