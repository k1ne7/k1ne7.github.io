'use strict';

// Add a static signature using Hexo's render hook, keeping the theme untouched.
const { escapeHTML } = require('hexo-util');

hexo.extend.filter.register('after_render:html', html => {
  const signature = hexo.config.subtitle;
  if (!signature || html.includes('id="site-signature"')) return html;
  return html.replace(
    /(<div id="site-info">\s*<h1\b[^>]*>[\s\S]*?<\/h1>)/,
    `$1<p id="site-signature">${escapeHTML(signature)}</p>`
  );
});
