// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

// 部署到 https://k1ne7.github.io（仓库名必须是 k1ne7.github.io，站点才在根路径）
// 将来换自定义域名，只改这一行 site 即可，其余不用动。
export default defineConfig({
  site: 'https://k1ne7.github.io',
  integrations: [sitemap()],
  markdown: {
    shikiConfig: { theme: 'github-light' },
  },
});
