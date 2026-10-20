# k1ne 的博客

从 WordPress（Sakurairo 主题，虚拟主机）迁移过来的静态博客，用 [Astro](https://astro.build) 构建，
部署在 GitHub Pages 上，零服务器、零数据库、零费用。

线上地址：<https://k1ne7.github.io>

## 本地开发

```bash
npm install       # 第一次
npm run dev       # 本地预览 http://localhost:4321
npm run build     # 构建到 dist/
npm run preview   # 预览构建结果
```

需要 Node 18+（推荐 22）。

## 写文章

在 `src/content/blog/` 里新建一个 `.md` 文件，文件名就是 URL 的一部分：

```
src/content/blog/hello-world.md  →  https://k1ne7.github.io/blog/hello-world/
```

文件开头写 frontmatter：

```yaml
---
title: 标题
date: 2026-03-10T19:24:08+08:00
category: 感想          # 可选，显示成标签
excerpt: 摘要，显示在列表卡片上   # 可选
cover: /images/foo.jpg  # 可选，卡片和文章顶部的配图
draft: false            # true = 不发布
---
```

正文用 Markdown 写即可。诗歌这种要保留换行的，行尾加两个空格。

图片放 `public/images/`，引用写 `/images/xxx.jpg`。

## 目录结构

```
src/
├─ content/blog/        文章（Markdown）
├─ content.config.ts    文章字段的校验规则
├─ layouts/             页面骨架
├─ components/          顶栏、页脚、文章卡片
├─ pages/
│  ├─ index.astro       首页
│  ├─ blog/index.astro  文章列表
│  ├─ blog/[...slug].astro  文章详情（按文件名自动生成）
│  ├─ about.astro       关于
│  ├─ 404.astro         404
│  └─ rss.xml.js        RSS
└─ styles/global.css    全部样式（配色、排版、响应式）
.github/workflows/deploy.yml  推送到 main 自动部署
```

## 部署到 GitHub Pages

1. 在 GitHub 上建一个**公开**仓库，名字必须是 `k1ne7.github.io`
   （仓库名和用户名一致，站点才会在 `https://k1ne7.github.io/` 根路径下）
2. 本仓库推上去：

   ```bash
   git remote add origin https://github.com/k1ne7/k1ne7.github.io.git
   git branch -M main
   git push -u origin main
   ```

3. 仓库 **Settings → Pages → Build and deployment → Source** 选 **GitHub Actions**
4. 等 Actions 跑完（约 1 分钟），访问 `https://k1ne7.github.io/`

之后每次 `git push` 到 `main` 都会自动重新构建部署。

## 换成自己的域名

1. 在域名服务商加记录：
   - `www` → CNAME → `k1ne7.github.io`
   - 根域名 → A → `185.199.108.153` / `185.199.109.153` / `185.199.110.153` / `185.199.111.153`
2. 仓库 Settings → Pages → Custom domain 填域名，勾 **Enforce HTTPS**
3. 把 `astro.config.mjs` 里的 `site` 改成新域名，同步改 `public/robots.txt` 里的 Sitemap 地址，重新 push

## 配置项

- `astro.config.mjs` — 站点地址（`site`）、sitemap
- `src/components/Header.astro` — 导航菜单
- `src/components/Footer.astro` — 页脚链接（RSS / GitHub / Bilibili）
- `src/styles/global.css` — 配色变量在文件顶部，`--accent` 是强调色，`--skin` 是原站的主色

## 从旧站带过来的东西

- 文章《遇见》（`src/content/blog/meet.md`）
- 头像（`public/images/avatar.jpg`）
- 文章配图（`public/images/meet.jpg`）

旧站的完整备份在 `_backup/`（已加进 `.gitignore`，不会上传）。
其中有一张微信加好友二维码，属于个人信息，**没有**放进站点。

## 待办

- [ ] 评论：接 [giscus](https://giscus.app)，需要仓库开启 Discussions
- [ ] 搜索：文章多了以后用 [Pagefind](https://pagefind.app)
- [ ] 统计：可接 Umami / Cloudflare Web Analytics
