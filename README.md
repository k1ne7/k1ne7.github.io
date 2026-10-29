# k1ne 的博客 · Hexo + Butterfly

使用官方 [Butterfly](https://butterfly.js.org/) 主题，通过 npm 安装并锁定版本。
站点地址：https://k1ne7.github.io，不需要续费旧域名或虚拟主机。

## 本地运行

需要 Node.js 22.22.0+，推荐 Node.js 24 LTS。

```powershell
npm ci
npm run dev
```

访问 http://localhost:4323。`npm run build` 生成静态网站到 `dist/`；
`npm run preview` 可预览构建结果。

## 写文章

```powershell
npm run new -- post "文章标题"
```

文章在 `source/_posts/`。文件名成为网址，发布后尽量不要改动。
例如 `meet.md` → `/blog/meet/`。文章开头：

```yaml
---
title: 文章标题
date: 2026-10-20 15:00:00
categories:
  - 生活
tags:
  - 随笔
description: 列表显示的摘要
cover: /images/meet.jpg
---
```

正文用 Markdown，图片放 `source/images/`，以 `/images/文件名.jpg` 引用。
也可以直接在 GitHub 网页新增或编辑文章并提交，触发自动部署。

草稿：`npx hexo new draft "标题"`，存在 `source/_drafts/`，默认不生成网页。
发布：`npx hexo publish "标题"`。草稿若提交到公开仓库，源码仍会公开；私密内容不要提交。

## 配置与主题

- `_config.yml`：标题、作者、域名、文章链接和插件。
- `_config.butterfly.yml`：导航、封面、头像、侧栏、搜索和深浅色模式。
- `source/about/index.md`：关于页面。
- `source/css/custom.css`：少量可访问性调整，主体保持官方主题。
- `scaffolds/`：新文章和页面模板。

首页大图暂时沿用旧站文章配图。更换后修改 `index_img` 和 `default_top_img` 即可。
首页封面占满一屏，向下滚动后显示文章列表。
`background` 设置列表及其他页面的固定背景，当前与首页大图相同；卡片半透明，不使用背景模糊。
`theme_color` 配置紫色强调色；按钮悬停和按压有轻微反馈，并尊重系统的减少动态效果设置。
点击时附近的文字、图片和页面背景会产生局部黑洞扭曲，短暂吸入、爆散并复原（`source/js/black-hole.js`）；移动鼠标不会触发。
黑洞、粒子和扭曲范围统一缩小至原来的 70%。手机端支持点击效果，按钮支持键盘触发；滚动、切换窗口或开启减少动态效果时清理动画，选择文字时不触发点击效果。
文章的 `cover` 同时用于列表封面、文章顶部与整页背景；《遇见》已使用 `meet-winter.png`。
文章背景由 `scripts/article-background.js` 自动跟随主题渲染的封面，正文与侧栏使用半透明卡片。
如果另设 `top_img`，文章背景会跟随该顶部图片；不设时自动使用 `cover`。
搜索、RSS、站点地图已配置；评论尚未接入。
访问统计使用 `source/js/view-counter.js` 对接 `https://bsz.dusays.com:9001/api`，兼容 Butterfly 的统计位置。
只在正式域名计数，本地预览显示 `—`；请求失败或超过 10 秒时显示“暂不可用”。统计数字仅供参考，切换服务前的历史数字不自动迁移。
已启用 `hexo-wordcount`：文章顶部显示字数和预计阅读分钟数，侧栏网站信息显示所有已发布文章的总字数。
首页文章卡片也在发表时间、分类旁显示字数和预计阅读时间，使用与文章页相同的统计方式，手机端自动换行。
统计按中文字符、英文单词估算，包含正文中的代码文本；阅读时长仅供参考，最少显示 1 分钟。
图标字体通过 `tools/vendor-assets.cjs` 从 npm 包复制到本地，随站点部署。
不要直接修改 `node_modules/` 内主题文件；更新依赖会覆盖它们。

## 部署到 GitHub Pages

### 添加友链

编辑 `source/_data/link.yml`，将 `link_list: []` 替换为下面的列表，填写真实信息：

```yaml
  link_list:
    - name: 朋友的博客名
      link: https://example.com/
      avatar: /images/avatar.jpg
      descr: 朋友的博客简介
```

`avatar` 改成对方头像链接，也可以将图片保存到 `source/images/` 后引用本地路径。
添加更多朋友时，继续增加同级的 `- name:` 条目。友链展示在 `/link/`，导航已添加入口。
这是手动维护的友链列表，不会自动接受申请；提交推送后才会更新线上页面。

### 发布步骤

仓库：https://github.com/k1ne7/k1ne7.github.io。

1. 仓库 **Settings → Pages → Build and deployment → Source** 选择 **GitHub Actions**。
2. 提交并推送本项目：

   ```powershell
   git add .
   git commit -m "迁移到 Hexo + Butterfly"
   git push -u origin main
   ```

3. 在 **Actions** 查看 `Deploy to GitHub Pages`，构建与部署成功后访问站点。
   如果第一次推送时尚未启用 Pages，可在启用后手动重新运行工作流。

每次推送到 `main` 会执行 `npm ci`、构建，再发布 `dist/`。
不要将构建目录、依赖或备份手动上传到仓库。

## 迁移内容与旧站备份

从旧站整理的公开文章为《遇见》，保留原发布日期、分类、转载署名和配图。
另已导入本地漏洞报告 `GHSA-4p5g-gh74-q524.md`，文章为 `source/_posts/repomix-git-config-rce.md`，
使用 `source/images/repomix-report.png` 作为封面和背景。日期为博客导入日期，不代表漏洞披露日期。
导入时仅整理标题、元数据和代码块排版，保留报告技术内容，未重新验证报告中的漏洞结论。
另从 `D:/漏洞报告/src/blog` 导入三篇报告到“渗透”分类：

- `insurance-order-callback-auth-bypass.md`：订单回调未授权，封面为红眼角色图。
- `chat-message-unauthorized-access.md`：聊天消息未授权，封面为持枪角色图。
- `payment-order-idor.md`：支付接口水平越权，封面为黑白简笔画。

正文四张截图保存在 `source/images/pentest/`，原始报告备份在 `_backup/pentest-reports-original/`。
正文截图按作者确认保留原图，与文章一同发布。
头像和图片已本地化，不依赖旧域名。请在旧站后台核对是否还有其他文章和页面。

`_backup/` 已从 Git 排除，其中公开内容抓取记录并非 WordPress 完整备份。
旧主机到期前，请另行下载「工具 → 导出 → 所有内容」XML、完整图片附件、
主机网站文件和数据库备份。草稿、私密文章及评论不能凭公开接口确认已保存。
旧域名到期后，原链接不会自动转到新站，需要向读者告知新地址。

## 回滚到迁移前的 Astro 版本

切换前的文件在 `_backup/astro-before-hexo/`，包含文章、图片、依赖锁文件和部署工作流。
先备份新写的 Hexo 文章，将 `src/`、`public/`、`astro.config.mjs`、`tsconfig.json`、
`package.json`、`package-lock.json` 和 README 恢复到原位置，
将备份的 `deploy.yml` 恢复到 `.github/workflows/deploy.yml`，再执行 `npm ci`、`npm run build`。
这份备份仅在当前机器；旧 Astro 源码也可从 Git 历史 `0fd2c2d` 取回。

## 依赖状态

npm 审计报告包含 Hexo 上游构建依赖的 9 项告警（2 moderate、7 high），
自动修复建议会降级 Hexo，暂未强制修改上游依赖。它们属于本地/CI 构建链，Pages 只提供生成的静态文件。
不要运行会强制降级 Hexo 的 `npm audit fix --force`；升级时先核对官方兼容性和构建结果。
