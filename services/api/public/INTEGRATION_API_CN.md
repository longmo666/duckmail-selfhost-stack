# DuckMail 自部署对接文档（脱敏示例版）

更新时间：2026-04-03（Asia/Shanghai）  
服务地址：`https://your-api.example.com`

本文档基于当前实现与实测结果整理，并参考社区开源 DuckMail 项目的文档格式（非官方）：  
`https://raw.githubusercontent.com/MoonWeSif/DuckMail/main/public/llm-api-docs.txt`

---

## 1. 鉴权方式

### 1.1 管理员鉴权（后台接口）
- Header：`x-admin-key: <ADMIN_KEY>`
- 用于：`/admin/*`

### 1.2 API Key 鉴权（自动化对接）
- Header：`Authorization: Bearer dk_xxx`
- 用于：`/domains`、`/accounts`、`/mailboxes/open`（按权限控制）

### 1.3 用户 Token 鉴权（邮箱会话）
- Header：`Authorization: Bearer <jwt>`
- 用于：`/me`、`/messages*`、`/codes/latest`、`/accounts/{id}`

---

## 2. API Key 权限

`GET /api-keys/permissions` 返回可选权限：
- `domains:read`：读取可用域名列表
- `accounts:create`：创建邮箱/打开邮箱
- `messages:read`：预留（当前消息读取仍基于用户 Token）

---

## 3. 管理端接口（Admin）

### 3.1 登录校验
`POST /admin/login`

```json
{ "key": "your_admin_key" }
```

### 3.2 统计信息
`GET /admin/stats`

### 3.3 域名管理
- `GET /admin/domains`
- `POST /admin/domains`
- `POST /admin/domains/:id/verify`
- `DELETE /admin/domains/:id`

新增域名返回 DNS 指引：
- TXT：`_duckmail-challenge.<domain>` = `<token>`
- MX：`<domain>` -> `<your-mx-host.example.com>`（prio 10）

### 3.4 API Key 管理
- `GET /admin/api-keys`
- `POST /admin/api-keys`
- `DELETE /admin/api-keys/:id`

创建请求示例：

```json
{
  "name": "prod-bot",
  "permissions": ["domains:read", "accounts:create", "messages:read"],
  "expiresInDays": 30
}
```

---

## 4. 对接接口（业务）

### 4.1 域名列表
`GET /domains`

- 可匿名访问
- 带 API Key 时会校验 `domains:read` 权限
- 返回已验证域名

### 4.2 创建邮箱（传统）
`POST /accounts`

```json
{
  "address": "bot@example-mail.test",
  "password": "your_password_here",
  "expiresIn": 3600
}
```

说明：
- 可带 API Key（需要 `accounts:create`）
- `password` 可选；若为空系统会生成随机密码哈希

### 4.3 打开邮箱（推荐，免密码）
`POST /mailboxes/open`

两种模式：

1) 指定邮箱地址

```json
{ "address": "bot@example-mail.test" }
```

2) 指定域名随机生成邮箱

```json
{ "domain": "example-mail.test" }
```

返回示例：

```json
{
  "id": "account-id",
  "address": "random-user@example-mail.test",
  "token": "jwt",
  "created": true,
  "random": true,
  "expiresAt": null
}
```

### 4.4 获取 Token
`POST /token`

1) 密码模式：

```json
{ "address": "bot@example-mail.test", "password": "your_password_here" }
```

2) 免密码模式（若该地址已允许）：

```json
{ "address": "bot@example-mail.test" }
```

### 4.5 当前用户
`GET /me`

### 4.6 消息列表/详情
- `GET /messages?page=1`
- `GET /messages/:id`

说明：
- 现已处理 MIME 编码与常见 base64 正文
- 详情正文优先纯文本分段，避免显示 HTML 标签和 boundary 垃圾

### 4.7 验证码提取
- `GET /messages/:id/code?regex=...`
- `GET /codes/latest?regex=...`

说明：
- 已过滤日期片段、短噪声数字等误提取
- 自定义正则命中结果也会经过候选过滤

### 4.8 消息状态与删除
- `PATCH /messages/:id` body: `{ "seen": true }`
- `DELETE /messages/:id`

### 4.9 删除当前账号
`DELETE /accounts/:id`

---

## 5. 错误码约定

- `400` 参数错误 / 校验失败
- `401` 未鉴权或鉴权无效
- `403` 权限不足
- `404` 资源不存在
- `409` 资源冲突
- `422` 业务校验失败
- `500` 服务端异常

---

## 6. 快速接入示例（curl）

### 6.1 创建 API Key（管理员）

```bash
curl -sS -X POST https://your-api.example.com/admin/api-keys \
  -H 'x-admin-key: YOUR_ADMIN_KEY' \
  -H 'content-type: application/json' \
  --data '{"name":"sdk-prod","permissions":["domains:read","accounts:create","messages:read"],"expiresInDays":30}'
```

### 6.2 用 API Key 随机开邮箱并拿 token

```bash
curl -sS -X POST https://your-api.example.com/mailboxes/open \
  -H 'Authorization: Bearer dk_xxx' \
  -H 'content-type: application/json' \
  --data '{"domain":"example-mail.test"}'
```

### 6.3 拉消息

```bash
curl -sS https://your-api.example.com/messages?page=1 \
  -H 'Authorization: Bearer USER_JWT'
```

### 6.4 拉最新验证码

```bash
curl -sS https://your-api.example.com/codes/latest \
  -H 'Authorization: Bearer USER_JWT'
```

---

## 7. 本次联调自测结果（2026-04-03）

E2E 基础信息：
- Base URL：`<YOUR_BASE_URL>`
- 测试域名：`<YOUR_TEST_DOMAIN>`
- 总用例：23
- 结果：全部通过

覆盖项：
- 管理登录、创建 API Key
- API Key 读域名、开邮箱
- 账号创建、token 获取、`/me`
- SMTP 投递 -> 消息列表/详情
- 最新验证码提取
- 标记已读、删信、删号

---

## 8. 发布到 Git 前建议

1. 把本文档纳入仓库：`INTEGRATION_API_CN.md`。  
2. 在 README 增加“生产环境变量说明（ADMIN_KEY/JWT_SECRET/SMTP_MX_HOST）”。  
3. 提交前再跑一次 23 项 E2E（可复用自动化脚本）。
