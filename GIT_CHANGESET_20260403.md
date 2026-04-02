# Git 变更清单（可提交）

日期：2026-04-03  
项目目录：`/opt/duckmail-selfhost-stack`（服务器） / `duckmail-selfhost-stack`（本地）

## 1) 建议纳入 Git 的文件

- `.gitignore`
- `services/api/src/index.js`
- `services/api/public/admin.html`
- `services/api/public/api-docs.html`
- `services/api/public/INTEGRATION_API_CN.md`
- `INTEGRATION_API_CN.md`

## 2) 不建议纳入 Git 的文件

- `.env`（包含密钥配置）
- `data/*`（运行时数据库与缓存）
- `*.log`
- `.DS_Store`
- `E2E_TEST_REPORT_20260403.json`（测试报告可选，不建议默认入仓）

## 3) 变更内容分组（建议 3 个提交）

### Commit A: `feat(api): improve MIME parsing and verification code extraction`

文件：
- `services/api/src/index.js`

要点：
- 修复 MIME 编码邮件显示乱码（`=?UTF-8?...?=`、`base64` 分段）。
- 优先解析 `text/plain`，避免把 HTML 标签与 boundary 显示给用户。
- 修复纯数字正文误判为 base64 的问题（如 `33333333`）。
- 优化验证码提取，过滤日期/短噪声数字，减少误命中（如 `222`）。
- 细化 message body 解析：优先 `MIME.Parts`，再 fallback `Content.Body`。

### Commit B: `feat(ui): improve mailbox detail display and add API docs entry`

文件：
- `services/api/public/admin.html`
- `services/api/public/api-docs.html`
- `services/api/public/INTEGRATION_API_CN.md`

要点：
- API 密钥页面新增“打开接口文档”跳转入口。
- 新增 `api-docs.html` 对接文档页。
- `api-docs.html` 内新增“完整版文档”可点击链接（跳转 `/INTEGRATION_API_CN.md`）。
- 新增 `public/INTEGRATION_API_CN.md`，让完整文档可在网页直接打开。
- `api-docs.html` 中示例已脱敏（不再展示真实域名/账号/密码）。
- 临时邮箱页新增复制能力：复制当前邮箱地址、复制最新验证码。
- 管理页文案与输入框示例全面脱敏，不再展示真实业务域名（改为通用占位示例）。
- 消息详情栏不再显示 MailHog 内部 messageId，改为“主题 | 验证码 | 时间”。
- 静态资源缓存策略已调整为 no-store，减少前端旧缓存影响。

### Commit C: `docs: add integration guide for self-host deployment`

文件：
- `INTEGRATION_API_CN.md`
- `.gitignore`

要点：
- 增加中文对接文档（鉴权、接口、示例、错误码、联调建议）。
- 文档示例全部脱敏，不包含真实域名、密码等敏感示例值。
- “参考文档”表述改为“社区开源参考（非官方）”。
- 增加 Git 忽略规则，避免误提交流水数据和敏感配置。

## 4) 提交前自检（已验证）

- API Key 创建、域名读取、开邮箱、发信、拉信、提码、删信、删号：全部通过（23/23）。
- 乱码样例（主题+正文 base64）已恢复为中文显示。
- 纯数字正文不再出现 boundary 垃圾或乱码。

## 5) 建议提交命令（在项目根目录执行）

```bash
cd duckmail-selfhost-stack

# 如果还没初始化 git（新仓库）
git init
git branch -M main

# Commit A
git add services/api/src/index.js
git commit -m "feat(api): improve MIME parsing and verification code extraction"

# Commit B
git add services/api/public/admin.html services/api/public/api-docs.html services/api/public/INTEGRATION_API_CN.md
git commit -m "feat(ui): improve mailbox detail display and add API docs entry"

# Commit C
git add INTEGRATION_API_CN.md .gitignore
git commit -m "docs: add integration guide and git ignore rules"
```

## 6) 推送前提醒

- 确认 `.env` 未被 `git add`。
- 若要公开仓库，请再次检查文档和截图中是否包含密钥。
- 当前测试用 API Key 如需下线，请在管理页删除。
