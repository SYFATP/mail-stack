# 安全配置与升级说明



## 修复内容

| 项目 | 当前行为 |
| --- | --- |
| F1：邮件读取权限 | 列表、详情、原文、正文、附件和回复均要求 `mail.read`；项目 Key 还需匹配邮件归属。 |
| F2：项目隔离 | 普通 Key 按项目限制，域名和邮件投递保存项目归属；管理员 Key 保持全局。项目 Webhook 只匹配自己的资源，全局 Webhook 订阅所有项目。 |
| F3：Webhook 出站限制 | 仅允许公开 HTTPS；发送时检查全部 DNS 地址并固定连接地址，TLS 校验原 hostname；拒绝重定向，不使用环境 proxy；异常仅记录分类码。 |
| F4：依赖和 Range | 固定 `fastapi==0.136.1`、`starlette==1.3.1`、`cryptography==50.0.0`；EML 原文接口额外拒绝 `Range` 请求。 |
| F5：密码认证限速 | 登录、改密码及所有携带 `X-Admin-Password` 的请求共享预算：每 client 300 秒内 10 次，全站 60 秒内 120 次；超限返回 `429` 和 `Retry-After`。 |
| F6：Cloudflare 凭据 | 全局配置存入现有 Fernet `CredentialStore`；`settings` 只保存引用，旧明文自动迁移；缺少 keyring 时拒绝迁移或保存。 |
| F7：退出登录 | 前端等待服务端注销当前 Session 后清理本地状态；网络或服务错误时保留状态并提示重试；修改密码撤销全部 Session。 |

## 升级前配置 keyring

已有全局 Cloudflare 明文配置的部署，必须在启动新版 API 前配置 keyring：

```sh
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

将生成的值放入部署环境，示例中的 `GENERATED_FERNET_KEY` 为占位符：

```dotenv
MAIL_CREDENTIAL_KEYS={"k1":"GENERATED_FERNET_KEY"}
MAIL_CREDENTIAL_ACTIVE_KEY=k1
```

保留所有仍被密文引用的旧 key；遗失 key 会导致相应密文读取失败。keyring 与数据库备份分开保管。

API startup 在启动 worker 前执行旧配置迁移。迁移成功后删除 `cf_api_token`、`cf_api_email`、`cf_api_key`；有密文引用时优先使用密文。若历史库存在明文但未配置 keyring，startup 会失败，避免继续使用明文。

未保存配置时仍可使用 `CF_API_TOKEN` 或 `CF_API_EMAIL` / `CF_API_KEY` 环境配置，不会将这些环境值明文写入数据库。正常密文读取使用只读事务，不占用 SQLite writer lock；仅保存和迁移需要写事务。

删除旧行不等于抹除所有历史副本。旧数据库备份、WAL、快照和日志可能保留原明文；若这些副本曾暴露，应在 Provider 端轮换凭据并按既有备份策略处理副本。

## 项目与 Key 的兼容变化

- Schema v14 为域名和邮件投递增加 `project_id`。新邮件使用摄取时的项目归属快照；域名后续重新分配不转移历史邮件权限。
- 管理员可使用 `PATCH /api/v1/mail-domains/{domain}`，提交 `{"project_id":"prj_..."}` 绑定启用中的项目，或提交 `{"project_id":null}` 解除绑定。普通域名更新省略该字段时保留归属。
- 历史邮件及升级时的既有域名保持未分配项目，不按当前域名配置猜测历史权限。为项目启用入站 Webhook 前，应先绑定对应域名。
- 项目 Webhook 只接收匹配项目的资源；`project_id=null` 的全局 Webhook 接收所有项目及未分配资源。只有具备全局 `webhook.manage` 的管理员 Key / 管理员 Session 可创建和管理全局订阅。
- 新建 Key 默认 `key_type=normal`（普通）；显式 `key_type=admin` 创建管理员 Key。类型用既有 `api_keys.global_access` 持久化（普通为 0、管理员为 1），无需新增数据库迁移。API 列表和创建响应都返回 `key_type`。
- 兼容旧的 `global_access` 创建参数；同时指定类型和旧参数但含义不一致时返回 400。既有 Key 根据原全局标记显示类型，不更换密钥。
- 普通 Key 仍按 scopes / 项目 grants 授权。可在创建时传 `project_id` 原子绑定项目；不绑定项目的普通 Key 没有全局邮件读取权限。项目 Key 查询列表必须传 `project_id`。
- 管理员 Key 在其 scopes 内可访问全局域名、历史邮件和任意启用项目；额外添加项目 grant 不会使其失去全局权限。创建 Key、管理 Key 类型及控制台设置仍使用原有管理员登录认证。
- 普通 Key 发件必须声明项目且 sender 域属于该项目；管理员 Key 可从任意已配置的发件域发送，并可保留业务 `project_id` 用于队列和事件关联。域名启用、发件 readiness 和发件人校验仍生效。
- 控制台 API Keys 列表提供“修改 / 删除”。创建和修改弹窗支持名称、普通 / 管理员类型与 scopes 勾选；修改普通 Key 时可配置多个项目及各项目的权限。管理员 Key 始终在所选 scopes 内全局访问，切为管理员时保留已有项目授权。
- `GET /api/v1/api-keys/{id}` 返回不含密钥材料的配置与项目授权；`PATCH /api/v1/api-keys/{id}` 接收 JSON `name`、`key_type`、`scopes`、`grants`。`scopes` 为权限数组，`grants` 为 `[{"project_id":"prj_...","scopes":["mail.read"]}]`；省略字段保留原值，`grants: []` 撤销全部项目授权。所有项目在事务内验证后统一保存，错误时整次修改回滚。
- 修改保持原 Key 值、hash 和创建时间，权限变更立即生效；已有停用项目的授权可保留或撤销，停用项目仍不可访问。修改接口继续只允许管理员 Session / 密码，业务管理员 Key 和普通 Key 均无权修改自身类型或权限。

## 项目管理配置

控制台侧栏新增“项目管理”，支持创建、改名、启停项目和复制项目 ID，并显示各项目的域名、历史邮件、授权 Key 与项目 Webhook 数量。项目 ID 和创建时间保持固定；不提供删除项目操作。

普通 Key 的配置顺序：

1. 在“项目管理”创建项目，默认启用。
2. 在“域名管理 → 编辑 → 所属项目”选择项目。选择“未分配项目”可解除绑定；项目列表加载失败时，保存其他域名设置会保留原归属。
3. 在“API Keys → 修改”勾选项目授权及权限。读取邮件需同时勾选 Key 和项目的 `mail.read`；查询邮件列表传入对应的 `project_id`。

项目停用会暂停普通项目 Key 的访问和该项目 Webhook，保留域名、历史邮件和全部授权；重新启用后恢复。业务管理员 Key 仍在其 scopes 内全局访问，全局 Webhook 保持全局订阅。域名归属只决定新收邮件的项目快照，修改归属不迁移历史邮件。

项目管理接口只允许控制台管理员 Session / 密码，业务普通 / 管理员 Key 均无权操作：

- `POST /api/v1/projects?name=...` 创建项目。
- `GET /api/v1/projects` 返回项目列表及资源计数；邮件数按收件时的项目归属统计，全局 Key / Webhook 不计入具体项目。
- `PATCH /api/v1/projects/{project_id}` 接收 JSON `name`、`enabled`。省略字段保留原值，显式 `null`、空白名称和重复名称会被拒绝；重名等错误时整次修改回滚。

本次功能沿用 Schema v14，无新增数据库迁移，也不自动调整现有生产项目、Key 授权、域名或历史邮件归属。

## Webhook 与代理

可使用逗号分隔的 exact hostname allowlist 进一步约束接收端：

```dotenv
WEBHOOK_ALLOWED_HOSTS=receiver.example.com,other.example.com
```

该列表不支持 wildcard 或 suffix 匹配；端点仍必须通过公开 IP 和 HTTPS 检查。每次投递重新解析 DNS，混合公开 / 私有地址的答案整体拒绝。接收端应直接返回 `2xx`，不要依赖 HTTP 到 HTTPS 或跨 hostname 重定向。

认证限速使用 ASGI client，并忽略应用层直接收到的 `X-Forwarded-For`。如果反向代理或容器网络使所有请求显示为同一 client，则共享每 client 的限额；需要真实 client IP 时，仅在 Uvicorn 配置中信任实际代理，不要信任任意来源。限速记录保存在共享 SQLite 中，重启 API 不会重置有效预算。

## 验证与发布

本轮验证使用临时 SQLite、真实授权记录和模拟 SMTP / Provider / Webhook I/O。`tests/test_security.py` 覆盖权限拒绝、项目快照、outbox 隔离、DNS pinning、TLS 校验、限速、凭据迁移和 Session 撤销；前端测试验证退出的等待与失败行为。
