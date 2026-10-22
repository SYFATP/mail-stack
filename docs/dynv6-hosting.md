# dynv6 DNS 托管

当前项目支持多个 dynv6 账号的邮箱密码加密保存、自动登录和已有 HTTP Token 发现、登录会话续期、单个及批量自带域名登记、域名绑定、实际 DNS 查看、冲突预览、应用、验证和验证后的启用。账号凭据可以管理多个 zone；登记后会用 HTTP Token 回读确认，再绑定域名。任务复用现有持久队列，登记任务按串行处理；DNS 写入沿用现有 journal、逐次回读、冲突检查和两个 worker 的并发边界。

## 自带域名的接入顺序

1. 在 **来源与 DNS → dynv6 账号 → 添加账号** 填写邮箱和密码，名称可留空。服务端获取新鲜登录 CSRF，提交一次登录表单，读取 `/keys` 中已有的 HTTP Token，再通过 REST API 验证。新账号需要至少一个范围为 `all` 的有效 HTTP Token；程序复用已有 key，不自动创建、删除或重置 key。
2. 多个账号分别保存密码、Token、会话和状态；Cookie 与 Token 的账号身份必须匹配。已有 Token 凭据可点击 **补充登录**，原凭据 ID 及绑定域名会保留。已保存密码的同邮箱账号编辑时，密码留空可保留原密码。**同步账号** 会重新登录并读取已有 Token；没有密码的旧凭据使用现有会话读取。若使用手动方式，仍可通过 **添加 DNS 凭据** 保存 HTTP Token，再通过 **dynv6 账号 → 手动会话** 保存 `_dynv6_session` 的值、Cookie header 或 Cookie 导出 JSON；只保存 session Cookie。手动会话与 Token 需要一个双方可见的 zone；自动登录账号通过同会话读取出的 Token 验证身份，也支持零 zone 的首次登记。
3. 对停用域名点击 **接入 dynv6**，或勾选域名点击 **登记并绑定 dynv6**，选择凭据并提交。每次最多 200 个。已有精确匹配的 zone 会直接复用，缺少时通过 `GET /domains/new` 获取新鲜 CSRF，再提交一次 `POST /domains`。任务成功后自动绑定凭据，随机子域最大深度设为 **1**，域名继续保持停用。也可在 dynv6 **My Domains → Add domain** 手动登记为 **Single zone**，然后使用项目的 **绑定凭据**。
4. 执行 **配置并启用**，将本地 MX、SPF、DKIM、DMARC、wildcard MX 和启用的 Brevo 认证记录配置到 dynv6。DNS 已存在时跳过写入，直接进入持久的 `dns_complete` 任务。
5. 后台核对精确匹配的 zone、完整记录集、三台 dynv6 权威和父区当前委派。已有 dynv6 委派时跳过切换；原 NS 为 DigitalPlat Hosted DNS、域名停用且保留原 claim 的 DigitalPlat credential 时，自动通过 `dns/switch-external` 切换。其他外部托管平台或父区与 API 冲突时停止并提示，不覆盖。
6. API 回读和父区全部权威确认新 NS 后，等待项目正常解析器验证。间隔从 15 秒逐步增至 5 分钟，最多等待 2 小时；等待时释放 worker。委派确认后仅重试验证，不重复读取 DNS 库存或切换 NS。检查通过后启用，实际路由生效后进入已就绪列表。

DigitalPlat 的外部 NS 预检未通过时，会返回 `409 external_nameserver_precheck_failed`；该响应本身没有给出具体失败的服务器和查询条件。因此需要先准备 dynv6 zone 和记录，通过新 NS 的直接权威查询判断是否就绪，再切换委派。dynv6 的 Delegation check 在父区切换前显示失败是预期状态。

父区已切换后，公共递归解析器可能仍命中旧委派并返回 SERVFAIL。应等待旧缓存 TTL 到期后再验证启用，不要重复修改 NS 或重写已确认的 DNS。

DigitalPlat Hosted DNS 迁移使用 POST /api/v1/domains/{domain}/dns/switch-external。请求包含目标 NS 和 force 字段；符合下述确认条件时，程序提交相同 NS、force:true。该操作会替换父区委派，因此需先确认目标权威上的 zone 和记录完整。

202 响应包含 operation_id，表示请求已受理。紧随其后的回读可能仍为 provisioning 和旧 NS。应继续回读最终状态、核对父区委派，再执行 DNS 验证；旧快照不应被当作迁移失败，也不应因为返回 202 就直接启用域名。


**首次登记仍由独立的“登记并绑定 dynv6”任务执行；父区 NS 切换已纳入“配置并启用”。** 普通绑定、DNS 预览和只读 DNS 验证不会切换 NS，DigitalPlat 自身托管及 Cloudflare 的现有流程保留。停用的 dynv6 域名执行“验证并启用”，或以 `activate_on_success=true` 应用 DNS，也进入相同的持久完成流程。

每个 NS POST 都先持久化提交阶段和独立幂等键。只有明确的 `409 external_nameserver_precheck_failed` 且重新核验三台权威通过，才以 `force=true` 提交确认；普通 409 不触发确认。已受理或超时的请求只进行回读，不重放。重启恢复沿用原 journal；配置、凭据绑定或 claim 领取批次在等待期间变化时停止旧任务。父区委派与公网 DNS 验证分别记录，批量操作直到最终验证结果才统计完成并释放对应行锁。

自带域名首次登记使用网页表单入口 POST https://dynv6.com/domains，提交 domain[name]、authenticity_token 等字段，需要有效登录会话。程序先获取新鲜 CSRF，再提交一次表单，并通过 HTTP Token 回读新 zone；记录管理使用 REST API。该流程同时使用登录会话和 HTTP Token。


## 登记 API 与结果核对

- `PUT /api/v1/dns-credentials/{id}/dynv6-session`：`{"cookie":"<session value, Cookie header, or exported JSON>"}`；检查通过后加密保存，返回状态。
- `POST /api/v1/dns-credentials/{id}/dynv6-session/check`：检查已存会话并保存轮换后的 session。
- `POST /api/v1/mail-domains/{domain}/dynv6-registration`：`{"credential_ref":"...","bind":true,"max_subdomain_depth":1}`。
- `POST /api/v1/dynv6/registrations`：相同字段，加上 `domains` 数组，最多 200 个；每域名独立任务和错误。登记接口要求 `Idempotency-Key`。
- `GET /api/v1/dynv6/accounts`：列出账号公开状态。
- `POST /api/v1/dynv6/accounts`：`{"email":"user@example.test","password":"<password>","label":"<optional label>"}`；登录验证通过才保存，重复添加同账号复用凭据 ID。
- `PUT /api/v1/dynv6/accounts/{id}`：相同字段，为原凭据补充或更新登录；同邮箱密码留空保留原密码。
- `POST /api/v1/dynv6/accounts/{id}/refresh`：重新登录或通过已有会话同步 Token 和 zone 数量。
- 上述接口均要求管理员鉴权。凭据列表公开 `session.configured/status/checked_at`，以及 `login.email/configured/status/checked_at/retry_at/token_id/token_scope/zone_count`；不返回密码、Cookie 或 API Token。

登记前按账号串行准备会话；会话过期且已保存密码时按需重新登录，复用新 Token 和 Cookie。Token 返回 401/403 时也可通过已保存登录信息重新发现同账号的有效 Token。登录失败后至少暂停自动重试五分钟，并尊重上游更长的 Retry-After；修正登录信息后可直接重新保存。额外验证或表单变化时停止并显示原因。没有新增定时登录轮询或 worker，网络登录不持有全局域名修改锁。

账号保存、会话和 Token 更新使用加密 envelope，并检查 revision，防止旧响应覆盖新登录信息。密码字段不回填，提交结束后清空前端输入；保存或同步只刷新列表数据。

登记前持久化 dispatch 状态。超时或 worker 中断后，再次操作先回读精确匹配的 zone；已存在则继续绑定，仍不存在且有未确认的提交记录时停止，不自动重放 POST。会话失效发生在提交前时，已配置密码的账号自动续期；旧手动凭据可更新 Cookie 后重新提交。首次登记完成后，点击“配置并启用”即可按步骤 4–6 自动完成记录配置、NS 迁移和邮件启用。

## DNS 记录和失败处理

- 使用 REST v2 的 `name`、`data`、`priority` 字段；apex 使用空名称；MX/CNAME 目标写入绝对域名，保留末尾的 `.`。
- dynv6 实测动态记录 TTL 为 60 秒。应用预览采用该 TTL，API 不发送未受支持的 TTL 或 ownership comment 字段。
- 同名 SPF TXT 和 Brevo 验证 TXT 分别保留；DKIM 的完整 TXT 值交给 provider 编码，应用后通过 DNS 验证核对。
- 保留未归本项目管理的外部记录；有冲突时不覆盖。主地址产生的 apex A/AAAA 也包含在库存快照中。
- 超时或不确定的写入不自动重放。先通过现有“核对写入”流程确认目标记录，再重新预览；确认相同记录存在不会冒领 ownership。
- 收到 429 后尊重 `Retry-After`，暂缓同 provider 后续写入。未将“免费”解释为已确认无限容量或无限速率。
- 2026-10-22 对三台 NS 的直接测试发现：`*.域名` 只为一层随机子域返回 MX，第二层及更深返回空答案；API 对 `*.*` 记录返回 422。因此该方案的随机子域深度限定为 1。普通 DNS 预览会阻止配置为两层或以上的自动写入，需明确调整域名配置；“登记并绑定 dynv6”会按弹窗说明将所选停用域名的深度设为 1。

## 参考

- 官方 REST API：https://dynv6.github.io/api-spec/
- 自带域名登记：https://dynv6.com/domains/new
