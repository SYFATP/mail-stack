# Readiness 自动刷新

`DOMAIN_JOBS_ENABLED=1` 时，现有单进程 `DomainWorker` 负责自动刷新已启用域名的 readiness。无需新增进程、cron、DNS provider 凭据或数据库迁移。

默认每 30 秒检查一次，证据达到 `DNS_CHECK_MAX_AGE_SECONDS / 2` 即排队重新验证；默认 TTL 为 3600 秒，因此约每 1800 秒重新验证。首次启动发现缺失、过期、未来时间戳、revision 不符或失败证据时也会排队。

可选环境变量（默认配置即启用，不需要生产新增参数）：

| 参数 | 默认 | 含义 |
| --- | --- | --- |
| `DNS_READINESS_REFRESH_ENABLED` | `1` | 自动刷新开关 |
| `DNS_READINESS_SCAN_SECONDS` | `30` | 扫描间隔，最大为 TTL 的四分之一 |
| `DNS_READINESS_RETRY_SECONDS` | `60` | 失败/缺失检查的重试最短间隔，最大为 TTL 的四分之一 |
| `DNS_READINESS_BATCH_SIZE` | `16` | 每次扫描最多排队任务数，最多 100 |

自动任务使用既有 `dns_validate` 类型，带 `auto-readiness:` idempotency key 和 `refresh_smtp_submission=true`。仅读取 DNS 并验证本地 SMTP submission；不会写 Cloudflare/DigitalPlat DNS、认领/释放域名或自动重放未知 provider 写操作。

同域名已有 queued/running DNS 检查时不重复排队。任务时间和状态保存在现有 ledger 中，重启后仍保留节流；中断的只读任务可通过新的检查恢复，不复用有外部写入副作用的旧任务。批量调度优先检查最旧/缺失证据，避免持续失败域名占满所有名额。

SMTP 使用与实际发件相同的 `SMTP_SUBMISSION_HOST/PORT`，执行 `EHLO → MAIL → RCPT → RSET → QUIT`。RCPT 使用保留域 `example.invalid`；**永不执行 DATA**，没有实际邮件、发件请求或外投。此检查确认本地 MTA 接收/relay 权限，不代表 Brevo 下游投递或最终收件。

DNS 或 SMTP 失败会写入新的 `failed` 证据，不伪造 `passed`、不续期旧成功结果；下一次有界重试重新进行检查。域名或 DKIM plan 在检查期间变化时拒绝记录旧结果。原 `receive_ready/send_ready` TTL 和 revision 判断保持不变；公共 API 不同步发起网络探测。

手工 `/dns-validate` 仍保持原来的纯 DNS 检查契约。开启多级子域后，
`wildcard_mx` 只有在 wildcard owner 本身和每个配置深度的随机探针都解析到
精确 MX 目标时才记为 `passed`；任一探针失败都会 fail-closed。该检查仍不推断
SMTP 发件能力，也不写入 DNS provider。

自动队列与手工控制任务共享既有单 worker；如果大量慢任务导致排队超过 TTL，可用列表仍按原规则 fail closed，需要调查队列和 DNS/SMTP 故障，而不是放宽 freshness 判断。自动任务同样需要按既有运维策略归档 ledger。
