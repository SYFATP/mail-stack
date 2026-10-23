# Cloudflare 托管接入

Cloudflare 接入会先读取现有 Zone；目标自身的 `pending` / `initializing` Zone 也可配置记录。找不到可用 Zone 时，后台尝试创建 `full` Zone，再读取 Cloudflare 分配的 Nameserver。项目不按后缀或域名层数拒绝创建，接入资格与套餐限制以 Cloudflare API 返回结果为准。

## 账号凭据

在“添加 DNS 凭据”中选择 Cloudflare，保存 API Token，按需填写 Account ID。旧有 Email + Global API Key 凭据继续可用。

Token 需要具备目标账号的 Zone 创建、读取及 DNS 记录读写权限，资源范围需覆盖新建 Zone。API 的创建权限定义参见官方文档。未填写 Account ID 时，项目读取账号列表，只有结果唯一才自动选择；多个账号或账号列表读取权限不足时，应补充目标 Account ID。

## 操作入口

- 新领取域名：选择 Cloudflare 及账号，启用“领取后自动配置、验证并启用”。后台串联领取、Zone 准备、DNS 预览与应用、委派核验、验证及启用。
- 已存在的停用域名：打开“DNS 绑定与变更”，选择 Cloudflare 凭据并点击“接入 Cloudflare”；Zone 确认后才更新本地绑定。再执行“配置并启用”。
- 已绑定 Cloudflare 的域名：直接执行“配置并启用”，缺少 Zone 时按需准备。

有匹配的原 DigitalPlat claim 凭据，且当前父区委派仍是 DigitalPlat 默认托管时，系统使用 DigitalPlat API 切换至 Cloudflare 实际分配的 NS。上游返回明确的 precheck 409 时，继续其二次确认协议。

普通注册商域名或没有 DigitalPlat registrar 凭据的域名，列表显示 Cloudflare 分配的 NS，并提示“等待手动修改 NS”。在注册商或父区修改 NS 委派后，系统定期回查，完成 DNS 与 SMTP 配置检查后启用，路由生效后进入“已就绪”。在域名内部新建普通 NS 记录不能替代注册商或父区的委派修改。

已有其他外部委派的域名会显示冲突，保留当前委派并等待处理。被停用或修改配置的任务会在写入前重新核对身份及配置。

## 等待与异常

- Zone 创建被拒绝时保留 Cloudflare 错误码，原 DNS 绑定保持原值。
- Zone 创建或委派 POST 超时时先只读回查；结果仍未确认时不重复提交。
- 创建成功与 DNS 写入成功都不直接等同于已就绪，委派等待中的域名继续显示“处理中”。
- 自动委派/解析回查最长等待两小时；超时后保留结果，可在完成手动 NS 修改后重新执行“验证并启用”。
- 配置验证不代表已做过真实收发件测试。

## 官方接口参考

- [Create Zone](https://developers.cloudflare.com/api/resources/zones/methods/create/)
- [Subdomain setup](https://developers.cloudflare.com/dns/zone-setups/subdomain-setup/)

一般的独立子区接入属于 Cloudflare 的 subdomain setup，其套餐要求与可注册域名接入不同；项目将判定交给上游，避免把多段公共后缀误判成普通子域。
