# Mail Stack

自托管邮件收发与域名管理服务，提供中文 Web 控制台、REST API 和签名 Webhook。

## 功能

- Postfix 接收邮件，支持固定用户、catch-all 与多级子域收件。
- OpenDKIM 签名、SPF / DKIM / DMARC / MX 记录预览、同步与 readiness 检查。
- 邮件检索、正文、附件、原始 EML，以及转发邮件的原始发件人与收件人解析。
- 异步发件队列，支持 SMTP relay 和可选 Brevo API fallback。
- 项目管理、普通 / 管理员 API Key、项目授权及签名 Webhook。
- Cloudflare / DigitalPlat DNS adapter，可配置域名来源。
- SQLite 存储、加密 Provider 凭据与 Docker Compose 部署。

## 快速开始

需要 Docker Engine、Docker Compose、Node.js 22+（仅前端测试）以及 Python 3.12（仅本地开发）。
邮件服务器需要自己的域名、DNS 配置和可用的 SMTP 端口。

```sh
cp .env.example .env
```

编辑 `.env`，至少配置：

```dotenv
MAIL_DOMAIN=example.com
MAIL_DOMAINS=example.com
MAIL_HOST=mail.example.com
MAILBOX_USERS=test,postmaster,admin
PUBLIC_SERVER_IP=203.0.113.10
ADMIN_PASSWORD_HASH=GENERATED_ARGON2ID_HASH
API_KEY_PEPPER=GENERATED_RANDOM_SECRET
```

`example.com` 和 `203.0.113.10` 是文档占位值，部署时填写自己的配置。
生成配置值时，可使用 Python 虚拟环境：

```sh
python -m venv .venv
# Linux / macOS
. .venv/bin/activate
# Windows PowerShell: .venv/Scripts/Activate.ps1
python -m pip install -r api/requirements.txt
python -c "from passlib.hash import argon2; from getpass import getpass; print(argon2.hash(getpass()))"
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

如需保存 Provider 凭据，另外生成 Fernet key，并设置 keyring：

```sh
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

```dotenv
MAIL_CREDENTIAL_KEYS={"k1":"GENERATED_FERNET_KEY"}
MAIL_CREDENTIAL_ACTIVE_KEY=k1
```

```sh
docker compose up -d --build
```

- 控制台：`http://127.0.0.1:18082`
- API：`http://127.0.0.1:18081/api/v1/health`
- SMTP：主机 TCP 25

生产环境通过反向代理发布 HTTPS，配置参考 `nginx/mail.example.com.conf.example`。
API 与前端默认仅绑定 loopback。首次登录使用与 `ADMIN_PASSWORD_HASH` 对应的密码。
在 DNS 中配置邮件域名的 MX 与主机 A 记录，使用控制台检查和同步其余邮件记录。

## 配置与数据

`.env.example` 包含 SMTP relay、Brevo、Webhook、Provider 凭据和后台任务配置说明。
默认使用单个 API process；域名任务使用有界并发，避免不确定的 Provider 操作被自动重放。

运行数据保存在 `app-data/`、`maildata/`、`dkim/`、`backups/` 和 `logs/`。
Postfix 队列使用 Docker volume。凭据 keyring 应单独备份。

- [安全配置与升级](docs/security-hardening.md)
- [Readiness 自动刷新](docs/readiness-refresh.md)
- [原始收件人解析](api/ACTUAL_RECIPIENT.md)
- [原始发件人解析](api/ACTUAL_SENDER.md)

## 开发与测试

```sh
python -m pip install -r tests/requirements.txt
python -m unittest discover -s tests -p 'test_*.py'
node tests/test_mail_layout.cjs
node tests/test_ui_appearance.cjs
python scripts/check_public_files.py
```

`tests/test_*.cjs` 是使用 Node.js 内置模块的前端测试。
`tests/compose.integration.yml` 和 `tests/integration_*.py` 用于隔离的 Docker integration 环境。
测试 fixture 使用虚构域名和固定测试凭据，不需要真实 Provider 凭据。

## License

[MIT](LICENSE)
