# Security

请通过 GitHub private vulnerability reporting 提交安全问题，避免在公开 issue 中填写凭据或邮件内容。

部署配置保存在 `.env`，Provider 凭据加密保存在运行数据库中。不要提交数据库、邮件、日志、
DKIM private key、SSH key、备份、访问 token 或生产部署记录。详细配置见 `docs/security-hardening.md`。

本仓库使用文档域名和示例 IP；实际部署信息应保存在独立的私有运维目录。
