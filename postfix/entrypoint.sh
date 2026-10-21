#!/bin/sh
set -eu

env_domain="${MAIL_DOMAIN:-example.com}"
env_domains="${MAIL_DOMAINS:-$env_domain}"
env_users="${MAILBOX_USERS:-test,postmaster,admin}"
postfix_mynetworks="${POSTFIX_MYNETWORKS:-127.0.0.0/8, 172.30.0.10/32}"
outbound_smtp_host="${MAIL_OUTBOUND_SMTP_HOST:-}"
outbound_smtp_port="${MAIL_OUTBOUND_SMTP_PORT:-587}"
outbound_smtp_username="${MAIL_OUTBOUND_SMTP_USERNAME:-}"
outbound_smtp_password="${MAIL_OUTBOUND_SMTP_PASSWORD:-}"
outbound_smtp_starttls="${MAIL_OUTBOUND_SMTP_STARTTLS:-1}"
active_generation="legacy"

runtime_snapshot() {
  if [ ! -f /app-data/routing.current ]; then
    if [ "${ALLOW_LEGACY_ROUTING:-0}" = 1 ]; then printf legacy; return; fi
    echo 'routing snapshot missing; refusing environment fallback' >&2
    return 1
  fi
  generation="$(tr -d '\r\n' < /app-data/routing.current)"
  [ "${#generation}" -eq 64 ] || return 1
  case "$generation" in *[!a-f0-9]*) return 1;; esac
  [ -f "/app-data/generations/$generation/manifest.json" ] || return 1
  printf '%s' "$generation"
}

write_ack() {
  generation="$1"; status="$2"
  temporary="/app-data/.postfix-applied.$$.tmp"
  printf '{"generation":"%s","status":"%s","applied_at":%s}\n' "$generation" "$status" "$(date +%s)" > "$temporary"
  mv "$temporary" /app-data/postfix-applied.json
}

render_config() {
  generation="$1"
  mkdir -p /var/mail/vhosts /var/spool/postfix/etc /var/log/mail
  chown postfix:postfix /var/mail/vhosts
  cp -L /etc/resolv.conf /var/spool/postfix/etc/resolv.conf
  cp -L /etc/hosts /var/spool/postfix/etc/hosts
  cp -L /etc/nsswitch.conf /var/spool/postfix/etc/nsswitch.conf
  postconf -e "myhostname = ${MAIL_HOST:-mail.$env_domain}"
  postconf -e "mydestination = localhost"
  postconf -e "mynetworks = $postfix_mynetworks"
  if [ "$generation" = legacy ]; then
    : > /etc/postfix/vdomains
    : > /etc/postfix/vmailbox
    for domain in $(printf '%s' "$env_domains" | tr ',' ' '); do
      printf '%s OK\n' "$domain" >> /etc/postfix/vdomains
      for user in $(printf '%s' "$env_users" | tr ',;' '  '); do
        printf '%s@%s %s/%s/Maildir/\n' "$user" "$domain" "$domain" "$user" >> /etc/postfix/vmailbox
      done
    done
    postmap /etc/postfix/vdomains
    postmap /etc/postfix/vmailbox
    postconf -e "virtual_mailbox_domains = hash:/etc/postfix/vdomains"
    postconf -e "virtual_mailbox_maps = hash:/etc/postfix/vmailbox"
  else
    source="/app-data/generations/$generation"
    destination="/etc/postfix/mail-stack/$generation"
    mkdir -p "$destination"
    cp "$source/vdomains.pcre" "$destination/vdomains.pcre"
    cp "$source/recipients.sqlite" "$destination/recipients.sqlite"
    cp "$source/vmailbox.cf" "$destination/vmailbox.cf"
    chmod 0444 "$destination/recipients.sqlite" "$destination/vmailbox.cf"
    diagnostics="$destination/vdomains.check"
    postmap -q '__mail_stack_probe__' "pcre:$destination/vdomains.pcre" 2> "$diagnostics" || true
    [ ! -s "$diagnostics" ] || { cat "$diagnostics" >&2; return 1; }
    # Native local SQLite lookup computes paths; no regexp substitution,
    # unauthenticated socketmap or dependency on the API's mutable database.
    diagnostics="$destination/sqlite.check"
    postmap -q '__mail_stack_probe__' "sqlite:$destination/vmailbox.cf" 2> "$diagnostics" || true
    [ ! -s "$diagnostics" ] || { cat "$diagnostics" >&2; return 1; }
    postconf -e "virtual_mailbox_domains = pcre:$destination/vdomains.pcre"
    postconf -e "virtual_mailbox_maps = sqlite:$destination/vmailbox.cf"
  fi
  postconf -e "virtual_mailbox_base = /var/mail/vhosts"
  postconf -e "virtual_minimum_uid = $(id -u postfix)"
  postconf -e "virtual_uid_maps = static:$(id -u postfix)"
  postconf -e "virtual_gid_maps = static:$(id -g postfix)"
  postconf -e "virtual_transport = virtual"
  # Do not collapse plus-tag addresses into a different Maildir identity.
  postconf -e "recipient_delimiter ="
  postconf -e "smtputf8_enable = no"
  postconf -e "smtpd_recipient_restrictions = permit_mynetworks, reject_non_fqdn_recipient, reject_unknown_recipient_domain, reject_unlisted_recipient, reject_unauth_destination"
  postconf -e "smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination"
  postconf -e "smtpd_milters ="
  postconf -e "non_smtpd_milters ="
  postconf -e "inet_interfaces = all"
  # Optional authenticated outbound relay. Local virtual delivery is selected
  # before relayhost, so enabling this does not change inbound MX handling.
  if [ -n "$outbound_smtp_host" ]; then
    case "$outbound_smtp_host" in *[!a-zA-Z0-9.-]*|.*|-*|*.) return 1;; esac
    case "$outbound_smtp_port" in ''|*[!0-9]*) return 1;; esac
    [ "$outbound_smtp_port" -ge 1 ] && [ "$outbound_smtp_port" -le 65535 ] || return 1
    [ -n "$outbound_smtp_username" ] && [ -n "$outbound_smtp_password" ] || return 1
    # AUTH requires verified STARTTLS; do not downgrade credentials to plaintext.
    [ "$outbound_smtp_starttls" = 1 ] && [ "$outbound_smtp_port" -ne 465 ] || return 1
    [ -n "$(find /usr/lib -name libplain.so -print -quit)" ] || {
      echo 'outbound relay requires libsasl2-modules' >&2; return 1;
    }
    case "$outbound_smtp_username" in *[[:space:]:]*) return 1;; esac
    case "$outbound_smtp_password" in *[[:space:]]*) return 1;; esac
    relay_file="/etc/postfix/sasl_passwd"
    # Restrict permissions at creation, not just after the plaintext is written.
    (umask 077; printf '[%s]:%s %s:%s\n' "$outbound_smtp_host" "$outbound_smtp_port" \
      "$outbound_smtp_username" "$outbound_smtp_password" > "$relay_file")
    chmod 0600 "$relay_file"
    postmap "$relay_file"
    chmod 0600 "${relay_file}.db"
    postconf -e "relayhost = [${outbound_smtp_host}]:${outbound_smtp_port}"
    postconf -e "smtp_sasl_auth_enable = yes"
    postconf -e "smtp_sasl_password_maps = hash:${relay_file}"
    postconf -e "smtp_sasl_security_options = noanonymous"
    postconf -e "smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt"
    postconf -e "smtp_tls_security_level = verify"
    postconf -e "smtp_tls_wrappermode = no"
  else
    rm -f /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
    postconf -e "relayhost ="
    postconf -e "smtp_sasl_auth_enable = no"
    postconf -e "smtp_sasl_password_maps ="
    postconf -e "smtp_tls_security_level = may"
    postconf -e "smtp_tls_wrappermode = no"
  fi
  message_mb="${MAX_MESSAGE_MB:-20}"
  case "$message_mb" in ''|*[!0-9]*) return 1;; esac
  [ "$message_mb" -ge 1 ] && [ "$message_mb" -le 100 ] || return 1
  postconf -e "message_size_limit = $((message_mb * 1048576))"
  postconf -e "mailbox_size_limit = 0"
  newaliases
  postfix check
}

# Explicit file logging; installing rsyslog alone never starts its daemon.
sed -i '/^module(load="imklog")/d' /etc/rsyslog.conf
mkdir -p /etc/rsyslog.d /var/log/mail
printf 'mail.* -/var/log/mail/mail.log\n' > /etc/rsyslog.d/20-mail-stack.conf
rsyslogd
# A persisted spool can retain PID 1 from the old container. The new entrypoint
# is also PID 1, which makes start-fg incorrectly report "already running".
# Only remove the stale PID metadata, never queue messages or an active master.
for process in /proc/[0-9]*/comm; do
  [ "$(cat "$process" 2>/dev/null || true)" != master ] || {
    echo 'another Postfix master already runs in this container' >&2
    exit 1
  }
done
rm -f /var/spool/postfix/pid/master.pid
active_generation="$(runtime_snapshot)"
write_ack "$active_generation" starting
render_config "$active_generation"
(
  until postfix status >/dev/null 2>&1; do sleep 1; done
  write_ack "$active_generation" applied
  while sleep 2; do
    current="$(runtime_snapshot)" || { echo 'invalid routing snapshot; keeping last valid generation' >&2; continue; }
    if [ "$current" != "$active_generation" ]; then
      if render_config "$current" && postfix reload; then
        active_generation="$current"
        write_ack "$current" applied
      else
        render_config "$active_generation" && postfix reload || true
        write_ack "$current" failed
        echo "routing generation failed: $current" >&2
      fi
    fi
    if [ "$current" = "$active_generation" ]; then
      master_pid="$(tr -d ' \r\n' < /var/spool/postfix/pid/master.pid 2>/dev/null || true)"
      if [ -n "$master_pid" ] && kill -0 "$master_pid" 2>/dev/null; then
        write_ack "$active_generation" applied
      else
        write_ack "$active_generation" failed
      fi
    fi
  done
) &
exec postfix start-fg
