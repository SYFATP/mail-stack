#!/bin/sh
set -eu

env_domain="${MAIL_DOMAIN:-example.com}"
env_domains="${MAIL_DOMAINS:-$env_domain}"

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

prepare_key() {
  domain="$1"
  selector="$2"
  directory="/etc/opendkim/keys/$domain"
  mkdir -p "$directory"
  private="$directory/$selector.private"
  if [ ! -f "$private" ]; then
    staging="$(mktemp -d "$directory/.keygen-XXXXXX")"
    opendkim-genkey -b 2048 -d "$domain" -D "$staging" -s "$selector"
    openssl pkey -in "$staging/$selector.private" -check -noout >/dev/null
    # One writer; a pre-existing private key is never overwritten.
    mv -n "$staging/$selector.private" "$private"
    rm -f "$staging/$selector.txt"
    rmdir "$staging"
  fi
  openssl pkey -in "$private" -check -noout >/dev/null
  public="$(openssl pkey -in "$private" -pubout -outform DER | openssl base64 -A)"
  [ -n "$public" ] || return 1
  temporary="$directory/.$selector.txt.$$.tmp"
  {
    printf '%s._domainkey IN TXT (\n' "$selector"
    printf 'v=DKIM1; h=sha256; k=rsa; p=%s' "$public" | fold -w 200 | while IFS= read -r chunk || [ -n "$chunk" ]; do
      printf '  "%s"\n' "$chunk"
    done
    printf ')\n'
  } > "$temporary"
  # Reconstruct a missing/inconsistent public TXT from the same private key.
  if [ -f "$directory/$selector.txt" ] && cmp -s "$temporary" "$directory/$selector.txt"; then
    rm -f "$temporary"
  else
    mv "$temporary" "$directory/$selector.txt"
  fi
}

render_config() {
  generation="$1"
  if [ "$generation" = legacy ]; then
    domains="$(printf '%s' "$env_domains" | tr ',' ' ')"
    selectors=''
  else
    domains="$(tr '\n' ' ' < "/app-data/generations/$generation/domains.list")"
    selectors="/app-data/generations/$generation/selectors.list"
    # Key preparation is independent of SMTP acceptance. Claimed/disabled
    # domains need public keys before DNS can be provisioned.
    if [ -f "/app-data/generations/$generation/key-domains.list" ]; then
      domains="$(tr '\n' ' ' < "/app-data/generations/$generation/key-domains.list")"
      selectors="/app-data/generations/$generation/key-selectors.list"
    fi
  fi
  : > /etc/opendkim/KeyTable.tmp
  : > /etc/opendkim/SigningTable.tmp
  for domain in $domains; do
    selector=default
    if [ -n "$selectors" ]; then
      selector="$(awk -v d="$domain" '$1 == d {print $2; exit}' "$selectors")"
    fi
    prepare_key "$domain" "$selector"
    printf '%s._domainkey.%s %s:%s:/etc/opendkim/keys/%s/%s.private\n' "$selector" "$domain" "$domain" "$selector" "$domain" "$selector" >> /etc/opendkim/KeyTable.tmp
    printf '*@%s %s._domainkey.%s\n' "$domain" "$selector" "$domain" >> /etc/opendkim/SigningTable.tmp
  done
  mv /etc/opendkim/KeyTable.tmp /etc/opendkim/KeyTable
  mv /etc/opendkim/SigningTable.tmp /etc/opendkim/SigningTable
  printf '127.0.0.1\n172.16.0.0/12\n' > /etc/opendkim/TrustedHosts
  cat > /etc/opendkim.conf <<EOF
Syslog no
SyslogSuccess no
LogWhy yes
UMask 002
Mode sv
UserID opendkim:opendkim
Socket inet:8891@0.0.0.0
Canonicalization relaxed/simple
KeyTable refile:/etc/opendkim/KeyTable
SigningTable refile:/etc/opendkim/SigningTable
ExternalIgnoreList refile:/etc/opendkim/TrustedHosts
InternalHosts refile:/etc/opendkim/TrustedHosts
EOF
  chown -R opendkim:opendkim /etc/opendkim
  opendkim -x /etc/opendkim.conf -n
  temporary="/app-data/.dkim-applied.$$.tmp"
  printf '{"generation":"%s","status":"keys_ready","applied_at":%s}\n' "$generation" "$(date +%s)" > "$temporary"
  mv "$temporary" /app-data/dkim-applied.json
}

last="$(runtime_snapshot)"
render_config "$last"
opendkim -x /etc/opendkim.conf -f &
opendkim_pid=$!
(
  while sleep 2; do
    current="$(runtime_snapshot)" || continue
    if [ "$current" != "$last" ]; then
      render_config "$current"
      # OpenDKIM reloads on SIGUSR1, not SIGHUP.
      kill -USR1 "$opendkim_pid" || exit 1
      last="$current"
    fi
  done
) &
watcher_pid=$!
terminate() {
  kill -TERM "$opendkim_pid" "$watcher_pid" 2>/dev/null || true
  wait "$opendkim_pid" 2>/dev/null || true
  exit 0
}
trap terminate TERM INT
wait "$opendkim_pid"
result=$?
kill -TERM "$watcher_pid" 2>/dev/null || true
exit "$result"
