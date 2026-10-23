#!/bin/sh
set -eu

env_domain="${MAIL_DOMAIN:-example.com}"
env_domains="${MAIL_DOMAINS:-$env_domain}"
rendered=0
cache_header='# mail-stack validated DKIM keys v1'

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
  private_hash="$(sha256sum "$private")"
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
  # Only cache bytes that actually passed validation and produced this TXT.
  [ "$private_hash" = "$(sha256sum "$private")" ] || return 1
  chown opendkim:opendkim "$directory" "$private" "$directory/$selector.txt"
  printf '%s\n' "$private_hash" >> "$work/changed.sha256"
  sha256sum "$directory/$selector.txt" >> "$work/changed.sha256"
}

key_hashes() {
  # Hash all required files in one process instead of forking per domain.
  xargs -r sha256sum -- < "$work/paths"
}

render_config() {
  generation="$1"
  work="$(mktemp -d /tmp/mail-stack-dkim-XXXXXX)"
  if [ "$generation" = legacy ]; then
    printf '%s' "$env_domains" | tr ', ' '\n\n' | awk 'NF {print $0, "default"}' > "$work/pairs"
  else
    domains="/app-data/generations/$generation/domains.list"
    selectors="/app-data/generations/$generation/selectors.list"
    # Key preparation is independent of SMTP acceptance. Claimed/disabled
    # domains need public keys before DNS can be provisioned.
    if [ -f "/app-data/generations/$generation/key-domains.list" ]; then
      domains="/app-data/generations/$generation/key-domains.list"
      selectors="/app-data/generations/$generation/key-selectors.list"
    fi
    awk 'FILENAME == ARGV[1] {selector[$1]=$2; next}
      NF {if (!selector[$1]) exit 1; print $1, selector[$1]}' "$selectors" "$domains" > "$work/pairs"
  fi
  # These identities also become paths and xargs input; admit no shell syntax.
  awk 'NF != 2 || length($1) > 253 || length($2) > 63 ||
    $1 !~ /^[a-z0-9][a-z0-9.-]*$/ || $2 !~ /^[a-z0-9][a-z0-9._-]*$/ {exit 1}' "$work/pairs"
  : > "$work/KeyTable"
  : > "$work/SigningTable"
  awk -v keys="$work/KeyTable" -v signing="$work/SigningTable" '
    {base="/etc/opendkim/keys/" $1 "/" $2;
     print base ".private"; print base ".txt";
     printf "%s._domainkey.%s %s:%s:%s.private\n", $2,$1,$1,$2,base > keys;
     printf "*@%s %s._domainkey.%s\n", $1,$2,$1 > signing}' "$work/pairs" > "$work/paths"

  cache=/etc/opendkim/.validated-keys.sha256
  : > "$work/known.sha256"
  if [ -f "$cache" ] && IFS= read -r header < "$cache" && [ "$header" = "$cache_header" ]; then
    cat "$cache" > "$work/known.sha256"
  fi
  # Missing files are work to prepare; a successful final hash pass is mandatory.
  key_hashes > "$work/before.sha256" 2>/dev/null || true
  awk 'FILENAME == ARGV[1] {if (NF == 2) known[$2]=$1; next}
       FILENAME == ARGV[2] {current[$2]=$1; next}
       {base="/etc/opendkim/keys/" $1 "/" $2; p=base ".private"; t=base ".txt";
        if (!current[p] || !current[t] || known[p] != current[p] || known[t] != current[t]) print $0}' \
    "$work/known.sha256" "$work/before.sha256" "$work/pairs" > "$work/todo"
  needs_reload=0
  : > "$work/changed.sha256"
  if [ -s "$work/todo" ]; then needs_reload=1; fi
  while read -r domain selector; do
    prepare_key "$domain" "$selector"
  done < "$work/todo"
  awk 'FILENAME == ARGV[1] || FILENAME == ARGV[2] {hash[$2]=$1; next}
       {if (!hash[$0]) exit 1; print hash[$0] "  " $0}' \
    "$work/before.sha256" "$work/changed.sha256" "$work/paths" > "$work/expected.sha256"
  key_hashes > "$work/after.sha256"
  # Detect changes during rendering, including unchanged keys edited concurrently.
  cmp -s "$work/expected.sha256" "$work/after.sha256"

  printf '127.0.0.1\n172.16.0.0/12\n' > "$work/TrustedHosts"
  cat > "$work/opendkim.conf" <<EOF
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
  mkdir -p /etc/opendkim
  for name in KeyTable SigningTable TrustedHosts opendkim.conf; do
    destination="/etc/opendkim/$name"
    if [ "$name" = opendkim.conf ]; then destination=/etc/opendkim.conf; fi
    if ! cmp -s "$work/$name" "$destination"; then
      mv "$work/$name" "$destination"
      chown opendkim:opendkim "$destination"
      needs_reload=1
    fi
  done
  if [ "$rendered" -eq 0 ] || [ "$needs_reload" -eq 1 ]; then
    opendkim -x /etc/opendkim.conf -n
  fi
  # Persist only validated private/TXT pairs; contents are checked on every render
  # and on restart. Unchanged keys need no RSA check, public export, or chown.
  { printf '%s\n' "$cache_header"; cat "$work/after.sha256"; } > "$work/cache"
  chmod 600 "$work/cache"
  if ! cmp -s "$work/cache" "$cache"; then mv "$work/cache" "$cache"; fi
  temporary="/app-data/.dkim-applied.$$.tmp"
  printf '{"generation":"%s","status":"keys_ready","applied_at":%s}\n' "$generation" "$(date +%s)" > "$temporary"
  mv "$temporary" /app-data/dkim-applied.json
  rm -rf "$work"
  rendered=1
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
      if [ "$needs_reload" -eq 1 ]; then
        # OpenDKIM reloads on SIGUSR1, not SIGHUP.
        kill -USR1 "$opendkim_pid" || exit 1
      fi
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
