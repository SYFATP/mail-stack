"""Exercise the real POSIX entrypoint/OpenSSL in an isolated Docker image.

Run on a Docker host: DKIM_TEST_IMAGE=<candidate> python3 tests/integration_opendkim_cache.py
Containers have no network or production mounts and are removed after each case.
"""
import json
import os
from pathlib import Path
import shlex
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "opendkim/entrypoint.sh").read_text(encoding="utf-8")
FUNCTIONS = SOURCE.split('\nlast="$(runtime_snapshot)"', 1)[0]
IMAGE = os.environ.get("DKIM_TEST_IMAGE")

HELPERS = r'''
mkdir -p /etc/opendkim/keys /app-data/generations
: > /tmp/calls
openssl() { printf 'openssl %s\n' "$*" >> /tmp/calls; command openssl "$@"; }
opendkim() { printf 'config-check\n' >> /tmp/calls; command opendkim "$@"; }
assert_same() { [ "$1" = "$2" ] || { echo "assertion failed: $3 ($1 != $2)" >&2; exit 91; }; }
checks() { awk '/openssl .* -check / {n++} END {print n+0}' /tmp/calls; }
exports() { awk '/openssl .* -pubout / {n++} END {print n+0}' /tmp/calls; }
generated() { awk '/openssl .*\.keygen-.* -check / {n++} END {print n+0}' /tmp/calls; }
config_checks() { awk '/^config-check$/ {n++} END {print n+0}' /tmp/calls; }
reset_calls() { : > /tmp/calls; }
make_generation() {
  mkdir -p "/app-data/generations/$1"
  printf '%s\n' "$2" > "/app-data/generations/$1/key-selectors.list"
  awk 'NF {print $1}' "/app-data/generations/$1/key-selectors.list" > "/app-data/generations/$1/key-domains.list"
}
initial() {
  make_generation first 'a.example.test default
b.example.test default'
  render_config first
  reset_calls
}
'''


@unittest.skipUnless(IMAGE, "set DKIM_TEST_IMAGE to a candidate image on a Docker host")
class IncrementalDKIMTests(unittest.TestCase):
    def shell(self, body, *, succeeds=True):
        result = subprocess.run([
            "docker", "run", "--rm", "-i", "--network", "none", "--memory", "64m",
            "--cpus", "0.35", "--entrypoint", "/bin/sh", IMAGE, "-s"],
            input=FUNCTIONS + '\n' + HELPERS + "\ntrap 'echo EXPECTED_FAILURE_CHECKED' EXIT\n" + body + '\n',
            text=True, capture_output=True, timeout=120)
        if succeeds:
            self.assertEqual(result.returncode, 0, result.stderr[-2500:] + result.stdout[-1500:])
        else:
            self.assertNotEqual(result.returncode, 0, "expected fail-closed rendering")
            self.assertIn("EXPECTED_FAILURE_CHECKED", result.stdout, result.stderr[-2500:])
        return result

    def test_first_render_validates_existing_private_and_rebuilds_txt(self):
        self.shell(r'''
mkdir -p /etc/opendkim/keys/a.example.test
command opendkim-genkey -b 2048 -d a.example.test -D /etc/opendkim/keys/a.example.test -s default
before="$(sha256sum /etc/opendkim/keys/a.example.test/default.private)"
printf 'invalid' > /etc/opendkim/keys/a.example.test/default.txt
make_generation first 'a.example.test default'
render_config first
assert_same "$(checks)" 1 'first validation'
assert_same "$(exports)" 1 'public reconstruction'
assert_same "$(generated)" 0 'never replace existing private'
assert_same "$before" "$(sha256sum /etc/opendkim/keys/a.example.test/default.private)" 'private preserved'
grep -q 'v=DKIM1' /etc/opendkim/keys/a.example.test/default.txt
''')

    def test_unrelated_generation_skips_rsa_exports_config_writes_and_reload(self):
        self.shell(r'''
initial
before="$(stat -c '%i:%Y' /etc/opendkim/KeyTable)"
make_generation second 'a.example.test default
b.example.test default'
render_config second
assert_same "$(checks)" 0 'cached checks'
assert_same "$(exports)" 0 'cached exports'
assert_same "$(config_checks)" 0 'cached config'
assert_same "$needs_reload" 0 'no unnecessary reload'
assert_same "$before" "$(stat -c '%i:%Y' /etc/opendkim/KeyTable)" 'table preserved'
grep -q '"generation":"second"' /app-data/dkim-applied.json
''')

    def test_add_domain_only_prepares_new_key(self):
        self.shell(r'''
initial
before="$(sha256sum /etc/opendkim/keys/a.example.test/default.private)"
make_generation second 'a.example.test default
b.example.test default
c.example.test default'
render_config second
assert_same "$(generated)" 1 'one new key'
assert_same "$(exports)" 1 'only new public export'
assert_same "$needs_reload" 1 'new key needs reload'
assert_same "$before" "$(sha256sum /etc/opendkim/keys/a.example.test/default.private)" 'existing private preserved'
assert_same "$(wc -l < /etc/opendkim/KeyTable)" 3 'all keys retained'
''')

    def test_selector_change_only_prepares_changed_identity(self):
        self.shell(r'''
initial
old="$(sha256sum /etc/opendkim/keys/a.example.test/default.private)"
make_generation second 'a.example.test rotated
b.example.test default'
render_config second
assert_same "$(generated)" 1 'new selector'
assert_same "$(exports)" 1 'only changed selector export'
assert_same "$old" "$(sha256sum /etc/opendkim/keys/a.example.test/default.private)" 'old selector retained'
grep -q 'rotated._domainkey.a.example.test' /etc/opendkim/KeyTable
! grep -q 'default._domainkey.a.example.test' /etc/opendkim/KeyTable
''')

    def test_corrupted_or_missing_txt_recovers_same_key(self):
        for change in ("rm /etc/opendkim/keys/a.example.test/default.txt",
                       "printf 'corrupt' > /etc/opendkim/keys/a.example.test/default.txt"):
            with self.subTest(change=change):
                self.shell(r'''
initial
before="$(sha256sum /etc/opendkim/keys/a.example.test/default.private /etc/opendkim/keys/a.example.test/default.txt)"
''' + change + r'''
render_config first
assert_same "$(checks)" 1 'only affected private checked'
assert_same "$(exports)" 1 'only affected TXT restored'
assert_same "$(generated)" 0 'private preserved'
assert_same "$before" "$(sha256sum /etc/opendkim/keys/a.example.test/default.private /etc/opendkim/keys/a.example.test/default.txt)" 'same original TXT recovered'
''')

    def test_private_rotation_detected_even_with_preserved_mtime(self):
        self.shell(r'''
initial
touch -r /etc/opendkim/keys/a.example.test/default.private /tmp/mtime
command openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /etc/opendkim/keys/a.example.test/default.private 2>/dev/null
touch -r /tmp/mtime /etc/opendkim/keys/a.example.test/default.private
rotated="$(sha256sum /etc/opendkim/keys/a.example.test/default.private)"
old_txt="$(sha256sum /etc/opendkim/keys/a.example.test/default.txt)"
render_config first
assert_same "$(checks)" 1 'rotated private checked'
assert_same "$(exports)" 1 'rotated public exported'
assert_same "$rotated" "$(sha256sum /etc/opendkim/keys/a.example.test/default.private)" 'rotation preserved'
[ "$old_txt" != "$(sha256sum /etc/opendkim/keys/a.example.test/default.txt)" ]
assert_same "$needs_reload" 1 'rotation needs reload'
''')

    def test_invalid_private_does_not_publish_ack_or_cache(self):
        self.shell(r'''
initial
cp /app-data/dkim-applied.json /tmp/ack-before
cp /etc/opendkim/.validated-keys.sha256 /tmp/cache-before
printf 'invalid private' > /etc/opendkim/keys/a.example.test/default.private
trap 'cmp -s /tmp/ack-before /app-data/dkim-applied.json && cmp -s /tmp/cache-before /etc/opendkim/.validated-keys.sha256 || exit 0; echo EXPECTED_FAILURE_CHECKED' EXIT
make_generation second 'a.example.test default
b.example.test default'
render_config second
''', succeeds=False)

    def test_removed_domain_leaves_key_but_removes_tables_and_cache_entry(self):
        self.shell(r'''
initial
make_generation second 'b.example.test default'
render_config second
assert_same "$(checks)" 0 'remove needs no RSA validation'
assert_same "$(exports)" 0 'remove needs no export'
assert_same "$needs_reload" 1 'table removal needs reload'
! grep -q 'a.example.test' /etc/opendkim/KeyTable
! grep -q 'a.example.test' /etc/opendkim/.validated-keys.sha256
[ -f /etc/opendkim/keys/a.example.test/default.private ]
''')

    def test_empty_set_and_readd_use_correct_identities(self):
        self.shell(r'''
initial
make_generation empty ''
render_config empty
assert_same "$(wc -l < /etc/opendkim/KeyTable)" 0 'empty key table'
assert_same "$(wc -l < /etc/opendkim/.validated-keys.sha256)" 1 'empty cache only header'
reset_calls
make_generation third 'a.example.test default'
render_config third
assert_same "$(checks)" 1 'readded private checked'
assert_same "$(generated)" 0 'readded key reused'
''')

    def test_restart_rechecks_content_and_validates_config_without_rsa(self):
        self.shell(r'''
initial
rendered=0
render_config first
assert_same "$(checks)" 0 'unchanged persisted cache'
assert_same "$(exports)" 0 'no startup public export'
assert_same "$(config_checks)" 1 'startup config still checked'
''')

    def test_unknown_cache_version_forces_validation(self):
        self.shell(r'''
initial
sed -i '1s/v1/v0/' /etc/opendkim/.validated-keys.sha256
render_config first
assert_same "$(checks)" 2 'untrusted version checks all keys'
assert_same "$(exports)" 2 'untrusted version exports all keys'
assert_same "$(stat -c %a /etc/opendkim/.validated-keys.sha256)" 600 'cache private'
''')

    def test_change_during_render_fails_closed(self):
        self.shell(r'''
initial
cp /app-data/dkim-applied.json /tmp/ack-before
cp /etc/opendkim/.validated-keys.sha256 /tmp/cache-before
hash_pass=0
key_hashes() {
  hash_pass=$((hash_pass+1))
  if [ "$hash_pass" -eq 2 ]; then printf 'changed' >> /etc/opendkim/keys/a.example.test/default.private; fi
  xargs -r sha256sum -- < "$work/paths"
}
trap 'cmp -s /tmp/ack-before /app-data/dkim-applied.json && cmp -s /tmp/cache-before /etc/opendkim/.validated-keys.sha256 || exit 0; echo EXPECTED_FAILURE_CHECKED' EXIT
render_config first
''', succeeds=False)

    def test_legacy_and_old_generation_file_layouts(self):
        self.shell(r'''
env_domains='a.example.test,b.example.test'
render_config legacy
assert_same "$(wc -l < /etc/opendkim/KeyTable)" 2 'legacy default selectors'
reset_calls
make_generation old 'a.example.test default'
mv /app-data/generations/old/key-domains.list /app-data/generations/old/domains.list
mv /app-data/generations/old/key-selectors.list /app-data/generations/old/selectors.list
render_config old
assert_same "$(checks)" 0 'old layout uses same cache'
assert_same "$(wc -l < /etc/opendkim/KeyTable)" 1 'old enabled domain list'
''')

    def test_unsafe_identity_fails_before_key_work(self):
        self.shell(r'''
make_generation first 'a.example.test ../../escape'
render_config first
''', succeeds=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
