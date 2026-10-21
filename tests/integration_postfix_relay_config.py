"""Validate relay rendering in disposable, network-disabled Postfix containers.

Usage: python tests/integration_postfix_relay_config.py --image IMAGE
No production environment, credentials, volumes, ports or mail submissions.
"""
import argparse
import json
import subprocess


PREPARE = """
set -eu
sed '/^# Explicit file logging/,$d' /entrypoint.sh > /tmp/config-definitions.sh
. /tmp/config-definitions.sh
render_config legacy
"""
DEFAULTS = {
    "MAIL_DOMAIN": "example.test",
    "MAIL_HOST": "mail.example.test",
    "MAIL_OUTBOUND_SMTP_HOST": "smtp.example.test",
    "MAIL_OUTBOUND_SMTP_PORT": "587",
    "MAIL_OUTBOUND_SMTP_USERNAME": "fixture-user",
    "MAIL_OUTBOUND_SMTP_PASSWORD": "fixture-password-not-a-secret",
    "MAIL_OUTBOUND_SMTP_STARTTLS": "1",
}


def check(image, name, overrides=None, script="", rejected=False):
    env = dict(DEFAULTS, **(overrides or {}))
    args = ["docker", "run", "--rm", "--network", "none", "--entrypoint", "sh"]
    for key, value in env.items():
        args += ["-e", key + "=" + value]
    result = subprocess.run(
        args + [image, "-c", PREPARE + script],
        capture_output=True, text=True, timeout=60,
    )
    if rejected:
        assert result.returncode != 0, name + ": invalid configuration accepted"
    else:
        assert result.returncode == 0, name + ": " + result.stderr[-800:]
    assert DEFAULTS["MAIL_OUTBOUND_SMTP_PASSWORD"] not in result.stdout + result.stderr
    print("PASS:", name)
    return {"test": name, "status": "passed"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    results = [check(args.image, "verified STARTTLS, AUTH and private password maps", script="""
test "$(postconf -h relayhost)" = '[smtp.example.test]:587'
test "$(postconf -h smtp_sasl_auth_enable)" = yes
test "$(postconf -h smtp_tls_security_level)" = verify
test "$(postconf -h smtp_tls_wrappermode)" = no
test "$(stat -c %a /etc/postfix/sasl_passwd)" = 600
test "$(stat -c %a /etc/postfix/sasl_passwd.db)" = 600
test "$(postmap -q '[smtp.example.test]:587' hash:/etc/postfix/sasl_passwd)" = \
  'fixture-user:fixture-password-not-a-secret'
test "$(postconf -h virtual_transport)" = virtual
""")]
    results.append(check(args.image, "disabling relay removes credentials and TLS wrapper state",
                         script="""
outbound_smtp_host=''
postconf -e 'smtp_tls_wrappermode=yes'
render_config legacy
test -z "$(postconf -h relayhost)"
test "$(postconf -h smtp_sasl_auth_enable)" = no
test "$(postconf -h smtp_tls_wrappermode)" = no
test ! -e /etc/postfix/sasl_passwd
test ! -e /etc/postfix/sasl_passwd.db
"""))
    invalid = [
        ("reject unauthenticated relay", {"MAIL_OUTBOUND_SMTP_USERNAME": ""}),
        ("reject missing password", {"MAIL_OUTBOUND_SMTP_PASSWORD": ""}),
        ("reject plaintext authentication", {"MAIL_OUTBOUND_SMTP_STARTTLS": "0"}),
        ("reject implicit TLS port in STARTTLS mode", {"MAIL_OUTBOUND_SMTP_PORT": "465"}),
        ("reject invalid port", {"MAIL_OUTBOUND_SMTP_PORT": "0"}),
        ("reject overflowing port", {"MAIL_OUTBOUND_SMTP_PORT": "65536"}),
        ("reject host injection", {"MAIL_OUTBOUND_SMTP_HOST": "smtp.example.test\nrelay"}),
        ("reject username injection", {"MAIL_OUTBOUND_SMTP_USERNAME": "user:injected"}),
        ("reject password newline", {"MAIL_OUTBOUND_SMTP_PASSWORD": "fake\ninjected"}),
    ]
    for name, overrides in invalid:
        results.append(check(args.image, name, overrides, rejected=True))
    print(json.dumps({"scope": "isolated network-disabled Postfix containers",
                      "status": "passed", "results": results}, indent=2))


if __name__ == "__main__":
    main()
