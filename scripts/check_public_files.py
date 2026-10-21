"""Check the exact staged Git snapshot for private files and deployment references."""
from __future__ import annotations
import ipaddress
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PARTS = {'.git', '.ssh', '.aws', '.codex', '.agents', '.codex-server-access',
                   'app-data', 'maildata', 'dkim', 'backups', 'logs', 'reports',
                   'node_modules', '__pycache__', '.venv', '.public-release'}
SECRET_SUFFIXES = {'.pem', '.key', '.private', '.p12', '.pfx', '.kdbx', '.eml', '.mbox',
                   '.sqlite', '.sqlite3', '.db', '.har', '.pcap', '.pcapng'}
IPV4 = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
TOKEN = re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}'
                   r'|xkeysib-[A-Za-z0-9-]{20,}|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9_-]{20,})\b')
PRIVATE_KEY = re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----')
LOCAL_HOME = re.compile(r'(?<![\w%])(?:[A-Za-z]:[\\/](?!/)|/(?:root|home|Users)/)')
URL = re.compile(r'https?://[^\s<>"\x27`]+')
PUBLIC_HOSTS = {'api.cloudflare.com', 'api.brevo.com', 'domain-api.digitalplat.org',
                'github.com', 'localhost'}
ALLOWED_NETWORKS = tuple(ipaddress.ip_network(net) for net in (
    '127.0.0.0/8', '172.30.0.0/24', '172.31.240.0/24', '192.0.2.0/24',
    '198.51.100.0/24', '203.0.113.0/24'))


def allowed_host(host: str) -> bool:
    host = host.rstrip('.').lower()
    if host in PUBLIC_HOSTS or host == 'example.com' or host.endswith(('.example.com', '.localhost')):
        return True
    if host.endswith(('.test', '.invalid', '.example')) or host in {'example', 'fixture'}:
        return True
    try:
        address = ipaddress.ip_address(host)
        return (address.is_loopback or str(address) in {'0.0.0.0','10.1.2.3','169.254.169.254'}
                or (getattr(address, 'ipv4_mapped', None) is not None and address.ipv4_mapped.is_loopback)
                or any(address.version == network.version and address in network for network in ALLOWED_NETWORKS))
    except ValueError:
        # Dynamic template URLs contain symbolic hostnames, never deployment values.
        return bool(re.fullmatch(r'[A-Z_]+', host.upper())) and '.' not in host


def snapshot():
    if (ROOT / '.git').exists():
        raw = subprocess.check_output(['git', 'ls-files', '--cached', '-z'], cwd=ROOT)
        for name in raw.decode('utf-8').split('\0'):
            if name:
                data = subprocess.check_output(['git', 'show', ':' + name], cwd=ROOT)
                yield name, data
    else:
        for path in ROOT.rglob('*'):
            if path.is_file() and not set(path.relative_to(ROOT).parts) & FORBIDDEN_PARTS:
                yield path.relative_to(ROOT).as_posix(), path.read_bytes()


def main() -> int:
    findings=[]
    count=0
    for name,data in snapshot():
        count+=1
        path=Path(name)
        if (set(path.parts) & FORBIDDEN_PARTS or path.suffix.lower() in SECRET_SUFFIXES
                or (path.name.startswith('.env') and path.name != '.env.example')
                or path.name.startswith(('deploy_', 'remote_', 'production_', 'tmp_'))):
            findings.append((name, 0, 'private file type'))
        try:
            text=data.decode('utf-8')
        except UnicodeDecodeError:
            findings.append((name, 0, 'binary file requires manual review'))
            continue
        for number,line in enumerate(text.splitlines(), 1):
            for kind,pattern in [('private key', PRIVATE_KEY), ('credential token', TOKEN), ('local user path', LOCAL_HOME)]:
                if pattern.search(line): findings.append((name,number,kind))
            for value in IPV4.findall(line):
                try: address=ipaddress.ip_address(value)
                except ValueError: continue
                if (str(address) not in {'0.0.0.0','8.8.8.8','10.1.2.3','169.254.169.254'}
                        and not any(address in network for network in ALLOWED_NETWORKS)):
                    findings.append((name,number,'non-example IP address'))
            for value in URL.findall(line):
                try: host=urlsplit(value).hostname
                except ValueError: continue
                if host and not any(c in host for c in '$%{}') and not allowed_host(host):
                    findings.append((name,number,'non-example service URL'))
    for name,number,kind in findings:
        print(f'{name}:{number}: {kind}')
    if not count:
        print('FAIL: snapshot contains no files')
        return 1
    print(f'{"FAIL" if findings else "PASS"}: {count} files, {len(findings)} findings (values hidden)')
    return bool(findings)


if __name__ == '__main__':
    sys.exit(main())
