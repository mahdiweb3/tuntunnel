#!/usr/bin/env bash
set -euo pipefail
if ! command -v python3 >/dev/null 2>&1; then
    [ "$(id -u)" -eq 0 ] || { printf '%s\n' 'python3 required; run as root.' >&2; exit 1; }
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update && apt-get install -y python3
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y python3
    elif command -v apk >/dev/null 2>&1; then
        apk add python3
    else
        printf '%s\n' 'Please install python3 first.' >&2; exit 1
    fi
fi
TE_SOURCE="$(readlink -f "${BASH_SOURCE[0]}")"
export TE_SOURCE
exec 3<&0
python3 - "$@" 3<&3 <<'__TUNNEL_EXTRA_PY__'
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import datetime
import tempfile
import time
import urllib.request
import urllib.error
import uuid
import zipfile
import zlib

# ponytail: BackPack-inspired Blue ANSI palette
B_DEEP = '\033[1;38;5;27m'
B_MAIN = '\033[1;38;5;33m'
B_BRIGHT = '\033[1;38;5;39m'
B_CYAN = '\033[1;38;5;45m'
B_ICE = '\033[1;38;5;51m'
B_SOFT = '\033[38;5;117m'
B_LINE = '\033[38;5;33m' + ('─' * 58) + '\033[0m'
C_WHITE = '\033[1;97m'
C_GREEN = '\033[38;5;48m'
C_YELLOW = '\033[38;5;220m'
C_RED = '\033[1;38;5;196m'
C_DIM = '\033[2;37m'
C_RST = '\033[0m'

VERSION = '2.7.1'

BANNER = (
    f'{B_DEEP}    ______            ______                      __{C_RST}\n'
    f'{B_MAIN}   /_  __/_  ______  /_  __/_  ______  ____  ___  / /{C_RST}\n'
    f'{B_BRIGHT}    / / / / / / __ \\  / / / / / / __ \\/ __ \\/ _ \\/ / {C_RST}\n'
    f'{B_CYAN}   / / / /_/ / / / / / / / /_/ / / / / / / /  __/ /  {C_RST}\n'
    f'{B_ICE}  /_/  \\__,_/_/ /_/ /_/  \\__,_/_/ /_/_/ /_/\\___/_/   {C_RST}\n\n'
    f'  {B_SOFT}Multi-Core Tunnel & Transport Benchmark Tool •{C_RST} {B_BRIGHT}v{VERSION}{C_RST}'
)


class Back(Exception):
    pass

ROOT = Path('/etc/tunnel-extra')
BIN = Path('/opt/tunnel-extra/bin')
SELF = Path('/usr/local/lib/tunnel-extra/tunnel-extra.sh')
UNITS = Path('/etc/systemd/system')
BUNDLE_RUNNER_SOURCE = '"""Run one tunnel bundle; child failure stops the whole bundle for systemd restart."""\nimport json\nimport os\nfrom pathlib import Path\nimport signal\nimport subprocess\nimport sys\nimport time\n\n\ndef main(path):\n    manifest = Path(path)\n    commands = json.loads(manifest.read_text())\n    if not isinstance(commands, list) or not commands:\n        raise ValueError(\'Empty tunnel bundle\')\n    for argv in commands:\n        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):\n            raise ValueError(\'Invalid bundle command\')\n    children = []\n    stopping = False\n\n    def stop(signum, frame):\n        nonlocal stopping\n        stopping = True\n\n    for signum in (signal.SIGTERM, signal.SIGINT):\n        signal.signal(signum, stop)\n    try:\n        for argv in commands:\n            if stopping:\n                return 0\n            children.append(subprocess.Popen(argv, cwd=manifest.parent, start_new_session=True))\n        while not stopping:\n            for child in children:\n                status = child.poll()\n                if status is not None:\n                    print(f\'Tunnel component exited: status={status}\', file=sys.stderr)\n                    return status if 0 < status < 126 else 1\n            time.sleep(.1)\n        return 0\n    finally:\n        for child in children:\n            if child.poll() is None:\n                try:\n                    os.killpg(child.pid, signal.SIGTERM)\n                except ProcessLookupError:\n                    pass\n        deadline = time.monotonic() + 5\n        for child in children:\n            try:\n                child.wait(timeout=max(.01, deadline - time.monotonic()))\n            except subprocess.TimeoutExpired:\n                try:\n                    os.killpg(child.pid, signal.SIGKILL)\n                except ProcessLookupError:\n                    pass\n                child.wait()\n\n\nif __name__ == \'__main__\':\n    sys.exit(main(sys.argv[1]))\n'


def _self_path():
    # ponytail: stdin heredoc (`tunnel-extra.sh`) omits __file__; resolve TE_SOURCE -> __file__ -> SELF.
    if os.environ.get('TE_SOURCE'):
        return Path(os.environ['TE_SOURCE']).resolve()
    if '__file__' in globals():
        return Path(__file__).resolve()
    return SELF

PROFILES = {
    'tcp-tls': dict(engine='sing-box'),

    # --- GOST v3 ---
    'gost-relay-tls': dict(engine='gost', transport='relay+tls'),
    'gost-relay-ws': dict(engine='gost', transport='relay+ws'),
    'gost-relay-wss': dict(engine='gost', transport='relay+wss'),
    'gost-relay-kcp': dict(engine='gost', transport='relay+kcp', udp=True),
    'gost-relay-quic': dict(engine='gost', transport='relay+quic', udp=True),
    'gost-relay-grpc': dict(engine='gost', transport='relay+grpc'),
    'gost-relay-h2': dict(engine='gost', transport='relay+h2'),

    'gost-relay-pht': dict(engine='gost', transport='relay+pht'),
    'gost-reverse-tls': dict(engine='gost', transport='relay+tls', direction='reverse'),
    'gost-reverse-ws': dict(engine='gost', transport='relay+ws', direction='reverse'),
    'gost-reverse-wss': dict(engine='gost', transport='relay+wss', direction='reverse'),
    'gost-reverse-kcp': dict(engine='gost', transport='relay+kcp', udp=True, direction='reverse'),
    'gost-reverse-quic': dict(engine='gost', transport='relay+quic', udp=True, direction='reverse'),
    'gost-reverse-grpc': dict(engine='gost', transport='relay+grpc', direction='reverse'),
    'gost-reverse-h2': dict(engine='gost', transport='relay+h2', direction='reverse'),

    'gost-reverse-pht': dict(engine='gost', transport='relay+pht', direction='reverse'),

    # --- Rathole ---
    'rathole-tcp': dict(engine='rathole', transport='tcp', direction='reverse'),
    'rathole-noise': dict(engine='rathole', transport='noise', direction='reverse'),
    'rathole-tls': dict(engine='rathole', transport='tls', direction='reverse'),
    'rathole-ws': dict(engine='rathole', transport='websocket', direction='reverse'),
    'rathole-direct-tcp': dict(engine='rathole', transport='tcp', direction='direct'),
    'rathole-direct-noise': dict(engine='rathole', transport='noise', direction='direct'),
    'rathole-direct-tls': dict(engine='rathole', transport='tls', direction='direct'),
    'rathole-direct-ws': dict(engine='rathole', transport='websocket', direction='direct'),

    # --- Backhaul ---
    'backhaul-tcp': dict(engine='backhaul', transport='tcp', direction='reverse'),
    'backhaul-tcpmux': dict(engine='backhaul', transport='tcpmux', direction='reverse'),
    'backhaul-ws': dict(engine='backhaul', transport='ws', direction='reverse'),
    'backhaul-wsmux': dict(engine='backhaul', transport='wsmux', direction='reverse'),
    'backhaul-wssmux': dict(engine='backhaul', transport='wssmux', direction='reverse'),
    'backhaul-direct-tcp': dict(engine='backhaul', transport='tcp', direction='direct'),
    'backhaul-direct-tcpmux': dict(engine='backhaul', transport='tcpmux', direction='direct'),
    'backhaul-direct-ws': dict(engine='backhaul', transport='ws', direction='direct'),
    'backhaul-direct-wsmux': dict(engine='backhaul', transport='wsmux', direction='direct'),
    'backhaul-direct-wssmux': dict(engine='backhaul', transport='wssmux', direction='direct'),

    # --- Kariz Native ---
    'kariz-tcp': dict(engine='kariz', transport='tcp', direction='direct'),
    'kariz-tcpmux': dict(engine='kariz', transport='tcpmux', direction='direct'),
    'kariz-ws': dict(engine='kariz', transport='ws', direction='direct'),
    'kariz-wss': dict(engine='kariz', transport='wss', direction='direct'),
    'kariz-quic': dict(engine='kariz', transport='quic', udp=True, direction='direct'),
    'kariz-kcp': dict(engine='kariz', transport='kcp', udp=True, direction='direct'),
    'kariz-paqet': dict(engine='kariz', transport='paqet', raw=True, direction='direct'),
    'kariz-reverse-tcp': dict(engine='kariz', transport='tcp', direction='reverse'),
    'kariz-reverse-tcpmux': dict(engine='kariz', transport='tcpmux', direction='reverse'),
    'kariz-reverse-ws': dict(engine='kariz', transport='ws', direction='reverse'),
    'kariz-reverse-wss': dict(engine='kariz', transport='wss', direction='reverse'),
    'kariz-reverse-quic': dict(engine='kariz', transport='quic', udp=True, direction='reverse'),
    'kariz-reverse-kcp': dict(engine='kariz', transport='kcp', udp=True, direction='reverse'),
    'kariz-reverse-paqet': dict(engine='kariz', transport='paqet', raw=True, direction='reverse'),

    # --- Sing-box & Xray ---
    'tuic-tls': dict(engine='sing-box', transport='tuic', udp=True),
    'tuic-udp': dict(engine='sing-box', transport='tuic', udp=True),
    'hysteria2-udp': dict(engine='sing-box', transport='hysteria2', udp=True),
    'vless-reality': dict(engine='sing-box', transport='reality'),
    'shadowtls-v3': dict(engine='sing-box', transport='shadowtls'),
    'reality-grpc': dict(engine='xray', transport='reality-grpc'),
    'reality-xhttp': dict(engine='xray', transport='reality-xhttp'),

    # --- BackPack Direct ---
    'bp-direct-tcp': dict(engine='backpack', transport='tcp', direction='direct'),
    'bp-direct-faketcp': dict(engine='backpack', transport='pck', raw=True, direction='direct'),
    'bp-direct-kcp': dict(engine='backpack', transport='kcp', udp=True, direction='direct'),
    'bp-direct-ws': dict(engine='backpack', transport='ws', direction='direct'),

    # --- Pango (Pangolin-compatible Tunnels) ---
    'pango-tcp': dict(engine='sing-box'),
    'pango-ws': dict(engine='sing-box', transport='ws', mux='smux'),
    'pango-tls': dict(engine='sing-box', transport='httpupgrade', mux='smux'),
    'pango-grpc': dict(engine='sing-box', transport='grpc'),

    'smux-tls': dict(engine='sing-box', mux='smux'),
    'yamux-tls': dict(engine='sing-box', mux='yamux'),
    'h2mux-tls': dict(engine='sing-box', mux='h2mux'),
    'wss': dict(engine='sing-box', transport='ws'),
    'wss-smux': dict(engine='sing-box', transport='ws', mux='smux'),
    'grpc-tls': dict(engine='sing-box', transport='grpc'),
    'h2-tls': dict(engine='sing-box', transport='http'),
    'httpupgrade-tls': dict(engine='sing-box', transport='httpupgrade', mux='smux'),
    'quic-tls': dict(engine='sing-box', transport='hysteria2'),
    'xhttp-tls': dict(engine='xray', transport='xhttp'),
    'xray-wss': dict(engine='xray', transport='ws'),
    'xray-grpc': dict(engine='xray', transport='grpc'),
    'mkcp-chacha': dict(engine='xray', transport='kcp', cipher='chacha20-poly1305'),
    'mkcp-aes': dict(engine='xray', transport='kcp', cipher='aes-128-gcm'),
    'tcp-stealth': dict(engine='backpack', transport='stealth', raw=True),
    'bp-tcpmux': dict(engine='backpack', transport='tcpmux'),
    'bp-wssmux': dict(engine='backpack', transport='wssmux'),
    'bp-quic': dict(engine='backpack', transport='quic', udp=True),
    'bp-ws': dict(engine='backpack', transport='ws'),
    'bp-tcp': dict(engine='backpack', transport='tcp'),
    'faketcp-pck': dict(engine='backpack', transport='pck', raw=True),
    'kcp-aes': dict(engine='backpack', transport='kcp', udp=True),
    'icmp-aes': dict(engine='backpack', transport='xdi', raw=True),

    **{'dagger-' + n: dict(engine='dagger', transport=n)
       for n in ('tcp', 'ws', 'wss', 'http', 'xhttp', 'quantum', 'quantum+')},
}
GOST_DTLS_PIN = 'v3.2.6'  # gost 3.3.x DTLS dialer fails (pre-connected WriteTo); 3.2.6 verified
# reverse-only engines: direct mode = engine dialled Iran->abroad + tuntunnel-core reverse bridge on top
CORE_WRAPPED = ('backhaul', 'rathole', 'backpack')
RELEASES = {
    'sing-box': ('SagerNet/sing-box', 'v1.14.4'),
    'xray': ('XTLS/Xray-core', 'v26.11.9'),
    'dagger': ('itsFLoKi/daggerConnect', 'v1.4'),
    'backpack': ('AminMGMT/BackPack', 'v1.8.5'),
    'kariz': ('Erfan-XRay/Kariz', 'v2.8.1'),  # paqet needs >=2.8.0; 2.8.1 = version the matrix ran
    'gost': ('go-gost/gost', 'v3.3.3'),
    'rathole': ('rathole-org/rathole', 'v0.5.0'),
    'backhaul': ('Musixal/Backhaul', 'v0.6.5'),
}

def run(argv, check=True, timeout=60):
    p = subprocess.run([str(x) for x in argv], capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f'Command failed: {argv[0]} (exit {p.returncode})')
    return p


def write(path, content, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode), 'w') as handle:
        handle.write(content)
    os.chmod(tmp, mode)
    tmp.replace(path)


def port(value, label='Port'):
    try:
        number = int(str(value).strip())
    except ValueError as exc:
        raise ValueError(f'{label} must be an integer.') from exc
    if not 1 <= number <= 65535:
        raise ValueError(f'{label} must be between 1 and 65535.')
    return number


def name_ok(name):
    name = name.strip().lower()
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,19}', name):
        raise ValueError('Connection name must be 1..20 lowercase letters/digits/dash.')
    return name


def parse_maps(value, network='tcp'):
    if network not in ('tcp', 'udp', 'both'):
        raise ValueError('Network protocol must be tcp, udp, or both.')
    items, used = [], set()
    for raw in [x.strip() for x in value.split(',') if x.strip()]:
        left, sep, right = raw.partition('=' if '=' in raw else ':')
        entry = port(left, 'Entry port')
        target = port(right if sep else left, 'Target port')
        if entry in used:
            raise ValueError(f'Duplicate entry port: {entry}')
        used.add(entry)
        items.append({'entry': entry, 'target': target, 'network': network})
    if not items:
        raise ValueError('At least one port mapping is required (e.g. 18080=8080).')
    return items


def next_free_port(base, forbidden):
    p = base + 1 if base < 65000 else base - 1000
    while p in forbidden or not (1 <= p <= 65535):
        p += 1
        if p > 65535:
            p = 20000
    return p


def new_pair(name, profile, iran, abroad, tunnel_port, maps, carrier='none', subnet='10.203.88.0/30', direction=None, adapter_port=None, link_id=None, vxlan_port=4789):
    if profile not in PROFILES:
        raise ValueError('Unknown transport profile.')
    engine = PROFILES[profile]['engine']
    if direction is None:
        direction = profile_direction(profile)
    if direction not in ('direct', 'reverse'):
        raise ValueError('Direction must be direct or reverse.')
    tp = port(tunnel_port, 'Tunnel port')
    used_ports = {tp} | {m['entry'] for m in maps} | {m['target'] for m in maps}
    ap = port(adapter_port, 'Adapter port') if adapter_port else next_free_port(tp, used_ports)
    secret = str(uuid.uuid4()) if engine == 'xray' else secrets.token_urlsafe(24)
    data = dict(
        version=1, name=name_ok(name), profile=profile, direction=direction,
        iran_ip=str(ipaddress.ip_address(iran.strip())),
        abroad_ip=str(ipaddress.ip_address(abroad.strip())),
        port=tp, adapter_port=ap, target='127.0.0.1',
        entry_bind='0.0.0.0', maps=maps, secret=secret,
        carrier=carrier, subnet=subnet,
        link_id=link_id or (int.from_bytes(hashlib.sha256(name.encode()).digest()[:3], 'big') % 16000000 + 100),
        vxlan_port=vxlan_port or 4789, pool=48, server_name='tunnel-extra.local', certificate='',
    )
    validate(data)
    return data


def validate(d):
    if not isinstance(d, dict):
        raise ValueError('Connection settings must be an object.')
    if 'dtls' in str(d.get('profile', '')).lower():
        raise ValueError('DTLS retired: choose another transport and create a new peer link.')
    if d.get('profile') not in PROFILES:
        raise ValueError('Unknown transport profile.')
    if d.get('direction', 'direct') not in ('direct', 'reverse'):
        raise ValueError('Direction must be direct or reverse.')
    name_ok(str(d.get('name', '')))
    for key in ('iran_ip', 'abroad_ip', 'target', 'entry_bind'):
        ipaddress.ip_address(str(d.get(key, '')))
    port(d.get('port', 0), 'Tunnel port')
    port(d.get('adapter_port', d.get('port', 30443) + 1), 'Adapter port')
    port(d.get('vxlan_port', 4789), 'VXLAN port')
    if not 1 <= int(d.get('pool', 48)) <= 256:
        raise ValueError('Pool size must be between 1 and 256.')
    if d.get('carrier') not in ('none', 'gre', 'vxlan', 'ipip'):
        raise ValueError('Carrier type is invalid.')
    net = ipaddress.ip_network(str(d.get('subnet', '10.203.88.0/30')), strict=False)
    if net.version != 4 or net.prefixlen > 30 or not net.is_private:
        raise ValueError('Private IPv4 /30 (or larger) subnet is required.')
    if not d.get('maps') or len(d['maps']) > 64:
        raise ValueError('Between 1 and 64 port mappings are required.')
    used = set()
    for item in d['maps']:
        entry, target = port(item['entry'], 'Entry port'), port(item['target'], 'Target port')
        if entry in used:
            raise ValueError(f'Duplicate entry port: {entry}')
        used.add(entry)
        if item.get('network') not in ('tcp', 'udp', 'both'):
            raise ValueError('Mapping protocol is invalid.')
    if len(str(d.get('secret', ''))) < 16:
        raise ValueError('Connection secret is invalid.')
    if 'camouflage' in d:
        d['camouflage'] = camouflage(d)
    direction_for(d)
    p = PROFILES[d['profile']]
    if p.get('transport', 'tcp') == 'paqet':
        iran, abroad = addresses(d)
        if d['carrier'] != 'none' or ':' in iran or ':' in abroad:
            raise ValueError('Paqet needs public IPv4 on both sides and no GRE/VXLAN/IPIP carrier (Kariz docs/paqet.md).')
    if p['engine'] == 'dagger' and direction_for(d) == 'direct':
        raise ValueError(f"{p['engine']} has no native direct forwarding in this setup; choose a native direct engine.")
    if p['engine'] in CORE_WRAPPED and direction_for(d) == 'direct' and any(m['network'] != 'tcp' for m in d['maps']):
        raise ValueError(f"{p['engine']} direct mode runs through tuntunnel-core and carries TCP mappings only.")
    if p['engine'] == 'backhaul' and any(m['network'] != 'tcp' for m in d['maps']):
        raise ValueError('Backhaul profiles support TCP mappings only.')
    if p['engine'] == 'xray':
        try:
            uuid.UUID(d['secret'])
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError('Xray secret must be a UUID.') from exc
    if d.get('adapter_port') == d['port'] or any(m['entry'] == d['port'] for m in d['maps']):
        raise ValueError('Tunnel, adapter and entry listeners must use distinct ports.')


def encode_code(d):
    validate(d)
    raw = json.dumps(d, separators=(',', ':'), sort_keys=True).encode()
    return 'TE1:' + base64.urlsafe_b64encode(raw).decode().rstrip('=')


def setup_link(d):
    return 'tuntunnel://' + encode_code(d)[4:]


def decode_code(code):
    code = code.strip().strip("'\"")
    if code.startswith('tuntunnel://'):
        raw_body = code[len('tuntunnel://'):]
    elif code.startswith('TE1:'):
        raw_body = code[4:]
    else:
        raise ValueError('Setup link must start with tuntunnel:// or TE1:.')
    body = raw_body + '=' * (-len(raw_body) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(body.encode()).decode())
    except Exception as exc:
        raise ValueError('Connection code is corrupted or invalid.') from exc
    if not isinstance(data, dict):
        raise ValueError('Connection settings must be an object.')
    if 'direction' not in data:
        data['direction'] = profile_direction(data.get('profile'))
    if 'adapter_port' not in data:
        tp = int(data.get('port', 30443))
        used = {tp} | {int(m['entry']) for m in data.get('maps', [])} | {int(m['target']) for m in data.get('maps', [])}
        data['adapter_port'] = next_free_port(tp, used)
    validate(data)
    return data


def addresses(d):
    if d['carrier'] == 'none':
        return d['iran_ip'], d['abroad_ip']
    hosts = list(ipaddress.ip_network(d['subnet'], strict=False).hosts())
    return str(hosts[0]), str(hosts[1])


def profile_direction(profile):
    p = PROFILES.get(profile, {})
    return p.get('direction', 'reverse' if p.get('engine') in ('dagger', 'backpack', 'backhaul', 'rathole') else 'direct')


def direction_for(d):
    direction = d.get('direction', profile_direction(d.get('profile')))
    if direction not in ('direct', 'reverse'):
        raise ValueError('Direction must be direct or reverse.')
    return direction


def side_for(d, role):
    if role not in ('server', 'client'):
        raise ValueError('Role must be server or client.')
    direction = direction_for(d)
    if direction == 'reverse':
        return 'iran' if role == 'server' else 'abroad'
    return 'abroad' if role == 'server' else 'iran'


def needs_adapter(d):
    engine = PROFILES[d['profile']]['engine']
    return engine in ('sing-box', 'xray') and direction_for(d) == 'reverse'


def camouflage(d):
    value = d.get('camouflage', 'www.microsoft.com:443')
    if not isinstance(value, str) or not value or re.search(r'\s', value):
        raise ValueError('Camouflage must be a hostname/IP and optional port.')
    parsed = urllib.parse.urlsplit('//' + value)
    try:
        host, number = parsed.hostname, parsed.port
    except ValueError as exc:
        raise ValueError('Invalid camouflage port.') from exc
    if not host or parsed.username is not None or parsed.password is not None or parsed.path or parsed.query or parsed.fragment:
        raise ValueError('Invalid camouflage address.')
    if ':' in host:
        ipaddress.IPv6Address(host)
    elif not all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', label) for label in host.split('.')):
        raise ValueError('Invalid camouflage hostname.')
    if value.endswith(':'):
        raise ValueError('Invalid camouflage port.')
    return endpoint(host, port(number if number is not None else 443, 'Camouflage port'))


def x25519_pub(priv):
    # RFC 7748 ladder, stdlib only: REALITY needs the public key at config time on both sides
    if len(priv) != 32:
        raise ValueError('X25519 private key must contain 32 bytes.')
    P, k = 2**255 - 19, bytearray(priv)
    k[0] &= 248; k[31] = (k[31] & 127) | 64
    k = int.from_bytes(k, 'little')
    x1, x2, z2, x3, z3, swap = 9, 1, 0, 9, 1, 0
    for t in range(254, -1, -1):
        bit = (k >> t) & 1
        if swap ^ bit:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b, aa, bb = (x2 + z2) % P, (x2 - z2) % P, 0, 0
        aa, bb = a * a % P, b * b % P
        e, c, d_ = (aa - bb) % P, (x3 + z3) % P, (x3 - z3) % P
        da, cb = d_ * a % P, c * b % P
        x3, z3 = (da + cb) ** 2 % P, x1 * (da - cb) ** 2 % P
        x2, z2 = aa * bb % P, e * (aa + 121665 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, 'little')


def reality_keys(secret):
    priv = hashlib.sha256(('reality:' + secret).encode()).digest()
    b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')
    return b64(priv), b64(x25519_pub(priv)), hashlib.sha256(('sid:' + secret).encode()).hexdigest()[:16]


def endpoint(host, number):
    return f'[{host}]:{number}' if ':' in host else f'{host}:{number}'


def cert_pin(path):
    import hashlib, ssl
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(Path(path).read_text())).hexdigest()


def make_certificate(directory):
    run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
         '-nodes', '-days', '3650', '-subj', '/CN=tunnel-extra.local',
         '-addext', 'subjectAltName=DNS:tunnel-extra.local',
         '-addext', 'basicConstraints=critical,CA:TRUE',
         '-keyout', str(directory / 'key.pem'), '-out', str(directory / 'cert.pem')])
    (directory / 'key.pem').chmod(0o600)
    (directory / 'cert.pem').chmod(0o600)


def make_config(d, role, directory):
    validate(d)
    side_for(d, role)
    directory = Path(directory)
    p = PROFILES[d['profile']]
    iran, abroad = addresses(d)
    direction = direction_for(d)
    remote = iran if direction == 'reverse' else abroad
    ip_obj = ipaddress.ip_address(remote)
    # ponytail: bind carrier/private GRE IP directly so internal tunnel ports stay off public NICs.
    listen = remote if (d.get('carrier', 'none') != 'none' or (ip_obj.is_private and not ip_obj.is_loopback)) else ('::' if ':' in remote else '0.0.0.0')
    cert, key = str(directory / 'cert.pem'), str(directory / 'key.pem')
    if role == 'client' and d.get('certificate'):
        cert_p = directory / 'cert.pem'
        if not cert_p.exists():
            try:
                write(cert_p, d['certificate'])
            except OSError as exc:
                raise RuntimeError('Unable to write trusted peer certificate.') from exc
    if p['engine'] == 'sing-box':
        inbound = dict(type='trojan', tag='tunnel', listen=listen, listen_port=d['port'],
                       users=[dict(password=d['secret'])],
                       tls=dict(enabled=True, min_version='1.3', certificate_path=cert, key_path=key))
        outbound = dict(type='trojan', tag='tunnel', server=remote, server_port=d['port'],
                        password=d['secret'], tls=dict(enabled=True, min_version='1.3',
                        server_name=d['server_name'], certificate=d['certificate'].splitlines()))
        transport = p.get('transport')
        if transport == 'reality':
            host, _, number = camouflage(d).rpartition(':')
            host = host.strip('[]')
            uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, d['secret']))
            priv, pub, sid = reality_keys(d['secret'])
            inbound.update(type='vless', users=[dict(uuid=uid)], tls=dict(enabled=True, server_name=host,
                reality=dict(enabled=True, handshake=dict(server=host, server_port=int(number)), private_key=priv, short_id=[sid])))
            outbound.update(type='vless', uuid=uid, tls=dict(enabled=True, server_name=host,
                utls=dict(enabled=True, fingerprint='chrome'), reality=dict(enabled=True, public_key=pub, short_id=sid)))
            outbound.pop('password')
        elif transport == 'hysteria2':
            inbound['type'] = outbound['type'] = transport
        elif transport == 'tuic':
            uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, d['secret']))
            inbound.update(type='tuic', users=[dict(uuid=uid, password=d['secret'])])
            outbound.update(type='tuic', uuid=uid)
        elif transport and transport != 'shadowtls':
            tr = dict(type=transport)
            if transport in ('ws', 'httpupgrade', 'http'):
                tr['path'] = '/tunnel'
            if transport == 'grpc':
                tr['service_name'] = 'tunnel'
            if transport == 'http':
                tr['host'] = [d['server_name']]
            inbound['transport'] = outbound['transport'] = tr
            if transport == 'httpupgrade':
                # ponytail: keep HTTPUpgrade; VLESS handles fragmented request headers.
                uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, d['secret']))
                inbound.update(type='vless', users=[dict(uuid=uid)])
                outbound.update(type='vless', uuid=uid)
                outbound.pop('password', None)
                inbound['tls']['alpn'] = outbound['tls']['alpn'] = ['http/1.1']
        inbounds, outbounds = [inbound], [outbound]
        if transport == 'shadowtls':
            host, _, port = camouflage(d).rpartition(':')
            host = host.strip('[]')
            key = base64.b64encode(hashlib.sha256(d['secret'].encode()).digest()[:16]).decode()
            ss = dict(type='shadowsocks', tag='tunnel', method='2022-blake3-aes-128-gcm', password=key)
            ss['multiplex'] = dict(enabled=True)
            inbounds = [dict(type='shadowtls', tag='stls', listen=listen, listen_port=d['port'], version=3,
                             users=[dict(name='tunnel', password=d['secret'])], handshake=dict(server=host, server_port=int(port)),
                             strict_mode=True, detour='tunnel'), ss]
            # ponytail: camouflage cert not verified; auth is the ShadowTLS v3 HMAC + inner AEAD key
            outbounds = [dict(ss, server=None, detour='stls'),
                         dict(type='shadowtls', tag='stls', server=remote, server_port=d['port'], version=3, password=d['secret'],
                              tls=dict(enabled=True, server_name=host, insecure=True))]
            outbounds[0].pop('server')
            outbounds[0]['multiplex'] = dict(enabled=True, protocol='smux')
        if p.get('mux'):
            inbound['multiplex'] = dict(enabled=True)
            inbound['tcp_fast_open'] = True
            outbound['tcp_fast_open'] = True
            outbound['multiplex'] = dict(enabled=True, protocol=p['mux'], max_connections=d['pool'],
                                         min_streams=4, max_streams=128, padding=False)
        if role == 'server':
            return dict(log=dict(level='warn'), inbounds=inbounds, outbounds=[dict(type='direct', tag='backend')],
                        route=dict(rules=[dict(inbound=['tunnel'], ip_cidr=[d['target'] + ('/128' if ':' in d['target'] else '/32')],
                        port=sorted(set(m['target'] for m in d['maps'])), action='route', outbound='backend'),
                        dict(inbound=['tunnel'], action='reject')], final='backend'))
        entries = [dict(type='direct', tag='entry' + str(m['entry']), listen=d['entry_bind'],
                        listen_port=m['entry'], override_address=d['target'], override_port=m['target'],
                        **({} if m['network'] == 'both' else dict(network=m['network']))) for m in d['maps']]
        return dict(log=dict(level='warn'), inbounds=entries, outbounds=outbounds, route=dict(final='tunnel'))
    if p['engine'] == 'xray':
        kcp = p['transport'] == 'kcp'
        real = p['transport'].startswith('reality-')
        net = p['transport'].split('-', 1)[1] if real else p['transport']
        stream = dict(network=net, security='reality' if real else 'none' if kcp else 'tls')
        if real:
            host = camouflage(d).rpartition(':')[0]
            priv, pub, sid = reality_keys(d['secret'])
            stream['realitySettings'] = (dict(show=False, dest=camouflage(d), serverNames=[host], privateKey=priv, shortIds=[sid])
                                         if role == 'server' else dict(serverName=host, fingerprint='chrome', publicKey=pub, shortId=sid, spiderX='/'))
            stream[net + 'Settings'] = dict(serviceName='tunnel') if net == 'grpc' else dict(path='/tunnel', mode='auto')
        elif kcp:
            stream['kcpSettings'] = dict(mtu=1350, tti=20, uplinkCapacity=100, downlinkCapacity=100,
                                        congestion=True, readBufferSize=16, writeBufferSize=16,
                                        seed=d['secret'], header=dict(type='none'))
        else:
            stream['tlsSettings'] = (dict(minVersion='1.3', certificates=[dict(certificateFile=cert, keyFile=key)])
                                     if role == 'server' else dict(minVersion='1.3', serverName=d['server_name'],
                                     certificates=[dict(usage='verify', certificateFile=cert, certificate=d['certificate'].splitlines())]))
            tr = p['transport']
            stream[tr + 'Settings'] = dict(serviceName='tunnel') if tr == 'grpc' else dict(path='/tunnel', **(dict(mode='auto') if tr == 'xhttp' else {}))
        protocol = 'vmess' if kcp else 'vless'
        if role == 'server':
            settings = dict(clients=[dict(id=d['secret'])], **({} if kcp else dict(decryption='none')))
            return dict(log=dict(loglevel='warning'), inbounds=[dict(tag='tunnel', listen=listen, port=d['port'],
                        protocol=protocol, settings=settings, streamSettings=stream)],
                        outbounds=[dict(tag='blocked', protocol='blackhole'),
                                   dict(tag='backend', protocol='freedom', settings=dict(finalRules=[dict(action='allow'), dict(action='block')]))],
                        routing=dict(rules=[dict(type='field', inboundTag=['tunnel'], ip=[d['target']],
                        port=','.join(str(m['target']) for m in d['maps']), outboundTag='backend'),
                        dict(type='field', inboundTag=['tunnel'], outboundTag='blocked')]))
        user = dict(id=d['secret'], **(dict(security=p['cipher']) if kcp else dict(encryption='none')))
        return dict(log=dict(loglevel='warning'),
                    inbounds=[dict(tag='entry' + str(m['entry']), listen=d['entry_bind'], port=m['entry'],
                    protocol='dokodemo-door', settings=dict(address=d['target'], port=m['target'],
                    network='tcp,udp' if m['network'] == 'both' else m['network'])) for m in d['maps']],
                    outbounds=[dict(tag='tunnel', protocol=protocol, settings=dict(vnext=[dict(address=remote,
                    port=d['port'], users=[user])]), streamSettings=stream)])
    if p['engine'] == 'backpack':
        transport = p['transport']
        mappings = [f"{endpoint(d['entry_bind'], m['entry'])}={endpoint(d['target'], m['target'])}" for m in d['maps']]
        has_udp = any(m['network'] in ('udp', 'both') for m in d['maps'])
        direction = d.get('direction', 'reverse')
        if direction == 'direct':
            if role == 'client':
                cfg = dict(role='client', transport=transport, token=d['secret'], remote_addr=endpoint(remote, d['port']),
                           ports=mappings, accept_udp=has_udp,
                           connection_pool=max(1, min(d['pool'], 32)), retry_interval=1, dial_timeout=5, skip_optz=True,
                           log_level='warn', nodelay=True, keepalive=60, mux_con=8, mux_version=2, mux_framesize=32768,
                           mux_recievebuffer=16777216, mux_streambuffer=1048576)
            else:
                cfg = dict(role='server', transport=transport, token=d['secret'], bind_addr=endpoint(listen, d['port']),
                           skip_optz=True, log_level='warn', nodelay=True, keepalive=60,
                           mux_con=8, mux_version=2, mux_framesize=32768, mux_recievebuffer=16777216, mux_streambuffer=1048576,
                           channel_size=2048, heartbeat=20, web_port=0)
        else:
            if role == 'server':
                cfg = dict(role='server', transport=transport, token=d['secret'], bind_addr=endpoint(listen, d['port']),
                           ports=mappings, accept_udp=has_udp, skip_optz=True, log_level='warn', nodelay=True, keepalive=60,
                           mux_con=8, mux_version=2, mux_framesize=32768, mux_recievebuffer=16777216, mux_streambuffer=1048576,
                           channel_size=2048, heartbeat=20, web_port=0)
            else:
                cfg = dict(role='client', transport=transport, token=d['secret'], remote_addr=endpoint(remote, d['port']),
                           connection_pool=max(1, min(d['pool'], 32)), retry_interval=1, dial_timeout=5, skip_optz=True,
                           log_level='warn', nodelay=True, keepalive=60, mux_con=8, mux_version=2, mux_framesize=32768,
                           mux_recievebuffer=16777216, mux_streambuffer=1048576)
            if transport == 'stealth':
                local_ip = abroad if direction == 'reverse' else iran
                cfg['local_addr'] = '127.0.0.1' if ipaddress.ip_address(remote).is_loopback else local_ip
        if transport in ('kcp', 'pck', 'xdi'):
            cfg.update(kcp_mtu=1200, kcp_interval=20, kcp_resend=2, kcp_nodelay=1, kcp_nocongestion=0,
                       kcp_sndwnd=2048, kcp_rcvwnd=2048, kcp_acknodelay=True, kcp_datashards=10, kcp_parityshards=3)
        return cfg
    if p['engine'] == 'kariz':
        transport = p['transport']
        profile_mode = p.get('mode', 'ultraspeed')
        is_entry = (role == 'client') if direction == 'direct' else (role == 'server')
        kariz_role = 'entry' if is_entry else 'exit'
        cfg = {
            'role': kariz_role,
            'mode': direction,
            'profile': profile_mode,
            'tunnel': {
                'transport': transport,
                'token': d['secret'],
            },
            'log': {'level': 'warn'}
        }
        if role == 'server':
            cfg['tunnel']['listen'] = endpoint(listen, d['port'])
        else:
            cfg['tunnel']['remote'] = endpoint(remote, d['port'])
        if is_entry:
            cfg['forwards'] = [
                {'listen': endpoint(d['entry_bind'], m['entry']), 'target': endpoint(d['target'], m['target']), 'protocol': 'tcp+udp' if m['network'] == 'both' else m['network']}
                for m in d['maps']
            ]
        if transport == 'wss':
            cfg['tunnel']['tls'] = ({'cert': cert, 'key': key} if role == 'server' else {'sni': d['server_name'], 'pin_sha256': cert_pin(cert)})
        return cfg
    if p['engine'] == 'backhaul':
        transport = p['transport']
        mappings = [f"{endpoint(d['entry_bind'], m['entry'])}={endpoint(d['target'], m['target'])}" for m in d['maps']]
        if role == 'server':
            return {
                'server': {
                    'bind_addr': endpoint(listen, d['port']),
                    'transport': transport,
                    'token': d['secret'],
                    'channel_size': 2048,
                    'keepalive': 60,
                    'nodelay': True,
                    'heartbeat': 20,
                    'ports': mappings,
                    **({'tls_cert': cert, 'tls_key': key} if transport in ('wss', 'wssmux') else {}),
                }
            }
        else:
            return {
                'client': {
                    'remote_addr': endpoint(remote, d['port']),
                    'transport': transport,
                    'token': d['secret'],
                    'connection_pool': max(1, min(d['pool'], 48)),
                    'nodelay': True,
                    'keepalive': 60,
                    'retry_interval': 1,
                }
            }
    if p['engine'] == 'gost':
        transport = p['transport'].split('+', 1)[1]
        auth = dict(username='tunnel', password=d['secret'])
        encrypted = transport in ('tls', 'wss', 'quic', 'grpc', 'h2', 'dtls')
        if role == 'server':
            listener = dict(type=transport)
            if encrypted:
                listener['tls'] = dict(certFile=cert, keyFile=key)
            if transport == 'dtls':
                listener['metadata'] = dict(mtu='1200', flightInterval='1000ms')  # gost dtls rejects zero defaults
            return dict(log=dict(level='warn'), services=[dict(name='tunnel', addr=endpoint(listen, d['port']),
                listener=listener, handler=dict(type='relay', auth=auth, metadata=dict(bind=direction == 'reverse')))])
        node = dict(name='peer', addr=endpoint(remote, d['port']), connector=dict(type='relay', auth=auth), dialer=dict(type=transport))
        if encrypted:
            node['dialer']['tls'] = dict(caFile=cert, serverName=d['server_name'], secure=True)
        if transport == 'dtls':
            node['dialer']['metadata'] = dict(mtu='1200', flightInterval='1000ms')
        if transport == 'grpc':
            node['dialer']['metadata'] = dict(host=d['server_name'])  # gRPC authority must match cert name, not dial IP
        services = []
        for m in d['maps']:
            for network in ('tcp', 'udp') if m['network'] == 'both' else (m['network'],):
                kind = ('r' if direction == 'reverse' else '') + network
                services.append(dict(name=f"entry-{m['entry']}-{network}", addr=endpoint(d['entry_bind'], m['entry']),
                    listener=dict(type=kind, **(dict(chain='tunnel') if direction == 'reverse' else {})),
                    handler=dict(type=kind, **(dict(chain='tunnel') if direction == 'direct' else {})),
                    forwarder=dict(nodes=[dict(name='backend', addr=endpoint(d['target'], m['target']))])))
        return dict(log=dict(level='warn'), services=services, chains=[dict(name='tunnel', hops=[dict(name='peer', nodes=[node])])])
    if p['engine'] == 'rathole':
        transport = dict(type=p['transport'])
        if p['transport'] == 'noise':
            transport['noise'] = dict(pattern='Noise_NN_25519_ChaChaPoly_BLAKE2s')
        elif p['transport'] == 'tls':
            if role == 'server':
                identity = directory / 'identity.p12'
                if not identity.exists():
                    run(['openssl', 'pkcs12', '-export', '-inkey', key, '-in', cert, '-out', identity, '-passout', 'pass:'])
                    identity.chmod(0o600)
                transport['tls'] = dict(pkcs12=str(identity), pkcs12_password='')
            else:
                transport['tls'] = dict(trusted_root=cert, hostname=d['server_name'])
        elif p['transport'] == 'websocket':
            transport['websocket'] = dict(tls=False)
        services = {}
        for m in d['maps']:
            for network in ('tcp', 'udp') if m['network'] == 'both' else (m['network'],):
                services[f"entry_{m['entry']}_{network}"] = dict(type=network, **({'bind_addr': endpoint(d['entry_bind'], m['entry'])} if role == 'server' else {'local_addr': endpoint(d['target'], m['target'])}))
        cfg = dict(default_token=d['secret'], transport=transport, services=services)
        cfg['bind_addr' if role == 'server' else 'remote_addr'] = endpoint(listen if role == 'server' else remote, d['port'])
        return {role: cfg}
    if p['engine'] != 'dagger':
        raise ValueError('No native configuration available for selected engine.')
    transport = p['transport']
    common = dict(mode=role, transport=transport, psk=d['secret'], log_level='info', profile_id=d['name'])
    if role == 'server':
        common['listeners'] = [dict(addr=endpoint(listen, d['port']), transport=transport,
            maps=[dict(bind=endpoint(d['entry_bind'], m['entry']), target=endpoint(d['target'], m['target'])) for m in d['maps']])]
        common['socks5'] = dict(enabled=False, bind='127.0.0.1:1080')
        if transport == 'wss':
            common['cert_file'], common['key_file'] = cert, key
        return common
    common['paths'] = [dict(transport=transport, addr=endpoint(remote, d['port']), connection_pool=d['pool'],
                            aggressive_pool=False, retry_interval=2, dial_timeout=10)]
    common['forwarders'] = [f"{m['entry']}:{d['target']}:{m['target']}/{m['network']}" for m in d['maps']]
    if transport == 'wss':
        common['tls'] = dict(insecure=False, server_name=d['server_name'], ca_file=cert)
    return common


def reliable_dtls_config(d, role, directory):
    """Keep DTLS on wire; KCP retransmits/reorders the inner relay stream."""
    cfg = make_config(d, role, directory)
    forbidden = {d['port'], d['adapter_port']} | {m[k] for m in d['maps'] for k in ('entry', 'target')}
    a = next_free_port(d['adapter_port'], forbidden)
    b = next_free_port(a, forbidden | {a})
    kcp = {'kcp.key': d['secret'], 'kcp.crypt': 'none', 'kcp.mtu': 1000,
           'kcp.nocomp': True, 'kcp.mode': 'fast', 'kcp.sndwnd': 256, 'kcp.rcvwnd': 256}
    if role == 'server':
        outer = cfg['services'][0]
        auth = outer['handler']['auth']
        outer['handler'] = dict(type='udp', chain='local-datagrams')
        cfg['chains'] = [dict(name='local-datagrams', hops=[dict(name='local', nodes=[
            dict(name='reliable-peer', addr=endpoint('127.0.0.1', b),
                 connector=dict(type='forward'), dialer=dict(type='udp'))])])]
        outer['forwarder'] = dict(nodes=[dict(name='reliable-peer', addr=endpoint('127.0.0.1', b))])
        cfg['services'].append(dict(name='reliable-relay', addr=endpoint('127.0.0.1', b),
            listener=dict(type='kcp', metadata=kcp),
            handler=dict(type='relay', auth=auth,
                         metadata=dict(bind=d.get('direction') == 'reverse'))))
    else:
        dtls = cfg['chains'][0]
        dtls['name'] = 'encrypted-datagrams'
        auth = dtls['hops'][0]['nodes'][0]['connector']['auth']
        dtls['hops'][0]['nodes'][0]['connector'] = dict(type='forward')
        cfg['chains'] = [dict(name='tunnel', hops=[dict(name='reliable-peer', nodes=[
            dict(name='peer', addr=endpoint('127.0.0.1', a),
                 connector=dict(type='relay', auth=auth),
                 dialer=dict(type='kcp', metadata=kcp))])]), dtls]
        cfg['services'].append(dict(name='encrypted-datagrams', addr=endpoint('127.0.0.1', a),
            listener=dict(type='udp', metadata=dict(keepalive=True, ttl='120s', readBufferSize=65535)),
            handler=dict(type='udp', chain='encrypted-datagrams'),
            forwarder=dict(nodes=[dict(name='reliable-peer', addr=endpoint('127.0.0.1', b))])))
    return cfg


def core_wrapped_bundle(d, role, directory):
    """Direct for reverse-only engines: engine listens abroad, Iran dials out; tuntunnel-core reverse rides on it."""
    iran, abroad = addresses(d)
    ap = d['adapter_port']
    forbidden = {d['port'], ap} | {m[k] for m in d['maps'] for k in ('entry', 'target')}
    cp = next_free_port(ap, forbidden)
    # engine in its native reverse orientation, endpoints swapped: listener on abroad, dialer on Iran
    inner = dict(d, direction='reverse', carrier='none', iran_ip=abroad, abroad_ip=iran, target='127.0.0.1',
                 entry_bind='127.0.0.1', maps=[dict(entry=ap, target=cp, network='tcp')])
    suffix = 'toml' if PROFILES[d['profile']]['engine'] in ('backhaul', 'rathole') else 'json'
    engine_item = dict(engine=PROFILES[d['profile']]['engine'], name=f'{role}.{suffix}', config=make_config(inner, role, directory))
    token = base64.b64encode(hashlib.sha256(('tuntunnel-core:' + d['secret']).encode()).digest()).decode()
    maps = [dict(entry=endpoint(d['entry_bind'], m['entry']), target=endpoint(d['target'], m['target'])) for m in d['maps']]
    if role == 'client':  # Iran: entries + core listener reached only through the engine
        core = dict(listen=endpoint('127.0.0.1', cp), connect=False, mode='reverse', token=token, maps=maps)
    else:  # abroad: core dials the engine-exposed loopback port, serves targets
        core = dict(peer=endpoint('127.0.0.1', ap), connect=True, mode='reverse', token=token, maps=maps)
    return [engine_item, dict(engine='tuntunnel-core', name='core.json', config=core)]


def config_bundle(d, role, directory):
    validate(d)
    p = PROFILES[d['profile']]
    engine = p['engine']
    if engine in CORE_WRAPPED and direction_for(d) == 'direct':
        return core_wrapped_bundle(d, role, directory)
    if not needs_adapter(d):
        suffix = 'toml' if engine in ('kariz', 'backhaul', 'rathole') else 'json'
        cfg = reliable_dtls_config(d, role, directory) if engine == 'gost' and p['transport'] == 'relay+dtls' else make_config(d, role, directory)
        return [dict(engine=engine, name=f'{role}.{suffix}', config=cfg,
                     **(dict(pin=GOST_DTLS_PIN) if engine == 'gost' and p['transport'].endswith('+dtls') else {}))]
    iran, abroad = addresses(d)
    ap = d.get('adapter_port', d['port'] + 1)
    if engine in ('sing-box', 'xray'):
        uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, d['secret']))
        if role == 'server':
            inner = dict(d, direction='direct', iran_ip=iran, abroad_ip=abroad, target='127.0.0.1',
                         entry_bind='127.0.0.1', maps=[dict(entry=ap, target=ap, network='both')])
            outer_cfg = make_config(inner, 'server', directory)
            listen = '::' if ':' in iran else '0.0.0.0'
            portal_cfg = dict(
                log=dict(loglevel='warning'),
                inbounds=[dict(tag='portal-in', listen='127.0.0.1', port=ap, protocol='vless',
                               settings=dict(clients=[dict(id=uid, reverse=dict(tag='portal'))], decryption='none'))]
                         + [dict(tag='entry' + str(m['entry']), listen=d['entry_bind'], port=m['entry'],
                                 protocol='dokodemo-door', settings=dict(address=d['target'], port=m['target'],
                                 network='tcp,udp' if m['network'] == 'both' else m['network'])) for m in d['maps']],
                outbounds=[dict(tag='blocked', protocol='blackhole')],
                routing=dict(rules=[dict(type='field', inboundTag=['entry' + str(m['entry']) for m in d['maps']], outboundTag='portal')]),
            )
            return [dict(engine=engine, name='server.json', config=outer_cfg),
                    dict(engine='xray', name='adapter.json', config=portal_cfg)]
        inner = dict(d, direction='direct', iran_ip=abroad, abroad_ip=iran, target='127.0.0.1',
                     entry_bind='127.0.0.1', maps=[dict(entry=ap, target=ap, network='both')])
        outer_cfg = make_config(inner, 'client', directory)
        bridge_cfg = dict(
            log=dict(loglevel='warning'),
            outbounds=[dict(tag='bridge-out', protocol='vless',
                            settings=dict(address='127.0.0.1', port=ap, id=uid, encryption='none', reverse=dict(tag='bridge'))),
                       dict(tag='backend', protocol='freedom', settings=dict(finalRules=[dict(action='allow'), dict(action='block')])),
                       dict(tag='blocked', protocol='blackhole')],
            routing=dict(rules=[dict(type='field', inboundTag=['bridge'], ip=[d['target']],
                                     port=','.join(str(m['target']) for m in d['maps']), outboundTag='backend'),
                                dict(type='field', inboundTag=['bridge'], outboundTag='blocked')]),
        )
        return [dict(engine=engine, name='client.json', config=outer_cfg),
                dict(engine='xray', name='adapter.json', config=bridge_cfg)]
    return [dict(engine=engine, name=f'{role}.json', config=make_config(d, role, directory))]


def device(d):
    return f"{d['carrier']}-{d['name'][:9]}"


def link_commands(d, role):
    validate(d)
    dev = device(d)
    is_iran = side_for(d, role) == 'iran'
    local = d['iran_ip'] if is_iran else d['abroad_ip']
    remote = d['abroad_ip'] if is_iran else d['iran_ip']
    try:
        r_out = subprocess.run(['ip', '-4', 'route', 'get', remote], capture_output=True, text=True, check=False).stdout
        m_src = re.search(r'src\s+([0-9.]+)', r_out)
        if m_src:
            local = m_src.group(1)
    except Exception:
        pass
    iran_addr, abroad_addr = addresses(d)
    addr = iran_addr if is_iran else abroad_addr
    prefix = ipaddress.ip_network(d['subnet'], strict=False).prefixlen
    if d['carrier'] == 'gre':
        create_cmd = ['ip', 'tunnel', 'add', dev, 'mode', 'gre', 'local', local, 'remote', remote, 'ttl', '255', 'key', str(d['link_id'])]
        mtu = '1472'
    elif d['carrier'] == 'ipip':
        create_cmd = ['ip', 'tunnel', 'add', dev, 'mode', 'ipip', 'local', local, 'remote', remote, 'ttl', '255']
        mtu = '1480'
    else:
        create_cmd = ['ip', 'link', 'add', dev, 'type', 'vxlan', 'id', str(d['link_id']), 'local', local, 'remote', remote, 'dstport', str(d['vxlan_port']), 'nolearning']
        mtu = '1450'
    return [create_cmd, ['ip', 'addr', 'replace', f'{addr}/{prefix}', 'dev', dev], ['ip', 'link', 'set', dev, 'mtu', mtu, 'up']]


def link_action(d, role, up=True):
    dev = device(d)
    if shutil.which('iptables'):
        run(['iptables', '-t', 'mangle', '-D', 'POSTROUTING', '-p', 'tcp',
             '--tcp-flags', 'SYN,RST', 'SYN', '-o', dev, '-j', 'TCPMSS', '--clamp-mss-to-pmtu'], check=False)
    run(['ip', 'link', 'del', dev], check=False)
    if up:
        for cmd in link_commands(d, role):
            run(cmd)
        if shutil.which('iptables'):
            run(['iptables', '-t', 'mangle', '-A', 'POSTROUTING', '-p', 'tcp',
                 '--tcp-flags', 'SYN,RST', 'SYN', '-o', dev, '-j', 'TCPMSS', '--clamp-mss-to-pmtu'], check=False)


def core_binary():
    """tuntunnel-core: local build first, else the checksummed asset of this tuntunnel release."""
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if not arch:
        raise RuntimeError('Unsupported CPU architecture.')
    target = BIN / f'tuntunnel-core-{VERSION}'
    if target.is_file() and os.access(target, os.X_OK):
        return target
    for cand in (_self_path().parent / '.tools' / 'tuntunnel-core', Path('/usr/local/bin/tuntunnel-core')):
        if cand.is_file() and os.access(cand, os.X_OK):
            BIN.mkdir(parents=True, exist_ok=True)
            shutil.copy2(cand, target)
            target.chmod(0o755)
            return target
    asset = f'tuntunnel-core-linux-{arch}'
    base = f'https://github.com/mahdiweb3/tuntunnel/releases/download/v{VERSION}'
    with urllib.request.urlopen(f'{base}/{asset}', timeout=120) as resp:
        blob = resp.read()
    with urllib.request.urlopen(f'{base}/SHA256SUMS', timeout=30) as resp:
        sums = resp.read(1024 * 1024).decode(errors='ignore')
    if not any(asset in line and hashlib.sha256(blob).hexdigest() in line.lower() for line in sums.splitlines()):
        raise RuntimeError('tuntunnel-core SHA-256 checksum mismatch.')
    BIN.mkdir(parents=True, exist_ok=True)
    pending = target.with_suffix('.pending')
    pending.write_bytes(blob)
    pending.chmod(0o755)
    os.replace(pending, target)
    return target


def download_engine(engine, pin=None):
    if engine == 'tuntunnel-core':
        return core_binary()
    if engine not in RELEASES:
        raise ValueError('Unknown engine.')
    if engine == 'backpack' and Path('/usr/local/bin/backpack').exists():
        return Path('/usr/local/bin/backpack')
    if engine == 'kariz':
        for cand in [Path('/usr/local/bin/kariz'), BIN / 'kariz']:
            if cand.exists():
                return cand
    if engine == 'backhaul':
        for cand in [Path('/usr/local/bin/backhaul'), BIN / 'backhaul']:
            if cand.exists():
                return cand
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if not arch:
        raise RuntimeError('Unsupported CPU architecture.')
    repo, tag = RELEASES[engine]
    tag = pin or tag
    target = BIN / f'{engine}-{tag}'
    if target.is_file() and os.access(target, os.X_OK):
        return target
    local_candidates = [
        _self_path().parent / '.tools' / ('DaggerLauncher' if engine == 'dagger' else engine),
        Path('/usr/local/bin') / ('DaggerConnect' if engine == 'dagger' else engine),
    ]
    for cand in ([] if pin else local_candidates):
        if cand.is_file() and os.access(cand, os.X_OK):
            BIN.mkdir(parents=True, exist_ok=True)
            shutil.copy2(cand, target)
            target.chmod(0o755)
            return target
    version = tag.lstrip('v')
    if engine == 'sing-box':
        asset, member = f'sing-box-{version}-linux-{arch}.tar.gz', f'sing-box-{version}-linux-{arch}/sing-box'
    elif engine == 'xray':
        xarch = '64' if arch == 'amd64' else 'arm64-v8a'
        asset, member = f'Xray-linux-{xarch}.zip', 'xray'
    elif engine == 'backpack':
        asset, member = f'backpack_linux_{arch}.tar.gz', 'backpack'
    elif engine == 'kariz':
        cpu = 'x86_64' if arch == 'amd64' else 'aarch64'
        asset, member = f'kariz-{tag}-{cpu}-linux.tar.gz', 'kariz'
    elif engine == 'backhaul':
        asset, member = f'backhaul_linux_{arch}.tar.gz', 'backhaul'
    elif engine == 'gost':
        asset, member = f'gost_{version}_linux_{arch}.tar.gz', 'gost'
    elif engine == 'rathole':
        cpu = 'x86_64-unknown-linux-gnu' if arch == 'amd64' else 'aarch64-unknown-linux-musl'
        asset, member = f'rathole-{cpu}.zip', 'rathole'
    else:
        if arch != 'amd64':
            raise RuntimeError('Dagger release supplies no verified ARM64 binary.')
        asset = member = 'DaggerLauncher'
    base = f'https://github.com/{repo}/releases/download/{tag}'
    BIN.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='te-dl-') as temp:
        temp_dir = Path(temp)
        pkg = temp_dir / asset
        with urllib.request.urlopen(f'{base}/{asset}', timeout=120) as resp:
            pkg.write_bytes(resp.read())
        for sums_name in (f'{asset}.sha256', 'checksums.txt', f'{asset}.dgst', 'SHA256SUMS'):
            try:
                with urllib.request.urlopen(f'{base}/{sums_name}', timeout=30) as resp:
                    text = resp.read().decode(errors='ignore')
                digest = hashlib.sha256(pkg.read_bytes()).hexdigest().lower()
                relevant = [line for line in text.splitlines() if asset in line] if sums_name in ('checksums.txt', 'SHA256SUMS') else text.splitlines()
                found = [m.group(0).lower() for line in relevant for m in re.finditer(r'\b[a-fA-F0-9]{64}\b', line)]
                if not found or digest not in found:
                    raise RuntimeError('Downloaded binary SHA-256 checksum mismatch.')
                break
            except urllib.error.URLError:
                continue
        staged = temp_dir / 'engine'
        if asset.endswith('.tar.gz'):
            with tarfile.open(pkg, 'r:gz') as tar:
                candidates = [m for m in tar.getmembers() if m.isfile() and (m.name == member or Path(m.name).name == Path(member).name)]
                if len(candidates) != 1:
                    raise RuntimeError('Release archive has no unique engine binary.')
                with tar.extractfile(candidates[0]) as source, staged.open('wb') as dest:
                    shutil.copyfileobj(source, dest)
        elif asset.endswith('.zip'):
            with zipfile.ZipFile(pkg) as zf:
                with zf.open(member) as source, staged.open('wb') as dest:
                    shutil.copyfileobj(source, dest)
        else:
            shutil.copy2(pkg, staged)
        if not staged.stat().st_size:
            raise RuntimeError('Release contains an empty engine binary.')
        staged.chmod(0o755)
        pending = target.with_suffix('.pending')
        try:
            shutil.copy2(staged, pending)
            os.replace(pending, target)
        finally:
            pending.unlink(missing_ok=True)
    return target


NATIVE_CHECK = ('sing-box', 'xray', 'kariz', 'tuntunnel-core')


def check_config(engine, binary, config):
    # ponytail: only sing-box/xray/kariz ship a config checker; the rest are proven by the startup/transfer tests
    if engine in NATIVE_CHECK:
        run(engine_argv(engine, binary, config, check=True))


def engine_argv(engine, binary, config, check=False):
    if engine == 'tuntunnel-core':
        return [binary, '-check' if check else '-config', config]
    if engine not in RELEASES:
        raise ValueError('Unknown engine.')
    if check and engine not in NATIVE_CHECK:
        raise RuntimeError(f'{engine} has no native config-check command; use an isolated startup/transfer test.')
    if engine == 'sing-box':
        return [binary, 'check' if check else 'run', '-c', config]
    if engine == 'xray':
        return [binary, 'run', '-test', '-config', config] if check else [binary, 'run', '-config', config]
    if engine == 'backpack':
        cfg_p = Path(config)
        if cfg_p.exists():
            txt = cfg_p.read_text().lstrip()
            if txt.startswith('{'):
                c = json.loads(txt)
                sec = c.pop('role', 'server')
                lines = [f'[{sec}]'] + [f'{k} = {json.dumps(v)}' for k, v in c.items()]
                toml_p = cfg_p.with_suffix('.toml')
                toml_p.write_text('\n'.join(lines) + '\n')
                os.chmod(toml_p, 0o600)
                config = toml_p
        return [binary, '-v'] if check else [binary, '-c', config]
    if engine == 'kariz':
        cfg_p = Path(config)
        if cfg_p.exists():
            txt = cfg_p.read_text().lstrip()
            if txt.startswith('{'):
                c = json.loads(txt)
                lines = [f'role = {json.dumps(c["role"])}', f'mode = {json.dumps(c["mode"])}', f'profile = {json.dumps(c["profile"])}', '']
                lines.append('[tunnel]')
                # TOML: scalars before sub-tables, else they land inside [tunnel.x]
                items = sorted(c['tunnel'].items(), key=lambda kv: isinstance(kv[1], dict))
                for k, v in items:
                    if isinstance(v, dict):
                        lines.append(f'[tunnel.{k}]')
                        for k2, v2 in v.items():
                            lines.append(f'{k2} = {json.dumps(v2)}')
                    else:
                        lines.append(f'{k} = {json.dumps(v)}')
                if 'forwards' in c:
                    for fwd in c['forwards']:
                        lines.append('[[forward]]')
                        for k, v in fwd.items():
                            lines.append(f'{k} = {json.dumps(v)}')
                lines.append('[log]')
                lines.append(f'level = {json.dumps(c["log"]["level"])}')
                toml_p = cfg_p.with_suffix('.toml')
                toml_p.write_text('\n'.join(lines) + '\n')
                os.chmod(toml_p, 0o600)
                config = toml_p
        return [binary, 'check', '-c', config] if check else [binary, 'run', '-c', config]
    if engine == 'backhaul':
        cfg_p = Path(config)
        if cfg_p.exists():
            txt = cfg_p.read_text().lstrip()
            if txt.startswith('{'):
                c = json.loads(txt)
                sec = 'server' if 'server' in c else 'client'
                data = c[sec]
                lines = [f'[{sec}]']
                for k, v in data.items():
                    lines.append(f'{k} = {json.dumps(v)}')
                toml_p = cfg_p.with_suffix('.toml')
                toml_p.write_text('\n'.join(lines) + '\n')
                os.chmod(toml_p, 0o600)
                config = toml_p
        return [binary, '-v'] if check else [binary, '-c', config]
    if engine == 'rathole':
        cfg_p = Path(config)
        if cfg_p.read_text().lstrip().startswith('{'):
            c = json.loads(cfg_p.read_text())
            lines = []
            def table(values, path):
                lines.append('[' + '.'.join(path) + ']')
                lines.extend(f'{k} = {json.dumps(v)}' for k, v in values.items() if not isinstance(v, dict))
                for k, v in values.items():
                    if isinstance(v, dict):
                        table(v, path + [k])
            for k, v in c.items():
                table(v, [k])
            cfg_p = cfg_p.with_suffix('.toml')
            write(cfg_p, '\n'.join(lines) + '\n')
            config = cfg_p
        return [binary, config]
    if engine == 'dagger':
        return [binary, '-c', config]
    return [binary, '-C', config]


def stage_bundle(d, role, directory):
    commands = []
    primary = None
    for item in config_bundle(d, role, directory):
        binary = download_engine(item['engine'], pin=item.get('pin'))
        primary = primary or binary
        cfg = directory / item['name']
        write(cfg, json.dumps(item['config'], indent=2) if isinstance(item['config'], dict) else item['config'])
        argv = engine_argv(item['engine'], binary, cfg)
        check_config(item['engine'], binary, Path(argv[-1]))
        commands.append([str(x) for x in argv])
    write(directory / 'bundle.json', json.dumps(commands))
    runner = globals().get('BUNDLE_RUNNER_SOURCE')
    if runner is None:
        for cand in (_self_path().with_name('bundle_runner.py'), SELF.with_name('bundle_runner.py')):
            if cand.exists():
                runner = cand.read_text()
                break
    if runner is None:
        raise FileNotFoundError('bundle_runner.py not bundled or found beside tuntunnel')
    write(directory / 'bundle_runner.py', runner)
    return primary


def root_required():
    if os.geteuid() != 0:
        raise RuntimeError('Root privileges are required for installation and service management.')


def prerequisites():
    missing = [tool for tool in ('ip', 'openssl', 'systemctl') if not shutil.which(tool)]
    if not missing:
        return
    if 'systemctl' in missing:
        raise RuntimeError('systemd is required for tunnel management.')
    root_required()
    packages = [('iproute2' if tool == 'ip' else tool) for tool in missing]
    if shutil.which('apt-get'):
        run(['apt-get', 'update'], timeout=180)
        run(['apt-get', 'install', '-y', *packages], timeout=300)
    elif shutil.which('dnf'):
        run(['dnf', 'install', '-y', *['iproute' if p == 'iproute2' else p for p in packages]], timeout=300)
    else:
        raise RuntimeError('Missing required tools: ' + ', '.join(missing))


def install_manager():
    source = os.environ.get('TE_SOURCE', '')
    if source and Path(source).is_file():
        SELF.parent.mkdir(parents=True, exist_ok=True)
        if Path(source).resolve() != SELF.resolve():
            shutil.copy2(source, SELF)
            SELF.chmod(0o755)
        for alias in (Path('/usr/local/bin/tunnel-extra'), Path('/usr/local/bin/tuntunnel')):
            if alias.is_symlink() or alias.exists():
                alias.unlink()
            alias.symlink_to(SELF)


def unit_name(name, link=False, adapter=False):
    if link:
        return f'tunnel-extra-link-{name}.service'
    if adapter:
        return f'tunnel-extra-adapter-{name}.service'
    return f'tunnel-extra-{name}.service'


def install(d, role, staged, binary):
    root_required()
    prerequisites()
    folder = ROOT / 'tunnels' / d['name']
    names = [unit_name(d['name'], adapter=True), unit_name(d['name']), unit_name(d['name'], link=True)]
    previous_units = {name: (UNITS / name).read_bytes() if (UNITS / name).exists() else None for name in names}
    active = {name: run(['systemctl', 'is-active', '--quiet', name], check=False).returncode == 0 for name in names}
    enabled = {name: run(['systemctl', 'is-enabled', '--quiet', name], check=False).returncode == 0 for name in names}
    with tempfile.TemporaryDirectory(prefix='te-rollback-') as tmp:
        saved = Path(tmp) / 'tunnel'
        if folder.exists():
            shutil.copytree(folder, saved)
        try:
            for name in names:
                if previous_units[name] is not None:
                    run(['systemctl', 'stop', name], check=False)
            _install(d, role, staged, binary)
            for name in names:
                if name not in {unit_name(d['name']),
                                unit_name(d['name'], adapter=True) if (folder / 'adapter.json').exists() and not (folder / 'bundle.json').exists() else '',
                                unit_name(d['name'], link=True) if d['carrier'] != 'none' else ''}:
                    run(['systemctl', 'disable', name], check=False)
                    (UNITS / name).unlink(missing_ok=True)
            run(['systemctl', 'daemon-reload'])
        except BaseException:
            for name in names:
                run(['systemctl', 'stop', name], check=False)
                run(['systemctl', 'disable', name], check=False)
            if d['carrier'] != 'none':
                link_action(d, role, up=False)
            if folder.exists():
                shutil.rmtree(folder)
            if saved.exists():
                shutil.copytree(saved, folder)
            for name, content in previous_units.items():
                path = UNITS / name
                if content is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_bytes(content)
            run(['systemctl', 'daemon-reload'], check=False)
            for name in names:
                if enabled[name]:
                    run(['systemctl', 'enable', name], check=False)
            for name in reversed(names):
                if active[name]:
                    run(['systemctl', 'start', name], check=False)
            raise


def _install(d, role, staged, binary):
    root_required()
    install_manager()
    folder = ROOT / 'tunnels' / d['name']
    if folder.exists():
        shutil.rmtree(folder)
    folder.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(staged), str(folder))
    folder.chmod(0o700)
    for f in folder.glob('*.json'):
        txt = f.read_text()
        if str(staged) in txt:
            write(f, txt.replace(str(staged), str(folder)))
    for f in folder.glob('*.toml'):
        txt = f.read_text()
        if str(staged) in txt:
            write(f, txt.replace(str(staged), str(folder)))
    engine = PROFILES[d['profile']]['engine']
    units = []
    if d['carrier'] != 'none':
        link_action(d, role, up=True)
        link_unit = UNITS / unit_name(d['name'], link=True)
        write(link_unit, f'''[Unit]
Description=Tunnel Extra Link {d['name']}
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={SELF} link-up {shlex.quote(d['name'])} --role {role}
ExecStop={SELF} link-down {shlex.quote(d['name'])} --role {role}

[Install]
WantedBy=multi-user.target
''', 0o644)
        units.append(link_unit.name)
    after = 'network-online.target' + (f' {units[0]}' if units else '')
    requires = f'Requires={units[0]}\n' if units else ''
    bundled = (folder / 'bundle.json').exists()
    if bundled:
        py_bin = shutil.which('python3', path='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin') or sys.executable
        command = ' '.join(shlex.quote(str(x)) for x in
                           (py_bin, folder / 'bundle_runner.py', folder / 'bundle.json'))
    else:
        command = ' '.join(shlex.quote(str(x)) for x in engine_argv(engine, binary, folder / f'{role}.json'))
    service = UNITS / unit_name(d['name'])
    write(service, f'''[Unit]
Description=Tunnel Extra {d['name']} ({d['profile']} {role})
After={after}
Wants=network-online.target
{requires}[Service]
Type=simple
UMask=0077
WorkingDirectory={folder}
ExecStart={command}
Restart=always
RestartSec=2
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
''', 0o644)
    units.append(service.name)
    if (folder / 'adapter.json').exists() and not bundled:
        abinary = download_engine('xray')
        acommand = ' '.join(shlex.quote(str(x)) for x in engine_argv('xray', abinary, folder / 'adapter.json'))
        aservice = UNITS / unit_name(d['name'], adapter=True)
        write(aservice, f'''[Unit]
Description=Tunnel Extra Reverse Adapter {d['name']}
After={service.name}
Requires={service.name}

[Service]
Type=simple
UMask=0077
WorkingDirectory={folder}
ExecStart={acommand}
Restart=always
RestartSec=2
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
''', 0o644)
        units.append(aservice.name)
    run(['systemctl', 'daemon-reload'])
    for item in units:
        run(['systemctl', 'enable', '--now', item])
    for item in units:
        run(['systemctl', 'is-active', '--quiet', item])


def load(name):
    name_ok(name)
    path = ROOT / 'tunnels' / name / 'pair.json'
    if not path.exists():
        raise ValueError('Tunnel not found.')
    return json.loads(path.read_text())


def show(d, role):
    iran, abroad = addresses(d)
    direction = d.get('direction', 'direct')
    here_side = side_for(d, role)
    peer_side = 'abroad' if here_side == 'iran' else 'iran'
    peer_label = 'Kharej (Abroad Server)' if peer_side == 'abroad' else 'Iran Server'
    link = setup_link(d)
    print(f"\nTunnel: {d['name']} | Profile: {d['profile']} ({PROFILES[d['profile']]['engine']}) | Direction: {direction} | Role: {role}")
    print(f"Carrier: {d['carrier']} | Endpoints: {iran} <-> {abroad}:{d['port']}")
    for m in d['maps']:
        print(f"Forward: {d['entry_bind']}:{m['entry']} -> {d['target']}:{m['target']} ({m['network']})")
    print(f'Service: {unit_name(d["name"])} (active)')
    if here_side == 'iran':
        print('\nForeign setup link (contains credentials; share privately):\n' + link)
    else:
        print('\nForeign configuration ready. No setup link here; paste the Iran link on this server.')


def confirm_install(yes):
    if yes:
        return
    answer = input('Install and start systemd service now? [y/N]: ').strip().lower()
    if answer not in ('y', 'yes'):
        raise RuntimeError('Cancelled by user.')


def create(args):
    if args.iran_ip == args.abroad_ip and not ipaddress.ip_address(args.iran_ip).is_loopback:
        raise ValueError('Iran IP and Foreign IP must not be identical.')
    maps = parse_maps(args.maps, 'tcp' if PROFILES[args.profile]['engine'] == 'dagger' else args.network)
    direction = getattr(args, 'direction', None)
    data = new_pair(args.name, args.profile, args.iran_ip, args.abroad_ip, args.tunnel_port, maps,
                    carrier=args.carrier, subnet=args.subnet, direction=direction)
    for field in ('entry_bind', 'target', 'server_name', 'camouflage', 'pool', 'mtu', 'link_id', 'vxlan_port',
                  'adapter_port', 'iran_private', 'abroad_private'):
        value = getattr(args, field, None)
        if value is not None:
            data[field] = value
    validate(data)
    if args.side != 'iran':
        raise ValueError('Create runs on the Iran server only. On the Foreign server run: tuntunnel join --code <Iran link>')
    role = args.role if args.role != 'auto' else ('server' if side_for(data, 'server') == args.side else 'client')
    if args.dry_run:
        print(setup_link(data))
        return
    confirm_install(args.yes)
    with tempfile.TemporaryDirectory(prefix='te-stage-') as temp:
        staged = Path(temp) / data['name']
        staged.mkdir(mode=0o700)
        make_certificate(staged)
        data['certificate'] = (staged / 'cert.pem').read_text()
        data['key'] = (staged / 'key.pem').read_text()
        write(staged / 'pair.json', json.dumps(dict(data, role=role), indent=2))
        install(data, role, staged, stage_bundle(data, role, staged))
    show(data, role)


def join(args):
    data = decode_code(args.code)
    if args.name:
        data['name'] = name_ok(args.name)
    role = args.role if args.role != 'auto' else ('server' if side_for(data, 'server') == args.side else 'client')
    if args.dry_run:
        print(json.dumps(dict(data, role=role), indent=2))
        return
    confirm_install(args.yes)
    with tempfile.TemporaryDirectory(prefix='te-stage-') as temp:
        staged = Path(temp) / data['name']
        staged.mkdir(mode=0o700)
        if role == 'server':
            if data.get('key'):
                write(staged / 'key.pem', data['key'])
                write(staged / 'cert.pem', data['certificate'])
            else:
                make_certificate(staged)
                data['certificate'] = (staged / 'cert.pem').read_text()
                data['key'] = (staged / 'key.pem').read_text()
        else:
            write(staged / 'cert.pem', data['certificate'])
            if data.get('key'):
                write(staged / 'key.pem', data['key'])
        write(staged / 'pair.json', json.dumps(dict(data, role=role), indent=2))
        install(data, role, staged, stage_bundle(data, role, staged))
    show(data, role)


def show_system_header():
    host = socket.gethostname()
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine(), platform.machine())
    distro = 'linux'
    try:
        for line in Path('/etc/os-release').read_text().splitlines():
            if line.startswith('PRETTY_NAME='):
                distro = line.split('=', 1)[1].strip('"')
                break
    except Exception:
        pass
    pub_v4 = '-'
    priv_ips = []
    try:
        out = subprocess.run(['ip', '-4', '-o', 'addr', 'show'], capture_output=True, text=True, check=False).stdout or ''
        for m_ip in re.finditer(r'\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/\d+', out):
            ifname, ip_s = m_ip.group(1), m_ip.group(2)
            if ifname == 'lo' or ip_s.startswith('127.'):
                continue
            ip_obj = ipaddress.ip_address(ip_s)
            if ip_obj.is_private:
                priv_ips.append(f'{ip_s} ({ifname})')
            elif pub_v4 == '-':
                pub_v4 = ip_s
    except Exception:
        pass
    cores = []
    for c in ('backpack', 'sing-box', 'xray'):
        found = bool(shutil.which(c) or Path(f'/usr/local/bin/{c}').exists() or (BIN.exists() and any(BIN.glob(f'{c}*'))))
        cores.append(f'{C_GREEN}{c}:✓{C_RST}' if found else f'{C_YELLOW}{c}:✗{C_RST}')
    items = all_tunnels()
    active_cnt = sum(1 for d in items if subprocess.run(['systemctl', 'is-active', unit_name(d['name'])], capture_output=True, text=True, check=False).stdout.strip() == 'active')
    priv_str = ', '.join(priv_ips[:2]) if priv_ips else '-'
    print(f'\n{BANNER}')
    print(B_LINE)
    print(f'  {B_SOFT}Host     :{C_RST} {C_WHITE}{host}{C_RST}  {C_DIM}({distro} • linux/{arch}){C_RST}')
    print(f'  {B_SOFT}Network  :{C_RST} {B_BRIGHT}IPv4:{C_RST} {pub_v4} {B_MAIN}|{C_RST} {B_BRIGHT}Private:{C_RST} {priv_str}')
    print(f'  {B_SOFT}Status   :{C_RST} {B_BRIGHT}Cores:{C_RST} {" ".join(cores)} {B_MAIN}|{C_RST} {B_BRIGHT}Active Tunnels:{C_RST} {C_GREEN if active_cnt else C_WHITE}{active_cnt}/{len(items)}{C_RST}')
    print(B_LINE)


def prompt(label, default=None, validator=None, allow_back=True):
    suffix = f' {B_SOFT}[{default}]{C_RST}' if default not in (None, '') else ''
    while True:
        try:
            raw = input(f'  {B_BRIGHT}• {label}{C_RST}{suffix}{B_BRIGHT}:{C_RST} ').strip()
        except EOFError:
            if default not in (None, ''):
                raw = str(default)
            else:
                raise Back()
        if allow_back and raw.lower() in ('b', 'back', '0'):
            raise Back()
        if not raw and default not in (None, ''):
            raw = str(default)
        if not raw:
            print(f'  {C_RED}Invalid value: input cannot be empty. Type 0 or b to go back.{C_RST}')
            continue
        if validator:
            try:
                return validator(raw)
            except Exception as exc:
                print(f'  {C_RED}Invalid value: {exc}{C_RST}')
                continue
        return raw


def choose(title, options, default=None, allow_back=True, exit_label='Back', allow_link=False):
    print(f'\n{B_LINE}')
    print(f'  {B_BRIGHT}◆ {title}{C_RST}')
    print(B_LINE)
    for idx, (_, text) in enumerate(options, 1):
        print(f'  {B_BRIGHT}[{idx}]{C_RST} {B_CYAN}•{C_RST} {C_WHITE}{text}{C_RST}')
    if allow_back:
        print(f'\n  {C_RED}[0]{C_RST} {B_CYAN}•{C_RST} \033[38;5;252m{exit_label}{C_RST}')
    print(B_LINE)
    valid_keys = {str(i): k for i, (k, _) in enumerate(options, 1)}
    for k, _ in options:
        valid_keys[str(k).lower()] = k
    suffix = f' {B_SOFT}[{default}]{C_RST}' if default not in (None, '') else ''
    while True:
        try:
            raw = input(f'  {B_BRIGHT}Select an option{C_RST}{suffix}{B_BRIGHT}:{C_RST} ').strip()
        except EOFError:
            raise Back()
        if not raw and default not in (None, ''):
            raw = str(default)
        clean = raw.strip("'\"")
        if allow_link and clean.startswith(('tuntunnel://', 'TE1:')):
            return ('__link__', clean)
        low = raw.lower()
        if allow_back and low in ('0', 'b', 'back', 'exit', 'q', 'quit'):
            raise Back()
        if low in valid_keys:
            return valid_keys[low]
        print(f'  {C_RED}Invalid value. Please select a valid option number or 0 to go back.{C_RST}')


def valid_ip(val):
    return str(ipaddress.ip_address(val.strip()))


def valid_subnet(val):
    net = ipaddress.ip_network(val.strip(), strict=False)
    if net.version != 4 or net.prefixlen > 30 or not net.is_private:
        raise ValueError('Private IPv4 /30 (or larger) subnet is required.')
    return str(net)


def valid_pool(val):
    n = int(val)
    if not 1 <= n <= 256:
        raise ValueError('Pool size must be between 1 and 256.')
    return n


def valid_link_id(val):
    n = int(val)
    if not 1 <= n <= 16777215:
        raise ValueError('Link ID / VNI must be between 1 and 16777215.')
    return n


BENCH_ZLIB_B64 = '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'


def find_best_tunnel_wizard():
    here = Path(os.environ.get('TE_SOURCE', str(SELF))).resolve().parent
    candidates = (here / 'tunnel_bench.py', SELF.parent / 'tunnel_bench.py', Path('/root/tunnel-bench/tunnel_bench.py'))
    bench_py = next((p for p in candidates if p.exists()), None)
    src = bench_py.read_text() if bench_py else zlib.decompress(base64.b64decode(BENCH_ZLIB_B64)).decode()
    ns = {'__name__': '__bench__', '__file__': str(bench_py or SELF)}
    exec(compile(src, 'tunnel_bench.py', 'exec'), ns)
    old_argv, old_subprocess = sys.argv[:], os.environ.get('TE_SUBPROCESS')
    os.environ['TE_SUBPROCESS'] = '1'
    try: sys.argv = ['tunnel-bench']; ns['main']()
    except (SystemExit, KeyboardInterrupt): pass
    finally:
        sys.argv = old_argv
        if old_subprocess is None:
            os.environ.pop('TE_SUBPROCESS', None)
        else:
            os.environ['TE_SUBPROCESS'] = old_subprocess


def configure_tunnel_wizard():
    state = {}
    step = 0
    while step >= 0:
        try:
            if step == 0:
                res = choose('Server Location (Iran or Foreign — or paste tuntunnel:// setup link)', [
                    ('iran', 'Iran Server'),
                    ('abroad', 'Abroad / Foreign Server'),
                ], default='2', allow_link=True)
                if isinstance(res, tuple) and res[0] == '__link__':
                    join(argparse.Namespace(code=res[1], side='abroad', role='auto', name=None, dry_run=False, yes=False))
                    return
                state['side'] = res
                state['mode'] = 'create' if res == 'iran' else 'join'
                step = 1 if res == 'iran' else 4
            elif step == 1:
                res = choose('Tunnel Direction (Reverse or Direct — or paste tuntunnel:// setup link)', [
                    ('reverse', 'Reverse Tunnel (Foreign dials Iran)'),
                    ('direct', 'Direct Tunnel (Iran dials Foreign)'),
                ], default='1', allow_link=True)
                if isinstance(res, tuple) and res[0] == '__link__':
                    join(argparse.Namespace(code=res[1], side='abroad', role='auto', name=None, dry_run=False, yes=False))
                    return
                state['direction'] = res
                step = 2
            elif step == 2:
                opts = [(k, f"{k} ({v['engine']})") for k, v in PROFILES.items()]
                res = choose('Select Transport Method (All Transports — or paste tuntunnel:// setup link)', opts, default='1', allow_link=True)
                if isinstance(res, tuple) and res[0] == '__link__':
                    join(argparse.Namespace(code=res[1], side='abroad', role='auto', name=None, dry_run=False, yes=False))
                    return
                state['profile'] = res
                step = 4
            elif step == 3:
                res = choose('Abroad Server Setup', [
                    ('join', 'Set up from a link (Paste tuntunnel:// or TE1: link)'),
                    ('create', 'Manual configuration (Direction, transport, IPs, ports)'),
                ], default='1', allow_link=True)
                if isinstance(res, tuple) and res[0] == '__link__':
                    join(argparse.Namespace(code=res[1], side='abroad', role='auto', name=None, dry_run=False, yes=False))
                    return
                state['mode'] = res
                step = 4 if res == 'join' else 1
            elif step == 4:
                if state['mode'] == 'join':
                    code = prompt('Setup Link (tuntunnel://... or TE1:...)')
                    name = prompt('Local tunnel name (leave default to keep link name)', 'keep')
                    join(argparse.Namespace(code=code, side=state['side'], role='auto',
                                            name=None if name == 'keep' else name, dry_run=False, yes=False))
                    return
                state['name'] = prompt('Tunnel name', 'main', validator=name_ok)
                step = 5
            elif step == 5:
                state['iran_ip'] = prompt('Iran Server IP', state.get('iran_ip'), validator=valid_ip)
                step = 6
            elif step == 6:
                def check_abroad(v):
                    ip = valid_ip(v)
                    if ip == state.get('iran_ip'):
                        raise ValueError('Foreign IP must differ from Iran IP.')
                    return ip
                state['abroad_ip'] = prompt('Foreign Server IP', state.get('abroad_ip'), validator=check_abroad)
                step = 7
            elif step == 7:
                state['tunnel_port'] = prompt('Tunnel port', state.get('tunnel_port', 30443), validator=port)
                step = 8
            elif step == 8:
                eng = PROFILES[state['profile']]['engine']
                net_default = 'tcp' if eng == 'dagger' else 'both'
                raw_maps = prompt('Port mappings (entry=target, e.g. 443=443,2053=2053)', state.get('raw_maps', '443=443'))
                parse_maps(raw_maps, net_default)
                state['raw_maps'] = raw_maps
                state['network'] = net_default
                step = 9
            elif step == 9:
                state['carrier'] = choose('Private Overlay Carrier', [
                    ('none', 'None (Direct over server IPs)'),
                    ('gre', 'GRE Private Network'),
                    ('vxlan', 'VXLAN Private Network'),
                    ('ipip', 'IPIP Private Network'),
                ], default='1')
                step = 10
            elif step == 10:
                subnet = '10.203.88.0/30'
                link_id = 100
                vxlan_port = 4789
                if state['carrier'] != 'none':
                    subnet = prompt('Private /30 subnet', '10.203.88.0/30', validator=valid_subnet)
                    link_id = prompt('GRE key / VXLAN VNI', '100', validator=valid_link_id)
                    if state['carrier'] == 'vxlan':
                        vxlan_port = prompt('VXLAN UDP port', '4789', validator=port)
                create(argparse.Namespace(
                    name=state['name'], profile=state['profile'], direction=state['direction'],
                    iran_ip=state['iran_ip'], abroad_ip=state['abroad_ip'], tunnel_port=state['tunnel_port'],
                    maps=state['raw_maps'], network=state['network'], target='127.0.0.1', entry_bind='0.0.0.0',
                    pool=48, carrier=state['carrier'], subnet=subnet, link_id=link_id, vxlan_port=vxlan_port,
                    side=state['side'], role='auto', dry_run=False, yes=False
                ))
                return
        except Back:
            step = {3: 0, 1: 0, 4: 0 if state.get('mode') == 'join' else 2}.get(step, step - 1)


def saved_networks():
    records = []
    for path in sorted((ROOT / 'networks').glob('*.json')):
        data = json.loads(path.read_text())
        if name_ok(data['name']) != path.stem or data['carrier'] not in ('gre', 'vxlan', 'ipip'):
            raise ValueError(f'Invalid network record: {path.name}')
        records.append(data)
    return records


def list_networks():
    records = saved_networks()
    print('\nNetworks Created by TunTunnel (this host)')
    print(f'{"Name":<20} {"Type":<7} {"Interface":<16} {"Subnet":<19} Status')
    for data in records:
        status = run(['ip', 'link', 'show', 'dev', device(data)], check=False)
        print(f'{data["name"]:<20} {data["carrier"].upper():<7} {device(data):<16} {data["subnet"]:<19} {"Present" if status.returncode == 0 else "Missing"}')
    if not records:
        print('No saved networks. Networks created before tracking was added are not included.')
    return records


def delete_network():
    records = list_networks()
    if not records:
        return
    name = choose('Delete Network', [(d['name'], f"{d['name']} ({device(d)})") for d in records])
    data = next(d for d in records if d['name'] == name)
    if any(d.get('carrier') != 'none' and device(d) == device(data) for d in all_tunnels()):
        raise RuntimeError('Network is used by a configured tunnel. Remove that tunnel first.')
    if prompt(f'Delete {name} on this host only? [y/N]', 'n').lower() not in ('y', 'yes'):
        print('Deletion cancelled.')
        return
    root_required()
    if run(['ip', 'link', 'show', 'dev', device(data)], check=False).returncode == 0:
        run(['ip', 'link', 'del', 'dev', device(data)])
    (ROOT / 'networks' / f'{name}.json').unlink()
    print(f'Network {name} deleted on this host. Peer host is unchanged.')


def create_network_wizard():
    state = {}
    step = 0
    while step >= 0:
        try:
            if step == 0:
                state['carrier'] = choose('Private Network Management', [
                    ('gre', 'GRE Point-to-Point Tunnel'),
                    ('vxlan', 'VXLAN Overlay Network'),
                    ('ipip', 'IPIP Point-to-Point Tunnel'),
                    ('list', 'List Networks'),
                    ('delete', 'Delete Network'),
                ], default='1')
                if state['carrier'] == 'list':
                    list_networks()
                    continue
                if state['carrier'] == 'delete':
                    delete_network()
                    continue
                step = 1
            elif step == 1:
                state['side'] = choose('Current Server Location', [
                    ('iran', 'Iran Server (1st host in subnet)'),
                    ('abroad', 'Foreign Server (2nd host in subnet)'),
                ], default='1')
                step = 2
            elif step == 2:
                state['name'] = prompt('Network name', 'net1', validator=name_ok)
                step = 3
            elif step == 3:
                state['iran_ip'] = prompt('Iran public IP', state.get('iran_ip'), validator=valid_ip)
                step = 4
            elif step == 4:
                def check_abroad(v):
                    ip = valid_ip(v)
                    if ip == state.get('iran_ip'):
                        raise ValueError('Foreign IP must differ from Iran IP.')
                    return ip
                state['abroad_ip'] = prompt('Foreign public IP', state.get('abroad_ip'), validator=check_abroad)
                step = 5
            elif step == 5:
                state['subnet'] = prompt('Private IPv4 /30 subnet', state.get('subnet', '10.203.88.0/30'), validator=valid_subnet)
                step = 6
            elif step == 6:
                state['link_id'] = prompt('Tunnel Key / VNI', state.get('link_id', '100'), validator=valid_link_id)
                step = 7
            elif step == 7:
                vxlan_port = 4789
                if state['carrier'] == 'vxlan':
                    vxlan_port = prompt('VXLAN UDP port', '4789', validator=port)
                data = new_pair(state['name'], 'tcp-tls', state['iran_ip'], state['abroad_ip'], 30443,
                                [{'entry': 443, 'target': 443, 'network': 'tcp'}], carrier=state['carrier'],
                                subnet=state['subnet'], link_id=state['link_id'], vxlan_port=vxlan_port)
                role = 'server' if side_for(data, 'server') == state['side'] else 'client'
                cmds = link_commands(data, role)
                print('\nGenerated network commands:')
                for c in cmds:
                    print('  ' + ' '.join(c))
                ans = prompt('Apply network interface on this host now? [y/N]', 'n')
                if ans.lower() in ('y', 'yes'):
                    root_required()
                    record = ROOT / 'networks' / f"{data['name']}.json"
                    if record.exists() or run(['ip', 'link', 'show', 'dev', device(data)], check=False).returncode == 0:
                        raise RuntimeError('Network name or interface already exists. Choose another name.')
                    link_action(data, role, up=True)
                    saved = {key: data[key] for key in ('name', 'carrier', 'iran_ip', 'abroad_ip', 'subnet', 'link_id', 'vxlan_port')}
                    write(record, json.dumps(saved, indent=2))
                    print(f"Network {device(data)} is up with address {addresses(data)[0 if state['side']=='iran' else 1]}.")
                return
        except Back:
            step -= 1



def all_tunnels():
    tunnels_dir = ROOT / 'tunnels'
    if not tunnels_dir.exists():
        return []
    out = []
    for item in sorted(tunnels_dir.glob('*/pair.json')):
        try:
            out.append(json.loads(item.read_text()))
        except Exception:
            continue
    return out


def unit_props(unit):
    p = subprocess.run(
        ['systemctl', 'show', unit, '-p', 'ActiveState,SubState,ActiveEnterTimestamp,MainPID,MemoryCurrent,CPUUsageNSec,NRestarts'],
        capture_output=True, text=True, check=False
    )
    props = {}
    for line in (p.stdout or '').splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            props[k.strip()] = v.strip()
    return props


def status_table(name=None):
    items = [load(name)] if name else all_tunnels()
    if not items:
        print('No tunnels configured.')
        return
    print(f"{'NAME':14} {'PROFILE':17} {'DIR':8} {'ROLE':7} {'CARRIER':7} {'ENDPOINTS':31} {'STATE':12} {'RESTARTS'}")
    print('-' * 108)
    for d in items:
        unit = unit_name(d['name'])
        pr = unit_props(unit)
        state = f"{pr.get('ActiveState', 'unknown')}/{pr.get('SubState', '?')}"
        restarts = pr.get('NRestarts', '0')
        iran, abroad = addresses(d)
        ep = f"{iran}<->{abroad}:{d['port']}"
        print(f"{d['name'][:14]:14} {d['profile'][:17]:17} {d.get('direction', 'direct')[:8]:8} {d.get('role', '?')[:7]:7} {d['carrier'][:7]:7} {ep[:31]:31} {state[:12]:12} {restarts}")
    if name:
        p = run(['systemctl', 'status', '--no-pager', unit_name(name)], check=False)
        print('\n' + (p.stdout or p.stderr or '').strip())


def transport_protocol(d):
    p = PROFILES.get(d['profile'], {})
    if p.get('raw'):
        return 'raw'
    if p.get('udp') or p.get('transport') in ('hysteria2', 'kcp', 'quic', 'paqet'):
        return 'udp'
    return 'tcp'


def health_check(name=None, fix=False):
    items = [load(name)] if name else all_tunnels()
    if not items:
        print('No tunnels configured.')
        return True
    ss_out = subprocess.run(['ss', '-lntup'], capture_output=True, text=True, check=False).stdout or ''
    overall_ok = True
    for d in items:
        tname = d['name']
        role = d.get('role', 'server')
        unit = unit_name(tname)
        issues, fixes = [], []
        state = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True, check=False).stdout.strip()
        if state != 'active':
            issues.append(f'service {unit} is {state or "inactive"}')
            if fix and os.geteuid() == 0:
                run(['systemctl', 'restart', unit], check=False)
                fixes.append(f'restarted {unit}')
        if needs_adapter(d):
            au = unit_name(tname, adapter=True)
            if not (UNITS / au).exists():
                issues.append(f'adapter unit {au} is missing; reapply tunnel configuration')
            astate = subprocess.run(['systemctl', 'is-active', au], capture_output=True, text=True, check=False).stdout.strip()
            if astate != 'active':
                issues.append(f'adapter {au} is {astate or "inactive"}')
                if fix and os.geteuid() == 0:
                    run(['systemctl', 'restart', au], check=False)
                    fixes.append(f'restarted {au}')
        if d['carrier'] != 'none':
            dev = device(d)
            ip_link = subprocess.run(['ip', 'link', 'show', dev], capture_output=True, text=True, check=False)
            if ip_link.returncode != 0 or 'UP' not in (ip_link.stdout or ''):
                issues.append(f'carrier interface {dev} is down/missing')
                if fix and os.geteuid() == 0:
                    link_action(d, role, up=True)
                    fixes.append(f'rebuilt carrier {dev}')
        if role == 'server':
            proto = transport_protocol(d)
            if proto == 'tcp':
                if not any(ln.startswith('tcp') and (f":{d['port']} " in ln or f":{d['port']}\n" in ln) for ln in ss_out.splitlines()):
                    issues.append(f"tunnel port {d['port']} not listening")
            elif proto == 'udp':
                if not any(ln.startswith('udp') and (f":{d['port']} " in ln or f":{d['port']}\n" in ln) for ln in ss_out.splitlines()):
                    issues.append(f"tunnel port {d['port']} UDP not listening")
        iran, abroad = addresses(d)
        peer = abroad if side_for(d, role) == 'iran' else iran
        direction = d.get('direction', 'direct')
        dials_peer = (role == 'client')
        if dials_peer and transport_protocol(d) == 'tcp':
            try:
                with socket.create_connection((peer, d['port']), timeout=2.5):
                    pass
            except OSError as exc:
                issues.append(f"peer {peer}:{d['port']} TCP unreachable ({exc.__class__.__name__})")
        logs = subprocess.run(['journalctl', '-u', unit, '-n', '40', '--no-pager'], capture_output=True, text=True, check=False).stdout or ''
        err_lines = [ln for ln in logs.splitlines() if any(w in ln.lower() for w in ('fatal', 'panic', 'permission denied', 'address already in use'))]
        if err_lines:
            issues.append(f'recent log error: {err_lines[-1][-90:]}')
        status_str = 'HEALTHY' if not issues else 'ISSUES FOUND'
        if issues:
            overall_ok = False
        print(f"\n[{status_str}] Tunnel: {tname} ({d['profile']}, {direction}, {role})")
        if not issues:
            print(f"  - Service {unit}: active | Peer: {peer}:{d['port']}")
        for iss in issues:
            print(f"  - Problem: {iss}")
        for fx in fixes:
            print(f"  - Fixed: {fx}")
    if fix:
        print('\nRechecking after repairs:')
        return health_check(name, fix=False)
    return overall_ok

def link_test(name):
    d = load(name)
    role = d.get('role', 'server')
    iran, abroad = addresses(d)
    peer = abroad if side_for(d, role) == 'iran' else iran
    proto = transport_protocol(d)
    print(f"\n=== Link Test: {name} -> Peer {peer}:{d['port']} ===")
    p = subprocess.run(['ping', '-c', '4', '-W', '2', peer], capture_output=True, text=True, check=False)
    for ln in (p.stdout or p.stderr or '').splitlines():
        if any(k in ln for k in ('packets transmitted', 'rtt ', 'round-trip', '100% packet loss')):
            print('  ICMP:', ln.strip())
    if proto != 'tcp':
        print(f"  Protocol {proto.upper()} ({d['profile']}) peer connection not verified via TCP handshake.")
        return
    t0 = time.monotonic()
    try:
        with socket.create_connection((peer, d['port']), timeout=3.0):
            dt = (time.monotonic() - t0) * 1000.0
            print(f"  TCP Port {d['port']}: OPEN ({dt:.1f} ms)")
    except OSError as exc:
        print(f"  TCP Port {d['port']}: UNREACHABLE/CLOSED ({exc})")


def tunnel_metrics(name=None):
    items = [load(name)] if name else all_tunnels()
    if not items:
        print('No tunnels configured.')
        return
    ss_est = subprocess.run(['ss', '-ntu', 'state', 'established'], capture_output=True, text=True, check=False).stdout or ''
    print(f"{'NAME':14} {'PROFILE':17} {'PID':8} {'MEM(MB)':9} {'CPU(s)':9} {'CONNS':7} {'RESTARTS':9} {'CARRIER RX/TX'}")
    print('-' * 98)
    for d in items:
        unit = unit_name(d['name'])
        pr = unit_props(unit)
        pid = pr.get('MainPID', '0')
        mem_b = int(pr.get('MemoryCurrent') or 0) if (pr.get('MemoryCurrent') or '').isdigit() else 0
        cpu_ns = int(pr.get('CPUUsageNSec') or 0) if (pr.get('CPUUsageNSec') or '').isdigit() else 0
        restarts = pr.get('NRestarts', '0')
        ports_set = {str(d['port'])} | {str(m['entry']) for m in d['maps']} | {str(m['target']) for m in d['maps']}
        conns = sum(1 for ln in ss_est.splitlines() if any(f':{pt} ' in ln or f':{pt}\t' in ln for pt in ports_set))
        carrier_io = '-'
        if d['carrier'] != 'none':
            dev = device(d)
            rx_p = Path(f'/sys/class/net/{dev}/statistics/rx_bytes')
            tx_p = Path(f'/sys/class/net/{dev}/statistics/tx_bytes')
            if rx_p.exists() and tx_p.exists():
                rx_m = int(rx_p.read_text().strip()) / 1048576.0
                tx_m = int(tx_p.read_text().strip()) / 1048576.0
                carrier_io = f'{rx_m:.1f}M/{tx_m:.1f}M'
        print(f"{d['name'][:14]:14} {d['profile'][:17]:17} {pid:8} {mem_b/1048576.0:9.1f} {cpu_ns/1e9:9.2f} {conns:<7d} {restarts:9} {carrier_io}")


def edit_tunnel(name, args=None):
    d = load(name)
    folder = ROOT / 'tunnels' / name
    role = d.get('role', 'server')
    here_side = side_for(d, role)
    cur_maps = ','.join(f"{m['entry']}={m['target']}" for m in d['maps'])
    cur_net = d['maps'][0].get('network', 'both') if d.get('maps') else 'both'
    if args is not None and any(getattr(args, k, None) is not None for k in ('profile', 'direction', 'tunnel_port', 'maps', 'network', 'pool', 'iran_ip', 'abroad_ip', 'target', 'entry_bind')):
        if getattr(args, 'profile', None):
            d['profile'] = args.profile
        if getattr(args, 'direction', None):
            d['direction'] = args.direction
        if getattr(args, 'iran_ip', None):
            d['iran_ip'] = valid_ip(args.iran_ip)
        if getattr(args, 'abroad_ip', None):
            d['abroad_ip'] = valid_ip(args.abroad_ip)
        if getattr(args, 'tunnel_port', None):
            d['port'] = port(args.tunnel_port, 'Tunnel port')
            d['adapter_port'] = 65500 if d['port'] >= 65534 else d['port'] + 1
        if getattr(args, 'maps', None) or getattr(args, 'network', None):
            d['maps'] = parse_maps(getattr(args, 'maps', None) or cur_maps, getattr(args, 'network', None) or cur_net)
        if getattr(args, 'pool', None):
            d['pool'] = valid_pool(args.pool)
        if getattr(args, 'target', None):
            d['target'] = valid_ip(args.target)
        if getattr(args, 'entry_bind', None):
            d['entry_bind'] = valid_ip(args.entry_bind)
    else:
        print(f"\n=== Edit Tunnel: {name} (Press Enter to keep current value, 0/b to cancel) ===")
        d['profile'] = choose('Select Transport Method', [(k, f"{k:18} ({v['engine']})") for k, v in PROFILES.items()], default=d['profile'])
        d['direction'] = choose('Tunnel Direction', [('reverse', 'Reverse Tunnel'), ('direct', 'Direct Tunnel')], default=d.get('direction', 'reverse'))
        d['iran_ip'] = prompt('Iran Server IP', d['iran_ip'], validator=valid_ip)
        d['abroad_ip'] = prompt('Foreign Server IP', d['abroad_ip'], validator=valid_ip)
        d['port'] = prompt('Tunnel Port', str(d['port']), validator=lambda v: port(v, 'Tunnel port'))
        d['adapter_port'] = 65500 if d['port'] >= 65534 else d['port'] + 1
        net = choose('Forwarded Protocol', [('both', 'TCP + UDP'), ('tcp', 'TCP only'), ('udp', 'UDP only')], default=cur_net)
        maps_raw = prompt('Port Mappings (entry=target,comma-separated)', cur_maps, validator=lambda v: v if parse_maps(v, net) else v)
        d['maps'] = parse_maps(maps_raw, net)
        d['pool'] = prompt('Connection Pool (1-256)', str(d.get('pool', 48)), validator=valid_pool)
    role = 'server' if side_for(d, 'server') == here_side else 'client'
    d['role'] = role
    validate(d)
    if args is not None and getattr(args, 'dry_run', False):
        print(setup_link(d))
        return
    with tempfile.TemporaryDirectory(prefix='te-edit-') as tmp:
        staged = Path(tmp) / 'staged'
        staged.mkdir(mode=0o700)
        if (folder / 'cert.pem').exists() and (folder / 'key.pem').exists():
            shutil.copy2(folder / 'cert.pem', staged / 'cert.pem')
            shutil.copy2(folder / 'key.pem', staged / 'key.pem')
        else:
            make_certificate(staged)
            d['certificate'] = (staged / 'cert.pem').read_text()
        if (staged / 'key.pem').exists():
            d['key'] = (staged / 'key.pem').read_text()
        write(staged / 'pair.json', json.dumps(dict(d, role=role), indent=2))
        install(d, role, staged, stage_bundle(d, role, staged))
        show(d, role)

def restart_all():
    root_required()
    items = all_tunnels()
    if not items:
        print('No tunnels configured.')
        return
    for d in items:
        tname = d['name']
        if d['carrier'] != 'none':
            link_action(d, d.get('role', 'server'), up=True)
        run(['systemctl', 'restart', unit_name(tname)], check=False)
        if (UNITS / unit_name(tname, adapter=True)).exists():
            run(['systemctl', 'restart', unit_name(tname, adapter=True)], check=False)
        st = subprocess.run(['systemctl', 'is-active', unit_name(tname)], capture_output=True, text=True, check=False).stdout.strip()
        print(f"Restarted {tname}: {st}")


def auto_refresh(hours=None, off=False):
    root_required()
    svc = UNITS / 'tunnel-extra-refresh.service'
    tmr = UNITS / 'tunnel-extra-refresh.timer'
    if off or hours == 0:
        run(['systemctl', 'disable', '--now', tmr.name], check=False)
        tmr.unlink(missing_ok=True)
        svc.unlink(missing_ok=True)
        run(['systemctl', 'daemon-reload'], check=False)
        print('Auto-refresh timer disabled.')
        return
    if hours is None:
        state = subprocess.run(['systemctl', 'is-active', tmr.name], capture_output=True, text=True, check=False).stdout.strip()
        print(f'Auto-refresh timer state: {state or "inactive"}')
        return
    if not 1 <= int(hours) <= 168:
        raise ValueError('Auto-refresh hours must be between 1 and 168.')
    install_manager()
    write(svc, f"""[Unit]
Description=Tunnel Extra Auto-Refresh All Tunnels

[Service]
Type=oneshot
ExecStart={SELF} restart-all
""", 0o644)
    write(tmr, f"""[Unit]
Description=Tunnel Extra Periodic Tunnel Restart ({hours}h)

[Timer]
OnBootSec=15min
OnUnitActiveSec={int(hours)}h
Persistent=true

[Install]
WantedBy=timers.target
""", 0o644)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', tmr.name])
    print(f'Auto-refresh enabled: every {int(hours)} hour(s).')


def select_tunnel_prompt(title='Select Tunnel'):
    items = all_tunnels()
    if not items:
        print('No tunnels configured yet.')
        raise Back()
    opts = []
    for d in items:
        st = subprocess.run(['systemctl', 'is-active', unit_name(d['name'])], capture_output=True, text=True, check=False).stdout.strip() or 'inactive'
        opts.append((d['name'], f"{d['name']:14} ({d['profile']}, {d.get('direction','direct')}, {d.get('role','?')} - {st})"))
    return choose(title, opts)


def single_tunnel_menu(tname):
    while True:
        try:
            d = load(tname)
            st = subprocess.run(['systemctl', 'is-active', unit_name(tname)], capture_output=True, text=True, check=False).stdout.strip() or 'inactive'
            act = choose(f"Tunnel: {tname} [{d['profile']} | {d.get('direction','direct')} | {st}]", [
                ('edit', 'Edit (ports, transport, direction, IPs, pool)'),
                ('start', 'Start service'),
                ('stop', 'Stop service'),
                ('restart', 'Restart service'),
                ('logs', 'Live / Recent Logs (last 80 lines)'),
                ('link', 'Setup Link (tuntunnel:// for peer server)'),
                ('health', 'Health Check & Auto-Fix'),
                ('test', 'Link Test (ICMP + TCP latency)'),
                ('delete', 'Delete tunnel permanently'),
            ])
            if act == 'edit':
                edit_tunnel(tname)
            elif act in ('start', 'stop', 'restart'):
                manage(act, tname)
            elif act == 'logs':
                manage('logs', tname)
            elif act == 'link' and side_for(d, d.get('role', 'server')) != 'iran':
                print('\nSetup link is issued on the Iran server only.')
            elif act == 'link':
                print(f"\nSetup Link:\n  {setup_link(d)}\n\nOne-line apply on peer server:\n  sudo tuntunnel link apply '{setup_link(d)}'\n\nLegacy TE1 code:\n  {encode_code(d)}")
            elif act == 'health':
                health_check(tname, fix=True)
            elif act == 'test':
                link_test(tname)
            elif act == 'delete':
                ans = prompt(f"Delete tunnel '{tname}' permanently? [y/N]", 'n')
                if ans.lower() in ('y', 'yes'):
                    manage('remove', tname)
                    return
        except Back:
            return


def manage_tunnels_wizard():
    while True:
        try:
            act = choose('Manage Tunnels', [
                ('tunnels', 'Manage Tunnels (Edit, Start/Stop, Logs, Setup Link, Delete)'),
                ('apply', 'Set Up From A Link (Paste tuntunnel:// or TE1: link)'),
                ('status', 'Status (Live tunnel table)'),
                ('health', 'Health Check (Diagnose problems & auto-fix)'),
                ('test', 'Link Test (Latency, loss & TCP port probe)'),
                ('metrics', 'Tunnel Metrics (Connections, memory, CPU & traffic)'),
                ('restart_all', 'Restart All (Every tunnel at once)'),
                ('autorefresh', 'Auto Refresh (Periodic restart every N hours)'),
            ], allow_link=True)
        except Back:
            return
        try:
            if isinstance(act, tuple) and act[0] == '__link__':
                join(argparse.Namespace(code=act[1], side='abroad', role='auto', name=None, dry_run=False, yes=False))
                continue
            if act == 'tunnels':
                tname = select_tunnel_prompt('Select A Tunnel')
                single_tunnel_menu(tname)
            elif act == 'apply':
                side = choose('This Server Side', [('abroad', 'Abroad / Foreign Server'), ('iran', 'Iran Server')], default='1')
                code = prompt('Paste tuntunnel:// or TE1: Setup Link', validator=lambda v: v if decode_code(v) else v)
                join(argparse.Namespace(code=code, side=side, role='auto', name=None, dry_run=False, yes=False))
            elif act == 'status':
                status_table()
            elif act == 'health':
                health_check(fix= (os.geteuid() == 0))
            elif act == 'test':
                tname = select_tunnel_prompt('Select Tunnel for Link Test')
                link_test(tname)
            elif act == 'metrics':
                tunnel_metrics()
            elif act == 'restart_all':
                restart_all()
            elif act == 'autorefresh':
                mode = choose('Auto Refresh Timer', [('enable', 'Enable periodic restart (every N hours)'), ('disable', 'Disable auto-refresh timer')])
                if mode == 'disable':
                    auto_refresh(off=True)
                else:
                    hrs = prompt('Restart interval in hours (1-168)', '4', validator=lambda v: int(v) if 1 <= int(v) <= 168 else (_ for _ in ()).throw(ValueError('Hours must be 1..168')))
                    auto_refresh(hours=hrs)
        except Back:
            continue

def uninstall():
    root_required()
    items = all_tunnels()
    networks = saved_networks()
    units = sorted({p for pattern in ('tunnel-extra-*.service', 'tunnel-extra-*.timer')
                    for p in UNITS.glob(pattern)})
    print('\nUninstall TunTunnel (this host only)')
    print('Stops and removes TunTunnel services, tracked interfaces, configuration,')
    print('private engines and installed commands. Other tools and peer hosts are unchanged.')
    print('Untracked interfaces and shared binaries in /usr/local/bin are preserved.')
    print(f'Configured tunnels: {len(items)}; tracked networks: {len(networks)}; units: {len(units)}')
    if prompt('Type UNINSTALL to confirm', '').strip() != 'UNINSTALL':
        print('Uninstall cancelled.')
        return False
    backup_dir = Path('/var/backups/tuntunnel')
    backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup = backup_dir / ('tuntunnel-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.tar.gz')
    # Backup must succeed before stopping services or deleting anything.
    with os.fdopen(os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            for path in (ROOT, BIN.parent, SELF.parent, *units):
                if path.exists():
                    archive.add(path, arcname=str(path).lstrip('/'))
    print(f'Backup saved: {backup}')
    for unit in sorted(units, key=lambda p: (p.suffix != '.timer', p.name)):
        run(['systemctl', 'disable', '--now', unit.name])
    for data in items + networks:
        if data.get('carrier') in ('gre', 'vxlan', 'ipip'):
            interface = device(data)
            if run(['ip', 'link', 'show', 'dev', interface], check=False).returncode == 0:
                run(['ip', 'link', 'del', 'dev', interface])
    for unit in units:
        unit.unlink()
    run(['systemctl', 'daemon-reload'])
    for alias in (Path('/usr/local/bin/tuntunnel'), Path('/usr/local/bin/tunnel-extra')):
        if alias.is_symlink() and alias.resolve().parent == SELF.parent.resolve():
            alias.unlink()
    for path in (ROOT, BIN.parent, SELF.parent):
        if path.exists():
            shutil.rmtree(path)
    print(f'TunTunnel uninstalled. Backup retained: {backup}')
    return True


def update():
    root_required()
    repo = 'https://api.github.com/repos/mahdiweb3/tuntunnel/releases/latest'
    with urllib.request.urlopen(repo, timeout=30) as response:
        tag = json.load(response)['tag_name']
    if not re.fullmatch(r'v\d+\.\d+\.\d+', tag):
        raise RuntimeError('Invalid release version.')
    if tuple(map(int, tag[1:].split('.'))) <= tuple(map(int, VERSION.split('.'))):
        print(f'TunTunnel v{VERSION} is already up to date (latest release: {tag}).')
        return False
    asset = f'tuntunnel-{tag}.zip'
    base = f'https://github.com/mahdiweb3/tuntunnel/releases/download/{tag}'
    with urllib.request.urlopen(f'{base}/SHA256SUMS', timeout=30) as response:
        checksums = response.read(1024 * 1024).decode()
    expected = next((line.split()[0].lower() for line in checksums.splitlines()
                     if len(line.split()) == 2 and line.split()[1].lstrip('*') == asset), None)
    if not expected or not re.fullmatch(r'[a-f0-9]{64}', expected):
        raise RuntimeError('Release archive checksum is missing.')
    with urllib.request.urlopen(f'{base}/{asset}', timeout=120) as response:
        archive = response.read(16 * 1024 * 1024 + 1)
    if len(archive) > 16 * 1024 * 1024 or hashlib.sha256(archive).hexdigest() != expected:
        raise RuntimeError('Release archive checksum mismatch.')
    with tempfile.TemporaryDirectory(prefix='tuntunnel-update-') as temp:
        package = Path(temp) / asset
        package.write_bytes(archive)
        with zipfile.ZipFile(package) as bundle:
            member = bundle.getinfo('tunnel-extra.sh')
            if member.file_size > 2 * 1024 * 1024:
                raise RuntimeError('Release script is too large.')
            script = bundle.read(member).decode('utf-8')
        marker = '__TUNNEL_' + 'EXTRA_PY__'
        opener = "<<'" + marker + "'\n"
        closer = '\n' + marker
        if not script.startswith('#!/usr/bin/env bash\n') or opener not in script or closer not in script:
            raise RuntimeError('Invalid release script.')
        code = script.split(opener, 1)[1].rsplit(closer, 1)[0]
        try:
            compile(code, 'tunnel-extra.sh', 'exec')
        except SyntaxError as exc:
            raise RuntimeError('Invalid release Python code.') from exc
        candidate = Path(temp) / 'tunnel-extra.sh'
        candidate.write_text(script)
        if run(['bash', '-n', candidate], check=False).returncode:
            raise RuntimeError('Invalid release shell code.')
        backup = ROOT / 'backups' / ('update-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S-') + uuid.uuid4().hex[:8])
        backup.mkdir(parents=True, mode=0o700)
        if SELF.exists():
            shutil.copy2(SELF, backup / 'tunnel-extra.sh')
        aliases = (Path('/usr/local/bin/tuntunnel'), Path('/usr/local/bin/tunnel-extra'))
        for alias in aliases:
            if alias.exists() and not alias.is_symlink():
                shutil.copy2(alias, backup / alias.name)
        SELF.parent.mkdir(parents=True, exist_ok=True)
        # ponytail: stage beside destination so replacement stays atomic across filesystems.
        with tempfile.NamedTemporaryFile(dir=SELF.parent, delete=False) as staged:
            staged.write(script.encode())
            stage = Path(staged.name)
        try:
            stage.chmod(0o755)
            os.replace(stage, SELF)
        finally:
            stage.unlink(missing_ok=True)
        for alias in aliases:
            alias.parent.mkdir(parents=True, exist_ok=True)
            pending = alias.with_name(alias.name + '.update-' + uuid.uuid4().hex[:8])
            try:
                pending.symlink_to(SELF)
                os.replace(pending, alias)
            finally:
                pending.unlink(missing_ok=True)
    print(f'Updated to {tag}. Backup: {backup}')
    print('Configuration preserved; running tunnels were not restarted. Run tuntunnel again.')
    return True


def wizard():
    while True:
        show_system_header()
        t_cnt = len(all_tunnels())
        try:
            choice = choose('Main Menu', [
                ('bench', f'Find Best Tunnel Method  {B_SOFT}(Auto-Benchmark All Transports){C_RST}'),
                ('config', 'Install / Configure Tunnel'),
                ('network', f'Create Private Network  {B_SOFT}(GRE / VXLAN / IPIP){C_RST}'),
                ('manage', f'Tunnel Management  {B_SOFT}({t_cnt} configured){C_RST}'),
                ('update', 'Update TunTunnel'),
                ('uninstall', 'Uninstall'),
            ], allow_back=True, exit_label='Exit', allow_link=True)
        except Back:
            print(f'  {B_BRIGHT}Exiting TunTunnel.{C_RST}')
            return
        if isinstance(choice, tuple) and choice[0] == '__link__':
            join(argparse.Namespace(code=choice[1], side='abroad', role='auto', name=None, dry_run=False, yes=False))
        elif choice == 'bench':
            find_best_tunnel_wizard()
        elif choice == 'config':
            configure_tunnel_wizard()
        elif choice == 'network':
            create_network_wizard()
        elif choice == 'manage':
            manage_tunnels_wizard()
        elif choice == 'update':
            if update():
                return
        elif choice == 'uninstall':
            if uninstall():
                return


def manage(action, name=None):
    if action == 'list':
        status_table()
        return
    if action == 'status' and not name:
        status_table()
        return
    if action == 'health':
        health_check(name, fix=(os.geteuid() == 0))
        return
    if action == 'metrics':
        tunnel_metrics(name)
        return
    if action == 'restart-all':
        restart_all()
        return
    d = load(name)
    if action == 'code':
        if side_for(d, d.get('role', 'server')) == 'iran':
            print(setup_link(d))
        else:
            print('Setup link is issued on the Iran server only.')
    elif action == 'status':
        status_table(d['name'])
    elif action == 'test':
        link_test(d['name'])
    elif action == 'logs':
        p = run(['journalctl', '-u', unit_name(d['name']), '-n', '80', '--no-pager'], check=False)
        print(p.stdout or p.stderr)
    elif action in ('start', 'restart', 'stop'):
        root_required()
        if action in ('start', 'restart') and d['carrier'] != 'none':
            link_action(d, d.get('role', 'server'), up=True)
        run(['systemctl', action, unit_name(d['name'])])
        if (UNITS / unit_name(d['name'], adapter=True)).exists():
            run(['systemctl', action, unit_name(d['name'], adapter=True)], check=False)
        print(f"Tunnel {d['name']} {action.rstrip('e')}ed.")
    elif action == 'remove':
        root_required()
        backup = ROOT / 'backups' / (d['name'] + '-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(ROOT / 'tunnels' / d['name'], backup)
        for u in (unit_name(d['name'], adapter=True), unit_name(d['name']), unit_name(d['name'], link=True)):
            if (UNITS / u).exists():
                shutil.copy2(UNITS / u, backup / u)
            run(['systemctl', 'disable', '--now', u], check=False)
            (UNITS / u).unlink(missing_ok=True)
        if d['carrier'] != 'none':
            link_action(d, d.get('role', 'server'), up=False)
        shutil.rmtree(ROOT / 'tunnels' / d['name'], ignore_errors=True)
        run(['systemctl', 'daemon-reload'], check=False)
        print(f"Tunnel {d['name']} removed. Backup retained: {backup}")


def parser():
    ap = argparse.ArgumentParser(prog='tuntunnel', description='Unified Multi-Engine Tunnel & Overlay Network Manager')
    sub = ap.add_subparsers(dest='command')
    sub.add_parser('uninstall', help='Back up and uninstall TunTunnel on this host')
    c = sub.add_parser('create', help='Create tunnel pair and connection code')
    c.add_argument('--name', default='main')
    c.add_argument('--profile', required=True, choices=list(PROFILES))
    c.add_argument('--direction', default=None, choices=['direct', 'reverse'])
    c.add_argument('--side', default='iran', choices=['iran', 'abroad'])
    c.add_argument('--role', default='auto', choices=['auto', 'server', 'client'])
    c.add_argument('--iran-ip', required=True)
    c.add_argument('--abroad-ip', required=True)
    c.add_argument('--tunnel-port', type=lambda v: port(v, 'Tunnel port'), default=30443)
    c.add_argument('--maps', required=True, help='entry=target,entry=target')
    c.add_argument('--network', default='both', choices=['tcp', 'udp', 'both'])
    c.add_argument('--target', default='127.0.0.1')
    c.add_argument('--entry-bind', default='0.0.0.0')
    c.add_argument('--camouflage', help='host:443 TLS1.3 site for ShadowTLS/REALITY handshake (default www.microsoft.com:443)')
    c.add_argument('--pool', type=int, default=48)
    c.add_argument('--carrier', default='none', choices=['none', 'gre', 'vxlan', 'ipip'])
    c.add_argument('--subnet', default='10.203.88.0/30')
    c.add_argument('--link-id', type=int, default=100)
    c.add_argument('--vxlan-port', type=lambda v: port(v, 'VXLAN port'), default=4789)
    c.add_argument('--dry-run', action='store_true')
    c.add_argument('-y', '--yes', action='store_true')
    j = sub.add_parser('join', help='Join peer server using tuntunnel:// or TE1 connection code')
    j.add_argument('--code', required=True)
    j.add_argument('--side', default='abroad', choices=['iran', 'abroad'])
    j.add_argument('--role', default='auto', choices=['auto', 'server', 'client'])
    j.add_argument('--name')
    j.add_argument('--dry-run', action='store_true')
    j.add_argument('-y', '--yes', action='store_true')
    lk = sub.add_parser('link', help='Apply tuntunnel:// setup link (BackPack style)')
    lk.add_argument('subaction', choices=['apply'])
    lk.add_argument('code')
    lk.add_argument('--name')
    lk.add_argument('--side', default='abroad', choices=['iran', 'abroad'])
    lk.add_argument('--dry-run', action='store_true')
    ed = sub.add_parser('edit', help='Edit existing tunnel configuration')
    ed.add_argument('name')
    ed.add_argument('--profile', choices=list(PROFILES))
    ed.add_argument('--direction', choices=['direct', 'reverse'])
    ed.add_argument('--iran-ip')
    ed.add_argument('--abroad-ip')
    ed.add_argument('--tunnel-port', type=lambda v: port(v, 'Tunnel port'))
    ed.add_argument('--maps')
    ed.add_argument('--network', choices=['tcp', 'udp', 'both'])
    ed.add_argument('--pool', type=int)
    ed.add_argument('--target')
    ed.add_argument('--entry-bind')
    ed.add_argument('--dry-run', action='store_true')
    ar = sub.add_parser('auto-refresh', help='Configure periodic restart timer')
    ar.add_argument('--hours', type=int)
    ar.add_argument('--off', action='store_true')
    for name in ('list', 'restart-all', 'update'):
        sub.add_parser(name)
    for name in ('status', 'health', 'metrics'):
        p = sub.add_parser(name)
        p.add_argument('name', nargs='?')
    for name in ('logs', 'start', 'restart', 'stop', 'remove', 'code', 'test'):
        p = sub.add_parser(name)
        p.add_argument('name')
    for name in ('link-up', 'link-down'):
        p = sub.add_parser(name)
        p.add_argument('name')
        p.add_argument('--role', choices=['server', 'client'])
    return ap


def main():
    args = parser().parse_args()
    if args.command == 'create':
        create(args)
    elif args.command == 'join':
        join(args)
    elif args.command == 'link':
        join(argparse.Namespace(code=args.code, side=args.side, role='auto', name=args.name, dry_run=args.dry_run, yes=True))
    elif args.command == 'edit':
        edit_tunnel(args.name, args)
    elif args.command == 'auto-refresh':
        auto_refresh(hours=args.hours, off=args.off)
    elif args.command in ('link-up', 'link-down'):
        root_required()
        data = load(args.name)
        role = args.role or data.get('role', 'server')
        if data['carrier'] != 'none':
            link_action(data, role, args.command == 'link-up')
    elif args.command == 'uninstall':
        uninstall()
    elif args.command == 'update':
        update()
    elif args.command:
        manage(args.command, getattr(args, 'name', None))
    else:
        wizard()


if __name__ == '__main__':
    os.umask(0o077)
    try:
        os.fstat(3)
        os.dup2(3, 0)
        sys.stdin = os.fdopen(0, 'r', closefd=False)
    except OSError:
        pass
    try:
        main()
    except KeyboardInterrupt:
        print('\nCancelled.', file=sys.stderr)
        sys.exit(130)
    except (ValueError, RuntimeError, OSError, KeyError, subprocess.TimeoutExpired) as exc:
        print(str(exc) if isinstance(exc, (ValueError, RuntimeError)) else 'Execution error; check network, files, and service logs.', file=sys.stderr)
        sys.exit(1)
__TUNNEL_EXTRA_PY__
