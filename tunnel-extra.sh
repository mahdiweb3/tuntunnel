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

VERSION = '2.7.0'

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
    'pango-tls': dict(engine='sing-box', transport='httpupgrade'),
    'pango-grpc': dict(engine='sing-box', transport='grpc'),

    'smux-tls': dict(engine='sing-box', mux='smux'),
    'yamux-tls': dict(engine='sing-box', mux='yamux'),
    'h2mux-tls': dict(engine='sing-box', mux='h2mux'),
    'wss': dict(engine='sing-box', transport='ws'),
    'wss-smux': dict(engine='sing-box', transport='ws', mux='smux'),
    'grpc-tls': dict(engine='sing-box', transport='grpc'),
    'h2-tls': dict(engine='sing-box', transport='http'),
    'httpupgrade-tls': dict(engine='sing-box', transport='httpupgrade'),
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
    listen = '::' if ':' in remote else '0.0.0.0'
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
    local = d['iran_ip'] if side_for(d, role) == 'iran' else d['abroad_ip']
    remote = d['abroad_ip'] if local == d['iran_ip'] else d['iran_ip']
    try:
        r_out = subprocess.run(['ip', '-4', 'route', 'get', remote], capture_output=True, text=True, check=False).stdout
        m_src = re.search(r'src\s+([0-9.]+)', r_out)
        if m_src:
            local = m_src.group(1)
    except Exception:
        pass
    iran_addr, abroad_addr = addresses(d)
    addr = iran_addr if local == d['iran_ip'] else abroad_addr
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
    run(['ip', 'link', 'del', dev], check=False)
    if up:
        for cmd in link_commands(d, role):
            run(cmd)


def core_binary():
    """tuntunnel-core: local build first, else the checksummed asset of this tuntunnel release."""
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if not arch:
        raise RuntimeError('Unsupported CPU architecture.')
    target = BIN / f'tuntunnel-core-{VERSION}'
    if target.is_file() and os.access(target, os.X_OK):
        return target
    for cand in (Path(__file__).resolve().parent / '.tools' / 'tuntunnel-core', Path('/usr/local/bin/tuntunnel-core')):
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
        Path(__file__).resolve().parent / '.tools' / ('DaggerLauncher' if engine == 'dagger' else engine),
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
        runner = Path(__file__).with_name('bundle_runner.py').read_text()
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
        command = ' '.join(shlex.quote(str(x)) for x in
                           (sys.executable, folder / 'bundle_runner.py', folder / 'bundle.json'))
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
