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
