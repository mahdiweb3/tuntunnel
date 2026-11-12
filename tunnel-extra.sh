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

BANNER = (
    f'{B_DEEP}    ______            ______                      __{C_RST}\n'
    f'{B_MAIN}   /_  __/_  ______  /_  __/_  ______  ____  ___  / /{C_RST}\n'
    f'{B_BRIGHT}    / / / / / / __ \\  / / / / / / __ \\/ __ \\/ _ \\/ / {C_RST}\n'
    f'{B_CYAN}   / / / /_/ / / / / / / / /_/ / / / / / / /  __/ /  {C_RST}\n'
    f'{B_ICE}  /_/  \\__,_/_/ /_/ /_/  \\__,_/_/ /_/_/ /_/\\___/_/   {C_RST}\n\n'
    f'  {B_SOFT}Multi-Core Tunnel & Transport Benchmark Tool •{C_RST} {B_BRIGHT}v2.6.0{C_RST}'
)


class Back(Exception):
    pass

ROOT = Path('/etc/tunnel-extra')
BIN = Path('/opt/tunnel-extra/bin')
SELF = Path('/usr/local/lib/tunnel-extra/tunnel-extra.sh')
UNITS = Path('/etc/systemd/system')
PROFILES = {
    'tcp-tls': dict(engine='sing-box'),
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
    'icmp-aes': dict(engine='backpack', transport='xdi', raw=True),
    **{'dagger-' + n: dict(engine='dagger', transport=n)
       for n in ('tcp', 'ws', 'wss', 'http', 'xhttp', 'quantum', 'quantum+')},
}
RELEASES = {
    'sing-box': ('SagerNet/sing-box', 'v1.14.4'),
    'xray': ('XTLS/Xray-core', 'v26.11.9'),
    'dagger': ('itsFLoKi/daggerConnect', 'v1.4'),
    'backpack': ('AminMGMT/BackPack', 'v1.8.5'),
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
        direction = 'reverse' if engine in ('dagger', 'backpack') else 'direct'
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
    if 'direction' not in data:
        data['direction'] = 'reverse' if PROFILES.get(data.get('profile'), {}).get('engine') in ('dagger', 'backpack') else 'direct'
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


def side_for(d, role):
    direction = d.get('direction', 'reverse' if PROFILES[d['profile']]['engine'] in ('dagger', 'backpack') else 'direct')
    if direction == 'reverse':
        return 'iran' if role == 'server' else 'abroad'
    return 'abroad' if role == 'server' else 'iran'


def needs_adapter(d):
    engine = PROFILES[d['profile']]['engine']
    direction = d.get('direction', 'reverse' if engine in ('dagger', 'backpack') else 'direct')
    return (engine in ('sing-box', 'xray') and direction == 'reverse') or (engine in ('dagger', 'backpack') and direction == 'direct')


def endpoint(host, number):
    return f'[{host}]:{number}' if ':' in host else f'{host}:{number}'


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
    directory = Path(directory)
    p = PROFILES[d['profile']]
    iran, abroad = addresses(d)
    direction = d.get('direction', 'reverse' if p['engine'] in ('dagger', 'backpack') else 'direct')
    remote = iran if direction == 'reverse' else abroad
    listen = '::' if ':' in remote else '0.0.0.0'
    cert, key = str(directory / 'cert.pem'), str(directory / 'key.pem')
    if role == 'client' and d.get('certificate'):
        cert_p = directory / 'cert.pem'
        if not cert_p.exists():
            try:
                write(cert_p, d['certificate'])
            except OSError:
                pass
    if p['engine'] == 'sing-box':
        inbound = dict(type='trojan', tag='tunnel', listen=listen, listen_port=d['port'],
                       users=[dict(password=d['secret'])],
                       tls=dict(enabled=True, min_version='1.3', certificate_path=cert, key_path=key))
        outbound = dict(type='trojan', tag='tunnel', server=remote, server_port=d['port'],
                        password=d['secret'], tls=dict(enabled=True, min_version='1.3',
                        server_name=d['server_name'], certificate=d['certificate'].splitlines()))
        transport = p.get('transport')
        if transport == 'hysteria2':
            inbound['type'] = outbound['type'] = transport
        elif transport:
            tr = dict(type=transport)
            if transport in ('ws', 'httpupgrade', 'http'):
                tr['path'] = '/tunnel'
            if transport == 'grpc':
                tr['service_name'] = 'tunnel'
            if transport == 'http':
                tr['host'] = [d['server_name']]
            inbound['transport'] = outbound['transport'] = tr
        if p.get('mux'):
            inbound['multiplex'] = dict(enabled=True)
            inbound['tcp_fast_open'] = True
            outbound['tcp_fast_open'] = True
            outbound['multiplex'] = dict(enabled=True, protocol=p['mux'], max_connections=d['pool'],
                                         min_streams=4, max_streams=128, padding=False)
        if role == 'server':
            return dict(log=dict(level='warn'), inbounds=[inbound], outbounds=[dict(type='direct', tag='backend')],
                        route=dict(rules=[dict(inbound=['tunnel'], ip_cidr=[d['target'] + ('/128' if ':' in d['target'] else '/32')],
                        port=sorted(set(m['target'] for m in d['maps'])), action='route', outbound='backend'),
                        dict(inbound=['tunnel'], action='reject')], final='backend'))
        entries = [dict(type='direct', tag='entry' + str(m['entry']), listen=d['entry_bind'],
                        listen_port=m['entry'], override_address=d['target'], override_port=m['target'],
                        **({} if m['network'] == 'both' else dict(network=m['network']))) for m in d['maps']]
        return dict(log=dict(level='warn'), inbounds=entries, outbounds=[outbound], route=dict(final='tunnel'))
    if p['engine'] == 'xray':
        kcp = p['transport'] == 'kcp'
        stream = dict(network=p['transport'], security='none' if kcp else 'tls')
        if kcp:
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
        if role == 'server':
            mappings = [f"{endpoint(d['entry_bind'], m['entry'])}={endpoint(d['target'], m['target'])}" for m in d['maps']]
            has_udp = any(m['network'] in ('udp', 'both') for m in d['maps'])
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


def config_bundle(d, role, directory):
    validate(d)
    p = PROFILES[d['profile']]
    engine = p['engine']
    if not needs_adapter(d):
        return [dict(engine=engine, name=f'{role}.json', config=make_config(d, role, directory))]
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


def download_engine(engine):
    if engine == 'backpack' and Path('/usr/local/bin/backpack').exists():
        return Path('/usr/local/bin/backpack')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if not arch:
        raise RuntimeError('Unsupported CPU architecture.')
    repo, tag = RELEASES[engine]
    target = BIN / f'{engine}-{tag}'
    if target.exists():
        return target
    local_candidates = [
        Path(__file__).resolve().parent / '.tools' / ('DaggerLauncher' if engine == 'dagger' else engine),
        Path('/usr/local/bin') / ('DaggerConnect' if engine == 'dagger' else engine),
    ]
    for cand in local_candidates:
        if cand.exists():
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
    else:
        asset = member = f'DaggerConnect_linux_{arch}'
    base = f'https://github.com/{repo}/releases/download/{tag}'
    BIN.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='te-dl-') as temp:
        temp_dir = Path(temp)
        pkg = temp_dir / asset
        with urllib.request.urlopen(f'{base}/{asset}', timeout=120) as resp:
            pkg.write_bytes(resp.read())
        for sums_name in ('checksums.txt', f'{asset}.dgst', 'SHA256SUMS'):
            try:
                with urllib.request.urlopen(f'{base}/{sums_name}', timeout=30) as resp:
                    text = resp.read().decode(errors='ignore')
                digest = hashlib.sha256(pkg.read_bytes()).hexdigest().lower()
                found = [m.group(0).lower() for m in re.finditer(r'\b[a-fA-F0-9]{64}\b', text)]
                if found and digest not in found:
                    raise RuntimeError('Downloaded binary SHA-256 checksum mismatch.')
                break
            except urllib.error.URLError:
                continue
        if asset.endswith('.tar.gz'):
            with tarfile.open(pkg, 'r:gz') as tar:
                shutil.copyfileobj(tar.extractfile(member), open(target, 'wb'))
        elif asset.endswith('.zip'):
            with zipfile.ZipFile(pkg) as zf:
                shutil.copyfileobj(zf.open(member), open(target, 'wb'))
        else:
            shutil.copy2(pkg, target)
        target.chmod(0o755)
    return target


def engine_argv(engine, binary, config, check=False):
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
    return [binary, '--help'] if check else [binary, '-c', config]


def root_required():
    if os.geteuid() != 0:
        raise RuntimeError('Root privileges are required for installation and service management.')


def prerequisites():
    missing = [tool for tool in ('ip', 'openssl', 'systemctl') if not shutil.which(tool)]
    if not missing:
        return
    root_required()
    if shutil.which('apt-get'):
        run(['apt-get', 'update'], timeout=180)
        run(['apt-get', 'install', '-y', 'iproute2', 'openssl', 'ca-certificates', 'systemd'], timeout=300)
    elif shutil.which('dnf'):
        run(['dnf', 'install', '-y', 'iproute', 'openssl', 'ca-certificates', 'systemd'], timeout=300)
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
    if (folder / 'adapter.json').exists():
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
    print(f'\n=== Setup {peer_label} ===')
    print(f'1) On the {peer_label}, as root (one-line apply):')
    print(f"   sudo tuntunnel link apply '{link}'")
    print(f'\n2) Or paste the Setup Link inside `sudo tuntunnel` -> Configure tunnel -> {peer_side.capitalize()}:')
    print(f'   {link}')
    print('\nLegacy TE1 code:\n' + encode_code(d))


def confirm_install(yes):
    if yes:
        return
    answer = input('Install and start systemd service now? [y/N]: ').strip().lower()
    if answer not in ('y', 'yes'):
        raise RuntimeError('Cancelled by user.')


def create(args):
    prerequisites()
    if args.iran_ip == args.abroad_ip and not ipaddress.ip_address(args.iran_ip).is_loopback:
        raise ValueError('Iran IP and Foreign IP must not be identical.')
    maps = parse_maps(args.maps, 'tcp' if PROFILES[args.profile]['engine'] == 'dagger' else args.network)
    direction = getattr(args, 'direction', None)
    data = new_pair(args.name, args.profile, args.iran_ip, args.abroad_ip, args.tunnel_port, maps,
                    carrier=args.carrier, subnet=args.subnet, direction=direction)
    role = args.role if args.role != 'auto' else ('server' if side_for(data, 'server') == args.side else 'client')
    with tempfile.TemporaryDirectory(prefix='te-stage-') as temp:
        staged = Path(temp) / data['name']
        staged.mkdir(mode=0o700)
        make_certificate(staged)
        data['certificate'] = (staged / 'cert.pem').read_text()
        data['key'] = (staged / 'key.pem').read_text()
        write(staged / 'pair.json', json.dumps(dict(data, role=role), indent=2))
        bundle = config_bundle(data, role, staged)
        binary = None
        for item in bundle:
            cfg_path = staged / item['name']
            write(cfg_path, json.dumps(item['config'], indent=2))
            eng_bin = download_engine(item['engine'])
            if item['name'] == f'{role}.json':
                binary = eng_bin
            run(engine_argv(item['engine'], eng_bin, cfg_path, check=True))
        if args.dry_run:
            print(encode_code(data))
            return
        confirm_install(args.yes)
        install(data, role, staged, binary)
    show(data, role)


def join(args):
    prerequisites()
    data = decode_code(args.code)
    if args.name:
        data['name'] = name_ok(args.name)
    role = args.role if args.role != 'auto' else ('server' if side_for(data, 'server') == args.side else 'client')
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
        bundle = config_bundle(data, role, staged)
        binary = None
        for item in bundle:
            cfg_path = staged / item['name']
            write(cfg_path, json.dumps(item['config'], indent=2))
            eng_bin = download_engine(item['engine'])
            if item['name'] == f'{role}.json':
                binary = eng_bin
            run(engine_argv(item['engine'], eng_bin, cfg_path, check=True))
        if args.dry_run:
            print(json.dumps(bundle[0]['config'], indent=2))
            return
        confirm_install(args.yes)
        install(data, role, staged, binary)
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
    old_argv, os.environ['TE_SUBPROCESS'] = sys.argv[:], '1'
    try: sys.argv = ['tunnel-bench']; ns['main']()
    except (SystemExit, KeyboardInterrupt): pass
    finally: sys.argv = old_argv


def configure_tunnel_wizard():
    state = {}
    step = 0
    while step >= 0:
        try:
            if step == 0:
                res = choose('Server Location (Iran or Foreign — or paste tuntunnel:// setup link)', [
                    ('iran', 'Iran Server'),
                    ('abroad', 'Abroad / Foreign Server'),
                ], default='1', allow_link=True)
                if isinstance(res, tuple) and res[0] == '__link__':
                    join(argparse.Namespace(code=res[1], side='abroad', role='auto', name=None, dry_run=False, yes=False))
                    return
                state['side'] = res
                state['mode'] = 'create'
                step = 1 if res == 'iran' else 3
            elif step == 1:
                res = choose('Tunnel Direction (Reverse or Direct — or paste tuntunnel:// setup link)', [
                    ('reverse', 'Reverse Tunnel (Foreign dials Iran)'),
                    ('direct', 'Direct Tunnel (Iran dials Foreign)'),
                ], default='1', allow_link=True)
                if isinstance(res, tuple) and res[0] == '__link__':
                    join(argparse.Namespace(code=res[1], side=state.get('side', 'abroad'), role='auto', name=None, dry_run=False, yes=False))
                    return
                state['direction'] = res
                step = 2
            elif step == 2:
                opts = [(k, f"{k} ({v['engine']})") for k, v in PROFILES.items()]
                res = choose('Select Transport Method (All Transports — or paste tuntunnel:// setup link)', opts, default='1', allow_link=True)
                if isinstance(res, tuple) and res[0] == '__link__':
                    join(argparse.Namespace(code=res[1], side=state.get('side', 'abroad'), role='auto', name=None, dry_run=False, yes=False))
                    return
                state['profile'] = res
                step = 4
            elif step == 3:
                res = choose('Abroad Server Setup', [
                    ('join', 'Set up from a link (Paste tuntunnel:// or TE1: link)'),
                    ('create', 'Manual configuration (Direction, transport, IPs, ports)'),
                ], default='1', allow_link=True)
                if isinstance(res, tuple) and res[0] == '__link__':
                    join(argparse.Namespace(code=res[1], side=state.get('side', 'abroad'), role='auto', name=None, dry_run=False, yes=False))
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
            step = {3: 0, 1: 3 if state.get('side') == 'abroad' else 0, 4: 3 if state.get('mode') == 'join' else 2}.get(step, step - 1)


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
        if needs_adapter(d) and (UNITS / unit_name(tname, adapter=True)).exists():
            au = unit_name(tname, adapter=True)
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
        if role == 'server' and f":{d['port']} " not in ss_out and f":{d['port']}\n" not in ss_out:
            issues.append(f"tunnel port {d['port']} not listening")
        iran, abroad = addresses(d)
        peer = abroad if side_for(d, role) == 'iran' else iran
        direction = d.get('direction', 'direct')
        dials_peer = (role == 'client')
        if dials_peer and PROFILES[d['profile']]['engine'] != 'backpack':
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
    return overall_ok

def link_test(name):
    d = load(name)
    role = d.get('role', 'server')
    iran, abroad = addresses(d)
    peer = abroad if side_for(d, role) == 'iran' else iran
    print(f"\n=== Link Test: {name} -> Peer {peer}:{d['port']} ===")
    p = subprocess.run(['ping', '-c', '4', '-W', '2', peer], capture_output=True, text=True, check=False)
    for ln in (p.stdout or p.stderr or '').splitlines():
        if any(k in ln for k in ('packets transmitted', 'rtt ', 'round-trip', '100% packet loss')):
            print('  ICMP:', ln.strip())
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
        bundle = config_bundle(d, role, staged)
        binary = None
        for item in bundle:
            cfg_path = staged / item['name']
            write(cfg_path, json.dumps(item['config'], indent=2))
            eng_bin = download_engine(item['engine'])
            if item['name'] == f'{role}.json':
                binary = eng_bin
            run(engine_argv(item['engine'], eng_bin, cfg_path, check=True))
        install(d, role, staged, binary)
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
        print(f"Setup Link:\n{setup_link(d)}\n\nLegacy TE1:\n{encode_code(d)}")
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
        for u in (unit_name(d['name'], adapter=True), unit_name(d['name']), unit_name(d['name'], link=True)):
            run(['systemctl', 'disable', '--now', u], check=False)
            (UNITS / u).unlink(missing_ok=True)
        if d['carrier'] != 'none':
            link_action(d, d.get('role', 'server'), up=False)
        shutil.rmtree(ROOT / 'tunnels' / d['name'], ignore_errors=True)
        run(['systemctl', 'daemon-reload'], check=False)
        print(f"Tunnel {d['name']} removed.")


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
    for name in ('list', 'restart-all'):
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
