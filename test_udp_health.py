"""Run: python3 test_udp_health.py [path/to/tunnel-extra.sh]. No live services touched."""
import ast
import contextlib
import io
from pathlib import Path
import socket
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch


def check(script):
    text = Path(script).read_text().split("<<'__TUNNEL_EXTRA_PY__'", 1)[1]
    tree = ast.parse(text.rsplit('__TUNNEL_EXTRA_PY__', 1)[0])
    nodes = [n for n in tree.body if
             isinstance(n, ast.FunctionDef) and n.name in
             ('health_check', 'link_test', 'transport_protocol') or
             isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'PROFILES' for t in n.targets)]
    scope = dict(socket=socket, subprocess=subprocess, time=time)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(script), 'exec'), scope)
    data = dict(name='regression', profile='quic-tls', role='client', carrier='none', port=3098)
    scope.update(load=lambda _: data, unit_name=lambda _: 'test.service',
                 needs_adapter=lambda _: False, addresses=lambda _: ('127.0.0.2', '127.0.0.1'),
                 side_for=lambda *_: 'iran')
    def command(argv, **_):
        stdout = 'active\n' if argv[0] == 'systemctl' else ''
        if argv[0] == 'ss':
            stdout = command.listeners
        return SimpleNamespace(stdout=stdout, stderr='', returncode=0)
    command.listeners = 'udp UNCONN 0 0 127.0.0.1:3098 0.0.0.0:*\n'
    count = 0
    with patch.object(subprocess, 'run', side_effect=command), patch.object(
            socket, 'create_connection', side_effect=ConnectionRefusedError('TCP closed')) as tcp:
        for profile in ('quic-tls', 'mkcp-aes', 'mkcp-chacha', 'kcp-aes'):
            if profile not in scope['PROFILES']:
                continue
            data.update(profile=profile, role='client')
            with contextlib.redirect_stdout(io.StringIO()) as out:
                assert scope['health_check']('regression'), out.getvalue()
                scope['link_test']('regression')
            assert not tcp.called, (profile, out.getvalue())
            assert 'not verified' in out.getvalue(), out.getvalue()
            count += 1
        data.update(profile='quic-tls', role='server')
        with contextlib.redirect_stdout(io.StringIO()):
            assert scope['health_check']('regression')
            command.listeners = 'tcp LISTEN 0 128 127.0.0.1:3098 0.0.0.0:*\n'
            assert not scope['health_check']('regression')
        data.update(profile='tcp-tls', role='client')
        with contextlib.redirect_stdout(io.StringIO()) as out:
            assert not scope['health_check']('regression')
            scope['link_test']('regression')
        assert tcp.call_count == 2
        assert 'TCP unreachable' in out.getvalue()
        assert 'UNREACHABLE/CLOSED' in out.getvalue()
    print(f'PASS: {script}: {count} UDP profiles; UDP listener check; TCP failure preserved')


if __name__ == '__main__':
    check(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).with_name('tunnel-extra.sh'))
