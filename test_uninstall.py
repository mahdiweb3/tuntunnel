"""Run: python3 test_uninstall.py. All paths and service calls are sandboxed."""
import contextlib
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile

source = Path(__file__).with_name('tunnel-extra.sh').read_text()
body = source.split("<<'__TUNNEL_EXTRA_PY__'\n", 1)[1].rsplit('\n__TUNNEL_EXTRA_PY__', 1)[0]
for answer, failure in [('no', ''), ('UNINSTALL', 'backup'), ('UNINSTALL', 'service'), ('UNINSTALL', '')]:
    ns = {'__name__': 'test'}
    exec(compile(body, 'tunnel-extra.sh', 'exec'), ns)
    with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
        base = Path(temp)
        sandbox = lambda p: base / str(p).lstrip('/')
        ns.update(ROOT=sandbox('/etc/tunnel-extra'), BIN=sandbox('/opt/tunnel-extra/bin'),
                  SELF=sandbox('/usr/local/lib/tunnel-extra/tunnel-extra.sh'), UNITS=sandbox('/etc/systemd/system'))
        ns['Path'] = sandbox
        ns['root_required'] = lambda: None
        ns['prompt'] = lambda *a: answer
        data = {'name': 'test', 'carrier': 'gre'}
        ns['all_tunnels'] = lambda: [data]
        ns['saved_networks'] = lambda: [data]
        ns['device'] = lambda d: 'te-test'
        for p in [ns['ROOT'], ns['BIN'], ns['SELF'].parent, ns['UNITS'], sandbox('/usr/local/bin')]:
            p.mkdir(parents=True, exist_ok=True)
        ns['SELF'].write_text('source')
        ns['ROOT'].joinpath('config.json').write_text('private')
        units = [ns['UNITS'] / 'tunnel-extra-test.service', ns['UNITS'] / 'tunnel-extra-refresh.timer']
        for u in units:
            u.write_text('owned')
        unrelated = ns['UNITS'] / 'unrelated.service'
        unrelated.write_text('preserve')
        shared = sandbox('/usr/local/bin/sing-box')
        shared.write_text('shared')
        alias = sandbox('/usr/local/bin/tuntunnel')
        alias.symlink_to(ns['SELF'])
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            if failure == 'service' and argv[0] == 'systemctl':
                raise RuntimeError('stop failed')
            return subprocess.CompletedProcess(argv, 0)
        ns['run'] = run
        if failure == 'backup':
            original_open = ns['tarfile'].open
            ns['tarfile'].open = lambda *a, **k: (_ for _ in ()).throw(OSError('backup failed'))
        try:
            result = ns['uninstall']()
            assert not failure
        except (OSError, RuntimeError):
            assert failure
        finally:
            if failure == 'backup':
                ns['tarfile'].open = original_open
        assert unrelated.exists() and shared.exists()
        if answer != 'UNINSTALL' or failure:
            assert ns['ROOT'].exists() and alias.is_symlink() and all(u.exists() for u in units)
            if failure != 'service':
                assert not calls
        else:
            assert result and not ns['ROOT'].exists() and not ns['BIN'].parent.exists()
            assert not ns['SELF'].exists() and not alias.is_symlink()
            assert not any(u.exists() for u in units)
            backups = list(sandbox('/var/backups/tuntunnel').glob('*.tar.gz'))
            assert len(backups) == 1 and backups[0].stat().st_mode & 0o777 == 0o600
            with tarfile.open(backups[0]) as archive:
                assert any(m.name.endswith('config.json') for m in archive.getmembers())
print('PASS: uninstall cancel, backup failure, service failure, confirmed cleanup; shared files preserved')

