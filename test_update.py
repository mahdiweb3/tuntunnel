"""Run: python3 test_update.py. All writes are sandboxed; no services touched."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import zipfile
from unittest.mock import patch

source = Path(__file__).with_name('tunnel-extra.sh').read_text()
body = source.split("<<'__TUNNEL_EXTRA_PY__'\n", 1)[1].rsplit('\n__TUNNEL_EXTRA_PY__', 1)[0]
ns = {'__name__': 'test'}
exec(compile(body, 'tunnel-extra.sh', 'exec'), ns)
assert ns['parser']().parse_args(['update']).command == 'update'
for case in ('success', 'unchanged', 'checksum', 'missing-checksum', 'syntax', 'python', 'network', 'backup', 'replace'):
    with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
        root = Path(temp)
        target = root / 'lib/tunnel-extra.sh'
        target.parent.mkdir()
        old = b'previous installed version'
        target.write_bytes(old)
        config = root / 'config.json'
        config.write_text('preserve')
        binary = root / 'bin/tuntunnel'
        binary.parent.mkdir()
        binary.write_bytes(b'old compiled launcher')
        payload = source
        if case == 'syntax':
            payload += '\nif\n'
        if case == 'python':
            payload = payload.replace('import argparse', 'def invalid syntax')
        package = io.BytesIO()
        with zipfile.ZipFile(package, 'w') as archive:
            archive.writestr('tunnel-extra.sh', payload)
        data = package.getvalue()
        digest = hashlib.sha256(data).hexdigest()
        if case == 'checksum':
            digest = '0' * 64
        tag = 'v2.6.0' if case == 'unchanged' else 'v99.0.0'
        def local_path(value):
            path = Path(value)
            if str(path).startswith('/usr/local/bin/'):
                return root / 'bin' / path.name
            return path
        ns.update(SELF=target, ROOT=root / 'config', Path=local_path, root_required=lambda: None)
        def download(url, **kwargs):
            if case == 'network':
                raise OSError('offline')
            if url.endswith('/latest'):
                return io.BytesIO(json.dumps({'tag_name': tag}).encode())
            if url.endswith('/SHA256SUMS'):
                text = '' if case == 'missing-checksum' else f'{digest}  tuntunnel-{tag}.zip\n'
                return io.BytesIO(text.encode())
            return io.BytesIO(data)
        copy2, replace = ns['shutil'].copy2, ns['os'].replace
        def copy(src, dst, *args, **kwargs):
            if case == 'backup':
                raise OSError('backup failed')
            return copy2(src, dst, *args, **kwargs)
        def swap(src, dst):
            if case == 'replace':
                raise OSError('replace failed')
            return replace(src, dst)
        with patch.object(ns['urllib'].request, 'urlopen', download), patch.object(ns['shutil'], 'copy2', copy), patch.object(ns['os'], 'replace', swap):
            try:
                result = ns['update']()
                assert case in ('success', 'unchanged'), f'{case} was accepted'
                assert result == (case == 'success')
            except (RuntimeError, ValueError, OSError):
                assert case not in ('success', 'unchanged'), case
        if case == 'success':
            assert target.read_text() == payload
            backups = list((root / 'config/backups').glob('*/tunnel-extra.sh'))
            assert len(backups) == 1 and backups[0].read_bytes() == old
            assert binary.is_symlink() and binary.resolve() == target
            assert target.stat().st_mode & 0o111
        else:
            assert target.read_bytes() == old
            assert binary.read_bytes() == b'old compiled launcher'
        assert config.read_text() == 'preserve'
print('PASS: update, no downgrade, checksums, validation, network/backup/replace failures, aliases and config preservation')
