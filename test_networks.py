"""Run: python3 test_networks.py (no real interfaces or services changed)."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch

source = Path(__file__).with_name('tunnel-extra.sh').read_text()
python = source.split("<<'__TUNNEL_EXTRA_PY__'\n", 1)[1].rsplit('\n__TUNNEL_EXTRA_PY__', 1)[0]
ns = {'__name__': 'tuntunnel_test'}
exec(compile(python, 'tunnel-extra.sh', 'exec'), ns)

with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()) as output:
    ns['ROOT'] = Path(temp)
    calls = []
    present = set()

    def run(args, check=True, **kwargs):
        calls.append(args)
        if args[:3] == ['ip', 'link', 'show']:
            return subprocess.CompletedProcess(args, 0 if args[-1] in present else 1)
        if args[:3] == ['ip', 'link', 'del']:
            present.discard(args[-1])
        return subprocess.CompletedProcess(args, 0)

    def apply(data, role, up=True):
        present.add(ns['device'](data))

    ns.update(run=run, root_required=lambda: None, link_commands=lambda d, r: [], link_action=apply)
    for carrier in ('gre', 'vxlan', 'ipip'):
        name = 'test-' + carrier
        answers = iter([carrier, 'iran', name, '192.0.2.1', '198.51.100.2', '10.203.88.0/30', '100'] + (['4789'] if carrier == 'vxlan' else []) + ['yes'])
        with patch('builtins.input', side_effect=lambda _: next(answers)):
            ns['create_network_wizard']()
        record = Path(temp) / 'networks' / (name + '.json')
        data = json.loads(record.read_text())
        assert data['carrier'] == carrier and 'secret' not in data
        assert data in ns['list_networks']()
        # A cancelled delete must preserve both interface and record.
        with patch('builtins.input', side_effect=[name, 'no']):
            ns['delete_network']()
        assert record.exists() and ns['device'](data) in present
        # Configured tunnels must block deletion of their carrier.
        ns['all_tunnels'] = lambda: [data]
        with patch('builtins.input', side_effect=[name]):
            try:
                ns['delete_network']()
            except RuntimeError as exc:
                assert 'used by' in str(exc)
            else:
                raise AssertionError('Deleted network used by tunnel')
        ns['all_tunnels'] = lambda: []
        # A failed link deletion must retain tracking metadata.
        real_run = ns['run']
        def fail_delete(args, **kwargs):
            if args[:3] == ['ip', 'link', 'del']:
                raise RuntimeError('delete failed')
            return real_run(args, **kwargs)
        ns['run'] = fail_delete
        with patch('builtins.input', side_effect=[name, 'yes']):
            try:
                ns['delete_network']()
            except RuntimeError:
                pass
            else:
                raise AssertionError('Deletion failure ignored')
        assert record.exists()
        ns['run'] = real_run
        with patch('builtins.input', side_effect=[name, 'yes']):
            ns['delete_network']()
        assert not record.exists() and ns['device'](data) not in present
    assert not ns['saved_networks']()
    assert all(c[0] == 'ip' for c in calls)
    assert 'Deletion cancelled.' in output.getvalue()
print('PASS: GRE/VXLAN/IPIP create, list, cancel, dependency guard, failure retention, delete; no live changes')
