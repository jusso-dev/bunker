#!/usr/bin/env python3
"""Exercise the user restore procedure using disposable data and ephemeral credentials."""
import argparse
import json
import os
import pathlib
import secrets
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=pathlib.Path, required=True)
    args = parser.parse_args()
    binary = str(args.binary.resolve(strict=True))
    env = os.environ.copy()
    env['BUNKER_PASSPHRASE'] = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix='bunker-runbook-') as directory:
        root = pathlib.Path(directory)
        work, repo = root / 'workspace', root / 'repository'
        work.mkdir()
        note = work / 'notes.txt'
        note.write_bytes(b'first version\n')

        def run(*arguments, repository=repo, success=True):
            result = subprocess.run([binary, '--repo', str(repository), *map(str, arguments)],
                                    env=env, capture_output=True, text=True, timeout=120)
            if success and result.returncode != 0:
                raise RuntimeError(f'Runbook step {arguments[0]} failed (output withheld)')
            if not success and result.returncode == 0:
                raise RuntimeError(f'Runbook step {arguments[0]} unexpectedly succeeded')
            return result.stdout

        run('init')
        snapshot = json.loads(run('snapshot', '--workspace', work))['id']
        assert any(item['id'] == snapshot for item in json.loads(run('list')))
        note.write_bytes(b'changed version\n')
        plan = json.loads(run('diff', snapshot, '--workspace', work))
        run('restore', snapshot, '--workspace', work)
        assert note.read_bytes() == b'changed version\n', 'preview must not modify files'
        note.write_bytes(b'changed after preview\n')
        run('restore', snapshot, '--workspace', work, '--confirm', plan['confirmation'], success=False)
        assert note.read_bytes() == b'changed after preview\n', 'stale approval must not write'
        plan = json.loads(run('diff', snapshot, '--workspace', work))
        run('restore', snapshot, '--workspace', work, '--confirm', plan['confirmation'])
        assert note.read_bytes() == b'first version\n', 'restored bytes differ'
        assert json.loads(run('verify', snapshot))['verified'] is True
        report = json.loads(run('restore-test', snapshot))
        assert report['file_integrity'] == 'passed'
        assert report['agent_boot'] == 'not_run' and report['mcp_connectivity'] == 'not_run'
        remote = root / 'secondary-copy'
        remote.mkdir()
        storage = root / 'storage.toml'
        storage.write_text('service = "local"\n[options]\nroot = ' + json.dumps(str(remote)) + '\n', encoding='utf-8')
        replication = json.loads(run('replicate', '--storage', storage))
        assert replication['immutable'] is False
        recovered = root / 'recovered-repository'
        run('recover', '--storage', storage, '--namespace', replication['namespace'], repository=recovered)
        assert json.loads(run('verify', snapshot, repository=recovered))['verified'] is True
        destination = root / 'recovered-workspace'
        destination.mkdir()
        recovery_plan = json.loads(run('diff', snapshot, '--workspace', destination, repository=recovered))
        run('restore', snapshot, '--workspace', destination, '--confirm', recovery_plan['confirmation'], repository=recovered)
        assert (destination / 'notes.txt').read_bytes() == b'first version\n'
    print(json.dumps({'runbook': 'passed', 'preview_no_write': True, 'stale_confirmation_rejected': True,
                      'restored_bytes_match': True, 'local_replication_recovery': 'passed',
                      'agent_boot': 'not_run', 'mcp_connectivity': 'not_run', 'live_cloud_providers': 'not_run'}))


if __name__ == '__main__':
    main()
