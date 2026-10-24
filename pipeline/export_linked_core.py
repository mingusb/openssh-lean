#!/usr/bin/env python3
"""Run the pinned 90-input ssh linked-Core data export under the checked lease.

This exports the complete linked Core record. It does not certify that Core,
the host adapters, or the pinned C executable are behaviorally equivalent.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = Path(__file__).resolve().parents[1] / "local/runtime"
sys.path.insert(0, str(ROOT / 'work'))
sys.path.insert(0, str(ROOT / 'work/cerberus-lean/scripts'))
import build_guard
from run_pointer_check_plan import check_build


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def delegated_scope():
    current = next((line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines()
                    if line.startswith('0::')), None)
    if not current or current == '/':
        return False
    parent = (Path('/sys/fs/cgroup') / current.lstrip('/')).parent
    return os.access(parent, os.W_OK) and 'memory' in (parent / 'cgroup.subtree_control').read_text().split()


def export_argv(binding_path, output, binding, *, runnable=False):
    prior = binding['lean_argv']
    need(prior[0] == binding['translator']['path'], 'Binding names a different translator')
    filtered = []
    index = 1
    while index < len(prior):
        option = prior[index]
        if option == '--pp-core':
            index += 1
        elif option in ('--host-abi', '--args'):
            need(index + 1 < len(prior), f'Missing value after {option}')
            index += 2
        else:
            filtered.append(option)
            index += 1
    mode = '--emit-core-data' if runnable else '--emit-linked-core-snapshot'
    return [prior[0], mode, str(binding_path), str(output), *filtered]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binding', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not delegated_scope():
        os.execvp('systemd-run', ['systemd-run', '--user', '--scope',
                  sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]])
    binding_path = args.binding.resolve(strict=True)
    output = args.output.absolute()
    need(binding_path.parent == RUNTIME and output.parent == RUNTIME and
         output != binding_path and not output.exists() and not output.is_symlink(),
         'Use a fresh direct child of the runtime directory for the output')
    receipt_path = RUNTIME / (output.name + '.receipt.json')
    run_dir = RUNTIME / (output.name + '.run')
    need(not receipt_path.exists() and not run_dir.exists(), 'Export receipt or run directory already exists')
    with build_guard.workflow_lock():
        build_guard.verify_tools()
        build_receipt = RUNTIME / 'logs/whole-table-build.json'
        check_build(ROOT, RUNTIME, sha(build_receipt))
        binding = json.loads(binding_path.read_bytes())
        need(binding['scope'] == 'configured-ssh-link-input-provenance' and
             binding['receipt_mode'] == 'ssh-inputs-only' and
             binding['input_provenance_verified'] is True and
             len(binding['frontend_order']) == 90 and
             len(binding['libc']['metadata_order']) == 12,
             'Binding does not identify the pinned 90-input ssh closure')
        need(sha(binding['translator']['path']) == binding['translator']['sha256'],
             'Translator differs from the source binding')
        command = export_argv(binding_path, output, binding)
        run_dir.mkdir()
        report = {'terminal': False, 'passed': False,
                  'scope': 'all data fields of the ordinary linked Core record; not OpenSSH behavioral equivalence',
                  'binding': str(binding_path), 'binding_sha256': sha(binding_path),
                  'build_receipt_sha256': sha(build_receipt), 'argv': command,
                  'output': str(output)}
        receipt_path.write_text(json.dumps(report, indent=2) + '\n')
        scope = None
        try:
            with (run_dir / 'stdout.log').open('wb') as stdout, (run_dir / 'stderr.log').open('wb') as stderr:
                from process_scope import ProcessScope
                scope = ProcessScope(run_dir / 'process')
                proc = scope.start(command, cwd=ROOT, env=dict(os.environ, LEAN_ABORT_ON_PANIC='1'),
                                   stdout=stdout, stderr=stderr)
                code = proc.wait()  # The operator requires no artificial timeout.
                residual = scope.finish()
            report.update(terminal=True, exit_code=code, residual_processes=residual,
                          output_present=output.is_file(),
                          output_sha256=sha(output) if output.is_file() else None,
                          output_bytes=output.stat().st_size if output.is_file() else None,
                          passed=code == 0 and not residual and output.is_file() and
                          sha(binding_path) == report['binding_sha256'] and
                          sha(binding['translator']['path']) == binding['translator']['sha256'])
        except BaseException as exc:
            if scope is not None:
                scope.finish(cancel=True)
            report.update(terminal=True, error=str(exc))
            raise
        finally:
            receipt_path.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': report['passed'], 'receipt': str(receipt_path),
                          'output_bytes': report.get('output_bytes')}))
        return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
