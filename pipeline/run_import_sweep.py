"""Run the existing full pinned-input importer under the shared workflow lease."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess

from build_guard import WORKSPACE, RUNTIME, workflow_lock, verify_tools, record_child, sha, save, need
from run_pointer_check_plan import check_build


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--blocker', type=int, action='append', default=[])
    parser.add_argument('--unit', action='append', default=[])
    parser.add_argument('--parser-only', action='store_true',
                        help='Refresh all Cabs parser outputs without Lean elaboration')
    args = parser.parse_args()
    repo = RUNTIME/'cerberus-lean'
    project = WORKSPACE/'outputs/openssh-lean'
    with workflow_lock():
        verify_tools()
        build_hash = sha(RUNTIME/'logs/whole-table-build.json')
        check_build(WORKSPACE, RUNTIME, build_hash)
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        out = RUNTIME/'logs'/('import-sweep-'+stamp)
        out.mkdir()
        chosen = None
        if args.parser_only and (args.blocker or args.unit):
            raise ValueError('Parser-only refresh must cover the full configured census')
        if args.blocker or args.unit:
            from import_feedback import selection
            units, chosen = selection(WORKSPACE, RUNTIME, args.blocker, args.unit)
            need(units, 'Targeted import selection is empty')
        inputs = [project/'scripts/import_c.py', project/'scripts/preprocessed_input.py',
                  RUNTIME/'c-import/census.json', project/'evidence/ssh-dependencies.json']
        if chosen:
            inputs += [Path(chosen['inventory']), Path(chosen['baseline_report']), WORKSPACE/'work/import_feedback.py']
        before = {str(path): sha(path) for path in inputs}
        command = [str(repo/'scripts/capped'), 'python3', str(project/'scripts/import_c.py'),
                   '--census', str(RUNTIME/'c-import/census.json'), '--cerberus', str(repo),
                   '--output', str(out/'targeted' if chosen else RUNTIME/'import-fork'),
                   '--gnu-pointer-conversions',
                   '--priority-inventory', str(project/'evidence/ssh-dependencies.json'),
                   '--jobs', '12']
        if not args.parser_only:
            command += ['--lean', '--inventory',
                        str(out/'targeted-blockers.json' if chosen else project/'evidence/compilation-blockers.json')]
        if chosen:
            for unit in units:
                command += ['--source', unit['source']]
        receipt = dict(terminal=False, command=command, build_receipt_sha256=build_hash, selection=chosen,
                       inputs_before=before, scope=('Full configured Cabs parser refresh only; no Lean elaboration, execution or equivalence claim.'
                           if args.parser_only else
                           'Selected TUs only; complete census is unchanged. No execution/equivalence claim.'
                           if chosen else 'Full configured C import only; no execution/equivalence claim.'))
        save(out/'result.json', receipt)
        env = dict(os.environ, CERB_MEM_MAX='none', LEAN_NUM_THREADS='2', LEAN_ABORT_ON_PANIC='1')
        with (out/'import.log').open('w') as log:
            process = subprocess.Popen(command, cwd=repo, env=env, stdout=log, stderr=subprocess.STDOUT)
            record_child(process)
            receipt['pid'] = process.pid
            save(out/'result.json', receipt)
            print(json.dumps(dict(pid=process.pid, receipt=str(out/'result.json'))), flush=True)
            status = process.wait()
        after = {str(path): sha(path) for path in inputs}
        check_build(WORKSPACE, RUNTIME, build_hash)
        receipt.update(terminal=True, exit_code=status, inputs_after=after,
                       unchanged=before == after, log_sha256=sha(out/'import.log'))
        save(out/'result.json', receipt)
        need(before == after, 'Sweep inputs changed during execution.')
        print((out/'import.log').read_text(), flush=True)
        return status


if __name__ == '__main__':
    raise SystemExit(main())
