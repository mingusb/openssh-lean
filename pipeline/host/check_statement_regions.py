"""Run the prebuilt direct Core region controls, bound to the successful build."""
import argparse
import json
import os
from pathlib import Path
import sys

from exact_float_publication import ENVIRONMENT, dependencies
from exercise_imported_c import invoke
from varargs_publication import check_capture, check_command, identity_snapshot, need, read, sha

WORKSPACE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(WORKSPACE/'work'))
from run_pointer_check_plan import check_build
from build_guard import workflow_lock

DIRECT = 'statement-region-model-check'
BINARY = 'lean_frontend/.lake/build/bin/statement-region-test'
SOURCE = 'lean_frontend/test/Unit/StatementRegionTest.lean'
CONTROLS = (
    'active region path is innermost first',
    'call frame hides caller regions',
    'jump helper preserves current region',
    'jump helper leaves inner region',
    'jump helper leaves all regions',
    'inactive region is refused',
    'sibling region is refused',
    'missing outer path is refused',
    'callee cannot enter caller region',
    'same-region transfer preserves environment',
    'outward transfer preserves enclosing region',
    'fully outward transfer restores procedure frame',
    'entry is a scheduling barrier and preserves environment',
    'completion restores saved context and environment',
    'nested region continuation path',
    'closed region label under nondeterministic choice',
    'measured collector visits nondeterministic choice',
    'ordinary unsupported choice label is not invented',
    'full-expression boundary retains closed region',
    'spawned thread starts an independent region path',
    'repeated Core display names have distinct lexical identities',
)
EXPECTED = ''.join('PASS '+name+'\n' for name in CONTROLS)+'Statement regions: 21 checks passed\n'


def command(repo):
    return [str(repo/BINARY), '17']


def snapshot(workspace, repo):
    build_path = repo.parent/'logs/whole-table-build.json'
    build = check_build(workspace, repo.parent, sha(build_path))
    need(build['outputs'].get(BINARY) == sha(repo/BINARY), 'region test binary bound to successful build')
    need(build['inputs_after']['mirrored_source'].get(SOURCE) == sha(repo/SOURCE),
         'region test source bound to successful build')
    project = workspace/'outputs/openssh-lean'
    lean = workspace/'work/lean-4.32.2-linux/bin/lean'
    files = [build_path, repo/BINARY, repo/SOURCE, workspace/'work/cerberus-lean'/SOURCE,
             project/'scripts/check_statement_regions.py', project/'scripts/varargs_publication.py',
             project/'scripts/exact_float_publication.py', project/'scripts/exercise_imported_c.py',
             workspace/'work/run_pointer_check_plan.py', lean, repo/'scripts/capped']
    with workflow_lock(repo.parent):
        compiled = dependencies(repo, lean, ('Unit.StatementRegionTest',),
            cache_path=repo.parent/'logs/statement-region-dependencies.json')
    return {'runtime': identity_snapshot(repo), 'files': {str(path): sha(path) for path in files},
            'compiled_dependencies': compiled}


def matches(result):
    return (result['exit_code'] == 0 and result['timeout'] is False and
            result['stdout'] == EXPECTED and result['stderr'] == '')


def validate_direct_regions(report, workspace, repo, directory):
    need(report['passed'] is True and report['full_suite'] is True and report['native_only'] is False,
         'complete direct region controls required')
    need(report['required_environment'] == ENVIRONMENT and report['cwd'] == str(repo/'lean_frontend'),
         'direct region resource/panic policy and working directory')
    need(report['artifact_hashes_verified'] is True and
         report['identity_before'] == report['identity_after'] == snapshot(workspace, repo),
         'direct region current binary, source, dependencies and successful build')
    need(len(report['cases']) == 1 and report['cases'][0]['case'] == 'StatementRegionTest',
         'exact direct region suite')
    row = report['cases'][0]
    check_capture(row, directory, 'StatementRegionTest', 'lean')
    check_command(row, command(repo), 'direct region command and explicit fuel')
    need(row['timeout_seconds'] == 120 and row['source_sha256'] == sha(repo/SOURCE),
         'direct region timeout and source')
    need(row['passed'] is True and matches(row), 'all 21 direct region controls')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cerberus', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'linux' or any(os.environ.get(key) != value for key, value in ENVIRONMENT.items()):
        parser.error('Run in WSL under the exact 4G/two-thread/abort-on-panic environment')
    repo, out = args.cerberus.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = dict(passed=False, full_suite=False, native_only=False, artifact_hashes_verified=False,
                  required_environment=ENVIRONMENT, cwd=str(repo/'lean_frontend'), cases=[])
    try:
        before = snapshot(WORKSPACE, repo)
        report['identity_before'] = before
        stdout, stderr = (out/('StatementRegionTest.lean.'+stream) for stream in ('stdout', 'stderr'))
        result = invoke(command(repo), stdout, stderr, repo/'lean_frontend', 120)
        result.update(stdout=stdout.read_text(encoding='utf-8', errors='replace'),
                      stderr=stderr.read_text(encoding='utf-8', errors='replace'), timeout_seconds=120)
        row = dict(result, case='StatementRegionTest', source_sha256=sha(repo/SOURCE), passed=matches(result))
        report['cases'].append(row)
        after = snapshot(WORKSPACE, repo)
        report.update(identity_after=after, full_suite=True, artifact_hashes_verified=before == after,
                      passed=before == after and row['passed'])
    except (OSError, ValueError, KeyError, TypeError) as error:
        report['error'] = str(error)
    report['scope'] = 'Finite direct Core controls; source constraints and nondeterministic outcome sets are checked separately.'
    (out/'result.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'passed': report['passed'], 'controls': len(CONTROLS)}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
