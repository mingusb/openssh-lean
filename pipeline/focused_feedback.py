"""Replay preserved failing C fixtures after focused compilation, for diagnosis only.

This never writes a full-build/check receipt, retires a failure, or changes a
fixture. The checked entry point supplies the lease and compiled OCaml driver.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from build_guard import need, record_child, save, sha
from workflow_feedback import excerpt

MAX_CASES = 4
TIMEOUT = 10
MAX_OUTPUT = 2 * 1024**2
SCOPE = ('Focused OCaml diagnostic only. No Lean execution, full regression, '
         'import gain or repaired behavior is established. Required checks are unchanged.')


def read_checked(path, digest, root):
    path = Path(path)
    need(path.resolve().is_relative_to(root.resolve()) and not path.is_symlink(),
         'Focused diagnostic receipt escapes runtime')
    need(path.stat().st_size <= 128 * 1024**2 and sha(path) == digest,
         'Focused diagnostic receipt identity changed')
    return json.loads(path.read_text())


def candidates(workspace, runtime):
    """Use exact preserved observations, not guessed case paths or shell commands."""
    from run_pointer_check_plan import check_scripts, report_cases
    index = runtime/'logs/latest-check-feedback.json'
    if not index.exists():
        return [], ['No preserved check feedback yet.']
    plan = json.loads((workspace/'work/pointer-check-plan.json').read_text())
    check_scripts(workspace, plan)
    steps = {step['id']: step for step in plan['steps']}
    chosen, skipped = [], []
    for ref in json.loads(index.read_text())['summaries']:
        if not ref.get('identity_checks_complete'):
            skipped.append('Incomplete check identities: '+ref['path'])
            continue
        summary = read_checked(ref['path'], ref['sha256'], runtime)
        chain = read_checked(summary['receipt'], summary['receipt_sha256'], runtime)
        completed = {row['id']: row for row in chain['completed']}
        for suite in summary['suites']:
            names = {row['case'] for row in suite.get('failures', [])}
            if not names:
                continue
            step = steps.get(suite['id'])
            if step is None:
                skipped.append(suite['id']+': no single-C-fixture replay adapter')
                continue
            report = read_checked(suite['receipt'], completed[suite['id']]['result_sha256'], runtime)
            # Wrapper suites record their own entrypoint and the shared runner
            # separately. Verify both against current checked files.
            harness_matches = report.get('test_script_sha256') == step['script_sha256']
            if 'entrypoint_sha256' in report:
                helper_hash = plan.get('current_helper_sha256', {}).get(
                    'work/check_opaque_extent_review.py')
                harness_matches = (helper_hash is not None
                    and report.get('entrypoint_sha256') == step['script_sha256']
                    and report.get('test_script_sha256') == helper_hash)
            if (report.get('native_only') or report.get('artifact_hashes_verified') is not True
                    or not harness_matches):
                skipped.append(suite['id']+': changed harness or incomplete fixture evidence')
                continue
            for row in report_cases(report, step.get('case_groups')):
                name = row.get('case', row.get('name'))
                if name not in names:
                    continue
                text = row.get('source_text')
                engine = row.get('engines', {}).get('ocaml-core-typed') or row.get('engines', {}).get('ocaml')
                if (not isinstance(text, str) or len(text.encode()) > 1024**2 or not engine
                        or row.get('preprocessor') is not None):
                    skipped.append(suite['id']+'/'+name+': fixture needs its original harness')
                    continue
                need(hashlib.sha256(text.encode()).hexdigest() == row.get('source_sha256'),
                     'Preserved diagnostic fixture bytes changed: '+name)
                # Accept only the known ordinary C runner profile. Never execute
                # an arbitrary command or preprocessor taken from a report.
                args = engine.get('arguments', [])
                fixed = {'--nolibc', '--typecheck-core', '--exec', '--batch', '--mode=exhaustive'}
                if (len(args) < 3 or Path(args[0]) != runtime/'cerberus-lean/_build/default/backend/driver/main.exe'
                        or any(arg not in fixed and arg != '--runtime='+str(runtime/'cerberus-lean/_build/install/default')
                               for arg in args[1:-1])):
                    skipped.append(suite['id']+'/'+name+': unsupported recorded execution profile')
                    continue
                wrong_result = (engine.get('exit_code') == 0
                    and engine.get('timeout') is False
                    and engine.get('expected_result_matched') is False
                    and isinstance(engine.get('stdout'), str)
                    and engine['stdout'].lstrip().startswith('Defined '))
                chosen.append((0 if wrong_result else 1, dict(suite=suite['id'],
                    case=name, source_text=text, source_sha256=row['source_sha256'],
                    nolibc='--nolibc' in args, original_receipt=suite['receipt'],
                    original_receipt_sha256=completed[suite['id']]['result_sha256'])))
    # Completed wrong answers are the first diagnostic priority. Preserve order
    # within each class and keep every deferred case outstanding.
    chosen = [row for _, row in sorted(chosen, key=lambda item: item[0])]
    if len(chosen) > MAX_CASES:
        skipped.extend(row['suite']+'/'+row['case']+': deferred by diagnostic budget; still required'
                       for row in chosen[MAX_CASES:])
    return chosen[:MAX_CASES], skipped


def bounded_capture(command, directory, runtime):
    """One bounded attempt, with terminal children and lossless capped output."""
    sys.path.insert(0, str(Path(__file__).parent/'cerberus-lean/scripts'))
    from process_scope import ProcessScope
    output = directory/'trace.log'
    started = time.monotonic()
    reason = None
    limiter = ('import os,resource,sys; limit=int(sys.argv[1]); '
               'resource.setrlimit(resource.RLIMIT_FSIZE,(limit,limit)); '
               'os.execv(sys.argv[2],sys.argv[2:])')
    with output.open('wb') as stream:
        scope = ProcessScope(directory)
        try:
            child = scope.start([sys.executable, '-c', limiter, str(MAX_OUTPUT), *command],
                stdout=stream, stderr=subprocess.STDOUT, cwd=runtime/'cerberus-lean', env=dict(os.environ))
            record_child(child, runtime)
            record_child(scope.guardian, runtime)
            while True:
                try:
                    scope.wait(0.05)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if time.monotonic()-started >= TIMEOUT:
                    reason = 'diagnostic-timeout'
                    break
                if output.stat().st_size >= MAX_OUTPUT:
                    reason = 'diagnostic-output-limit'
                    break
        finally:
            residual = scope.finish(cancel=reason is not None)
            if residual and reason is None:
                reason = 'diagnostic-residual-descendants'
    with output.open('rb') as stream:
        data = stream.read(MAX_OUTPUT)
    if output.stat().st_size >= MAX_OUTPUT:
        reason = reason or 'diagnostic-output-limit'
    lines = data.decode('utf-8', errors='replace').splitlines()
    # Keep each distinct decision, rather than repeating the whole trace.
    decisions = list(dict.fromkeys(line[:1200] for line in lines if
        ('GNU ' in line or 'Error' in line or 'error:' in line)))
    return dict(exit_code=child.returncode, inconclusive=reason,
        containment_cleaned=scope.closed,
        elapsed_seconds=round(time.monotonic()-started, 2), trace=str(output), trace_sha256=sha(output),
        diagnostic=excerpt({'stdout': '\n'.join(lines)}), decisions=decisions[-16:])



def ocaml_artifact_identity(repo):
    """Bind every input used by OCaml diagnostics; no Lean execution is claimed."""
    installed = repo/'_build/install/default'
    roots = [installed/'lib'/name/'runtime'
             for name in ('cerberus-lib', 'cerberus', 'cerberus-bmc')]
    need(roots[0].is_dir(), 'Focused OCaml installed runtime directory missing')
    return dict(
        parser_binary_sha256=sha(repo/'_build/default/backend/driver/main.exe'),
        lean_binary_sha256=None,
        installed_runtime_sha256={
            str(path.relative_to(installed)): sha(path)
            for root in roots for path in sorted(root.rglob('*')) if path.is_file()})


def replay(workspace, runtime, out, selected, skipped, source_identity):
    root = out/'focused-diagnostics'
    root.mkdir()
    repo = runtime/'cerberus-lean'
    driver = repo/'_build/default/backend/driver/main.exe'
    sys.path.insert(0, str(workspace/'outputs/openssh-lean/scripts'))
    need(candidates(workspace, runtime) == (selected, skipped), 'Focused diagnostic selection changed')
    before = dict(source=source_identity(), artifacts=ocaml_artifact_identity(repo),
                  helper_sha256=sha(Path(__file__)))
    report = dict(scope=SCOPE, required_checks_satisfied=False, identity_before=before,
                  budget=dict(max_cases=MAX_CASES, seconds_per_case=TIMEOUT, output_bytes=MAX_OUTPUT),
                  skipped=skipped, cases=[])
    for index, case in enumerate(selected):
        folder = root/str(index)
        folder.mkdir()
        source = folder/'case.c'
        source.write_text(case['source_text'], encoding='utf-8')
        need(sha(source) == case['source_sha256'], 'Diagnostic source changed while writing')
        command = [str(repo/'scripts/capped'), str(driver), '--runtime='+str(repo/'_build/install/default')]
        if case['nolibc']:
            command.append('--nolibc')
        command += ['--debug=2', '--typecheck-core', '--exec', '--mode=exhaustive', '--batch', str(source)]
        result = bounded_capture(command, folder, runtime)
        need(sha(source) == case['source_sha256'], 'Diagnostic fixture changed during execution')
        row = {key: value for key, value in case.items() if key != 'source_text'}
        row.update(result)
        report['cases'].append(row)
        print(json.dumps(dict(focused_diagnostic=row, scope=SCOPE)), flush=True)
    report['identity_after'] = dict(source=source_identity(), artifacts=ocaml_artifact_identity(repo),
                                    helper_sha256=sha(Path(__file__)))
    need(candidates(workspace, runtime) == (selected, skipped), 'Focused diagnostic selection changed during replay')
    report['identity_verified'] = before == report['identity_after']
    save(root/'result.json', report)
    need(report['identity_verified'], 'Focused diagnostic inputs changed during replay')
    compact = dict(receipt=str(root/'result.json'), receipt_sha256=sha(root/'result.json'),
                   source_identity=before['source'], scope=SCOPE, required_checks_satisfied=False,
                   cases=[{key: row[key] for key in ('suite', 'case', 'exit_code', 'inconclusive', 'diagnostic', 'decisions')}
                          for row in report['cases']], skipped=skipped)
    save(runtime/'logs/latest-focused-feedback.json', compact)
    return compact
