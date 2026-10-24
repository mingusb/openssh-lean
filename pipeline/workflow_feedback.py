"""Derived, bounded diagnostics from existing receipts; never an acceptance gate.

No test outcomes, source, inventories or expectations are changed here.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path

from build_guard import need, save, sha

CURRENT_START = '<!-- checked-workflow-current-state:start -->'
CURRENT_END = '<!-- checked-workflow-current-state:end -->'


def write_continuation(workspace, snapshot):
    """Refresh observable state, preserving every manually maintained repair note."""
    path = workspace/'outputs/openssh-lean/EXPERIMENT.md'
    original = path.read_text(encoding='utf-8')
    if CURRENT_START in original:
        need(original.startswith(CURRENT_START) and original.count(CURRENT_START) == 1
             and original.count(CURRENT_END) == 1, 'Invalid automatic continuation markers')
        history = original.split(CURRENT_END, 1)[1].lstrip('\n')
    else:
        history = '## Preserved repair notes and history\n\n'+original
    operation = snapshot.get('last_operation', {})
    build = snapshot.get('build', {})
    census = snapshot.get('import', {})
    checks = snapshot.get('last_checks', {})
    lines = [CURRENT_START, '# Current state (maintained automatically)', '',
             'Proof-only workspace: native C executes OpenSSH; Lean supplies model reasoning and source correspondence.',
             'Whole-program Lean execution and CRIU replay are retired. Older runtime notes are historical.',
             'These observations come from checked workflow receipts; they are not equivalence proofs.', '',
             '- Last operation: '+str(operation.get('operation'))+' / '+str(operation.get('status'))+
             '; receipt `'+str(operation.get('receipt'))+'`.',
             '- Full build matches current sources: '+str(build.get('matches_current_sources', False))+'.']
    if build.get('receipt_sha256'):
        lines.append('- Build receipt SHA-256: `'+build['receipt_sha256']+'`.')
    models = snapshot.get('models')
    if models:
        if models.get('error'):
            lines.append('- Current model archive requires attention: '+models['error']+'.')
        else:
            lines.append('- Single maintained model set: '+str(models['targets'])+' tools at `'+
                models['archive']+'`; manifest `'+models['manifest_sha256']+
                '`. Initial archive verification passed: '+str(models['initial_verification_passed'])+
                '; producer matches current binaries: '+str(models['producer_matches_current_binaries'])+
                '. Reading models does not require translation or execution. This status reads metadata; '
                'use the archive verifier for fresh payload hashes.')
    if census:
        total = census.get('stage_counts', {}).get('lean_attempted', 'unknown')
        ssh_total = sum(value for name, value in census['ssh_counts'].items() if name.startswith('lean_'))
        lines.append('- Last complete import `'+str(census.get('run_id'))+'`: '+
            str(census['counts'].get('lean_elaborated', 0))+'/'+str(total)+'; ssh '+
            str(census['ssh_counts'].get('lean_elaborated', 0))+'/'+str(ssh_total)+'. Matches current full build: '+
            str(census.get('matches_current_build', False))+'. Translation counts are not behavior coverage.')
    for group in checks.get('summaries', []):
        for suite in group.get('suites', []):
            lines.append('- Last checked `'+suite['id']+'`: '+json.dumps(suite.get('counts', {}), sort_keys=True)+
                '; matches current full build: '+str(checks.get('matches_current_build', False))+
                '; unresolved: '+', '.join(suite.get('failed_cases', []))+'.')
    cohort = snapshot.get('focused_import_feedback')
    if cohort:
        lines.append('- Latest OCaml TU replay: `'+cohort['receipt']+'`; batch '+
            json.dumps(cohort.get('counts', {}),sort_keys=True)+'; last observed whole-table '+
            json.dumps(cohort.get('cumulative_counts', {}),sort_keys=True)+
            '; older-source observations: '+str(cohort.get('stale_source_observations', 'unknown'))+
            '. This is not a Lean pass.')
    focused = snapshot.get('focused_diagnostics')
    if focused:
        lines.append('- Latest focused diagnostic: `'+focused['receipt']+'`; matches current sources: '+
            str(focused.get('matches_current_sources', False))+'. '+focused['scope'])
    lines += ['', 'Semantic repair notes remain manual; this block never discharges a blocker.', CURRENT_END, '', history]
    temporary = path.with_suffix('.md.tmp')
    temporary.write_text('\n'.join(lines), encoding='utf-8')
    os.replace(temporary, path)
    ledger = workspace/'work/pointer-repairs95830.json'
    data = json.loads(ledger.read_text())
    # A derived observation alongside, not a replacement for, semantic rows.
    data['workflow_observation'] = {key: snapshot[key] for key in
        ('last_operation', 'build', 'models', 'import', 'last_checks', 'focused_diagnostics', 'focused_import_feedback') if key in snapshot}
    save(ledger, data)


def excerpt(result):
    text = result.get('stderr') or result.get('stdout') or ''
    lines = str(text).splitlines()
    relevant = [line for line in lines if any(word in line.lower() for word in
                ('error', 'unsupported', 'timeout', 'exception', 'mismatch', 'failed'))]
    return '\n'.join(relevant or lines[:8])[:1200]


def case_summary(report, previous=None, groups=None):
    from run_pointer_check_plan import report_cases
    cases = report_cases(report, groups)
    cases = [row for row in cases if isinstance(row, dict)]
    old = {row.get('case', row.get('name')): row for row in report_cases(previous or {}, groups)
           if isinstance(row, dict)}
    counts = dict(passed=0, failed=0, inconclusive=0)
    changes = dict(improved=[], regressed=[], unchanged_failure=[], new_or_changed=[])
    failures = []
    same_profile = bool(previous and report.get('native_only', False) == previous.get('native_only', False)
                        and report.get('native_compiler_binary_sha256')
                        and report.get('native_compiler_binary_sha256') == previous.get('native_compiler_binary_sha256')
                        and report.get('compiler') == previous.get('compiler'))
    for row in cases:
        name = row.get('case', row.get('name', '?'))
        outcome = row.get('passed')
        counts['passed' if outcome is True else 'failed' if outcome is False else 'inconclusive'] += 1
        prior = old.get(name)
        expected_keys = {key for key in row if key.startswith('expected_')}
        def flags(case):
            return [arg for arg in case.get('compile', {}).get('arguments', []) if arg.startswith('-')]
        comparable = (same_profile and prior and bool(row.get('source_sha256')) and expected_keys
                      and row['source_sha256'] == prior.get('source_sha256')
                      and expected_keys == {key for key in prior if key.startswith('expected_')}
                      and all(row[key] == prior[key] for key in expected_keys) and flags(row) == flags(prior))
        if not comparable:
            changes['new_or_changed'].append(name)
        elif outcome is True and prior.get('passed') is False:
            changes['improved'].append(name)
        elif outcome is not True and prior.get('passed') is True:
            changes['regressed'].append(name)
        elif outcome is not True and prior.get('passed') is not True:
            changes['unchanged_failure'].append(name)
        if outcome is True:
            continue
        observations = []
        for phase in ('compile', 'native', 'parser'):
            result = row.get(phase)
            if not isinstance(result, dict):
                continue
            bad = (result.get('timeout') or result.get('exit_code') not in (None, 0)
                   if phase != 'native' else row.get('native_expectation_matched') is False)
            if bad:
                observations.append(dict(phase=phase, timeout=result.get('timeout'),
                    exit_code=result.get('exit_code'), diagnostic=excerpt(result)))
        engines = row.get('engines', {})
        for phase, result in (engines.items() if isinstance(engines, dict) else []):
            if isinstance(result, dict) and result.get('status') != 'matched':
                observations.append(dict(phase=phase, status=result.get('status'),
                    timeout=result.get('timeout'), exit_code=result.get('exit_code'), diagnostic=excerpt(result)))
        failures.append(dict(case=name, observations=observations,
            next_action='Inspect the exact failed observation and repair its cause; preserve the expected outcome.'
                        if observations else 'Inspect this case in the linked authoritative receipt; its schema has no recognized diagnostic fields.'))
    return dict(counts=counts, changes=changes, failures=failures,
                scope='Case flags and comparable observations only; neither behavioral coverage nor proof of correctness.')


def prior_report(directory):
    index_path = directory/'archive-index.json'
    if not index_path.exists():
        return None
    index = json.loads(index_path.read_text())
    item = next((row for row in index['files'] if row['path'] == 'result.json'), None)
    if not item:
        return None
    path = directory/item['stored_path']
    need(path.resolve().is_relative_to(directory.resolve()) and not path.is_symlink(), 'Invalid archived report path')
    need(sha(path) == item['stored_sha256'], 'Archived report bytes changed')
    opener = gzip.open if item['encoding'] == 'gzip' else open
    with opener(path, 'rb') as stream:
        data = stream.read(128*1024**2+1)
    need(len(data) == item['bytes'] and len(data) <= 128*1024**2
         and hashlib.sha256(data).hexdigest() == item['sha256'], 'Archived report identity changed')
    return json.loads(data)


def summarize_chain(directory):
    directory = Path(directory)
    path = directory/'result.json'
    chain = json.loads(path.read_text())
    plan_path = directory/'plan.json'
    steps = json.loads(plan_path.read_text()).get('steps', []) if plan_path.exists() else chain.get('plan', [])
    groups = {step['id']:step.get('case_groups') for step in steps}
    integrity = bool(chain.get('status') == 'terminal' and chain.get('identity_before')
                     and chain.get('identity_before') == chain.get('identity_after'))
    summary = dict(receipt=str(path), receipt_sha256=sha(path),
        build_receipt_sha256=chain.get('build_receipt_sha256'), identity_checks_complete=integrity,
        suites=[], scope='Derived diagnostic index. Original reports and publication gates remain authoritative.')
    for row in chain.get('completed', []):
        name = row['id']
        need(Path(name).name == name and name not in ('.', '..'), 'Invalid suite name')
        copied = directory/(name+'.result.json')
        suite = dict(id=name, receipt=str(copied), exit_code=row.get('exit_code'),
                     report_passed=row.get('report_passed', row.get('passed')),
                     required_report_valid=row.get('required_report_valid', row.get('passed')),
                     expected_case_count=row.get('expected_case_count'))
        try:
            need(copied.exists() and sha(copied) == row.get('result_sha256'), 'Missing or changed suite receipt')
            report = json.loads(copied.read_text())
            previous = prior_report(directory/'prior'/name)
            # Incomplete/stale identities cannot establish an improvement.
            verified = integrity and report.get('artifact_hashes_verified', True) is True
            suite.update(case_summary(report, previous if verified else None, groups.get(name)))
            suite['harness_scope'] = report.get('scope')
            suite['comparison_identity_checked'] = verified
            suite['previous_execution_identity'] = {key: previous.get(key) for key in
                ('parser_binary_sha256', 'lean_binary_sha256', 'installed_runtime_sha256')} if previous else None
            suite['attribution'] = 'Changes are between these receipts, not attributed to the latest edit or model.'
        except (OSError, ValueError, KeyError, RuntimeError, TypeError) as error:
            suite.update(diagnostic_unavailable=str(error), next_action='Inspect the preserved authoritative receipt; do not infer a pass.')
        summary['suites'].append(suite)
    output = directory/'diagnostics.json'
    save(output, summary)
    compact = []
    for suite in summary['suites']:
        row = {key: suite[key] for key in ('id', 'counts', 'required_report_valid', 'expected_case_count',
                                          'diagnostic_unavailable') if key in suite}
        row['change_counts'] = {key:len(value) for key,value in suite.get('changes', {}).items()}
        row['failed_cases'] = [failure['case'] for failure in suite.get('failures', [])]
        compact.append(row)
    return dict(path=str(output), sha256=sha(output), build_receipt_sha256=chain.get('build_receipt_sha256'),
                identity_checks_complete=integrity,
                suites=compact)
