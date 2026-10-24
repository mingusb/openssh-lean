"""Required current-artifact publication checks for GNU variadic execution.

Publication requires current complete execution evidence, never native-only
observations or a successful parser/import. This module starts no processes.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

ENGINES = {'ocaml', 'ocaml-core-typed', 'lean'}
SUITES = {
    'gnu-varargs-abi-check': ('scripts/check_gnu_varargs_abi.py', 'cerberus-gnu-varargs-abi.json'),
    'gnu-varargs-control-flow-check': ('drafts/check_varargs_control_flow.py', 'cerberus-gnu-varargs-control-flow.json'),
    'aggregate-initializer-copies-check': ('drafts/check_aggregate_initializer_copies.py', 'cerberus-aggregate-initializer-copies.json'),
    'exact-float-arithmetic-check': ('drafts/check_exact_float_arithmetic.py', 'cerberus-exact-float-arithmetic.json'),
    'floating-constants-check': ('drafts/check_floating_constants.py', 'cerberus-floating-constants.json'),
    'closed-condition-branches-check': ('drafts/check_closed_condition_branches.py', 'cerberus-closed-condition-branches.json'),
    'nested-statement-expressions-check': ('drafts/check_nested_statement_expressions.py', 'cerberus-nested-statement-expressions.json'),
    'vla-statement-results-check': ('drafts/check_vla_statement_results.py', 'cerberus-vla-statement-results.json'),
    'gnu-varargs-parameter-origin-check': ('drafts/check_varargs_parameter_origin.py', 'cerberus-gnu-varargs-parameter-origin.json'),
    'gnu-varargs-borrowing-check': ('drafts/check_varargs_borrowing.py', 'cerberus-gnu-varargs-borrowing.json'),
    'gnu-varargs-type-exceptions-check': ('drafts/check_varargs_type_exceptions.py', 'cerberus-gnu-varargs-type-exceptions.json'),
    'physical-vformat-check': ('drafts/check_physical_vformat.py', 'cerberus-physical-vformat.json'),
    'gnu-libc-profile-check': ('drafts/check_gnu_libc_profile.py', 'cerberus-gnu-libc-profile.json'),
}
REMAINING_GAPS = (
    'variadic-aggregate-bitfield-classification', 'erased-global-forwarded-va-list-origin',
    'raw-selected-va-list-cursor-mutation', 'nonlocal-exits-and-signals',
    'physical-va-list-concurrency', 'stdio-FILE-state-buffering-and-errors',
    'floating-pointer-locale-positional-formatting', 'EOVERFLOW-errno',
    'fortified-abort-and-readonly-format-policy', 'narrow-percent-n-overflow',
    'same-allocation-formatting-ranges', 'complete-OpenSSH-execution-and-equivalence',
    'floating-environment-state-flags-and-traps', 'two-NaN-instruction-payload-selection',
    'unsupported-x87-and-GNU-extended-formats', 'floating-Core-constructor-patterns',
    'general-libm-and-non-AMD64-typed-floating-codecs',
    'dynamic-signed-whitespace-over64bit-and-partial-GNU-NaN-tags',
)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def need(condition, label):
    if not condition:
        raise ValueError('Varargs publication refused: '+label)


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def identity_snapshot(repo):
    """Hash current binaries and every installed runtime input before/after a run."""
    repo = Path(repo)
    installed = repo/'_build/install/default'
    runtime_roots = [installed/'lib'/name/'runtime' for name in ('cerberus-lib', 'cerberus', 'cerberus-bmc')]
    need(runtime_roots[0].is_dir(), 'installed runtime directory missing')
    return {
        'parser_binary_sha256': sha(repo/'_build/default/backend/driver/main.exe'),
        'lean_binary_sha256': sha(repo/'lean_frontend/.lake/build/bin/cerberus-lean'),
        'installed_runtime_sha256': {
            str(path.relative_to(installed)): sha(path)
            for runtime in runtime_roots for path in sorted(runtime.rglob('*')) if path.is_file()
        },
    }


def load_module(path):
    spec = importlib.util.spec_from_file_location('publication_'+Path(path).stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_capture(result, directory, name, lane, stdout_path=None, expected_exit=0):
    need(result['exit_code'] == expected_exit and result['timeout'] is False, name+'/'+lane+' terminal outcome')
    for stream in ('stdout', 'stderr'):
        path = stdout_path if stream == 'stdout' and stdout_path is not None else directory/(name+'.'+lane+'.'+stream)
        need(result[stream+'_sha256'] == sha(path), str(path)+' receipt hash')
        if stream in result:
            need(result[stream] == path.read_text(encoding='utf-8', errors='replace'), str(path)+' exact output')


def abi_commands(repo, source, tree, gnu=False):
    driver = str(repo/'_build/default/backend/driver/main.exe')
    lean = str(repo/'lean_frontend/.lake/build/bin/cerberus-lean')
    runtime = str(repo/'_build/install/default')
    switch = ['--switches=gnu_pointer_conversions'] if gnu else []
    common = [driver, '--runtime='+runtime, '--nolibc']
    execution = ['--exec', '--mode=exhaustive', '--batch', *switch, str(source)]
    return {
        'parse': [driver, '--runtime='+runtime, '--cabs-json', str(source)],
        'ocaml': common+execution,
        'ocaml-core-typed': common+['--typecheck-core']+execution,
        'lean': [lean, '--batch', '--runtime', runtime, *switch, str(tree)],
    }


def profile_execution_commands(profile, source, tree):
    return {
        'ocaml': profile['commands']['ocaml_prefix']+['--exec', '--mode=exhaustive', '--batch', str(source)],
        'ocaml-core-typed': profile['commands']['ocaml_prefix']+['--typecheck-core', '--exec', '--mode=exhaustive', '--batch', str(source)],
        'lean': profile['commands']['lean_prefix'][:1]+['--batch']+
            profile['commands']['lean_prefix'][1:]+[str(tree)],
    }


def check_command(result, expected, label):
    need(result['arguments'] == expected, label+' exact command, lane flags and input')


def check_profile_parser(parsed, directory, name):
    check_capture(parsed, directory, name, 'parse')
    tree = directory/(name+'.json')
    need(sha(tree) == parsed['stdout_sha256'], name+' parsed JSON identity')
    read(tree)


def check_native(row, specification, directory):
    name = row['case']
    need(set(row['native']) == {'O0', 'O2'}, name+' native lanes')
    for optimization, result in row['native'].items():
        rejecting = 'expected_frontend_error' in specification
        check_capture(result['compile'], directory, name, optimization+'-compile', expected_exit=1 if rejecting else 0)
        need('-'+optimization in result['compile']['arguments'], name+' native optimization')
        need(result['matched'] is True, name+' native match')
        if rejecting:
            need(specification['native_diagnostic'] in result['compile']['stderr'] and
                 result['execution'] is None and result['binary_sha256'] is None, name+' exact native rejection')
            continue
        binary = directory/(name+'.'+optimization+'.native')
        need(result['binary_sha256'] == sha(binary), name+' native executable hash')
        if specification['native_execution']:
            expected_exit = specification.get('native_expected_exit',{}).get(optimization,0)
            if 'expected_returns' in specification:
                expected_exit = result['execution']['exit_code']
                need(expected_exit in specification['expected_returns'], name+' native allowed outcome')
            check_capture(result['execution'], directory, name, optimization+'-native',
                          expected_exit=expected_exit)
            need(result['execution']['stdout'] == specification.get('native_stdout', '') and
                 result['execution']['stderr'] == '', name+' native output')
        else:
            need(result['execution'] is None, name+' undefined control must not execute natively')


def defined_return_set(stdout, expected_returns):
    """Require a complete exact enumeration containing every permitted return.

    Unlike a per-result allowed-value check, this catches lost execution orders.
    Outcome multiplicity is retained by the engines, but not fixed by this
    contract; no diagnostic, program output or missing final newline is allowed.
    """
    if not stdout.endswith('\n'):
        return False
    lines = stdout[:-1].split('\n')
    if lines and lines[0].startswith('EXECUTION '):
        if len(lines)<4 or len(lines)%2 or any(
                lines[i] != 'EXECUTION '+str(i//2)+':' for i in range(0,len(lines),2)):
            return False
        lines = lines[1::2]
    elif len(lines) != 1:
        return False
    values = []
    for line in lines:
        matched = re.fullmatch(r'Defined \{value: "Specified\((-?[0-9]+)\)", stdout: "", stderr: "", blocked: "false"\}', line)
        if matched is None:
            return False
        values.append(int(matched[1]))
    return bool(values) and set(values) == set(expected_returns)


def frontend_rejection(result, lane, source, specification):
    cause = specification['expected_frontend_error']
    location = str(source)+':'+specification['frontend_position']
    combined = result['stdout']+result['stderr']
    if result['timeout'] or result['exit_code'] != 1 or 'Defined {' in combined or 'Undefined {' in combined:
        return False
    if lane == 'lean':
        return (result['stderr'] == '' and re.fullmatch(
            re.escape('Error {msg: "desugaring failed at '+location+'-')+
            r'(?:[0-9]+:)?[0-9]+'+
            re.escape('; cause: DESUGAR NotYetSupported: '+cause+'"}\n'), result['stdout']) is not None)
    # Pp_errors.make_message + Cerb_location.head_pos_of_location, in a
    # nonterminal batch process: one diagnostic, its exact source line and
    # underline, followed by the existing batch timing line. No program stdout
    # or unrelated diagnostics are allowed around the expected failure.
    if result['stdout'] != '':
        return False
    line, column = map(int, specification['frontend_position'].split(':'))
    source_lines = source.read_text(encoding='utf-8').splitlines()
    if line < 1 or line > len(source_lines) or column < 1 or column > len(source_lines[line-1]):
        return False
    source_line = source_lines[line-1]
    prefix = ''.join('\t' if char == '\t' else ' ' for char in source_line[:column-1])
    diagnostic = location+': error: feature not yet supported: '+cause+'\n'+source_line+'\n'+prefix+'^'
    return re.fullmatch(re.escape(diagnostic)+r'~{0,'+str(len(source_line)-column)+
                        r'} ?\nTime spent: [0-9]+\.[0-9]{6} seconds\n', result['stderr']) is not None


def undefined_batch_exit(stdout, expected_undefined):
    """Exact batch grammar and existing singleton/multiple-outcome exit contract.

    OCaml driver main.ml returns 1 for one Undefined/Error, 0 for a complete
    multiple-outcome enumeration. Lean mirrors it. No other outcome or output
    is accepted here, and every reported program stderr must be empty.
    """
    if not stdout.endswith('\n'):
        return None
    lines = stdout[:-1].split('\n')
    if lines and lines[0].startswith('EXECUTION '):
        if len(lines) < 4 or len(lines) % 2 or any(
                lines[i] != 'EXECUTION '+str(i//2)+':' for i in range(0, len(lines), 2)):
            return None
        lines = lines[1::2]
        exit_code = 0
    else:
        if len(lines) != 1:
            return None
        exit_code = 1
    for line in lines:
        outcome = re.fullmatch(
            r'Undefined \{ub: "([^"\\]+)", stderr: "", loc: "(?:[^"\\\r\n]|\\.)*"\}', line)
        if outcome is None or not (outcome[1] == expected_undefined or
                outcome[1].startswith(expected_undefined+'_')):
            return None
    return exit_code


def check_engine(result, expected_undefined, expected_stdout, directory, name, lane, helpers, expected_returns=None):
    expected_exit = (0 if expected_undefined is None else
                     undefined_batch_exit(result['stdout'], expected_undefined))
    need(expected_exit is not None, name+'/'+lane+' complete exact UB outcomes')
    check_capture(result, directory, name, lane, expected_exit=expected_exit)
    need(result['matched'] is True, name+'/'+lane+' match')
    need(result.get('status', 'matched') == 'matched', name+'/'+lane+' no refusal accepted')
    observed = result['stdout']+result['stderr']
    need(not any(marker in observed.lower() for marker in helpers.CRASH), name+'/'+lane+' crash')
    need(helpers.diagnostics_ok('lean' if lane.endswith('lean') else 'ocaml', result['stderr']), name+'/'+lane+' diagnostics')
    if expected_undefined is None:
        formatter = sys.modules['check_fortified_format']
        if expected_returns is None:
            need(formatter.defined_output(result['stdout'], 0, expected_stdout), name+'/'+lane+' defined output')
        else:
            need(expected_stdout == '' and defined_return_set(result['stdout'], expected_returns), name+'/'+lane+' complete return outcome set')


def check_common(report, checker, scripts, repo):
    need(report['passed'] is True and report['native_only'] is False, 'complete engine result required')
    need(report['artifact_hashes_verified'] is True, 'artifact stability')
    current = identity_snapshot(repo)
    need(report['identity_before'] == report['identity_after'] == current, 'current binary/runtime identity')
    need(report['parser_binary_sha256'] == current['parser_binary_sha256'] and
         report['lean_binary_sha256'] == current['lean_binary_sha256'], 'binary identities')
    need(report['test_script_sha256'] == sha(checker), 'current checker hash')
    expected_helpers = {'check_function_name.py', 'exercise_imported_c.py',
                        'check_fortified_format.py', 'varargs_publication.py'}
    if checker.name == 'check_varargs_type_exceptions.py':
        expected_helpers.add('check_gnu_varargs_abi.py')
    need(set(report['helper_sha256']) == expected_helpers, 'complete helper manifest')
    for name, digest in report['helper_sha256'].items():
        need(digest == sha(scripts/name), 'current helper '+name)
    if checker.name not in {'check_gnu_varargs_abi.py', 'check_varargs_type_exceptions.py', 'check_gnu_libc_profile.py'}:
        need(report['base_test_script_sha256'] == sha(scripts/'check_gnu_varargs_abi.py'), 'current base harness')


def validate_abi_report(report, checker, scripts, repo, directory):
    check_common(report, checker, scripts, repo)
    module = load_module(checker)
    cases = module.CASES
    need(report['full_suite'] is True, 'full ABI corpus')
    need(len(report['selected_cases']) == len(cases) and set(report['selected_cases']) == set(cases), 'selected ABI cases')
    need(len(report['cases']) == len(cases) and {r['case'] for r in report['cases']} == set(cases), 'complete ABI rows')
    typed = checker.name == 'check_varargs_type_exceptions.py'
    if typed:
        need(report['semantics_switches'] == {'strict': [], 'gnu': ['gnu_pointer_conversions']}, 'strict/GNU switch contract')
    helpers = sys.modules['check_function_name']
    for row in report['cases']:
        name = row['case']
        specification = cases[name]
        need(row['passed'] is True and row['native_verified'] is True, name+' passed')
        need(row['specification'] == specification, name+' current specification')
        expected_hash = hashlib.sha256(specification['source'].encode()).hexdigest()
        need(row['source_sha256'] == expected_hash == sha(directory/(name+'.c')), name+' exact source')
        check_native(row, specification, directory)
        check_capture(row['parser'], directory, name, 'parse', directory/(name+'.json'))
        commands = abi_commands(repo, directory/(name+'.c'), directory/(name+'.json'))
        check_command(row['parser'], commands['parse'], name+' parser')
        read(directory/(name+'.json'))
        lanes = {p+'-'+e for p in ('strict', 'gnu') for e in ENGINES} if typed else ENGINES
        need(set(row['engines']) == lanes, name+' all interpreter lanes')
        for lane, result in row['engines'].items():
            if 'expected_frontend_error' in specification:
                check_command(result, commands[lane], name+'/'+lane)
                check_capture(result, directory, name, lane, expected_exit=1)
                need(result['matched'] is True and frontend_rejection(result,lane,directory/(name+'.c'),specification),
                     name+'/'+lane+' exact frontend cause, stage and location')
                need(not any(marker in (result['stdout']+result['stderr']).lower() for marker in helpers.CRASH),name+'/'+lane+' crash')
                continue
            expected_ub = 'UB141' if typed and lane.startswith('strict-') and name in module.GNU_EXTENSION_CASES else specification['expected_undefined']
            if typed:
                profile = lane.split('-')[0]
                need(row['profile_expectations'][profile] == expected_ub, name+' profile expectation')
                has_switch = '--switches=gnu_pointer_conversions' in result['arguments']
                need(has_switch == (profile == 'gnu'), name+' actual profile command')
                commands = abi_commands(repo, directory/(name+'.c'), directory/(name+'.json'), profile == 'gnu')
                engine = lane[len(profile)+1:]
            else:
                engine = lane
            check_command(result, commands[engine], name+'/'+lane)
            check_engine(result, expected_ub, specification.get('native_stdout', ''), directory, name, lane, helpers,
                         specification.get('expected_returns'))


def validate_profile_report(report, checker, scripts, repo, directory):
    check_common(report, checker, scripts, repo)
    module = load_module(checker)
    need(report['full_suite'] is True and len(report['cases']) == len(module.CASES) and
         {r['case'] for r in report['cases']} == set(module.CASES), 'complete public profile corpus')
    profile_path = Path(report['profile_path'])
    need(report['profile_sha256'] == sha(profile_path), 'profile preparation receipt hash')
    profile = read(profile_path)
    need(profile['profile'] == 'gnu-amd64-physical-va-list' and profile['artifacts_prepared'] is True
         and profile['plan_only'] is False and profile['before'] == profile['after'], 'successful stable profile preparation')
    prepare = repo/'scripts/prepare_gnu_amd64_libc.py'
    need(profile['preparer_sha256'] == sha(prepare), 'current profile preparer')
    preparer = load_module(prepare)
    driver = str(repo/'_build/default/backend/driver/main.exe')
    runtime = str(repo/'_build/install/default')
    cpp = ['--nostdinc', '-I', str(repo/'runtime/libc/include'), '-I',
           str(repo/'runtime/libc/include/posix'), '-DCERB_GNU_AMD64_LIBC=1']
    gnu = '--switches=gnu_pointer_conversions' in profile['commands']['ocaml_prefix']
    common = [driver, '--runtime='+runtime, '--impl='+preparer.IMPL, '--nolibc'] + (
        ['--switches=gnu_pointer_conversions'] if gnu else [])
    core = profile_path.parent/'libc_gnu_amd64.core'
    metadata = [profile_path.parent/('libc_gnu_amd64_'+tu+'.json') for tu in preparer.TUS]
    expected_commands = {
        'ocaml_prefix': common+cpp+['-L', str(profile_path.parent), '-l', 'c_gnu_amd64'],
        'parse_prefix': common+cpp+['--cabs-json'],
        'lean_prefix': [str(repo/'lean_frontend/.lake/build/bin/cerberus-lean'), '--runtime', runtime]
            + (['--switches', 'gnu_pointer_conversions'] if gnu else [])
            + ['--libc', str(core)] + [arg for path in metadata for arg in ('--libc-tu', str(path))],
    }
    need(profile['commands'] == expected_commands, 'exact supported physical-profile selection')
    expected_artifacts = {'libc_gnu_amd64.co', 'libc_gnu_amd64.core'} | {
        'libc_gnu_amd64_'+tu+'.json' for tu in preparer.TUS}
    need(set(profile['artifact_sha256']) == expected_artifacts, 'complete Core and metadata bundle')
    for name, digest in profile['artifact_sha256'].items():
        need(digest == sha(profile_path.parent/name), 'profile artifact '+name)
    expected_inputs = {str(path.relative_to(repo)) for path in
        list((repo/'runtime/libc/include').rglob('*.h')) +
        [repo/'runtime/libc/src'/(tu+'.c') for tu in preparer.TUS] +
        [repo/'runtime/libc/src/internal.h', repo/'runtime/libcore/std.core',
         repo/'runtime/libcore/impls'/(preparer.IMPL+'.impl')]}
    need(set(profile['after']['inputs']) == expected_inputs, 'complete profile source manifest')
    for relative, digest in profile['after']['inputs'].items():
        need(digest == sha(repo/relative), 'profile input '+relative)
    defaults = {'_build/default/runtime/libc/libc.co',
                '_build/default/runtime/libc/libc_inner_arg_temps.co',
                '_build/install/default/lib/cerberus/runtime/libc/libc.co'}
    need(set(profile['after']['defaults']) == defaults, 'default libc preservation manifest')
    for relative, digest in profile['after']['defaults'].items():
        need(digest == (sha(repo/relative) if (repo/relative).exists() else None), 'default libc changed '+relative)
    need(profile['after']['compiler_sha256'] == report['parser_binary_sha256'] and
         profile['after']['lean_sha256'] == report['lean_binary_sha256'], 'profile and engine binaries')
    expected_steps = {'library-object', 'library-core'} | {'metadata-'+tu for tu in preparer.TUS}
    need(len(profile['steps']) == len(expected_steps) and {s['name'] for s in profile['steps']} == expected_steps, 'complete preparation stages')
    for step in profile['steps']:
        need(step['terminal'] is True and step['exit_code'] == 0 and step['timeout'] is False, 'profile stage '+step['name'])
    for row in report['cases']:
        name = row['case']
        body, stdout = module.CASES[name]
        source = module.PREFIX+body+'\n'
        need(row['passed'] is True and row['source_sha256'] == hashlib.sha256(source.encode()).hexdigest()
             == sha(directory/(name+'.c')), name+' current public source')
        check_native(row, {'native_execution': True, 'native_stdout': stdout}, directory)
        check_profile_parser(row['parser'], directory, name)
        need(row['parser']['arguments'] == profile['commands']['parse_prefix']+[str(directory/(name+'.c'))], name+' physical parser profile')
        need(set(row['engines']) == ENGINES, name+' complete public engine lanes')
        commands = profile_execution_commands(profile, directory/(name+'.c'), directory/(name+'.json'))
        for lane, result in row['engines'].items():
            check_command(result, commands[lane], name+'/'+lane+' selected physical profile')
            check_engine(result, None, stdout, directory, name, lane, sys.modules['check_function_name'])


def validate_required_varargs(workspace, repo, runtime):
    project = Path(workspace)/'outputs/openssh-lean'
    scripts = project/'scripts'
    sys.path.insert(0, str(scripts))
    import check_function_name, check_fortified_format  # Pure helper imports.
    from exact_float_publication import DIRECT, validate_direct_float
    from check_statement_regions import DIRECT as REGION_DIRECT, validate_direct_regions
    pairs = []
    for name, (checker, destination) in SUITES.items():
        directory = Path(runtime)/name
        report = read(directory/'result.json')
        validator = validate_profile_report if name == 'gnu-libc-profile-check' else validate_abi_report
        validator(report, project/checker, scripts, Path(repo), directory)
        pairs.append((name+'/result.json', destination))
    validate_direct_float(read(Path(runtime)/DIRECT/'result.json'), workspace, repo, Path(runtime)/DIRECT)
    pairs.append((DIRECT+'/result.json', 'cerberus-exact-float-model.json'))
    validate_direct_regions(read(Path(runtime)/REGION_DIRECT/'result.json'), Path(workspace), Path(repo), Path(runtime)/REGION_DIRECT)
    pairs.append((REGION_DIRECT+'/result.json', 'cerberus-statement-region-model.json'))
    # Always retain these boundaries; these seven finite corpora cannot clear them.
    return pairs, list(REMAINING_GAPS)
