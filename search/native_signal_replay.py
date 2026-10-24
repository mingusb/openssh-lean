"""Measure native C signal behavior and retain exact, replayable invocations.

The generic runner accepts any hash-pinned executable. The OpenSSH adapter below
resolves its binary and source identity from the maintained model archive.
"""
import argparse
import base64
import binascii
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time
import uuid

from common import WORKSPACE, installed_path, need, sha
from elf_instruction_site import decode_elf_instruction
from model_archive import Archive
from signal_catalog import Catalog, DEFAULT as DEFAULT_CATALOG

ARCHIVE = WORKSPACE/'local/models/current'
SIGNAL_LINE = re.compile(r'^(?:\[(?P<pc>[0-9a-fA-F]+|\?+)\] )?--- (?P<signal>SIG[A-Z0-9]+) (?P<detail>.*) ---$')
STACK_LINE = re.compile(r'^ > (?P<module>.+)\((?P<symbol>.*)\) \[(?P<offset>0x[0-9a-fA-F]+)\]$')
SIGNAL_CODE = re.compile(r'\bsi_code=([^,}]+)')
SIGNAL_ADDRESS = re.compile(r'\bsi_addr=([^,}]+)')
KILLED_LINE = re.compile(r'^(?:\[[^]]+\] )?\+\+\+ killed by (SIG[A-Z0-9]+)(?: \(core dumped\))? \+\+\+$')
DEFAULT_ENV = {'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'}
MAX_DEBUGGER_RECORD_BYTES = 65536


def packed(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def debugger_stop_records(path, marker):
    """Extract bounded JSON records after a marker, even after binary stdout."""
    path = Path(path)
    if path.stat().st_size == 0:
        return []
    token = marker.encode('ascii')
    found = []
    with path.open('rb') as stream, mmap.mmap(stream.fileno(), 0,
                                              access=mmap.ACCESS_READ) as contents:
        position = 0
        while (start := contents.find(token, position)) >= 0:
            start += len(token)
            end = contents.find(b'\n', start,
                                min(len(contents), start + MAX_DEBUGGER_RECORD_BYTES + 1))
            need(end >= 0, 'Debugger stop record is missing or exceeds its byte limit')
            payload = contents[start:end].rstrip(b'\r')
            need(len(payload) <= MAX_DEBUGGER_RECORD_BYTES,
                 'Debugger stop record exceeds its byte limit')
            found.append(json.loads(payload))
            position = end + 1
    return found


def check_invocation(recipe):
    """Canonicalize the OS inputs without any OpenSSH-specific assumptions."""
    need(type(recipe) is dict and recipe.get('schema') == 1, 'Expected recipe schema 1')
    argv = recipe.get('argv')
    need(type(argv) is list and all(type(arg) is str and '\x00' not in arg for arg in argv),
         'argv must be an array of strings without NUL bytes')
    environment = recipe.get('env', DEFAULT_ENV)
    need(type(environment) is dict and all(type(k) is str and type(v) is str and
         k and '=' not in k and '\x00' not in k and '\x00' not in v
         for k, v in environment.items()), 'env must contain exact string keys and values')
    cwd = Path(recipe.get('cwd', Path.cwd()))
    need(cwd.is_absolute() and cwd.is_dir(), 'cwd must be an existing absolute directory')
    input_text = recipe.get('stdin_base64', '')
    need(type(input_text) is str, 'stdin_base64 must be a base64 string')
    try:
        input_bytes = base64.b64decode(input_text, validate=True)
    except (binascii.Error, ValueError) as error:
        raise RuntimeError('stdin_base64 is invalid') from error
    timeout = recipe.get('timeout_seconds')
    need(timeout is None or (type(timeout) in (float, int) and timeout > 0),
         'timeout_seconds must be positive when supplied')
    expected = recipe.get('expect_signal')
    need(expected is None or (type(expected) is str and expected in signal.Signals.__members__),
         'expect_signal must be a known signal name')
    checked = dict(schema=1, argv=argv, env=environment, cwd=str(cwd.resolve()),
                   stdin_base64=base64.b64encode(input_bytes).decode('ascii'),
                   timeout_seconds=timeout, expect_signal=expected)
    if 'target' in recipe:
        need(type(recipe['target']) is str and recipe['target'], 'target must be a nonempty string')
        checked['target'] = recipe['target']
    return checked, input_bytes


def native_binary(archive, target):
    """The OpenSSH adapter: resolve and verify its archived native build."""
    need(target in archive.data['models'], 'Unknown archived OpenSSH target')
    model = archive.model(target)
    binding = archive.read_json(model['binding_sha256'])
    need(binding['target'] == target and binding['openssh_commit'] == archive.data['openssh_commit'],
         'Archived target binding differs from the model')
    pinned = binding['native_target']
    path = installed_path(pinned['path'])
    source_root = WORKSPACE/'work/reference-source'
    need(path.is_absolute() and not path.is_symlink() and path.parent.resolve() == source_root.resolve(),
         'Archived native target is outside the pinned C build')
    need(path.is_file() and os.access(path, os.X_OK), 'Pinned native target is unavailable')
    need(sha(path) == pinned['sha256'], 'Native binary differs from archived translation input')
    return path, pinned['sha256'], model['artifact_sha256']


def parse_signal_traces(directory):
    deliveries, terminations, trace_files = [], [], []
    for path in sorted(directory.glob('trace.*')):
        digest = sha(path)
        trace_files.append(dict(file=path.name, sha256=digest, bytes=path.stat().st_size))
        pid = path.name.removeprefix('trace.')
        current = None
        with path.open(errors='replace') as stream:
            for raw_line in stream:
                line = raw_line.rstrip('\n')
                if matched := SIGNAL_LINE.match(line):
                    detail = matched['detail']
                    code = SIGNAL_CODE.search(detail)
                    address = SIGNAL_ADDRESS.search(detail)
                    pc = matched['pc']
                    current = dict(pid=pid, signal=matched['signal'], detail=detail,
                                           si_code=code[1] if code else None,
                                           si_addr=address[1] if address else None,
                                           instruction_pointer=(hex(int(pc, 16)) if pc and
                                                                '?' not in pc else None),
                                           stack_frames=[])
                    deliveries.append(current)
                    continue
                if current is not None and (frame := STACK_LINE.match(line)):
                    current['stack_frames'].append(dict(module=frame['module'],
                                                        symbol=frame['symbol'],
                                                        module_offset=frame['offset'].lower()))
                    continue
                if matched := KILLED_LINE.match(line):
                    terminations.append(dict(pid=pid, signal=matched[1]))
                current = None
    return deliveries, terminations, trace_files


def primary_fault_sites(deliveries, terminations, expected):
    """Retain the same-run instruction for every process killed by the signal."""
    sites = []
    terminated = sorted({row['pid'] for row in terminations if row['signal'] == expected})
    for pid in terminated:
        relevant = [row for row in deliveries if row['pid'] == pid and
                    row['signal'] == expected]
        if not relevant:
            sites.append(dict(status='not_captured', pid=pid, signal=expected,
                              reason='trace lacks terminating signal delivery'))
            continue
        delivery = relevant[-1]
        frames = delivery.get('stack_frames') or []
        if not delivery.get('instruction_pointer') or not frames:
            sites.append(dict(status='not_captured', pid=pid, signal=expected,
                              si_code=delivery['si_code'],
                              fault_address=delivery['si_addr'],
                              reason='trace lacks instruction pointer or unwind frame'))
            continue
        first = frames[0]
        module = Path(first['module'])
        base = dict(pid=pid, signal=expected,
                    pc=delivery['instruction_pointer'], module_path=str(module),
                    module_offset=first['module_offset'], symbol=first['symbol'],
                    si_code=delivery['si_code'], fault_address=delivery['si_addr'])
        if not module.is_file():
            sites.append(dict(status='not_captured', **base,
                              reason='faulting mapped object is unavailable'))
            continue
        try:
            decoded = decode_elf_instruction(module, int(first['module_offset'], 16),
                                             int(delivery['instruction_pointer'], 16))
        except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
            sites.append(dict(status='not_decoded', **base, reason=str(error)))
            continue
        sites.append(dict(status='captured', **base, **decoded))
    return sites


def select_primary_fault_site(sites):
    """Select a unique crash, tolerating collateral thread-group terminations."""
    if not sites:
        return None
    if len(sites) > 1:
        causal = [site for site in sites
                  if site.get('status') == 'captured' and site.get('signal') == 'SIGSEGV' and
                  str(site.get('si_code')).startswith('SEGV_')]
        collateral = [site for site in sites
                      if site.get('status') == 'not_captured' and
                      site.get('reason') == 'trace lacks terminating signal delivery']
        if len(causal) == 1 and len(collateral) == len(sites) - 1:
            return causal[0]
        return dict(status='ambiguous', reason='multiple traced processes terminated by signal',
                    pids=[site['pid'] for site in sites])
    return sites[0]


def primary_fault_site(deliveries, terminations, expected):
    """Compatibility helper for callers that require one unambiguous site."""
    return select_primary_fault_site(primary_fault_sites(deliveries, terminations, expected))


def observe(program, recipe, stdin, directory, trace_signals, capture_crash_site=False):
    """Measure one invocation. Tracing sees delivery even if a handler returns."""
    stdout, stderr = directory/'stdout.bin', directory/'stderr.bin'
    command = [str(program), *recipe['argv']]
    if trace_signals:
        tracer = shutil.which('strace')
        need(tracer is not None, 'strace is required for delivered-signal tracing')
        command = [tracer, '-ff', *(['-i', '-k'] if capture_crash_site else []),
                   '-e', 'trace=none', '-e', 'signal=all',
                   '-o', str(directory/'trace'), '--', *command]
    started = time.time_ns()
    with stdout.open('wb') as out, stderr.open('wb') as err:
        process = subprocess.Popen(command, cwd=recipe['cwd'], env=recipe['env'],
                                   stdin=subprocess.PIPE, stdout=out, stderr=err,
                                   start_new_session=True)
        timed_out = False
        try:
            process.communicate(input=stdin, timeout=recipe['timeout_seconds'])
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
        except BaseException:
            # A cancelled search must not leave a traced descendant or a
            # detached native process behind. Preserve the original error.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                    process.wait(timeout=2)
                except BaseException:
                    pass
            except BaseException:
                pass
            raise
    finished = time.time_ns()
    deliveries, terminations, trace_files = parse_signal_traces(directory) if trace_signals else ([], [], [])
    if trace_signals:
        need(trace_files, 'strace produced no per-process signal trace')
    if not trace_signals and not timed_out and process.returncode is not None and process.returncode < 0:
        try:
            direct_signal = signal.Signals(-process.returncode).name
        except ValueError:
            direct_signal = 'SIG'+str(-process.returncode)
        terminations.append(dict(pid=str(process.pid), signal=direct_signal))
        deliveries.append(dict(pid=str(process.pid), signal=direct_signal,
                               detail='Inferred from direct process termination'))
    if timed_out:
        # SIGKILL came from this harness, so it is not a discovered signal.
        deliveries = []
        terminations = []
    expected = recipe['expect_signal']
    return dict(started_ns=started, finished_ns=finished,
                elapsed_ns=finished-started, pid=process.pid, tracer=trace_signals,
                tracer_returncode=process.returncode if trace_signals else None,
                native_returncode=process.returncode if not trace_signals else None,
                timed_out=timed_out, signal_deliveries=deliveries,
                signal_terminations=terminations, trace_files=trace_files,
                expected_signal=expected,
                expected_observed=None if expected is None else any(
                    row['signal'] == expected for row in deliveries),
                stdout=dict(file=stdout.name, bytes=stdout.stat().st_size, sha256=sha(stdout)),
                stderr=dict(file=stderr.name, bytes=stderr.stat().st_size, sha256=sha(stderr)))


def capture_crash_instruction(program, recipe, stdin, directory):
    """Run the same recipe under GDB and record each expected signal stop.

    The last stop can corroborate a terminating primary delivery even when an
    earlier expected signal was handled. The runtime PC identifies one
    machine instruction; its DWARF line is not by itself a unique C expression.
    """
    expected = recipe['expect_signal']
    need(expected is not None, 'Debugger capture requires expect_signal')
    debugger = shutil.which('gdb')
    need(debugger is not None, 'gdb is required for crash-instruction capture')
    marker = 'CODEX_CRASH_SITE_' + uuid.uuid4().hex + '='
    script_path = directory/'capture.gdb'
    log_path = directory/'debugger.log'
    script_path.write_text(
        'set pagination off\nset confirm off\nset print thread-events off\n'
        + 'catch signal ' + expected + '\n'
        + 'commands\nsilent\n'
        + 'python\nimport gdb, json\n'
        + 'try:\n'
        + '    frame = gdb.selected_frame()\n'
        + '    sal = frame.find_sal()\n'
        + '    pc = frame.pc()\n'
        + '    decoded = frame.architecture().disassemble(pc, count=1)[0]\n'
        + '    instruction = decoded["asm"]\n'
        + '    instruction_bytes = gdb.selected_inferior().read_memory(pc, decoded["length"]).tobytes().hex()\n'
        + '    siginfo = gdb.parse_and_eval("$_siginfo")\n'
        + '    signal_code = int(siginfo["si_code"])\n'
        + '    fault_address = (hex(int(siginfo["_sifields"]["_sigfault"]["si_addr"]))'
        + ' if signal_code > 0 else None)\n'
        + '    mapping = None\n'
        + '    for line in gdb.execute("info proc mappings", to_string=True).splitlines():\n'
        + '        parts = line.split(maxsplit=5)\n'
        + '        if len(parts) != 6:\n'
        + '            continue\n'
        + '        try:\n'
        + '            start, end, offset = int(parts[0], 16), int(parts[1], 16), int(parts[3], 16)\n'
        + '        except ValueError:\n'
        + '            continue\n'
        + '        if start <= pc < end:\n'
        + '            mapping = {"path":parts[5].rstrip(),"file_offset":hex(offset + pc - start),'
        + '"permissions":parts[4]}\n'
        + '            break\n'
        + '    record = {"status":"captured","signal":"' + expected + '",'
        + '"pc":hex(pc),"instruction":instruction,"instruction_bytes":instruction_bytes,'
        + '"si_code":signal_code,"fault_address":fault_address,'
        + '"mapping":mapping,"function":frame.name(),'
        + '"source":sal.symtab.fullname() if sal.symtab else None,'
        + '"line":sal.line,"line_pc":hex(sal.pc),"line_end":hex(sal.last)}\n'
        + 'except Exception as error:\n'
        + '    record = {"status":"not_captured","reason":str(error)}\n'
        + 'print("' + marker + '" + json.dumps(record, sort_keys=True))\n'
        + 'end\ncontinue\nend\nrun\n', encoding='utf-8')
    command = [debugger, '-nx', '-batch', '-q', '-x', str(script_path),
               '--args', str(program), *recipe['argv']]
    timed_out = False
    try:
        with log_path.open('wb') as log:
            process = subprocess.Popen(command, cwd=recipe['cwd'], env=recipe['env'],
                                       stdin=subprocess.PIPE, stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            try:
                process.communicate(input=stdin, timeout=recipe['timeout_seconds'])
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
            except BaseException:
                # Match the observer's cancellation cleanup without changing
                # successful debugger execution or its interpretation.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                try:
                    process.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    try:
                        process.kill()
                        process.wait(timeout=2)
                    except BaseException:
                        pass
                except BaseException:
                    pass
                raise
    finally:
        script_path.unlink(missing_ok=True)
    found = debugger_stop_records(log_path, marker)
    result = found[-1] if found else dict(status='not_captured', reason='no debugger stop record')
    result['record_marker'] = marker
    result['signal_stop_count'] = len(found)
    result['timed_out'] = timed_out
    result['tool'] = dict(path=debugger, sha256=sha(debugger))
    result['log'] = dict(file=log_path.name, bytes=log_path.stat().st_size, sha256=sha(log_path))
    source = result.get('source')
    if source is not None and Path(source).is_file():
        result['source_sha256'] = sha(Path(source))
    mapping = result.get('mapping')
    if result.get('status') == 'captured' and mapping and Path(mapping['path']).is_file():
        module_path = Path(mapping['path']).resolve()
        result['module_sha256'] = sha(module_path)
        stable_site = dict(module_sha256=result['module_sha256'],
                           file_offset=mapping['file_offset'],
                           instruction_bytes=result['instruction_bytes'])
        result['stable_site_key'] = hashlib.sha256(packed(stable_site).encode()).hexdigest()
    return result


def replay_binary(binary, expected_sha256, recipe, source_identity,
                  catalog_dir=DEFAULT_CATALOG, linked_certificate=None, trace_signals=False,
                  capture_crash_site=False):
    """Persist one native C observation; binary/source identity are supplied by a corpus adapter."""
    catalog_dir = Path(catalog_dir).resolve()
    checked, input_bytes = check_invocation(recipe)
    need(not capture_crash_site or checked['expect_signal'] is not None,
         'Crash-instruction capture requires expect_signal')
    program = Path(binary).resolve(strict=True)
    need(program.is_file() and os.access(program, os.X_OK) and
         sha(program) == expected_sha256, 'Native executable differs from expected bytes')
    need(type(source_identity) is dict and type(source_identity.get('kind')) is str,
         'A corpus source identity is required')
    if source_identity['kind'] != 'openssh-archive':
        sources = source_identity.get('source_files')
        need(type(sources) is list and bool(sources),
             'Generic C replay requires pinned source_files')
        for source in sources:
            source_path = Path(source['path'])
            need(source_path.is_absolute() and source_path.is_file() and
                 sha(source_path) == source['sha256'],
                 'Generic C source bytes differ from the supplied identity')
    root = catalog_dir/'native-observations'
    root.mkdir(parents=True, exist_ok=True)
    identity = uuid.uuid4().hex
    stage = Path(tempfile.mkdtemp(prefix='.pending-', dir=root))
    final = root/identity
    try:
        actual_tracing = trace_signals or capture_crash_site
        observation = observe(program, checked, input_bytes, stage,
                              actual_tracing, capture_crash_site)
        observation['primary_sites'] = (primary_fault_sites(
            observation['signal_deliveries'], observation['signal_terminations'],
            checked['expect_signal']) if capture_crash_site else [])
        observation['primary_site'] = select_primary_fault_site(observation['primary_sites'])
        # argv/env/stdin do not capture the filesystem, peers, services, or other
        # external process state needed to reproduce arbitrary invocations.
        observation['external_state_complete'] = False
        observation['external_dependency_status'] = 'not_captured'
        observation['debugger_requested'] = bool(capture_crash_site)
        debugger_available = shutil.which('gdb') is not None
        observation['debugger_unavailable'] = bool(
            capture_crash_site and observation['expected_observed'] and not debugger_available)
        observation['debugger'] = (
            capture_crash_instruction(program, checked, input_bytes, stage)
            if capture_crash_site and observation['expected_observed'] and debugger_available
            else None)
        first_site, debugger = observation['primary_site'], observation['debugger']
        observation['same_native_site_observed'] = bool(
            first_site and first_site.get('status') == 'captured' and debugger and
            debugger.get('status') == 'captured' and
            first_site['stable_site_key'] == debugger.get('stable_site_key') and
            first_site['signal'] == debugger.get('signal'))
        receipt = dict(schema=1, id=identity, kind='native-c-observation',
                       scope='Native execution observation; source correspondence and formal proof are separate',
                       source_identity=source_identity,
                       binary=dict(path=str(program), sha256=expected_sha256),
                       recipe=checked, linked_certificate=linked_certificate,
                       observation=observation)
        (stage/'receipt.json').write_text(packed(receipt)+'\n', encoding='utf-8')
        receipt_digest = sha(stage/'receipt.json')
        os.replace(stage, final)
        summary = dict(id=identity, receipt=str(final/'receipt.json'),
                       receipt_sha256=receipt_digest, target=checked.get('target'),
                       expected_signal=observation['expected_signal'],
                       expected_observed=observation['expected_observed'],
                       signal_deliveries=observation['signal_deliveries'],
                       signal_terminations=observation['signal_terminations'],
                       primary_sites=observation['primary_sites'],
                       primary_site=observation['primary_site'],
                       crash_instruction=observation['debugger'],
                       same_native_site_observed=observation['same_native_site_observed'],
                       external_state_complete=observation['external_state_complete'],
                       external_dependency_status=observation['external_dependency_status'],
                       timed_out=observation['timed_out'],
                       catalog_id=linked_certificate['catalog_id'] if linked_certificate else None)
        if linked_certificate is None and capture_crash_site and summary['expected_observed']:
            with Catalog(catalog_dir) as catalog:
                catalog.add_native_instruction_sites(summary)
        return summary
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def replay_recipe(recipe, catalog_dir=DEFAULT_CATALOG, catalog_id=None, trace_signals=False,
                  capture_crash_site=False):
    """OpenSSH adapter for the generic native C replay core."""
    catalog_dir = Path(catalog_dir).resolve()
    archive = Archive(ARCHIVE)
    need(type(recipe) is dict and type(recipe.get('target')) is str and
         recipe['target'] in archive.data['models'], 'Unknown archived OpenSSH target')
    selected = dict(recipe)
    selected.setdefault('cwd', str(WORKSPACE/'work/reference-source'))
    checked, _ = check_invocation(selected)
    target = checked['target']
    program, binary_digest, model_digest = native_binary(archive, target)
    linked = None
    if catalog_id is not None:
        with Catalog(catalog_dir) as catalog:
            entry = catalog.read(catalog_id)
            need(entry['evidence']['identity']['archive_manifest'] == archive.manifest_sha256,
                 'Candidate belongs to another model archive')
            mappings = entry['evidence']['source_mappings']
            need(any(row['source'].get('status') == 'mapped' and
                     row['source'].get('target') == target for row in mappings),
                 'Candidate has no mapped C source for the selected target')
            linked = dict(catalog_id=catalog_id, certificate_kind=entry['evidence']['kind'],
                          source_mappings=mappings)
    source_identity = dict(kind='openssh-archive', target=target,
                           archive_manifest_sha256=archive.manifest_sha256,
                           openssh_commit=archive.data['openssh_commit'],
                           configuration_profile=archive.data['configuration_profile'],
                           model_artifact_sha256=model_digest)
    summary = replay_binary(program, binary_digest, checked, source_identity,
                            catalog_dir, linked, trace_signals, capture_crash_site)
    if catalog_id is not None:
        with Catalog(catalog_dir) as catalog:
            catalog.add_native_observation(catalog_id, summary)
            if capture_crash_site and summary['expected_observed']:
                catalog.add_native_instruction_sites(summary)
    return summary


def verify_receipt(path, expected_sha256=None):
    """Check preserved bytes and recorded C/Lean identities without rerunning the program."""
    path = Path(path).resolve(strict=True)
    if expected_sha256 is not None:
        need(sha(path) == expected_sha256, 'Native replay receipt hash changed')
    receipt = json.loads(path.read_bytes())
    need(receipt['schema'] == 1 and receipt['kind'] == 'native-c-observation',
         'Not a native replay receipt')
    checked, _ = check_invocation(receipt['recipe'])
    need(checked == receipt['recipe'], 'Native replay recipe changed')
    program = Path(receipt['binary']['path'])
    need(program.is_file() and not program.is_symlink() and
         sha(program) == receipt['binary']['sha256'], 'Native binary changed')
    identity = receipt['source_identity']
    if identity['kind'] == 'openssh-archive':
        archive = Archive(ARCHIVE)
        need(identity['archive_manifest_sha256'] == archive.manifest_sha256 and
             identity['openssh_commit'] == archive.data['openssh_commit'],
             'OpenSSH archive/source identity changed')
        pinned, digest, model_digest = native_binary(archive, identity['target'])
        need(program == pinned and digest == receipt['binary']['sha256'] and
             model_digest == identity['model_artifact_sha256'] and
             checked.get('target') == identity['target'], 'OpenSSH binary/model binding changed')
    for source in identity.get('source_files', []):
        source_path = Path(source['path'])
        need(source_path.is_file() and sha(source_path) == source['sha256'],
             'Recorded C source bytes changed: '+str(source_path))
    for item in (receipt['observation']['stdout'], receipt['observation']['stderr'],
                 *receipt['observation']['trace_files']):
        file = path.parent/item['file']
        need(file.is_file() and not file.is_symlink() and file.stat().st_size == item['bytes'] and
             sha(file) == item['sha256'], 'Native replay output changed: '+str(file))
    observation = receipt['observation']
    if observation['tracer']:
        deliveries, terminations, trace_files = parse_signal_traces(path.parent)
        if observation['timed_out']:
            deliveries, terminations = [], []
        need((deliveries, terminations, trace_files) ==
             (observation['signal_deliveries'], observation['signal_terminations'],
              observation['trace_files']), 'Native signal trace differs from receipt')
    expected = checked['expect_signal']
    need(observation['expected_signal'] == expected and
         observation['expected_observed'] == (None if expected is None else any(
             row['signal'] == expected for row in observation['signal_deliveries'])),
         'Native expected-signal result differs from deliveries')
    sites = (primary_fault_sites(observation['signal_deliveries'],
                                 observation['signal_terminations'], expected)
             if observation['debugger_requested'] else [])
    need(observation.get('primary_sites') == sites,
         'Native primary fault sites differ from trace')
    first_site = select_primary_fault_site(sites)
    need(observation.get('primary_site') == first_site,
         'Native primary fault site differs from trace')
    need(observation.get('external_state_complete') is False and
         observation.get('external_dependency_status') == 'not_captured',
         'Native external dependency status differs from receipt contract')
    debugger = receipt['observation'].get('debugger')
    if debugger is not None:
        item = debugger['log']
        file = path.parent/item['file']
        need(file.is_file() and not file.is_symlink() and file.stat().st_size == item['bytes'] and
             sha(file) == item['sha256'], 'Native debugger log changed: '+str(file))
        marker = debugger['record_marker']
        found = debugger_stop_records(file, marker)
        if found:
            need(all(debugger.get(key) == value for key,value in found[-1].items()),
                 'Native debugger site differs from saved log')
        else:
            need(debugger['status'] == 'not_captured' and
                 debugger['reason'] == 'no debugger stop record',
                 'Native debugger site has no saved stop record')
        need(debugger.get('signal_stop_count') == len(found),
             'Native debugger stop count differs from saved log')
        if debugger.get('source_sha256') is not None:
            need(sha(Path(debugger['source'])) == debugger['source_sha256'],
                 'Native debugger source bytes changed')
        mapping = debugger.get('mapping')
        if mapping and debugger.get('module_sha256') is not None:
            need(sha(Path(mapping['path'])) == debugger['module_sha256'],
                 'Native debugger mapped object changed')
            expected_site = dict(module_sha256=debugger['module_sha256'],
                                 file_offset=mapping['file_offset'],
                                 instruction_bytes=debugger['instruction_bytes'])
            expected_key = hashlib.sha256(packed(expected_site).encode()).hexdigest()
            need(debugger.get('stable_site_key') == expected_key,
                 'Native debugger stable site key changed')
    same_site = bool(first_site and first_site.get('status') == 'captured' and
                     debugger and debugger.get('status') == 'captured' and
                     first_site['stable_site_key'] == debugger.get('stable_site_key') and
                     first_site['signal'] == debugger.get('signal'))
    need(observation.get('same_native_site_observed') == same_site,
         'Native cross-run site comparison differs from receipt')
    linked = receipt['linked_certificate']
    if linked is not None:
        catalog_dir = path.parents[2]
        with Catalog(catalog_dir) as catalog:
            entry = catalog.read(linked['catalog_id'])
            need(entry['evidence']['source_mappings'] == linked['source_mappings'] and
                 any(row['id'] == receipt['id'] and row['receipt_sha256'] == sha(path)
                     for row in entry['native_observations']),
                 'Linked catalog entry or replay receipt changed')
    return dict(id=receipt['id'], status='verified', observation=receipt['observation'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', type=Path, default=DEFAULT_CATALOG)
    commands = parser.add_subparsers(dest='command', required=True)
    replay = commands.add_parser('run')
    replay.add_argument('--recipe', type=Path, required=True)
    replay.add_argument('--catalog-id')
    replay.add_argument('--trace-signals', action='store_true')
    replay.add_argument('--capture-crash-site', action='store_true')
    check = commands.add_parser('verify')
    check.add_argument('receipt', type=Path)
    check.add_argument('--sha256')
    args = parser.parse_args()
    if args.command == 'run':
        recipe = json.loads(args.recipe.read_bytes())
        print(packed(replay_recipe(recipe, args.catalog, args.catalog_id,
                                   args.trace_signals, args.capture_crash_site)))
    else:
        print(packed(verify_receipt(args.receipt, args.sha256)))


if __name__ == '__main__':
    main()
