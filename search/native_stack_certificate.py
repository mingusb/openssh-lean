"""Same-run native stack evidence for verified, local crash reproducers.

The two debugger stops measure one function entry and its fatal stack probe.
The resulting certificate is a native observation plus checked arithmetic;
it does not claim that Cerberus's Core model delivered an OS signal.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
import uuid

from common import WORKSPACE, need, sha
from model_archive import Archive
from native_entry_seeds import (SeedStore, DEFAULT_STORE, DEFAULT_ARCHIVE,
                                derive_seed, record_sha256, verified_asset,
                                verified_asset_bytes)
from native_signal_replay import verify_receipt
from signal_catalog import Catalog, DEFAULT as DEFAULT_CATALOG, packed


DEFAULT_OUTPUT = WORKSPACE/'local/search/native-stack'
SUPPORTED_PROBE = bytes.fromhex('48830c2400')
GDB_EVENT = re.compile(r'^[A-Za-z_][A-Za-z_0-9]*$')
HEX = re.compile(r'^[0-9a-f]{64}$')
SCP_RESERVATIONS = (
    (0x820e, bytes.fromhex('4881ec00100000'), 4096),
    (0x821a, bytes.fromhex('4881ec88010000'), 392),
)
ASSET_ROLES = ('stdin', 'events', 'debugger-script', 'debugger-output',
               'inferior-stdout', 'inferior-stderr',
               'lean-certificate-source', 'lean-stdout')
LEAN_SOURCE = WORKSPACE/'search/lean/SignalSearch/NativeStack.lean'
LEAN_COMPILER = WORKSPACE/'work/lean-4.32.2-linux/bin/lean'


def _gdb_script(function, argv, stdin_path, result_path, stdout_path,
                stderr_path):
    """The paths are private generated paths; function is a checked C symbol."""
    need(GDB_EVENT.fullmatch(function) is not None,
         'Debugger function must be a simple symbol')
    need(all(type(arg) is str and '\n' not in arg and '\r' not in arg
             and '\x00' not in arg for arg in argv),
         'Debugger arguments contain a command separator')
    for path in (stdin_path, result_path, stdout_path, stderr_path):
        need(re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path)) is not None,
             'Debugger artifact path has unsupported characters')
    event_path = repr(str(result_path))
    first = '''python
import gdb, json, os
frame = gdb.selected_frame()
pid = gdb.selected_inferior().pid
ptid = list(gdb.selected_thread().ptid)
pc = frame.pc()
mapping = None
for line in gdb.execute('info proc mappings', to_string=True).splitlines():
    fields = line.split(maxsplit=5)
    if len(fields) != 6:
        continue
    try:
        start, end, offset = int(fields[0], 16), int(fields[1], 16), int(fields[3], 16)
    except ValueError:
        continue
    if start <= pc < end:
        mapping = {'path': fields[5].rstrip(),
                   'start': hex(start), 'end': hex(end),
                   'mapping_offset': hex(offset),
                   'file_offset': hex(offset + pc - start),
                   'permissions': fields[4]}
        break
with open('/proc/%d/limits' % pid, encoding='utf-8') as handle:
    limits = handle.read()
record = {'kind': 'first', 'pid': pid, 'ptid': ptid, 'pc': hex(pc),
          'rsp': hex(int(frame.read_register('rsp'))),
          'function': frame.name(), 'mapping': mapping, 'limits': limits}
with open(__EVENT_PATH__, 'a', encoding='utf-8') as out:
    out.write(json.dumps(record, sort_keys=True) + '\\n')
    out.flush()
    os.fsync(out.fileno())
end'''.replace('__EVENT_PATH__', event_path)
    fatal = '''python
import gdb, json, os
frame = gdb.selected_frame()
pid = gdb.selected_inferior().pid
ptid = list(gdb.selected_thread().ptid)
pc = frame.pc()
decoded = frame.architecture().disassemble(pc, count=1)[0]
raw = gdb.selected_inferior().read_memory(pc, decoded['length']).tobytes()
siginfo = gdb.parse_and_eval('$_siginfo')
signo = int(siginfo['si_signo'])
code = int(siginfo['si_code'])
address = hex(int(siginfo['_sifields']['_sigfault']['si_addr'])) if code > 0 else None
with open('/proc/%d/limits' % pid, encoding='utf-8') as handle:
    limits = handle.read()
mapping = None
for line in gdb.execute('info proc mappings', to_string=True).splitlines():
    fields = line.split(maxsplit=5)
    if len(fields) != 6:
        continue
    try:
        start, end, offset = int(fields[0], 16), int(fields[1], 16), int(fields[3], 16)
    except ValueError:
        continue
    if start <= pc < end:
        mapping = {'path': fields[5].rstrip(),
                   'start': hex(start), 'end': hex(end),
                   'mapping_offset': hex(offset),
                   'file_offset': hex(offset + pc - start),
                   'permissions': fields[4]}
        break
frames = []
walk = frame
while walk is not None:
    try:
        current = {'function': walk.name(), 'pc': hex(walk.pc()),
                   'rsp': hex(int(walk.read_register('rsp')))}
        frames.append(current)
        walk = walk.older()
    except (gdb.error, ValueError) as error:
        frames.append({'unwind_error': str(error)})
        break
record = {'kind': 'fatal', 'pid': pid, 'ptid': ptid, 'pc': hex(pc),
          'rsp': hex(int(frame.read_register('rsp'))),
          'instruction': decoded['asm'], 'instruction_bytes': raw.hex(),
          'signal_number': signo, 'si_code': code, 'fault_address': address,
          'mapping': mapping, 'limits': limits, 'frames': frames}
with open(__EVENT_PATH__, 'a', encoding='utf-8') as out:
    out.write(json.dumps(record, sort_keys=True) + '\\n')
    out.flush()
    os.fsync(out.fileno())
end'''.replace('__EVENT_PATH__', event_path)
    return ('set pagination off\nset confirm off\nset print thread-events off\n'
            'catch signal SIGSEGV\n'
            'break '+function+'\n'
            'commands 2\nsilent\n'+first+'\ndisable 2\ncontinue\nend\n'
            'commands 1\nsilent\n'+fatal+'\ncontinue\nend\n'
            'run '+shlex.join(argv)+' < '+str(stdin_path)+' > '+str(stdout_path)+
            ' 2> '+str(stderr_path)+'\n')


def _stack_limits(limits):
    for line in limits.splitlines():
        if line.startswith('Max stack size'):
            match = re.fullmatch(r'Max stack size\s+([0-9]+|unlimited)\s+'
                                 r'([0-9]+|unlimited)\s+bytes\s*', line)
            need(match is not None and match[1] != 'unlimited',
                 'Native stack limit is unavailable or unlimited')
            return int(match[1]), (None if match[2] == 'unlimited'
                                   else int(match[2]))
    raise RuntimeError('Native process did not report its stack limit')


def _site_key(module_digest, offset, instructions):
    return hashlib.sha256(packed(dict(module_sha256=module_digest,
        file_offset=offset, instruction_bytes=instructions)).encode()).hexdigest()


def validate_stack_events(events, *, binary, expected_binary_sha256,
                          function, expected_site_key, gdb_sha256,
                          expected_first_offset=None):
    """Qualify the same-run sample, exact pinned PC, and measured stack drop."""
    need(type(events) is list and len(events) == 2 and
         [item.get('kind') for item in events] == ['first','fatal'],
         'Debugger did not record exactly one first entry and one fatal stop')
    first, fatal = events
    need(first.get('pid') == fatal.get('pid') and
         type(first.get('pid')) is int and first['pid'] > 0 and
         type(first.get('ptid')) is list and len(first['ptid']) == 3 and
         first['ptid'] == fatal.get('ptid') and
         first.get('function') == function,
         'Native stack samples belong to different processes, threads, or functions')
    first_rsp, fatal_rsp = int(first['rsp'],16), int(fatal['rsp'],16)
    need(0 < fatal_rsp < first_rsp and
         fatal['fault_address'] is not None and
         int(fatal['fault_address'],16) == fatal_rsp and
         fatal['signal_number'] == signal.SIGSEGV and
         fatal['si_code'] > 0,
         'Fatal stop is not a descending stack-pointer probe')
    mapping = fatal.get('mapping') or {}
    first_mapping = first.get('mapping') or {}
    module = Path(mapping.get('path',''))
    first_module = Path(first_mapping.get('path',''))
    expected = Path(binary).resolve(strict=True)
    need(module.is_absolute() and module.resolve(strict=True) == expected and
         first_module.is_absolute() and
         first_module.resolve(strict=True) == expected and
         sha(expected) == expected_binary_sha256 and
         fatal['instruction_bytes'] == SUPPORTED_PROBE.hex(),
         'Fatal instruction is not the supported pinned stack probe')
    for sample, mapped in ((first,first_mapping),(fatal,mapping)):
        pc = int(sample['pc'],16)
        start, end = int(mapped['start'],16), int(mapped['end'],16)
        base_offset = int(mapped['mapping_offset'],16)
        need(start <= pc < end and
             int(mapped['file_offset'],16) == base_offset + pc - start,
             'Debugger PC does not match its executable mapping offset')
    if expected_first_offset is not None:
        need(int(first_mapping['file_offset'],16) == expected_first_offset,
             'First stack sample is not the pinned function entry')
    offset = mapping['file_offset']
    need(_site_key(expected_binary_sha256,offset,
                   fatal['instruction_bytes']) == expected_site_key,
         'Fatal native site differs from verified reproducer')
    with expected.open('rb') as stream:
        stream.seek(int(offset,16))
        need(stream.read(len(SUPPORTED_PROBE)) == SUPPORTED_PROBE,
             'Faulting executable bytes differ from debugger report')
    frames = fatal.get('frames')
    need(type(frames) is list and frames and
         frames[0].get('function') == function and
         frames[0].get('rsp') == fatal['rsp'],
         'Fatal trace has no matching top frame')
    recursive = 0
    for frame in frames:
        if frame.get('function') != function:
            break
        recursive += 1
    need(recursive >= 2, 'Fatal trace does not show recursive frames')
    limit, hard_limit = _stack_limits(first['limits'])
    need(_stack_limits(fatal['limits']) == (limit, hard_limit),
         'Native stack limit changed between first and fatal stops')
    return dict(schema=1, kind='same-run-native-stack-growth',
                function=function, binary=dict(path=str(expected),
                    sha256=expected_binary_sha256),
                exact_site_key=expected_site_key, file_offset=offset,
                instruction_bytes=fatal['instruction_bytes'],
                first=dict(pid=first['pid'],ptid=first['ptid'],
                           pc=first['pc'],rsp=first['rsp'],
                           file_offset=first_mapping['file_offset']),
                fatal=dict(pid=fatal['pid'],ptid=fatal['ptid'],
                           pc=fatal['pc'],rsp=fatal['rsp'],
                           fault_address=fatal['fault_address'],
                           signal_number=fatal['signal_number'],
                           si_code=fatal['si_code']),
                recursive_frames=recursive, stack_drop_bytes=first_rsp-fatal_rsp,
                stack_soft_limit_bytes=limit,
                stack_hard_limit_bytes=hard_limit,
                debugger_sha256=gdb_sha256,
                importance=dict(status='unassessed'),
                scope=('Native same-run stack growth and fatal SIGSEGV at a '
                       'hash-pinned stack probe. No Core entry reachability '
                       'or C/Core/ABI correspondence is concluded.'))


def collect_two_stop(program, argv, stdin, cwd, env, function,
                     expected_site_key, *, timeout_seconds=90,
                     expected_stack_limit_bytes=None,
                     work_root=None):
    """Reproduce in a fresh local process and retain complete debugger bytes."""
    program = Path(program).resolve(strict=True)
    need(program.is_file() and os.access(program,os.X_OK) and
         type(argv) is list and all(type(arg) is str and '\x00' not in arg
                                    for arg in argv) and
         type(stdin) is bytes and
         Path(cwd).resolve(strict=True).is_dir() and
         GDB_EVENT.fullmatch(function) is not None and
         HEX.fullmatch(expected_site_key) is not None,
         'Invalid pinned native stack replay')
    debugger = Path(shutil.which('gdb') or '').resolve(strict=True)
    need(debugger.is_file() and os.access(debugger,os.X_OK),
         'GDB is required for native stack capture')
    root = Path(work_root).resolve() if work_root else DEFAULT_OUTPUT
    root.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='stack-',dir=root) as scratch:
        directory = Path(scratch)
        protocol = directory/'stdin.bin'
        protocol.write_bytes(stdin)
        script = directory/'capture.gdb'
        events_path = directory/'events.jsonl'
        inferior_stdout = directory/'inferior.stdout'
        inferior_stderr = directory/'inferior.stderr'
        script.write_text(_gdb_script(function,argv,protocol,events_path,
                                      inferior_stdout,inferior_stderr),
                          encoding='utf-8')
        command = [str(debugger),'-nx','-batch','-q','-x',str(script),
                   '--args',str(program),*argv]
        started = time.monotonic_ns()
        if expected_stack_limit_bytes is not None:
            need(type(expected_stack_limit_bytes) is int and
                 expected_stack_limit_bytes > 0,
                 'Expected stack limit must be positive')
            need(resource.getrlimit(resource.RLIMIT_STACK)[0] ==
                 expected_stack_limit_bytes,
                 'Current stack limit differs from pinned Bash reproducer')
        process = subprocess.Popen(command,cwd=cwd,env=env,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            output, _ = process.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGKILL)
            output, _ = process.communicate()
            raise RuntimeError('Native stack replay timed out')
        elapsed = time.monotonic_ns()-started
        need(events_path.is_file(),
             'GDB produced no same-run stack events: '+
             output[-1000:].decode(errors='replace')+'; inferior stderr: '+
             (inferior_stderr.read_bytes()[-1000:].decode(errors='replace')
              if inferior_stderr.is_file() else '<missing>'))
        event_bytes = events_path.read_bytes()
        events = [json.loads(line) for line in event_bytes.splitlines()]
        need(b'Program terminated with signal SIGSEGV' in output,
             'Debugger did not observe a fatal SIGSEGV')
        digest = sha(program)
        checked = validate_stack_events(events,binary=program,
            expected_binary_sha256=digest,function=function,
            expected_site_key=expected_site_key,gdb_sha256=sha(debugger))
        if expected_stack_limit_bytes is not None:
            need(checked['stack_soft_limit_bytes'] ==
                 expected_stack_limit_bytes,
                 'Measured stack limit differs from pinned reproducer')
        return dict(measurement=checked,events=events,
                    event_bytes=event_bytes,debugger_output=output,
                    inferior_stdout=inferior_stdout.read_bytes(),
                    inferior_stderr=inferior_stderr.read_bytes(),
                    debugger_script=script.read_bytes(),
                    stdin_sha256=hashlib.sha256(stdin).hexdigest(),
                    stdin_bytes=len(stdin),elapsed_ns=elapsed,
                    debugger_exit_code=process.returncode,
                    capture_paths=dict(stdin=str(protocol),
                        events=str(events_path),script=str(script),
                        stdout=str(inferior_stdout),
                        stderr=str(inferior_stderr)),
                    debugger_command=command)


def verified_seed_context(catalog, seed_id, seed_dir=DEFAULT_STORE,
                          archive_dir=DEFAULT_ARCHIVE):
    """Accept only the existing hash-pinned, local Bash scp reproducer."""
    with SeedStore(seed_dir, catalog_dir=catalog.directory,
                   archive_dir=archive_dir) as store:
        seed = store.read(seed_id)
    need(record_sha256(seed) == seed_id and seed['target'] == 'scp' and
         seed['signal'] == 'SIGSEGV' and
         seed['stdin']['kind'] == 'repeated-record',
         'This stack collector has no supported verified seed profile')
    reproducer_id = seed['provenance']['catalog_reproducer_id']
    record = catalog.read_native_reproducer(reproducer_id)
    profile = verified_asset(record, 'profile')
    result = verified_asset(record, 'search-result')
    archive = Archive(archive_dir)
    need(derive_seed(record, profile, result, archive) == seed,
         'Saved native seed no longer matches its catalog reproducer')
    need(seed['replay']['command'] == ['/usr/bin/bash',
                                     seed['replay']['script_path']] and
         seed['replay']['script_sha256'] ==
             record['assets']['script']['sha256'] and
         verified_asset_bytes(record, 'script').startswith(b'#!/usr/bin/env bash\n'),
         'Native seed is not bound to its pinned Bash reproducer')
    receipt_path = Path(seed['provenance']['native_receipt_path'])
    receipt_digest = seed['provenance']['native_receipt_sha256']
    verified = verify_receipt(receipt_path, receipt_digest)
    original = json.loads(receipt_path.read_bytes())
    need(verified['status'] == 'verified' and
         verified['id'] == seed['provenance']['observation_id'] and
         original['recipe']['argv'] == seed['invocation']['argv'] and
         original['recipe']['env'] == seed['invocation']['env'] and
         original['recipe']['cwd'] == seed['invocation']['cwd'] and
         original['recipe']['expect_signal'] == 'SIGSEGV',
         'First-run native receipt and pinned invocation differ')
    sites = [site for site in verified['observation']['primary_sites']
             if site.get('status') == 'captured' and
                site.get('signal') == 'SIGSEGV' and
                site.get('module_sha256') == seed['native_binary']['sha256']]
    need(len(sites) == 1 and
         len(record['native']['fatal_sites']) == 1 and
         sites[0]['stable_site_key'] ==
             record['native']['fatal_sites'][0]['stable_site_key'] and
         sites[0]['file_offset'] == '0x8215' and
         sites[0]['instruction_bytes'] == SUPPORTED_PROBE.hex() and
         sites[0]['source_line_context']['frames'][0]['function'] == 'sink',
         'Verified first-run crash is not the supported scp stack probe')
    link = profile.get('core_link') or {}
    need(profile['argv'].count('{destination}') == 1 and
         profile['argv'] == ['-r', '-t', '{destination}'] and
         profile['cwd'] == seed['invocation']['cwd'] and
         profile['env'] == seed['invocation']['env'] and
         link.get('relation') == 'causal_recursive_call' and
         link.get('recursive_symbol') == 'sink' and
         link.get('source_file') == 'scp.c' and
         link.get('source_line') == 1865 and
         type(link.get('min_recursive_frames')) is int and
         link['min_recursive_frames'] >= 2,
         'Native profile is not the pinned local recursive scp invocation')
    binary = Path(seed['native_binary']['path']).resolve(strict=True)
    source = binary.parent/'scp.c'
    elf = binary.read_bytes()
    c_bytes = source.read_bytes()
    need(sha(binary) == seed['native_binary']['sha256'] and
         sha(source) == link['source_sha256'] and
         c_bytes.decode().splitlines()[1864].strip() == 'sink(1, vect, src);',
         'Original C source or executable differs from the seed')
    reservations = []
    for offset, opcode, bytes_reserved in SCP_RESERVATIONS:
        need(elf[offset:offset+len(opcode)] == opcode,
             'Pinned scp sink prologue reservation changed')
        reservations.append(dict(file_offset=hex(offset),
                                 instruction_bytes=opcode.hex(),
                                 reservation_bytes=bytes_reserved))
    need(sum(item['reservation_bytes'] for item in reservations) == 4488,
         'Pinned scp frame reservation changed')
    stack_kib = result['reproducer_runtime']['stack_limit_kib']
    need(type(stack_kib) is str and stack_kib.isdecimal() and
         int(stack_kib) > 0,
         'Pinned Bash reproducer has no finite stack limit')
    prefix, repeated, suffix = (base64.b64decode(profile[name], validate=True)
                                for name in ('prefix_base64', 'record_base64',
                                             'suffix_base64'))
    stdin = prefix + repeated*seed['stdin']['depth'] + suffix
    need(len(stdin) == seed['stdin']['bytes'] and
         hashlib.sha256(stdin).hexdigest() == seed['stdin']['sha256'] and
         base64.b64decode(original['recipe']['stdin_base64'], validate=True)
             == stdin,
         'Generated input differs from first run or Bash reproducer')
    return dict(seed=seed, reproducer=record, profile=profile,
                result=result, receipt=original, first_site=sites[0],
                stdin=stdin, source=dict(path=str(source),sha256=sha(source),
                    recursive_call_line=1865),
                reservation=dict(frame_bytes=4488,prologue=reservations),
                expected_stack_limit_bytes=int(stack_kib)*1024)


def _near_limit_goal(measurement, frame_bytes):
    first_rsp = int(measurement['first']['rsp'], 16)
    fatal_rsp = int(measurement['fatal']['rsp'], 16)
    return ('SignalSearch.NativeStack.NearLimit '+
            ' '.join(str(value) for value in (
                first_rsp, fatal_rsp, measurement['stack_soft_limit_bytes'],
                frame_bytes, measurement['recursive_frames'])))


def prove_native_arithmetic(measurement, frame_bytes, work_root=DEFAULT_OUTPUT):
    """Compile a standalone concrete theorem under the pinned Lean toolchain."""
    goal = _near_limit_goal(measurement, frame_bytes)
    drop = measurement['stack_drop_bytes']
    limit = measurement['stack_soft_limit_bytes']
    complete = measurement['recursive_frames'] - 1
    need(0 < drop <= limit and complete*frame_bytes <= drop and
         limit-drop < frame_bytes,
         'Measured native stack data do not satisfy NearLimit premises')
    maintained = LEAN_SOURCE.read_bytes()
    need(maintained.startswith(b'import Lean\n') and
         b'def NearLimit ' in maintained and
         maintained.endswith(b'end SignalSearch.NativeStack\n'),
         'Maintained native stack arithmetic source is not self-contained')
    source = (maintained + b'\n' +
              ('theorem nativeStackObservation : '+goal+' := by\n'
               '  unfold SignalSearch.NativeStack.NearLimit\n'
               '  decide\n'
               '#print axioms nativeStackObservation\n').encode())
    root = Path(work_root).resolve()
    root.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='stack-lean-',dir=root) as path:
        certificate = Path(path)/'NativeStackObservation.lean'
        certificate.write_bytes(source)
        result = subprocess.run([str(LEAN_COMPILER),str(certificate)],
            cwd=WORKSPACE,capture_output=True,timeout=120)
        expected = b"'nativeStackObservation' does not depend on any axioms\n"
        need(result.returncode == 0 and not result.stderr and
             result.stdout == expected,
             'Pinned Lean compiler rejected native stack arithmetic: '+
             (result.stdout+result.stderr)[-1000:].decode(errors='replace'))
    return (dict(goal=goal,theorem='nativeStackObservation',
                 status='kernel-checked',
                 compiler_path=str(LEAN_COMPILER),
                 compiler_sha256=sha(LEAN_COMPILER),
                 maintained_source_sha256=hashlib.sha256(maintained).hexdigest(),
                 certificate_source_sha256=hashlib.sha256(source).hexdigest(),
                 axiom_report=expected.decode().strip()),
            source,result.stdout)


def _capture_verified_seed(seed_id, *, catalog_dir=DEFAULT_CATALOG,
                           seed_dir=DEFAULT_STORE,
                           archive_dir=DEFAULT_ARCHIVE,
                           timeout_seconds=90):
    """Trusted collector: derive all evidence from a verified seed ID."""
    with Catalog(catalog_dir) as catalog:
        context = verified_seed_context(catalog,seed_id,seed_dir,archive_dir)
        profile = context['profile']
        root = DEFAULT_OUTPUT
        root.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='verified-scp-',dir=root) as tmp:
            destination = Path(tmp)/'destination'
            destination.mkdir()
            argv = [argument.replace('{destination}',str(destination))
                    for argument in profile['argv']]
            need(argv[:2] == context['seed']['invocation']['argv'][:2] and
                 argv[2] == str(destination) and
                 destination.is_dir() and
                 destination.parent == Path(tmp),
                 'Fresh destination differs from pinned Bash invocation')
            replay = collect_two_stop(
                context['seed']['native_binary']['path'],argv,
                context['stdin'],profile['cwd'],profile['env'],'sink',
                context['first_site']['stable_site_key'],
                timeout_seconds=timeout_seconds,
                expected_stack_limit_bytes=
                    context['expected_stack_limit_bytes'],work_root=root)
            need(replay['measurement']['recursive_frames'] >=
                 profile['core_link']['min_recursive_frames'] and
                 int(replay['measurement']['first']['file_offset'],16)
                     == 0x8200 and
                 replay['stdin_sha256'] == context['seed']['stdin']['sha256'] and
                 replay['stdin_bytes'] == context['seed']['stdin']['bytes'],
                 'Two-stop replay differs from pinned input or recursion')
            proof,lean_source,lean_stdout = prove_native_arithmetic(
                replay['measurement'],context['reservation']['frame_bytes'],
                root)
            raw_assets = dict(stdin=context['stdin'],
                events=replay['event_bytes'],
                **{'debugger-script':replay['debugger_script'],
                   'debugger-output':replay['debugger_output'],
                   'inferior-stdout':replay['inferior_stdout'],
                   'inferior-stderr':replay['inferior_stderr'],
                   'lean-certificate-source':lean_source,
                   'lean-stdout':lean_stdout})
            record = dict(schema=1,kind='verified-native-stack-certificate',
                seed_id=seed_id,
                reproducer_id=context['reproducer']['id'],
                original_observation_id=context['seed']['provenance']
                    ['observation_id'],
                original_receipt_sha256=context['seed']['provenance']
                    ['native_receipt_sha256'],
                original_script_sha256=context['seed']['replay']
                    ['script_sha256'],
                profile_sha256=context['seed']['provenance']
                    ['profile_sha256'],
                invocation=dict(argv=argv,cwd=profile['cwd'],env=profile['env']),
                input_sha256=replay['stdin_sha256'],
                source=context['source'],
                reservation=context['reservation'],
                measurement=replay['measurement'],
                proof=proof,
                capture_paths=replay['capture_paths'],
                debugger_command=replay['debugger_command'],
                debugger_exit_code=replay['debugger_exit_code'],
                scope=('Independent native SIGSEGV replay and checked arithmetic '
                       'for the measured stack addresses. C/Core reachability, '
                       'compiler ABI correspondence, and an OS-signal theorem '
                       'remain separate obligations.'),
                importance=dict(status='unassessed'))
            return record, raw_assets


def collect_verified_seed(seed_id, *, catalog_dir=DEFAULT_CATALOG,
                          seed_dir=DEFAULT_STORE,
                          archive_dir=DEFAULT_ARCHIVE,
                          timeout_seconds=90):
    """Autonomously capture and admit one supported native stack seed."""
    with Catalog(catalog_dir) as catalog:
        return catalog.add_native_stack_certificate(
            seed_id,seed_dir=seed_dir,archive_dir=archive_dir,
            timeout_seconds=timeout_seconds)


def verify_catalog_certificate(catalog, record, *, seed_dir=DEFAULT_STORE,
                               archive_dir=DEFAULT_ARCHIVE,
                               require_current_source=True):
    """Recheck pinned native bytes and kernel-replay only the arithmetic claim."""
    need(record.get('schema') == 1 and
         record.get('kind') == 'verified-native-stack-certificate' and
         set(record.get('assets',{})) == set(ASSET_ROLES),
         'Unsupported native stack certificate record')
    context = verified_seed_context(catalog,record['seed_id'],
                                    seed_dir,archive_dir)
    seed = context['seed']
    need(record['reproducer_id'] == context['reproducer']['id'] and
         record['original_observation_id'] ==
             seed['provenance']['observation_id'] and
         record['original_receipt_sha256'] ==
             seed['provenance']['native_receipt_sha256'] and
         record['original_script_sha256'] ==
             seed['replay']['script_sha256'] and
         record['profile_sha256'] ==
             seed['provenance']['profile_sha256'] and
         record['input_sha256'] == seed['stdin']['sha256'] and
         record['source'] == context['source'] and
         record['reservation'] == context['reservation'],
         'Stack certificate differs from immutable first-run evidence')
    assets = {role:catalog.read_native_stack_asset(record['assets'][role])
              for role in ASSET_ROLES}
    need(assets['stdin'] == context['stdin'],
         'Stored stack replay stdin differs from pinned Bash input')
    argv = record['invocation']['argv']
    need(type(argv) is list and len(argv) == 3 and
         argv[:2] == context['profile']['argv'][:2] and
         type(argv[2]) is str and Path(argv[2]).is_absolute() and
         Path(argv[2]).name == 'destination' and
         Path(argv[2]).parent.name.startswith('verified-scp-') and
         Path(argv[2]).parent.parent == DEFAULT_OUTPUT and
         record['invocation']['cwd'] == context['profile']['cwd'] and
         record['invocation']['env'] == context['profile']['env'],
         'Saved GDB argv is not the local pinned reproducer substitution')
    paths = record['capture_paths']
    need(type(paths) is dict and
         set(paths) == {'stdin','events','script','stdout','stderr'} and
         all(type(value) is str and Path(value).is_absolute()
             for value in paths.values()),
         'Saved debugger capture paths are incomplete')
    parents = {Path(value).parent for value in paths.values()}
    need(len(parents) == 1 and
         next(iter(parents)).parent == DEFAULT_OUTPUT and
         next(iter(parents)).name.startswith('stack-') and
         {Path(value).name for value in paths.values()} ==
             {'stdin.bin','events.jsonl','capture.gdb',
              'inferior.stdout','inferior.stderr'},
         'Saved debugger artifacts are outside the generated local capture')
    expected_command = [str(Path(shutil.which('gdb') or '').resolve(strict=True)),
        '-nx','-batch','-q','-x',paths['script'],'--args',
        seed['native_binary']['path'],*argv]
    need(record['debugger_command'] == expected_command and
         assets['debugger-script'] == _gdb_script('sink',argv,
             Path(paths['stdin']),Path(paths['events']),
             Path(paths['stdout']),Path(paths['stderr'])).encode(),
         'Saved debugger command or script differs from generated protocol')
    lines = assets['events'].splitlines()
    need(len(lines) == 2, 'Stored GDB event sequence is incomplete')
    events = [json.loads(line) for line in lines]
    need(assets['events'] == b''.join((json.dumps(event,sort_keys=True)+'\n').encode()
                                        for event in events),
         'Stored GDB events are not canonical newline-delimited JSON')
    debugger = Path(shutil.which('gdb') or '').resolve(strict=True)
    measurement = validate_stack_events(events,
        binary=seed['native_binary']['path'],
        expected_binary_sha256=seed['native_binary']['sha256'],
        function='sink',
        expected_site_key=context['first_site']['stable_site_key'],
        gdb_sha256=sha(debugger),expected_first_offset=0x8200)
    need(measurement == record['measurement'] and
         measurement['stack_soft_limit_bytes'] ==
             context['expected_stack_limit_bytes'] and
         measurement['recursive_frames'] >=
             context['profile']['core_link']['min_recursive_frames'] and
         record['debugger_exit_code'] == 0 and
         b'Program terminated with signal SIGSEGV' in
             assets['debugger-output'] and
         b'catch signal SIGSEGV\n' in assets['debugger-script'],
         'Saved GDB replay differs from the checked stack measurements')
    proof = record['proof']
    goal = _near_limit_goal(measurement,
                            context['reservation']['frame_bytes'])
    drop = measurement['stack_drop_bytes']
    limit = measurement['stack_soft_limit_bytes']
    complete = measurement['recursive_frames'] - 1
    need(0 < drop <= limit and
         complete*context['reservation']['frame_bytes'] <= drop and
         limit-drop < context['reservation']['frame_bytes'] and
         proof['goal'] == goal and
         proof['theorem'] == 'nativeStackObservation' and
         proof['status'] == 'kernel-checked' and
         proof['certificate_source_sha256'] ==
             hashlib.sha256(assets['lean-certificate-source']).hexdigest() and
         proof['compiler_path'] == str(LEAN_COMPILER) and
         proof['compiler_sha256'] == sha(LEAN_COMPILER) and
         proof['axiom_report'] == assets['lean-stdout'].decode().strip(),
         'Stack measurements do not meet the saved Lean arithmetic premises')
    DEFAULT_OUTPUT.mkdir(parents=True,exist_ok=True)
    theorem_suffix = ('\ntheorem nativeStackObservation : '+goal+' := by\n'
        '  unfold SignalSearch.NativeStack.NearLimit\n'
        '  decide\n#print axioms nativeStackObservation\n').encode()
    maintained_size = len(assets['lean-certificate-source']) - len(theorem_suffix)
    need(maintained_size > 0 and
         assets['lean-certificate-source'][maintained_size:] == theorem_suffix and
         hashlib.sha256(assets['lean-certificate-source'][:maintained_size])
             .hexdigest() == proof['maintained_source_sha256'],
         'Saved native stack theorem source identity differs')
    if require_current_source:
        need(assets['lean-certificate-source'][:maintained_size] ==
             LEAN_SOURCE.read_bytes(),
             'Certificate does not use the approved maintained Lean theorem')
    with tempfile.TemporaryDirectory(prefix='stack-check-',
                                     dir=DEFAULT_OUTPUT) as directory:
        certificate = Path(directory)/'NativeStackObservation.lean'
        certificate.write_bytes(assets['lean-certificate-source'])
        result = subprocess.run([str(LEAN_COMPILER),str(certificate)],
            cwd=WORKSPACE,capture_output=True,timeout=120)
        need(result.returncode == 0 and not result.stderr and
             result.stdout == assets['lean-stdout'] and
             result.stdout ==
               b"'nativeStackObservation' does not depend on any axioms\n",
             'Saved native stack arithmetic failed independent Lean replay')
    return dict(status='verified',seed_id=record['seed_id'],
                reproducer_id=record['reproducer_id'],
                exact_site_key=measurement['exact_site_key'],
                stack_drop_bytes=drop,recursive_frames=complete+1,
                lean_arithmetic='kernel-checked',
                core_reachability='unproved')
