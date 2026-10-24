"""Deterministic Bash reproducers for checked native SIGSEGV observations."""
import base64
import hashlib
from pathlib import Path
import shlex


TOKEN = '{destination}'


def input_identity(profile, depth):
    """Hash repeated input with memory independent of the witness depth."""
    prefix, record, suffix = (
        base64.b64decode(profile[name], validate=True) for name in
        ('prefix_base64', 'record_base64', 'suffix_base64'))
    if not record or type(depth) is not int or depth < 0:
        raise ValueError('A nonempty record and nonnegative depth are required')
    digest = hashlib.sha256()
    total = 0
    for part in (prefix,):
        digest.update(part)
        total += len(part)
    per_chunk = max(1, 65536 // len(record))
    chunk, remaining = record * per_chunk, depth
    while remaining >= per_chunk:
        digest.update(chunk)
        total += len(chunk)
        remaining -= per_chunk
    if remaining:
        part = record * remaining
        digest.update(part)
        total += len(part)
    digest.update(suffix)
    total += len(suffix)
    return total, digest.hexdigest()


def shell_argument(value):
    """Quote a literal argv element, retaining one destination substitution."""
    if TOKEN not in value:
        return shlex.quote(value)
    before, after = value.split(TOKEN, 1)
    if TOKEN in after:
        raise ValueError('One argument has multiple destination tokens')
    return shlex.quote(before) + '"$destination"' + shlex.quote(after)


SCRIPT = r"""#!/usr/bin/env bash
# Generated from a verified native search result. Do not edit.
# Search profile SHA-256: @@PROFILE_SHA@@
# Native observation ID: @@OBSERVATION_ID@@
set -euo pipefail
PATH=/usr/bin:/bin
binary=@@BINARY@@
expected_binary_sha256=@@BINARY_SHA@@
expected_stack_kib=@@STACK_KIB@@
work_dir=@@WORK_DIR@@
expected_parser_sha256=@@PARSER_SHA@@
cwd=@@CWD@@
if [[ $(sha256sum -- "$binary") != "$expected_binary_sha256 "* ]]; then
  printf '%s\n' 'Pinned OpenSSH executable changed.' >&2
  exit 1
fi
if [[ $(ulimit -s) != "$expected_stack_kib" ]]; then
  printf '%s\n' 'Process stack limit differs from the cataloged reproducer.' >&2
  exit 1
fi
if [[ $(sha256sum -- "$work_dir/native_signal_replay.py") != "$expected_parser_sha256 "* ]]; then
  printf '%s\n' 'Native trace parser changed.' >&2
  exit 1
fi
@@SOURCE_CHECK@@
scratch=$(mktemp -d /tmp/openssh-native-reproducer.XXXXXXXX)
trap 'rm -rf -- "$scratch"' EXIT
destination="$scratch/destination"
mkdir -- "$destination"
python3 - "$scratch/protocol" <<'GENERATE_INPUT'
import base64
import hashlib
import sys
prefix = base64.b64decode(@@PREFIX_PY@@, validate=True)
record = base64.b64decode(@@RECORD_PY@@, validate=True)
suffix = base64.b64decode(@@SUFFIX_PY@@, validate=True)
depth = @@DEPTH@@
expected_bytes = @@INPUT_BYTES@@
expected_sha256 = @@INPUT_SHA_PY@@
digest = hashlib.sha256()
total = 0
with open(sys.argv[1], 'wb') as output:
    output.write(prefix); digest.update(prefix); total += len(prefix)
    per_chunk = max(1, 65536 // len(record))
    chunk = record * per_chunk
    remaining = depth
    while remaining >= per_chunk:
        output.write(chunk); digest.update(chunk); total += len(chunk)
        remaining -= per_chunk
    if remaining:
        part = record * remaining
        output.write(part); digest.update(part); total += len(part)
    output.write(suffix); digest.update(suffix); total += len(suffix)
if total != expected_bytes or digest.hexdigest() != expected_sha256:
    raise SystemExit('Generated stdin differs from the checked search input')
GENERATE_INPUT
cd -- "$cwd"
set +e
{
  /usr/bin/strace -ff -i -k -e trace=none -e signal=all -o "$scratch/trace" -- \
    @@COMMAND@@ \
    < "$scratch/protocol" > "$scratch/stdout" 2> "$scratch/stderr"
  status=$?
} 2> "$scratch/runner-stderr"
set -e
@@DIRECT_STATUS_CHECK@@
PYTHONPATH="$work_dir" python3 - "$scratch" "$binary" <<'VERIFY_FAULT'
import json
from pathlib import Path
import sys
from native_signal_replay import parse_signal_traces, primary_fault_sites
scratch = Path(sys.argv[1])
binary = sys.argv[2]
deliveries, terminations, traces = parse_signal_traces(scratch)
sites = primary_fault_sites(deliveries, terminations, 'SIGSEGV')
fatal = [site for site in sites if site.get('status') == 'captured'
         and str(site.get('si_code', '')).startswith('SEGV_')
         and any(row.get('pid') == site.get('pid')
                 and row.get('signal') == 'SIGSEGV' for row in terminations)]
if not traces or len(fatal) != 1:
    raise SystemExit('No unique decoded fatal synchronous SIGSEGV')
site = fatal[0]
delivery = next((row for row in reversed(deliveries)
                 if row.get('pid') == site['pid']
                 and row.get('signal') == 'SIGSEGV'
                 and row.get('instruction_pointer') == site['pc']
                 and row.get('si_code') == site['si_code']), None)
if delivery is None:
    raise SystemExit('Fault site lacks a same-run signal trace')
pinned_frames = sum(frame.get('module') == binary
                    for frame in delivery['stack_frames'])
if pinned_frames == 0:
    raise SystemExit('Fatal process has no frame in the pinned OpenSSH executable')
symbol = @@RECURSIVE_SYMBOL_PY@@
minimum_frames = @@MIN_RECURSIVE_FRAMES@@
recursive_frames = sum(frame.get('module') == binary
                       and frame.get('symbol', '').partition('+')[0] == symbol
                       for frame in delivery['stack_frames'])
if minimum_frames and recursive_frames < minimum_frames:
    raise SystemExit('Fatal trace lacks the required native recursion')
print('REPRODUCED_SIGSEGV ' + json.dumps({
    'target': @@TARGET_PY@@,
    'signal': 'SIGSEGV',
    'pc': site['pc'],
    'module_path': site['module_path'],
    'file_offset': site['file_offset'],
    'stable_site_key': site['stable_site_key'],
    'pinned_frames': pinned_frames,
    'recursive_frames': recursive_frames,
}, sort_keys=True, separators=(',', ':')))
VERIFY_FAULT
"""


def render_reproducer_script(profile: dict, result: dict) -> bytes:
    """Return canonical script bytes for new catalog insertions."""
    if (profile.get('expect_signal') != 'SIGSEGV' or
            profile.get('target') != result.get('target') or
            type(result.get('witness_depth')) is not int or
            type(result.get('receipt')) is not dict or
            type(result.get('reproducer_runtime')) is not dict):
        raise ValueError('A captured matching SIGSEGV search is required')
    runtime = result['reproducer_runtime']
    binary = result['native_binary']
    if not Path(binary).is_absolute():
        raise ValueError('The pinned native binary path must be absolute')
    depth = result['witness_depth']
    input_bytes, input_sha = input_identity(profile, depth)
    env = [shlex.quote(k + '=' + v) for k, v in
           sorted(profile['env'].items())]
    argv = [shell_argument(arg) for arg in profile['argv']]
    command = ' '.join(['/usr/bin/env', '-i', '--', *env, '"$binary"', *argv])
    linked = profile.get('core_link') or {}
    recursive_symbol = (linked.get('recursive_symbol')
                        if linked.get('relation') == 'causal_recursive_call' else None)
    minimum_frames = linked.get('min_recursive_frames', 0) if recursive_symbol else 0
    source_check = ''
    if linked.get('source_file') is not None:
        source = str(Path(binary).parent / linked['source_file'])
        source_check = (
            'source_file=' + shlex.quote(source) + '\n'
            'expected_source_sha256=' + shlex.quote(linked['source_sha256']) + '\n'
            'if [[ $(sha256sum -- "$source_file") != "$expected_source_sha256 "* ]]; then\n'
            "  printf '%s\\n' 'Pinned original C source changed.' >&2\n"
            '  exit 1\nfi')
    status_check = ''
    if profile.get('observation_mode') == 'direct':
        status_check = (
            'if [[ $status != 139 ]]; then\n'
            '  printf "Expected fatal native SIGSEGV; exit status was %s.\\n" "$status" >&2\n'
            '  cat -- "$scratch/stderr" "$scratch/runner-stderr" >&2\n'
            '  exit 1\nfi')
    replacements = {
        '@@PROFILE_SHA@@': result['profile_sha256'],
        '@@OBSERVATION_ID@@': result['receipt']['id'],
        '@@BINARY@@': shlex.quote(binary),
        '@@BINARY_SHA@@': shlex.quote(result['native_binary_sha256']),
        '@@STACK_KIB@@': shlex.quote(runtime['stack_limit_kib']),
        '@@WORK_DIR@@': shlex.quote(str(Path(binary).parent.parent)),
        '@@PARSER_SHA@@': shlex.quote(runtime['trace_parser_sha256']),
        '@@CWD@@': shlex.quote(profile['cwd']),
        '@@SOURCE_CHECK@@': source_check,
        '@@PREFIX_PY@@': repr(profile['prefix_base64']),
        '@@RECORD_PY@@': repr(profile['record_base64']),
        '@@SUFFIX_PY@@': repr(profile['suffix_base64']),
        '@@DEPTH@@': str(depth),
        '@@INPUT_BYTES@@': str(input_bytes),
        '@@INPUT_SHA_PY@@': repr(input_sha),
        '@@COMMAND@@': command,
        '@@DIRECT_STATUS_CHECK@@': status_check,
        '@@RECURSIVE_SYMBOL_PY@@': repr(recursive_symbol),
        '@@MIN_RECURSIVE_FRAMES@@': str(minimum_frames),
        '@@TARGET_PY@@': repr(profile['target']),
    }
    script = SCRIPT
    for marker, value in replacements.items():
        script = script.replace(marker, value)
    if '@@' in script:
        raise ValueError('Unresolved reproducer template marker')
    return script.encode('utf-8')
