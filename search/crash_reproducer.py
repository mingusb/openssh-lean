"""Emit a Bash reproducer only from a verified, fatal native SIGSEGV receipt.

The generated script invokes the pinned C executable directly, then replays
the same recipe under the native observer to confirm its fatal PC and mapped-
file site key. Runtime instruction bytes are not captured by strace.
"""
import argparse
import base64
import json
from pathlib import Path
import shlex
import textwrap

from common import WORKSPACE, need, sha
from native_signal_replay import verify_receipt


def shell(value):
    return shlex.quote(value)


def b64(value):
    return base64.b64encode(json.dumps(value, sort_keys=True, separators=(',', ':'))
                            .encode()).decode()


def lines(value):
    return '\n'.join(textwrap.wrap(value, 76))


def emit_reproducer(receipt_path, output_path, require_openssh=True, site_key=None):
    """Write an executable script tied to one observed fatal PC/file site."""
    receipt_path = Path(receipt_path).resolve(strict=True)
    verified = verify_receipt(receipt_path)
    receipt = json.loads(receipt_path.read_bytes())
    need(verified['status'] == 'verified', 'Native observation is not verified')
    identity = receipt['source_identity']
    if require_openssh:
        need(identity['kind'] == 'openssh-archive',
             'A public reproducer requires a pinned OpenSSH C program')
    recipe = receipt['recipe']
    observation = receipt['observation']
    expected = recipe['expect_signal']
    need(expected == 'SIGSEGV' and observation['expected_observed'] is True and
         not observation['timed_out'] and
         any(row['signal'] == expected for row in observation['signal_terminations']),
         'The receipt does not show a fatal native SIGSEGV')
    primary_sites = observation.get('primary_sites', [])
    eligible = [site for site in primary_sites
                if site.get('status') == 'captured' and
                   site.get('stable_site_key') and site.get('instruction_bytes') and
                   str(site.get('si_code', '')).startswith('SEGV_')]
    keys = {site['stable_site_key'] for site in eligible}
    need(observation['tracer'] is True and keys,
         'The receipt does not show a synchronous C memory fault')
    if site_key is None:
        need(len(keys) == 1, 'Multiple fatal sites; select one with --site-key')
        site_key = next(iter(keys))
    else:
        need(site_key in keys, 'Selected site key is not a fatal memory fault in this receipt')
    primary = next(site for site in eligible if site['stable_site_key'] == site_key)
    output_path = Path(output_path).resolve()
    need(not output_path.exists(), 'Reproducer output already exists')
    need(output_path.parent.is_dir(), 'Reproducer parent directory is missing')
    env_args = ' '.join(shell(key+'='+value) for key, value in sorted(recipe['env'].items()))
    argv = ' '.join(shell(arg) for arg in recipe['argv'])
    invocation = ('strace -ff -i -k -e trace=none -e signal=all -o "$scratch/trace" -- '
                  'env -i -- ' + env_args + ' "$binary"' + (' '+argv if argv else ''))
    if recipe['timeout_seconds'] is not None:
        invocation = ('timeout --preserve-status --kill-after=1s '
                      + shell(str(recipe['timeout_seconds'])+'s')+' '+invocation)
    script = f'''#!/usr/bin/env bash
set -euo pipefail
# Native observation: {receipt['id']}
# Receipt SHA-256: {sha(receipt_path)}
# Recorded fatal-PC mapped-file site key: {primary['stable_site_key']}
# This reproducer checks a fatal SIGSEGV and rechecks the same instruction site.
binary={shell(receipt['binary']['path'])}
expected_binary_sha256={shell(receipt['binary']['sha256'])}
expected_site_key={shell(primary['stable_site_key'])}
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
actual_binary_sha256=$(sha256sum -- "$binary")
[[ ${{actual_binary_sha256%% *}} == "$expected_binary_sha256" ]] || {{
  printf '%s\\n' 'Pinned C executable changed' >&2; exit 1;
}}
cd -- {shell(recipe['cwd'])}
base64 --decode > "$scratch/stdin.bin" <<'OPENSSH_STDIN_BASE64'
{lines(recipe['stdin_base64'])}
OPENSSH_STDIN_BASE64
base64 --decode > "$scratch/recipe.json" <<'OPENSSH_RECIPE_BASE64'
{lines(b64(recipe))}
OPENSSH_RECIPE_BASE64
base64 --decode > "$scratch/source-identity.json" <<'OPENSSH_SOURCE_BASE64'
{lines(b64(identity))}
OPENSSH_SOURCE_BASE64
set +e
{invocation} < "$scratch/stdin.bin" > "$scratch/stdout.bin" 2> "$scratch/stderr.bin"
status=$?
set -e
'''
    script += '''shopt -s nullglob
traces=("$scratch"/trace.*)
if (( ${#traces[@]} == 0 )); then
  printf 'No signal trace from invocation (status %s)\\n' "$status" >&2
  exit 1
fi
'''
    script += f'''python3 - "$scratch/recipe.json" "$scratch/source-identity.json" \\
  "$scratch/catalog" "$binary" "$expected_binary_sha256" "$expected_site_key" \\
  "$scratch" <<'OPENSSH_SITE_CHECK'
import json
from pathlib import Path
import sys
sys.path.insert(0, {str(WORKSPACE/'search')!r})
from native_signal_replay import (parse_signal_traces, primary_fault_sites,
                                  replay_binary, replay_recipe)
recipe = json.loads(Path(sys.argv[1]).read_bytes())
source = json.loads(Path(sys.argv[2]).read_bytes())
if source['kind'] == 'openssh-archive':
    replay = replay_recipe(recipe, catalog_dir=sys.argv[3],
                           trace_signals=True, capture_crash_site=True)
else:
    replay = replay_binary(sys.argv[4], sys.argv[5], recipe, source,
                           catalog_dir=sys.argv[3], trace_signals=True,
                           capture_crash_site=True)
sites = replay.get('primary_sites') or []
site = next((row for row in sites if row.get('stable_site_key') == sys.argv[6] and
             row.get('status') == 'captured' and
             str(row.get('si_code', '')).startswith('SEGV_')), None)
fatal = any(row.get('signal') == 'SIGSEGV'
            for row in replay.get('signal_terminations', []))
deliveries, terminations, _ = parse_signal_traces(Path(sys.argv[7]))
first_sites = primary_fault_sites(deliveries, terminations, 'SIGSEGV')
first_site = next((row for row in first_sites
                   if row.get('stable_site_key') == sys.argv[6] and
                      row.get('status') == 'captured' and
                      str(row.get('si_code', '')).startswith('SEGV_')), None)
if not replay.get('expected_observed') or not fatal or \\
        site is None or first_site is None:
    raise SystemExit('SIGSEGV site did not reproduce exactly')
print('Reproduced fatal SIGSEGV at native site', sys.argv[6])
print('Faulting PC:', site['pc'], 'file offset:', site['file_offset'])
print('Fault address:', site.get('fault_address'))
OPENSSH_SITE_CHECK
'''
    output_path.write_text(script, encoding='utf-8', newline='\n')
    output_path.chmod(0o755)
    return dict(path=str(output_path), native_site_key=primary['stable_site_key'],
                observation_id=receipt['id'], target=recipe.get('target'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--site-key', help='Required when a receipt contains distinct fatal sites')
    args = parser.parse_args()
    print(json.dumps(emit_reproducer(args.receipt, args.output,
                                     site_key=args.site_key), sort_keys=True))


if __name__ == '__main__':
    main()
