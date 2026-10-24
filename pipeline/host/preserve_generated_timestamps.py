"""Reuse verified generation, preserving mtimes of byte-identical outputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


# These mining-only inputs generate independent native-call capture fixtures.
# Neither prelude target nor any of its generation recipes consumes them.
# Keep this list exact: other/new scripts remain generation inputs by default.
_CAPTURE_ONLY_INPUTS = frozenset((
    "scripts/generate_direct_capture.py",
    "scripts/direct_capture_scalars.py",
    "scripts/direct-capture-scenarios.json",
    "scripts/direct_capture_spans.py",
    "scripts/direct-capture-spans.json",
))


def generation_identity(root, command, language):
    # Lem's own stamps cover model sources and generated content. They omit
    # generation recipes; bind those separately before permitting reuse.
    paths = [root/'Makefile']
    if language == 'lean':
        paths.append(root/'lean_frontend/handwritten_copy.manifest')
        paths.extend(sorted((root/'lean_frontend').glob('inject_*.py')))
    for folder in ('tools', 'scripts'):
        paths.extend(path for path in (root/folder).rglob('*')
                     if path.is_file() and '__pycache__' not in path.parts
                     and path.suffix != '.pyc'
                     and path.relative_to(root).as_posix() not in _CAPTURE_ONLY_INPUTS)
    # Host generation also reads maintained family generators, contract data,
    # templates and descriptor source-contract snapshots outside tools/scripts.
    # Generated artifacts and Python/build caches are not recipe inputs.
    if language == "lean":
        host = root/"lean_frontend/host"
        paths.extend(path for path in host.rglob("*")
                     if path.is_file() and path.suffix in (".py", ".json", ".in")
                     and not {"generated", "__pycache__", ".cache", "cache", "_build", ".lake"}
                             .intersection(path.relative_to(host).parts))
    lock = Path(__file__).resolve().parents[2]/'work/toolchain-lock.json'
    return dict(command=command, helper_sha256=digest(Path(__file__)).hex(),
                toolchain_lock_sha256=digest(lock).hex(),
                recipes={str(path.relative_to(root)): digest(path).hex()
                         for path in sorted(set(paths)) if path.is_file()})


def check_generation(root, language):
    commands = [[str(root/'tools/check_lem_sync.sh'),
                 '--check-lean' if language == 'lean' else '--check']]
    if language == 'lean':
        commands.append([str(root/'tools/check_handwritten_sync.sh')])
        commands.append(['bash', str(root/'tools/check_host_adapters.sh'), '--quiet'])
    return all(subprocess.run(command, cwd=root, check=False).returncode == 0
               for command in commands)


def model_inputs(root):
    return {str(path.relative_to(root)): digest(path).hex()
            for folder in ('frontend/model', 'frontend/concurrency')
            for path in sorted((root/folder).rglob('*.lem')) if path.is_file()}
import sys

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').digest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,required=True)
    parser.add_argument('--receipt',type=Path,required=True)
    parser.add_argument('--reuse-verified', choices=('ocaml', 'lean'))
    parser.add_argument('--reuse-receipt', type=Path,
                        help='Read prior verification here; write this attempt to --receipt.')
    parser.add_argument('command',nargs=argparse.REMAINDER)
    args=parser.parse_args()
    command=args.command[1:] if args.command[:1]==['--'] else args.command
    if not command:
        parser.error('A generation command is required')
    directory=args.directory.resolve()
    started = time.monotonic()
    root = directory.parent.parent
    identity = generation_identity(root, command, args.reuse_verified) if args.reuse_verified else None
    prior = {}
    if args.reuse_verified:
        try:
            prior = json.loads((args.reuse_receipt or args.receipt).read_text())
        except (OSError, ValueError):
            pass
        if not isinstance(prior, dict):
            prior = {}
        if (prior.get('exit_code') == 0
                and prior.get('verified_generation_identity') == identity
                and prior.get('directory') == str(directory)
                and check_generation(root, args.reuse_verified)):
            receipt = dict(command=command, directory=str(directory), exit_code=0,
                           generation_reused=True, verified_generation_identity=identity,
                           elapsed_seconds=round(time.monotonic()-started, 3),
                           policy='Source/output content stamps, handwritten copies and generation recipes verified; generator not run.')
            args.receipt.write_text(json.dumps(receipt, indent=2)+'\n')
            print(json.dumps({key: value for key, value in receipt.items()
                              if key != 'verified_generation_identity'}), flush=True)
            return 0
    previous={}
    for path in directory.rglob('*'):
        if path.is_file() and not path.is_symlink():
            state=path.stat()
            previous[path]=(digest(path),state.st_atime_ns,state.st_mtime_ns)
    inputs = model_inputs(root) if args.reuse_verified else None
    result=subprocess.run(command,check=False)
    code = result.returncode
    if args.reuse_verified and code == 0:
        if (inputs != model_inputs(root) or identity != generation_identity(root, command, args.reuse_verified)
                or not check_generation(root, args.reuse_verified)):
            code = 1
    restored=changed=removed=0
    for path,(before,atime,mtime) in previous.items():
        if not path.is_file() or path.is_symlink():
            removed+=1
        elif digest(path)==before:
            os.utime(path,ns=(atime,mtime))
            restored+=1
        else:
            changed+=1
    receipt=dict(command=command,directory=str(directory),exit_code=code,
        previous_files=len(previous),unchanged_mtimes_preserved=restored,
        changed_files=changed,removed_files=removed,
        generation_reused=False, elapsed_seconds=round(time.monotonic()-started, 3),
        policy='Generation ran; timestamps restored only for identical output bytes. Failed generation never enables reuse.')
    if args.reuse_verified and code == 0:
        receipt['verified_generation_identity'] = identity
    args.receipt.parent.mkdir(parents=True,exist_ok=True)
    args.receipt.write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({key: value for key, value in receipt.items()
                      if key != 'verified_generation_identity'}),flush=True)
    return code

if __name__=='__main__':
    sys.exit(main())
