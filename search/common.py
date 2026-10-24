"""Shared search paths, hashes, and workflow lease."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

WORKSPACE = Path(__file__).resolve().parents[1]
RUNTIME = WORKSPACE/'local/runtime'
PIN = 'c4284b08f80c4461f97d179896868106e510327e'
LEM_PIN = '2d3a492758cb23dc4e417f2961983d25b36ce130'
PROFILE = WORKSPACE/'work/toolchain-lock.json'
LIMIT = 256 * 1024 * 1024  # One bounded executable/runtime bundle; never a checkout.
BINARIES = ('_build/default/backend/driver/main.exe',
            'lean_frontend/.lake/build/bin/cerberus-lean',
            'lean_frontend/.lake/build/bin/statement-region-test')


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def installed_path(original):
    """Map a release producer's absolute path to this checked-out workspace."""
    original = Path(original)
    marker = WORKSPACE/'local/release/turnkey.json'
    if not marker.is_file():
        need(original.is_file(), 'Pinned runtime path is missing: '+str(original))
        return original
    release = json.loads(marker.read_bytes())
    producer = Path(release['original_workspace'])
    need(original.is_absolute() and original.is_relative_to(producer),
         'Pinned runtime path is outside the release producer workspace')
    relative = original.relative_to(producer)
    need(relative.parts[:2] in (('local', 'runtime'), ('work', 'reference-source')) or
         relative.parts[:1] == ('work',),
         'Pinned runtime path is outside the released runtime')
    current = WORKSPACE/relative
    need(current.is_file(), 'Released runtime file is missing: '+str(relative))
    return current


def save(path, data):
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp-' + uuid.uuid4().hex)
    temporary.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    os.replace(temporary, path)


def process_identity(pid):
    try:
        # PID plus Linux start ticks avoids mistaking a reused PID for our job.
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        return None if fields[0] == 'Z' else dict(pid=pid, start_ticks=fields[19])
    except (FileNotFoundError, ProcessLookupError):
        # A task can disappear after opening its procfs entry but before read().
        return None


def live_children(owner):
    return [row for row in owner.get('children', []) if process_identity(row['pid']) == row]


def record_child(process, runtime=RUNTIME):
    path = Path(runtime)/'workflow-owner.json'
    owner = json.loads(path.read_text())
    need(owner['token'] == os.environ.get('OPENSSH_LEAN_LOCK_TOKEN'), 'Child has no workflow lease.')
    identity = process_identity(process.pid)
    if identity:
        owner['children'] = live_children(owner) + [identity]
        save(path, owner)


@contextmanager
def workflow_lock(runtime=RUNTIME, token=None):
    """Children may join the live owner; unrelated sync/build/test jobs cannot."""
    runtime = Path(runtime).resolve(strict=True)
    lock_path = runtime/'workflow.lock'
    owner_path = runtime/'workflow-owner.json'
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    token = token or os.environ.get('OPENSSH_LEAN_LOCK_TOKEN')
    owned = False
    previous = os.environ.get('OPENSSH_LEAN_LOCK_TOKEN')
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            owned = True
        except BlockingIOError:
            owner = json.loads(owner_path.read_text())
            need(token is not None and token == owner['token'],
                 f"Another workflow owns the build/test environment (PID {owner['pid']}).")
            os.kill(owner['pid'], 0)
        if owned:
            need(token is None, 'A stale workflow token cannot start a new operation.')
            if owner_path.exists():
                previous_owner = json.loads(owner_path.read_text())
                need(not live_children(previous_owner),
                     'An interrupted workflow still has live children. Wait for their actual termination.')
            token = uuid.uuid4().hex
            save(owner_path, dict(pid=os.getpid(), token=token, children=[]))
        os.environ['OPENSSH_LEAN_LOCK_TOKEN'] = token
        yield token
    finally:
        if previous is None:
            os.environ.pop('OPENSSH_LEAN_LOCK_TOKEN', None)
        else:
            os.environ['OPENSSH_LEAN_LOCK_TOKEN'] = previous
        if owned and owner_path.exists() and not live_children(json.loads(owner_path.read_text())):
            owner_path.unlink(missing_ok=True)
        os.close(descriptor)

def tool_paths(workspace=WORKSPACE, runtime=RUNTIME):
    repo = runtime/'cerberus-lean'
    paths = [workspace/'work/lean-4.32.2-linux/bin'/name for name in ('lean', 'lake', 'leanc')]
    paths += [repo/'_opam/bin'/name for name in ('lem', 'dune')]
    paths += [Path(shutil.which(name) or '/missing-tool/'+name) for name in ('ocamlc', 'ocamlopt', 'opam', 'cc')]
    paths += [repo/'_opam/.opam-switch/overlay/lem/opam']
    return paths


def seal_tools():
    """One-time explicit enrollment after verifying the existing successful build."""
    need(not PROFILE.exists(), 'Toolchain lock already exists; automatic replacement is forbidden.')
    repo = RUNTIME/'cerberus-lean'
    overlay = repo/'_opam/.opam-switch/overlay/lem/opam'
    need(LEM_PIN in overlay.read_text(), 'Installed Lem pin differs from the project pin.')
    lean = WORKSPACE/'work/lean-4.32.2-linux/bin/lean'
    need('version 4.32.2' in subprocess.check_output([str(lean), '--version'], text=True), 'Wrong Lean version')
    need(subprocess.check_output(['ocamlc', '-version'], text=True).strip() == '5.4.0', 'Wrong OCaml version')
    paths = tool_paths()
    need(all(path.is_file() for path in paths), 'An installed tool is missing.')
    save(PROFILE, dict(schema=1, upstream=PIN, lem_pin=LEM_PIN,
         policy='Verification only. Routine builds never install, upgrade or repin tools.',
         files={str(path): dict(resolved=str(path.resolve()), sha256=sha(path)) for path in paths}))


def verify_tools(profile=PROFILE):
    profile = Path(profile)
    need(profile.is_file(), 'Missing toolchain lock. Do not bootstrap automatically.')
    data = json.loads(profile.read_text())
    need(data['schema'] == 1 and data['upstream'] == PIN and data['lem_pin'] == LEM_PIN,
         'Toolchain lock has the wrong profile.')
    need(bool(data['files']), 'Empty toolchain lock is invalid.')
    for name, expected in data['files'].items():
        path = Path(name)
        need(path.is_file() and str(path.resolve()) == expected['resolved'] and sha(path) == expected['sha256'],
             'Pinned tool changed or is missing: ' + name + '. Routine builds will not repair/reinstall it.')
    return sha(profile)
