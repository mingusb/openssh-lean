"""Closed build workflow primitives. No installation, source reset, or cache deletion."""
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
RUNTIME = Path(__file__).resolve().parents[1] / "local/runtime"
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


def artifact_sources(workspace=WORKSPACE, runtime=RUNTIME):
    repo = runtime/'cerberus-lean'
    sources = {name: repo/name for name in BINARIES}
    for package in ('cerberus-lib', 'cerberus', 'cerberus-bmc'):
        root = repo/'_build/install/default/lib'/package/'runtime'
        if root.is_dir():
            for path in sorted(root.rglob('*')):
                if path.is_file():
                    need(path.resolve().is_relative_to(repo.resolve()), 'Runtime input escapes the repository.')
                    sources[str(path.relative_to(repo))] = path
    sources['source.patch'] = workspace/'outputs/openssh-lean/patches/cerberus-gnu-keywords.patch'
    return sources


def verify_bundle(root):
    root = Path(root)
    need(not root.is_symlink(), 'Bundle root cannot be a symlink.')
    manifest = json.loads((root/'manifest.json').read_text())
    need(manifest['schema'] == 1 and 0 < manifest['bytes'] <= LIMIT, 'Invalid bundle size or schema.')
    total = 0
    for name, expected in manifest['files'].items():
        path = root/name
        need(not path.is_symlink() and path.resolve().is_relative_to(root.resolve()), 'Bundle path escapes its root.')
        need(path.is_file() and path.stat().st_size == expected['bytes'] and sha(path) == expected['sha256'],
             'Known-good artifact changed: ' + name)
        total += path.stat().st_size
    need(total == manifest['bytes'], 'Bundle byte count differs.')
    need(set(BINARIES) | {'source.patch'} <= set(manifest['files']), 'Bundle omits a required artifact.')
    return manifest


def verify_working(runtime=RUNTIME):
    base = Path(runtime)/'known-good'
    current = json.loads((base/'current.json').read_text())
    name = current['directory']
    need(len(name) == 32 and all(c in '0123456789abcdef' for c in name), 'Invalid known-good identity.')
    need(not (base/name).is_symlink(), 'Known-good generation cannot be a symlink.')
    verify_bundle(base/name)
    return base/name


def validate_analysis_reports(build, reports):
    """Require the current analysis checks, never a historical execution receipt."""
    need(len(reports) == 1, 'The proof frontend report is required.')
    report = reports[0]
    need(report.get('kind') == 'proof-frontend' and report.get('terminal') is True and
         report.get('passed') is True and report.get('artifact_hashes_verified') is True and
         report['identity_before'] == report['identity_after'], 'Analysis checks are incomplete or stale.')
    expected = {'help': 0, 'bare-program': 2, 'batch': 2, 'saved-program': 2,
                'host-execution': 2, 'export-with-execution': 2, 'parse-c': 0, 'translate-core': 0}
    cases = report.get('cases', [])
    need(len(cases) == len(expected) and
         {row['name']: row['exit_code'] for row in cases} == expected,
         'Analysis checks omitted translation or execution-retirement cases.')
    identity = report['identity_before']
    need(identity['parser_binary_sha256'] == build['outputs'][BINARIES[0]] and
         identity['lean_binary_sha256'] == build['outputs'][BINARIES[1]], 'Analysis checks used different binaries.')


def preserve_working(build, smoke_reports, workspace=WORKSPACE, runtime=RUNTIME):
    """Publish only a built, smoke-tested bundle. One retained bundle, <=256 MiB."""
    need(build['terminal'] and build['passed'] and build['exit_code'] == 0 and
         build['inputs_before'] == build['inputs_after'], 'Only an unchanged successful build may be preserved.')
    repo = runtime/'cerberus-lean'
    for name in BINARIES:
        need(sha(repo/name) == build['outputs'][name], 'Executable differs from successful build: ' + name)
    validate_analysis_reports(build, smoke_reports)
    sources = artifact_sources(workspace, runtime)
    prefix = '_build/install/default/'
    actual_runtime = {name[len(prefix):]: sha(path) for name, path in sources.items() if name.startswith(prefix)}
    for report in smoke_reports:
        identity = report['identity_before']
        identity = identity.get('runtime', identity)
        need(identity['installed_runtime_sha256'] == actual_runtime, 'Installed runtime differs from smoke-tested inputs.')
    need(sha(sources['source.patch']) == build['inputs_after']['patch'], 'Patch differs from the built source.')
    total = sum(path.stat().st_size for path in sources.values())
    need(0 < total <= LIMIT and len(sources) <= 4096, 'Artifact bundle exceeds its fixed size/file cap.')
    base = runtime/'known-good'
    base.mkdir(exist_ok=True)
    need(not base.is_symlink(), 'Known-good root cannot be a symlink.')
    current = base/'current.json'
    old = json.loads(current.read_text())['directory'] if current.exists() else None
    if old:
        need(len(old) == 32 and all(c in '0123456789abcdef' for c in old), 'Invalid previous bundle identity.')
        verify_bundle(base/old)
    # Refuse abandoned generations instead of accumulating backups indefinitely.
    need(set(p.name for p in base.iterdir()) <= ({'current.json', old} if old else set()),
         'Unexpected artifact generation present; inspect the recorded failure before continuing.')
    generation = uuid.uuid4().hex
    destination = base/generation
    destination.mkdir()
    try:
        entries = {}
        for name, path in sources.items():
            target = destination/name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            target.chmod(0o555 if name in BINARIES else 0o444)
            entries[name] = dict(bytes=target.stat().st_size, sha256=sha(target))
            need(entries[name]['sha256'] == sha(path), 'Artifact changed while preserving it: ' + name)
        save(destination/'manifest.json', dict(schema=1, bytes=total, files=entries,
             source_patch_sha256=build['inputs_after']['patch'], build=build,
             scope='Buildable and smoke-tested only; outstanding semantic failures are not discharged.'))
        verify_bundle(destination)
        save(current, dict(directory=generation, bytes=total, source_patch_sha256=build['inputs_after']['patch']))
    except BaseException:
        # Only our unpublished generation. The previous pointer and artifacts
        # remain untouched even if copying or manifest validation fails.
        published = json.loads(current.read_text())['directory'] if current.exists() else None
        if published != generation:
            need(not destination.is_symlink() and destination.resolve().parent == base.resolve(),
                 'Unsafe partial artifact path.')
            shutil.rmtree(destination)
        raise
    if old:
        previous = base/old
        need(not previous.is_symlink() and previous.resolve().parent == base.resolve(), 'Unsafe old artifact path.')
        shutil.rmtree(previous)  # Exact verified previous bundle only; never a checkout/build tree.
    return destination


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['verify', 'join'])
    parser.add_argument('--token')
    args = parser.parse_args()
    if args.action == 'join':
        need(bool(args.token), 'Joining requires a live workflow token.')
    with workflow_lock(token=args.token):
        verify_tools()
        print('Pinned tools and workflow lease verified.')
