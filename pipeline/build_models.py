#!/usr/bin/env python3
"""Reconstruct the pinned local toolchain and publish the 14 model archive.

Run from a Linux checkout. Generated sources, receipts, binaries, and the
multi-gigabyte archive live in ignored work/, outputs/, and local/ directories.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'work'
LOCAL = ROOT / 'local'
RUNTIME = LOCAL / 'runtime'
PROJECT = ROOT / 'outputs/openssh-lean'
EVIDENCE = PROJECT / 'evidence'
CERBERUS_PIN = 'c4284b08f80c4461f97d179896868106e510327e'
OPENSSH_PIN = 'a8c72b842423f0774f542d3c2197247c3dd28d74'
LEAN_URL = 'https://github.com/leanprover/lean4/releases/download/v4.32.2/lean-4.32.2-linux.tar.zst'
LEAN_SHA256 = '5f2069e6f5db73780f374ccb49ce8ea649aa20a0cebf0116816744c999ce72aa'
LEM_PIN = '2d3a492758cb23dc4e417f2961983d25b36ce130'


def run(*args, cwd=ROOT, env=None, stdout=None):
    command = [str(item) for item in args]
    print('+', ' '.join(command), flush=True)
    subprocess.run(command, cwd=cwd, env=env, stdout=stdout, check=True)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def link(destination, source):
    source = Path(source).resolve(strict=True)
    if destination.is_symlink():
        if destination.resolve() != source:
            raise RuntimeError(f'Unexpected existing link: {destination}')
    elif destination.exists():
        raise RuntimeError(f'Unexpected existing path: {destination}')
    else:
        destination.symlink_to(source, target_is_directory=source.is_dir())


def stage():
    if sys.platform != 'linux' or platform.machine() != 'x86_64':
        raise RuntimeError('This pinned build requires Linux x86_64')
    for directory in (WORK, LOCAL, RUNTIME, RUNTIME/'logs', EVIDENCE,
                      PROJECT/'scripts', PROJECT/'patches', LOCAL/'models'):
        directory.mkdir(parents=True, exist_ok=True)
    for path in (ROOT/'pipeline').glob('*.py'):
        link(WORK/path.name, path)
    for name in ('model_archive.py', 'saved_program_provenance.py',
                 'source_locations.py', 'verified_file_cache.py'):
        link(WORK/name, ROOT/'search'/name)
    link(WORK/'cerberus-changed-files.txt', ROOT/'cerberus/changed-files.txt')
    link(PROJECT/'patches/cerberus-gnu-keywords.patch', ROOT/'cerberus/patch.patch')
    for name in ('import_c.py', 'exercise_imported_c.py', 'preprocessed_input.py'):
        if sha(ROOT/'pipeline/host'/name) != sha(ROOT/'cerberus'/name):
            raise RuntimeError('Duplicated host helper differs from cerberus/: '+name)
    for path in (ROOT/'pipeline/host').glob('*'):
        if path.is_file() and path.suffix in ('.py', '.sh'):
            link(PROJECT/'scripts'/path.name, path)
    required = (
        WORK/'build_guard.py', WORK/'run_whole_table_build.py',
        WORK/'export_release.py', WORK/'linked_source_binding.py',
        WORK/'export_target_inventory.py', WORK/'bind_export_targets.py',
        WORK/'export_all_target_core.py', WORK/'freeze_models.py',
        WORK/'model_archive.py', WORK/'source_locations.py',
        PROJECT/'scripts/bootstrap_cerberus.sh',
        PROJECT/'scripts/preserve_generated_timestamps.py',
        PROJECT/'scripts/run_capped_lean_build.py',
        PROJECT/'scripts/check_host_dispatch.py',
        PROJECT/'scripts/ssh_startup_inputs.py',
        PROJECT/'scripts/inventory.py', PROJECT/'scripts/import_c.py',
        PROJECT/'scripts/catalog_host_adapters.py',
        ROOT/'cerberus/census_c.py', ROOT/'cerberus/ssh_dependencies.py',
        ROOT/'cerberus/patch.patch', ROOT/'cerberus/verify.py',
    )
    missing = [str(path.relative_to(ROOT)) for path in required if not path.is_file()]
    if missing:
        raise RuntimeError('Incomplete model source package: '+', '.join(missing))
    fork = WORK/'cerberus-lean'
    if fork.exists():
        link(LOCAL/'cerberus-lean', fork)
    runtime_fork = RUNTIME/'cerberus-lean'
    if runtime_fork.is_symlink():
        raise RuntimeError('The build checkout must be physical, not a source symlink')
    print(json.dumps({'staged': True, 'model_archive': str(LOCAL/'models/current')}))


def clone_pinned(url, destination, pin):
    if not destination.exists():
        run('git', 'clone', url, destination)
        run('git', '-C', destination, 'checkout', '--detach', pin)
    actual = subprocess.check_output(['git', '-C', str(destination), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != pin:
        raise RuntimeError(f'{destination} has {actual}, expected {pin}')



def verify_actual_tree(fork=None):
    """Compare the actual patched checkout with the recorded Git tree."""
    fork = Path(fork or WORK/'cerberus-lean')
    package = json.loads((ROOT/'cerberus/source-package.json').read_text())['cerberus']
    names = (ROOT/'cerberus/changed-files.txt').read_text(encoding='utf-8').splitlines()
    with tempfile.TemporaryDirectory(prefix='model-source-index-') as temporary:
        env = dict(os.environ, GIT_INDEX_FILE=str(Path(temporary)/'index'))
        subprocess.run(['git', '-C', str(fork), 'read-tree', CERBERUS_PIN], env=env, check=True)
        subprocess.run(['git', '-C', str(fork), 'add', '-f', '--all', '--', *names], env=env, check=True)
        tree = subprocess.check_output(['git', '-C', str(fork), 'write-tree'], env=env, text=True).strip()
    if tree != package['patched_tree']:
        raise RuntimeError('Actual Cerberus source differs from the pinned patch tree')
    changed = set(subprocess.check_output(['git', '-C', str(fork), 'diff', '--name-only', CERBERUS_PIN],
                                          text=True).splitlines())
    if changed - set(names):
        raise RuntimeError('Tracked Cerberus edits outside the pinned patch')


def fetch_sources():
    clone_pinned('https://github.com/OathTech/cerberus-lean.git', WORK/'cerberus-lean', CERBERUS_PIN)
    fork = WORK/'cerberus-lean'
    patch = ROOT/'cerberus/patch.patch'
    reverse = subprocess.run(['git', '-C', str(fork), 'apply', '--reverse', '--check', str(patch)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if reverse.returncode:
        run('git', '-C', fork, 'apply', patch)
    stage()
    run(sys.executable, ROOT/'cerberus/verify.py')
    run('git', '-C', fork, 'apply', '--reverse', '--check', patch)
    verify_actual_tree(fork)
    runtime_fork = RUNTIME/'cerberus-lean'
    clone_pinned('https://github.com/OathTech/cerberus-lean.git', runtime_fork, CERBERUS_PIN)
    reverse = subprocess.run(['git', '-C', str(runtime_fork), 'apply', '--reverse', '--check', str(patch)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if reverse.returncode:
        run('git', '-C', runtime_fork, 'apply', patch)
    verify_actual_tree(runtime_fork)
    clone_pinned('https://github.com/openssh/openssh-portable.git', WORK/'reference-source', OPENSSH_PIN)


def install_lean():
    target = WORK/'lean-4.32.2-linux'
    if (target/'bin/lean').is_file():
        version = subprocess.check_output([str(target/'bin/lean'), '--version'], text=True)
        if 'version 4.32.2' not in version:
            raise RuntimeError('Wrong local Lean version')
        return
    archive = LOCAL/'lean-4.32.2-linux.tar.zst'
    if not archive.is_file():
        with urllib.request.urlopen(LEAN_URL, timeout=120) as source, archive.open('wb') as output:
            shutil.copyfileobj(source, output, 8*1024*1024)
    if sha(archive) != LEAN_SHA256:
        raise RuntimeError('Lean release archive digest differs; inspect the download')
    run('tar', '--zstd', '-xf', archive, '-C', WORK)
    if 'version 4.32.2' not in subprocess.check_output([str(target/'bin/lean'), '--version'], text=True):
        raise RuntimeError('Extracted Lean version differs')


def install_opam():
    if subprocess.check_output(['ocamlc', '-version'], text=True).strip() != '5.4.0':
        raise RuntimeError('Install OCaml 5.4.0 before setup')
    repo = RUNTIME/'cerberus-lean'
    opam_root = RUNTIME/'opam-root'
    env = dict(os.environ, OPAMROOT=str(opam_root), OPAMJOBS='4', OPAMDOWNLOADJOBS='4')
    if not (opam_root/'config').is_file():
        run('opam', 'init', '--bare', '--no-setup', '-y', cwd=repo, env=env)
    if not (repo/'_opam').is_dir():
        run('opam', 'switch', 'create', '.', 'ocaml-system.5.4.0', '--no-switch', '--no-install', '-y', cwd=repo, env=env)
    run('opam', 'pin', 'add', '--switch=.', 'lem',
        'git+https://github.com/OathTech/lem-lean.git#'+LEM_PIN, '--yes', cwd=repo, env=env)
    run('opam', 'install', '--switch=.', '--deps-only', './cerberus-lib.opam', './cerberus.opam', '--yes', cwd=repo, env=env)
    if not (WORK/'toolchain-lock.json').exists():
        run(sys.executable, '-c',
            'import sys; sys.path.insert(0, sys.argv[1]); from build_guard import seal_tools; seal_tools()',
            WORK, cwd=ROOT, env=env)


def setup():
    stage()
    fetch_sources()
    install_lean()
    install_opam()


def configure_openssh(jobs):
    src = WORK/'reference-source'
    if not (src/'Makefile').is_file():
        run('autoreconf', cwd=src)
        run('./configure', '--without-openssl', '--without-zlib', cwd=src)
    config = subprocess.check_output([str(src/'config.status'), '--config'], text=True).strip()
    if config != '--without-openssl --without-zlib':
        raise RuntimeError('OpenSSH configuration differs: '+config)
    run('make', f'-j{jobs}', 'all', cwd=src)


def build_frontend():
    receipt = RUNTIME/'logs/whole-table-build.json'
    if receipt.is_file():
        try:
            sys.path.insert(0, str(WORK))
            from run_pointer_check_plan import check_build
            check_build(ROOT, RUNTIME, sha(receipt))
            print('Reusing verified Cerberus build receipt')
            return
        except Exception as error:
            print('Rebuilding Cerberus:', error)
    run(sys.executable, WORK/'run_whole_table_build.py', ROOT, RUNTIME)


def prepare_inputs(jobs):
    stage()
    if not (WORK/'cerberus-lean').is_dir() or not (WORK/'reference-source').is_dir() or not (RUNTIME/'cerberus-lean').is_dir():
        raise RuntimeError('Run setup first')
    configure_openssh(jobs)
    build_frontend()
    existing = (RUNTIME/'c-import/census.json', RUNTIME/'import-fork/import-report.json',
                RUNTIME/'ssh-dependencies/result.json', EVIDENCE/'ssh-dependencies.json',
                EVIDENCE/'adapter-catalog.json', EVIDENCE/'source-inventory.json')
    if all(path.is_file() for path in existing):
        sys.path.insert(0, str(PROJECT/'scripts'))
        from ssh_startup_inputs import load_inputs
        parser = WORK/'cerberus-lean/_build/default/backend/driver/main.exe'
        load_inputs(ROOT, RUNTIME, parser)
        print('Reusing verified OpenSSH model inputs')
        return
    run(sys.executable, PROJECT/'scripts/inventory.py', '--source', WORK/'reference-source',
        '--output-dir', EVIDENCE)
    plan = WORK/'openssh-full-build-plan.txt'
    with plan.open('wb') as output:
        run('make', '-B', '-n', 'all', cwd=WORK/'reference-source', stdout=output)
    census_dir = RUNTIME/'c-import'
    if census_dir.exists():
        raise RuntimeError('Existing C census; use a fresh runtime or verify/reuse it explicitly')
    run(sys.executable, ROOT/'cerberus/census_c.py', '--source', WORK/'reference-source',
        '--plan', plan, '--inventory', EVIDENCE/'source-inventory.json',
        '--output', census_dir, '--clang', WORK/'lean-4.32.2-linux/bin/clang', '--jobs', min(jobs, 8))
    shutil.copyfile(census_dir/'census.json', EVIDENCE/'c-source-census.json')
    imports = RUNTIME/'import-fork'
    if imports.exists():
        raise RuntimeError('Existing C import; use a fresh runtime or verify/reuse it explicitly')
    run(sys.executable, PROJECT/'scripts/import_c.py', '--census', census_dir/'census.json',
        '--cerberus', WORK/'cerberus-lean', '--output', imports,
        '--gnu-pointer-conversions', '--jobs', min(jobs, 12))
    deps = RUNTIME/'ssh-dependencies'
    run(sys.executable, ROOT/'cerberus/ssh_dependencies.py', '--census', census_dir/'census.json',
        '--imports', imports/'import-report.json', '--output', deps)
    shutil.copyfile(deps/'result.json', EVIDENCE/'ssh-dependencies.json')
    catalog = RUNTIME/'adapter-catalog'
    run(sys.executable, PROJECT/'scripts/catalog_host_adapters.py', '--workspace', ROOT,
        '--output', catalog)
    shutil.copyfile(catalog/'adapter-catalog.json', EVIDENCE/'adapter-catalog.json')


def export_models(run_id, jobs):
    run(sys.executable, WORK/'export_release.py', '--model-targets',
        '--run-id', run_id, '--jobs', jobs)
    result = RUNTIME/f'release-run-{run_id}'/'result.json'
    data = json.loads(result.read_text())
    if not data.get('terminal') or not data.get('passed'):
        raise RuntimeError('Model export did not pass: '+str(result))
    return RUNTIME/f'release-core-{run_id}'/'result.json'


def freeze_models(result):
    run(sys.executable, WORK/'freeze_models.py', '--result', result)
    archive = LOCAL/'models/current'
    run(sys.executable, WORK/'model_archive.py', '--archive', archive, 'verify', '--deep', '--offline')
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('stage', 'setup', 'inputs', 'export', 'freeze', 'all', 'status'))
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--run-id', default=datetime.now(timezone.utc).strftime('models-%Y%m%dT%H%M%SZ'))
    parser.add_argument('--result', type=Path)
    args = parser.parse_args()
    if args.jobs < 1 or args.jobs > 12:
        parser.error('jobs must be 1..12')
    if args.command == 'stage':
        stage()
    elif args.command == 'setup':
        setup()
    elif args.command == 'inputs':
        prepare_inputs(args.jobs)
    elif args.command == 'export':
        stage()
        print(export_models(args.run_id, args.jobs))
    elif args.command == 'freeze':
        stage()
        if args.result is None:
            parser.error('freeze requires --result')
        print(freeze_models(args.result))
    elif args.command == 'all':
        setup()
        prepare_inputs(args.jobs)
        print(freeze_models(export_models(args.run_id, args.jobs)))
    else:
        archive = LOCAL/'models/current'
        receipt_path = RUNTIME/'logs/whole-table-build.json'
        receipt = json.loads(receipt_path.read_text()) if receipt_path.is_file() else {}
        print(json.dumps({'sources': (WORK/'cerberus-lean').is_dir() and (WORK/'reference-source').is_dir(),
                          'build': receipt.get('terminal') is True and receipt.get('passed') is True,
                          'census': (RUNTIME/'c-import/census.json').is_file(),
                          'models': (archive/'manifest.json').is_file(), 'archive': str(archive)}))


if __name__ == '__main__':
    main()
