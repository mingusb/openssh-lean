"""Build archive-search consumers with the existing pinned tools and workflow lease."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

from common import WORKSPACE, RUNTIME, need, record_child, save, sha, seal_tools, verify_tools, workflow_lock


def run(command, cwd, env=None):
    child = subprocess.Popen(command, cwd=cwd, env=env)
    record_child(child)
    need(child.wait() == 0, 'Signal-search build command failed')


def build_framer():
    source = WORKSPACE/'search/core_json_framer.c'
    directory = RUNTIME/'signal-search-native'
    directory.mkdir(exist_ok=True)
    library, receipt = directory/'core_json_framer.so', directory/'build.json'
    identity = dict(source_sha256=sha(source), compiler_sha256=sha(Path(shutil.which('cc'))))
    if receipt.exists() and library.exists():
        previous = json.loads(receipt.read_bytes())
        if all(previous.get(k) == v for k, v in identity.items()) and previous.get('library_sha256') == sha(library):
            return library
    temporary = directory/'core_json_framer.so.pending'
    run(['cc', '-std=c11', '-O3', '-fPIC', '-shared', '-Wall', '-Wextra', '-Werror',
         str(source), '-o', str(temporary)], directory)
    need(identity['source_sha256'] == sha(source), 'Framer source changed during build')
    os.replace(temporary, library)
    save(receipt, dict(identity, library_sha256=sha(library)))
    return library


def build_lean():
    source = WORKSPACE/'search/lean'
    directory = RUNTIME/'signal-search'
    directory.mkdir(exist_ok=True)
    files = {str(p.relative_to(source)): sha(p) for p in sorted(source.rglob('*'))
             if p.is_file() and (p.suffix in ('.lean', '.toml') or p.name == 'lean-toolchain')}
    need(files and 'lakefile.toml' in files, 'Search Lean package is missing')
    before_path = directory/'source-receipt.json'
    previous = json.loads(before_path.read_bytes()) if before_path.exists() else {}
    for name in previous.get('files', {}):
        if name not in files:
            path = directory/name
            need(path.resolve().is_relative_to(directory.resolve()) and not path.is_symlink(),
                 'Stale analysis source path escaped build directory')
            path.unlink(missing_ok=True)
    for name, digest in files.items():
        dest = directory/name
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists() or sha(dest) != digest:
            shutil.copyfile(source/name, dest)
    save(before_path, dict(files=files))
    repo = WORKSPACE/'local/runtime/cerberus-lean'
    shutil.copyfile(repo/'lean_frontend/lean-toolchain', directory/'lean-toolchain')
    run(['opam', 'exec', '--switch='+str(repo), '--',
         str(WORKSPACE/'work/lean-4.32.2-linux/bin/lake'), 'build'], directory,
        env=dict(os.environ, OPAMROOT=str(RUNTIME/'opam-root'),
                 LEAN_CC='/usr/bin/cc'))
    need(all(sha(source/name) == digest for name,digest in files.items()),
         'Search source changed while building')
    # Lake records the transitive non-toolchain imports used for this worker.
    # The executable alone does not identify the .olean files loaded at runtime.
    setup = json.loads((directory/'.lake/build/ir/SignalSearch/Worker.setup.json').read_bytes())
    imports = {str(Path(path).resolve()): sha(Path(path))
               for paths in setup['importArts'].values() for path in paths}
    builder_setup = json.loads((directory/'.lake/build/ir/SnapshotBuilder.setup.json').read_bytes())
    builder_imports = {str(Path(path).resolve()): sha(Path(path))
                       for paths in builder_setup['importArts'].values()
                       for path in paths}
    need(builder_imports and not any('SignalSearch.olean' in path
                                    for path in builder_imports),
         'Snapshot builder imported the full search proof environment')
    snapshot_builder = dict(
        source_sha256=files['SnapshotBuilder.lean'],
        executable_sha256=sha(directory/'.lake/build/bin/snapshot-builder'),
        import_artifacts=builder_imports)
    save(directory/'build.json', dict(files=files,
        executable_sha256=sha(directory/'.lake/build/bin/signal-search'),
        import_artifacts=imports,
        snapshot_builder=snapshot_builder,
        toolchain_sha256=verify_tools()))
    return directory/'.lake/build/bin/signal-search'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-only', action='store_true')
    parser.add_argument('--seal-tools', action='store_true',
                        help='Explicitly record the installed pinned toolchain')
    args = parser.parse_args()
    RUNTIME.mkdir(parents=True, exist_ok=True)
    if args.seal_tools:
        seal_tools()
        print(json.dumps(dict(toolchain_sealed=True)))
        return
    with workflow_lock():
        verify_tools()
        library = build_framer()
        executable = None if args.native_only else build_lean()
        print(json.dumps(dict(passed=True, framer=str(library),
                              executable=str(executable) if executable else None)))


if __name__ == '__main__':
    main()
