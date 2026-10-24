"""Persistent Lean proof worker over selected fragments of the current archive."""
import hashlib
import errno
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from common import WORKSPACE, RUNTIME, installed_path, need, sha
from core_index import Index


SOURCE = WORKSPACE/'search/lean'
BUILD = RUNTIME/'signal-search'


def checked_build():
    receipt = json.loads((BUILD/'build.json').read_bytes())
    files = {str(p.relative_to(SOURCE)): sha(p) for p in sorted(SOURCE.rglob('*'))
             if p.is_file() and (p.suffix in ('.lean', '.toml') or p.name == 'lean-toolchain')}
    need(files == receipt['files'], 'Search sources changed; rebuild the checked Lean worker')
    executable = BUILD/'.lake/build/bin/signal-search'
    need(sha(executable) == receipt['executable_sha256'], 'Search executable changed')
    for path, digest in receipt['import_artifacts'].items():
        need(sha(installed_path(path)) == digest,
             'Search semantic dependency changed: '+path)
    builder = receipt.get('snapshot_builder')
    need(type(builder) is dict and
         builder.get('source_sha256') == receipt['files'].get('SnapshotBuilder.lean') and
         sha(BUILD/'.lake/build/bin/snapshot-builder') == builder.get('executable_sha256') and
         type(builder.get('import_artifacts')) is dict and
         bool(builder['import_artifacts']),
         'Snapshot builder differs from the checked build')
    for path, digest in builder['import_artifacts'].items():
        need(sha(installed_path(path)) == digest,
             'Snapshot-builder semantic dependency changed: '+path)
    return executable, receipt


class Worker:
    """One worker per job: semantics imports and immutable proof contexts are shared.

    Only declared fragments are introduced. A name/hash identity cannot silently
    be rebound inside an existing proof environment.
    """
    def __init__(self, directory, modules=(), lean_path=(), role='search'):
        executable, self.build = checked_build()
        need(role in ('search', 'snapshot-builder') and
             (role == 'search' or not modules),
             'Invalid proof-worker role or snapshot-builder imports')
        if role == 'snapshot-builder':
            executable = BUILD/'.lake/build/bin/snapshot-builder'
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.stderr = (self.directory/'worker.stderr').open('a')
        tool_bin = WORKSPACE/'work/lean-4.32.2-linux/bin'
        environment = dict(os.environ, PATH=str(tool_bin)+os.pathsep+os.environ['PATH'])
        command = [str(tool_bin/'lake'), 'env']
        if lean_path:
            # Lake constructs LEAN_PATH inside `lake env`, so prepend our
            # checked cache root only after Lake has prepared that environment.
            roots = os.pathsep.join(str(Path(path).resolve()) for path in lean_path)
            command += ['sh', '-c',
                        'LEAN_PATH="$1${LEAN_PATH:+:$LEAN_PATH}"; export LEAN_PATH; shift; exec "$@"',
                        'sh', roots]
        self.process = subprocess.Popen(
            [*command, str(executable), *modules], cwd=BUILD, env=environment,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr,
            text=True, encoding='utf-8', bufsize=1)
        self.loaded = {}
        self.snapshot_import_timings = {}
        try:
            response = self.request(dict(op='ping'))
            need(response['status'] == 'ready', 'Lean worker failed to initialize: '+str(response))
            self.imports = {}
            if modules:
                response = self.request(dict(op='imports'))
                need(response['status'] == 'imports', 'Could not identify query imports')
                self.imports = {path: sha(Path(path)) for path in response['paths']}
        except BaseException:
            self.close()
            raise

    def request(self, request):
        need(self.process.poll() is None, 'Lean worker exited; inspect '+str(self.directory/'worker.stderr'))
        self.process.stdin.write(json.dumps(request, separators=(',', ':'))+'\n')
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        need(line, 'Lean worker closed its response stream; inspect '+str(self.directory/'worker.stderr'))
        return json.loads(line)

    def load(self, index, target, field, ordinal, name):
        metadata, raw = index.read(target, field, ordinal)
        if name in self.loaded:
            need(self.loaded[name] == metadata, 'A proof fragment name cannot be rebound')
            return metadata
        path = self.directory/(metadata['sha256']+'.json')
        if path.exists():
            need(hashlib.sha256(path.read_bytes()).hexdigest() == metadata['sha256'],
                 'Saved proof fragment changed')
        else:
            path.write_bytes(raw)
        response = self.request(dict(op='load', section=field, name=name,
                                     path=str(path), sha256=metadata['sha256']))
        need(response['status'] == 'loaded', 'Lean rejected the fragment: '+str(response))
        self.loaded[name] = metadata
        return metadata

    def load_snapshot(self, index, target, name):
        """Quote one complete, source-bound archived model into the proof worker.

        Linked model objects are gzip streams named by digest in the archive.
        The Lean importer recognizes a .gz suffix, so expose the exact bytes
        under that suffix without changing or decompressing the archive.
        """
        indexed = index.model(target)
        entry = index.archive.model(target)
        need(indexed['artifact_sha256'] == entry['artifact_sha256'],
             'Indexed target differs from the current linked model')
        metadata = dict(target=target, artifact_sha256=entry['artifact_sha256'],
                        binding_sha256=entry['binding_sha256'],
                        archive_manifest_sha256=index.archive.manifest_sha256)
        if name in self.loaded:
            need(self.loaded[name] == metadata, 'A proof model name cannot silently change identity')
            return metadata
        source = index.archive.object_path(entry['artifact_sha256'])
        alias = self.directory/(entry['artifact_sha256']+'.json.gz')
        if not alias.exists():
            try:
                os.link(source, alias)
            except OSError as error:
                if error.errno != errno.EXDEV:
                    raise
                with tempfile.NamedTemporaryFile(dir=self.directory, suffix='.json.gz',
                                                 delete=False) as temporary:
                    pending = Path(temporary.name)
                    try:
                        with source.open('rb') as original:
                            shutil.copyfileobj(original, temporary)
                    except BaseException:
                        pending.unlink(missing_ok=True)
                        raise
                need(sha(pending) == entry['artifact_sha256'], 'Copied model bytes changed')
                os.replace(pending, alias)
        need(sha(alias) == entry['artifact_sha256'], 'Pinned linked model bytes changed')
        response = self.request(dict(op='load_snapshot', name=name, path=str(alias),
                                     sha256=entry['artifact_sha256']))
        need(response['status'] == 'snapshot-loaded' and
             response['artifact_sha256'] == entry['artifact_sha256'],
             'Lean rejected the complete linked model: '+str(response))
        self.loaded[name] = metadata
        self.snapshot_import_timings[name] = dict(response['timing'],
                                                  worker_elapsed_ns=response['elapsed_ns'])
        return metadata

    def use_snapshot(self, index, target, name, cache):
        """Select an already checked model imported at worker startup."""
        module_path = Path(cache['path'])
        need(self.imports.get(str(module_path)) == cache['olean_sha256'],
             'Query worker imported different cached model bytes')
        indexed = index.model(target)
        entry = index.archive.model(target)
        need(indexed['artifact_sha256'] == entry['artifact_sha256'] and
             cache['identity']['target'] == target and
             cache['identity']['artifact_sha256'] == entry['artifact_sha256'] and
             cache['identity']['binding_sha256'] == entry['binding_sha256'] and
             cache['identity']['declaration_name'] == name and
             cache['identity']['archive_manifest_sha256'] == index.archive.manifest_sha256,
             'Cached proof model identity differs from current archive')
        metadata = dict(target=target, artifact_sha256=entry['artifact_sha256'],
                        binding_sha256=entry['binding_sha256'],
                        archive_manifest_sha256=index.archive.manifest_sha256)
        if name in self.loaded:
            need(self.loaded[name] == metadata, 'A proof model name cannot silently change identity')
            return metadata
        response = self.request(dict(op='use_snapshot', name=name))
        need(response['status'] == 'snapshot-in-use' and response['name'] == name,
             'Lean did not import the cached model: '+str(response))
        self.loaded[name] = metadata
        self.snapshot_import_timings[name] = dict(cached=True,
                                                  worker_elapsed_ns=response['elapsed_ns'])
        return metadata

    def scan(self, index, target, section, ordinal, kinds=()):
        """Inspect one exact typed record without adding it to the proof environment."""
        metadata, raw = index.read(target, section, ordinal)
        path = self.directory/'scan-input.json'
        path.write_bytes(raw)
        try:
            response = self.request(dict(op='scan', section=section, path=str(path),
                                         sha256=metadata['sha256'], kinds=list(kinds)))
        finally:
            path.unlink(missing_ok=True)
        need(response['status'] == 'sites' and response['section'] == section,
             'Lean rejected the typed scan: '+str(response))
        return metadata, response

    def sites(self, alias, kinds=()):
        need(alias in self.loaded, 'Load a typed model record before inspecting it')
        response = self.request(dict(op='sites', name=alias, kinds=list(kinds)))
        need(response['status'] == 'sites', 'Could not inspect typed model record: '+str(response))
        return response

    def close(self):
        if self.process.stdin and not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait()
        self.process.stdout.close()
        self.stderr.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
