"""Checked, content-addressed Lean modules for complete archived Core models."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
import uuid

from common import WORKSPACE, need, sha
from signal_search import Worker, checked_build


DEFAULT = WORKSPACE/'local/search/snapshot-cache'
FORMAT = 2


def packed(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def cache_key(identity):
    return hashlib.sha256(packed(identity).encode('utf-8')).hexdigest()


def cache_location(root, identity):
    key = cache_key(identity)
    name = 'k_'+key
    # A separate top-level namespace avoids Lean resolving the checked
    # SignalSearch package from this dynamically generated cache root.
    return ('PinnedCoreCache.'+name,
            Path(root)/'PinnedCoreCache'/(name+'.olean'))


def valid_receipt(path, receipt_path, identity, module):
    """A missing, partial, or changed module is always a cache miss."""
    if path.is_symlink() or receipt_path.is_symlink() or not path.is_file():
        return False
    try:
        receipt = json.loads(receipt_path.read_bytes())
        if not isinstance(receipt, dict):
            return False
        return (receipt.get('schema') == FORMAT and
                receipt.get('identity') == identity and
                receipt.get('key') == cache_key(identity) and
                receipt.get('module') == module and
                receipt.get('declaration') == identity['declaration_name'] and
                receipt.get('olean_bytes') == path.stat().st_size and
                receipt.get('olean_sha256') == sha(path))
    except (FileNotFoundError, ValueError, KeyError, OSError):
        return False


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class SnapshotModuleCache:
    def __init__(self, root=DEFAULT):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def identity(self, index, target, name):
        """Pin the target and all inputs that define the saved declaration."""
        indexed = index.model(target)
        entry = index.archive.model(target)
        need(indexed['artifact_sha256'] == entry['artifact_sha256'],
             'Indexed target differs from archived model')
        header = json.loads(indexed['header'])
        binding_path = Path(header['sourceBindingPath'])
        need(binding_path.is_absolute() and
             header['sourceBindingSHA256'] == entry['binding_sha256'],
             'Indexed source binding differs from archived model')
        index.archive.resolve(binding_path, entry['binding_sha256'])
        binding = index.archive.read_json(entry['binding_sha256'])
        need(binding['target'] == target and
             header['translatorSHA256'] == binding['translator']['sha256'],
             'Indexed translator differs from archived binding')
        _, build = checked_build()
        builder = build['snapshot_builder']
        lean_executable = WORKSPACE/'work/lean-4.32.2-linux/bin/lean'
        toolchain = WORKSPACE/'work/toolchain-lock.json'
        files = json.loads(toolchain.read_bytes())['files']
        matches = [row['sha256'] for path, row in files.items()
                   if path == str(lean_executable) or
                   path.endswith('/work/lean-4.32.2-linux/bin/lean')]
        need(len(matches) == 1, 'Pinned Lean executable is missing from the toolchain lock')
        pinned = matches[0]
        need(sha(lean_executable) == pinned, 'Pinned Lean executable changed')
        return dict(module_format=FORMAT,
                    archive_manifest_sha256=index.archive.manifest_sha256,
                    target=target,
                    artifact_sha256=entry['artifact_sha256'],
                    binding_path=str(binding_path),
                    binding_sha256=entry['binding_sha256'],
                    translator_path=binding['translator']['path'],
                    translator_sha256=binding['translator']['sha256'],
                    declaration_name=name,
                    builder_dependencies_sha256=cache_key(builder),
                    toolchain_sha256=sha(toolchain),
                    lean_executable_sha256=pinned)

    def prepare(self, index, target, name):
        """Verify a hit or kernel-check, serialize, and publish one miss."""
        identity = self.identity(index, target, name)
        module, path = cache_location(self.root, identity)
        path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path = path.with_suffix('.json')
        lock_path = path.with_suffix('.lock')
        with lock_path.open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            source = index.archive.object_path(identity['artifact_sha256'])
            need(sha(source) == identity['artifact_sha256'],
                 'Pinned linked model bytes changed')
            hit = valid_receipt(path, receipt_path, identity, module)
            builder_directory = self.root/'builders'/cache_key(identity)
            with Worker(builder_directory, role='snapshot-builder') as builder:
                if hit:
                    checked = builder.request(dict(op='verify_snapshot_binding',
                        binding_path=identity['binding_path'],
                        binding_sha256=identity['binding_sha256'],
                        translator_path=identity['translator_path'],
                        translator_sha256=identity['translator_sha256']))
                    need(checked['status'] == 'binding-verified',
                         'Cached model source binding changed: '+str(checked))
                else:
                    builder.load_snapshot(index, target, name)
                    pending = path.parent/('.pending-'+cache_key(identity)+
                                           '-'+uuid.uuid4().hex+'.olean')
                    try:
                        written = builder.request(dict(op='write_snapshot_module',
                            module=module, name=name, path=str(pending)))
                        need(written['status'] == 'snapshot-module-written' and
                             written['module'] == module and written['name'] == name,
                             'Lean did not serialize the checked model: '+str(written))
                        need(pending.is_file() and pending.stat().st_size > 0,
                             'Lean wrote no model module')
                        with pending.open('rb') as stream:
                            os.fsync(stream.fileno())
                        digest = sha(pending)
                        size = pending.stat().st_size
                        os.replace(pending, path)
                        sync_directory(path.parent)
                        receipt = dict(schema=FORMAT, identity=identity,
                                       key=cache_key(identity), module=module,
                                       declaration=name, olean_sha256=digest,
                                       olean_bytes=size)
                        with tempfile.NamedTemporaryFile('w', encoding='utf-8',
                                prefix='.receipt-', suffix='.json', dir=path.parent,
                                delete=False) as output:
                            pending_receipt = Path(output.name)
                            output.write(packed(receipt)+'\n')
                            output.flush()
                            os.fsync(output.fileno())
                        try:
                            os.replace(pending_receipt, receipt_path)
                            sync_directory(path.parent)
                        finally:
                            pending_receipt.unlink(missing_ok=True)
                    finally:
                        pending.unlink(missing_ok=True)
            if not hit:
                need(valid_receipt(path, receipt_path, identity, module),
                     'Published snapshot cache did not revalidate')
            receipt = json.loads(receipt_path.read_bytes())
        return dict(module=module, path=str(path), receipt=str(receipt_path),
                    identity=identity, olean_sha256=receipt['olean_sha256'], hit=hit)
