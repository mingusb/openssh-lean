"""Local digest memoization under the workflow lease, never a new provenance claim.

A hit requires the same inode, device, mode, size, mtime and ctime. Any changed
metadata forces a fresh content hash. Cache corruption/missing files are misses.
The cache is an optimization for locally controlled build/runtime artifacts.
"""
import hashlib
import json
import os
from pathlib import Path
import stat


def signature(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns]


class VerifiedDigests:
    def __init__(self, path):
        self.path = Path(path)
        self.entries = {}
        self.dirty = False
        try:
            record = json.loads(self.path.read_bytes())
            entries = record['entries']
            encoded = json.dumps(entries, sort_keys=True, separators=(',', ':')).encode()
            if isinstance(entries, dict) and record['schema'] == 1 and record['integrity'] == hashlib.sha256(encoded).hexdigest():
                self.entries = entries
        except (OSError, ValueError, KeyError, TypeError):
            pass

    def digest(self, path):
        path = Path(path)
        # Open first so the signature and hash refer to the same file object.
        with path.open('rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise RuntimeError('Expected a regular artifact file: '+str(path))
            current = signature(before)
            previous = self.entries.get(str(path))
            if isinstance(previous, dict) and previous.get('signature') == current:
                digest = previous.get('sha256', '')
                if isinstance(digest, str) and len(digest) == 64 and all(c in '0123456789abcdef' for c in digest):
                    return digest
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            if signature(os.fstat(stream.fileno())) != current or signature(path.stat()) != current:
                raise RuntimeError('Artifact changed during verification: '+str(path))
        self.entries[str(path)] = dict(signature=current, sha256=digest)
        self.dirty = True
        return digest

    def flush(self):
        if not self.dirty:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(self.entries, sort_keys=True, separators=(',', ':')).encode()
        record = dict(schema=1, entries=self.entries, integrity=hashlib.sha256(encoded).hexdigest())
        temporary = self.path.with_name(self.path.name+'.'+str(os.getpid())+'.tmp')
        temporary.write_text(json.dumps(record, sort_keys=True))
        temporary.replace(self.path)
        self.dirty = False
