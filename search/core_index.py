"""Persistent random access to exact fragments of the current Core model archive.

The one-time streaming pass preserves all snapshot fields, not just functions.
Search consumers read a small fragment by target/section/key, never a whole model.
"""
import argparse
import ctypes
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import time

from model_archive import Archive, sha
from saved_program_provenance import need

WORKSPACE = Path(__file__).resolve().parent.parent
RUNTIME = WORKSPACE/'local/runtime'
DEFAULT_INDEX = WORKSPACE/'local/search/index'
ROWS = {'tagDefs', 'enumDefs', 'stdlib', 'impl0', 'globs', 'funs', 'extern',
        'funinfo', 'loopAttributes', 'visibleObjects'}
SCALARS = {'main', 'callingConvention'}


class Frame(ctypes.Structure):
    _fields_ = [('depth', ctypes.c_uint64), ('started', ctypes.c_uint32),
                ('kind', ctypes.c_uint32), ('quoted', ctypes.c_uint32),
                ('escaped', ctypes.c_uint32)]


class Framer:
    def __init__(self, library=None):
        source = Path(__file__).with_name('core_json_framer.c')
        if library is None:
            root = RUNTIME/'signal-search-native'
            receipt = json.loads((root/'build.json').read_bytes())
            need(receipt['source_sha256'] == sha(source), 'Index framer needs a checked rebuild')
            library = root/'core_json_framer.so'
            need(receipt['library_sha256'] == sha(library), 'Index framer binary changed')
        self.library = ctypes.CDLL(str(library))
        self.feed = self.library.core_json_frame_feed
        self.feed.argtypes = [ctypes.POINTER(Frame), ctypes.c_void_p,
                              ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self.feed.restype = ctypes.c_int


class Stream:
    def __init__(self, stream, framer, chunk_size=1024*1024):
        self.stream, self.framer, self.chunk_size = stream, framer, chunk_size
        self.buffer, self.position, self.offset = b'', 0, 0
        self.digest, self.bytes_read = hashlib.sha256(), 0

    def fill(self):
        if self.position < len(self.buffer):
            return True
        self.offset += len(self.buffer)
        self.buffer = self.stream.read(self.chunk_size)
        self.position = 0
        self.digest.update(self.buffer)
        self.bytes_read += len(self.buffer)
        return bool(self.buffer)

    def peek(self):
        while self.fill():
            value = self.buffer[self.position]
            if value not in b' \r\n\t':
                return value
            self.position += 1
        return None

    def take(self, byte):
        need(self.peek() == byte, 'Unexpected JSON delimiter at '+str(self.tell()))
        self.position += 1

    def tell(self):
        return self.offset + self.position

    def value(self):
        need(self.peek() is not None, 'Truncated JSON value')
        start, state, chunks = self.tell(), Frame(), []
        while self.fill():
            data = self.buffer[self.position:]
            used = ctypes.c_size_t()
            status = self.framer.feed(ctypes.byref(state), data, len(data), ctypes.byref(used))
            need(status >= 0, 'Invalid JSON framing at '+str(self.tell()))
            chunks.append(data[:used.value])
            self.position += used.value
            if status == 1:
                return start, self.tell(), b''.join(chunks)
        # A scalar can end at EOF; its actual JSON grammar is checked by readers.
        need(state.kind == 3 and state.started, 'Truncated JSON composite or string')
        return start, self.tell(), b''.join(chunks)

    def object_fields(self):
        self.take(ord('{'))
        names = set()
        if self.peek() == ord('}'):
            self.position += 1
            return
        while True:
            _, _, raw = self.value()
            key = json.loads(raw)
            need(isinstance(key, str) and key not in names, 'Invalid or duplicate JSON field')
            names.add(key)
            self.take(ord(':'))
            yield key
            delimiter = self.peek()
            if delimiter == ord('}'):
                self.position += 1
                return
            self.take(ord(','))

    def array(self):
        self.take(ord('['))
        if self.peek() == ord(']'):
            self.position += 1
            return
        while True:
            yield self.value()
            if self.peek() == ord(']'):
                self.position += 1
                return
            self.take(ord(','))


def row_identity(raw, framer):
    stream = Stream(io.BytesIO(raw), framer)
    stream.take(ord('['))
    _, _, first = stream.value()
    key = json.loads(first)
    name, kind, location = None, None, None
    if isinstance(key, dict) and 'Symbol' in key:
        symbol = key['Symbol']
        need(isinstance(symbol, list) and len(symbol) == 3, 'Malformed symbol')
        desc = symbol[2]
        if isinstance(desc, dict):
            name = desc.get('SD_Id') or desc.get('SD_ObjectAddress')
    stream.take(ord(','))
    if stream.peek() == ord('{'):
        stream.position += 1
        _, _, raw_kind = stream.value()
        kind = json.loads(raw_kind)
        stream.take(ord(':'))
        if kind in ('Proc', 'ProcDecl', 'BuiltinDecl'):
            stream.take(ord('['))
            _, _, loc = stream.value()
            location = json.loads(loc)
    return json.dumps(key, separators=(',', ':')), name, kind, location


SCHEMA = '''
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS models(
 target TEXT PRIMARY KEY, artifact_sha256 TEXT NOT NULL, raw_sha256 TEXT NOT NULL,
 raw_bytes INTEGER NOT NULL, header TEXT NOT NULL, counts TEXT NOT NULL,
 indexed_seconds REAL NOT NULL);
CREATE TABLE IF NOT EXISTS objects(
 sha256 TEXT PRIMARY KEY, raw_bytes INTEGER NOT NULL, compressed BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS fragments(
 target TEXT NOT NULL, section TEXT NOT NULL, ordinal INTEGER NOT NULL,
 sha256 TEXT NOT NULL REFERENCES objects(sha256), raw_start INTEGER NOT NULL,
 raw_end INTEGER NOT NULL, symbol_key TEXT, name TEXT, kind TEXT, location TEXT,
 PRIMARY KEY(target,section,ordinal));
CREATE INDEX IF NOT EXISTS fragment_name ON fragments(target,section,name);
CREATE INDEX IF NOT EXISTS fragment_symbol ON fragments(target,section,symbol_key);
'''


class Index:
    def __init__(self, root=DEFAULT_INDEX, archive=None, writable=False):
        self.root = Path(root).resolve()
        self.archive = archive or Archive(WORKSPACE/'local/models/current')
        path = self.root/'index.sqlite'
        if writable:
            self.root.mkdir(parents=True, exist_ok=True)
            self.db = sqlite3.connect(path)
        else:
            self.db = sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)
        try:
            if writable:
                self.db.execute('PRAGMA journal_mode=WAL')
                self.db.execute('PRAGMA synchronous=FULL')
                self.db.executescript(SCHEMA)
            wanted = {'schema': '1', 'archive_manifest': self.archive.manifest_sha256}
            existing = dict(self.db.execute('SELECT key,value FROM metadata'))
            if writable and not existing:
                self.db.executemany('INSERT INTO metadata VALUES(?,?)', wanted.items())
                self.db.commit()
            else:
                need(existing == wanted, 'Index belongs to a different archive/schema')
            self.db.row_factory = sqlite3.Row
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def add(self, target, section, ordinal, start, end, raw, framer):
        digest = hashlib.sha256(raw).hexdigest()
        if not self.db.execute('SELECT 1 FROM objects WHERE sha256=?', (digest,)).fetchone():
            self.db.execute('INSERT INTO objects VALUES(?,?,?)',
                            (digest, len(raw), gzip.compress(raw, compresslevel=1, mtime=0)))
        key, name, kind, loc = row_identity(raw, framer) if section in ROWS else (None, None, None, None)
        self.db.execute('INSERT INTO fragments VALUES(?,?,?,?,?,?,?,?,?,?)',
            (target, section, ordinal, digest, start, end, key, name, kind,
             json.dumps(loc, separators=(',', ':')) if loc is not None else None))

    def build_target(self, target, framer, progress=None):
        entry = self.archive.model(target)
        previous = self.db.execute('SELECT * FROM models WHERE target=?', (target,)).fetchone()
        if previous:
            need(previous['artifact_sha256'] == entry['artifact_sha256'], 'Indexed model changed')
            return dict(target=target, reused=True, counts=json.loads(previous['counts']))
        report = self.archive.read_json(entry['report_sha256'])
        row = next(r for r in report['targets'] if r['target'] == target)
        path = self.archive.object_path(entry['artifact_sha256'])
        need(sha(path) == entry['artifact_sha256'], 'Model bytes changed before indexing')
        before = path.stat()
        started = time.monotonic()
        header, counts, sections = {}, {}, set()
        with self.db:
            self.db.execute('DELETE FROM fragments WHERE target=?', (target,))
            with gzip.open(path, 'rb') as file:
                stream = Stream(file, framer)
                for field in stream.object_fields():
                    if field != 'snapshot':
                        _, _, raw = stream.value()
                        header[field] = json.loads(raw)
                        continue
                    for section in stream.object_fields():
                        sections.add(section)
                        need(section in ROWS | SCALARS, 'Unknown snapshot field: '+section)
                        if section in ROWS:
                            count = 0
                            for start, end, raw in stream.array():
                                self.add(target, section, count, start, end, raw, framer)
                                count += 1
                            counts[section] = count
                        else:
                            start, end, raw = stream.value()
                            json.loads(raw)
                            self.add(target, section, 0, start, end, raw, framer)
                            counts[section] = 1
                        if progress:
                            progress(dict(target=target, section=section, fragments=counts[section],
                                          raw_bytes=stream.tell()))
                need(stream.peek() is None, 'Trailing model data')
            need(sections == ROWS | SCALARS, 'Incomplete snapshot fields')
            need(stream.digest.hexdigest() == row['raw_output_sha256'] and
                 stream.bytes_read == row['raw_output_bytes'], 'Decompressed model differs from export')
            need(header.get('schemaVersion') == 1 and
                 header.get('translatorSHA256') == self.archive.data['cohort']['translator_sha256'] and
                 header.get('sourceBindingSHA256') == entry['binding_sha256'] and
                 header.get('linkedFunctionCount') == counts['funs'] and
                 header.get('linkedGlobalCount') == counts['globs'], 'Model header/counts differ')
            after = path.stat()
            need((before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) ==
                 (after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),
                 'Model changed during indexing')
            elapsed = time.monotonic()-started
            self.db.execute('INSERT INTO models VALUES(?,?,?,?,?,?,?)',
                (target, entry['artifact_sha256'], stream.digest.hexdigest(), stream.bytes_read,
                 json.dumps(header, separators=(',', ':')), json.dumps(counts), elapsed))
        self.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        return dict(target=target, reused=False, seconds=elapsed, counts=counts)

    def model(self, target):
        row = self.db.execute('SELECT * FROM models WHERE target=?', (target,)).fetchone()
        need(row is not None, 'Target is not indexed yet: '+target)
        need(row['artifact_sha256'] == self.archive.model(target)['artifact_sha256'],
             'Indexed model differs from archive')
        return dict(row)

    def find(self, target, section, name=None):
        self.model(target)
        # Without index statistics SQLite can prefer the ordinal primary key
        # and scan an entire tool to avoid sorting a handful of name matches.
        hint = ' INDEXED BY fragment_name' if name is not None else ''
        sql, args = 'SELECT * FROM fragments'+hint+' WHERE target=? AND section=?', [target, section]
        if name is not None:
            sql += ' AND name=?'
            args.append(name)
        return [dict(r) for r in self.db.execute(sql+' ORDER BY ordinal', args)]

    def read(self, target, section, ordinal):
        model = self.model(target)
        row = self.db.execute('''SELECT f.*,o.raw_bytes,o.compressed FROM fragments f
            JOIN objects o ON f.sha256=o.sha256
            WHERE target=? AND section=? AND ordinal=?''', (target,section,ordinal)).fetchone()
        need(row is not None, 'Fragment is not indexed')
        raw = gzip.decompress(row['compressed'])
        need(len(raw) == row['raw_bytes'] == row['raw_end']-row['raw_start'] and
             hashlib.sha256(raw).hexdigest() == row['sha256'], 'Indexed fragment bytes changed')
        metadata = {k:row[k] for k in row.keys() if k!='compressed'}
        metadata.update(artifact_sha256=model['artifact_sha256'],
                        archive_manifest_sha256=self.archive.manifest_sha256)
        return metadata, raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index', type=Path, default=DEFAULT_INDEX)
    sub = parser.add_subparsers(dest='command', required=True)
    build = sub.add_parser('build')
    build.add_argument('--target', action='append', help='Defaults to every configured tool')
    lookup = sub.add_parser('find')
    lookup.add_argument('--target', required=True)
    lookup.add_argument('--section', required=True, choices=sorted(ROWS))
    lookup.add_argument('--name')
    read = sub.add_parser('read')
    read.add_argument('--target', required=True)
    read.add_argument('--section', required=True, choices=sorted(ROWS | SCALARS))
    read.add_argument('--ordinal', type=int, required=True)
    sub.add_parser('status')
    args = parser.parse_args()
    if args.command == 'build':
        from common import workflow_lock, save
        with workflow_lock():
            index = Index(args.index, writable=True)
            framer = Framer()
            try:
                for target in args.target or index.archive.data['models']:
                    result = index.build_target(target, framer,
                        lambda row: print(json.dumps(row), file=sys.stderr, flush=True))
                    print(json.dumps(result), flush=True)
                completed = [r[0] for r in index.db.execute('SELECT target FROM models ORDER BY target')]
                receipt = dict(schema=1, archive_manifest_sha256=index.archive.manifest_sha256,
                    targets=completed, complete=set(completed)==set(index.archive.data['models']),
                    fragments=index.db.execute('SELECT count(*) FROM fragments').fetchone()[0],
                    objects=index.db.execute('SELECT count(*) FROM objects').fetchone()[0],
                    database_bytes=(index.root/'index.sqlite').stat().st_size,
                    indexer_sha256=sha(Path(__file__)), framer_sha256=sha(Path(__file__).with_name('core_json_framer.c')))
                save(index.root/'receipt.json', receipt)
                print(json.dumps(receipt), flush=True)
            finally:
                index.close()
        return
    index = Index(args.index)
    try:
        if args.command == 'find':
            print(json.dumps(index.find(args.target, args.section, args.name), indent=2))
        elif args.command == 'read':
            metadata, raw = index.read(args.target, args.section, args.ordinal)
            print(json.dumps(metadata), file=sys.stderr)
            sys.stdout.buffer.write(raw+b'\n')
        else:
            rows = [dict(r) for r in index.db.execute('SELECT target,artifact_sha256,counts,indexed_seconds FROM models ORDER BY target')]
            print(json.dumps(dict(archive_manifest_sha256=index.archive.manifest_sha256,
                complete=len(rows)==len(index.archive.data['models']), models=rows), indent=2))
    finally:
        index.close()


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
        print(json.dumps(dict(status='error',error=str(error))), file=sys.stderr)
        sys.exit(2)
