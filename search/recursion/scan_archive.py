"""Stream archived function rows through the standalone Lean recursion scanner.

The detector finds exact-symbol direct self-call candidates. It does not infer
reachability, unbounded recursion, platform stack limits, or native signals.
Results are keyed by content hash so shared fragments across all 14 targets
are analyzed once and every target membership is retained.
"""
import argparse
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time

WORKSPACE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(WORKSPACE / 'search'))
from core_index import Index  # noqa: E402
from signal_search import BUILD, checked_build  # noqa: E402

SOURCE = Path(__file__).with_name('Main.lean')
DEFAULT = WORKSPACE / 'local/search/recursion-campaign'
SCHEMA = '''
CREATE TABLE IF NOT EXISTS identity(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scans(
  sha256 TEXT PRIMARY KEY, created_ns INTEGER NOT NULL, result TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS members(
  target TEXT NOT NULL, ordinal INTEGER NOT NULL, sha256 TEXT NOT NULL,
  name TEXT, kind TEXT, PRIMARY KEY(target, ordinal));
CREATE INDEX IF NOT EXISTS members_sha ON members(sha256,target,ordinal);
'''


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def packed(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def open_state(directory, identity):
    directory.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(directory / 'scan.sqlite')
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=FULL')
    db.executescript(SCHEMA)
    stored = dict(db.execute('SELECT key,value FROM identity'))
    if stored:
        if stored != identity:
            raise RuntimeError('Scanner, checked worker, or archive identity changed')
    else:
        with db:
            db.executemany('INSERT INTO identity VALUES(?,?)', identity.items())
    return db


def start_lean(directory, log_name='lean.stderr', expected_worker_sha=None):
    executable, receipt = checked_build()
    if expected_worker_sha is not None and \
            receipt['executable_sha256'] != expected_worker_sha:
        raise RuntimeError('Checked Lean worker changed during scan')
    tool_bin = WORKSPACE / 'work/lean-4.32.2-linux/bin'
    environment = dict(os.environ, PATH=str(tool_bin) + os.pathsep + os.environ['PATH'])
    lean_path = subprocess.check_output(
        [str(tool_bin / 'lake'), 'env', 'printenv', 'LEAN_PATH'],
        cwd=BUILD, env=environment, text=True).strip()
    environment['LEAN_PATH'] = lean_path
    log = (directory / log_name).open('a')
    try:
        process = subprocess.Popen(
            [str(tool_bin / 'lean'), '--run', str(SOURCE), '--jsonl'],
            cwd=SOURCE.parent, env=environment, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=log, text=True, bufsize=1)
    except BaseException:
        log.close()
        raise
    return process, log, receipt


def request(process, path, digest):
    if process.poll() is not None:
        raise RuntimeError('Lean scanner exited before the request')
    process.stdin.write(packed(dict(path=str(path), sha256=digest)) + '\n')
    process.stdin.flush()
    response = process.stdout.readline()
    if not response:
        raise RuntimeError('Lean scanner closed its output stream')
    result = json.loads(response)
    if result.get('status') != 'scanned' or result.get('row_sha256') != digest:
        raise RuntimeError('Lean scanner rejected the hash-pinned row: ' + packed(result))
    return result


class LeanPool:
    """One persistent Lean process and row file per thread; no SQLite access."""

    def __init__(self, directory, jobs, source_sha, worker_sha):
        self.directory = directory
        self.source_sha = source_sha
        self.worker_sha = worker_sha
        self.executor = ThreadPoolExecutor(max_workers=jobs)
        self.local = threading.local()
        self.lock = threading.Lock()
        self.cancelled = threading.Event()
        self.workers = []

    def scan(self, raw, digest):
        worker = getattr(self.local, 'worker', None)
        if worker is None:
            if sha(SOURCE) != self.source_sha:
                raise RuntimeError('Lean scanner source changed during scan')
            ident = threading.get_ident()
            row_path = self.directory / f'current-row-{ident}.json'
            process, log, _ = start_lean(self.directory, f'lean-{ident}.stderr',
                                         self.worker_sha)
            worker = (process, log, row_path)
            with self.lock:
                if self.cancelled.is_set():
                    if process.poll() is None:
                        process.terminate()
                    process.wait()
                    process.stdout.close()
                    process.stdin.close()
                    log.close()
                    raise RuntimeError('Scan interrupted during worker startup')
                self.workers.append(worker)
            self.local.worker = worker
        process, _, row_path = worker
        row_path.write_bytes(raw)
        return request(process, row_path, digest)

    def submit(self, raw, digest):
        return self.executor.submit(self.scan, raw, digest)

    def close(self, interrupted=False):
        if interrupted:
            with self.lock:
                self.cancelled.set()
                active = list(self.workers)
            for process, _, _ in active:
                if process.poll() is None:
                    process.terminate()
        self.executor.shutdown(wait=True, cancel_futures=interrupted)
        for process, log, row_path in self.workers:
            try:
                process.stdin.close()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait()
            finally:
                process.stdout.close()
                log.close()
                row_path.unlink(missing_ok=True)


def scan_rows(index, db, directory, targets, name, ordinal, jobs,
              source_sha, worker_sha, work_items=None):
    """Stream the selection; a work quantum yields without narrowing its scope."""
    pool = LeanPool(directory, jobs, source_sha, worker_sha)
    pending = {}
    queued = set()
    scanned = 0
    submitted = 0
    exhausted = True
    writes = 0

    def commit_if_needed(force=False):
        nonlocal writes
        if force or writes >= 64:
            db.commit()
            writes = 0

    def harvest():
        nonlocal scanned, writes
        done, _ = wait(pending, return_when=FIRST_COMPLETED)
        for future in sorted(done, key=lambda item: pending[item][1]['sha256']):
            target, row = pending.pop(future)
            queued.remove(row['sha256'])
            result = future.result()
            if sha(SOURCE) != source_sha:
                raise RuntimeError('Lean scanner source changed during scan')
            db.execute('INSERT INTO scans VALUES(?,?,?)',
                       (row['sha256'], time.time_ns(), packed(result)))
            scanned += 1
            writes += 1
            if result['candidates']:
                commit_if_needed(force=True)
                print(packed(dict(target=target, ordinal=row['ordinal'],
                                  sha256=row['sha256'],
                                  candidates=result['candidates'])), flush=True)
            else:
                commit_if_needed()
            if scanned % 1000 == 0:
                commit_if_needed(force=True)
                print(packed(dict(scanned_groups=scanned,
                                  last_target=target,
                                  last_ordinal=row['ordinal'])),
                      file=sys.stderr, flush=True)

    try:
        for target, row in rows(index, targets, name, ordinal):
            digest = row['sha256']
            if digest not in queued and db.execute(
                    'SELECT 1 FROM scans WHERE sha256=?', (digest,)).fetchone() is None:
                if work_items is not None and submitted >= work_items:
                    exhausted = False
                    break
                while len(pending) >= jobs * 2:
                    harvest()
                meta, raw = index.read(target, 'funs', row['ordinal'])
                if meta['sha256'] != digest:
                    raise RuntimeError('Index row hash changed')
                pending[pool.submit(raw, digest)] = (target, row)
                queued.add(digest)
                submitted += 1
            added = db.execute('INSERT OR IGNORE INTO members VALUES(?,?,?,?,?)',
                               (target, row['ordinal'], digest,
                                row['name'], row['kind']))
            writes += added.rowcount
            commit_if_needed()
        while pending:
            harvest()
        commit_if_needed(force=True)
        return scanned, exhausted
    except BaseException:
        # Every completed write remains recoverable; uncommitted work is valid
        # and can be repeated idempotently on the next run.
        db.commit()
        raise
    finally:
        pool.close(interrupted=bool(pending))


def rows(index, targets, name, ordinal):
    for target in targets:
        if ordinal is not None:
            selected = index.db.execute(
                'SELECT * FROM fragments WHERE target=? AND section=? AND ordinal=?',
                (target, 'funs', ordinal)).fetchone()
            if selected is None:
                raise ValueError('Unknown function ordinal for ' + target)
            candidates = [dict(selected)]
        else:
            candidates = index.find(target, 'funs', name)
        for row in candidates:
            if row['kind'] in ('Fun', 'Proc'):
                yield target, row


def report(db):
    results = []
    for digest, payload in db.execute('SELECT sha256,result FROM scans ORDER BY sha256'):
        result = json.loads(payload)
        if not result['candidates']:
            continue
        members = [dict(target=target, ordinal=ordinal, name=name)
                   for target, ordinal, name in db.execute(
                       'SELECT target,ordinal,name FROM members WHERE sha256=? '
                       'ORDER BY target,ordinal', (digest,))]
        results.append(dict(sha256=digest, members=members,
                            candidates=result['candidates']))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=DEFAULT)
    parser.add_argument('--target', action='append',
                        help='Defaults to all archived OpenSSH programs')
    parser.add_argument('--name', help='Optional exact archived function name')
    parser.add_argument('--ordinal', type=int,
                        help='One exact function row; requires one --target')
    parser.add_argument('--status', action='store_true')
    parser.add_argument('--report', action='store_true')
    parser.add_argument('--jobs', type=int, default=4,
                        help='Parallel persistent Lean workers (default: 4)')
    parser.add_argument('--work-items', type=int,
                        help='Yield after this many new groups; resume later')
    args = parser.parse_args()
    if args.ordinal is not None and (not args.target or len(args.target) != 1):
        parser.error('--ordinal requires exactly one --target')
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    if args.work_items is not None and args.work_items < 1:
        parser.error('--work-items must be positive')
    index = Index()
    targets = args.target or sorted(index.archive.data['models'])
    for target in targets:
        index.model(target)
    _, checked = checked_build()
    identity = dict(archive_manifest=index.archive.manifest_sha256,
                    standalone_source_sha256=sha(SOURCE),
                    checked_worker_executable_sha256=checked['executable_sha256'])
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    lock = (directory / 'scan.lock').open('a+b')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        db = open_state(directory, identity)
    except BaseException:
        lock.close()
        raise
    try:
        if args.status or args.report:
            print(packed(dict(status='ready',
                scanned_groups=db.execute('SELECT count(*) FROM scans').fetchone()[0],
                members=db.execute('SELECT count(*) FROM members').fetchone()[0],
                candidates=report(db) if args.report else None)))
            return
        newly_scanned, exhausted = scan_rows(
            index, db, directory, targets, args.name, args.ordinal, args.jobs,
            identity['standalone_source_sha256'],
            identity['checked_worker_executable_sha256'], args.work_items)
        if sha(SOURCE) != identity['standalone_source_sha256']:
            raise RuntimeError('Lean scanner source changed during this campaign run')
        print(packed(dict(status='complete' if exhausted else 'yielded',
                          scanned_now=newly_scanned,
                          scanned_groups=db.execute('SELECT count(*) FROM scans').fetchone()[0],
                          members=db.execute('SELECT count(*) FROM members').fetchone()[0])))
    finally:
        db.close()
        index.db.close()
        lock.close()


if __name__ == '__main__':
    main()
