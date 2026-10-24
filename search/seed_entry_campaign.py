"""Autonomously turn verified native crashes into staged Lean entry searches.

The native replay fixes a concrete argv and supplies a search priority. A Lean
driver kill remains model evidence until input-state and C/Core correspondence
are independently established; this campaign never publishes a signal entry.
"""

import argparse
from collections import OrderedDict
import fcntl
import json
from pathlib import Path
import re
import sqlite3
import time

from common import WORKSPACE, installed_path, need, sha
from core_index import Index
from native_entry_seeds import SeedStore, DEFAULT_STORE, record_sha256
from search_job import Job
from signal_catalog import DEFAULT as DEFAULT_CATALOG
from signal_search import BUILD, checked_build
from native_stack_certificate import collect_verified_seed
from signal_catalog import Catalog


DEFAULT = WORKSPACE / 'local/search/jobs/native-seed-entry'
SCHEMA = '''
CREATE TABLE IF NOT EXISTS identity(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tasks(
 build_sha256 TEXT NOT NULL,seed_id TEXT NOT NULL,hypothesis TEXT NOT NULL,
 query TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'queued',
 last_turn INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(build_sha256,seed_id,hypothesis));
CREATE INDEX IF NOT EXISTS task_order ON tasks(build_sha256,status,last_turn,seed_id);
'''
HYPOTHESES = {
    'driver-kill': 'driverFaultForArgv',
    'memory-access': 'memoryAccessForArgv',
}
SCP_STACK_PROFILE_SHA256 = '1432f65babda45073d2599954c83a29c8555930bf652b149ff52fc2f525cc083'


def packed(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False)


def lean_string(value):
    """Quote an argument as data, without admitting Lean source from argv."""
    need(type(value) is str and '\x00' not in value and
         all(not 0xd800 <= ord(char) <= 0xdfff for char in value),
         'Native argv is not representable as a Lean string')
    return 'String.ofList [' + ','.join(
        'Char.ofNat ' + str(ord(char)) for char in value) + ']'


def lean_argv(values):
    need(type(values) is list and all(type(value) is str for value in values),
         'Native argv is not a string list')
    return '[' + ','.join(lean_string(value) for value in values) + ']'


def hypotheses(seed):
    """Use native stack evidence for the pinned compiler probe crash."""
    if (seed.get('target') == 'scp' and seed.get('signal') == 'SIGSEGV' and
            seed.get('stdin',{}).get('kind') == 'repeated-record' and
            seed.get('provenance',{}).get('profile_sha256') ==
                SCP_STACK_PROFILE_SHA256):
        # Full site and reproducer validation occurs before the GDB run.
        return ('native-stack',)
    if seed['signal'] in ('SIGSEGV', 'SIGBUS'):
        return ('memory-access', 'driver-kill')
    return ('driver-kill',)


def seed_query(index, seed_id, seed, hypothesis):
    """Generate a checked-model proposition; no caller writes Lean source."""
    need(re.fullmatch(r'[0-9a-f]{64}', seed_id) is not None and
         record_sha256(seed) == seed_id and
         seed['kind'] == 'verified-native-fault-seed' and
         hypothesis in hypotheses(seed),
         'Unverified or incompatible native seed query')
    target = seed['target']
    model = index.archive.model(target)
    indexed = index.model(target)
    need(seed['archive_manifest_sha256'] == index.archive.manifest_sha256 and
         seed['model_artifact_sha256'] == model['artifact_sha256'] ==
             indexed['artifact_sha256'],
         'Native seed and current archived model differ')
    if 'model_binding_sha256' in seed:
        need(seed['model_binding_sha256'] == model['binding_sha256'],
             'Native seed and archived source binding differ')
    binding = index.archive.read_json(model['binding_sha256'])
    pinned = binding['native_target']
    binary_path = str(installed_path(pinned['path']))
    need(seed['native_binary'] ==
         {'path':binary_path,'sha256':pinned['sha256']},
         'Native seed is not bound to the archived C binary')
    args = seed['invocation']['argv']
    need(type(args) is list, 'Native seed has no argument list')
    # execve receives the executable path as argv[0]. Cerberus's
    # prepare_main_args consumes the complete argv list.
    argv = [binary_path, *args]
    alias = 'Pinned.' + re.sub(r'[^A-Za-z0-9_]', '_', target)
    need(re.fullmatch(r'Pinned\.[A-Za-z_][A-Za-z0-9_]*', alias) is not None,
         'Native target has no valid Lean alias')
    goal = ('SignalSearch.SeedEntryQuery.' + HYPOTHESES[hypothesis] +
            ' ' + alias + ' (' + lean_argv(argv) + ')')
    return dict(goal=goal, snapshots=[dict(target=target,alias=alias)],
                catalog_policy='staged', stop_after_first=True,
                native_seed=dict(id=seed_id,target=target,signal=seed['signal'],
                    hypothesis=hypothesis,
                    binary_sha256=pinned['sha256'],
                    stdin_sha256=seed['stdin']['sha256'],
                    replay_script_sha256=seed['replay']['script_sha256']),
                scope=('Fixed textual argv and pinned model. Native stdin, '
                       'environment, filesystem, and C/Core correspondence '
                       'remain separate obligations.'))


class SeedEntryCampaign:
    def __init__(self, directory=DEFAULT, *, seed_dir=DEFAULT_STORE,
                 catalog_dir=DEFAULT_CATALOG, seed_factory=SeedStore,
                 index_factory=Index, job_factory=Job,max_live_jobs=4):
        need(type(max_live_jobs) is int and max_live_jobs > 0,
             'Live proof-worker capacity must be positive')
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.seed_dir = Path(seed_dir).resolve()
        self.catalog_dir = Path(catalog_dir).resolve()
        self.seed_factory = seed_factory
        self.index_factory = index_factory
        self.job_factory = job_factory
        self.max_live_jobs = max_live_jobs
        self.live_jobs = OrderedDict()
        self.lock = (self.directory/'campaign.lock').open('a')
        self.db = None
        self.current_build = None
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.db = sqlite3.connect(self.directory/'campaign.sqlite')
            self.db.row_factory = sqlite3.Row
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.executescript(SCHEMA)
        except BaseException:
            self.close()
            raise

    def sync(self):
        checked_build()
        build_sha = sha(BUILD/'build.json')
        if self.current_build is not None and self.current_build != build_sha:
            self._close_jobs()
        index = self.index_factory()
        try:
            wanted = dict(schema='1', seeds=str(self.seed_dir),
                          catalog=str(self.catalog_dir),
                          archive_manifest_sha256=index.archive.manifest_sha256)
            prior = dict(self.db.execute('SELECT key,value FROM identity'))
            need(not prior or prior == wanted,
                 'Seed campaign belongs to another catalog or archive')
            if not prior:
                with self.db:
                    self.db.executemany('INSERT INTO identity VALUES(?,?)',
                                        wanted.items())
            with self.seed_factory(self.seed_dir,
                                   catalog_dir=self.catalog_dir) as store:
                store.sync()
                additions = []
                deferred = []
                for seed_id in store.ids():
                    seed = store.read(seed_id)
                    selected = hypotheses(seed)
                    if selected == ('native-stack',):
                        old_driver = self.db.execute(
                            'SELECT status FROM tasks WHERE build_sha256=? '
                            'AND seed_id=? AND hypothesis=?',
                            (build_sha,seed_id,'driver-kill')).fetchone()
                        if old_driver is not None and old_driver['status'] in (
                                'queued','searching'):
                            deferred.append(seed_id)
                    for hypothesis in selected:
                        if hypothesis == 'native-stack':
                            query = packed(dict(kind='verified-native-stack-request',
                                                seed_id=seed_id))
                        else:
                            query = packed(seed_query(index,seed_id,seed,hypothesis))
                        old = self.db.execute(
                            'SELECT query FROM tasks WHERE build_sha256=? '
                            'AND seed_id=? AND hypothesis=?',
                            (build_sha,seed_id,hypothesis)).fetchone()
                        need(old is None or old['query'] == query,
                             'A previously scheduled seed query changed')
                        if old is None:
                            additions.append((build_sha,seed_id,hypothesis,query))
                for seed_id in deferred:
                    live = self.live_jobs.pop((build_sha,seed_id,'driver-kill'),
                                              None)
                    if live is not None:
                        live.close()
                with self.db:
                    self.db.executemany(
                        'INSERT INTO tasks(build_sha256,seed_id,hypothesis,query) '
                        'VALUES(?,?,?,?)',additions)
                    self.db.executemany(
                        "UPDATE tasks SET status='deferred-inapplicable' "
                        "WHERE build_sha256=? AND seed_id=? "
                        "AND hypothesis='driver-kill' "
                        "AND status IN ('queued','searching')",
                        ((build_sha,seed_id) for seed_id in deferred))
        finally:
            index.close()
        self.current_build = build_sha
        return dict(inserted=len(additions),deferred=len(deferred),
                    **self.status())

    def status(self):
        if self.current_build is None:
            return dict(status='not-synced',tasks={})
        counts = dict(self.db.execute(
            'SELECT status,count(*) FROM tasks WHERE build_sha256=? '
            'GROUP BY status',(self.current_build,)))
        return dict(status='searching' if counts.get('queued',0) or
                    counts.get('searching',0) else 'waiting',
                    build_sha256=self.current_build,tasks=counts)

    def _job(self, row):
        key = (row['build_sha256'],row['seed_id'],row['hypothesis'])
        if key in self.live_jobs:
            self.live_jobs.move_to_end(key)
            return self.live_jobs[key]
        while len(self.live_jobs) >= self.max_live_jobs:
            _, old = self.live_jobs.popitem(last=False)
            old.close()
        directory = (self.directory/'jobs'/row['build_sha256'] /
                     row['seed_id']/row['hypothesis'])
        job = self.job_factory(directory,json.loads(row['query']),
                               catalog=self.catalog_dir)
        self.live_jobs[key] = job
        return job

    def _close_jobs(self):
        while self.live_jobs:
            _, job = self.live_jobs.popitem(last=False)
            job.close()

    def advance(self, work_items=1000,round_seconds=30.0):
        need(type(work_items) is int and work_items > 0,
             'Search quantum must be positive')
        need(type(round_seconds) in (float,int) and round_seconds > 0,
             'Search round duration must be positive')
        need(self.current_build is not None,'Sync seeds before searching')
        row = self.db.execute(
            "SELECT * FROM tasks WHERE build_sha256=? AND status IN "
            "('queued','searching') ORDER BY last_turn,seed_id,"
            "CASE hypothesis WHEN 'native-stack' THEN 0 "
            "WHEN 'memory-access' THEN 1 ELSE 2 END LIMIT 1",
            (self.current_build,)).fetchone()
        if row is None:
            return self.status()
        key = (row['build_sha256'],row['seed_id'],row['hypothesis'])
        if row['hypothesis'] == 'native-stack':
            with Catalog(self.catalog_dir) as catalog:
                prior = list(catalog.list_native_stack_certificates(row['seed_id']))
                if prior:
                    identity = prior[0]['id']
                    checked = catalog.replay_native_stack_certificate(identity)
                else:
                    identity = collect_verified_seed(row['seed_id'],
                        catalog_dir=self.catalog_dir,seed_dir=self.seed_dir)
                    checked = catalog.replay_native_stack_certificate(identity)
            turn = self.db.execute(
                'SELECT COALESCE(MAX(last_turn),0)+1 FROM tasks '
                'WHERE build_sha256=?',(self.current_build,)).fetchone()[0]
            with self.db:
                self.db.execute(
                    'UPDATE tasks SET status=?,last_turn=? WHERE build_sha256=? '
                    'AND seed_id=? AND hypothesis=?',
                    ('certified-native',turn,row['build_sha256'],row['seed_id'],
                     row['hypothesis']))
            return dict(seed_id=row['seed_id'],hypothesis='native-stack',
                        certificate_id=identity,certificate=checked,
                        **self.status())
        job = self._job(row)
        try:
            state = job.status()
            deadline = time.monotonic() + round_seconds
            for _ in range(work_items):
                if state['status'] != 'searching' or time.monotonic() >= deadline:
                    break
                state = job.advance()
        except BaseException:
            self.live_jobs.pop(key).close()
            raise
        if state['status'] != 'searching':
            self.live_jobs.pop(key).close()
        need(state['status'] in ('searching','proved','quiescent'),
             'Unexpected Lean proof-job status')
        turn = self.db.execute(
            'SELECT COALESCE(MAX(last_turn),0)+1 FROM tasks '
            'WHERE build_sha256=?',(self.current_build,)).fetchone()[0]
        with self.db:
            self.db.execute(
                'UPDATE tasks SET status=?,last_turn=? WHERE build_sha256=? '
                'AND seed_id=? AND hypothesis=?',
                (state['status'],turn,row['build_sha256'],row['seed_id'],
                 row['hypothesis']))
        return dict(seed_id=row['seed_id'],hypothesis=row['hypothesis'],
                    job=state, **self.status())

    def close(self):
        self._close_jobs()
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.lock is not None:
            self.lock.close()
            self.lock = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('sync','status','advance','run'))
    parser.add_argument('--directory',type=Path,default=DEFAULT)
    parser.add_argument('--seeds',type=Path,default=DEFAULT_STORE)
    parser.add_argument('--catalog',type=Path,default=DEFAULT_CATALOG)
    parser.add_argument('--work-items',type=int,default=1000)
    parser.add_argument('--round-seconds',type=float,default=30.0)
    parser.add_argument('--max-live-jobs',type=int,default=4)
    parser.add_argument('--refresh-seconds',type=float,default=60.0)
    args = parser.parse_args()
    need(args.refresh_seconds > 0,'Refresh interval must be positive')
    with SeedEntryCampaign(args.directory,seed_dir=args.seeds,
                           catalog_dir=args.catalog,
                           max_live_jobs=args.max_live_jobs) as campaign:
        if args.command == 'sync':
            print(packed(campaign.sync()),flush=True)
        elif args.command == 'status':
            campaign.sync()
            print(packed(campaign.status()),flush=True)
        elif args.command == 'advance':
            campaign.sync()
            print(packed(campaign.advance(args.work_items,args.round_seconds)),flush=True)
        else:
            campaign.sync()
            refreshed = time.monotonic()
            while True:
                state = campaign.advance(args.work_items,args.round_seconds)
                print(packed(state),flush=True)
                if state['status'] == 'waiting':
                    time.sleep(args.refresh_seconds)
                    campaign.sync()
                    refreshed = time.monotonic()
                elif time.monotonic() - refreshed >= args.refresh_seconds:
                    campaign.sync()
                    refreshed = time.monotonic()


if __name__ == '__main__':
    main()
