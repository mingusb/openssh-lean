"""Durable, autonomous native-crash discovery and staged proof search.

Native probes, fatal-signal cataloging, seed synchronization, and seed-entry
search share one process. Each stage owns its existing evidence store; this
coordinator records handoffs and retries without treating a finite work slice
as a search limit.
"""
import argparse
import fcntl
import json
from pathlib import Path
import signal
import sqlite3
import stat
import threading
import time

from common import WORKSPACE, need
from native_input_search import NativeFrontier, DEFAULT as DEFAULT_FRONTIER
from native_frontier_catalog import (ingest_fatal_outcomes,
                                     retry_fatal_observation)
from seed_entry_campaign import SeedEntryCampaign, DEFAULT as DEFAULT_CAMPAIGN
from native_entry_seeds import DEFAULT_STORE as DEFAULT_SEEDS
from signal_catalog import DEFAULT as DEFAULT_CATALOG


DEFAULT = WORKSPACE/'local/search/jobs/autonomous-loop'
SCHEMA = """
CREATE TABLE IF NOT EXISTS identity(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS fatal_intake(
 input_id TEXT NOT NULL, attempt INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN
  ('queued','error','replay-pending','done','superseded')),
 result TEXT, next_retry_ns INTEGER NOT NULL DEFAULT 0,
 updated_ns INTEGER NOT NULL,
 PRIMARY KEY(input_id,attempt));
CREATE INDEX IF NOT EXISTS fatal_intake_due
 ON fatal_intake(status,next_retry_ns,updated_ns);
CREATE TABLE IF NOT EXISTS replay_pending(
 observation_id TEXT PRIMARY KEY,
 input_id TEXT NOT NULL, attempt INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','done')),
 attempts INTEGER NOT NULL, next_retry_ns INTEGER NOT NULL,
 result TEXT NOT NULL, updated_ns INTEGER NOT NULL,
 FOREIGN KEY(input_id,attempt) REFERENCES fatal_intake(input_id,attempt));
CREATE INDEX IF NOT EXISTS replay_pending_due
 ON replay_pending(status,next_retry_ns,updated_ns);
CREATE TABLE IF NOT EXISTS stage_retry(
 stage TEXT NOT NULL, item_key TEXT NOT NULL,
 failures INTEGER NOT NULL, next_retry_ns INTEGER NOT NULL,
 PRIMARY KEY(stage,item_key));
CREATE TABLE IF NOT EXISTS stage_attempts(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 stage TEXT NOT NULL, item_key TEXT NOT NULL,
 started_ns INTEGER NOT NULL, finished_ns INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('ok','error')),
 result TEXT, error TEXT);
CREATE INDEX IF NOT EXISTS stage_attempts_recent ON stage_attempts(id DESC);
"""


def packed(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def _error(error):
    return type(error).__name__+': '+str(error)


def _replay_summary(item):
    replay = item.get('replay') or {}
    script = replay.get('script') or {}
    return dict(id=item['id'],target=item.get('target'),
                signal=item.get('signal'),status=item.get('status'),
                reproduced=replay.get('reproducer_verified') is True,
                exact_site=replay.get('exact_site_verified') is True,
                pinned_target=script.get('pinned_target_attributed') is True,
                site_count=len(script.get('exact_pc_sites') or []))


def _qualified(item):
    replay = item.get('replay') or {}
    script = replay.get('script') or {}
    return (replay.get('reproducer_verified') is True and
            replay.get('exact_site_verified') is True and
            script.get('status') == 'reproduced' and
            script.get('pinned_target_attributed') is True and
            bool(script.get('exact_pc_sites')))


def read_status(directory=DEFAULT):
    """Inspect one committed receipt snapshot without taking its writer lock."""
    path = Path(directory).resolve()/'loop.sqlite'
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        return dict(status='not-started', directory=str(path.parent))
    need(stat.S_ISREG(mode), 'Coordinator database path is not a regular file')
    db = sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)
    db.row_factory = sqlite3.Row
    try:
        db.execute('BEGIN')
        required = {'fatal_intake','replay_pending','stage_retry','stage_attempts'}
        tables = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        missing = required-tables
        if missing:
            return dict(status='unavailable', directory=str(path.parent),
                        reason='incomplete-schema', missing_tables=sorted(missing))
        intake = dict(db.execute(
            'SELECT status,count(*) FROM fatal_intake GROUP BY status'))
        replays = dict(db.execute(
            'SELECT status,count(*) FROM replay_pending GROUP BY status'))
        retries = [dict(row) for row in db.execute(
            'SELECT stage,item_key,failures,next_retry_ns FROM stage_retry '
            'ORDER BY next_retry_ns,stage,item_key LIMIT 20')]
        recent = [dict(row) for row in db.execute(
            'SELECT id,stage,item_key,started_ns,finished_ns,status,result,error '
            'FROM stage_attempts ORDER BY id DESC LIMIT 10')]
        return dict(status='recorded', directory=str(path.parent),
                    fatal_intake=intake, replay_pending=replays,
                    retries=retries, recent=recent)
    finally:
        db.close()


class AutonomousSearchLoop:
    def __init__(self, directory=DEFAULT, *, frontier_dir=DEFAULT_FRONTIER,
                 catalog_dir=DEFAULT_CATALOG, seed_dir=DEFAULT_SEEDS,
                 campaign_dir=DEFAULT_CAMPAIGN,
                 frontier_factory=NativeFrontier,
                 campaign_factory=SeedEntryCampaign,
                 ingest=ingest_fatal_outcomes,
                 retry=retry_fatal_observation,
                 native_work_items=14, catalog_work_items=2,
                 proof_work_items=1000, proof_round_seconds=10.0,
                 refresh_seconds=60.0, retry_seconds=1.0,
                 time_ns=time.time_ns):
        need(type(native_work_items) is int and native_work_items > 0 and
             type(catalog_work_items) is int and catalog_work_items > 0 and
             type(proof_work_items) is int and proof_work_items > 0 and
             proof_round_seconds > 0 and refresh_seconds > 0 and retry_seconds > 0,
             'Search quanta and intervals must be positive')
        self.directory = Path(directory).resolve()
        self.frontier_dir = Path(frontier_dir).resolve()
        self.catalog_dir = Path(catalog_dir).resolve()
        self.seed_dir = Path(seed_dir).resolve()
        self.campaign_dir = Path(campaign_dir).resolve()
        self.frontier_factory = frontier_factory
        self.campaign_factory = campaign_factory
        self.ingest = ingest
        self.retry = retry
        self.native_work_items = native_work_items
        self.catalog_work_items = catalog_work_items
        self.proof_work_items = proof_work_items
        self.proof_round_seconds = proof_round_seconds
        self.refresh_ns = int(refresh_seconds*1e9)
        self.retry_ns = int(retry_seconds*1e9)
        self.time_ns = time_ns
        self.frontier = None
        self.campaign = None
        self.last_reconcile_ns = None
        self.last_sync_ns = None
        self.campaign_status = 'not-synced'
        self.directory.mkdir(parents=True, exist_ok=True)
        self.lock = (self.directory/'loop.lock').open('a')
        self.db = None
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.db = sqlite3.connect(self.directory/'loop.sqlite')
            self.db.row_factory = sqlite3.Row
            self.db.execute('PRAGMA foreign_keys=ON')
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.executescript(SCHEMA)
            wanted = dict(schema='2', frontier=str(self.frontier_dir),
                          catalog=str(self.catalog_dir), seeds=str(self.seed_dir),
                          campaign=str(self.campaign_dir))
            prior = dict(self.db.execute('SELECT key,value FROM identity'))
            need(not prior or prior == wanted,
                 'Autonomous loop belongs to another frontier, catalog, or campaign')
            if not prior:
                with self.db:
                    self.db.executemany('INSERT INTO identity VALUES(?,?)',wanted.items())
        except BaseException:
            self.close()
            raise

    def _due(self, stage, key=''):
        row = self.db.execute(
            'SELECT next_retry_ns FROM stage_retry WHERE stage=? AND item_key=?',
            (stage,key)).fetchone()
        return row is None or row['next_retry_ns'] <= self.time_ns()

    def _attempt(self, stage, key, call):
        started = self.time_ns()
        try:
            result = call()
            status, error = 'ok', None
        except Exception as exc:
            result, status, error = None, 'error', _error(exc)
        finished = self.time_ns()
        with self.db:
            if status == 'ok':
                self.db.execute('DELETE FROM stage_retry WHERE stage=? AND item_key=?',
                                (stage,key))
            else:
                row = self.db.execute(
                    'SELECT failures FROM stage_retry WHERE stage=? AND item_key=?',
                    (stage,key)).fetchone()
                failures = (row['failures'] if row else 0)+1
                delay = min(self.retry_ns*(2**min(failures-1,10)),
                            60*1_000_000_000)
                self.db.execute('''INSERT INTO stage_retry VALUES(?,?,?,?)
                    ON CONFLICT(stage,item_key) DO UPDATE SET
                    failures=excluded.failures,next_retry_ns=excluded.next_retry_ns''',
                    (stage,key,failures,finished+delay))
            self.db.execute('''INSERT INTO stage_attempts
                (stage,item_key,started_ns,finished_ns,status,result,error)
                VALUES(?,?,?,?,?,?,?)''',
                (stage,key,started,finished,status,
                 packed(result) if result is not None else None,error))
        return dict(stage=stage,key=key,status=status,result=result,error=error)

    def _frontier(self):
        if self.frontier is None:
            self.frontier = self.frontier_factory(self.frontier_dir)
        return self.frontier

    def _campaign(self):
        if self.campaign is None:
            self.campaign = self.campaign_factory(
                self.campaign_dir,seed_dir=self.seed_dir,
                catalog_dir=self.catalog_dir)
        return self.campaign

    def _enqueue(self, input_id, attempt):
        need(type(input_id) is str and input_id and
             type(attempt) is int and attempt > 0,
             'Fatal frontier key is invalid')
        with self.db:
            self.db.execute('''INSERT OR IGNORE INTO fatal_intake
                (input_id,attempt,status,updated_ns) VALUES(?,?,'queued',?)''',
                (input_id,attempt,self.time_ns()))

    def _reconcile(self):
        """Recover fatalities committed before an interrupted handoff."""
        path = self.frontier_dir/'frontier.sqlite'
        try:
            mode = path.stat().st_mode
        except FileNotFoundError:
            return dict(found=0)
        need(stat.S_ISREG(mode), 'Frontier database path is not a regular file')
        db = sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)
        try:
            rows = list(db.execute('''SELECT f.id,o.attempt FROM frontier f
                JOIN outcomes o ON o.input_id=f.id AND o.attempt=f.attempts
                WHERE f.status='fatal' ORDER BY f.id'''))
        finally:
            db.close()
        for input_id, attempt in rows:
            self._enqueue(input_id,attempt)
        self.last_reconcile_ns = self.time_ns()
        return dict(found=len(rows))

    def _native(self):
        result = self._frontier().run(self.native_work_items)
        fatals = [(item['input_id'],item['attempt']) for item in result['results']
                  if item['state'] == 'fatal']
        for input_id, attempt in fatals:
            self._enqueue(input_id,attempt)
        states = {}
        for item in result['results']:
            states[item['state']] = states.get(item['state'],0)+1
        return dict(processed=result['processed'],states=states,
                    fatal_keys=[list(key) for key in fatals])

    def _catalog_one(self, row):
        result = self.ingest(self.frontier_dir,self.catalog_dir,
                             input_id=row['input_id'],attempt=row['attempt'])
        need(type(result) is list,
             'Fatal catalog ingestion returned an invalid result')
        if not result:
            frontier = sqlite3.connect(
                (self.frontier_dir/'frontier.sqlite').as_uri()+'?mode=ro',
                uri=True)
            try:
                current = frontier.execute(
                    'SELECT status,attempts FROM frontier WHERE id=?',
                    (row['input_id'],)).fetchone()
            finally:
                frontier.close()
            need(current == ('runner_signal',row['attempt']),
                 'Selected fatal outcome produced no catalog adjudication')
            summary = dict(reason='runner_signal_reclassification',
                           input_id=row['input_id'],attempt=row['attempt'])
            with self.db:
                self.db.execute('''UPDATE fatal_intake SET status='superseded',
                    result=?,next_retry_ns=0,updated_ns=?
                    WHERE input_id=? AND attempt=?''',
                    (packed(summary),self.time_ns(),row['input_id'],row['attempt']))
            return dict(status='superseded',items=[])
        summary = [_replay_summary(item) for item in result]
        now = self.time_ns()
        with self.db:
            for item, brief in zip(result,summary):
                if item.get('status') == 'rejected':
                    continue
                need(type(item.get('replay')) is dict,
                     'Catalog observation has no replay result')
                qualified = _qualified(item)
                self.db.execute('''INSERT OR IGNORE INTO replay_pending
                    (observation_id,input_id,attempt,status,attempts,
                     next_retry_ns,result,updated_ns)
                    VALUES(?,?,?,?,?,?,?,?)''',
                    (item['id'],row['input_id'],row['attempt'],
                     'done' if qualified else 'pending',1,
                     0 if qualified else now+self.retry_ns,
                     packed(brief),now))
                if qualified:
                    self.db.execute('''UPDATE replay_pending SET status='done',
                        next_retry_ns=0,result=?,updated_ns=?
                        WHERE observation_id=?''',
                        (packed(brief),now,item['id']))
            pending = self.db.execute('''SELECT count(*) FROM replay_pending
                WHERE input_id=? AND attempt=? AND status='pending' ''',
                (row['input_id'],row['attempt'])).fetchone()[0]
            status = 'replay-pending' if pending else 'done'
            self.db.execute('''UPDATE fatal_intake SET status=?,result=?,
                next_retry_ns=0,updated_ns=? WHERE input_id=? AND attempt=?''',
                (status,packed(summary),now,row['input_id'],row['attempt']))
        return dict(status=status,items=summary)

    def _catalog(self):
        rows = self.db.execute('''SELECT i.* FROM fatal_intake i
            LEFT JOIN stage_retry s ON s.stage='catalog' AND
                s.item_key=i.input_id||':'||i.attempt
            WHERE i.status IN ('queued','error') AND i.next_retry_ns<=? AND
                  (s.next_retry_ns IS NULL OR s.next_retry_ns<=?)
            ORDER BY CASE i.status WHEN 'queued' THEN 0 ELSE 1 END,
                     i.updated_ns,i.input_id,i.attempt LIMIT ?''',
            (self.time_ns(),self.time_ns(),self.catalog_work_items)).fetchall()
        attempts = []
        for row in rows:
            key = row['input_id']+':'+str(row['attempt'])
            outcome = self._attempt('catalog',key,
                                    lambda row=row: self._catalog_one(row))
            if outcome['status'] == 'error':
                retry = self.db.execute(
                    'SELECT next_retry_ns FROM stage_retry WHERE stage=? AND item_key=?',
                    ('catalog',key)).fetchone()['next_retry_ns']
                with self.db:
                    self.db.execute('''UPDATE fatal_intake SET status='error',
                        next_retry_ns=?,updated_ns=?
                        WHERE input_id=? AND attempt=?''',
                        (retry,self.time_ns(),row['input_id'],row['attempt']))
            attempts.append(outcome)
        return attempts

    def _replay_one(self, row):
        result = self.retry(row['observation_id'],self.frontier_dir,
                            self.catalog_dir)
        selected = [item for item in result
                    if item.get('id') == row['observation_id'] and
                       type(item.get('replay')) is dict]
        need(len(selected) == 1,
             'Replay retry did not return its selected observation')
        item = selected[0]
        brief = _replay_summary(item)
        qualified = _qualified(item)
        now = self.time_ns()
        attempts = row['attempts']+1
        delay = min(self.retry_ns*(2**min(attempts-1,16)),
                    3600*1_000_000_000)
        with self.db:
            self.db.execute('''UPDATE replay_pending SET status=?,attempts=?,
                next_retry_ns=?,result=?,updated_ns=? WHERE observation_id=?''',
                ('done' if qualified else 'pending',attempts,
                 0 if qualified else now+delay,packed(brief),now,
                 row['observation_id']))
            pending = self.db.execute('''SELECT count(*) FROM replay_pending
                WHERE input_id=? AND attempt=? AND status='pending' ''',
                (row['input_id'],row['attempt'])).fetchone()[0]
            if not pending:
                self.db.execute('''UPDATE fatal_intake SET status='done',
                    updated_ns=? WHERE input_id=? AND attempt=?''',
                    (now,row['input_id'],row['attempt']))
        return dict(status='done' if not pending else 'replay-pending',
                    replay=brief,attempts=attempts)

    def _replays(self):
        rows = self.db.execute('''SELECT p.* FROM replay_pending p
            LEFT JOIN stage_retry s ON s.stage='replay' AND
                s.item_key=p.observation_id
            WHERE p.status='pending' AND p.next_retry_ns<=? AND
                  (s.next_retry_ns IS NULL OR s.next_retry_ns<=?)
            ORDER BY p.updated_ns,p.observation_id LIMIT ?''',
            (self.time_ns(),self.time_ns(),self.catalog_work_items)).fetchall()
        return [self._attempt('replay',row['observation_id'],
                              lambda row=row: self._replay_one(row))
                for row in rows]

    def _proof(self):
        result = self._campaign().advance(self.proof_work_items,
                                          self.proof_round_seconds)
        return dict(status=result['status'],tasks=result['tasks'],
                    build_sha256=result.get('build_sha256'),
                    seed_id=result.get('seed_id'),
                    hypothesis=result.get('hypothesis'),
                    certificate_id=result.get('certificate_id'),
                    job_status=result.get('job',{}).get('status'))

    def cycle(self):
        """Run one fair slice of each available stage and commit its receipts."""
        steps = []
        now = self.time_ns()
        if (self.last_reconcile_ns is None or
                now-self.last_reconcile_ns >= self.refresh_ns):
            if self._due('reconcile'):
                steps.append(self._attempt('reconcile','',self._reconcile))
        if self._due('native'):
            outcome = self._attempt('native','',self._native)
            steps.append(outcome)
            if outcome['status'] == 'error' and self.frontier is not None:
                self.frontier.close()
                self.frontier = None
        steps.extend(self._catalog())
        steps.extend(self._replays())
        catalog_added = any(step['stage'] in ('catalog','replay') and
                            step['status'] == 'ok' and
                            step['result']['status'] == 'done'
                            for step in steps)
        now = self.time_ns()
        if (self.last_sync_ns is None or catalog_added or
                now-self.last_sync_ns >= self.refresh_ns):
            if self._due('seed-sync'):
                outcome = self._attempt('seed-sync','',lambda: self._campaign().sync())
                steps.append(outcome)
                if outcome['status'] == 'ok':
                    self.last_sync_ns = self.time_ns()
                    self.campaign_status = outcome['result']['status']
                else:
                    self.campaign_status = 'not-synced'
                    if self.campaign is not None:
                        self.campaign.close()
                        self.campaign = None
        if self.campaign_status == 'searching' and self._due('proof'):
            outcome = self._attempt('proof','',self._proof)
            steps.append(outcome)
            if outcome['status'] == 'ok':
                self.campaign_status = outcome['result']['status']
            else:
                self.campaign_status = 'not-synced'
                if self.campaign is not None:
                    self.campaign.close()
                    self.campaign = None
        return dict(time_ns=self.time_ns(),steps=steps,
                    fatal_intake=dict(self.db.execute(
                        'SELECT status,count(*) FROM fatal_intake GROUP BY status')),
                    replay_pending=dict(self.db.execute(
                        'SELECT status,count(*) FROM replay_pending GROUP BY status')),
                    campaign_status=self.campaign_status)

    def run(self, stop, *, idle_seconds=0.25, report_seconds=30.0):
        need(idle_seconds > 0 and report_seconds > 0,
             'Run intervals must be positive')
        last_report = 0.0
        while not stop.is_set():
            result = self.cycle()
            now = time.monotonic()
            notable = any(step['stage'] in ('catalog','replay') and
                          step['status'] == 'ok'
                          or step['status'] == 'error' for step in result['steps'])
            if notable or now-last_report >= report_seconds:
                print(packed(result),flush=True)
                last_report = now
            productive = any(step['stage'] == 'native' and
                             step['status'] == 'ok' and
                             step['result']['processed'] > 0
                             for step in result['steps'])
            if not productive and not stop.is_set():
                stop.wait(idle_seconds)

    def close(self):
        if self.campaign is not None:
            self.campaign.close()
            self.campaign = None
        if self.frontier is not None:
            self.frontier.close()
            self.frontier = None
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.lock is not None:
            self.lock.close()
            self.lock = None

    def __enter__(self):
        return self

    def __exit__(self,*_):
        self.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('cycle','run','status'))
    parser.add_argument('--directory',type=Path,default=DEFAULT)
    parser.add_argument('--frontier',type=Path,default=DEFAULT_FRONTIER)
    parser.add_argument('--catalog',type=Path,default=DEFAULT_CATALOG)
    parser.add_argument('--seeds',type=Path,default=DEFAULT_SEEDS)
    parser.add_argument('--campaign',type=Path,default=DEFAULT_CAMPAIGN)
    parser.add_argument('--native-work-items',type=int,default=14)
    parser.add_argument('--catalog-work-items',type=int,default=2)
    parser.add_argument('--proof-work-items',type=int,default=1000)
    parser.add_argument('--proof-round-seconds',type=float,default=10.0)
    parser.add_argument('--refresh-seconds',type=float,default=60.0)
    args = parser.parse_args()
    if args.command == 'status':
        print(packed(read_status(args.directory)),flush=True)
        return
    with AutonomousSearchLoop(
            args.directory,frontier_dir=args.frontier,catalog_dir=args.catalog,
            seed_dir=args.seeds,campaign_dir=args.campaign,
            native_work_items=args.native_work_items,
            catalog_work_items=args.catalog_work_items,
            proof_work_items=args.proof_work_items,
            proof_round_seconds=args.proof_round_seconds,
            refresh_seconds=args.refresh_seconds) as loop:
        if args.command == 'cycle':
            print(packed(loop.cycle()),flush=True)
            return
        stop = threading.Event()
        for name in (signal.SIGINT,signal.SIGTERM):
            signal.signal(name,lambda *_: stop.set())
        loop.run(stop)


if __name__ == '__main__':
    main()
