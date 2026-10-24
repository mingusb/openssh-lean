"""A fatal observation survives failed handoffs and coordinator restarts."""
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from autonomous_search_loop import AutonomousSearchLoop, SCHEMA, read_status


def observation(*, exact=True):
    return dict(id='observation-a',target='scp',signal='SIGSEGV',
                replay=dict(reproducer_verified=True,
                            exact_site_verified=exact,
                            script=dict(status='reproduced',
                                        pinned_target_attributed=True,
                                        exact_pc_sites=([dict(stable_site_key='site-a')]
                                                        if exact else []))))


class Clock:
    def __init__(self):
        self.value = 1_000_000_000

    def now(self):
        return self.value

    def advance(self, seconds):
        self.value += int(seconds*1_000_000_000)


class FakeFrontier:
    def __init__(self, directory, *, emit=True):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True,exist_ok=True)
        self.db = sqlite3.connect(self.directory/'frontier.sqlite')
        self.db.execute('CREATE TABLE IF NOT EXISTS frontier '
                        '(id TEXT PRIMARY KEY,status TEXT,attempts INTEGER)')
        self.db.execute('CREATE TABLE IF NOT EXISTS outcomes '
                        '(input_id TEXT,attempt INTEGER)')
        self.emit = emit
        self.runs = 0

    def run(self, work_items):
        assert work_items > 0
        self.runs += 1
        if self.emit:
            self.emit = False
            with self.db:
                self.db.execute("INSERT INTO frontier VALUES('fault-a','fatal',1)")
                self.db.execute("INSERT INTO outcomes VALUES('fault-a',1)")
            results = [dict(state='fatal',input_id='fault-a',attempt=1)]
        else:
            results = []
        return dict(processed=len(results),results=results)

    def close(self):
        self.db.close()


class FakeCampaign:
    def __init__(self, _directory, *, seed_dir, catalog_dir, waiting=False):
        self.waiting = waiting
        self.syncs = 0
        self.advances = 0

    def sync(self):
        self.syncs += 1
        return dict(status='waiting' if self.waiting else 'searching',
                    inserted=0,tasks={})

    def advance(self, work_items, round_seconds):
        assert work_items > 0 and round_seconds > 0
        self.advances += 1
        return dict(status='searching',tasks={'searching':1},
                    seed_id='seed-a',hypothesis='memory-access',
                    job=dict(status='searching'))

    def close(self):
        pass


class AutonomousSearchLoopTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='autonomous-loop-',
                                                dir='/var/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.clock = Clock()
        self.frontiers = []
        self.campaigns = []
        self.ingest_calls = []

    def frontier_factory(self,directory):
        frontier = FakeFrontier(directory,emit=not self.frontiers)
        self.frontiers.append(frontier)
        return frontier

    def campaign_factory(self,directory,*,seed_dir,catalog_dir):
        campaign = FakeCampaign(directory,seed_dir=seed_dir,catalog_dir=catalog_dir)
        self.campaigns.append(campaign)
        return campaign

    def open_loop(self,ingest,*,retry=None):
        return AutonomousSearchLoop(
            self.root/'loop',frontier_dir=self.root/'frontier',
            catalog_dir=self.root/'catalog',seed_dir=self.root/'seeds',
            campaign_dir=self.root/'campaign',
            frontier_factory=self.frontier_factory,
            campaign_factory=self.campaign_factory,ingest=ingest,
            retry=retry or (lambda *_a,**_k: [observation()]),
            refresh_seconds=60,retry_seconds=1,time_ns=self.clock.now)

    def test_failed_catalog_handoff_retries_after_restart_without_stalling_search(self):
        def ingest(_frontier,_catalog,*,input_id,attempt):
            self.ingest_calls.append((input_id,attempt))
            if len(self.ingest_calls) == 1:
                raise RuntimeError('temporary replay failure')
            return [observation()]

        with self.open_loop(ingest) as loop:
            first = loop.cycle()
            self.assertEqual([step['status'] for step in first['steps']
                              if step['stage'] == 'catalog'],['error'])
            self.assertEqual(first['fatal_intake'],{'error':1})
            self.assertEqual(self.campaigns[0].advances,1)
            second = loop.cycle()
            self.assertEqual([step for step in second['steps']
                              if step['stage'] == 'catalog'],[])
            self.assertEqual(self.frontiers[0].runs,2)
            self.assertEqual(len(self.ingest_calls),1)
        self.clock.advance(2)
        with self.open_loop(ingest) as restarted:
            result = restarted.cycle()
            self.assertEqual(result['fatal_intake'],{'done':1})
            self.assertEqual(self.ingest_calls,
                             [('fault-a',1),('fault-a',1)])
            self.assertEqual(self.campaigns[1].syncs,1)
            self.assertEqual(self.campaigns[1].advances,1)
        recorded = read_status(self.root/'loop')
        self.assertEqual(recorded['fatal_intake'],{'done':1})
        catalog = [row for row in recorded['recent']
                   if row['stage'] == 'catalog']
        self.assertEqual(catalog[0]['status'],'ok')

    def test_provisional_replay_survives_restart_until_exact_site_is_verified(self):
        retries = []

        def retry(observation_id,_frontier,_catalog):
            retries.append(observation_id)
            return [observation()]

        with self.open_loop(lambda *_a,**_k: [observation(exact=False)],
                            retry=retry) as loop:
            result = loop.cycle()
            self.assertEqual(result['fatal_intake'],{'replay-pending':1})
            self.assertEqual(result['replay_pending'],{'pending':1})
            self.assertEqual(retries,[])
        self.clock.advance(2)
        with self.open_loop(lambda *_a,**_k: [observation(exact=False)],
                            retry=retry) as restarted:
            result = restarted.cycle()
            self.assertEqual(result['fatal_intake'],{'done':1})
            self.assertEqual(result['replay_pending'],{'done':1})
            self.assertEqual(retries,['observation-a'])
        recorded = read_status(self.root/'loop')
        self.assertEqual(recorded['replay_pending'],{'done':1})

    def test_reconciliation_recovers_crash_between_probe_and_handoff(self):
        frontier = FakeFrontier(self.root/'frontier',emit=False)
        with frontier.db:
            frontier.db.execute("INSERT INTO frontier VALUES('fault-a','fatal',1)")
            frontier.db.execute("INSERT INTO outcomes VALUES('fault-a',1)")
        frontier.close()

        def ingest(_frontier,_catalog,*,input_id,attempt):
            self.ingest_calls.append((input_id,attempt))
            return [dict(id='observation-a',status='rejected')]

        with self.open_loop(ingest) as loop:
            result = loop.cycle()
            self.assertEqual(result['fatal_intake'],{'done':1})
            self.assertEqual(self.ingest_calls,[('fault-a',1)])
            self.assertEqual(self.campaigns[0].advances,1)

    def test_reconciliation_handles_literal_uri_characters(self):
        self.root = self.root/'literal#?%41'
        frontier = FakeFrontier(self.root/'frontier',emit=False)
        with frontier.db:
            frontier.db.execute("INSERT INTO frontier VALUES('fault-a','fatal',1)")
            frontier.db.execute("INSERT INTO outcomes VALUES('fault-a',1)")
        frontier.close()
        with self.open_loop(lambda *_a,**_k: []) as loop:
            self.assertEqual(loop._reconcile(),dict(found=1))
            self.assertEqual(dict(loop.db.execute(
                'SELECT status,count(*) FROM fatal_intake GROUP BY status')),
                {'queued':1})

    def test_reconciliation_reports_unreadable_or_invalid_database(self):
        with self.open_loop(lambda *_a,**_k: []) as loop:
            self.assertEqual(loop._reconcile(),dict(found=0))

        frontier = FakeFrontier(self.root/'frontier',emit=False)
        frontier.close()
        directory = self.root/'frontier'
        directory.chmod(0)
        try:
            try:
                (directory/'frontier.sqlite').stat()
            except PermissionError:
                pass
            else:
                self.skipTest('The test user can bypass directory permissions')
            with self.open_loop(lambda *_a,**_k: []) as loop:
                with self.assertRaises(PermissionError):
                    loop._reconcile()
        finally:
            directory.chmod(0o700)

        (directory/'frontier.sqlite').unlink()
        (directory/'frontier.sqlite').mkdir()
        with self.open_loop(lambda *_a,**_k: []) as loop:
            with self.assertRaisesRegex(RuntimeError,'regular file'):
                loop._reconcile()

    def test_runner_signal_reclassification_supersedes_fatal_handoff(self):
        frontier = FakeFrontier(self.root/'frontier',emit=False)
        with frontier.db:
            frontier.db.execute("INSERT INTO frontier VALUES('fault-a','runner_signal',1)")
            frontier.db.execute("INSERT INTO outcomes VALUES('fault-a',1)")
        frontier.close()
        with self.open_loop(lambda *_a,**_k: []) as loop:
            loop._enqueue('fault-a',1)
            result = loop.cycle()
            self.assertEqual(result['fatal_intake'],{'superseded':1})
            again = loop.cycle()
            self.assertFalse([step for step in again['steps']
                              if step['stage'] == 'catalog'])

    def test_runner_signal_reclassification_handles_literal_uri_characters(self):
        self.root = self.root/'literal#?%41'
        frontier = FakeFrontier(self.root/'frontier',emit=False)
        with frontier.db:
            frontier.db.execute("INSERT INTO frontier VALUES('fault-a','runner_signal',1)")
        frontier.close()
        with self.open_loop(lambda *_a,**_k: []) as loop:
            loop._enqueue('fault-a',1)
            result = loop._catalog_one(dict(input_id='fault-a',attempt=1))
            self.assertEqual(result,dict(status='superseded',items=[]))

    def test_waiting_campaign_does_not_consume_proof_slices(self):
        def waiting_campaign(directory,*,seed_dir,catalog_dir):
            value = FakeCampaign(directory,seed_dir=seed_dir,
                                 catalog_dir=catalog_dir,waiting=True)
            self.campaigns.append(value)
            return value

        with AutonomousSearchLoop(
                self.root/'loop',frontier_dir=self.root/'frontier',
                catalog_dir=self.root/'catalog',seed_dir=self.root/'seeds',
                campaign_dir=self.root/'campaign',
                frontier_factory=self.frontier_factory,
                campaign_factory=waiting_campaign,
                ingest=lambda *_a,**_k: [dict(id='rejection-a',status='rejected')],
                time_ns=self.clock.now) as loop:
            result = loop.cycle()
            self.assertEqual(result['campaign_status'],'waiting')
            self.assertEqual(self.campaigns[0].advances,0)
            self.assertEqual(result['fatal_intake'],{'done':1})


class AutonomousSearchStatusTests(unittest.TestCase):
    """Inspect synthetic receipts without constructing or running a search."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='autonomous-status-',
                                                dir='/var/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def database(self, directory):
        directory.mkdir(parents=True)
        db = sqlite3.connect(directory/'loop.sqlite')
        self.addCleanup(db.close)
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript(SCHEMA)
        return db

    def test_missing_status_does_not_create_a_directory_or_database(self):
        directory = self.root/'missing'
        self.assertEqual(read_status(directory),
                         dict(status='not-started',directory=str(directory)))
        self.assertFalse(directory.exists())
        directory.mkdir()
        self.assertEqual(read_status(directory)['status'],'not-started')
        self.assertEqual(list(directory.iterdir()),[])

    def test_inaccessible_database_is_not_reported_as_not_started(self):
        directory = self.root/'inaccessible'
        self.database(directory).close()
        path = directory/'loop.sqlite'
        before = path.read_bytes()
        directory.chmod(0)
        try:
            try:
                path.stat()
            except PermissionError:
                pass
            else:
                self.skipTest('The test user can bypass directory permissions')
            with self.assertRaises(PermissionError):
                read_status(directory)
        finally:
            directory.chmod(0o700)
        self.assertEqual(path.read_bytes(),before)

    def test_invalid_database_path_types_are_not_reported_as_not_started(self):
        directory = self.root/'directory-at-database-path'
        (directory/'loop.sqlite').mkdir(parents=True)
        with self.assertRaisesRegex(RuntimeError,'regular file'):
            read_status(directory)
        parent = self.root/'file-at-directory-path'
        parent.write_text('not a directory')
        with self.assertRaises(NotADirectoryError):
            read_status(parent)

    def test_status_handles_literal_uri_characters_in_directory_names(self):
        for name in ('space loop','hash#loop','query?loop','percent%41loop',
                     'unicode-\u03bb'):
            with self.subTest(name=name):
                directory = self.root/name
                self.database(directory)
                paths = set(self.root.iterdir())
                result = read_status(directory)
                self.assertEqual(result,dict(status='recorded',
                    directory=str(directory),fatal_intake={},replay_pending={},
                    retries=[],recent=[]))
                self.assertEqual(set(self.root.iterdir()),paths)

    def test_incomplete_schema_is_unavailable_without_changing_the_database(self):
        required = {'fatal_intake','replay_pending','stage_retry','stage_attempts'}
        for present in (set(),{'fatal_intake'}):
            with self.subTest(present=present):
                directory = self.root/('partial' if present else 'empty')
                directory.mkdir()
                path = directory/'loop.sqlite'
                db = sqlite3.connect(path)
                try:
                    if present:
                        db.execute('''CREATE TABLE fatal_intake
                            (input_id TEXT,attempt INTEGER,status TEXT)''')
                        db.commit()
                finally:
                    db.close()
                before = path.read_bytes()
                self.assertEqual(read_status(directory),dict(
                    status='unavailable',directory=str(directory),
                    reason='incomplete-schema',
                    missing_tables=sorted(required-present)))
                self.assertEqual(path.read_bytes(),before)

    def test_status_connection_rejects_writes(self):
        directory = self.root/'loop'
        self.database(directory)
        connect = sqlite3.connect

        def checked_connect(*args,**kwargs):
            db = connect(*args,**kwargs)
            try:
                with self.assertRaisesRegex(sqlite3.OperationalError,'readonly'):
                    db.execute("INSERT INTO identity VALUES('unexpected','write')")
                db.rollback()
            except BaseException:
                db.close()
                raise
            return db

        with mock.patch('autonomous_search_loop.sqlite3.connect',
                        side_effect=checked_connect):
            self.assertEqual(read_status(directory)['status'],'recorded')

    def test_status_reads_one_snapshot_during_a_concurrent_commit(self):
        directory = self.root/'loop'
        writer = self.database(directory)
        with writer:
            writer.execute('''INSERT INTO fatal_intake
                (input_id,attempt,status,updated_ns)
                VALUES('item-a',1,'replay-pending',1)''')
            writer.execute('''INSERT INTO replay_pending
                VALUES('record-a','item-a',1,'pending',1,2,'{}',1)''')
            writer.execute("INSERT INTO stage_retry VALUES('example','item-a',1,2)")
            writer.execute('''INSERT INTO stage_attempts
                (stage,item_key,started_ns,finished_ns,status,error)
                VALUES('example','item-a',1,1,'error','previous state')''')

        class Reader(sqlite3.Connection):
            def execute(self, sql, *args, **kwargs):
                if sql.startswith('SELECT status,count(*) FROM replay_pending'):
                    with writer:
                        writer.execute("UPDATE fatal_intake SET status='done'")
                        writer.execute("UPDATE replay_pending SET status='done'")
                        writer.execute('DELETE FROM stage_retry')
                        writer.execute('''INSERT INTO stage_attempts
                            (stage,item_key,started_ns,finished_ns,status,result)
                            VALUES('example','item-a',2,2,'ok','{}')''')
                return super().execute(sql,*args,**kwargs)

        connect = sqlite3.connect
        with mock.patch('autonomous_search_loop.sqlite3.connect',
                        side_effect=lambda *a,**k: connect(*a,**k,factory=Reader)):
            before = read_status(directory)
        self.assertEqual(before['fatal_intake'],{'replay-pending':1})
        self.assertEqual(before['replay_pending'],{'pending':1})
        self.assertEqual(len(before['retries']),1)
        self.assertEqual([row['status'] for row in before['recent']],['error'])
        after = read_status(directory)
        self.assertEqual(after['fatal_intake'],{'done':1})
        self.assertEqual(after['replay_pending'],{'done':1})
        self.assertEqual(after['retries'],[])
        self.assertEqual([row['status'] for row in after['recent']],['ok','error'])


if __name__ == '__main__':
    unittest.main()
