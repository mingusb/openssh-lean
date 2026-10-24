"""Durable scheduling for Lean-generated proof-search branches; no total search bound."""
import argparse
import fcntl
import json
from pathlib import Path
import sqlite3

from common import need, sha
from core_index import Index
from signal_search import Worker
from snapshot_module_cache import SnapshotModuleCache, cache_key
from signal_catalog import Catalog, DEFAULT as DEFAULT_CATALOG


def packed(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def resource_retry(response):
    message = response.get('error', '')
    return any(text in message for text in ('maximum number of heartbeats', 'maxHeartbeats',
                                            'maximum recursion depth', 'maxRecDepth'))


SCHEMA = '''
CREATE TABLE IF NOT EXISTS identity(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS nodes(id INTEGER PRIMARY KEY,parent INTEGER,tactic TEXT,
 quantum TEXT NOT NULL,response TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY,node INTEGER NOT NULL,
 kind TEXT NOT NULL,tactic TEXT NOT NULL,quantum TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'queued',response TEXT,UNIQUE(node,kind,tactic,quantum));
CREATE INDEX IF NOT EXISTS task_queue ON tasks(status,id);
CREATE INDEX IF NOT EXISTS task_node_queue ON tasks(node,status);
CREATE TABLE IF NOT EXISTS results(id INTEGER PRIMARY KEY,node INTEGER NOT NULL UNIQUE,
 evidence TEXT NOT NULL,catalog_id TEXT);
CREATE INDEX IF NOT EXISTS catalog_outbox ON results(id) WHERE catalog_id IS NULL;
CREATE TABLE IF NOT EXISTS counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL);
CREATE TRIGGER IF NOT EXISTS count_task_insert AFTER INSERT ON tasks BEGIN
 INSERT INTO counters VALUES('tasks.'||NEW.status,1) ON CONFLICT(name) DO UPDATE SET value=value+1;
END;
CREATE TRIGGER IF NOT EXISTS count_task_update AFTER UPDATE OF status ON tasks
 WHEN OLD.status != NEW.status BEGIN
 UPDATE counters SET value=value-1 WHERE name='tasks.'||OLD.status;
 INSERT INTO counters VALUES('tasks.'||NEW.status,1) ON CONFLICT(name) DO UPDATE SET value=value+1;
END;
CREATE TRIGGER IF NOT EXISTS count_node_insert AFTER INSERT ON nodes BEGIN
 INSERT INTO counters VALUES('nodes',1) ON CONFLICT(name) DO UPDATE SET value=value+1;
END;
CREATE TRIGGER IF NOT EXISTS count_result_insert AFTER INSERT ON results BEGIN
 INSERT INTO counters VALUES('results',1) ON CONFLICT(name) DO UPDATE SET value=value+1;
END;
'''


class Job:
    def __init__(self, directory, query=None, catalog=DEFAULT_CATALOG):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.lock = (self.directory/'job.lock').open('a')
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            self.lock.close()
            raise
        self.worker = self.index = self.db = self.catalog = None
        self.live = {}
        try:
            self.db = sqlite3.connect(self.directory/'job.sqlite')
            self.db.row_factory = sqlite3.Row
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            # Never reinterpret a previous queue schema as current work.
            tables = {r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            need('outcome' not in tables, 'Job schema changed; preserve the previous job evidence')
            self.db.executescript(SCHEMA)
            before = dict(self.db.execute('SELECT key,value FROM identity'))
            if query is None:
                need('query' in before, 'New jobs require a query')
                query = json.loads(before['query'])
            need(isinstance(query.get('goal'), str), 'A query requires a Lean proposition')
            self.query = query
            need(not before or before.get('query') == packed(query), 'Job query changed')
            self.catalog_policy = query.get('catalog_policy', 'publish')
            need(self.catalog_policy in ('publish', 'staged'),
                 'Catalog policy must be publish or staged')
            need(not query.get('snapshots') or self.catalog_policy == 'staged',
                 'Complete-model entry queries remain staged until exact-site promotion')
            self.stop_after_first = query.get('stop_after_first', False)
            need(type(self.stop_after_first) is bool, 'stop_after_first must be boolean')
            self.quantum = query.get('quantum', 200000)
            need(type(self.quantum) is int and self.quantum > 0, 'Scheduling quantum must be positive')
            self.index = Index()
            cache_records = []
            snapshots_requested = query.get('snapshots', [])
            aliases = [entry.get('alias') for entry in
                       [*query.get('fragments', []), *snapshots_requested]]
            need(all(isinstance(alias, str) for alias in aliases) and
                 len(aliases) == len(set(aliases)),
                 'Proof input aliases must be distinct strings')
            if snapshots_requested:
                cache = SnapshotModuleCache()
                for entry in snapshots_requested:
                    need(all(key in entry for key in ('target', 'alias')),
                         'Complete-model imports require exact target and alias')
                    cache_records.append(cache.prepare(self.index, entry['target'], entry['alias']))
            modules = [*query.get('modules', ()),
                       *(record['module'] for record in cache_records)]
            self.worker = Worker(self.directory/'worker', modules,
                                 lean_path=[cache.root] if cache_records else ())
            fragments = []
            for entry in query.get('fragments', []):
                need(all(key in entry for key in ('target','section','ordinal','alias')),
                     'Fragments require exact target, section, ordinal and alias')
                metadata = self.worker.load(self.index, entry['target'], entry['section'],
                                            entry['ordinal'], entry['alias'])
                fragments.append(dict(alias=entry['alias'], **metadata))
            snapshots = []
            for entry, record in zip(snapshots_requested, cache_records):
                metadata = self.worker.use_snapshot(self.index, entry['target'],
                                                    entry['alias'], record)
                snapshots.append(dict(alias=entry['alias'], **metadata))
            identity = dict(schema='2', query=packed(query), build=packed(self.worker.build),
                            imports=packed(self.worker.imports),
                            scheduler_sha256=sha(Path(__file__)),
                            archive_manifest=self.index.archive.manifest_sha256,
                            fragments=packed(fragments))
            if snapshots:
                identity['snapshots'] = packed(snapshots)
                identity['snapshot_cache'] = packed([
                    dict(module=record['module'], key=cache_key(record['identity']),
                         identity=record['identity']) for record in cache_records])
            need(not before or before == identity, 'Job query, archive, fragments or prover build changed')
            self.identity = identity
            self.catalog = Catalog(catalog)
            quantum = self.quantum
            while True:
                indexed = self.worker.request(dict(op='rules', names=query.get('rules', []), quantum=quantum))
                if not resource_retry(indexed):
                    break
                quantum *= 2
            need(indexed['status'] == 'indexed', 'Could not index semantic rules: '+str(indexed))
            self.rules = indexed['rule_set']
            with self.db:
                if not before:
                    self.db.executemany('INSERT INTO identity VALUES(?,?)', identity.items())
                # An interrupted attempt is replayed, never silently discarded.
                self.db.execute("UPDATE tasks SET status='queued' WHERE status='running'")
                if not self.db.execute('SELECT 1 FROM nodes').fetchone():
                    reply = self.worker.request(dict(op='start', goal=query['goal'], quantum=self.quantum))
                    need(reply['status'] == 'open', 'Could not elaborate query: '+str(reply))
                    self.db.execute('INSERT INTO nodes VALUES(0,NULL,NULL,?,?)', (str(self.quantum),packed(reply)))
                    self.live[0] = reply['node']
                    self.enqueue(0, 'expand', '', self.quantum)
            self.publish_pending()
            result = self.db.execute('SELECT evidence FROM results ORDER BY id LIMIT 1').fetchone()
            if result and self.stop_after_first:
                evidence = json.loads(result[0])
                need(evidence['identity'] == identity, 'Saved result identity changed')
                checked = self.worker.request(dict(op='verify', goal=query['goal'],
                    proof=evidence['result']['proof'], declarations=evidence['result']['declarations'], quantum=0))
                need(checked['status'] == 'proved', 'Saved proof did not recheck: '+str(checked))
        except BaseException:
            self.close()
            raise

    def restore(self, node):
        path = []
        current = node
        while current not in self.live:
            row = self.db.execute('SELECT * FROM nodes WHERE id=?', (current,)).fetchone()
            need(row is not None, 'Missing proof node')
            path.append(row)
            if row['parent'] is None:
                break
            current = row['parent']
        for row in reversed(path):
            quantum = int(row['quantum'])
            request = dict(op='start', goal=self.query['goal'], quantum=quantum) if row['parent'] is None else dict(
                op='step', node=self.live[row['parent']], tactic=row['tactic'], quantum=quantum)
            reply = self.worker.request(request)
            recorded = json.loads(row['response'])
            need(reply['status'] == recorded['status'] and reply.get('goals') == recorded.get('goals'),
                 'Saved proof branch did not replay: '+str(reply))
            self.live[row['id']] = reply['node']
        return self.live[node]

    def enqueue(self, node, kind, tactic, quantum):
        self.db.execute('INSERT OR IGNORE INTO tasks(node,kind,tactic,quantum) VALUES(?,?,?,?)',
                        (node,kind,tactic,str(quantum)))

    def publish_pending(self):
        if self.catalog_policy == 'staged':
            return
        # Durable outbox: a crash between the two commits repeats an idempotent
        # insert. Finding a proof never waits for interpretation or an LLM.
        for row in self.db.execute('SELECT id,evidence FROM results WHERE catalog_id IS NULL ORDER BY id'):
            identity = self.catalog.insert(json.loads(row['evidence']))
            with self.db:
                self.db.execute('UPDATE results SET catalog_id=? WHERE id=?', (identity,row['id']))

    def evidence(self, reply):
        maps, mappers = [], {}
        for fragment in json.loads(self.identity['fragments']):
            if fragment['alias'] not in reply['references'] or not fragment['location']:
                continue
            target = fragment['target']
            if target not in mappers:
                mappers[target] = self.index.archive.source_map(target)
            mapped = mappers[target].resolve(dict(
                artifact_sha256=fragment['artifact_sha256'], target=target,
                location=json.loads(fragment['location'])))
            maps.append(dict(alias=fragment['alias'], fragment_sha256=fragment['sha256'], source=mapped))
        return dict(identity=self.identity, result=reply, source_mappings=maps,
                    scope='kernel-checked user proposition with referenced source locations')

    def status(self):
        stats = dict(self.db.execute('SELECT name,value FROM counters'))
        counts = {key[6:]:value for key,value in stats.items() if key.startswith('tasks.')}
        found = stats.get('results', 0)
        state = 'proved' if self.stop_after_first and found else 'searching' if counts.get('queued') else 'quiescent'
        return dict(status=state, nodes=stats.get('nodes', 0), attempts=counts,
                    discoveries=found, frontier=counts.get('queued', 0),
                    rule_candidates=stats.get('matching_rules', 0),
                    rules_without_index=stats.get('rule_count', 0))

    def advance(self):
        """Commit one fair-queue work item. Call repeatedly or resume in another process."""
        state = self.status()
        if state['status'] != 'searching':
            return state
        task = self.db.execute("SELECT * FROM tasks WHERE status='queued' ORDER BY id LIMIT 1").fetchone()
        if task is None:
            return self.status()
        with self.db:
            self.db.execute("UPDATE tasks SET status='running' WHERE id=?", (task['id'],))
        request = dict(op='choices', rule_set=self.rules) if task['kind'] == 'expand' else dict(
            op='step', tactic=task['tactic'])
        reply = self.worker.request(dict(request, node=self.restore(task['node']), quantum=int(task['quantum'])))
        with self.db:
            self.db.execute('UPDATE tasks SET status=?,response=? WHERE id=?',
                            (reply['status'],packed(reply),task['id']))
            if reply['status'] == 'error':
                if resource_retry(reply):
                    self.enqueue(task['node'], task['kind'], task['tactic'], int(task['quantum'])*2)
            elif task['kind'] == 'expand':
                need(reply['status'] == 'choices', 'Could not expand proof node: '+str(reply))
                for key in ('rule_count', 'matching_rules'):
                    self.db.execute('INSERT INTO counters VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value',
                                    (key, reply[key]))
                for tactic in reply['tactics'] + self.query.get('tactics', []):
                    self.enqueue(task['node'], 'step', tactic, self.quantum)
            else:
                need(reply['status'] in ('open', 'proved'), 'Unexpected worker reply')
                cursor = self.db.execute('INSERT INTO nodes(parent,tactic,quantum,response) VALUES(?,?,?,?)',
                                        (task['node'],task['tactic'],task['quantum'],packed(reply)))
                node = cursor.lastrowid
                self.live[node] = reply['node']
                if reply['status'] == 'proved':
                    self.db.execute('INSERT INTO results(node,evidence) VALUES(?,?)', (node,packed(self.evidence(reply))))
                    self.drop(node)
                else:
                    self.enqueue(node, 'expand', '', self.quantum)
        self.publish_pending()
        if not self.db.execute("SELECT 1 FROM tasks WHERE node=? AND status='queued' LIMIT 1",
                               (task['node'],)).fetchone():
            self.drop(task['node'])
        return self.status()

    def drop(self, node):
        live = self.live.pop(node, None)
        if live is not None:
            self.worker.request(dict(op='drop', node=live))

    def close(self):
        if self.worker:
            self.worker.close()
        if self.index:
            self.index.close()
        if self.db:
            self.db.close()
        if self.catalog:
            self.catalog.close()
        self.lock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('job', type=Path)
    parser.add_argument('--query', type=Path, help='JSON query; omit when resuming')
    parser.add_argument('--catalog', type=Path, default=DEFAULT_CATALOG)
    parser.add_argument('--work-items', type=int, help='Yield after this many attempts; unfinished work remains queued')
    args = parser.parse_args()
    need(args.work_items is None or args.work_items > 0, 'Work-item quantum must be positive')
    query = json.loads(args.query.read_bytes()) if args.query else None
    with Job(args.job, query, catalog=args.catalog) as job:
        count = 0
        while True:
            state = job.advance()
            count += 1
            if state['status'] != 'searching' or (args.work_items and count >= args.work_items):
                print(packed(state), flush=True)
                break
            if count % 100 == 0:
                print(packed(state), flush=True)


if __name__ == '__main__':
    main()
