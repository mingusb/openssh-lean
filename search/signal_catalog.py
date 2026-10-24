"""Automatic discovery storage, independent certificate replay and later enrichment."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import zlib

from common import WORKSPACE, need, sha


DEFAULT = WORKSPACE/'local/search/catalog'
PARSER_BUNDLE_MODULES = (
    'native_signal_replay.py', 'common.py', 'elf_instruction_site.py',
    'model_archive.py', 'signal_catalog.py', 'saved_program_provenance.py',
    'source_locations.py', 'verified_file_cache.py',
)


def packed(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def current_native_site_record(record):
    """Recognize records that distinguish same-run PC from mapped-file bytes."""
    return (record.get('runtime_instruction_bytes_verified') is False and
            'causal_fault_pc_observed' in record and
            record.get('instruction', {}).get('instruction_byte_source') ==
            'mapped_elf_file')


def pinned_recursive_frame_count(frames, symbol, binary_path):
    """Count only same-executable frames, not same-named foreign DSO frames."""
    return sum(frame.get('module') == binary_path and
               frame.get('symbol', '').partition('+')[0] == symbol
               for frame in frames)


def pinned_signal_delivery(observation, site, binary_path):
    """Find this exact signal event with a frame in the pinned executable."""
    return any(
        row.get('pid') == site.get('pid') and
        row.get('signal') == 'SIGSEGV' and
        row.get('instruction_pointer') == site.get('pc') and
        row.get('si_code') == site.get('si_code') and
        any(frame.get('module') == binary_path
            for frame in row.get('stack_frames', []))
        for row in observation['signal_deliveries'])


def current_native_core_link(record):
    """A recursive link must identify the executable whose frames were counted."""
    relation = record.get('relation', {})
    if relation.get('kind') != 'causal_recursive_call':
        return True
    module = relation.get('recursive_frame_module')
    digest = relation.get('recursive_frame_module_sha256')
    return (type(module) is str and bool(module) and
            type(digest) is str and len(digest) == 64 and
            all(character in '0123456789abcdef' for character in digest))


def repeated_input_identity(profile, depth):
    """Hash a repeated input without allocating the full witness."""
    from native_depth_search import profile_bytes

    need(type(depth) is int and depth >= 0, 'Invalid reproducer witness depth')
    prefix, record, suffix = profile_bytes(profile)
    digest = hashlib.sha256()
    digest.update(prefix)
    per_chunk = max(1, 65536//len(record))
    chunk = record*per_chunk
    remaining = depth
    while remaining >= per_chunk:
        digest.update(chunk)
        remaining -= per_chunk
    if remaining:
        digest.update(record*remaining)
    digest.update(suffix)
    return dict(bytes=len(prefix)+len(record)*depth+len(suffix),
                sha256=digest.hexdigest())


def encoded_input_identity(encoded):
    """Hash the saved base64 recipe in bounded additional memory."""
    need(type(encoded) is str, 'Native receipt lacks encoded stdin')
    digest = hashlib.sha256()
    size = 0
    for offset in range(0, len(encoded), 65536):
        part = base64.b64decode(encoded[offset:offset+65536], validate=True)
        digest.update(part)
        size += len(part)
    return dict(bytes=size, sha256=digest.hexdigest())


SCHEMA = '''
CREATE TABLE IF NOT EXISTS discoveries(
 id TEXT PRIMARY KEY, signal TEXT, archive TEXT NOT NULL, created_ns INTEGER NOT NULL,
 evidence BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS discovery_signal ON discoveries(signal,created_ns,id);
CREATE TABLE IF NOT EXISTS enrichments(
 id INTEGER PRIMARY KEY, discovery TEXT NOT NULL REFERENCES discoveries(id),
 author TEXT NOT NULL, created_ns INTEGER NOT NULL, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS enrichment_discovery ON enrichments(discovery,id);
CREATE TABLE IF NOT EXISTS native_observations(
 id TEXT PRIMARY KEY, discovery TEXT NOT NULL REFERENCES discoveries(id),
 created_ns INTEGER NOT NULL, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS native_observation_discovery ON native_observations(discovery,created_ns,id);
CREATE TABLE IF NOT EXISTS native_fatal_observations(
 id TEXT PRIMARY KEY, target TEXT NOT NULL, signal TEXT NOT NULL,
 created_ns INTEGER NOT NULL, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS native_fatal_observation_signal
 ON native_fatal_observations(signal,target,created_ns,id);
CREATE TABLE IF NOT EXISTS native_fatal_replays(
 id TEXT PRIMARY KEY, observation_id TEXT NOT NULL REFERENCES native_fatal_observations(id),
 created_ns INTEGER NOT NULL, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS native_fatal_replay_observation
 ON native_fatal_replays(observation_id,created_ns,id);
CREATE TABLE IF NOT EXISTS native_fatal_rejections(
 id TEXT PRIMARY KEY, input_id TEXT NOT NULL, created_ns INTEGER NOT NULL,
 payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS native_fatal_rejection_input
 ON native_fatal_rejections(input_id,created_ns,id);
CREATE TABLE IF NOT EXISTS native_instruction_sites(
 id TEXT PRIMARY KEY, stable_site_key TEXT NOT NULL, signal TEXT NOT NULL,
 created_ns INTEGER NOT NULL, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS native_instruction_site_group
 ON native_instruction_sites(signal,stable_site_key,created_ns,id);
CREATE INDEX IF NOT EXISTS native_instruction_site_key
 ON native_instruction_sites(stable_site_key,signal,created_ns,id);
CREATE TABLE IF NOT EXISTS native_instruction_site_pending(
 id TEXT PRIMARY KEY, signal TEXT NOT NULL, created_ns INTEGER NOT NULL,
 payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS native_instruction_site_pending_signal
 ON native_instruction_site_pending(signal,created_ns,id);
CREATE TABLE IF NOT EXISTS native_core_links(
 id TEXT PRIMARY KEY, observation_id TEXT NOT NULL, stable_site_key TEXT NOT NULL,
 core_site_sha256 TEXT NOT NULL, relation TEXT NOT NULL,
 created_ns INTEGER NOT NULL, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS native_core_link_observation
 ON native_core_links(observation_id,created_ns,id);
CREATE INDEX IF NOT EXISTS native_core_link_core_site
 ON native_core_links(core_site_sha256,created_ns,id);
CREATE TABLE IF NOT EXISTS native_reproducers(
 id TEXT PRIMARY KEY, observation_id TEXT NOT NULL, target TEXT NOT NULL,
 script_sha256 TEXT NOT NULL, core_link_id TEXT,
 created_ns INTEGER NOT NULL, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS native_reproducer_observation
 ON native_reproducers(observation_id,created_ns,id);
CREATE INDEX IF NOT EXISTS native_reproducer_target
 ON native_reproducers(target,created_ns,id);
CREATE TABLE IF NOT EXISTS native_reproducer_toolchains(
 reproducer_id TEXT PRIMARY KEY REFERENCES native_reproducers(id),
 binding_id TEXT UNIQUE NOT NULL, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS native_reproducer_formal_links(
 id TEXT PRIMARY KEY, reproducer_id TEXT NOT NULL
 REFERENCES native_reproducers(id), obligation_id TEXT NOT NULL,
 created_ns INTEGER NOT NULL, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS native_reproducer_formal_link_reproducer
 ON native_reproducer_formal_links(reproducer_id,created_ns,id);
CREATE TABLE IF NOT EXISTS native_stack_certificates(
 id TEXT PRIMARY KEY, reproducer_id TEXT NOT NULL
 REFERENCES native_reproducers(id), seed_id TEXT NOT NULL,
 created_ns INTEGER NOT NULL, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS native_stack_certificate_seed
 ON native_stack_certificates(seed_id,created_ns,id);
CREATE TRIGGER IF NOT EXISTS immutable_discovery_update BEFORE UPDATE ON discoveries
 BEGIN SELECT RAISE(ABORT,'Discovery evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_discovery_delete BEFORE DELETE ON discoveries
 BEGIN SELECT RAISE(ABORT,'Discovery evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_enrichment_update BEFORE UPDATE ON enrichments
 BEGIN SELECT RAISE(ABORT,'Enrichment history is append-only'); END;
CREATE TRIGGER IF NOT EXISTS immutable_enrichment_delete BEFORE DELETE ON enrichments
 BEGIN SELECT RAISE(ABORT,'Enrichment history is append-only'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_observation_update BEFORE UPDATE ON native_observations
 BEGIN SELECT RAISE(ABORT,'Native observations are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_observation_delete BEFORE DELETE ON native_observations
 BEGIN SELECT RAISE(ABORT,'Native observations are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_fatal_observation_update
 BEFORE UPDATE ON native_fatal_observations
 BEGIN SELECT RAISE(ABORT,'Native fatal observations are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_fatal_observation_delete
 BEFORE DELETE ON native_fatal_observations
 BEGIN SELECT RAISE(ABORT,'Native fatal observations are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_fatal_replay_update
 BEFORE UPDATE ON native_fatal_replays
 BEGIN SELECT RAISE(ABORT,'Native fatal replays are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_fatal_replay_delete
 BEFORE DELETE ON native_fatal_replays
 BEGIN SELECT RAISE(ABORT,'Native fatal replays are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_fatal_rejection_update
 BEFORE UPDATE ON native_fatal_rejections
 BEGIN SELECT RAISE(ABORT,'Native fatal rejections are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_fatal_rejection_delete
 BEFORE DELETE ON native_fatal_rejections
 BEGIN SELECT RAISE(ABORT,'Native fatal rejections are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_instruction_site_update BEFORE UPDATE ON native_instruction_sites
 BEGIN SELECT RAISE(ABORT,'Native instruction sites are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_instruction_site_delete BEFORE DELETE ON native_instruction_sites
 BEGIN SELECT RAISE(ABORT,'Native instruction sites are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_instruction_site_pending_update
 BEFORE UPDATE ON native_instruction_site_pending
 BEGIN SELECT RAISE(ABORT,'Pending native instruction sites are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_instruction_site_pending_delete
 BEFORE DELETE ON native_instruction_site_pending
 BEGIN SELECT RAISE(ABORT,'Pending native instruction sites are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_core_link_update
 BEFORE UPDATE ON native_core_links
 BEGIN SELECT RAISE(ABORT,'Native-Core links are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_core_link_delete
 BEFORE DELETE ON native_core_links
 BEGIN SELECT RAISE(ABORT,'Native-Core links are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_reproducer_update
 BEFORE UPDATE ON native_reproducers
 BEGIN SELECT RAISE(ABORT,'Native reproducers are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_reproducer_delete
 BEFORE DELETE ON native_reproducers
 BEGIN SELECT RAISE(ABORT,'Native reproducers are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_reproducer_toolchain_update
 BEFORE UPDATE ON native_reproducer_toolchains
 BEGIN SELECT RAISE(ABORT,'Native reproducer toolchains are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_reproducer_toolchain_delete
 BEFORE DELETE ON native_reproducer_toolchains
 BEGIN SELECT RAISE(ABORT,'Native reproducer toolchains are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_reproducer_formal_link_update
 BEFORE UPDATE ON native_reproducer_formal_links
 BEGIN SELECT RAISE(ABORT,'Native reproducer formal links are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_reproducer_formal_link_delete
 BEFORE DELETE ON native_reproducer_formal_links
 BEGIN SELECT RAISE(ABORT,'Native reproducer formal links are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_stack_certificate_update
 BEFORE UPDATE ON native_stack_certificates
 BEGIN SELECT RAISE(ABORT,'Native stack certificates are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_native_stack_certificate_delete
 BEFORE DELETE ON native_stack_certificates
 BEGIN SELECT RAISE(ABORT,'Native stack certificates are immutable'); END;
'''


def canonical_evidence(evidence):
    """Exclude worker handles and timing; retain the exact proposition and proof DAG.

    This deduplicates identical certificates, not arbitrary semantically equivalent
    eliciting methods. Semantic witness keys can be supplied by the search layer.
    """
    result = evidence['result']
    need(result['status'] == 'proved', 'Only checked discoveries can be cataloged')
    need('sorryAx' not in result['axioms'], 'Admitted propositions cannot be cataloged')
    query = json.loads(evidence['identity']['query'])
    need(isinstance(query['goal'], str), 'Discovery has no replayable query')
    fields = ('proposition', 'proof', 'declarations', 'axioms', 'references')
    certificate = {key: result[key] for key in fields}
    for key in ('axioms', 'references'):
        certificate[key] = sorted(set(certificate[key]))
    return dict(schema=1, kind='lean-proposition', identity=evidence['identity'],
                certificate=certificate, source_mappings=evidence['source_mappings'],
                reproduction=dict(kind='lean-certificate', goal=query['goal'],
                                  preconditions='Those quantified or assumed by the saved proposition'),
                scope=evidence['scope'])


class Catalog:
    def __init__(self, directory=DEFAULT):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.directory/'catalog.sqlite')
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript(SCHEMA)

    def insert(self, evidence):
        """Idempotent ingestion. No author, interpretation or importance is required."""
        record = canonical_evidence(evidence)
        raw = packed(record).encode()
        identity = hashlib.sha256(raw).hexdigest()
        query = json.loads(record['identity']['query'])
        with self.db:
            self.db.execute('INSERT OR IGNORE INTO discoveries VALUES(?,?,?,?,?)',
                            (identity, query.get('signal'), record['identity']['archive_manifest'],
                             time.time_ns(), zlib.compress(raw)))
        return identity

    def read(self, identity):
        row = self.db.execute('SELECT * FROM discoveries WHERE id=?', (identity,)).fetchone()
        need(row is not None, 'Unknown catalog entry: '+identity)
        raw = zlib.decompress(row['evidence'])
        need(hashlib.sha256(raw).hexdigest() == identity, 'Catalog evidence hash mismatch')
        enrichments = [dict(id=r['id'], author=r['author'], created_ns=r['created_ns'],
                            payload=json.loads(r['payload'])) for r in self.db.execute(
            'SELECT * FROM enrichments WHERE discovery=? ORDER BY id', (identity,))]
        importance = dict(status='unassessed')
        for entry in enrichments:
            if 'importance' in entry['payload']:
                importance = dict(status='assessed', author=entry['author'],
                                  assessment=entry['payload']['importance'], enrichment_id=entry['id'])
        native_observations = [json.loads(r['payload']) for r in self.db.execute(
            'SELECT payload FROM native_observations WHERE discovery=? ORDER BY created_ns,id',
            (identity,))]
        return dict(id=identity, signal=row['signal'], created_ns=row['created_ns'],
                    evidence=json.loads(raw), importance=importance, enrichments=enrichments,
                    native_observations=native_observations)

    def add_native_observation(self, identity, observation):
        """Append one immutable native run linked to an existing certificate."""
        need(isinstance(observation, dict) and observation.get('catalog_id') == identity and
             isinstance(observation.get('id'), str), 'Invalid linked native observation')
        receipt = Path(observation['receipt'])
        need(receipt.is_file() and not receipt.is_symlink() and
             hashlib.sha256(receipt.read_bytes()).hexdigest() == observation['receipt_sha256'],
             'Linked native observation receipt is missing or changed')
        with self.db:
            need(self.db.execute('SELECT 1 FROM discoveries WHERE id=?', (identity,)).fetchone(),
                 'Unknown catalog entry: '+identity)
            self.db.execute('INSERT INTO native_observations VALUES(?,?,?,?)',
                            (observation['id'], identity, time.time_ns(), packed(observation)))
        return observation['id']

    def store_native_fatal_asset(self, role, contents):
        """Store one immutable byte asset for a fatal native observation."""
        need(type(role) is str and re.fullmatch(r'[a-z0-9][a-z0-9._-]*', role)
             and role not in ('.', '..') and type(contents) is bytes,
             'Invalid native fatal asset')
        suffix = '.sh' if role == 'script' else '.json' if role == 'outcome' else '.bin'
        digest = hashlib.sha256(contents).hexdigest()
        directory = self.directory/'native-fatal-assets'
        directory.mkdir(parents=True, exist_ok=True)
        need(not directory.is_symlink(), 'Native fatal asset directory is a symlink')
        path = directory/(digest+'-'+role+suffix)
        try:
            with path.open('xb') as stream:
                stream.write(contents)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            pass
        need(path.is_file() and not path.is_symlink() and
             path.read_bytes() == contents, 'Native fatal asset changed')
        return dict(path=str(path), sha256=digest, bytes=len(contents), role=role)

    def add_native_fatal_observation(self, record):
        """Insert one first-run fatal observation and its generated Bash program."""
        from native_fatal_reproducer import render_native_fatal_script

        need(type(record) is dict and record.get('schema') == 1 and
             record.get('kind') == 'native-fatal-signal-observation' and
             type(record.get('target')) is str and
             type(record.get('signal')) is str and
             type(record.get('assets')) is dict and
             type(record.get('script_spec')) is dict,
             'Invalid native fatal observation')
        assets = record['assets']
        spec = record['script_spec']
        need('script' in assets and 'stdin' in assets and 'outcome' in assets and
             spec.get('schema') == 1 and
             spec.get('target') == record['target'] and
             spec.get('signal') == record['signal'] and
             spec.get('binary') == record.get('binary') and
             spec.get('recipe') == record.get('first_run', {}).get('recipe') and
             spec.get('stdin') == assets['stdin'] and
             assets['outcome'].get('sha256') ==
             record.get('frontier', {}).get('outcome_sha256'),
             'Native fatal observation has inconsistent input identity')
        for role, entry in assets.items():
            need(type(role) is str and type(entry) is dict and
                 entry.get('role') == role and
                 type(entry.get('sha256')) is str and
                 re.fullmatch(r'[0-9a-f]{64}', entry['sha256']) and
                 type(entry.get('bytes')) is int and entry['bytes'] >= 0,
                 'Native fatal asset metadata differs')
            path = Path(entry['path'])
            need(path.parent == self.directory/'native-fatal-assets' and
                 path.is_file() and not path.is_symlink() and
                 path.stat().st_size == entry['bytes'] and
                 sha(path) == entry['sha256'],
                 'Native fatal asset is missing or changed')
        script = Path(assets['script']['path']).read_bytes()
        need(script == render_native_fatal_script(record['script_spec']),
             'Native fatal Bash program differs from the recorded invocation')
        payload = packed(record)
        identity = hashlib.sha256(payload.encode()).hexdigest()
        with self.db:
            existing = self.db.execute(
                'SELECT payload FROM native_fatal_observations WHERE id=?',
                (identity,)).fetchone()
            if existing is None:
                self.db.execute(
                    'INSERT INTO native_fatal_observations VALUES(?,?,?,?,?)',
                    (identity, record['target'], record['signal'],
                     time.time_ns(), payload))
            else:
                need(existing['payload'] == payload,
                     'Native fatal observation identity changed')
        self.export_native_fatal_observation(identity)
        return identity

    def export_native_fatal_observation(self, identity):
        row = self.db.execute(
            'SELECT payload FROM native_fatal_observations WHERE id=?',
            (identity,)).fetchone()
        need(row is not None and hashlib.sha256(row['payload'].encode()).hexdigest() == identity,
             'Unknown or changed native fatal observation')
        directory = self.directory/'native-fatal-records'
        directory.mkdir(parents=True, exist_ok=True)
        need(not directory.is_symlink(), 'Native fatal record directory is a symlink')
        path = directory/(identity+'.json')
        expected = (row['payload']+'\n').encode()
        try:
            with path.open('xb') as stream:
                stream.write(expected)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            pass
        need(path.is_file() and not path.is_symlink() and
             path.read_bytes() == expected, 'Exported native fatal record changed')
        return path

    def read_native_fatal_observation(self, identity):
        row = self.db.execute(
            'SELECT payload,created_ns FROM native_fatal_observations WHERE id=?',
            (identity,)).fetchone()
        need(row is not None and hashlib.sha256(row['payload'].encode()).hexdigest() == identity,
             'Unknown or changed native fatal observation')
        record = json.loads(row['payload'])
        exported = self.export_native_fatal_observation(identity)
        need(exported.read_bytes() == (row['payload']+'\n').encode(),
             'Native fatal export differs from catalog')
        for entry in record['assets'].values():
            path = Path(entry['path'])
            need(path.is_file() and not path.is_symlink() and
                 path.stat().st_size == entry['bytes'] and sha(path) == entry['sha256'],
                 'Native fatal asset is missing or changed')
        return dict(id=identity, created_ns=row['created_ns'], **record)

    def list_native_fatal_observations(self, signal=None, target=None):
        conditions, values = [], []
        if signal is not None:
            conditions.append('signal=?')
            values.append(signal)
        if target is not None:
            conditions.append('target=?')
            values.append(target)
        sql = 'SELECT id FROM native_fatal_observations'
        if conditions:
            sql += ' WHERE ' + ' AND '.join(conditions)
        for row in self.db.execute(sql+' ORDER BY created_ns,id', values):
            yield self.read_native_fatal_observation(row['id'])

    def add_native_fatal_replay(self, observation_id, result):
        """Append one replay attempt without changing the first observation."""
        need(type(result) is dict and result.get('schema') == 1 and
             result.get('kind') == 'native-fatal-replay-attempt' and
             result.get('observation_id') == observation_id,
             'Invalid native fatal replay')
        need(result.get('reproducer_verified') is
             (result.get('script', {}).get('status') == 'reproduced') and
             (not result.get('exact_site_verified') or
              (result.get('reproducer_verified') and
               bool(result.get('script', {}).get('exact_pc_sites')))) and
             (result.get('source_link', {}).get('status') !=
              'native-dwarf-line-mapped' or result.get('exact_site_verified')),
             'Native fatal replay overstates verified evidence')
        payload = packed(result)
        identity = hashlib.sha256(payload.encode()).hexdigest()
        with self.db:
            need(self.db.execute('SELECT 1 FROM native_fatal_observations WHERE id=?',
                                 (observation_id,)).fetchone() is not None,
                 'Unknown first-run fatal observation')
            existing = self.db.execute(
                'SELECT payload FROM native_fatal_replays WHERE id=?',
                (identity,)).fetchone()
            if existing is None:
                self.db.execute('INSERT INTO native_fatal_replays VALUES(?,?,?,?)',
                                (identity,observation_id,time.time_ns(),payload))
            else:
                need(existing['payload'] == payload, 'Native fatal replay identity changed')
        return identity

    def list_native_fatal_replays(self, observation_id):
        for row in self.db.execute(
                'SELECT id,created_ns,payload FROM native_fatal_replays '
                'WHERE observation_id=? ORDER BY created_ns,id', (observation_id,)):
            need(hashlib.sha256(row['payload'].encode()).hexdigest() == row['id'],
                 'Native fatal replay payload changed')
            yield dict(id=row['id'], created_ns=row['created_ns'],
                       **json.loads(row['payload']))

    def add_native_fatal_rejection(self, record):
        """Record why a committed frontier outcome was not promoted."""
        need(type(record) is dict and record.get('schema') == 1 and
             record.get('kind') == 'native-fatal-ingest-rejection' and
             type(record.get('input_id')) is str and
             type(record.get('unqualified_signals')) is list,
             'Invalid native fatal ingestion rejection')
        payload = packed(record)
        identity = hashlib.sha256(payload.encode()).hexdigest()
        with self.db:
            existing = self.db.execute(
                'SELECT payload FROM native_fatal_rejections WHERE id=?',
                (identity,)).fetchone()
            if existing is None:
                self.db.execute(
                    'INSERT INTO native_fatal_rejections VALUES(?,?,?,?)',
                    (identity, record['input_id'], time.time_ns(), payload))
            else:
                need(existing['payload'] == payload,
                     'Native fatal rejection identity changed')
        return identity

    def list_native_fatal_rejections(self, input_id=None):
        sql = 'SELECT id,created_ns,payload FROM native_fatal_rejections'
        values = []
        if input_id is not None:
            sql += ' WHERE input_id=?'
            values.append(input_id)
        for row in self.db.execute(sql+' ORDER BY created_ns,id', values):
            need(hashlib.sha256(row['payload'].encode()).hexdigest() == row['id'],
                 'Native fatal rejection payload changed')
            yield dict(id=row['id'], created_ns=row['created_ns'],
                       **json.loads(row['payload']))

    def add_native_instruction_site(self, summary, primary_pid=None):
        """Index one first-run fatal PC by its mapped-file machine site.

        The debugger is a second execution of the recorded recipe. It may
        corroborate a matching primary site, but cannot identify a missing
        first-run fatal instruction or its process. This record does not join
        the instruction to an archived Core address or original C expression.
        """
        from native_signal_replay import verify_receipt

        need(type(summary) is dict and type(summary.get('id')) is str and summary['id'],
             'Native site needs a replay summary id')
        need(type(summary.get('receipt')) is str and summary['receipt'],
             'Native site receipt path is required')
        receipt = Path(summary['receipt'])
        need(receipt.is_absolute() and receipt.is_file() and not receipt.is_symlink() and
             receipt.parent.parent == self.directory/'native-observations',
             'Native site receipt is outside this catalog')
        digest = summary.get('receipt_sha256')
        receipt_bytes = receipt.read_bytes()
        need(type(digest) is str and len(digest) == 64 and
             hashlib.sha256(receipt_bytes).hexdigest() == digest,
             'Native site receipt hash differs')
        checked = verify_receipt(receipt, digest)
        saved = json.loads(receipt_bytes)
        observation = saved['observation']
        expected = saved['recipe']['expect_signal']
        debugger = observation.get('debugger')
        need(checked['id'] == saved['id'] == summary['id'],
             'Native site replay id differs from receipt')
        need(checked['observation'] == observation,
             'Native site receipt changed during verification')
        linked = saved.get('linked_certificate')
        need(summary.get('target') == saved['recipe'].get('target') and
             summary.get('catalog_id') == (linked.get('catalog_id') if linked else None),
             'Native site source or certificate context differs from receipt')
        need(type(expected) is str and expected and
             summary.get('expected_signal') == observation.get('expected_signal') == expected and
             summary.get('expected_observed') is True and
             observation.get('expected_observed') is True and
             summary.get('timed_out') is False and observation.get('timed_out') is False and
             summary.get('signal_deliveries') == observation.get('signal_deliveries') and
             any(row.get('signal') == expected for row in observation['signal_deliveries']),
             'Expected native signal delivery is not verified')
        need(summary.get('signal_terminations') == observation.get('signal_terminations'),
             'Native signal termination differs from receipt')
        need(summary.get('primary_sites') == observation.get('primary_sites') and
             summary.get('primary_site') == observation.get('primary_site') and
             summary.get('same_native_site_observed') ==
             observation.get('same_native_site_observed'),
             'Native primary site or cross-run comparison differs from receipt')
        need(summary.get('external_state_complete') is False and
             observation.get('external_state_complete') is False and
             summary.get('external_dependency_status') ==
             observation.get('external_dependency_status') == 'not_captured',
             'Native external dependency status differs from receipt')
        need(summary.get('crash_instruction') == debugger,
             'Native debugger result differs from receipt')
        if primary_pid is None:
            need(len(observation['primary_sites']) < 2,
                 'Multiple fatal native sites require separate catalog entries')
            primary = observation.get('primary_site')
        else:
            need(type(primary_pid) is str and primary_pid and
                 len(observation['primary_sites']) > 1,
                 'Per-process native indexing requires multiple fatal sites')
            matching = [site for site in observation['primary_sites']
                        if site.get('pid') == primary_pid]
            need(len(matching) == 1 and matching[0].get('status') == 'captured',
                 'Per-process native site was not decoded')
            primary = matching[0]
        need(type(primary) is dict and primary.get('status') == 'captured',
             'No decoded first-run fatal instruction for this process')
        need(primary.get('signal') == expected and
             any(row.get('signal') == expected and row.get('pid') == primary.get('pid')
                 for row in observation['signal_terminations']),
             'Primary instruction is not the terminating process')
        selected = primary
        module_path = primary.get('module_path')
        offset = primary.get('file_offset')
        assembly = primary.get('assembly')
        pc = primary.get('pc')
        signal_code = primary.get('si_code')
        fault_address = primary.get('fault_address')
        module_sha = selected.get('module_sha256')
        instruction = selected.get('instruction_bytes')
        key = selected.get('stable_site_key')
        try:
            file_offset = int(offset, 16)
        except (TypeError, ValueError) as error:
            raise RuntimeError('Native primary file offset is malformed') from error
        need(type(module_sha) is str and len(module_sha) == 64 and
             all(c in '0123456789abcdef' for c in module_sha) and
             type(instruction) is str and len(instruction) > 0 and
             len(instruction) % 2 == 0 and
             all(c in '0123456789abcdef' for c in instruction) and
             offset.startswith('0x') and offset == hex(file_offset) and
             type(key) is str and len(key) == 64,
             'Native primary instruction identity is malformed')
        site = dict(module_sha256=module_sha, file_offset=offset,
                    instruction_bytes=instruction)
        need(key == hashlib.sha256(packed(site).encode()).hexdigest(),
             'Native stable site key differs')
        module = Path(module_path)
        with module.open('rb') as stream:
            stream.seek(file_offset)
            file_instruction = stream.read(len(instruction)//2)
        need(file_instruction.hex() == instruction,
             'Native instruction bytes differ from mapped file')
        terminated = any(row.get('signal') == expected and
                         row.get('pid') == primary.get('pid')
                         for row in observation['signal_terminations'])
        synchronous = bool(expected == 'SIGSEGV' and
                           str(signal_code).startswith('SEGV_'))
        causal_pc = bool(terminated and synchronous)
        record_id = saved['id'] if primary_pid is None else saved['id'] + ':' + primary_pid
        record = dict(schema=1, kind='native-instruction-site-observation',
                      id=record_id, observation_id=saved['id'],
                      pid=primary.get('pid'),
                      receipt=str(receipt), receipt_sha256=digest,
                      stable_site_key=key, signal=expected,
                      observed_delivery=True, terminated_by_signal=terminated,
                      site_role=('corroborated_primary_fault_pc'
                                 if causal_pc and
                                    observation.get('same_native_site_observed')
                                 else 'primary_synchronous_fault_pc'
                                 if causal_pc else 'primary_signal_delivery'),
                      primary_site=primary,
                      primary_sites=observation['primary_sites'],
                      external_state_complete=False,
                      external_dependency_status='not_captured',
                      cross_run_instruction_equivalence_observed=
                          observation.get('same_native_site_observed') is True,
                      causal_fault_pc_observed=causal_pc,
                      synchronous_fault_pc_observed=synchronous,
                      causal_fault_instruction_verified=False,
                      synchronous_fault_instruction_observed=False,
                      runtime_instruction_bytes_verified=False,
                      cross_run_instruction_equivalence_proved=False,
                      exact_original_c_expression_verified=False,
                      observed_signal_codes=sorted({row.get('si_code') for row in
                          observation['signal_deliveries']
                          if row.get('signal') == expected and row.get('si_code') and
                          row.get('pid') == primary.get('pid')}),
                      target=saved['recipe'].get('target'),
                      linked_certificate=summary.get('catalog_id'),
                      instruction=dict(site, module_path=str(module), pc=pc,
                                       assembly=assembly, si_code=signal_code,
                                       fault_address=fault_address,
                                       instruction_byte_source='mapped_elf_file',
                                       runtime_instruction_bytes_verified=False,
                                       source_line_context=selected.get('source_line_context'),
                                       function=selected.get('symbol'),
                                       source=(debugger.get('source') if
                                               observation.get('same_native_site_observed')
                                               else None),
                                       line=(debugger.get('line') if
                                             observation.get('same_native_site_observed')
                                             else None)),
                      debugger_instruction=(debugger if type(debugger) is dict else None),
                      scope='Same-run fatal PC with mapped ELF file bytes; runtime '
                            'instruction bytes, original C expression, and Core-node '
                            'link are not verified')
        payload = packed(record)
        with self.db:
            existing = self.db.execute(
                'SELECT payload FROM native_instruction_sites WHERE id=?',
                (record['id'],)).fetchone()
            if existing is None:
                self.db.execute('INSERT INTO native_instruction_sites VALUES(?,?,?,?,?)',
                                (record['id'], key, expected, time.time_ns(), payload))
            else:
                need(existing['payload'] == payload,
                     'Native replay id already names another instruction site')
        return key

    def add_native_instruction_sites(self, summary):
        """Index every fatal PID; retain undecoded ones as explicit pending work."""
        need(type(summary) is dict and type(summary.get('receipt')) is str and
             type(summary.get('receipt_sha256')) is str, 'Native receipt is required')
        receipt = Path(summary['receipt'])
        need(receipt.is_absolute() and receipt.is_file() and not receipt.is_symlink() and
             receipt.parent.parent == self.directory/'native-observations' and
             hashlib.sha256(receipt.read_bytes()).hexdigest() == summary['receipt_sha256'],
             'Native site receipt is missing or changed')
        from native_signal_replay import verify_receipt
        verified = verify_receipt(receipt, summary['receipt_sha256'])
        saved = json.loads(receipt.read_bytes())
        observation = verified['observation']
        sites = observation['primary_sites']
        need(saved['id'] == summary.get('id') == verified['id'] and
             summary.get('primary_sites') == sites and
             summary.get('signal_terminations') == observation['signal_terminations'] and
             summary.get('external_state_complete') is False and
             summary.get('external_dependency_status') == 'not_captured',
             'Native per-process summary differs from receipt')
        keys = []
        if len(sites) < 2:
            primary = summary.get('primary_site')
            if type(primary) is dict and primary.get('status') == 'captured':
                keys.append(self.add_native_instruction_site(summary))
            if not sites:
                return keys
        for site in sites:
            if site.get('status') == 'captured':
                if len(sites) > 1:
                    keys.append(self.add_native_instruction_site(summary, site['pid']))
                continue
            need(site.get('status') in ('not_captured', 'not_decoded') and
                 type(site.get('pid')) is str,
                 'Unrecognized pending native site status')
            record = dict(schema=1, kind='native-instruction-site-pending',
                          id=saved['id'] + ':' + site['pid'], observation_id=saved['id'],
                          pid=site['pid'], signal=saved['recipe']['expect_signal'],
                          status=site['status'], reason=site.get('reason'), site=site,
                          receipt=str(receipt), receipt_sha256=summary['receipt_sha256'],
                          external_state_complete=False,
                          external_dependency_status='not_captured')
            payload = packed(record)
            with self.db:
                existing = self.db.execute(
                    'SELECT payload FROM native_instruction_site_pending WHERE id=?',
                    (record['id'],)).fetchone()
                if existing is None:
                    self.db.execute('INSERT INTO native_instruction_site_pending VALUES(?,?,?,?)',
                                    (record['id'], record['signal'], time.time_ns(), payload))
                else:
                    need(existing['payload'] == payload,
                         'Native replay id already names another pending site')
        return keys

    def list_pending_native_instruction_sites(self, signal=None):
        """Return fatalities whose machine instruction could not be decoded."""
        sql = 'SELECT payload FROM native_instruction_site_pending'
        args = ()
        if signal is not None:
            sql += ' WHERE signal=?'
            args = (signal,)
        for row in self.db.execute(sql + ' ORDER BY created_ns,id', args):
            yield json.loads(row['payload'])

    def list_native_instruction_sites(self, signal=None, stable_site_key=None):
        """Group immutable observations without promoting superseded claims."""
        clauses, args = [], []
        if signal is not None:
            clauses.append('signal=?')
            args.append(signal)
        if stable_site_key is not None:
            clauses.append('stable_site_key=?')
            args.append(stable_site_key)
        where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
        sql = ('SELECT stable_site_key,signal,COUNT(*) AS observation_count,'
               'MIN(created_ns) AS first_seen_ns,MAX(created_ns) AS last_seen_ns '
               'FROM native_instruction_sites' + where +
               ' GROUP BY stable_site_key,signal ORDER BY signal,stable_site_key')
        for group in self.db.execute(sql, args):
            representatives = self.db.execute(
                'SELECT payload FROM native_instruction_sites '
                'WHERE stable_site_key=? AND signal=? ORDER BY created_ns DESC,id DESC',
                (group['stable_site_key'], group['signal']))
            item = None
            current_count = 0
            for candidate in representatives:
                record = json.loads(candidate['payload'])
                if current_native_site_record(record):
                    current_count += 1
                    if item is None:
                        item = record
            yield dict(stable_site_key=group['stable_site_key'], signal=group['signal'],
                       observation_count=group['observation_count'],
                       current_observation_count=current_count,
                       legacy_observation_count=group['observation_count']-current_count,
                       first_seen_ns=group['first_seen_ns'],
                       last_seen_ns=group['last_seen_ns'],
                       representative_status=('current' if item else
                                              'legacy_only_no_current_claim'),
                       representative_receipt=item['receipt'] if item else None,
                       representative_receipt_sha256=item['receipt_sha256'] if item else None,
                       representative=item)

    def native_instruction_site_observations(self, stable_site_key, signal):
        """Read the individual immutable receipts underlying one native site."""
        for row in self.db.execute(
                'SELECT payload FROM native_instruction_sites '
                'WHERE stable_site_key=? AND signal=? ORDER BY created_ns,id',
                (stable_site_key, signal)):
            yield json.loads(row['payload'])

    def add_native_core_link(self, *, receipt, receipt_sha256, stable_site_key,
                             target, section, ordinal, address, site_kind,
                             core_site_sha256, source_file, source_line,
                             source_sha256, relation, fatal_pid=None,
                             recursive_symbol=None, min_recursive_frames=2):
        """Link a fatal native PC to an independently checked archived Core site.

        The relation is source-and-trace evidence. It is not a Lean execution
        proof, a translation-preservation proof, or equality of the Core site
        with the machine instruction at the fatal PC.
        """
        from core_index import Index
        from fault_source_map import _core_site_identity, resolve_typed_site
        from native_signal_replay import verify_receipt
        from signal_search import Worker

        receipt = Path(receipt).resolve(strict=True)
        need(receipt.parent.parent == self.directory/'native-observations' and
             receipt.name == 'receipt.json' and not receipt.is_symlink() and
             sha(receipt) == receipt_sha256,
             'Native-Core link requires a hash-pinned receipt in this catalog')
        verified = verify_receipt(receipt, receipt_sha256)
        saved = json.loads(receipt.read_bytes())
        need(verified['id'] == saved['id'] and
             saved['source_identity']['kind'] == 'openssh-archive' and
             saved['source_identity']['target'] == target and
             saved['recipe'].get('target') == target,
             'Native-Core link target differs from the pinned OpenSSH receipt')
        need(type(stable_site_key) is str and len(stable_site_key) == 64 and
             type(core_site_sha256) is str and len(core_site_sha256) == 64 and
             type(site_kind) is str and site_kind and
             (address is None or
              (type(address) is list and all(type(part) is int and part >= 0
                                             for part in address))),
             'Native-Core link has an invalid site identity')
        candidates = [site for site in saved['observation']['primary_sites']
                      if site.get('status') == 'captured' and
                      site.get('stable_site_key') == stable_site_key and
                      (fatal_pid is None or site.get('pid') == fatal_pid)]
        need(len(candidates) == 1,
             'Native-Core link must select one decoded first-run fatal process')
        native_site = candidates[0]
        need(native_site.get('signal') == 'SIGSEGV' and
             str(native_site.get('si_code', '')).startswith('SEGV_') and
             any(row.get('pid') == native_site['pid'] and row.get('signal') == 'SIGSEGV'
                 for row in saved['observation']['signal_terminations']),
             'Native-Core link requires a synchronous fatal SIGSEGV')
        deliveries = [row for row in saved['observation']['signal_deliveries']
                      if row.get('pid') == native_site['pid'] and
                      row.get('signal') == 'SIGSEGV']
        need(deliveries and deliveries[-1].get('instruction_pointer') ==
             native_site.get('pc') and
             deliveries[-1].get('si_code') == native_site.get('si_code'),
             'Native-Core link fatal trace and PC differ')
        fatal_delivery = deliveries[-1]
        need(relation in ('source_context_association', 'causal_recursive_call'),
             'Unsupported native-Core link relation')
        frame_count = None
        if relation == 'causal_recursive_call':
            need(type(recursive_symbol) is str and
                 re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', recursive_symbol) and
                 type(min_recursive_frames) is int and min_recursive_frames >= 2,
                 'Recursive-call relation needs a C symbol and frame threshold')
            frame_count = pinned_recursive_frame_count(
                fatal_delivery['stack_frames'], recursive_symbol,
                saved['binary']['path'])
            need(frame_count >= min_recursive_frames,
                 'Fatal native trace lacks recursive frames in the pinned executable')
        else:
            need(recursive_symbol is None,
                 'A recursive symbol requires a causal_recursive_call relation')

        need(type(target) is str and target and type(section) is str and section and
             type(ordinal) is int and ordinal >= 0 and
             type(source_file) is str and source_file and
             type(source_line) is int and source_line > 0 and
             type(source_sha256) is str and len(source_sha256) == 64,
             'Native-Core link has an invalid archive or source selector')
        index = Index()
        try:
            need(index.archive.manifest_sha256 ==
                 saved['source_identity']['archive_manifest_sha256'],
                 'Native-Core link archive differs from the native receipt')
            with tempfile.TemporaryDirectory(prefix='native-core-link-') as directory:
                with Worker(directory) as worker:
                    alias = 'NativeCoreLink.row'
                    metadata = worker.load(index, target, section, ordinal, alias)
                    observed = worker.sites(alias, [site_kind])
                    sites = [site for site in observed['sites']
                             if site.get('kind') == site_kind and
                             (address is None or site.get('address') == address) and
                             _core_site_identity(index.archive.manifest_sha256,
                                 target, section, ordinal, metadata['sha256'],
                                 site['address'])['sha256'] == core_site_sha256]
                    need(len(sites) == 1,
                         'Native-Core link site is not in the checked archived row')
                    mapped = resolve_typed_site(
                        index, worker, alias, sites[0], metadata['sha256'],
                        expected_target=target, expected_section=section,
                        expected_ordinal=ordinal)
            identity = _core_site_identity(index.archive.manifest_sha256,
                target, section, ordinal, metadata['sha256'], sites[0]['address'])
            need(identity['sha256'] == core_site_sha256 and
                 mapped['core_site_identity'] == identity,
                 'Native-Core link archived site hash differs')
        finally:
            index.close()

        focus = mapped['source_focus'] or mapped['context_focus']
        need(mapped['source']['status'] == 'mapped' and focus is not None and
             focus['source'] == source_file and focus['line'] == source_line and
             focus['sha256'] == source_sha256 and
             sha(Path(focus['original_path'])) == source_sha256,
             'Native-Core link original C source line or bytes differ')
        relation_evidence = dict(kind=relation,
            interpretation_status='supported_by_checked_source_and_native_trace; not proved')
        if relation == 'causal_recursive_call':
            need(site_kind in ('call', 'indirect-call', 'pure-call') and
                 metadata['name'] == recursive_symbol and
                 re.search(r'(?<![A-Za-z0-9_])'+re.escape(recursive_symbol)+r'\s*\(',
                           focus['text']),
                 'Recursive-call relation lacks a matching archived/source call')
            relation_evidence.update(recursive_symbol=recursive_symbol,
                observed_recursive_frames=frame_count,
                required_recursive_frames=min_recursive_frames,
                recursive_frame_module=saved['binary']['path'],
                recursive_frame_module_sha256=saved['binary']['sha256'],
                total_captured_frames=len(fatal_delivery['stack_frames']),
                source_call_text_checked=True)

        record = dict(schema=1, kind='native-to-archived-core-source-link',
            native=dict(observation_id=saved['id'], receipt=str(receipt),
                        receipt_sha256=receipt_sha256,
                        stable_site_key=stable_site_key, pid=native_site['pid'],
                        fatal_pc=native_site['pc'], signal='SIGSEGV',
                        si_code=native_site['si_code'],
                        fault_address=native_site.get('fault_address'),
                        module_path=native_site.get('module_path'),
                        module_sha256=native_site.get('module_sha256'),
                        mapped_file_offset=native_site.get('file_offset'),
                        mapped_file_instruction_bytes=native_site.get('instruction_bytes'),
                        runtime_instruction_bytes_verified=False,
                        evidence='same-run fatal signal trace'),
            compiler_dwarf_line=dict(
                reported=native_site.get('source_line_context'),
                evidence='addr2line report for pinned faulting ELF; not the causal call site'),
            archived_core=dict(identity=identity, site_kind=site_kind,
                site=sites[0], row_name=metadata['name'],
                source_annotation_origin=mapped['source_location_origin'],
                own_source_location_verified=mapped['site_source_mapping_verified'],
                original_c_line_context=dict(source=focus['source'],
                    original_path=focus['original_path'], sha256=focus['sha256'],
                    line=focus['line'], text=focus['text'],
                    line_byte_span=focus['line_byte_span'],
                    relationship=('own_annotation' if mapped['source_focus'] else
                                  'inherited_context_only'))),
            relation=relation_evidence,
            proof_status=dict(lean_entry_reachability_proved=False,
                c_core_translation_preservation_proved=False,
                core_native_execution_correspondence_proved=False,
                original_c_expression_span_verified=False,
                fatal_instruction_equals_core_site=False))
        payload = packed(record)
        identity = hashlib.sha256(payload.encode()).hexdigest()
        with self.db:
            existing = self.db.execute(
                'SELECT payload FROM native_core_links WHERE id=?', (identity,)).fetchone()
            if existing is None:
                self.db.execute('INSERT INTO native_core_links VALUES(?,?,?,?,?,?,?)',
                    (identity, saved['id'], stable_site_key, core_site_sha256,
                     relation, time.time_ns(), payload))
            else:
                need(existing['payload'] == payload,
                     'Native-Core link id already names different evidence')
        return identity

    def read_native_core_link(self, identity):
        row = self.db.execute('SELECT payload FROM native_core_links WHERE id=?',
                              (identity,)).fetchone()
        need(row is not None, 'Unknown native-Core link: '+identity)
        need(hashlib.sha256(row['payload'].encode()).hexdigest() == identity,
             'Native-Core link evidence hash differs')
        record = json.loads(row['payload'])
        return dict(id=identity,
                    record_status=('current' if current_native_core_link(record)
                                   else 'legacy_module_unscoped'), **record)

    def list_native_core_links(self, observation_id=None, core_site_sha256=None,
                               include_history=False):
        """List one current link per relation; opt in to immutable history."""
        where, values = [], []
        if observation_id is not None:
            where.append('observation_id=?')
            values.append(observation_id)
        if core_site_sha256 is not None:
            where.append('core_site_sha256=?')
            values.append(core_site_sha256)
        sql = 'SELECT id,created_ns,payload FROM native_core_links'
        if where:
            sql += ' WHERE ' + ' AND '.join(where)
        rows = list(self.db.execute(sql+' ORDER BY created_ns,id', values))
        if include_history:
            for row in rows:
                yield self.read_native_core_link(row['id'])
            return
        selected = {}
        for row in rows:
            record = json.loads(row['payload'])
            if not current_native_core_link(record):
                continue
            key = (record['native']['observation_id'],
                   record['native']['stable_site_key'],
                   record['archived_core']['identity']['sha256'],
                   record['relation']['kind'])
            selected[key] = row
        for row in sorted(selected.values(), key=lambda row:
                          (row['created_ns'], row['id'])):
            yield self.read_native_core_link(row['id'])

    def _reproducer_asset_path(self, role, digest):
        need(role in ('profile', 'search-result', 'script', 'renderer',
                      'parser-module', 'parser-bundle') and
             type(digest) is str and re.fullmatch(r'[0-9a-f]{64}', digest),
             'Invalid native reproducer asset identity')
        suffix = {'script': '.sh', 'renderer': '.py',
                  'parser-module': '.py'}.get(role, '.json')
        return self.directory/'native-reproducer-assets'/(digest+'-'+role+suffix)

    def _store_reproducer_asset(self, role, contents):
        digest = hashlib.sha256(contents).hexdigest()
        path = self._reproducer_asset_path(role, digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        need(not path.parent.is_symlink(), 'Reproducer asset directory is a symlink')
        try:
            with path.open('xb') as stream:
                stream.write(contents)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            pass
        need(path.is_file() and not path.is_symlink() and path.read_bytes() == contents,
             'Catalog reproducer asset differs from its content hash')
        return path

    def _archive_parser_bundle(self, parser_sha256):
        """Preserve the parser and its local import closure for historical replay."""
        need(sha(WORKSPACE/'search/native_signal_replay.py') == parser_sha256,
             'Recorded native trace parser has already changed')
        modules = []
        for name in PARSER_BUNDLE_MODULES:
            source = WORKSPACE/'search'/name
            need(source.is_file() and not source.is_symlink(),
                 'Parser dependency is missing or linked: '+name)
            raw = source.read_bytes()
            asset = self._store_reproducer_asset('parser-module', raw)
            modules.append(dict(name=name, sha256=hashlib.sha256(raw).hexdigest(),
                                asset=str(asset)))
        manifest = dict(schema=1, parser_sha256=parser_sha256, modules=modules)
        expected = (packed(manifest)+'\n').encode()
        return self._store_reproducer_asset('parser-bundle', expected)

    def _bind_parser_bundle(self, identity, parser_sha256, bundle_path):
        """Append-only reproducer-to-toolchain reference outside legacy payloads."""
        record = dict(schema=1, reproducer_id=identity,
                      parser_sha256=parser_sha256,
                      bundle_sha256=sha(bundle_path),
                      bundle_path=str(bundle_path))
        payload = packed(record)
        binding_id = hashlib.sha256(payload.encode()).hexdigest()
        with self.db:
            existing = self.db.execute(
                'SELECT binding_id,payload FROM native_reproducer_toolchains '
                'WHERE reproducer_id=?', (identity,)).fetchone()
            if existing is None:
                self.db.execute(
                    'INSERT INTO native_reproducer_toolchains VALUES(?,?,?)',
                    (identity, binding_id, payload))
            else:
                need(existing['binding_id'] == binding_id and
                     existing['payload'] == payload,
                     'Native reproducer already has a different parser toolchain')
        directory = self.directory/'native-reproducer-toolchains'
        directory.mkdir(parents=True, exist_ok=True)
        need(not directory.is_symlink(),
             'Native reproducer toolchain directory is a symlink')
        path = directory/(identity+'.json')
        expected = (payload+'\n').encode()
        try:
            with path.open('xb') as stream:
                stream.write(expected)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            pass
        need(path.is_file() and not path.is_symlink() and
             path.read_bytes() == expected,
             'Native reproducer parser binding changed')
        return path

    def _load_parser_bundle(self, identity, parser_sha256):
        bound = self.db.execute(
            'SELECT binding_id,payload FROM native_reproducer_toolchains '
            'WHERE reproducer_id=?', (identity,)).fetchone()
        need(bound is not None and
             hashlib.sha256(bound['payload'].encode()).hexdigest() ==
             bound['binding_id'],
             'Native reproducer parser binding is missing or changed')
        binding = self.directory/'native-reproducer-toolchains'/(identity+'.json')
        need(binding.is_file() and not binding.is_symlink(),
             'Native reproducer parser binding is missing')
        need(binding.read_bytes() == (bound['payload']+'\n').encode(),
             'Exported native reproducer parser binding differs from catalog')
        reference = json.loads(binding.read_bytes())
        path = self._reproducer_asset_path('parser-bundle',
                                           reference['bundle_sha256'])
        need(reference == dict(schema=1, reproducer_id=identity,
                               parser_sha256=parser_sha256,
                               bundle_sha256=reference['bundle_sha256'],
                               bundle_path=str(path)) and
             binding.read_bytes() == (packed(reference)+'\n').encode(),
             'Native reproducer parser binding differs')
        need(path.is_file() and not path.is_symlink(),
             'Versioned native trace parser bundle is missing')
        need(sha(path) == reference['bundle_sha256'],
             'Versioned native trace parser bundle changed')
        manifest = json.loads(path.read_bytes())
        need(manifest.get('schema') == 1 and
             manifest.get('parser_sha256') == parser_sha256 and
             type(manifest.get('modules')) is list and
             [row.get('name') for row in manifest['modules']] ==
             list(PARSER_BUNDLE_MODULES) and
             path.read_bytes() == (packed(manifest)+'\n').encode(),
             'Versioned native trace parser bundle is malformed')
        drift = False
        for row in manifest['modules']:
            asset = self._reproducer_asset_path('parser-module', row['sha256'])
            need(row.get('asset') == str(asset) and
                 asset.is_file() and not asset.is_symlink() and
                 sha(asset) == row['sha256'],
                 'Versioned native trace parser dependency is missing or changed')
            current = WORKSPACE/'search'/row['name']
            drift |= (not current.is_file() or current.is_symlink() or
                      sha(current) != row['sha256'])
        need(manifest['modules'][0]['sha256'] == parser_sha256,
             'Versioned parser source differs from recorded parser identity')
        return manifest, drift

    def _parser_bundle_command(self, manifest, command):
        need(Path('/usr/bin/bwrap').is_file(),
             'Historical native replay needs the bubblewrap mount tool')
        wrapped = ['/usr/bin/bwrap', '--bind', '/', '/',
                   '--dev-bind', '/dev', '/dev']
        cache = WORKSPACE/'search/__pycache__'
        if cache.is_dir():
            wrapped.extend(['--tmpfs', str(cache)])
        for row in manifest['modules']:
            wrapped.extend(['--ro-bind', row['asset'],
                            str(WORKSPACE/'search'/row['name'])])
        return wrapped+['--', *command]

    def _native_reproducer_record(self, contents, origins, core_link_id,
                                  source_call_witness_id,
                                  core_cabs_bridge_id, *,
                                  historical_renderer_sha256=None,
                                  historical_parser_sha256=None,
                                  historical_reproducer_id=None):
        """Recompute the complete generated-script, native, C and Core chain."""
        from cabs_call_witness import DEFAULT_ARCHIVE, verify_call_witness
        from core_cabs_context_bridge import verify_context_bridge
        from model_archive import Archive
        from native_depth_search import (DESTINATION, check_profile,
                                         expanded_argv)
        from native_reproducer import render_reproducer_script
        import native_reproducer
        from native_signal_replay import verify_receipt

        need(set(contents) == {'profile', 'search-result', 'script'} and
             set(origins) == set(contents) and
             all(type(path) is str and Path(path).is_absolute()
                 for path in origins.values()),
             'Native reproducer source paths are incomplete')
        profile = check_profile(json.loads(contents['profile']))
        result = json.loads(contents['search-result'])
        need(type(result) is dict and
             result.get('status') in ('observed_depth_bracket',
                                      'observed_crash_at_zero_depth',
                                      'mixed_zero_depth_signal') and
             type(result.get('witness_depth')) is int and
             result['witness_depth'] >= 0,
             'Native reproducer needs an observed search witness')
        target = profile['target']
        profile_digest = hashlib.sha256(contents['profile']).hexdigest()
        need(result.get('profile_sha256') == profile_digest and
             result.get('target') == target and
             result.get('output') == str(Path(origins['search-result']).parent) and
             result.get('catalog_dir') == str(self.directory) and
             result.get('native_core_link_id') == core_link_id,
             'Native reproducer search identity differs')
        runtime = result.get('reproducer_runtime')
        current_parser_sha256 = sha(WORKSPACE/'search/native_signal_replay.py')
        need(type(runtime) is dict and
             type(runtime.get('stack_limit_kib')) is str and
             runtime['stack_limit_kib'].isdigit() and
             type(runtime.get('trace_parser_sha256')) is str and
             re.fullmatch(r'[0-9a-f]{64}', runtime['trace_parser_sha256']) and
             (historical_parser_sha256 == runtime['trace_parser_sha256'] or
              runtime['trace_parser_sha256'] == current_parser_sha256),
             'Native reproducer runtime or trace parser identity differs')
        expected_input = repeated_input_identity(profile, result['witness_depth'])
        need(result.get('capture_input_materialized_bytes') ==
             expected_input['bytes'],
             'Native reproducer selected input length differs')
        renderer_path = Path(native_reproducer.__file__).resolve(strict=True)
        renderer_digest = sha(renderer_path)
        if historical_renderer_sha256 is None:
            need(contents['script'] == render_reproducer_script(profile, result),
                 'Bash program is not the deterministic search-generated reproducer')
        else:
            versioned_renderer = self._reproducer_asset_path(
                'renderer', historical_renderer_sha256)
            need(type(historical_renderer_sha256) is str and
                 re.fullmatch(r'[0-9a-f]{64}', historical_renderer_sha256) and
                 versioned_renderer.is_file() and
                 not versioned_renderer.is_symlink() and
                 sha(versioned_renderer) == historical_renderer_sha256,
                 'Versioned native reproducer renderer is missing or changed')
            historical_render = runpy.run_path(str(versioned_renderer))[
                'render_reproducer_script']
            need(contents['script'] == historical_render(profile, result),
                 'Bash program differs from its versioned renderer')
            renderer_digest = historical_renderer_sha256

        receipt_ref = result.get('receipt')
        need(type(receipt_ref) is dict and
             type(receipt_ref.get('id')) is str and
             type(receipt_ref.get('receipt')) is str and
             type(receipt_ref.get('receipt_sha256')) is str,
             'Native search result lacks a replay receipt')
        receipt = Path(receipt_ref['receipt'])
        need(receipt.is_absolute() and receipt.is_file() and
             not receipt.is_symlink() and
             receipt.parent.parent == self.directory/'native-observations' and
             receipt.name == 'receipt.json' and
             sha(receipt) == receipt_ref['receipt_sha256'],
             'Native reproducer receipt is missing or outside this catalog')
        if historical_parser_sha256 is None:
            checked = verify_receipt(receipt, receipt_ref['receipt_sha256'])
        else:
            bundle, _ = self._load_parser_bundle(
                historical_reproducer_id, historical_parser_sha256)
            command = self._parser_bundle_command(bundle, [
                '/usr/bin/python3', str(WORKSPACE/'search/native_signal_replay.py'),
                'verify', str(receipt), '--sha256', receipt_ref['receipt_sha256']])
            completed = subprocess.run(command, cwd=WORKSPACE,
                                       capture_output=True, text=True, timeout=120)
            need(completed.returncode == 0,
                 'Historical native receipt verification failed: '+
                 completed.stderr[-2000:])
            checked = json.loads(completed.stdout)
        saved = json.loads(receipt.read_bytes())
        observation = saved['observation']
        need(checked['id'] == receipt_ref['id'] == saved['id'] and
             checked['observation'] == observation and
             saved['source_identity'].get('kind') == 'openssh-archive' and
             saved['source_identity'].get('target') == target and
             saved['recipe'].get('target') == target and
             saved['binary']['path'] == result.get('native_binary') and
             saved['binary']['sha256'] == result.get('native_binary_sha256') and
             receipt_ref.get('primary_sites') == observation['primary_sites'] and
             saved['recipe']['expect_signal'] == 'SIGSEGV' and
             observation['expected_signal'] == 'SIGSEGV' and
             observation['expected_observed'] is True and
             observation['timed_out'] is False,
             'Native reproducer receipt and pinned OpenSSH identity differ')
        destination = (Path(result['output'])/'capture-destination'
                       if any(DESTINATION in arg for arg in profile['argv'])
                       else None)
        need(saved['recipe']['argv'] ==
             expanded_argv(profile['argv'], destination) and
             saved['recipe']['cwd'] == profile['cwd'] and
             saved['recipe']['env'] == profile['env'] and
             saved['recipe']['timeout_seconds'] == profile['timeout_seconds'] and
             encoded_input_identity(saved['recipe']['stdin_base64']) == expected_input,
             'Generated profile does not reproduce the receipt invocation')
        terminations = {(row.get('pid'), row.get('signal'))
                        for row in observation['signal_terminations']}
        fatal_sites = [dict(pid=site['pid'], pc=site['pc'],
                            module_path=site['module_path'],
                            file_offset=site['file_offset'],
                            stable_site_key=site['stable_site_key'],
                            si_code=site['si_code'])
                       for site in observation['primary_sites']
                       if site.get('status') == 'captured' and
                          site.get('signal') == 'SIGSEGV' and
                          str(site.get('si_code', '')).startswith('SEGV_') and
                          (site.get('pid'), 'SIGSEGV') in terminations and
                          pinned_signal_delivery(
                              observation, site, saved['binary']['path'])]
        need(fatal_sites, 'Reproducer has no fatal synchronous SIGSEGV with '
             'a frame in the pinned OpenSSH executable')

        link = None
        if core_link_id is not None:
            need(type(core_link_id) is str and
                 re.fullmatch(r'[0-9a-f]{64}', core_link_id),
                 'Invalid native-Core link identity')
            link = self.read_native_core_link(core_link_id)
            native = link['native']
            need(link['record_status'] == 'current' and
                 native['observation_id'] == saved['id'] and
                 native['receipt'] == str(receipt) and
                 native['receipt_sha256'] == receipt_ref['receipt_sha256'] and
                 native['signal'] == 'SIGSEGV' and
                 native['stable_site_key'] in {site['stable_site_key']
                                               for site in fatal_sites} and
                 link['archived_core']['identity']['target'] == target and
                 link['archived_core']['identity']['archive_manifest_sha256'] ==
                 saved['source_identity']['archive_manifest_sha256'],
                 'Native-Core link does not match this fatal receipt')
            requested = profile['core_link']
            context = link['archived_core']['original_c_line_context']
            need(requested is not None and
                 requested['core_site_sha256'] ==
                 link['archived_core']['identity']['sha256'] and
                 requested['site_kind'] == link['archived_core']['site_kind'] and
                 requested['section'] ==
                 link['archived_core']['identity']['section'] and
                 requested['ordinal'] ==
                 link['archived_core']['identity']['row_ordinal'] and
                 requested['source_file'] == context['source'] and
                 requested['source_line'] == context['line'] and
                 requested['source_sha256'] == context['sha256'] and
                 requested['relation'] == link['relation']['kind'],
                 'Search profile and selected native-Core source link differ')

        call, archive = None, None
        if source_call_witness_id is not None:
            need(link is not None and type(source_call_witness_id) is str and
                 re.fullmatch(r'[0-9a-f]{64}', source_call_witness_id),
                 'An exact C call witness requires a checked native-Core link')
            call_path = self.directory/'source-call-witnesses'/(
                source_call_witness_id+'.json')
            need(call_path.is_file() and not call_path.is_symlink(),
                 'Exact C call witness is missing from this catalog')
            call = json.loads(call_path.read_bytes())
            archive = Archive(DEFAULT_ARCHIVE)
            verify_call_witness(archive, call)
            context = link['archived_core']['original_c_line_context']
            need(call['id'] == source_call_witness_id and
                 call['target'] == target and
                 call['archive_manifest_sha256'] ==
                 saved['source_identity']['archive_manifest_sha256'] and
                 call['source'] == context['source'] and
                 call['line'] == context['line'] and
                 call['original_c_sha256'] == context['sha256'] and
                 call['caller'] == link['archived_core']['row_name'] and
                 (link['relation']['kind'] != 'causal_recursive_call' or
                  call['callee'] == link['relation']['recursive_symbol']),
                 'Exact original-C call witness and archived context differ')

        bridge = None
        if core_cabs_bridge_id is not None:
            need(link is not None and call is not None and
                 type(core_cabs_bridge_id) is str and
                 re.fullmatch(r'[0-9a-f]{64}', core_cabs_bridge_id),
                 'Core-Cabs bridge requires checked Core and Cabs witnesses')
            bridge_path = self.directory/'core-cabs-bridges'/(
                core_cabs_bridge_id+'.json')
            need(bridge_path.is_file() and not bridge_path.is_symlink(),
                 'Core-Cabs context bridge is missing from this catalog')
            bridge = json.loads(bridge_path.read_bytes())
            verify_context_bridge(archive, bridge, call)
            identity = link['archived_core']['identity']
            need(bridge['id'] == core_cabs_bridge_id and
                 bridge['target'] == target and
                 bridge['archive_manifest_sha256'] ==
                 identity['archive_manifest_sha256'] and
                 bridge['section'] == identity['section'] and
                 bridge['row_ordinal'] == identity['row_ordinal'] and
                 bridge['fragment_sha256'] == identity['fragment_sha256'] and
                 bridge['core_site_sha256'] == identity['sha256'] and
                 bridge['core_site_kind'] == link['archived_core']['site_kind'],
                 'Core-Cabs bridge does not name the selected archived Core site')

        assets = {}
        for role, raw in contents.items():
            digest = hashlib.sha256(raw).hexdigest()
            assets[role] = dict(path=str(self._reproducer_asset_path(role, digest)),
                                sha256=digest, bytes=len(raw),
                                source_path=origins[role])
        script_path = assets['script']['path']
        proof = dict(lean_certificate_id=None,
            archived_core_candidate=(link['archived_core']['identity']
                                     if link is not None else None),
            native_core_link_id=core_link_id,
            exact_cabs_call_witness_id=source_call_witness_id,
            core_cabs_bridge_id=core_cabs_bridge_id,
            exact_cabs_original_c_expression_verified=call is not None,
            core_own_ancestor_cabs_region_verified=bridge is not None,
            lean_entry_to_signal_proved=False,
            cabs_to_core_translation_proved=False,
            core_native_execution_correspondence_proved=False,
            obligations=['Lean entry-to-fault reachability',
                         'Cabs-to-Core translation preservation',
                         'Core-to-native execution correspondence'])
        if link is None:
            proof['obligations'].append('Map native result to an archived Core and original-C site')
        elif call is None:
            proof['obligations'].append('Verify an exact original-C expression span')
        elif bridge is None:
            proof['obligations'].append('Check Core owning region against the Cabs call')
        return dict(schema=1, kind='generated-native-sigsegv-reproducer',
            search=dict(algorithm='native-repeated-input-depth-search',
                        status=result['status'],
                        witness_depth=result['witness_depth'],
                        profile_sha256=profile_digest,
                        result_sha256=assets['search-result']['sha256'],
                        probe_count=result.get('probe_count')),
            target=target, assets=assets,
            generator=dict(path=str(renderer_path), sha256=renderer_digest,
                           function='render_reproducer_script'),
            native=dict(observation_id=saved['id'], receipt=str(receipt),
                        receipt_sha256=receipt_ref['receipt_sha256'],
                        binary=saved['binary'], argv=saved['recipe']['argv'],
                        cwd=saved['recipe']['cwd'], env=saved['recipe']['env'],
                        stdin=expected_input, signal='SIGSEGV',
                        fatal_sites=fatal_sites),
            original_c=(dict(witness_id=call['id'], source=call['source'],
                             line=call['line'],
                             byte_span=call['original_c']['byte_span'],
                             expression_sha256=call['original_c']['expression_sha256'],
                             text=call['original_c']['text'])
                        if call is not None else
                        dict(witness_id=None, source_context=(
                            link['archived_core']['original_c_line_context']
                            if link is not None else None))),
            formal=proof,
            replay=dict(command=['/usr/bin/bash', script_path],
                        bash_sha256=sha(Path('/usr/bin/bash')),
                        success_marker='REPRODUCED_SIGSEGV '))

    def add_native_reproducer(self, *, profile, search_result, script,
                              native_core_link_id=None,
                              source_call_witness_id=None,
                              core_cabs_bridge_id=None):
        """Catalog only a generated Bash program with a checked fatal receipt."""
        supplied = dict(profile=profile, **{'search-result': search_result},
                        script=script)
        contents, origins = {}, {}
        for role, value in supplied.items():
            path = Path(value)
            need(path.is_absolute() and path.is_file() and not path.is_symlink(),
                 'Native reproducer source is not an absolute regular file: '+role)
            contents[role] = path.read_bytes()
            origins[role] = str(path)
        record = self._native_reproducer_record(
            contents, origins, native_core_link_id, source_call_witness_id,
            core_cabs_bridge_id)
        renderer_source = Path(record['generator']['path']).read_bytes()
        need(str(self._store_reproducer_asset('renderer', renderer_source)) ==
             str(self._reproducer_asset_path(
                 'renderer', record['generator']['sha256'])),
             'Versioned renderer asset differs from generated program')
        parser_sha256 = json.loads(contents['search-result'])[
            'reproducer_runtime']['trace_parser_sha256']
        bundle_path = self._archive_parser_bundle(
            parser_sha256)
        for role, raw in contents.items():
            need(str(self._store_reproducer_asset(role, raw)) ==
                 record['assets'][role]['path'],
                 'Stored native reproducer asset identity changed')
        payload = packed(record)
        identity = hashlib.sha256(payload.encode()).hexdigest()
        with self.db:
            existing = self.db.execute(
                'SELECT payload FROM native_reproducers WHERE id=?',
                (identity,)).fetchone()
            if existing is None:
                self.db.execute('INSERT INTO native_reproducers VALUES(?,?,?,?,?,?,?)',
                    (identity, record['native']['observation_id'], record['target'],
                     record['assets']['script']['sha256'], native_core_link_id,
                     time.time_ns(), payload))
            else:
                need(existing['payload'] == payload,
                     'Native reproducer id already names different evidence')
        self._bind_parser_bundle(identity, parser_sha256, bundle_path)
        self.export_native_reproducer(identity)
        return identity

    def preserve_native_reproducer_renderer(self, identity):
        """Archive the exact renderer source for a preexisting immutable record."""
        row = self.db.execute(
            'SELECT payload FROM native_reproducers WHERE id=?',
            (identity,)).fetchone()
        need(row is not None and
             hashlib.sha256(row['payload'].encode()).hexdigest() == identity,
             'Cannot preserve renderer for an unknown or changed reproducer')
        record = json.loads(row['payload'])
        generator = record['generator']
        source = Path(generator['path'])
        need(source.is_file() and not source.is_symlink() and
             sha(source) == generator['sha256'],
             'Recorded renderer source has already changed')
        return self._store_reproducer_asset('renderer', source.read_bytes())

    def preserve_native_reproducer_parser(self, identity):
        """Archive the parser import closure for a preexisting reproducer."""
        row = self.db.execute(
            'SELECT payload FROM native_reproducers WHERE id=?',
            (identity,)).fetchone()
        need(row is not None and
             hashlib.sha256(row['payload'].encode()).hexdigest() == identity,
             'Cannot preserve parser for an unknown or changed reproducer')
        record = json.loads(row['payload'])
        search = Path(record['assets']['search-result']['path'])
        need(search.is_file() and not search.is_symlink() and
             sha(search) == record['assets']['search-result']['sha256'],
             'Recorded search result changed')
        parser_sha256 = json.loads(search.read_bytes())[
            'reproducer_runtime']['trace_parser_sha256']
        bound = self.db.execute(
            'SELECT binding_id,payload FROM native_reproducer_toolchains '
            'WHERE reproducer_id=?', (identity,)).fetchone()
        if bound is not None:
            need(hashlib.sha256(bound['payload'].encode()).hexdigest() ==
                 bound['binding_id'],
                 'Immutable parser binding differs from its hash')
            reference = json.loads(bound['payload'])
            bundle_path = self._reproducer_asset_path(
                'parser-bundle', reference['bundle_sha256'])
            need(reference.get('reproducer_id') == identity and
                 reference.get('parser_sha256') == parser_sha256 and
                 reference.get('bundle_path') == str(bundle_path) and
                 bundle_path.is_file() and sha(bundle_path) ==
                 reference['bundle_sha256'],
                 'Immutable parser binding or bundle changed')
        else:
            # First migration binds the live hash-matching parser and current
            # helper closure; an existing exported file cannot choose them.
            bundle_path = self._archive_parser_bundle(parser_sha256)
        self._bind_parser_bundle(identity, parser_sha256, bundle_path)
        return bundle_path

    def export_native_reproducer(self, identity):
        """Publish the immutable SQLite payload as a portable JSON artifact."""
        row = self.db.execute(
            'SELECT payload FROM native_reproducers WHERE id=?',
            (identity,)).fetchone()
        need(row is not None and
             hashlib.sha256(row['payload'].encode()).hexdigest() == identity,
             'Cannot export an unknown or changed native reproducer')
        directory = self.directory/'native-reproducer-records'
        directory.mkdir(parents=True, exist_ok=True)
        need(not directory.is_symlink(),
             'Native reproducer record directory is a symlink')
        path = directory/(identity+'.json')
        expected = (row['payload']+'\n').encode()
        try:
            with path.open('xb') as stream:
                stream.write(expected)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            pass
        need(path.is_file() and not path.is_symlink() and
             path.read_bytes() == expected,
             'Exported native reproducer record differs from SQLite')
        return path

    def _portable_catalog_record(self, subdirectory, identity):
        """Read a canonical, hash-named JSON export without trusting SQLite."""
        need(type(identity) is str and re.fullmatch(r'[0-9a-f]{64}', identity),
             'Invalid portable catalog identity')
        path = self.directory/subdirectory/(identity+'.json')
        need(path.is_file() and not path.is_symlink(),
             'Portable catalog export is missing: '+str(path))
        raw = path.read_bytes()
        need(raw.endswith(b'\n'), 'Portable catalog export lacks final newline')
        payload = raw[:-1].decode('utf-8')
        record = json.loads(payload)
        need(packed(record) == payload and
             hashlib.sha256(payload.encode()).hexdigest() == identity,
             'Portable catalog export has a noncanonical or changed identity')
        return record, payload

    def _observation_file_descriptors(self, receipt):
        observation = receipt['observation']
        entries = [observation['stdout'], observation['stderr'],
                   *observation['trace_files']]
        if observation.get('debugger') is not None:
            entries.append(observation['debugger']['log'])
        files = {}
        for entry in entries:
            name = entry['file']
            need(type(name) is str and name not in ('', '.', '..') and
                 Path(name).name == name and name not in files and
                 type(entry.get('bytes')) is int and entry['bytes'] >= 0 and
                 type(entry.get('sha256')) is str and
                 re.fullmatch(r'[0-9a-f]{64}', entry['sha256']),
                 'Native receipt has an unsafe or duplicate output file')
            files[name] = entry
        return files

    def export_native_observation_assets(self, receipt_id):
        """Package receipt-pinned trace/output bytes in a UTF-8 JSON export."""
        receipt_path = self.directory/'native-observations'/receipt_id/'receipt.json'
        need(type(receipt_id) is str and
             re.fullmatch(r'[0-9a-f]{32}', receipt_id) and
             receipt_path.is_file() and not receipt_path.is_symlink(),
             'Native observation receipt is missing')
        receipt = json.loads(receipt_path.read_bytes())
        need(receipt['id'] == receipt_id,
             'Native observation receipt ID differs')
        from native_signal_replay import verify_receipt
        verify_receipt(receipt_path, sha(receipt_path))
        files = self._observation_file_descriptors(receipt)
        entries = []
        for name, description in sorted(files.items()):
            source = receipt_path.parent/name
            need(source.is_file() and not source.is_symlink() and
                 source.stat().st_size == description['bytes'] and
                 sha(source) == description['sha256'],
                 'Native observation output differs from receipt: '+name)
            entries.append(dict(name=name, bytes=description['bytes'],
                sha256=description['sha256'],
                base64=base64.b64encode(source.read_bytes()).decode('ascii')))
        artifact = dict(schema=1, kind='native-observation-byte-assets',
                        receipt_id=receipt_id,
                        receipt_sha256=sha(receipt_path), files=entries)
        directory = self.directory/'native-observation-assets'
        directory.mkdir(parents=True, exist_ok=True)
        need(not directory.is_symlink(),
             'Native observation asset directory is a symlink')
        path = directory/(receipt_id+'.json')
        expected = (packed(artifact)+'\n').encode()
        try:
            with path.open('xb') as stream:
                stream.write(expected)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            pass
        need(path.is_file() and not path.is_symlink() and
             path.read_bytes() == expected,
             'Portable native observation byte assets changed')
        return path

    def _restore_native_observation_assets(self, receipt_id, receipt_sha256):
        need(type(receipt_id) is str and
             re.fullmatch(r'[0-9a-f]{32}', receipt_id) and
             type(receipt_sha256) is str and
             re.fullmatch(r'[0-9a-f]{64}', receipt_sha256),
             'Invalid portable native observation identity')
        receipt_path = self.directory/'native-observations'/receipt_id/'receipt.json'
        need(receipt_path.is_file() and not receipt_path.is_symlink() and
             sha(receipt_path) == receipt_sha256,
             'Portable native observation receipt differs')
        receipt = json.loads(receipt_path.read_bytes())
        need(receipt['id'] == receipt_id,
             'Portable native observation receipt ID differs')
        files = self._observation_file_descriptors(receipt)
        export = self.directory/'native-observation-assets'/(receipt_id+'.json')
        need(export.is_file() and not export.is_symlink(),
             'Portable native observation byte assets are missing')
        raw = export.read_bytes()
        artifact = json.loads(raw)
        need(raw == (packed(artifact)+'\n').encode() and
             artifact.get('schema') == 1 and
             artifact.get('kind') == 'native-observation-byte-assets' and
             artifact.get('receipt_id') == receipt_id and
             artifact.get('receipt_sha256') == receipt_sha256 and
             type(artifact.get('files')) is list and
             [row.get('name') for row in artifact['files']] == sorted(files),
             'Portable native observation byte assets differ from receipt')
        for row in artifact['files']:
            name = row['name']
            expected = files[name]
            contents = base64.b64decode(row['base64'], validate=True)
            need(row['bytes'] == expected['bytes'] == len(contents) and
                 row['sha256'] == expected['sha256'] ==
                 hashlib.sha256(contents).hexdigest(),
                 'Portable observation output hash differs: '+name)
            path = receipt_path.parent/name
            try:
                with path.open('xb') as stream:
                    stream.write(contents)
                    stream.flush()
                    os.fsync(stream.fileno())
            except FileExistsError:
                pass
            need(path.is_file() and not path.is_symlink() and
                 path.read_bytes() == contents,
                 'Restored observation output differs: '+name)
        from native_signal_replay import verify_receipt
        verify_receipt(receipt_path, receipt_sha256)

    def import_native_reproducer(self, identity):
        """Rebuild checked SQLite indexes from portable, pinned JSON evidence."""
        record, payload = self._portable_catalog_record(
            'native-reproducer-records', identity)
        need(record.get('schema') == 1 and
             record.get('kind') == 'generated-native-sigsegv-reproducer',
             'Portable record is not a native reproducer')
        result_asset = record['assets']['search-result']
        result_path = self._reproducer_asset_path(
            'search-result', result_asset['sha256'])
        need(result_asset['path'] == str(result_path) and
             result_path.is_file() and not result_path.is_symlink() and
             sha(result_path) == result_asset['sha256'],
             'Portable reproducer search result is missing or changed')
        result = json.loads(result_path.read_bytes())
        self._restore_native_observation_assets(
            record['native']['observation_id'],
            record['native']['receipt_sha256'])
        core_id = record['formal']['native_core_link_id']
        need(result.get('native_core_link_id') == core_id,
             'Portable reproducer and search result name different Core links')
        if core_id is not None:
            output = Path(result['output'])
            spec_path = output/'native-core-link-spec.json'
            need(output.is_absolute() and spec_path.is_file() and
                 not spec_path.is_symlink(),
                 'Portable native-Core link specification is missing')
            spec = json.loads(spec_path.read_bytes())
            need(spec.get('receipt') == result['receipt']['receipt'] and
                 spec.get('receipt_sha256') ==
                 result['receipt']['receipt_sha256'],
                 'Native-Core link specification names another receipt')
            need(self.add_native_core_link(**spec) == core_id,
                 'Rebuilt native-Core link differs from portable reproducer')
        with self.db:
            existing = self.db.execute(
                'SELECT payload FROM native_reproducers WHERE id=?',
                (identity,)).fetchone()
            if existing is None:
                self.db.execute('INSERT INTO native_reproducers VALUES(?,?,?,?,?,?,?)',
                    (identity, record['native']['observation_id'],
                     record['target'], record['assets']['script']['sha256'],
                     core_id, 0, payload))
            else:
                need(existing['payload'] == payload,
                     'SQLite reproducer differs from portable export')
        parser_sha256 = result['reproducer_runtime']['trace_parser_sha256']
        reference_path = self.directory/'native-reproducer-toolchains'/(
            identity+'.json')
        need(reference_path.is_file() and not reference_path.is_symlink(),
             'Portable parser binding is missing')
        reference = json.loads(reference_path.read_bytes())
        bundle = self._reproducer_asset_path(
            'parser-bundle', reference['bundle_sha256'])
        need(reference.get('reproducer_id') == identity and
             reference.get('parser_sha256') == parser_sha256 and
             reference.get('bundle_path') == str(bundle) and
             bundle.is_file() and sha(bundle) == reference['bundle_sha256'],
             'Portable parser binding or bundle differs')
        self._bind_parser_bundle(identity, parser_sha256, bundle)
        self.read_native_reproducer(identity)

        receipt = Path(record['native']['receipt'])
        saved = json.loads(receipt.read_bytes())
        observation = saved['observation']
        summary = dict(id=saved['id'], receipt=str(receipt),
            receipt_sha256=record['native']['receipt_sha256'],
            target=saved['recipe']['target'],
            expected_signal=observation['expected_signal'],
            expected_observed=observation['expected_observed'],
            signal_deliveries=observation['signal_deliveries'],
            signal_terminations=observation['signal_terminations'],
            primary_sites=observation['primary_sites'],
            primary_site=observation['primary_site'],
            crash_instruction=observation['debugger'],
            same_native_site_observed=observation['same_native_site_observed'],
            external_state_complete=observation['external_state_complete'],
            external_dependency_status=observation['external_dependency_status'],
            timed_out=observation['timed_out'],
            catalog_id=(saved['linked_certificate']['catalog_id']
                        if saved['linked_certificate'] else None))
        site_keys = self.add_native_instruction_sites(summary)

        formal_ids = []
        formal_dir = self.directory/'native-reproducer-formal-links'
        if formal_dir.is_dir():
            for path in sorted(formal_dir.glob('*.json')):
                link_id = path.stem
                link, link_payload = self._portable_catalog_record(
                    'native-reproducer-formal-links', link_id)
                if link.get('reproducer_id') != identity:
                    continue
                source = Path(link['original_obligation_path'])
                stored = self.directory/'native-reproducer-obligations'/(
                    link['obligation_id']+'.json')
                need(link['obligation_path'] == str(stored) and
                     source.is_file() and not source.is_symlink() and
                     sha(source) == link['obligation_sha256'],
                     'Portable Lean obligation source is missing or changed')
                stored.parent.mkdir(parents=True, exist_ok=True)
                raw = source.read_bytes()
                try:
                    with stored.open('xb') as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(stream.fileno())
                except FileExistsError:
                    pass
                need(stored.is_file() and not stored.is_symlink() and
                     stored.read_bytes() == raw,
                     'Restored Lean obligation differs from portable source')
                with self.db:
                    existing = self.db.execute(
                        'SELECT payload FROM native_reproducer_formal_links '
                        'WHERE id=?', (link_id,)).fetchone()
                    if existing is None:
                        self.db.execute(
                            'INSERT INTO native_reproducer_formal_links '
                            'VALUES(?,?,?,?,?)',
                            (link_id, identity, link['obligation_id'], 0,
                             link_payload))
                    else:
                        need(existing['payload'] == link_payload,
                             'SQLite formal link differs from portable export')
                self.read_native_reproducer_formal_link(link_id)
                formal_ids.append(link_id)
        return dict(id=identity, native_core_link_id=core_id,
                    instruction_site_keys=site_keys,
                    formal_link_ids=formal_ids, status='imported_and_verified')

    def read_native_reproducer(self, identity):
        row = self.db.execute('SELECT * FROM native_reproducers WHERE id=?',
                              (identity,)).fetchone()
        need(row is not None, 'Unknown native reproducer: '+str(identity))
        need(hashlib.sha256(row['payload'].encode()).hexdigest() == identity,
             'Native reproducer record hash differs')
        exported = self.directory/'native-reproducer-records'/(identity+'.json')
        need(exported.is_file() and not exported.is_symlink() and
             exported.read_bytes() == (row['payload']+'\n').encode(),
             'Native reproducer exported record is missing or changed')
        record = json.loads(row['payload'])
        renderer_digest = record['generator']['sha256']
        renderer_asset = self._reproducer_asset_path('renderer', renderer_digest)
        need(renderer_asset.is_file() and not renderer_asset.is_symlink() and
             sha(renderer_asset) == renderer_digest,
             'Versioned native reproducer renderer is missing or changed')
        need(record.get('schema') == 1 and
             record.get('kind') == 'generated-native-sigsegv-reproducer' and
             record.get('target') == row['target'] and
             record.get('native', {}).get('observation_id') ==
             row['observation_id'] and
             record.get('assets', {}).get('script', {}).get('sha256') ==
             row['script_sha256'] and
             record.get('formal', {}).get('native_core_link_id') ==
             row['core_link_id'],
             'Native reproducer table and payload differ')
        contents, origins = {}, {}
        for role in ('profile', 'search-result', 'script'):
            asset = record['assets'][role]
            path = Path(asset['path'])
            need(path == self._reproducer_asset_path(role, asset['sha256']) and
                 path.is_file() and not path.is_symlink() and
                 path.stat().st_size == asset['bytes'] and
                 sha(path) == asset['sha256'],
                 'Catalog reproducer asset is missing or changed: '+role)
            contents[role] = path.read_bytes()
            origins[role] = asset['source_path']
        current_source = Path(record['generator']['path'])
        current_renderer = (sha(current_source) if current_source.is_file() and
                            not current_source.is_symlink() else None)
        parser_sha256 = json.loads(contents['search-result'])[
            'reproducer_runtime']['trace_parser_sha256']
        _, parser_drift = self._load_parser_bundle(identity, parser_sha256)
        historical_renderer = (
            renderer_digest if current_renderer != renderer_digest else None)
        need(self._native_reproducer_record(contents, origins,
             row['core_link_id'],
             record['formal']['exact_cabs_call_witness_id'],
             record['formal']['core_cabs_bridge_id'],
             historical_renderer_sha256=historical_renderer,
             historical_parser_sha256=(parser_sha256 if parser_drift else None),
             historical_reproducer_id=identity)
             == record,
             'Native reproducer provenance chain differs')
        need(sha(Path('/usr/bin/bash')) == record['replay']['bash_sha256'],
             'Native reproducer Bash interpreter changed')
        latest = self.db.execute(
            'SELECT id FROM native_reproducer_formal_links '
            'WHERE reproducer_id=? ORDER BY created_ns DESC,id DESC LIMIT 1',
            (identity,)).fetchone()
        return dict(id=identity, **record,
                    latest_formal_link_id=latest['id'] if latest else None)

    def list_native_reproducers(self, target=None, observation_id=None):
        where, values = [], []
        if target is not None:
            where.append('target=?')
            values.append(target)
        if observation_id is not None:
            where.append('observation_id=?')
            values.append(observation_id)
        sql = ('SELECT id,target,observation_id,script_sha256,core_link_id,created_ns '
               'FROM native_reproducers')
        if where:
            sql += ' WHERE '+' AND '.join(where)
        for row in self.db.execute(sql+' ORDER BY created_ns,id', values):
            yield dict(row)

    def _checked_reproducer_formal_obligation(self, reproducer_id, path):
        """Replay the Lean obligation and compare its exact native dependencies."""
        path = Path(path)
        need(path.is_absolute() and path.is_file() and not path.is_symlink(),
             'Native reproducer formal obligation is not an absolute regular file')
        saved = json.loads(path.read_bytes())
        need(type(saved) is dict and saved.get('schema') == 1 and
             saved.get('kind') == 'scp-stack-reservation-proof-obligation' and
             type(saved.get('id')) is str and
             re.fullmatch(r'[0-9a-f]{64}', saved['id']) and
             path.name == saved['id']+'.json',
             'Native reproducer Lean obligation has an invalid identity')
        command = [sys.executable,
                   str(WORKSPACE/'search/recursion/emit_stack_obligation.py'),
                   '--verify', str(path)]
        checked = subprocess.run(command, cwd=WORKSPACE, capture_output=True,
                                 text=True, timeout=300)
        need(checked.returncode == 0,
             'Lean obligation replay failed: '+
             (checked.stdout+checked.stderr)[-2000:])
        response = json.loads(checked.stdout.strip().splitlines()[-1])
        digest = sha(path)
        need(response.get('status') == 'verified' and
             response.get('id') == saved['id'] and
             response.get('sha256') == digest,
             'Lean obligation verifier returned another artifact')
        reproducer = self.read_native_reproducer(reproducer_id)
        witness = saved['witness']['reproducer']
        native = saved['witness']['native_receipt']
        need(witness['catalog_id'] == reproducer_id and
             witness['sha256'] == reproducer['assets']['script']['sha256'] and
             witness['profile_sha256'] ==
             reproducer['assets']['profile']['sha256'] and
             witness['search_result_sha256'] ==
             reproducer['assets']['search-result']['sha256'] and
             witness['receipt_id'] == reproducer['native']['observation_id'] and
             witness['input_sha256'] == reproducer['native']['stdin']['sha256'] and
             witness['exact_cabs_call_witness_id'] ==
             reproducer['formal']['exact_cabs_call_witness_id'] and
             witness['core_cabs_bridge_id'] ==
             reproducer['formal']['core_cabs_bridge_id'] and
             native['id'] == reproducer['native']['observation_id'] and
             native['sha256'] == reproducer['native']['receipt_sha256'] and
             saved['named_sink_core_site_sha256'] ==
             reproducer['formal']['archived_core_candidate']['sha256'] and
             saved['archive_manifest_sha256'] ==
             reproducer['formal']['archived_core_candidate']
                 ['archive_manifest_sha256'] and
             saved['formal']['status'] == 'kernel-checked' and
             type(saved['unproved_premises']) is list and
             len(saved['unproved_premises']) > 0,
             'Lean obligation and immutable native reproducer differ')
        return saved, digest

    def add_native_reproducer_formal_link(self, *, reproducer_id,
                                         obligation):
        """Append a checked Lean theorem/obligation without changing the witness."""
        source = Path(obligation)
        saved, digest = self._checked_reproducer_formal_obligation(
            reproducer_id, source)
        directory = self.directory/'native-reproducer-obligations'
        directory.mkdir(parents=True, exist_ok=True)
        need(not directory.is_symlink(),
             'Native reproducer obligation directory is a symlink')
        stored = directory/(saved['id']+'.json')
        raw = source.read_bytes()
        try:
            with stored.open('xb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            pass
        need(stored.is_file() and not stored.is_symlink() and
             stored.read_bytes() == raw,
             'Stored Lean obligation differs from checked source')
        record = dict(schema=1, kind='native-reproducer-lean-obligation-link',
            reproducer_id=reproducer_id, obligation_id=saved['id'],
            obligation_path=str(stored), obligation_sha256=digest,
            original_obligation_path=str(source),
            kernel_checked_theorems=saved['formal']['theorems'],
            theorem_claim_scope=saved['formal']['claim_scope'],
            unproved_premises=saved['unproved_premises'],
            scope='Checked abstract stack theorem and exact native reproducer '
                  'are linked; native SIGSEGV is observed, not derived by Lean')
        payload = packed(record)
        identity = hashlib.sha256(payload.encode()).hexdigest()
        with self.db:
            existing = self.db.execute(
                'SELECT payload FROM native_reproducer_formal_links WHERE id=?',
                (identity,)).fetchone()
            if existing is None:
                self.db.execute(
                    'INSERT INTO native_reproducer_formal_links VALUES(?,?,?,?,?)',
                    (identity, reproducer_id, saved['id'], time.time_ns(),
                     payload))
            else:
                need(existing['payload'] == payload,
                     'Native reproducer formal link id changed')
        self.export_native_reproducer_formal_link(identity)
        return identity

    def export_native_reproducer_formal_link(self, identity):
        row = self.db.execute(
            'SELECT payload FROM native_reproducer_formal_links WHERE id=?',
            (identity,)).fetchone()
        need(row is not None and
             hashlib.sha256(row['payload'].encode()).hexdigest() == identity,
             'Cannot export an unknown or changed formal link')
        directory = self.directory/'native-reproducer-formal-links'
        directory.mkdir(parents=True, exist_ok=True)
        need(not directory.is_symlink(), 'Formal link directory is a symlink')
        path = directory/(identity+'.json')
        expected = (row['payload']+'\n').encode()
        try:
            with path.open('xb') as stream:
                stream.write(expected)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            pass
        need(path.is_file() and not path.is_symlink() and
             path.read_bytes() == expected,
             'Exported formal link differs from SQLite')
        return path

    def read_native_reproducer_formal_link(self, identity):
        row = self.db.execute(
            'SELECT * FROM native_reproducer_formal_links WHERE id=?',
            (identity,)).fetchone()
        need(row is not None, 'Unknown native reproducer formal link: '+str(identity))
        need(hashlib.sha256(row['payload'].encode()).hexdigest() == identity,
             'Native reproducer formal link hash differs')
        exported = self.directory/'native-reproducer-formal-links'/(
            identity+'.json')
        need(exported.is_file() and not exported.is_symlink() and
             exported.read_bytes() == (row['payload']+'\n').encode(),
             'Native reproducer formal link export is missing or changed')
        record = json.loads(row['payload'])
        need(record['reproducer_id'] == row['reproducer_id'] and
             record['obligation_id'] == row['obligation_id'] and
             Path(record['obligation_path']) ==
             self.directory/'native-reproducer-obligations'/(
                 row['obligation_id']+'.json') and
             sha(Path(record['obligation_path'])) ==
             record['obligation_sha256'],
             'Native reproducer formal link assets differ')
        obligation, digest = self._checked_reproducer_formal_obligation(
            record['reproducer_id'], record['obligation_path'])
        need(obligation['id'] == row['obligation_id'] and
             digest == record['obligation_sha256'] and
             obligation['formal']['theorems'] ==
             record['kernel_checked_theorems'] and
             obligation['formal']['claim_scope'] ==
             record['theorem_claim_scope'] and
             obligation['unproved_premises'] == record['unproved_premises'],
             'Lean obligation and formal link differ')
        return dict(id=identity, **record)

    def list_native_reproducer_formal_links(self, reproducer_id=None):
        sql = ('SELECT id,reproducer_id,obligation_id,created_ns '
               'FROM native_reproducer_formal_links')
        args = ()
        if reproducer_id is not None:
            sql += ' WHERE reproducer_id=?'
            args = (reproducer_id,)
        for row in self.db.execute(sql+' ORDER BY created_ns,id', args):
            yield dict(row)

    def store_native_stack_asset(self, role, contents):
        """Preserve one byte-for-byte input, debugger, or Lean proof asset."""
        from native_stack_certificate import ASSET_ROLES
        need(role in ASSET_ROLES and type(contents) is bytes,
             'Invalid native stack certificate asset')
        digest = hashlib.sha256(contents).hexdigest()
        directory = self.directory/'native-stack-assets'
        directory.mkdir(parents=True,exist_ok=True)
        need(not directory.is_symlink(),
             'Native stack asset directory is a symlink')
        path = directory/(digest+'-'+role+'.bin')
        try:
            with path.open('xb') as stream:
                stream.write(contents)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            pass
        need(path.is_file() and not path.is_symlink() and
             path.read_bytes() == contents,
             'Native stack asset changed after admission')
        return dict(role=role,path=str(path),sha256=digest,bytes=len(contents))

    def read_native_stack_asset(self, descriptor):
        from native_stack_certificate import ASSET_ROLES
        need(type(descriptor) is dict and
             set(descriptor) == {'role','path','sha256','bytes'} and
             descriptor['role'] in ASSET_ROLES and
             type(descriptor['bytes']) is int and
             descriptor['bytes'] >= 0 and
             type(descriptor['sha256']) is str and
             re.fullmatch(r'[0-9a-f]{64}',descriptor['sha256']),
             'Invalid saved native stack asset descriptor')
        expected = self.directory/'native-stack-assets'/(
            descriptor['sha256']+'-'+descriptor['role']+'.bin')
        path = Path(descriptor['path'])
        need(path == expected and path.is_file() and not path.is_symlink(),
             'Native stack asset path changed')
        raw = path.read_bytes()
        need(len(raw) == descriptor['bytes'] and
             hashlib.sha256(raw).hexdigest() == descriptor['sha256'],
             'Native stack asset bytes changed')
        return raw

    def add_native_stack_certificate(self, seed_id, *, seed_dir=None,
                                     archive_dir=None,timeout_seconds=90):
        """Capture from a verified seed; callers cannot supply debugger evidence."""
        from native_stack_certificate import (ASSET_ROLES, _capture_verified_seed,
            verify_catalog_certificate, DEFAULT_STORE, DEFAULT_ARCHIVE)
        need(type(seed_id) is str and re.fullmatch(r'[0-9a-f]{64}',seed_id),
             'Native stack admission requires a verified seed ID')
        record, raw_assets = _capture_verified_seed(seed_id,
            catalog_dir=self.directory,seed_dir=seed_dir or DEFAULT_STORE,
            archive_dir=archive_dir or DEFAULT_ARCHIVE,
            timeout_seconds=timeout_seconds)
        need(record['seed_id'] == seed_id and
             set(raw_assets) == set(ASSET_ROLES),
             'Trusted native stack collector returned another seed')
        stored = {role:self.store_native_stack_asset(role,raw_assets[role])
                  for role in ASSET_ROLES}
        admitted = dict(record,assets=stored)
        verify_catalog_certificate(self,admitted,
            seed_dir=seed_dir or DEFAULT_STORE,
            archive_dir=archive_dir or DEFAULT_ARCHIVE)
        payload = packed(admitted)
        identity = hashlib.sha256(payload.encode()).hexdigest()
        with self.db:
            prior = self.db.execute(
                'SELECT payload FROM native_stack_certificates WHERE id=?',
                (identity,)).fetchone()
            if prior is None:
                self.db.execute(
                    'INSERT INTO native_stack_certificates VALUES(?,?,?,?,?)',
                    (identity,admitted['reproducer_id'],admitted['seed_id'],
                     time.time_ns(),payload))
            else:
                need(prior['payload'] == payload,
                     'Native stack certificate identity collision')
        exported = self.directory/'native-stack-certificates'
        exported.mkdir(parents=True,exist_ok=True)
        need(not exported.is_symlink(),
             'Native stack certificate directory is a symlink')
        path = exported/(identity+'.json')
        expected = (payload+'\n').encode()
        try:
            with path.open('xb') as stream:
                stream.write(expected)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            pass
        need(path.is_file() and not path.is_symlink() and
             path.read_bytes() == expected,
             'Native stack certificate export changed')
        self.read_native_stack_certificate(identity)
        return identity

    def read_native_stack_certificate(self, identity):
        """Read immutable evidence without pretending to recompile old Lean."""
        row = self.db.execute(
            'SELECT * FROM native_stack_certificates WHERE id=?',
            (identity,)).fetchone()
        need(row is not None and
             hashlib.sha256(row['payload'].encode()).hexdigest() == identity,
             'Unknown or changed native stack certificate')
        record = json.loads(row['payload'])
        from native_stack_certificate import ASSET_ROLES
        need(record['reproducer_id'] == row['reproducer_id'] and
             record['seed_id'] == row['seed_id'] and
             set(record['assets']) == set(ASSET_ROLES),
             'Native stack certificate relation changed')
        for role in ASSET_ROLES:
            need(record['assets'][role]['role'] == role,
                 'Native stack certificate asset role changed')
            self.read_native_stack_asset(record['assets'][role])
        exported = self.directory/'native-stack-certificates'/(
            identity+'.json')
        need(exported.is_file() and not exported.is_symlink() and
             exported.read_bytes() == (row['payload']+'\n').encode(),
             'Native stack certificate export changed')
        return dict(id=identity,created_ns=row['created_ns'],
                    evidence_status='hash-verified',**record)

    def replay_native_stack_certificate(self, identity):
        """Freshly recompile the exact saved theorem and recheck native binding."""
        from native_stack_certificate import verify_catalog_certificate
        record = self.read_native_stack_certificate(identity)
        return dict(id=identity,**verify_catalog_certificate(
            self,record,require_current_source=False))

    def list_native_stack_certificates(self, seed_id=None):
        sql = ('SELECT id,reproducer_id,seed_id,created_ns '
               'FROM native_stack_certificates')
        args = ()
        if seed_id is not None:
            sql += ' WHERE seed_id=?'
            args = (seed_id,)
        for row in self.db.execute(sql+' ORDER BY created_ns,id',args):
            yield dict(row)

    def replay_native_reproducer(self, identity, timeout_seconds=120):
        """Rerun a checked generated script and require its fresh fatal marker."""
        record = self.read_native_reproducer(identity)
        need(type(timeout_seconds) in (int, float) and timeout_seconds > 0,
             'Native reproducer timeout must be positive')
        parser_sha256 = json.loads(Path(
            record['assets']['search-result']['path']).read_bytes())[
            'reproducer_runtime']['trace_parser_sha256']
        bundle, parser_drift = self._load_parser_bundle(identity, parser_sha256)
        command = (self._parser_bundle_command(bundle, record['replay']['command'])
                   if parser_drift else record['replay']['command'])
        process = subprocess.Popen(command,
            cwd=WORKSPACE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True, text=True)
        try:
            stdout, stderr = process.communicate(timeout=timeout_seconds)
        except BaseException as error:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            if isinstance(error, subprocess.TimeoutExpired):
                raise RuntimeError('Native reproducer timed out') from error
            raise
        need(process.returncode == 0,
             'Native reproducer failed: '+stderr[-2000:])
        marker = record['replay']['success_marker']
        rows = [line[len(marker):] for line in stdout.splitlines()
                if line.startswith(marker)]
        need(len(rows) == 1, 'Native reproducer emitted no unique success marker')
        fresh = json.loads(rows[0])
        need(type(fresh) is dict and
             fresh.get('target') == record['target'] and
             fresh.get('signal') == 'SIGSEGV' and
             type(fresh.get('pc')) is str and
             type(fresh.get('module_path')) is str and
             type(fresh.get('file_offset')) is str and
             type(fresh.get('stable_site_key')) is str and
             re.fullmatch(r'[0-9a-f]{64}', fresh['stable_site_key']),
             'Native reproducer marker is malformed')
        pinned_frames = fresh.get('pinned_frames')
        if pinned_frames is None:
            # The first immutable scp generator predates this marker field;
            # its checked recursive-frame count is executable-scoped.
            need(record['formal']['native_core_link_id'] is not None and
                 type(fresh.get('recursive_frames')) is int and
                 fresh['recursive_frames'] >= 2,
                 'Historical marker lacks a pinned OpenSSH frame witness')
        else:
            need(type(pinned_frames) is int and pinned_frames > 0,
                 'Fresh fault trace lacks a pinned OpenSSH executable frame')
        site_relation = ('cataloged_site' if fresh['stable_site_key'] in {
            site['stable_site_key'] for site in record['native']['fatal_sites']}
            else 'new_site')
        return dict(id=identity, status='fresh_sigsegv_reproduced',
                    observation_id=record['native']['observation_id'],
                    fresh_site=fresh, site_relation=site_relation)

    def enrich(self, identity, author, payload):
        need(isinstance(author, str) and author.strip(), 'Enrichment author is required')
        need(isinstance(payload, dict) and payload, 'Enrichment must be a nonempty object')
        with self.db:
            need(self.db.execute('SELECT 1 FROM discoveries WHERE id=?', (identity,)).fetchone(),
                 'Unknown catalog entry: '+identity)
            return self.db.execute('INSERT INTO enrichments(discovery,author,created_ns,payload) VALUES(?,?,?,?)',
                                   (identity,author,time.time_ns(),packed(payload))).lastrowid

    def list(self, signal=None):
        sql, args = 'SELECT id,signal,archive,created_ns FROM discoveries', ()
        if signal is not None:
            sql += ' WHERE signal=?'
            args = (signal,)
        for row in self.db.execute(sql+' ORDER BY created_ns,id', args):
            yield dict(row)

    def replay(self, identity):
        """Recheck in a fresh Lean worker; the originating job is unnecessary."""
        from core_index import Index
        from signal_search import Worker
        record = self.read(identity)['evidence']
        saved = record['identity']
        query = json.loads(saved['query'])
        index = Index()
        try:
            need(index.archive.manifest_sha256 == saved['archive_manifest'], 'Catalog archive changed')
            with tempfile.TemporaryDirectory(prefix='openssh-catalog-replay-') as directory:
                with Worker(directory, query.get('modules', ())) as worker:
                    need(worker.build == json.loads(saved['build']), 'Catalog prover build changed')
                    need(worker.imports == json.loads(saved['imports']), 'Catalog query imports changed')
                    for fragment in json.loads(saved['fragments']):
                        metadata = worker.load(index, fragment['target'], fragment['section'],
                                               fragment['ordinal'], fragment['alias'])
                        need(dict(alias=fragment['alias'], **metadata) == fragment,
                             'Catalog fragment identity changed')
                    certificate = record['certificate']
                    result = worker.request(dict(op='verify', goal=query['goal'],
                        proof=certificate['proof'], declarations=certificate['declarations'], quantum=0))
                    need(result['status'] == 'proved', 'Catalog certificate failed: '+str(result))
                    need(result['proposition'] == certificate['proposition'], 'Replay proposition changed')
                    return dict(id=identity, status='verified', kind=record['kind'],
                                axioms=result['axioms'], elapsed_ns=result['elapsed_ns'])
        finally:
            index.close()

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', type=Path, default=DEFAULT)
    commands = parser.add_subparsers(dest='command', required=True)
    listing = commands.add_parser('list')
    listing.add_argument('--signal')
    native_listing = commands.add_parser('native-sites')
    native_listing.add_argument('--signal')
    native_listing.add_argument('--stable-site-key')
    native_detail = commands.add_parser('native-site-observations')
    native_detail.add_argument('stable_site_key')
    native_detail.add_argument('signal')
    native_core_listing = commands.add_parser('native-core-links')
    native_core_listing.add_argument('--observation-id')
    native_core_listing.add_argument('--core-site-sha256')
    native_core_listing.add_argument('--include-history', action='store_true')
    native_core_detail = commands.add_parser('native-core-link')
    native_core_detail.add_argument('id')
    native_core_add = commands.add_parser('link-native-core')
    native_core_add.add_argument('--file', type=Path, required=True,
                                 help='JSON arguments for add_native_core_link')
    reproducer_listing = commands.add_parser('native-reproducers')
    reproducer_listing.add_argument('--target')
    reproducer_listing.add_argument('--observation-id')
    reproducer_add = commands.add_parser('add-native-reproducer')
    reproducer_add.add_argument('--profile', type=Path, required=True)
    reproducer_add.add_argument('--search-result', type=Path, required=True)
    reproducer_add.add_argument('--script', type=Path, required=True)
    reproducer_add.add_argument('--native-core-link-id')
    reproducer_add.add_argument('--source-call-witness-id')
    reproducer_add.add_argument('--core-cabs-bridge-id')
    formal_listing = commands.add_parser('native-reproducer-formal-links')
    formal_listing.add_argument('--reproducer-id')
    formal_add = commands.add_parser('link-native-reproducer-formal')
    formal_add.add_argument('--reproducer-id', required=True)
    formal_add.add_argument('--obligation', type=Path, required=True)
    commands.add_parser('native-reproducer-formal-link').add_argument('id')
    for command in ('native-reproducer', 'verify-native-reproducer',
                    'replay-native-reproducer',
                    'preserve-native-reproducer-parser',
                    'import-native-reproducer'):
        commands.add_parser(command).add_argument('id')
    commands.add_parser('export-native-observation-assets').add_argument('id')
    for command in ('show', 'replay', 'enrich'):
        sub = commands.add_parser(command)
        sub.add_argument('id')
        if command == 'enrich':
            sub.add_argument('--author', required=True)
            sub.add_argument('--file', type=Path, required=True)
    args = parser.parse_args()
    with Catalog(args.catalog) as catalog:
        if args.command == 'list':
            for record in catalog.list(args.signal):
                print(packed(record))
        elif args.command == 'native-sites':
            for record in catalog.list_native_instruction_sites(
                    args.signal, args.stable_site_key):
                print(packed(record))
        elif args.command == 'native-site-observations':
            for record in catalog.native_instruction_site_observations(
                    args.stable_site_key, args.signal):
                print(packed(record))
        elif args.command == 'native-core-links':
            for record in catalog.list_native_core_links(
                    args.observation_id, args.core_site_sha256,
                    args.include_history):
                print(packed(record))
        elif args.command == 'native-core-link':
            print(packed(catalog.read_native_core_link(args.id)))
        elif args.command == 'link-native-core':
            spec = json.loads(args.file.read_bytes())
            print(packed(dict(id=catalog.add_native_core_link(**spec))))
        elif args.command == 'native-reproducers':
            for record in catalog.list_native_reproducers(
                    args.target, args.observation_id):
                print(packed(record))
        elif args.command == 'add-native-reproducer':
            print(packed(dict(id=catalog.add_native_reproducer(
                profile=args.profile.resolve(strict=True),
                search_result=args.search_result.resolve(strict=True),
                script=args.script.resolve(strict=True),
                native_core_link_id=args.native_core_link_id,
                source_call_witness_id=args.source_call_witness_id,
                core_cabs_bridge_id=args.core_cabs_bridge_id))))
        elif args.command == 'native-reproducer':
            print(packed(catalog.read_native_reproducer(args.id)))
        elif args.command == 'verify-native-reproducer':
            record = catalog.read_native_reproducer(args.id)
            print(packed(dict(id=record['id'], status='verified',
                              target=record['target'],
                              command=record['replay']['command'])))
        elif args.command == 'replay-native-reproducer':
            print(packed(catalog.replay_native_reproducer(args.id)))
        elif args.command == 'preserve-native-reproducer-parser':
            path = catalog.preserve_native_reproducer_parser(args.id)
            print(packed(dict(id=args.id, parser_bundle=str(path),
                              sha256=sha(path))))
        elif args.command == 'import-native-reproducer':
            print(packed(catalog.import_native_reproducer(args.id)))
        elif args.command == 'export-native-observation-assets':
            path = catalog.export_native_observation_assets(args.id)
            print(packed(dict(id=args.id, path=str(path), sha256=sha(path))))
        elif args.command == 'native-reproducer-formal-links':
            for record in catalog.list_native_reproducer_formal_links(
                    args.reproducer_id):
                print(packed(record))
        elif args.command == 'link-native-reproducer-formal':
            print(packed(dict(id=catalog.add_native_reproducer_formal_link(
                reproducer_id=args.reproducer_id,
                obligation=args.obligation.resolve(strict=True)))))
        elif args.command == 'native-reproducer-formal-link':
            print(packed(catalog.read_native_reproducer_formal_link(args.id)))
        elif args.command == 'show':
            print(packed(catalog.read(args.id)))
        elif args.command == 'replay':
            print(packed(catalog.replay(args.id)))
        else:
            print(packed(dict(enrichment=catalog.enrich(args.id, args.author, json.loads(args.file.read_bytes())))))


if __name__ == '__main__':
    main()
