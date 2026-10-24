"""End-to-end generic fatal-signal catalog tests using a tiny native C fixture."""
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zlib

from common import sha
from native_frontier_catalog import (ingest_fatal_outcomes,
                                     retry_fatal_observation,
                                     _source_link_for_sites, _qualified_native_sites)
from native_input_search import NativeFrontier
from native_input_grammar import Grammar
from native_signal_replay import observe
from signal_catalog import Catalog


TARGETS = ('scp','sftp','sftp-server','ssh','ssh-add','ssh-agent','ssh-keygen',
           'ssh-keyscan','ssh-keysign','ssh-pkcs11-helper','ssh-sk-helper',
           'sshd','sshd-auth','sshd-session')


class FixtureArchive:
    manifest_sha256 = 'a'*64
    data = {'models': {name: {} for name in TARGETS},
            'openssh_commit': 'fixture-commit',
            'configuration_profile': {'fixture': True}}

    def __init__(self, _root):
        pass


class FrontierDatabaseUriTests(unittest.TestCase):
    def test_ingest_handles_literal_uri_characters(self):
        with tempfile.TemporaryDirectory(prefix='catalog-uri-',dir='/var/tmp') as directory:
            root = Path(directory)
            frontier = root/'frontier#?%41'
            frontier.mkdir()
            database = sqlite3.connect(frontier/'frontier.sqlite')
            database.execute('CREATE TABLE identity(key TEXT,value TEXT)')
            database.commit()
            database.close()

            class ReachedArchive(Exception):
                pass

            def stop_before_ingest(_archive_root):
                raise ReachedArchive()

            with self.assertRaises(ReachedArchive):
                ingest_fatal_outcomes(frontier,root/'catalog',
                                      archive_factory=stop_before_ingest)
            self.assertFalse((root/'frontier').exists())


class NativeFatalCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='native-fatal-catalog-', dir='/var/tmp')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.frontier = self.root/'frontier'
        self.catalog = self.root/'catalog'
        self.source = self.root/'abort.c'
        self.binary = self.root/'abort'
        self.source.write_text('#include <signal.h>\n'
                               'int main(void) { raise(SIGABRT); return 0; }\n')
        subprocess.run(['cc','-g','-O0','-o',str(self.binary),str(self.source)],
                       check=True)
        self.binary_digest = sha(self.binary)

    def resolve_binary(self, _archive, target):
        if sha(self.binary) != self.binary_digest:
            raise RuntimeError('Pinned native binary changed')
        return self.binary, self.binary_digest, hashlib.sha256(target.encode()).hexdigest()

    def source_identity(self, _archive, target, _model_sha):
        return dict(kind='test-c-fixture', target=target,
                    source_files=[dict(path=str(self.source), sha256=sha(self.source))])

    def probe(self):
        def grammars(_archive, names):
            return {name: Grammar(name, 'fixture.c', sha(self.source), None,
                                  '', (), (), ()) for name in names}
        with NativeFrontier(self.frontier, archive_factory=FixtureArchive,
                            binary_resolver=self.resolve_binary,
                            grammar_resolver=grammars,
                            value_modes_resolver=lambda _grammars: (('scp','fixture'),),
                            value_candidate=lambda _target,_mode,index:
                                (('-h',),b'','fixture:'+str(index)),
                            observer=observe) as search:
            result = search.run_one()
        self.assertEqual(result['state'], 'fatal', result)
        self.assertEqual(result['fatal_signals'], ['SIGABRT']
                         if 'raise(SIGABRT)' in self.source.read_text()
                         else ['SIGSEGV'])
        return result

    def ingest(self):
        return ingest_fatal_outcomes(
            self.frontier, self.catalog, archive_factory=FixtureArchive,
            binary_resolver=self.resolve_binary,
            source_identity_factory=self.source_identity)

    def test_fatal_signal_script_and_exact_pc_replay_are_separate(self):
        observed = self.probe()
        entries = self.ingest()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['signal'], 'SIGABRT')
        replay = entries[0]['replay']
        self.assertTrue(replay['reproducer_verified'], replay)
        self.assertTrue(replay['exact_site_verified'], replay)
        self.assertEqual(replay['script']['status'], 'reproduced')
        self.assertEqual(replay['exact_pc_replay']['status'], 'reproduced', replay)
        with Catalog(self.catalog) as catalog:
            record = catalog.read_native_fatal_observation(entries[0]['id'])
            self.assertEqual(record['frontier']['input_id'], observed['input_id'])
            self.assertEqual(record['binary']['sha256'], self.binary_digest)
            self.assertEqual(record['assets']['stdin']['bytes'], 0)
            self.assertEqual(record['first_run']['recipe']['argv'], ['-h'])
            self.assertEqual(record['first_run']['observation']
                             ['signal_terminations'][0]['signal'], 'SIGABRT')
            script_path = Path(record['assets']['script']['path'])
            self.assertTrue(script_path.is_file())
            script_bytes = script_path.read_bytes()
            self.assertTrue(script_bytes.startswith(b'#!/usr/bin/bash\n'))
            self.assertIn(b'PATH=/usr/bin:/bin\n', script_bytes)
            self.assertIn(b'/usr/bin/python3 -I', script_bytes)
            self.assertEqual(len(list(catalog.list_native_fatal_replays(entries[0]['id']))), 1)
        again = self.ingest()
        self.assertEqual(again[0]['id'], entries[0]['id'])
        with Catalog(self.catalog) as catalog:
            self.assertEqual(len(list(catalog.list_native_fatal_observations())), 1)
            self.assertEqual(len(list(catalog.list_native_fatal_replays(entries[0]['id']))), 1)

    def test_explicit_retry_appends_success_after_failed_replay(self):
        self.probe()

        def failed_replay(catalog, observation_id, _record, _source_identity):
            result = dict(schema=1, kind='native-fatal-replay-attempt',
                          observation_id=observation_id,
                          script=dict(status='not_reproduced'),
                          exact_pc_replay=dict(status='not_reproduced'),
                          reproducer_verified=False, exact_site_verified=False,
                          source_link=dict(status='unmapped'))
            catalog.add_native_fatal_replay(observation_id, result)
            return result

        with patch('native_frontier_catalog._run_replays', side_effect=failed_replay):
            first = self.ingest()[0]
        self.assertEqual(first['replay']['script']['status'], 'not_reproduced')
        self.assertEqual(self.ingest()[0]['replay']['script']['status'],
                         'not_reproduced')
        retried = retry_fatal_observation(
            first['id'], self.frontier, self.catalog,
            archive_factory=FixtureArchive, binary_resolver=self.resolve_binary,
            source_identity_factory=self.source_identity)
        self.assertEqual(len(retried), 1)
        self.assertEqual(retried[0]['id'], first['id'])
        self.assertTrue(retried[0]['replay']['reproducer_verified'],
                        retried[0]['replay'])
        self.assertTrue(retried[0]['replay']['exact_site_verified'],
                        retried[0]['replay'])
        with Catalog(self.catalog) as catalog:
            attempts = list(catalog.list_native_fatal_replays(first['id']))
        self.assertEqual(len(attempts), 2)
        self.assertEqual(attempts[0]['script']['status'], 'not_reproduced')
        self.assertEqual(attempts[1]['script']['status'], 'reproduced')

    def test_sigsegv_maps_exact_native_pc_without_claiming_c_expression(self):
        self.source.write_text('int main(void) { volatile int *p = 0; return *p; }\n')
        subprocess.run(['cc','-g','-O0','-o',str(self.binary),str(self.source)],
                       check=True)
        self.binary_digest = sha(self.binary)
        observed = self.probe()
        self.assertEqual(observed['fatal_signals'], ['SIGSEGV'])
        entry = self.ingest()[0]
        replay = entry['replay']
        self.assertTrue(replay['reproducer_verified'], replay)
        self.assertTrue(replay['exact_site_verified'], replay)
        sites = replay['script']['exact_pc_sites']
        self.assertTrue(any(site['signal'] == 'SIGSEGV' and
                            site['module_path'] == str(self.binary) and
                            site.get('source_line_context')
                            for site in sites), replay)
        self.assertFalse(replay['original_c_expression_verified'])
        with Catalog(self.catalog) as catalog:
            record = catalog.read_native_fatal_observation(entry['id'])
            self.assertEqual(record['signal'], 'SIGSEGV')
            self.assertEqual(record['source_link']['status'], 'unmapped')
        self.assertEqual(replay['source_link']['status'], 'unmapped')
        class PinnedFixture:
            manifest_sha256 = 'a'*64
            data = {'source_snapshot': {'files': {'abort.c': sha(self.source)}}}

        mapping = _source_link_for_sites(
            record, sites, dict(kind='openssh-archive'),
            archive_factory=lambda _: PinnedFixture(), source_root=self.root)
        self.assertEqual(mapping['status'], 'native-dwarf-line-mapped')
        self.assertEqual(mapping['sites'][0]['source_sha256'], sha(self.source))
        wrong_site = dict(sites[0], module_path='/usr/lib/unrelated.so')
        self.assertEqual(_source_link_for_sites(
            record, [wrong_site], dict(kind='openssh-archive'),
            archive_factory=lambda _: PinnedFixture(),
            source_root=self.root)['status'], 'unmapped')

    def test_unpaired_helper_sigkill_is_recorded_and_skipped(self):
        self.probe()
        database = sqlite3.connect(self.frontier/'frontier.sqlite')
        row = database.execute(
            'SELECT input_id,attempt,payload FROM outcomes').fetchone()
        evidence = json.loads(zlib.decompress(row[2]))
        capture = Path(evidence['sandbox'])/'capture'
        for path in capture.glob('trace.*'):
            path.unlink()
        trace = capture/'trace.999'
        trace.write_text('+++ killed by SIGKILL +++\n')
        evidence['observation']['signal_deliveries'] = []
        evidence['observation']['signal_terminations'] = [
            dict(pid='999', signal='SIGKILL')]
        evidence['observation']['trace_files'] = [
            dict(file=trace.name, bytes=trace.stat().st_size, sha256=sha(trace))]
        evidence['fatal_signals'] = ['SIGKILL']
        raw = json.dumps(evidence, sort_keys=True,
                         separators=(',', ':'), ensure_ascii=False).encode()
        database.execute(
            'UPDATE outcomes SET payload=?,sha256=? WHERE input_id=? AND attempt=?',
            (zlib.compress(raw), hashlib.sha256(raw).hexdigest(),
             row[0], row[1]))
        database.commit()
        database.close()
        result = self.ingest()
        self.assertEqual(result[0]['status'], 'rejected')
        with Catalog(self.catalog) as catalog:
            self.assertEqual(list(catalog.list_native_fatal_observations()), [])
            rejected = list(catalog.list_native_fatal_rejections(row[0]))
            self.assertEqual(len(rejected), 1)
            self.assertEqual(rejected[0]['unqualified_signals'], ['SIGKILL'])

    def test_captured_pc_must_match_attributed_fatal_pid(self):
        deliveries = [
            dict(pid='10', signal='SIGSEGV',
                 stack_frames=[dict(module=str(self.binary))]),
            dict(pid='20', signal='SIGSEGV',
                 stack_frames=[dict(module='/usr/lib/wrapper.so')])]
        terminations = [dict(pid='10', signal='SIGSEGV'),
                        dict(pid='20', signal='SIGSEGV')]
        sites = [dict(pid='10', signal='SIGSEGV', status='not_captured'),
                 dict(pid='20', signal='SIGSEGV', status='captured',
                      stable_site_key='wrong-process')]
        pairs, selected = _qualified_native_sites(
            deliveries, terminations, sites, 'SIGSEGV', str(self.binary))
        self.assertIn(('10','SIGSEGV'), pairs)
        self.assertNotIn(('20','SIGSEGV'), pairs)
        self.assertEqual(selected, [])
        sites[0] = dict(pid='10', signal='SIGSEGV', status='captured',
                        stable_site_key='right-process')
        _, selected = _qualified_native_sites(
            deliveries, terminations, sites, 'SIGSEGV', str(self.binary))
        self.assertEqual([site['stable_site_key'] for site in selected],
                         ['right-process'])
        handled_then_fatal = [
            dict(pid='10', signal='SIGSEGV',
                 stack_frames=[dict(module=str(self.binary))]),
            dict(pid='10', signal='SIGSEGV',
                 stack_frames=[dict(module='/usr/lib/wrapper.so')])]
        _, selected = _qualified_native_sites(
            handled_then_fatal, [dict(pid='10', signal='SIGSEGV')],
            [dict(pid='10', signal='SIGSEGV', status='captured',
                  stable_site_key='later-unpinned')],
            'SIGSEGV', str(self.binary))
        self.assertEqual(selected, [])

    def test_changed_outcome_hash_is_rejected(self):
        self.probe()
        database = sqlite3.connect(self.frontier/'frontier.sqlite')
        row = database.execute('SELECT input_id,attempt,payload FROM outcomes').fetchone()
        evidence = json.loads(zlib.decompress(row[2]))
        evidence['target'] = 'changed'
        changed = zlib.compress(json.dumps(evidence, sort_keys=True,
                                            separators=(',', ':')).encode())
        database.execute('UPDATE outcomes SET payload=? WHERE input_id=? AND attempt=?',
                         (changed,row[0],row[1]))
        database.commit()
        database.close()
        with self.assertRaisesRegex(RuntimeError, 'hash or canonical JSON'):
            self.ingest()

    def test_changed_binary_is_rejected(self):
        self.probe()
        self.binary.write_bytes(self.binary.read_bytes()+b'changed')
        with self.assertRaisesRegex(RuntimeError, 'Pinned|pinned|differs'):
            self.ingest()


if __name__ == '__main__':
    unittest.main()
