"""Durable frontier, fair scheduling, timeout, and fatal-sandbox tests."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest import mock

from native_input_search import (NativeFrontier, BASELINES,
                                 LEGACY_VALUE_MODES,
                                 LEGACY_VALUE_POLICY_SHA256,
                                 cleanup_sandbox, packed)
from native_input_grammar import Grammar, SAFE_FLAGS, SAFE_ARGUMENTS


TARGETS = ('scp','sftp','sftp-server','ssh','ssh-add','ssh-agent','ssh-keygen',
           'ssh-keyscan','ssh-keysign','ssh-pkcs11-helper','ssh-sk-helper',
           'sshd','sshd-auth','sshd-session')


class FakeArchive:
    manifest_sha256 = 'a'*64
    data = {'models': {name: {} for name in TARGETS}}

    def __init__(self, _root):
        pass


def fake_binary(_archive, target):
    path = Path('/usr/bin/true')
    return path, 'b'*64, hashlib.sha256(target.encode()).hexdigest()


def fake_grammars(_archive, names):
    found = {}
    extra_arguments = {'ssh-add':'t', 'ssh-agent':'t',
                       'ssh-keygen':'f', 'sshd-auth':'u',
                       'sshd-session':'po'}
    for name in names:
        flags = tuple(SAFE_FLAGS[name])
        arguments = tuple(dict.fromkeys(
            [row[0] for row in SAFE_ARGUMENTS[name]] +
            list(extra_arguments.get(name,''))))
        found[name] = Grammar(name,name+'.c','c'*64,1,
                              ''.join(flags)+''.join(ch+':' for ch in arguments),
                              flags,arguments,())
    return found


def native_argv(recipe):
    args = recipe['argv']
    marker = max(index for index, arg in enumerate(args) if arg == '--')
    assert args[marker+1] == '/usr/bin/true'
    return tuple(args[marker+2:])


def observation(recipe, *, timed_out=False, fatal=False):
    signal_rows = ([{'pid':'1','signal':'SIGSEGV'}] if fatal else [])
    return dict(timed_out=timed_out, tracer_returncode=(None if timed_out else
                                                       -11 if fatal else 0),
                stdout={'bytes':0,'sha256':hashlib.sha256(b'').hexdigest()},
                stderr={'bytes':0,'sha256':hashlib.sha256(b'').hexdigest()},
                signal_terminations=signal_rows,
                signal_deliveries=signal_rows,
                trace_files=[])


class DoneObserver:
    def __init__(self):
        self.calls = []

    def __call__(self, program, recipe, stdin, directory, trace_signals,
                 capture_crash_site):
        self.calls.append((program,recipe,stdin,directory,trace_signals,
                           capture_crash_site))
        assert program == Path('/usr/bin/bwrap')
        assert '--unshare-net' in recipe['argv']
        assert '--unshare-pid' in recipe['argv']
        assert native_argv(recipe) in BASELINES or native_argv(recipe) == () or native_argv(recipe)[0].startswith('-')
        assert not stdin and trace_signals and not capture_crash_site
        assert Path(recipe['env']['HOME']).is_dir()
        assert Path(recipe['cwd']).is_dir()
        (directory/'stdout.bin').write_bytes(b'')
        (directory/'stderr.bin').write_bytes(b'')
        return observation(recipe)


class FirstTimeoutThenFatal(DoneObserver):
    def __init__(self):
        super().__init__()
        self.first_argv = None

    def __call__(self,*args):
        program,recipe,stdin,directory,tracing,capture = args
        self.calls.append(args)
        assert tracing and not capture and not stdin
        (directory/'stdout.bin').write_bytes(b'')
        (directory/'stderr.bin').write_bytes(b'')
        key = (recipe['target'],native_argv(recipe))
        if self.first_argv is None:
            self.first_argv = key
            return observation(recipe,timed_out=True)
        return observation(recipe,fatal=key == self.first_argv)


class UnpairedKill(DoneObserver):
    def __call__(self,*args):
        result = super().__call__(*args)
        result['signal_terminations'] = [{'pid':'999','signal':'SIGKILL'}]
        return result


class ValueObserver:
    def __init__(self):
        self.calls = []

    def __call__(self,program,recipe,stdin,directory,trace_signals,
                 capture_crash_site):
        assert program == Path('/usr/bin/bwrap')
        assert '--unshare-net' in recipe['argv']
        assert trace_signals and not capture_crash_site
        self.calls.append((recipe['target'],native_argv(recipe),stdin))
        (directory/'stdout.bin').write_bytes(b'')
        (directory/'stderr.bin').write_bytes(b'')
        return observation(recipe)


class NativeInputSearchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-frontier-test-')
        self.root = Path(self.temp.name)
        self.directory = self.root/'state'

    def tearDown(self):
        self.temp.cleanup()

    def frontier(self, observer):
        return NativeFrontier(self.directory, archive_factory=FakeArchive,
                              binary_resolver=fake_binary, observer=observer,
                              grammar_resolver=fake_grammars,
                              isolation_resolver=lambda: (Path('/usr/bin/bwrap'),
                                                          'd'*64),
                              isolation_preflight=lambda _path: None)

    def test_all_targets_seeded_and_fair_after_restart(self):
        observer = DoneObserver()
        with self.frontier(observer) as search:
            state = search.status()
            self.assertEqual(state['targets'],14)
            self.assertEqual(state['inputs'],28)
            self.assertEqual(state['states'],{'queued':28})
            batch = search.run(14)
            self.assertEqual(batch['processed'],14)
            self.assertEqual({r['target'] for r in batch['results']},set(TARGETS))
            self.assertEqual(batch['status']['states'],{'done':14,'queued':14})
            with self.assertRaises(BlockingIOError):
                self.frontier(observer)
        with self.frontier(observer) as resumed:
            self.assertEqual(resumed.run(14)['processed'],14)
            self.assertEqual(resumed.status()['states'],{'done':28})
            self.assertEqual(resumed.status()['outcomes'],28)
            self.assertEqual(resumed.status()['behavior_signatures'],1)
            self.assertGreater(resumed.status()['grammar_atoms'],28)
            self.assertEqual(list((self.directory/'sandboxes').iterdir()),[])
            payload = resumed.db.execute(
                'SELECT payload,sha256 FROM outcomes LIMIT 1').fetchone()
            raw = __import__('zlib').decompress(payload['payload'])
            self.assertEqual(hashlib.sha256(raw).hexdigest(),payload['sha256'])

    def test_timeout_requeues_and_fatal_sandbox_is_retained(self):
        observer = FirstTimeoutThenFatal()
        with self.frontier(observer) as search:
            first = search.run_one()
            self.assertEqual(first['state'],'queued')
            row = search.db.execute(
                'SELECT timeout_seconds,attempts FROM frontier WHERE id=?',
                (first['input_id'],)).fetchone()
            self.assertEqual(tuple(row),(4.0,1))
            second = None
            for _ in range(30):
                result = search.run_one()
                if result['input_id'] == first['input_id']:
                    second = result
                    break
            self.assertIsNotNone(second)
            self.assertEqual(second['state'],'fatal')
            self.assertEqual(second['fatal_signals'],['SIGSEGV'])
            self.assertEqual(search.status()['states']['fatal'],1)
            record = search.db.execute(
                'SELECT payload FROM outcomes WHERE input_id=? AND attempt=2',
                (first['input_id'],)).fetchone()
            evidence = json.loads(__import__('zlib').decompress(record['payload']))
            sandbox = Path(evidence['sandbox'])
            self.assertTrue(sandbox.is_dir())
            self.assertEqual(evidence['recipe']['timeout_seconds'],4.0)
            self.assertIn('Lean proof',search.status()['scope'])
            cleanup_sandbox(self.directory,sandbox)
            self.assertFalse(sandbox.exists())

    def test_interrupted_lease_replays_and_identity_is_pinned(self):
        with self.frontier(DoneObserver()) as search:
            row = search.db.execute(
                "SELECT id FROM frontier WHERE status='queued' LIMIT 1").fetchone()
            with search.db:
                search.db.execute("UPDATE frontier SET status='running',attempts=1 "
                                  'WHERE id=?', (row['id'],))
        with self.frontier(DoneObserver()) as resumed:
            result = resumed.run_one()
            self.assertEqual(result['state'],'done')
            # Another queued target may run first; the interrupted record stays queued.
            saved = resumed.db.execute(
                'SELECT status,attempts FROM frontier WHERE id=?',
                (row['id'],)).fetchone()
            self.assertIn(saved['status'],('queued','done'))
            self.assertGreaterEqual(saved['attempts'],1)
        with self.assertRaisesRegex(RuntimeError,'another archive'):
            original = FakeArchive.manifest_sha256
            try:
                FakeArchive.manifest_sha256 = 'c'*64
                self.frontier(DoneObserver())
            finally:
                FakeArchive.manifest_sha256 = original

    def test_generated_options_are_durable_and_feedback_extends_novel_inputs(self):
        observer = DoneObserver()
        with self.frontier(observer) as search:
            self.assertEqual(search.generate(14),14)
            self.assertEqual(search.status()['generated_inputs'],14)
            first = search.db.execute(
                "SELECT id,argv,origin FROM frontier WHERE origin LIKE 'generated:%' "
                'ORDER BY id LIMIT 1').fetchone()
            self.assertTrue(first['origin'].startswith('generated:'))
            self.assertEqual(search.generate(14),14)
        with self.frontier(observer) as resumed:
            self.assertEqual(resumed.status()['generated_inputs'],28)
            self.assertEqual(resumed.db.execute(
                'SELECT argv FROM frontier WHERE id=?',
                (first['id'],)).fetchone()[0],first['argv'])
            # Complete old baselines and the newly generated, private probes.
            result = resumed.run(56)
            self.assertEqual(result['processed'],56)
            self.assertGreater(result['status']['completed_grammar_atoms'],0)
            self.assertGreater(result['status']['mutation_seeds'],0)
            self.assertEqual(list((self.directory/'sandboxes').iterdir()),[])

    def test_unpaired_wrapper_kill_is_not_native_fatal(self):
        with self.frontier(UnpairedKill()) as search:
            result = search.run_one()
            self.assertEqual(result['state'],'runner_signal')
            self.assertEqual(result['fatal_signals'],[])
            row = search.db.execute('''SELECT classification FROM
                outcome_classifications WHERE input_id=? AND attempt=1''',
                (result['input_id'],)).fetchone()
            self.assertEqual(row[0],'runner_signal')
            payload = search.db.execute('SELECT payload FROM outcomes WHERE input_id=?',
                                        (result['input_id'],)).fetchone()[0]
            evidence = json.loads(__import__('zlib').decompress(payload))
            self.assertTrue(Path(evidence['sandbox']).is_dir())
            cleanup_sandbox(self.directory,evidence['sandbox'])
        with self.frontier(DoneObserver()) as resumed:
            self.assertEqual(resumed.status()['states']['runner_signal'],1)

    def test_open_ended_value_cursors_resume_and_reach_stdin_readers(self):
        observer = ValueObserver()
        with self.frontier(observer) as search:
            with search.db:
                search.db.execute('UPDATE generators SET phase=3,cursor=0')
                search.db.execute("UPDATE frontier SET status='done' "
                                  "WHERE status='queued'")
            self.assertEqual(search.generate(40),40)
            before = search.status()['value_cursors']
            self.assertEqual(sum(map(int,before.values())),40)
            by_target = {}
            for label, cursor in before.items():
                target = label.split(':',1)[0]
                by_target[target] = by_target.get(target,0)+int(cursor)
            self.assertLessEqual(max(by_target.values())-min(by_target.values()),1)
            self.assertEqual(search.run(40)['processed'],40)
            self.assertTrue(any(target == 'sftp-server' and stdin
                                for target,_argv,stdin in observer.calls))
            self.assertTrue(all(not any('ssh://' in arg for arg in argv)
                                for _target,argv,_stdin in observer.calls))
        with self.frontier(observer) as resumed:
            self.assertEqual(resumed.status()['value_cursors'],before)
            self.assertEqual(resumed.generate(20),20)
            after = resumed.status()['value_cursors']
            self.assertGreater(sum(map(int,after.values())),
                               sum(map(int,before.values())))
            self.assertEqual(resumed.run(20)['processed'],20)
            self.assertNotIn('idle',resumed.status()['states'])

    def test_exact_legacy_value_roster_migrates_without_changing_inputs(self):
        with self.frontier(ValueObserver()) as search:
            target, mode = LEGACY_VALUE_MODES[0]
            argv, stdin, tag = search.value_candidate(target,mode,0)
            with search.db:
                search._offer_input(target,argv,'value/0/0:'+tag,stdin=stdin)
                search.db.execute("UPDATE value_generators SET cursor='1' "
                                  'WHERE slot=0')
                search.db.execute('DELETE FROM value_generators WHERE slot>=?',
                                  (len(LEGACY_VALUE_MODES),))
                search.db.execute("UPDATE value_identity SET value='1' "
                                  "WHERE key='schema'")
                search.db.execute('UPDATE value_identity SET value=? '
                                  "WHERE key='policy_sha256'",
                                  (LEGACY_VALUE_POLICY_SHA256,))
                search.db.execute('UPDATE value_identity SET value=? '
                                  "WHERE key='modes'",
                                  (packed(LEGACY_VALUE_MODES),))
            old = [tuple(row) for row in search.db.execute(
                "SELECT * FROM frontier WHERE origin LIKE 'value/%' ORDER BY id")]
            self.assertEqual(len(old),1)
        with self.frontier(ValueObserver()) as migrated:
            new = [tuple(row) for row in migrated.db.execute(
                "SELECT * FROM frontier WHERE origin LIKE 'value/%' ORDER BY id")]
            self.assertEqual(new,old)
            slots = list(migrated.db.execute(
                'SELECT slot,target,mode,cursor FROM value_generators ORDER BY slot'))
            self.assertEqual([(row['target'],row['mode']) for row in slots[:10]],
                             list(LEGACY_VALUE_MODES))
            self.assertEqual(slots[0]['cursor'],'1')
            self.assertTrue(all(row['cursor'] == '0' for row in slots[10:]))
            receipt = migrated.db.execute(
                'SELECT * FROM value_policy_migrations').fetchone()
            self.assertEqual(receipt['verified_inputs'],1)
            self.assertEqual(receipt['from_policy_sha256'],
                             LEGACY_VALUE_POLICY_SHA256)
            self.assertEqual(migrated.status()['open_ended_value_modes'],16)
            with self.assertRaises(sqlite3.IntegrityError):
                with migrated.db:
                    migrated.db.execute(
                        'UPDATE value_policy_migrations SET verified_inputs=0')
            with self.assertRaises(sqlite3.IntegrityError):
                with migrated.db:
                    migrated.db.execute('DELETE FROM value_policy_migrations')
        with self.frontier(ValueObserver()) as resumed:
            self.assertEqual(resumed.db.execute(
                'SELECT count(*) FROM value_policy_migrations').fetchone()[0],1)

    def test_legacy_value_migration_rejects_modified_input(self):
        with self.frontier(ValueObserver()) as search:
            target, mode = LEGACY_VALUE_MODES[0]
            argv, stdin, tag = search.value_candidate(target,mode,0)
            with search.db:
                search._offer_input(target,argv,'value/0/0:'+tag,stdin=stdin)
                search.db.execute("UPDATE value_generators SET cursor='1' "
                                  'WHERE slot=0')
                search.db.execute('DELETE FROM value_generators WHERE slot>=?',
                                  (len(LEGACY_VALUE_MODES),))
                search.db.execute("UPDATE value_identity SET value='1' "
                                  "WHERE key='schema'")
                search.db.execute('UPDATE value_identity SET value=? '
                                  "WHERE key='policy_sha256'",
                                  (LEGACY_VALUE_POLICY_SHA256,))
                search.db.execute('UPDATE value_identity SET value=? '
                                  "WHERE key='modes'",
                                  (packed(LEGACY_VALUE_MODES),))
                search.db.execute("UPDATE frontier SET argv='[\"-P\",\"999\"]' "
                                  "WHERE origin LIKE 'value/%'")
        with self.assertRaisesRegex(RuntimeError,
                                    'Legacy value input differs'):
            self.frontier(ValueObserver())
        db = sqlite3.connect(self.directory/'frontier.sqlite')
        try:
            self.assertEqual(db.execute("SELECT value FROM value_identity "
                                        "WHERE key='schema'").fetchone()[0],'1')
            self.assertEqual(db.execute(
                'SELECT count(*) FROM value_policy_migrations').fetchone()[0],0)
        finally:
            db.close()


class CleanupSandboxSafetyTests(unittest.TestCase):
    """Only disposable local directories are used; no probes are executed."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cleanup-safety-',
                                                dir='/var/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.frontier = self.root/'frontier'
        self.base = self.frontier/'sandboxes'
        self.base.mkdir(parents=True)
        self.outside = self.root/'outside'
        self.outside.mkdir()
        (self.outside/'keep.txt').write_text('preserve outside data')

    def sandbox(self, parent, name='probe-test'):
        path = parent/name
        path.mkdir()
        (path/'marker.txt').write_text('fixture')
        return path

    def test_normal_cleanup_preserves_siblings_and_link_destinations(self):
        path = self.sandbox(self.base)
        sibling = self.sandbox(self.base,'probe-sibling')
        (path/'outside-link').symlink_to(self.outside,target_is_directory=True)
        cleanup_sandbox(self.frontier,path)
        self.assertFalse(path.exists())
        self.assertEqual((sibling/'marker.txt').read_text(),'fixture')
        self.assertEqual((self.outside/'keep.txt').read_text(),'preserve outside data')

    def test_symlinked_parent_cannot_authorize_deleting_an_outside_directory(self):
        self.base.rmdir()
        self.base.symlink_to(self.outside,target_is_directory=True)
        outside = self.sandbox(self.outside)
        with self.assertRaises((RuntimeError,OSError)):
            cleanup_sandbox(self.frontier,outside)
        self.assertEqual((outside/'marker.txt').read_text(),'fixture')

    def test_parent_replacement_during_cleanup_cannot_redirect_deletion(self):
        path = self.sandbox(self.base)
        outside = self.sandbox(self.outside)
        saved = self.frontier/'original-sandboxes'
        original_remove = shutil.rmtree

        def replace_parent_then_remove(*args,**kwargs):
            self.base.rename(saved)
            self.base.symlink_to(self.outside,target_is_directory=True)
            return original_remove(*args,**kwargs)

        with mock.patch('native_input_search.shutil.rmtree',
                        side_effect=replace_parent_then_remove) as remove:
            remove.avoids_symlink_attacks = original_remove.avoids_symlink_attacks
            cleanup_sandbox(self.frontier,path)
        self.assertEqual((outside/'marker.txt').read_text(),'fixture')
        self.assertFalse((saved/path.name).exists())

    def test_linked_parent_is_rejected_even_with_an_in_scope_child_path(self):
        self.base.rmdir()
        self.base.symlink_to(self.outside,target_is_directory=True)
        outside = self.sandbox(self.outside)
        with self.assertRaises((RuntimeError,OSError)):
            cleanup_sandbox(self.frontier,self.base/outside.name)
        self.assertEqual((outside/'marker.txt').read_text(),'fixture')

    def test_symlink_at_the_cleanup_target_is_rejected(self):
        outside = self.sandbox(self.outside)
        path = self.base/'probe-link'
        path.symlink_to(outside,target_is_directory=True)
        with self.assertRaises((RuntimeError,OSError)):
            cleanup_sandbox(self.frontier,path)
        self.assertTrue(path.is_symlink())
        self.assertEqual((outside/'marker.txt').read_text(),'fixture')

    def test_cleanup_error_closes_open_directory_descriptors(self):
        path = self.sandbox(self.base)
        original_open = os.open
        descriptors = []

        def tracked_open(*args,**kwargs):
            descriptor = original_open(*args,**kwargs)
            descriptors.append(descriptor)
            return descriptor

        with mock.patch('native_input_search.os.open',side_effect=tracked_open):
            with mock.patch('native_input_search.shutil.rmtree',
                            side_effect=OSError('synthetic cleanup failure')) as remove:
                remove.avoids_symlink_attacks = True
                with self.assertRaisesRegex(OSError,'synthetic cleanup failure'):
                    cleanup_sandbox(self.frontier,path)
        self.assertTrue(descriptors)
        for descriptor in descriptors:
            with self.assertRaises(OSError):
                os.fstat(descriptor)
        self.assertTrue(path.is_dir())


if __name__ == '__main__':
    unittest.main()
