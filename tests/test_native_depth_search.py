"""Focused checks for the logarithmic native repetition search strategy."""
import base64
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from common import sha
from native_depth_search import (NativeDepthSearch, check_profile, expanded_argv,
                                 ensure_reproducer_runtime, profile_bytes,
                                 protocol_input, write_protocol)


def profile(**changes):
    result = dict(schema=1, target='scp', argv=['-r', '-t', '{destination}'],
                  record_base64=base64.b64encode(b'D0700 0 x\n').decode(),
                  expect_signal='SIGSEGV', initial_depth=1, growth_factor=2,
                  confirmation_runs=3, max_depth=64, timeout_seconds=5,
                  cwd=tempfile.gettempdir())
    result.update(changes)
    return check_profile(result)


class NativeDepthSearchTest(unittest.TestCase):
    def test_cataloged_runtime_survives_parser_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            result_path = Path(directory)/'search-result.json'
            marker = Path(directory)/'reproducer-catalog.json'
            saved = dict(reproducer_runtime=dict(
                stack_limit_kib='8192', trace_parser_sha256='0'*64))
            marker.write_text('{}')
            with patch('native_depth_search.sha',
                       side_effect=AssertionError('current parser was queried')):
                ensure_reproducer_runtime(saved, result_path, marker)
            self.assertEqual(saved['reproducer_runtime']['trace_parser_sha256'],
                             '0'*64)
            self.assertFalse(result_path.exists())

            marker.unlink()
            with patch('native_depth_search.sha', return_value='1'*64), \
                    patch('native_depth_search.subprocess.check_output',
                          return_value='8192\n'):
                with self.assertRaisesRegex(RuntimeError, 'trace parser changed'):
                    ensure_reproducer_runtime(saved, result_path, marker)
                fresh = {}
                ensure_reproducer_runtime(fresh, result_path, marker)
            self.assertEqual(fresh['reproducer_runtime'], dict(
                stack_limit_kib='8192', trace_parser_sha256='1'*64))
            self.assertEqual(json.loads(result_path.read_text()), fresh)

    def test_published_scp_profile_is_open_ended_and_source_linked(self):
        path = Path(__file__).resolve().parents[1]/'search/recursion/scp-recursive-sink.json'
        raw = json.loads(path.read_bytes())
        raw['cwd'] = tempfile.gettempdir()
        selected = check_profile(raw)
        self.assertIsNone(selected['max_depth'])
        self.assertEqual(selected['core_link']['relation'], 'causal_recursive_call')
        self.assertEqual(selected['expect_signal'], 'SIGSEGV')

    def test_profile_and_binary_record(self):
        selected = profile()
        self.assertEqual(protocol_input(profile_bytes(selected), 3),
                         b'D0700 0 x\n'*3)
        self.assertEqual(expanded_argv(['-t', '{destination}'], '/tmp/d'),
                         ['-t', '/tmp/d'])
        with self.assertRaises(ValueError):
            profile(record_base64='!')
        with self.assertRaises(RuntimeError):
            profile(argv=['{destination}', '{destination}'])
        if 'SIGIOT' in signal.Signals.__members__:
            self.assertEqual(profile(expect_signal='SIGIOT')['expect_signal'],
                             'SIGABRT')

    def test_streaming_input_uses_bounded_chunks(self):
        class CountingSink:
            largest = 0
            def write(self, chunk):
                self.largest = max(self.largest, len(chunk))
            def flush(self):
                pass
        sink = CountingSink()
        total, digest = write_protocol(sink, profile_bytes(profile()),
                                       100000, rewind=False)
        self.assertEqual(total, 1000000)
        self.assertLessEqual(sink.largest, 65536)
        self.assertEqual(len(digest), 64)

    def test_doubling_and_bisection_find_observed_bracket(self):
        search = object.__new__(NativeDepthSearch)
        search.profile = profile()
        search.cache = {}

        def probe(depth):
            record = dict(depth=depth, timed_out=False,
                          expected_signal_observed=depth >= 13)
            search.cache.setdefault(depth, []).append(record)
            return record

        search.probe = probe
        result = search.search()
        self.assertEqual(result['status'], 'observed_depth_bracket')
        self.assertEqual(result['exponential_crash_depth'], 16)
        self.assertEqual(result['observed_noncrashing_depth'], 12)
        self.assertEqual(result['observed_crash_depth'], 13)
        self.assertLessEqual(result['probe_count'], 60)

    def test_profile_maximum_is_an_observation_boundary(self):
        search = object.__new__(NativeDepthSearch)
        search.profile = profile(max_depth=7)
        search.cache = {}

        def probe(depth):
            record = dict(depth=depth, timed_out=False,
                          expected_signal_observed=False)
            search.cache.setdefault(depth, []).append(record)
            return record

        search.probe = probe
        result = search.search()
        self.assertEqual(result['status'],
                         'no_crash_observed_through_profile_maximum')
        self.assertEqual(result['max_depth'], 7)
        self.assertIn(7, search.cache)

    def test_sequential_mode_finds_nonmonotone_depth(self):
        search = object.__new__(NativeDepthSearch)
        search.profile = profile(mode='sequential')
        search.cache = {}

        def probe(depth):
            record = dict(depth=depth, timed_out=False,
                          expected_signal_observed=depth == 3)
            search.cache.setdefault(depth, []).append(record)
            return record

        search.probe = probe
        result = search.search()
        self.assertEqual(result['witness_depth'], 3)
        self.assertEqual(result['observed_noncrashing_depth'], 2)
        self.assertEqual(result['search_mode'], 'sequential')

    def test_resume_replays_complete_probes_and_preserves_torn_tail(self):
        with tempfile.TemporaryDirectory() as root:
            destination = Path(root)/'campaign'
            selected = profile(argv=['-c', 'import sys; sys.stdin.buffer.read()'],
                               max_depth=2)
            first = NativeDepthSearch(
                selected, sys.executable, sha(sys.executable), destination,
                profile_source_sha256='fixed-profile',
                archive_manifest_sha256='fixed-archive')
            first.probe(0)
            first.probe(2)
            with first.events.open('ab') as stream:
                stream.write(b'{"incomplete":')
            resumed = NativeDepthSearch(
                selected, sys.executable, sha(sys.executable), destination,
                resume=True, profile_source_sha256='fixed-profile',
                archive_manifest_sha256='fixed-archive')
            self.assertEqual(resumed.next_sequence, 2)
            self.assertEqual(len(resumed.cache[2]), 1)
            self.assertEqual(len(list(destination.glob('probes.partial-tail-*.bin'))), 1)
            resumed.probe(1)
            self.assertEqual(resumed.next_sequence, 3)
            with self.assertRaises(RuntimeError):
                NativeDepthSearch(
                    profile(argv=['-c', 'import sys; sys.stdin.buffer.read()'],
                            max_depth=2, env={'LC_ALL': 'C'}),
                    sys.executable, sha(sys.executable), destination, resume=True,
                    profile_source_sha256='fixed-profile',
                    archive_manifest_sha256='fixed-archive')

    def test_process_family_mode_sees_fatal_child_with_parent_zero(self):
        script = ('import os,signal\n'
                  'pid=os.fork()\n'
                  'if pid == 0: os.kill(os.getpid(), signal.SIGSEGV)\n'
                  'else: os.waitpid(pid, 0)\n')
        with tempfile.TemporaryDirectory() as root:
            selected = profile(argv=['-c', script],
                               observation_mode='process_family', max_depth=1)
            search = NativeDepthSearch(selected, sys.executable,
                                       sha(sys.executable), Path(root)/'family')
            observed = search.probe(1)
            self.assertEqual(observed['returncode'], 0)
            self.assertTrue(observed['expected_signal_observed'])
            self.assertIn('SIGSEGV', observed['family_signal_terminations'])

    def test_timeout_kills_forked_process_family_in_both_modes(self):
        for mode in ('direct', 'process_family'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root:
                pidfile = Path(root)/'pids'
                script = (
                    'import os,time\n'
                    'child=os.fork()\n'
                    f'if child: open({str(pidfile)!r},"w").write('
                    'f"{os.getpid()} {child}")\n'
                    'time.sleep(30)\n')
                selected = profile(argv=['-c', script], timeout_seconds=0.25,
                                   observation_mode=mode, max_depth=1)
                search = NativeDepthSearch(selected, sys.executable,
                                           sha(sys.executable), Path(root)/'scan')
                try:
                    observed = search.probe(1)
                    self.assertTrue(observed['timed_out'])
                    self.assertTrue(pidfile.is_file())
                    pids = [int(value) for value in pidfile.read_text().split()]
                    time.sleep(0.05)
                    for pid in pids:
                        status = Path('/proc')/str(pid)/'stat'
                        if status.exists():
                            self.assertEqual(status.read_text().split()[2], 'Z')
                finally:
                    if pidfile.exists():
                        for value in pidfile.read_text().split():
                            try:
                                os.kill(int(value), signal.SIGKILL)
                            except ProcessLookupError:
                                pass


if __name__ == '__main__':
    unittest.main()
