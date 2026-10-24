"""Native OpenSSH replay and signal-delivery controls."""
import json
import os
import platform
import sqlite3
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from native_signal_replay import (observe, replay_binary, replay_recipe,
                                  verify_receipt, capture_crash_instruction)
from common import sha
from core_index import Index
from search_job import Job
from signal_catalog import Catalog


class NativeSignalReplayTests(unittest.TestCase):
    def test_observe_reaps_process_group_on_communicate_error(self):
        for cleanup_times_out in (False,True):
            with self.subTest(cleanup_times_out=cleanup_times_out):
                with tempfile.TemporaryDirectory(prefix='native-observe-reap-') as directory:
                    root = Path(directory)
                    original_popen = subprocess.Popen
                    launched = []

                    class FailOnce:
                        def __init__(self, *args, **kwargs):
                            self.child = original_popen(*args, **kwargs)
                            self.pid = self.child.pid
                            self.calls = 0
                            launched.append(self)

                        def communicate(self, *args, **kwargs):
                            self.calls += 1
                            if self.calls == 1:
                                raise RuntimeError('injected communication failure')
                            if cleanup_times_out and self.calls == 2:
                                raise subprocess.TimeoutExpired('sleep',2)
                            return self.child.communicate(*args, **kwargs)

                        def kill(self):
                            return self.child.kill()

                        def wait(self, *args, **kwargs):
                            return self.child.wait(*args, **kwargs)

                    recipe = dict(argv=['60'], cwd=str(root), env={'LC_ALL':'C'},
                                  timeout_seconds=5, expect_signal=None)
                    with mock.patch('native_signal_replay.subprocess.Popen', FailOnce):
                        with self.assertRaisesRegex(RuntimeError,
                                                    'injected communication failure'):
                            observe(Path('/usr/bin/sleep'), recipe, b'', root,
                                    trace_signals=False)
                    self.assertEqual(len(launched),1)
                    self.assertEqual(launched[0].child.returncode,-9)
                    with self.assertRaises(ProcessLookupError):
                        os.killpg(launched[0].pid,0)

    def test_pinned_ssh_invocation_and_receipt(self):
        root = Path(__file__).resolve().parents[1]
        if not (root/'work/reference-source/ssh').is_file() or not (
                root/'local/models/current/manifest.json').is_file():
            self.skipTest('pinned native OpenSSH and model archive are local data')
        with tempfile.TemporaryDirectory(prefix='openssh-native-replay-') as directory:
            recipe = dict(schema=1, target='ssh', argv=['-V'], expect_signal='SIGSEGV')
            for traced in (False, True):
                summary = replay_recipe(recipe, catalog_dir=directory, trace_signals=traced)
                receipt = json.loads(Path(summary['receipt']).read_bytes())
                self.assertEqual(receipt['recipe']['argv'], ['-V'])
                self.assertEqual(len(receipt['binary']['sha256']), 64)
                self.assertFalse(summary['expected_observed'])
                self.assertFalse(summary['timed_out'])
                self.assertEqual(verify_receipt(summary['receipt'])['status'], 'verified')
                stderr = Path(summary['receipt']).parent/'stderr.bin'
                self.assertIn(b'OpenSSH_', stderr.read_bytes())
                if traced:
                    self.assertTrue(receipt['observation']['trace_files'])
                else:
                    self.assertEqual(receipt['observation']['native_returncode'], 0)
                    output = Path(summary['receipt']).parent/'stdout.bin'
                    output.write_bytes(b'altered')
                    with self.assertRaisesRegex(RuntimeError, 'output changed'):
                        verify_receipt(summary['receipt'])

    def test_signal_delivery_and_handler_are_measured_separately(self):
        with tempfile.TemporaryDirectory(prefix='openssh-signal-control-') as directory:
            root = Path(directory)
            source = root/'signal.c'
            binary = root/'signal'
            source.write_text('''#include <signal.h>
static volatile sig_atomic_t handled;
static void handler(int number) { (void)number; handled = 1; }
int main(int argc, char **argv) {
    (void)argv;
    if (argc > 1) signal(SIGSEGV, handler);
    raise(SIGSEGV);
    return handled ? 0 : 1;
}
''')
            subprocess.run(['cc', '-o', str(binary), str(source)], check=True)
            baseline = dict(schema=1, argv=[], cwd=str(root), env={'LC_ALL': 'C'},
                            timeout_seconds=5, expect_signal='SIGSEGV')
            source_identity = dict(kind='test-c-fixture', source_files=[dict(
                path=str(source), sha256=sha(source))])
            direct = replay_binary(binary, sha(binary), baseline, source_identity,
                                   catalog_dir=root/'catalog')
            self.assertTrue(direct['expected_observed'])
            direct_receipt = json.loads(Path(direct['receipt']).read_bytes())
            self.assertEqual(direct_receipt['observation']['native_returncode'], -11)
            self.assertEqual(direct['signal_terminations'][0]['signal'], 'SIGSEGV')
            self.assertEqual(verify_receipt(direct['receipt'])['status'], 'verified')
            handled = replay_binary(binary, sha(binary), dict(baseline, argv=['handler']),
                                    source_identity, catalog_dir=root/'catalog', trace_signals=True)
            handled_receipt = json.loads(Path(handled['receipt']).read_bytes())
            self.assertEqual(handled_receipt['observation']['tracer_returncode'], 0)
            self.assertTrue(handled['expected_observed'])
            self.assertTrue(any(row['signal'] == 'SIGSEGV' for row in handled['signal_deliveries']))
            self.assertEqual(handled['signal_deliveries'][0]['si_code'], 'SI_TKILL')
            self.assertEqual(handled['signal_terminations'], [])
            self.assertEqual(verify_receipt(handled['receipt'])['status'], 'verified')

    def test_input_dependent_c_memory_fault_records_segv_code(self):
        with tempfile.TemporaryDirectory(prefix='openssh-memory-fault-control-') as directory:
            root = Path(directory)
            source = root/'fault.c'
            binary = root/'fault'
            source.write_text("""int main(int argc, char **argv) {
    if (argc > 1 && argv[1][0] == 'x') {
        volatile int *pointer = 0;
        return *pointer;
    }
    return 0;
}
""")
            subprocess.run(['cc', '-g', '-O0', '-o', str(binary), str(source)], check=True)
            identity = dict(kind='test-c-fixture', source_files=[dict(
                path=str(source), sha256=sha(source))])
            recipe = dict(schema=1, argv=['x'], cwd=str(root),
                          expect_signal='SIGSEGV', timeout_seconds=5)
            summary = replay_binary(binary, sha(binary), recipe, identity,
                                    catalog_dir=root/'catalog', trace_signals=True,
                                    capture_crash_site=True)
            self.assertTrue(summary['expected_observed'])
            self.assertTrue(any(row['si_code'] == 'SEGV_MAPERR' for row in summary['signal_deliveries']))
            debugger = summary['crash_instruction']
            self.assertEqual(debugger['status'], 'captured')
            self.assertEqual(debugger['signal'], 'SIGSEGV')
            self.assertEqual(debugger['si_code'], 1)
            self.assertEqual(debugger['fault_address'], '0x0')
            self.assertEqual(debugger['source'], str(source))
            self.assertEqual(debugger['source_sha256'], sha(source))
            self.assertEqual(debugger['line'], 4)
            self.assertTrue(debugger['pc'].startswith('0x'))
            self.assertTrue(debugger['instruction'])
            self.assertTrue(debugger['instruction_bytes'])
            self.assertTrue(summary['same_native_site_observed'])
            self.assertEqual(summary['primary_site']['module_offset'],
                             debugger['mapping']['file_offset'])
            self.assertEqual(summary['primary_site']['module_sha256'], sha(binary))
            context = summary['primary_site']['source_line_context']
            self.assertEqual(context['status'], 'reported')
            self.assertEqual(context['module_sha256'], sha(binary))
            self.assertEqual(len(context['tool']['sha256']), 64)
            self.assertTrue(any(str(source) in frame['location']
                                for frame in context['frames']))
            self.assertEqual(debugger['mapping']['path'], str(binary))
            self.assertTrue(debugger['mapping']['file_offset'].startswith('0x'))
            self.assertEqual(debugger['module_sha256'], sha(binary))
            self.assertEqual(len(debugger['stable_site_key']), 64)
            self.assertEqual(verify_receipt(summary['receipt'])['status'], 'verified')
            repeated = replay_binary(binary, sha(binary), recipe, identity,
                                     catalog_dir=root/'catalog', capture_crash_site=True)
            self.assertEqual(repeated['crash_instruction']['stable_site_key'],
                             debugger['stable_site_key'])

    def test_debugger_replays_stdin_and_identifies_fault_instruction(self):
        with tempfile.TemporaryDirectory(prefix='stdin-fault-control-') as directory:
            root = Path(directory)
            source, binary = root/'stdin.c', root/'stdin'
            source.write_text("#include <stdio.h>\nint main(void) { if (getchar() == 'x') { volatile int *p = 0; return *p; } return 0; }\n")
            subprocess.run(['cc', '-g', '-O0', '-o', str(binary), str(source)], check=True)
            identity = dict(kind='test-c-fixture', source_files=[dict(
                path=str(source), sha256=sha(source))])
            recipe = dict(schema=1, argv=[], stdin_base64='eA==', cwd=str(root),
                          expect_signal='SIGSEGV', timeout_seconds=5)
            summary = replay_binary(binary, sha(binary), recipe, identity,
                                    catalog_dir=root/'catalog', capture_crash_site=True)
            self.assertTrue(summary['expected_observed'])
            site = summary['crash_instruction']
            self.assertEqual(site['status'], 'captured')
            self.assertEqual(site['source'], str(source))
            self.assertEqual(site['line'], 2)
            self.assertTrue(site['pc'].startswith('0x'))
            self.assertTrue(summary['same_native_site_observed'])
            self.assertEqual(verify_receipt(summary['receipt'])['status'], 'verified')
            receipt_path = Path(summary['receipt'])
            original = receipt_path.read_bytes()
            altered = json.loads(receipt_path.read_bytes())
            altered['observation']['debugger']['pc'] = '0x0'
            receipt_path.write_text(json.dumps(altered))
            with self.assertRaisesRegex(RuntimeError, 'differs from saved log'):
                verify_receipt(receipt_path)
            altered = json.loads(original)
            altered['observation']['primary_site']['module_offset'] = '0x0'
            receipt_path.write_text(json.dumps(altered))
            with self.assertRaisesRegex(RuntimeError, 'primary fault site differs'):
                verify_receipt(receipt_path)
            altered = json.loads(original)
            altered['observation']['primary_sites'][0]['instruction_bytes'] = '00'
            receipt_path.write_text(json.dumps(altered))
            with self.assertRaisesRegex(RuntimeError, 'primary fault sites differ'):
                verify_receipt(receipt_path)
            altered = json.loads(original)
            altered['observation']['external_state_complete'] = True
            receipt_path.write_text(json.dumps(altered))
            with self.assertRaisesRegex(RuntimeError, 'external dependency status'):
                verify_receipt(receipt_path)

    def test_forked_process_fault_uses_same_run_primary_instruction(self):
        with tempfile.TemporaryDirectory(prefix='fork-fault-control-') as directory:
            root = Path(directory)
            source, binary = root/'fork.c', root/'fork'
            source.write_text('''#include <unistd.h>
#include <sys/wait.h>
int main(void) {
    if (fork() == 0) { volatile int *p = 0; return *p; }
    int status; wait(&status); return 0;
}
''')
            subprocess.run(['cc', '-g', '-O0', '-o', str(binary), str(source)], check=True)
            identity = dict(kind='test-c-fixture', source_files=[dict(
                path=str(source), sha256=sha(source))])
            summary = replay_binary(binary, sha(binary),
                dict(schema=1, argv=[], cwd=str(root), expect_signal='SIGSEGV',
                     timeout_seconds=5), identity, catalog_dir=root/'catalog',
                capture_crash_site=True)
            self.assertEqual(summary['primary_site']['status'], 'captured')
            self.assertEqual(summary['primary_site']['si_code'], 'SEGV_MAPERR')
            self.assertEqual(summary['primary_site']['module_sha256'], sha(binary))
            self.assertTrue(summary['primary_site']['instruction_bytes'])
            self.assertFalse(summary['same_native_site_observed'])
            self.assertEqual(summary['crash_instruction']['status'], 'not_captured')
            self.assertEqual(verify_receipt(summary['receipt'])['status'], 'verified')
            with Catalog(root/'catalog') as catalog:
                groups = list(catalog.list_native_instruction_sites(signal='SIGSEGV'))
            self.assertEqual(len(groups), 1)
            self.assertEqual(groups[0]['stable_site_key'],
                             summary['primary_site']['stable_site_key'])
            self.assertTrue(groups[0]['representative']['causal_fault_pc_observed'])
            self.assertFalse(groups[0]['representative']['causal_fault_instruction_verified'])

    def test_primary_site_remains_available_without_gdb(self):
        with tempfile.TemporaryDirectory(prefix='primary-without-gdb-') as directory:
            root = Path(directory)
            source, binary = root/'fault.c', root/'fault'
            source.write_text('int main(void) { volatile int *p = 0; return *p; }\n')
            subprocess.run(['cc', '-g', '-O0', '-o', str(binary), str(source)], check=True)
            identity = dict(kind='test-c-fixture', source_files=[dict(
                path=str(source), sha256=sha(source))])
            original_which = shutil.which
            with mock.patch('native_signal_replay.shutil.which',
                            side_effect=lambda name: None if name == 'gdb' else original_which(name)):
                summary = replay_binary(binary, sha(binary),
                    dict(schema=1, argv=[], cwd=str(root), expect_signal='SIGSEGV',
                         timeout_seconds=5), identity, catalog_dir=root/'catalog',
                    capture_crash_site=True)
            self.assertIsNone(summary['crash_instruction'])
            self.assertEqual(summary['primary_site']['status'], 'captured')
            self.assertEqual(summary['primary_sites'], [summary['primary_site']])
            self.assertFalse(summary['external_state_complete'])
            self.assertEqual(summary['external_dependency_status'], 'not_captured')
            self.assertEqual(verify_receipt(summary['receipt'])['status'], 'verified')
            with Catalog(root/'catalog') as catalog:
                group = list(catalog.list_native_instruction_sites(signal='SIGSEGV'))[0]
            self.assertEqual(group['stable_site_key'], summary['primary_site']['stable_site_key'])
            self.assertFalse(group['representative']['external_state_complete'])

    def test_multiple_fatal_process_sites_are_all_retained(self):
        with tempfile.TemporaryDirectory(prefix='multiple-fault-control-') as directory:
            root = Path(directory)
            source, binary = root/'many.c', root/'many'
            source.write_text('''#include <unistd.h>
#include <sys/wait.h>
static int first(void) { volatile int *p = 0; return *p; }
static int second(void) { volatile int *p = 0; return *p; }
int main(void) {
    if (fork() == 0) return first();
    if (fork() == 0) return second();
    int status; wait(&status); wait(&status); return 0;
}
''')
            subprocess.run(['cc', '-g', '-O0', '-o', str(binary), str(source)], check=True)
            identity = dict(kind='test-c-fixture', source_files=[dict(
                path=str(source), sha256=sha(source))])
            summary = replay_binary(binary, sha(binary),
                dict(schema=1, argv=[], cwd=str(root), expect_signal='SIGSEGV',
                     timeout_seconds=5), identity, catalog_dir=root/'catalog',
                capture_crash_site=True)
            self.assertEqual(len(summary['signal_terminations']), 2)
            self.assertEqual(summary['primary_site']['status'], 'ambiguous')
            self.assertEqual(len(summary['primary_sites']), 2)
            self.assertEqual({row['status'] for row in summary['primary_sites']}, {'captured'})
            self.assertEqual(len({row['stable_site_key'] for row in summary['primary_sites']}), 2)
            self.assertEqual(verify_receipt(summary['receipt'])['status'], 'verified')
            with Catalog(root/'catalog') as catalog:
                groups = list(catalog.list_native_instruction_sites())
                self.assertEqual(len(groups), 2)
                self.assertEqual({row['stable_site_key'] for row in groups},
                                 {row['stable_site_key'] for row in summary['primary_sites']})
                self.assertEqual({row['representative']['pid'] for row in groups},
                                 {row['pid'] for row in summary['primary_sites']})
                self.assertEqual(list(catalog.list_pending_native_instruction_sites()), [])
                with self.assertRaisesRegex(RuntimeError, 'Multiple fatal native sites'):
                    catalog.add_native_instruction_site(summary)
                self.assertEqual(set(catalog.add_native_instruction_sites(summary)),
                                 {row['stable_site_key'] for row in summary['primary_sites']})

    def test_unavailable_faulting_module_is_cataloged_as_pending(self):
        with tempfile.TemporaryDirectory(prefix='deleted-module-fault-') as directory:
            root = Path(directory)
            plugin_source, plugin = root/'plugin.c', root/'plugin.so'
            source, binary = root/'main.c', root/'main'
            plugin_source.write_text('int plugin_fault(void) { volatile int *p = 0; return *p; }\n')
            source.write_text('''#include <dlfcn.h>
#include <unistd.h>
#include <sys/wait.h>
static int first(void) { volatile int *p = 0; return *p; }
int main(void) {
    if (fork() == 0) return first();
    if (fork() == 0) {
        void *module = dlopen("./plugin.so", RTLD_NOW);
        int (*fault)(void) = (int (*)(void)) dlsym(module, "plugin_fault");
        unlink("./plugin.so");
        return fault();
    }
    int status; wait(&status); wait(&status); return 0;
}
''')
            subprocess.run(['cc', '-g', '-O0', '-fPIC', '-shared', '-o', str(plugin),
                            str(plugin_source)], check=True)
            subprocess.run(['cc', '-g', '-O0', '-o', str(binary), str(source), '-ldl'],
                           check=True)
            identity = dict(kind='test-c-fixture', source_files=[
                dict(path=str(source), sha256=sha(source)),
                dict(path=str(plugin_source), sha256=sha(plugin_source))])
            summary = replay_binary(binary, sha(binary),
                dict(schema=1, argv=[], cwd=str(root), expect_signal='SIGSEGV',
                     timeout_seconds=5), identity, catalog_dir=root/'catalog',
                capture_crash_site=True)
            self.assertEqual(len(summary['primary_sites']), 2)
            self.assertEqual(verify_receipt(summary['receipt'])['status'], 'verified')
            with Catalog(root/'catalog') as catalog:
                groups = list(catalog.list_native_instruction_sites(signal='SIGSEGV'))
                pending = list(catalog.list_pending_native_instruction_sites('SIGSEGV'))
            self.assertEqual(len(groups), 1)
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0]['status'], 'not_captured')
            self.assertIn('unavailable', pending[0]['reason'])
            self.assertFalse(pending[0]['external_state_complete'])

            # A single undecodable fatal PID must also be visible in the catalog.
            single_source, single_binary = root/'single.c', root/'single'
            single_source.write_text('''#include <dlfcn.h>
#include <unistd.h>
int main(void) {
    void *module = dlopen("./plugin.so", RTLD_NOW);
    int (*fault)(void) = (int (*)(void)) dlsym(module, "plugin_fault");
    unlink("./plugin.so"); return fault();
}
''')
            subprocess.run(['cc', '-g', '-O0', '-fPIC', '-shared', '-o', str(plugin),
                            str(plugin_source)], check=True)
            subprocess.run(['cc', '-g', '-O0', '-o', str(single_binary), str(single_source),
                            '-ldl'], check=True)
            single_identity = dict(kind='test-c-fixture', source_files=[
                dict(path=str(single_source), sha256=sha(single_source)),
                dict(path=str(plugin_source), sha256=sha(plugin_source))])
            single = replay_binary(single_binary, sha(single_binary),
                dict(schema=1, argv=[], cwd=str(root), expect_signal='SIGSEGV',
                     timeout_seconds=5), single_identity, catalog_dir=root/'single-catalog',
                capture_crash_site=True)
            self.assertEqual(len(single['primary_sites']), 1)
            self.assertEqual(single['primary_site']['status'], 'not_captured')
            self.assertEqual(verify_receipt(single['receipt'])['status'], 'verified')
            with Catalog(root/'single-catalog') as catalog:
                self.assertEqual(list(catalog.list_native_instruction_sites()), [])
                pending = list(catalog.list_pending_native_instruction_sites('SIGSEGV'))
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0]['pid'], single['primary_site']['pid'])

    def test_thread_group_termination_does_not_hide_faulting_thread(self):
        with tempfile.TemporaryDirectory(prefix='thread-fault-control-') as directory:
            root = Path(directory)
            source, binary = root/'thread.c', root/'thread'
            source.write_text('''#include <pthread.h>
#include <unistd.h>
static void *worker(void *unused) {
    (void)unused; volatile int *p = 0; return (void *)(long)*p;
}
int main(void) {
    pthread_t thread; pthread_create(&thread, 0, worker, 0);
    for (;;) sleep(1);
}
''')
            subprocess.run(['cc', '-g', '-O0', '-pthread', '-o', str(binary), str(source)],
                           check=True)
            identity = dict(kind='test-c-fixture', source_files=[dict(
                path=str(source), sha256=sha(source))])
            summary = replay_binary(binary, sha(binary),
                dict(schema=1, argv=[], cwd=str(root), expect_signal='SIGSEGV',
                     timeout_seconds=5), identity, catalog_dir=root/'catalog',
                capture_crash_site=True)
            self.assertEqual(verify_receipt(summary['receipt'])['status'], 'verified')
            fatal = [site for site in summary['primary_sites']
                     if site.get('si_code') == 'SEGV_MAPERR']
            self.assertEqual(len(fatal), 1)
            self.assertEqual(fatal[0]['status'], 'captured')
            self.assertEqual(summary['primary_site'], fatal[0])
            with Catalog(root/'catalog') as catalog:
                groups = list(catalog.list_native_instruction_sites(signal='SIGSEGV'))
                pending = list(catalog.list_pending_native_instruction_sites('SIGSEGV'))
            self.assertIn(fatal[0]['stable_site_key'],
                          {group['stable_site_key'] for group in groups})
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0]['reason'],
                             'trace lacks terminating signal delivery')

    def test_handled_delivery_before_fatal_fault_keeps_fatal_site(self):
        with tempfile.TemporaryDirectory(prefix='handled-before-fault-') as directory:
            root = Path(directory)
            source, binary = root/'two.c', root/'two'
            source.write_text('''#include <signal.h>
static void handler(int number) { (void)number; signal(SIGSEGV, SIG_DFL); }
int main(void) {
    signal(SIGSEGV, handler); raise(SIGSEGV);
    volatile int *p = 0; return *p;
}
''')
            subprocess.run(['cc', '-g', '-O0', '-o', str(binary), str(source)], check=True)
            identity = dict(kind='test-c-fixture', source_files=[dict(
                path=str(source), sha256=sha(source))])
            summary = replay_binary(binary, sha(binary),
                dict(schema=1, argv=[], cwd=str(root), expect_signal='SIGSEGV',
                     timeout_seconds=5), identity, catalog_dir=root/'catalog',
                capture_crash_site=True)
            self.assertEqual([row['si_code'] for row in summary['signal_deliveries']],
                             ['SI_TKILL', 'SEGV_MAPERR'])
            self.assertEqual(summary['primary_site']['si_code'], 'SEGV_MAPERR')
            self.assertEqual(summary['primary_site']['module_sha256'], sha(binary))
            with Catalog(root/'catalog') as catalog:
                groups = list(catalog.list_native_instruction_sites(signal='SIGSEGV'))
            self.assertEqual(groups[0]['stable_site_key'],
                             summary['primary_site']['stable_site_key'])
            self.assertTrue(groups[0]['representative']['causal_fault_pc_observed'])
            self.assertFalse(groups[0]['representative']['causal_fault_instruction_verified'])

    def test_debugger_selects_fatal_fault_after_handled_signal(self):
        with tempfile.TemporaryDirectory(prefix='handled-then-fault-control-') as directory:
            root = Path(directory)
            source, binary = root/'two.c', root/'two'
            source.write_text('''#include <signal.h>
static volatile sig_atomic_t seen;
static void handler(int number) { (void)number; seen = 1; signal(SIGSEGV, SIG_DFL); }
int main(void) {
    signal(SIGSEGV, handler);
    raise(SIGSEGV);
    if (seen) { volatile int *p = 0; return *p; }
    return 0;
}
''')
            subprocess.run(['cc', '-g', '-O0', '-o', str(binary), str(source)], check=True)
            identity = dict(kind='test-c-fixture', source_files=[dict(
                path=str(source), sha256=sha(source))])
            summary = replay_binary(binary, sha(binary),
                dict(schema=1, argv=[], cwd=str(root), expect_signal='SIGSEGV',
                     timeout_seconds=5), identity, catalog_dir=root/'catalog',
                capture_crash_site=True)
            self.assertTrue(summary['same_native_site_observed'])
            self.assertEqual(summary['primary_site']['si_code'], 'SEGV_MAPERR')
            self.assertEqual(summary['crash_instruction']['si_code'], 1)
            self.assertEqual(summary['crash_instruction']['signal_stop_count'], 2)
            self.assertEqual(verify_receipt(summary['receipt'])['status'], 'verified')

    def test_debugger_marker_after_binary_stdout_is_extracted(self):
        with tempfile.TemporaryDirectory(prefix='debugger-binary-prefix-') as directory:
            root = Path(directory)
            source, binary = root/'prefix.c', root/'prefix'
            source.write_text('''#include <unistd.h>
int main(void) {
    char zeros[65536] = {0};
    write(1, zeros, sizeof zeros);
    volatile int *p = 0; return *p;
}
''')
            subprocess.run(['cc', '-g', '-O0', '-o', str(binary), str(source)],
                           check=True)
            identity = dict(kind='test-c-fixture', source_files=[dict(
                path=str(source), sha256=sha(source))])
            summary = replay_binary(binary, sha(binary),
                dict(schema=1, argv=[], cwd=str(root), expect_signal='SIGSEGV',
                     timeout_seconds=5), identity, catalog_dir=root/'catalog',
                capture_crash_site=True)
            self.assertEqual(summary['crash_instruction']['status'], 'captured')
            self.assertEqual(summary['crash_instruction']['signal_stop_count'], 1)
            log = Path(summary['receipt']).parent/'debugger.log'
            self.assertIn(b'\x00'*1024, log.read_bytes())
            self.assertEqual(verify_receipt(summary['receipt'])['status'], 'verified')

    @unittest.skipUnless(platform.machine() == 'x86_64', 'x86-64 instruction fixture')
    def test_file_instruction_is_not_claimed_as_runtime_instruction(self):
        with tempfile.TemporaryDirectory(prefix='self-modifying-fault-') as directory:
            root = Path(directory)
            source, binary = root/'selfmod.c', root/'selfmod'
            source.write_text('''#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
__attribute__((noinline,naked)) int victim(void) {
    __asm__ volatile("xor %%eax, %%eax; xor %%eax, %%eax; ret" ::: "eax");
}
int main(void) {
    unsigned char *code = (unsigned char *)(void *)victim;
    long n = sysconf(_SC_PAGESIZE);
    void *page = (void *)((uintptr_t)code & ~((uintptr_t)n-1));
    if (mprotect(page, (size_t)n, PROT_READ|PROT_WRITE|PROT_EXEC)) return 2;
    code[2] = 0x8b; code[3] = 0x00;
    __builtin___clear_cache((char *)code, (char *)code+5);
    return victim();
}
''')
            subprocess.run(['cc', '-g', '-O0', '-fcf-protection=none', '-o',
                            str(binary), str(source)], check=True)
            identity = dict(kind='test-c-fixture', source_files=[dict(
                path=str(source), sha256=sha(source))])
            summary = replay_binary(binary, sha(binary),
                dict(schema=1, argv=[], cwd=str(root), expect_signal='SIGSEGV',
                     timeout_seconds=5), identity, catalog_dir=root/'catalog',
                capture_crash_site=True)
            primary = summary['primary_site']
            debugger = summary['crash_instruction']
            self.assertEqual(primary['si_code'], 'SEGV_MAPERR')
            self.assertEqual(primary['instruction_bytes'], '31c0')
            self.assertEqual(primary['instruction_byte_source'], 'mapped_elf_file')
            self.assertFalse(primary['runtime_instruction_bytes_verified'])
            self.assertEqual(debugger['instruction_bytes'], '8b00')
            self.assertFalse(summary['same_native_site_observed'])
            with Catalog(root/'catalog') as catalog:
                representative = list(catalog.list_native_instruction_sites())[0]
                self.assertTrue(representative['representative']['causal_fault_pc_observed'])
                self.assertFalse(representative['representative']
                                 ['causal_fault_instruction_verified'])

    def test_linked_native_observation_does_not_mutate_certificate(self):
        root = Path(__file__).resolve().parents[1]
        if not (root/'local/search/index/index.sqlite').is_file() or not (
                root/'local/models/current/manifest.json').is_file():
            self.skipTest('model archive and source index are local data')
        with tempfile.TemporaryDirectory(prefix='openssh-linked-replay-') as directory:
            root = Path(directory)
            catalog_path = root/'catalog'
            index = Index()
            try:
                rows = [row for row in index.find('ssh', section='funs', name='sshbuf_ptr')
                        if row['kind'] in ('Proc','Fun')]
                self.assertEqual(len(rows), 1)
                fragment = dict(target='ssh', section='funs', ordinal=rows[0]['ordinal'],
                                alias='Mapped.function')
            finally:
                index.close()
            query = dict(goal='Mapped.function.1 = Mapped.function.1',
                         fragments=[fragment], stop_after_first=True)
            with Job(root/'job', query, catalog=catalog_path) as job:
                for _ in range(30):
                    state = job.advance()
                    if state['status'] != 'searching':
                        break
                self.assertEqual(state['status'], 'proved', state)
                identity = job.db.execute('SELECT catalog_id FROM results').fetchone()[0]
            with Catalog(catalog_path) as catalog:
                prior = catalog.read(identity)['evidence']
            summary = replay_recipe(dict(schema=1, target='ssh', argv=['-V'],
                                         expect_signal='SIGSEGV'),
                                    catalog_dir=catalog_path, catalog_id=identity)
            with Catalog(catalog_path) as catalog:
                entry = catalog.read(identity)
            self.assertEqual(entry['evidence'], prior)
            self.assertEqual(entry['native_observations'], [summary])
            with Catalog(catalog_path) as catalog:
                with self.assertRaisesRegex(sqlite3.IntegrityError, 'immutable'):
                    catalog.db.execute('UPDATE native_observations SET payload=? WHERE id=?',
                                       ('changed', summary['id']))
            self.assertFalse(summary['expected_observed'])
            self.assertEqual(verify_receipt(summary['receipt'])['status'], 'verified')


class DebuggerCleanupSafetyTests(unittest.TestCase):
    """Use mocks or a sleeping stand-in; never start a debugger or native target."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='debugger-cleanup-',
                                                dir='/var/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.recipe = dict(argv=[],cwd=str(self.root),env={'LC_ALL':'C'},
                           timeout_seconds=5,expect_signal='SIGTERM')
        patcher = mock.patch('native_signal_replay.shutil.which',
                             return_value='/usr/bin/true')
        patcher.start()
        self.addCleanup(patcher.stop)

    def capture(self):
        return capture_crash_instruction(Path('/usr/bin/true'),self.recipe,
                                         b'',self.root)

    def test_launch_failure_removes_temporary_script(self):
        with mock.patch('native_signal_replay.subprocess.Popen',
                        side_effect=OSError('synthetic launch failure')):
            with self.assertRaisesRegex(OSError,'synthetic launch failure'):
                self.capture()
        self.assertFalse((self.root/'capture.gdb').exists())

    def test_error_and_cancellation_stop_and_reap_sleeping_standin(self):
        original_popen = subprocess.Popen
        for exception_type in (RuntimeError,KeyboardInterrupt):
            for cleanup_times_out in (False,True):
                with self.subTest(exception=exception_type.__name__,
                                  cleanup_times_out=cleanup_times_out):
                    failure = exception_type('synthetic communication failure')
                    launched = []

                    class StandIn:
                        def __init__(self, _command, **kwargs):
                            self.child = original_popen(['/usr/bin/sleep','60'],
                                                        **kwargs)
                            self.pid = self.child.pid
                            self.calls = 0
                            launched.append(self.child)

                        def communicate(self, *args, **kwargs):
                            self.calls += 1
                            if self.calls == 1:
                                raise failure
                            if self.calls == 2 and cleanup_times_out:
                                raise subprocess.TimeoutExpired('stand-in',2)
                            return self.child.communicate(*args,**kwargs)

                        def kill(self):
                            return self.child.kill()

                        def wait(self, *args, **kwargs):
                            return self.child.wait(*args,**kwargs)

                    try:
                        with mock.patch('native_signal_replay.subprocess.Popen',
                                        StandIn):
                            with self.assertRaises(exception_type) as caught:
                                self.capture()
                        self.assertIs(caught.exception,failure)
                        self.assertEqual(launched[0].returncode,-9)
                        with self.assertRaises(ProcessLookupError):
                            os.killpg(launched[0].pid,0)
                        self.assertFalse((self.root/'capture.gdb').exists())
                    finally:
                        for child in launched:
                            if child.poll() is None:
                                child.kill()
                            child.wait(timeout=5)
                            if child.stdin is not None:
                                child.stdin.close()

    def test_timeout_with_already_gone_group_still_removes_script(self):
        process = mock.Mock(pid=123456789)
        process.communicate.side_effect = [
            subprocess.TimeoutExpired('stand-in',5),(None,None)]
        with mock.patch('native_signal_replay.subprocess.Popen',return_value=process):
            with mock.patch('native_signal_replay.os.killpg',
                            side_effect=ProcessLookupError):
                result = self.capture()
        self.assertTrue(result['timed_out'])
        self.assertFalse((self.root/'capture.gdb').exists())

    def test_normal_completion_removes_script_without_signalling_a_group(self):
        process = mock.Mock()
        process.communicate.return_value = (None,None)
        with mock.patch('native_signal_replay.subprocess.Popen',return_value=process):
            with mock.patch('native_signal_replay.os.killpg') as kill_group:
                result = self.capture()
        self.assertEqual(result['status'],'not_captured')
        self.assertFalse(result['timed_out'])
        kill_group.assert_not_called()
        self.assertFalse((self.root/'capture.gdb').exists())


if __name__ == '__main__':
    unittest.main()
