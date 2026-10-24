"""Native C control for a generated Bash crash reproducer."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from common import sha
from crash_reproducer import emit_reproducer
from native_signal_replay import replay_binary, replay_recipe


class CrashReproducerTests(unittest.TestCase):
    def test_multiple_fatal_sites_require_selection_and_reproduce_selected_site(self):
        with tempfile.TemporaryDirectory(prefix='multi-reproducer-control-') as directory:
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
            keys = {row['stable_site_key'] for row in summary['primary_sites']}
            self.assertEqual(len(keys), 2)
            output = root/'reproduce-one.sh'
            with self.assertRaisesRegex(RuntimeError, 'select one with --site-key'):
                emit_reproducer(summary['receipt'], output, require_openssh=False)
            selected = sorted(keys)[0]
            emitted = emit_reproducer(summary['receipt'], output,
                                      require_openssh=False, site_key=selected)
            replay = subprocess.run(['bash', str(output)], cwd=root,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(replay.returncode, 0, replay.stderr)
            self.assertEqual(emitted['native_site_key'], selected)
            self.assertIn(selected, replay.stdout)

    def test_forked_process_memory_fault_reproducer(self):
        with tempfile.TemporaryDirectory(prefix='forked-reproducer-control-') as directory:
            root = Path(directory)
            source, binary = root/'fork.c', root/'fork'
            source.write_text('''#include <unistd.h>
#include <sys/wait.h>
int main(void) {
    pid_t pid = fork();
    if (pid < 0) return 3;
    if (pid == 0) { volatile int *p = 0; return *p; }
    int status;
    waitpid(pid, &status, 0);
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
            self.assertTrue(summary['expected_observed'])
            self.assertEqual(len(summary['primary_sites']), 1)
            self.assertEqual(summary['primary_site']['status'], 'captured')
            self.assertEqual(summary['primary_site']['si_code'], 'SEGV_MAPERR')
            output = root/'reproduce-fork.sh'
            emitted = emit_reproducer(summary['receipt'], output, require_openssh=False)
            self.assertEqual(emitted['native_site_key'],
                             summary['primary_site']['stable_site_key'])
            replay = subprocess.run(['bash', str(output)], cwd=root,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(replay.returncode, 0, replay.stderr)
            self.assertIn(emitted['native_site_key'], replay.stdout)

    def test_thread_group_collateral_termination_does_not_hide_fault(self):
        with tempfile.TemporaryDirectory(prefix='threaded-reproducer-control-') as directory:
            root = Path(directory)
            source, binary = root/'thread.c', root/'thread'
            source.write_text('''#include <pthread.h>
static void *fault(void *unused) {
    (void)unused;
    volatile int *p = 0;
    return (void *)(long)*p;
}
int main(void) {
    pthread_t thread;
    if (pthread_create(&thread, 0, fault, 0) != 0) return 3;
    pthread_join(thread, 0);
    return 0;
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
            self.assertGreaterEqual(len(summary['primary_sites']), 2)
            self.assertEqual(summary['primary_site']['status'], 'captured')
            self.assertEqual(summary['primary_site']['si_code'], 'SEGV_MAPERR')
            output = root/'reproduce-thread.sh'
            emitted = emit_reproducer(summary['receipt'], output, require_openssh=False)
            replay = subprocess.run(['bash', str(output)], cwd=root,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(replay.returncode, 0, replay.stderr)
            self.assertIn(emitted['native_site_key'], replay.stdout)

    def test_deliberate_fatal_signal_is_not_a_memory_fault_reproducer(self):
        with tempfile.TemporaryDirectory(prefix='signal-reproducer-negative-') as directory:
            root = Path(directory)
            source, binary = root/'raise.c', root/'raise'
            source.write_text('#include <signal.h>\nint main(void) { raise(SIGSEGV); }\n')
            subprocess.run(['cc', '-g', '-O0', '-o', str(binary), str(source)], check=True)
            identity = dict(kind='test-c-fixture', source_files=[dict(
                path=str(source), sha256=sha(source))])
            summary = replay_binary(binary, sha(binary),
                dict(schema=1, argv=[], cwd=str(root), expect_signal='SIGSEGV'),
                identity, catalog_dir=root/'catalog', capture_crash_site=True)
            self.assertTrue(summary['same_native_site_observed'])
            self.assertLess(summary['crash_instruction']['si_code'], 0)
            output = root/'false-memory-fault.sh'
            with self.assertRaisesRegex(RuntimeError, 'synchronous C memory fault'):
                emit_reproducer(summary['receipt'], output, require_openssh=False)
            self.assertFalse(output.exists())

    def test_real_ssh_version_without_a_crash_cannot_emit_a_script(self):
        if not (Path(__file__).resolve().parents[1]/'local/models/current/manifest.json').is_file():
            self.skipTest('requires the local OpenSSH model archive')
        with tempfile.TemporaryDirectory(prefix='openssh-reproducer-negative-') as directory:
            root = Path(directory)
            summary = replay_recipe(dict(schema=1, target='ssh', argv=['-V'],
                                         expect_signal='SIGSEGV'), catalog_dir=root/'catalog')
            output = root/'false-reproducer.sh'
            with self.assertRaisesRegex(RuntimeError, 'fatal native SIGSEGV'):
                emit_reproducer(summary['receipt'], output)
            self.assertFalse(output.exists())

    def test_bash_script_reproduces_the_same_instruction(self):
        with tempfile.TemporaryDirectory(prefix='openssh-reproducer-control-') as directory:
            root = Path(directory)
            source, binary = root/'fault.c', root/'fault'
            source.write_text('''int main(int argc, char **argv) {
    if (argc > 1 && argv[1][0] == 'x') {
        volatile int *pointer = 0;
        return *pointer;
    }
    return 0;
}
''')
            subprocess.run(['cc', '-g', '-O0', '-o', str(binary), str(source)], check=True)
            identity = dict(kind='test-c-fixture', source_files=[dict(
                path=str(source), sha256=sha(source))])
            summary = replay_binary(binary, sha(binary),
                dict(schema=1, argv=['x'], cwd=str(root), env={'LC_ALL': 'C'},
                     timeout_seconds=5, expect_signal='SIGSEGV'),
                identity, catalog_dir=root/'catalog', capture_crash_site=True)
            with self.assertRaisesRegex(RuntimeError, 'pinned OpenSSH'):
                emit_reproducer(summary['receipt'], root/'open-ssh-only.sh')
            output = root/'reproduce.sh'
            emitted = emit_reproducer(summary['receipt'], output, require_openssh=False)
            self.assertEqual(emitted['native_site_key'],
                             summary['crash_instruction']['stable_site_key'])
            replay = subprocess.run(['bash', str(output)], cwd=root,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(replay.returncode, 0, replay.stderr)
            self.assertIn('Reproduced fatal SIGSEGV at native site', replay.stdout)
            self.assertIn(emitted['native_site_key'], replay.stdout)


if __name__ == '__main__':
    unittest.main()
