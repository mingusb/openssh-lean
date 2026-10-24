"""Native instruction-site catalog controls with real C signal observations."""
import base64
from contextlib import closing
import copy
import hashlib
import json
import os
import shutil
import sqlite3
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from common import WORKSPACE, sha
from native_signal_replay import replay_binary
from native_reproducer import render_reproducer_script
from native_depth_search import check_profile
from signal_catalog import (Catalog, DEFAULT, encoded_input_identity, packed,
                            pinned_recursive_frame_count,
                            pinned_signal_delivery, repeated_input_identity)


class NativeInstructionSiteCatalog(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='native-site-catalog-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root/'fault.c'
        self.binary = self.root/'fault'
        self.source.write_text('''int main(int argc, char **argv) {
    (void)argv;
    if (argc > 1) {
        volatile int *p = 0;
        return *p;
    }
    return 0;
}
''')
        subprocess.run(['cc', '-g', '-O0', '-o', str(self.binary), str(self.source)],
                       check=True)
        self.catalog_path = self.root/'catalog'
        self.source_identity = dict(kind='test-c-fixture', source_files=[dict(
            path=str(self.source), sha256=sha(self.source))])
        self.recipe = dict(schema=1, argv=['fault'], cwd=str(self.root),
                           expect_signal='SIGSEGV', timeout_seconds=5)

    def observe_fault(self):
        return replay_binary(self.binary, sha(self.binary), self.recipe,
                             self.source_identity, catalog_dir=self.catalog_path,
                             capture_crash_site=True)

    def test_repeated_machine_site_is_grouped_without_collapsing_receipts(self):
        first, second = self.observe_fault(), self.observe_fault()
        self.assertNotEqual(first['id'], second['id'])
        key = first['crash_instruction']['stable_site_key']
        self.assertEqual(second['crash_instruction']['stable_site_key'], key)
        with Catalog(self.catalog_path) as catalog:
            self.assertEqual(catalog.add_native_instruction_site(first), key)
            self.assertEqual(catalog.add_native_instruction_site(second), key)
            self.assertEqual(catalog.add_native_instruction_site(first), key)
            groups = list(catalog.list_native_instruction_sites())
            self.assertEqual(len(groups), 1)
            group = groups[0]
            self.assertEqual(group['stable_site_key'], key)
            self.assertEqual(group['signal'], 'SIGSEGV')
            self.assertEqual(group['observation_count'], 2)
            self.assertEqual(group['representative_receipt'], second['receipt'])
            self.assertEqual(group['representative_receipt_sha256'],
                             second['receipt_sha256'])
            self.assertTrue(group['representative']['observed_delivery'])
            self.assertTrue(group['representative']['terminated_by_signal'])
            self.assertEqual(group['representative']['site_role'],
                             'corroborated_primary_fault_pc')
            self.assertTrue(group['representative']['cross_run_instruction_equivalence_observed'])
            self.assertEqual(group['representative']['primary_site']['module_offset'],
                             group['representative']['instruction']['file_offset'])
            self.assertTrue(group['representative']['causal_fault_pc_observed'])
            self.assertTrue(group['representative']['synchronous_fault_pc_observed'])
            self.assertFalse(group['representative']['causal_fault_instruction_verified'])
            self.assertFalse(group['representative']['runtime_instruction_bytes_verified'])
            self.assertEqual(group['representative']['instruction']['instruction_byte_source'],
                             'mapped_elf_file')
            self.assertEqual(group['representative']['instruction']['si_code'],
                             'SEGV_MAPERR')
            self.assertEqual(group['representative']['instruction']['fault_address'], 'NULL')
            self.assertEqual(group['representative']['instruction']
                             ['source_line_context']['status'], 'reported')
            self.assertGreater(group['representative']['debugger_instruction']['si_code'], 0)
            self.assertEqual(group['representative']['debugger_instruction']['fault_address'],
                             '0x0')
            self.assertFalse(group['representative']['cross_run_instruction_equivalence_proved'])
            self.assertFalse(group['representative']['exact_original_c_expression_verified'])
            self.assertEqual(len(list(catalog.list_native_instruction_sites(
                signal='SIGSEGV', stable_site_key=key))), 1)
            self.assertEqual(list(catalog.list_native_instruction_sites(signal='SIGILL')), [])
            rows = list(catalog.native_instruction_site_observations(key, 'SIGSEGV'))
            self.assertEqual({row['id'] for row in rows}, {first['id'], second['id']})
            self.assertEqual({row['receipt_sha256'] for row in rows},
                             {first['receipt_sha256'], second['receipt_sha256']})
            with self.assertRaisesRegex(sqlite3.IntegrityError, 'immutable'):
                catalog.db.execute('UPDATE native_instruction_sites SET signal=? WHERE id=?',
                                   ('SIGILL', first['id']))

    def test_summary_must_agree_with_hash_checked_receipt_and_instruction(self):
        summary = self.observe_fault()
        changes = (
            ('receipt_sha256', '0'*64),
            ('id', 'another-id'),
            ('expected_signal', 'SIGILL'),
            ('expected_observed', False),
            ('timed_out', True),
            ('same_native_site_observed', False),
            ('crash_instruction.status', 'not_captured'),
            ('crash_instruction.stable_site_key', '0'*64),
            ('crash_instruction.module_sha256', '0'*64),
            ('crash_instruction.mapping.file_offset', '0x0'),
            ('crash_instruction.instruction_bytes', '00'),
        )
        with Catalog(self.catalog_path) as catalog:
            baseline = list(catalog.list_native_instruction_sites())
            self.assertEqual(len(baseline), 1)
            for field, value in changes:
                with self.subTest(field=field):
                    altered = copy.deepcopy(summary)
                    target = altered
                    parts = field.split('.')
                    for part in parts[:-1]:
                        target = target[part]
                    target[parts[-1]] = value
                    with self.assertRaises(RuntimeError):
                        catalog.add_native_instruction_site(altered)
            self.assertEqual(list(catalog.list_native_instruction_sites()), baseline)
            catalog.add_native_instruction_site(summary)
            self.assertEqual(len(list(catalog.list_native_instruction_sites())), 1)

    def test_legacy_overclaim_is_not_selected_as_public_representative(self):
        summary = self.observe_fault()
        with Catalog(self.catalog_path) as catalog:
            current = list(catalog.list_native_instruction_sites())[0]['representative']
            legacy = copy.deepcopy(current)
            legacy['id'] = 'legacy-'+current['id']
            legacy['causal_fault_instruction_verified'] = True
            legacy.pop('causal_fault_pc_observed')
            legacy.pop('runtime_instruction_bytes_verified')
            legacy['instruction'].pop('instruction_byte_source')
            with catalog.db:
                catalog.db.execute('INSERT INTO native_instruction_sites VALUES(?,?,?,?,?)',
                    (legacy['id'], current['stable_site_key'], 'SIGSEGV', 0,
                     packed(legacy)))
            group = list(catalog.list_native_instruction_sites())[0]
            self.assertEqual(group['observation_count'], 2)
            self.assertEqual(group['current_observation_count'], 1)
            self.assertEqual(group['legacy_observation_count'], 1)
            self.assertEqual(group['representative_status'], 'current')
            self.assertEqual(group['representative']['id'], current['id'])
            self.assertFalse(group['representative']['causal_fault_instruction_verified'])
        with Catalog(self.root/'legacy-only') as catalog:
            with catalog.db:
                catalog.db.execute('INSERT INTO native_instruction_sites VALUES(?,?,?,?,?)',
                    (legacy['id'], current['stable_site_key'], 'SIGSEGV', 0,
                     packed(legacy)))
            group = list(catalog.list_native_instruction_sites())[0]
            self.assertEqual(group['representative_status'],
                             'legacy_only_no_current_claim')
            self.assertIsNone(group['representative'])

    def test_handled_delivery_is_not_cataloged_as_fatal_instruction(self):
        source, binary = self.root/'handled.c', self.root/'handled'
        source.write_text('''#include <signal.h>
static void handler(int signal_number) { (void)signal_number; }
int main(void) { signal(SIGSEGV, handler); raise(SIGSEGV); return 0; }
''')
        subprocess.run(['cc', '-g', '-O0', '-o', str(binary), str(source)], check=True)
        identity = dict(kind='test-c-fixture', source_files=[dict(
            path=str(source), sha256=sha(source))])
        recipe = dict(schema=1, argv=[], cwd=str(self.root),
                      expect_signal='SIGSEGV', timeout_seconds=5)
        summary = replay_binary(binary, sha(binary), recipe, identity,
                                catalog_dir=self.catalog_path, trace_signals=True,
                                capture_crash_site=True)
        self.assertTrue(summary['expected_observed'])
        self.assertEqual(summary['signal_terminations'], [])
        with Catalog(self.catalog_path) as catalog:
            self.assertEqual(catalog.add_native_instruction_sites(summary), [])
            self.assertEqual(list(catalog.list_native_instruction_sites()), [])
            with self.assertRaisesRegex(RuntimeError, 'No decoded first-run fatal'):
                catalog.add_native_instruction_site(summary)

    def test_debugger_handled_parent_signal_cannot_name_child_fault(self):
        plugin_source, plugin = self.root/'plugin.c', self.root/'plugin.so'
        source, binary = self.root/'parent.c', self.root/'parent'
        plugin_source.write_text('int crash(void) { volatile int *p = 0; return *p; }\n')
        source.write_text('''#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <dlfcn.h>
static void handler(int number) { (void)number; }
int main(void) {
    signal(SIGSEGV, handler); raise(SIGSEGV);
    if (fork() == 0) {
        signal(SIGSEGV, SIG_DFL);
        void *module = dlopen("./plugin.so", RTLD_NOW);
        int (*fault)(void) = (int (*)(void)) dlsym(module, "crash");
        unlink("./plugin.so");
        return fault();
    }
    int status; wait(&status); return 0;
}
''')
        subprocess.run(['cc', '-g', '-O0', '-fPIC', '-shared', '-o', str(plugin),
                        str(plugin_source)], check=True)
        subprocess.run(['cc', '-g', '-O0', '-o', str(binary), str(source), '-ldl'],
                       check=True)
        identity = dict(kind='test-c-fixture', source_files=[dict(
            path=str(path), sha256=sha(path)) for path in (source, plugin_source)])
        summary = replay_binary(binary, sha(binary),
            dict(schema=1, argv=[], cwd=str(self.root), expect_signal='SIGSEGV',
                 timeout_seconds=5), identity, catalog_dir=self.catalog_path,
            capture_crash_site=True)
        self.assertEqual(len(summary['primary_sites']), 1)
        fatal = summary['primary_sites'][0]
        self.assertEqual(fatal['status'], 'not_captured')
        self.assertEqual(fatal['si_code'], 'SEGV_MAPERR')
        self.assertEqual(summary['crash_instruction']['status'], 'captured')
        self.assertLess(summary['crash_instruction']['si_code'], 0)
        with Catalog(self.catalog_path) as catalog:
            self.assertEqual(catalog.add_native_instruction_sites(summary), [])
            self.assertEqual(list(catalog.list_native_instruction_sites('SIGSEGV')), [])
            pending = list(catalog.list_pending_native_instruction_sites('SIGSEGV'))
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0]['pid'], fatal['pid'])
            with self.assertRaisesRegex(RuntimeError, 'No decoded first-run fatal'):
                catalog.add_native_instruction_site(summary)

    def test_last_of_several_forked_processes_faults(self):
        source, binary = self.root/'many.c', self.root/'many'
        source.write_text('''#include <unistd.h>
#include <sys/wait.h>
int main(void) {
    for (int i = 0; i < 6; i++) {
        if (fork() == 0) {
            if (i == 5) { volatile int *p = 0; return *p; }
            return 0;
        }
    }
    for (int i = 0; i < 6; i++) { int status; wait(&status); }
    return 0;
}
''')
        subprocess.run(['cc', '-g', '-O0', '-o', str(binary), str(source)], check=True)
        identity = dict(kind='test-c-fixture', source_files=[dict(
            path=str(source), sha256=sha(source))])
        summary = replay_binary(binary, sha(binary),
            dict(schema=1, argv=[], cwd=str(self.root), expect_signal='SIGSEGV',
                 timeout_seconds=5), identity, catalog_dir=self.catalog_path,
            capture_crash_site=True)
        self.assertEqual(len(summary['signal_terminations']), 1)
        self.assertEqual(summary['primary_site']['status'], 'captured')
        self.assertTrue(summary['primary_site']['instruction_bytes'])
        self.assertFalse(summary['same_native_site_observed'])
        with Catalog(self.catalog_path) as catalog:
            grouped = list(catalog.list_native_instruction_sites(signal='SIGSEGV'))
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]['stable_site_key'],
                         summary['primary_site']['stable_site_key'])
        self.assertTrue(grouped[0]['representative']['causal_fault_pc_observed'])
        self.assertFalse(grouped[0]['representative']['causal_fault_instruction_verified'])


class NativeCoreLinkIntegration(unittest.TestCase):
    CORE_SITE_SHA256 = '5b849417d044322bcac7180deb17649d6572bfa881e2fef3415d323ccd1c2aca'

    def test_same_named_foreign_module_frames_do_not_count(self):
        frames = [dict(module='/tmp/foreign.so', symbol='sink+0x1'),
                  dict(module='/tmp/foreign.so', symbol='sink+0x2'),
                  dict(module='/pinned/scp', symbol='sink+0x3')]
        self.assertEqual(pinned_recursive_frame_count(
            frames, 'sink', '/pinned/scp'), 1)

    def test_pinned_scp_recursive_call_link_preserves_evidence_boundaries(self):
        source = Path('work/reference-source/scp.c').resolve()
        observations = DEFAULT/'native-observations'
        if not source.is_file() or not observations.is_dir():
            self.skipTest('Pinned OpenSSH native observation is unavailable')
        selected = None
        for directory in observations.iterdir():
            receipt = directory/'receipt.json'
            if not receipt.is_file():
                continue
            saved = json.loads(receipt.read_bytes())
            site = saved['observation'].get('primary_site') or {}
            if (saved['recipe'].get('target') == 'scp' and
                    saved.get('linked_certificate') is None and
                    site.get('status') == 'captured' and
                    site.get('symbol', '').startswith('sink+') and
                    site.get('si_code') == 'SEGV_MAPERR' and
                    site.get('instruction_byte_source') == 'mapped_elf_file'):
                selected = receipt
                break
        if selected is None:
            self.skipTest('Pinned scp fatal-site receipt is unavailable')

        with tempfile.TemporaryDirectory(prefix='native-core-link-test-') as directory:
            catalog_dir = Path(directory)
            copied = catalog_dir/'native-observations'/selected.parent.name
            copied.parent.mkdir(parents=True)
            shutil.copytree(selected.parent, copied)
            receipt = copied/'receipt.json'
            site = json.loads(receipt.read_bytes())['observation']['primary_site']
            arguments = dict(receipt=receipt, receipt_sha256=sha(receipt),
                stable_site_key=site['stable_site_key'], target='scp',
                section='funs', ordinal=32142, address=None,
                site_kind='indirect-call', core_site_sha256=self.CORE_SITE_SHA256,
                source_file='scp.c', source_line=1865,
                source_sha256=sha(source), relation='causal_recursive_call',
                recursive_symbol='sink', min_recursive_frames=2)
            with Catalog(catalog_dir) as catalog:
                with self.assertRaisesRegex(RuntimeError, 'one decoded first-run fatal'):
                    catalog.add_native_core_link(**dict(arguments, stable_site_key='0'*64))
                identity = catalog.add_native_core_link(**arguments)
                record = catalog.read_native_core_link(identity)
                self.assertEqual(record['native']['fatal_pc'], site['pc'])
                self.assertEqual(record['compiler_dwarf_line']['reported'],
                                 site['source_line_context'])
                self.assertEqual(record['archived_core']['identity']['sha256'],
                                 self.CORE_SITE_SHA256)
                self.assertEqual(record['archived_core']['source_annotation_origin'],
                                 'inherited')
                self.assertFalse(record['archived_core']['own_source_location_verified'])
                context = record['archived_core']['original_c_line_context']
                self.assertEqual(context['line'], 1865)
                self.assertEqual(context['relationship'], 'inherited_context_only')
                self.assertGreaterEqual(record['relation']['observed_recursive_frames'], 2)
                self.assertFalse(record['proof_status']['lean_entry_reachability_proved'])
                self.assertFalse(record['proof_status']
                                 ['c_core_translation_preservation_proved'])
                self.assertEqual([identity], [item['id'] for item in
                    catalog.list_native_core_links(observation_id=selected.parent.name)])
                with self.assertRaisesRegex(sqlite3.IntegrityError, 'immutable'):
                    catalog.db.execute('UPDATE native_core_links SET relation=? WHERE id=?',
                                       ('false', identity))

            foreign_dir = catalog_dir/'foreign'
            foreign_copy = foreign_dir/'native-observations'/selected.parent.name
            foreign_copy.parent.mkdir(parents=True)
            shutil.copytree(selected.parent, foreign_copy)
            foreign_receipt = foreign_copy/'receipt.json'
            altered = json.loads(foreign_receipt.read_bytes())
            for delivery in altered['observation']['signal_deliveries']:
                if delivery.get('pid') == site['pid'] and \
                        delivery.get('signal') == 'SIGSEGV':
                    for frame in delivery['stack_frames']:
                        if frame['symbol'].partition('+')[0] == 'sink':
                            frame['module'] = '/tmp/foreign-sink.so'
            foreign_receipt.write_text(packed(altered)+'\n')
            foreign_args = dict(arguments, receipt=foreign_receipt,
                                receipt_sha256=sha(foreign_receipt))
            # Only the forged-trace test bypasses receipt verification, so the
            # recursive-frame check is exercised independently of trace hashing.
            with mock.patch('native_signal_replay.verify_receipt',
                            return_value=dict(id=altered['id'])):
                with Catalog(foreign_dir) as catalog:
                    with self.assertRaisesRegex(RuntimeError,
                            'recursive frames in the pinned executable'):
                        catalog.add_native_core_link(**foreign_args)


class NativeCoreLinkListing(unittest.TestCase):
    def test_three_legacy_and_three_current_links_select_current_by_default(self):
        with tempfile.TemporaryDirectory(prefix='native-core-link-listing-') as directory:
            old_ids, current_ids = [], []
            with Catalog(directory) as catalog:
                with catalog.db:
                    for number in range(3):
                        base = dict(schema=1,
                            kind='native-to-archived-core-source-link',
                            native=dict(observation_id=f'observation-{number}',
                                        stable_site_key=f'site-{number}'),
                            archived_core=dict(identity=dict(sha256=f'core-{number}')),
                            relation=dict(kind='causal_recursive_call',
                                          observed_recursive_frames=256))
                        current = copy.deepcopy(base)
                        current['relation'].update(
                            recursive_frame_module='/pinned/scp',
                            recursive_frame_module_sha256='a'*64)
                        for created, record, ids in (
                                (number*2, base, old_ids),
                                (number*2+1, current, current_ids)):
                            payload = packed(record)
                            identity = hashlib.sha256(payload.encode()).hexdigest()
                            ids.append(identity)
                            catalog.db.execute(
                                'INSERT INTO native_core_links VALUES(?,?,?,?,?,?,?)',
                                (identity, record['native']['observation_id'],
                                 record['native']['stable_site_key'],
                                 record['archived_core']['identity']['sha256'],
                                 record['relation']['kind'], created, payload))
                selected = list(catalog.list_native_core_links())
                history = list(catalog.list_native_core_links(include_history=True))
                self.assertEqual({row['id'] for row in selected}, set(current_ids))
                self.assertTrue(all(row['record_status'] == 'current'
                                    for row in selected))
                self.assertEqual(len(history), 6)
                self.assertEqual({row['id'] for row in history},
                                 set(old_ids+current_ids))
                self.assertEqual(catalog.read_native_core_link(old_ids[0])
                                 ['record_status'], 'legacy_module_unscoped')
                self.assertEqual(len(list(catalog.list_native_core_links(
                    observation_id='observation-0'))), 1)
                self.assertEqual(len(list(catalog.list_native_core_links(
                    observation_id='observation-0', include_history=True))), 2)


class NativeReproducerControls(unittest.TestCase):
    def test_portable_exports_rebuild_an_empty_catalog(self):
        identity = ('3be34d318643dccef7fe9215737fe49f2b93d4e12749b213b632b98a3533e987')
        if not (DEFAULT/'native-reproducer-records'/(identity+'.json')).is_file():
            self.skipTest('Portable scp reproducer is unavailable')
        with tempfile.TemporaryDirectory(prefix='native-catalog-import-') as root:
            mirror = Path(root)/'catalog'
            mirror.mkdir()
            for name in ('native-observation-assets', 'native-reproducer-assets',
                         'native-reproducer-records', 'native-reproducer-toolchains',
                         'native-reproducer-formal-links', 'source-call-witnesses',
                         'core-cabs-bridges'):
                shutil.copytree(DEFAULT/name, mirror/name)
            receipt_id = '8a20ff732a8a45d394af1fc800aab6be'
            source = DEFAULT/'native-observations'/receipt_id/'receipt.json'
            destination = mirror/'native-observations'/receipt_id
            destination.mkdir(parents=True)
            shutil.copyfile(source, destination/'receipt.json')
            self.assertFalse((mirror/'catalog.sqlite').exists())
            self.assertFalse((destination/'trace.326223').exists())
            self.assertFalse((mirror/'native-reproducer-obligations').exists())
            command = ['/usr/bin/bwrap', '--bind', '/', '/',
                       '--dev-bind', '/dev', '/dev', '--bind',
                       str(mirror), str(DEFAULT), '--', '/usr/bin/python3',
                       str(WORKSPACE/'search/signal_catalog.py'),
                       'import-native-reproducer', identity]
            completed = subprocess.run(command, cwd=WORKSPACE,
                env=dict(os.environ, PYTHONPATH=str(WORKSPACE/'search')),
                capture_output=True, text=True, timeout=360)
            self.assertEqual(completed.returncode, 0,
                             completed.stdout+completed.stderr)
            outcome = json.loads(completed.stdout)
            self.assertEqual(outcome['status'], 'imported_and_verified')
            self.assertEqual(outcome['id'], identity)
            self.assertEqual(len(outcome['formal_link_ids']), 1)
            self.assertTrue(outcome['instruction_site_keys'])
            self.assertTrue((mirror/'catalog.sqlite').is_file())
            self.assertTrue((destination/'trace.326223').is_file())
            with closing(sqlite3.connect(mirror/'catalog.sqlite')) as db:
                for table in ('native_core_links', 'native_reproducers',
                              'native_reproducer_toolchains',
                              'native_reproducer_formal_links',
                              'native_instruction_sites'):
                    self.assertGreater(db.execute(
                        'SELECT COUNT(*) FROM '+table).fetchone()[0], 0)

    def test_historical_replay_uses_parser_snapshot_after_source_revision(self):
        with Catalog(DEFAULT) as catalog:
            rows = list(catalog.list_native_reproducers(target='scp'))
            if not rows:
                self.skipTest('Generated pinned scp reproducer is unavailable')
            identity = rows[-1]['id']
        parser = WORKSPACE/'search/native_signal_replay.py'
        with tempfile.TemporaryDirectory(prefix='historical-parser-') as root:
            revised = Path(root)/'native_signal_replay.py'
            revised.write_bytes(parser.read_bytes()+b'\n# later parser revision\n')
            base = ['/usr/bin/bwrap', '--bind', '/', '/',
                    '--dev-bind', '/dev', '/dev', '--ro-bind',
                    str(revised), str(parser), '--', '/usr/bin/python3',
                    str(WORKSPACE/'search/signal_catalog.py')]
            env = dict(os.environ, PYTHONPATH=str(WORKSPACE/'search'))
            for operation in ('verify-native-reproducer',
                              'replay-native-reproducer'):
                completed = subprocess.run(base+[operation, identity],
                    cwd=WORKSPACE, env=env, capture_output=True,
                    text=True, timeout=120)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                outcome = json.loads(completed.stdout)
                self.assertEqual(outcome['id'], identity)
                self.assertEqual(outcome['status'],
                    'verified' if operation == 'verify-native-reproducer'
                    else 'fresh_sigsegv_reproduced')

    def test_replay_reports_new_crash_site_without_calling_it_same_site(self):
        class FinishedProcess:
            returncode = 0

            def __init__(self, marker):
                self.marker = marker

            def communicate(self, timeout=None):
                return 'REPRODUCED_SIGSEGV '+packed(self.marker)+'\n', ''

        record = dict(target='scp',
            replay=dict(command=['/usr/bin/bash', '/pinned/reproduce.sh'],
                        success_marker='REPRODUCED_SIGSEGV '),
            formal=dict(native_core_link_id=None),
            native=dict(observation_id='receipt',
                        fatal_sites=[dict(stable_site_key='a'*64)]))
        marker = dict(target='scp', signal='SIGSEGV', pc='0x1234',
                      module_path='/pinned/scp', file_offset='0x1234',
                      stable_site_key='b'*64, pinned_frames=1)
        with tempfile.TemporaryDirectory(prefix='native-reproducer-site-') as root:
            result = Path(root)/'search-result.json'
            result.write_text(packed(dict(reproducer_runtime=dict(
                trace_parser_sha256='a'*64))))
            record['assets'] = {'search-result': {'path': str(result)}}
            with Catalog(root) as catalog:
                with mock.patch.object(catalog, 'read_native_reproducer',
                                       return_value=record), \
                        mock.patch.object(catalog, '_load_parser_bundle',
                                          return_value=({}, False)), \
                        mock.patch('signal_catalog.subprocess.Popen',
                                   return_value=FinishedProcess(marker)):
                    replay = catalog.replay_native_reproducer('reproducer')
                    self.assertEqual(replay['status'], 'fresh_sigsegv_reproduced')
                    self.assertEqual(replay['site_relation'], 'new_site')
                    self.assertEqual(replay['fresh_site']['stable_site_key'], 'b'*64)
                    marker['stable_site_key'] = 'a'*64
                    same = catalog.replay_native_reproducer('reproducer')
                    self.assertEqual(same['site_relation'], 'cataloged_site')

    def test_foreign_descendant_sigsegv_is_not_an_openssh_reproducer(self):
        site = dict(pid=42, pc='0x400123', si_code='SEGV_MAPERR')
        row = dict(pid=42, signal='SIGSEGV', instruction_pointer='0x400123',
                   si_code='SEGV_MAPERR',
                   stack_frames=[dict(module='/usr/bin/python3')])
        observation = dict(signal_deliveries=[row])
        self.assertFalse(pinned_signal_delivery(observation, site, '/pinned/scp'))
        observation['signal_deliveries'].append(dict(
            row, stack_frames=[dict(module='/pinned/scp')], pid=43))
        self.assertFalse(pinned_signal_delivery(observation, site, '/pinned/scp'))
        observation['signal_deliveries'][-1]['pid'] = 42
        observation['signal_deliveries'][-1]['si_code'] = 'SEGV_ACCERR'
        self.assertFalse(pinned_signal_delivery(observation, site, '/pinned/scp'))
        observation['signal_deliveries'][-1]['si_code'] = 'SEGV_MAPERR'
        self.assertTrue(pinned_signal_delivery(observation, site, '/pinned/scp'))

    def test_repeated_input_matches_saved_recipe_without_materializing_it(self):
        prefix, record, suffix = b'prefix\0', b'D0700 0 x\n', b'E\n'
        profile = {name: base64.b64encode(value).decode() for name, value in (
            ('prefix_base64', prefix), ('record_base64', record),
            ('suffix_base64', suffix))}
        for depth in (0, 1, 20000):
            actual = prefix+record*depth+suffix
            self.assertEqual(repeated_input_identity(profile, depth),
                             dict(bytes=len(actual),
                                  sha256=hashlib.sha256(actual).hexdigest()))
            self.assertEqual(encoded_input_identity(
                base64.b64encode(actual).decode()),
                repeated_input_identity(profile, depth))

    def test_reproducer_records_are_append_only(self):
        with tempfile.TemporaryDirectory(prefix='native-reproducer-schema-') as root:
            with Catalog(root) as catalog:
                with catalog.db:
                    catalog.db.execute('INSERT INTO native_reproducers '
                        'VALUES(?,?,?,?,?,?,?)',
                        ('id', 'observation', 'scp', 'hash', None, 1, '{}'))
                with self.assertRaisesRegex(sqlite3.IntegrityError, 'immutable'):
                    catalog.db.execute('UPDATE native_reproducers SET target=? '
                                       'WHERE id=?', ('ssh', 'id'))
                with self.assertRaisesRegex(sqlite3.IntegrityError, 'immutable'):
                    catalog.db.execute('DELETE FROM native_reproducers WHERE id=?',
                                       ('id',))
                with catalog.db:
                    catalog.db.execute('INSERT INTO native_reproducer_formal_links '
                        'VALUES(?,?,?,?,?)',
                        ('formal', 'id', 'obligation', 1, '{}'))
                with catalog.db:
                    catalog.db.execute('INSERT INTO native_reproducer_toolchains '
                        'VALUES(?,?,?)', ('id', 'binding', '{}'))
                with self.assertRaisesRegex(sqlite3.IntegrityError, 'immutable'):
                    catalog.db.execute(
                        'UPDATE native_reproducer_toolchains SET binding_id=? '
                        'WHERE reproducer_id=?', ('other', 'id'))
                with self.assertRaisesRegex(sqlite3.IntegrityError, 'immutable'):
                    catalog.db.execute('DELETE FROM native_reproducer_toolchains '
                                       'WHERE reproducer_id=?', ('id',))
                with self.assertRaisesRegex(sqlite3.IntegrityError, 'immutable'):
                    catalog.db.execute(
                        'UPDATE native_reproducer_formal_links SET obligation_id=? '
                        'WHERE id=?', ('other', 'formal'))
                with self.assertRaisesRegex(sqlite3.IntegrityError, 'immutable'):
                    catalog.db.execute(
                        'DELETE FROM native_reproducer_formal_links WHERE id=?',
                        ('formal',))

    def test_parser_binding_export_cannot_select_another_bundle(self):
        with tempfile.TemporaryDirectory(prefix='native-parser-binding-') as root:
            with Catalog(root) as catalog:
                with catalog.db:
                    catalog.db.execute('INSERT INTO native_reproducers '
                        'VALUES(?,?,?,?,?,?,?)',
                        ('reproducer', 'observation', 'scp', 'hash', None, 1, '{}'))
                bundle = Path(root)/'bundle.json'
                bundle.write_text('{}\n')
                reference = catalog._bind_parser_bundle(
                    'reproducer', 'a'*64, bundle)
                tampered = json.loads(reference.read_bytes())
                tampered['bundle_sha256'] = 'b'*64
                reference.write_text(packed(tampered)+'\n')
                with self.assertRaisesRegex(RuntimeError,
                                            'binding differs from catalog'):
                    catalog._load_parser_bundle('reproducer', 'a'*64)

    def test_generated_scp_reproducer_has_checked_catalog_readback(self):
        with Catalog(DEFAULT) as catalog:
            rows = list(catalog.list_native_reproducers(target='scp'))
            if not rows:
                self.skipTest('Generated pinned scp reproducer is unavailable')
            record = catalog.read_native_reproducer(rows[-1]['id'])
            self.assertEqual(record['target'], 'scp')
            self.assertEqual(record['native']['signal'], 'SIGSEGV')
            self.assertTrue(record['native']['fatal_sites'])
            self.assertEqual(record['replay']['command'][0], '/usr/bin/bash')
            self.assertTrue(record['formal']
                            ['exact_cabs_original_c_expression_verified'])
            self.assertTrue(record['formal']
                            ['core_own_ancestor_cabs_region_verified'])
            self.assertFalse(record['formal']['lean_entry_to_signal_proved'])
            self.assertEqual(record['original_c']['text'],
                             'sink(1, vect, src)')
            formal_links = list(catalog.list_native_reproducer_formal_links(
                record['id']))
            if formal_links:
                self.assertEqual(record['latest_formal_link_id'],
                                 formal_links[-1]['id'])
            sources = record['assets']
            with tempfile.TemporaryDirectory(prefix='reproducer-tamper-') as root:
                tampered = Path(root)/'reproduce.sh'
                tampered.write_bytes(Path(sources['script']['path']).read_bytes()
                                     + b'\n# changed\n')
                with self.assertRaisesRegex(RuntimeError, 'deterministic'):
                    catalog.add_native_reproducer(
                        profile=Path(sources['profile']['source_path']),
                        search_result=Path(sources['search-result']['source_path']),
                        script=tampered,
                        native_core_link_id=record['formal']['native_core_link_id'],
                        source_call_witness_id=record['formal']
                            ['exact_cabs_call_witness_id'],
                        core_cabs_bridge_id=record['formal']['core_cabs_bridge_id'])

    def test_unlinked_native_witness_preserves_mapping_obligation(self):
        with Catalog(DEFAULT) as catalog:
            rows = list(catalog.list_native_reproducers(target='scp'))
            if not rows:
                self.skipTest('Generated pinned scp reproducer is unavailable')
            linked = catalog.read_native_reproducer(rows[-1]['id'])
            contents = {role: Path(asset['path']).read_bytes()
                        for role, asset in linked['assets'].items()}
            origins = {role: asset['source_path']
                       for role, asset in linked['assets'].items()}
            result = json.loads(contents['search-result'])
            result.pop('native_core_link_id', None)
            contents['search-result'] = packed(result).encode()+b'\n'
            contents['script'] = render_reproducer_script(
                check_profile(json.loads(contents['profile'])), result)
            unlinked = catalog._native_reproducer_record(
                contents, origins, None, None, None)
            self.assertIsNone(unlinked['formal']['native_core_link_id'])
            self.assertIsNone(unlinked['original_c']['source_context'])
            self.assertIn('Map native result to an archived Core and original-C site',
                          unlinked['formal']['obligations'])


if __name__ == '__main__':
    unittest.main()
