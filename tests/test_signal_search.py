"""Real Lean-worker controls, including archived Core fragments; no semantic stubs."""
import json
import copy
import gzip
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from core_index import Index, ROWS, SCALARS
from common import WORKSPACE, sha
from entry_query import all_memory_access_queries, memory_access_query
from signal_search import Worker
from snapshot_module_cache import FORMAT, SnapshotModuleCache, cache_key, cache_location, valid_receipt
from search_job import Job
from signal_catalog import Catalog


def fixture_fragment(target='ssh', name='sshbuf_ptr', alias='Selected.record'):
    index = Index()
    try:
        rows = [row for row in index.find(target, section='funs', name=name)
                if row['kind'] in ('Proc','Fun')]
        if len(rows) != 1:
            raise AssertionError(f'Expected one exact test fixture: {target}/{name}')
        return dict(target=target, section='funs', ordinal=rows[0]['ordinal'], alias=alias)
    finally:
        index.close()


@unittest.skipUnless((WORKSPACE/'local/models/current/manifest.json').is_file(),
                     'requires the local OpenSSH model archive and Lean build')
class SearchWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='openssh-proof-worker-')
        cls.worker = Worker(cls.temporary.name)

    @classmethod
    def tearDownClass(cls):
        cls.worker.close()
        cls.temporary.cleanup()

    def start(self, goal):
        result = self.worker.request(dict(op='start', goal=goal))
        self.assertEqual(result['status'], 'open', result)
        return result['node']

    def step(self, node, tactic):
        return self.worker.request(dict(op='step', node=node, tactic=tactic))

    def job(self, path, query=None):
        if query is not None:
            query = dict(query, stop_after_first=True)
        return Job(path, query, catalog=Path(self.temporary.name)/'catalog')

    def test_arbitrary_predicate_and_input_witness(self):
        node = self.start('∃ input : Nat, input > 7 ∧ input < 9')
        result = self.step(node, 'exact ⟨8, by omega, by omega⟩')
        self.assertEqual(result['status'], 'proved', result)
        self.assertIn('proof', result)
        self.assertNotIn('sorryAx', result['axioms'])
        for goal, status in [('∃ input : Nat, input > 7 ∧ input < 9', 'proved'), ('False', 'error')]:
            replay = self.worker.request(dict(op='verify', goal=goal, proof=result['proof'],
                                              declarations=result['declarations']))
            self.assertEqual(replay['status'], status, replay)

    def test_failed_branch_does_not_damage_parent_or_sibling(self):
        parent = self.start('(True ∧ True) ∨ False')
        failed = self.step(parent, 'exact False.elim (by assumption)')
        self.assertEqual(failed['status'], 'error')
        branch = self.step(parent, 'left')
        self.assertEqual(branch['status'], 'open', branch)
        solved = self.step(branch['node'], 'exact ⟨True.intro, True.intro⟩')
        self.assertEqual(solved['status'], 'proved', solved)
        independent = self.step(parent, 'exact Or.inl ⟨True.intro, True.intro⟩')
        self.assertEqual(independent['status'], 'proved', independent)

    def test_admitted_goal_is_rejected(self):
        node = self.start('False')
        result = self.step(node, 'sorry')
        self.assertEqual(result['status'], 'error', result)

    def test_unresolved_query_and_nonproposition_rejected(self):
        for goal in ('Nat', '(_ : Nat) = 3'):
            result = self.worker.request(dict(op='start', goal=goal))
            self.assertEqual(result['status'], 'error', result)

    def test_real_model_record_is_a_typed_lean_term(self):
        index = Index()
        try:
            fragment = fixture_fragment(alias='Archived.sshbuf_ptr')
            metadata = self.worker.load(index, fragment['target'], fragment['section'],
                                        fragment['ordinal'], fragment['alias'])
            self.assertEqual(metadata['kind'], 'Proc')
            node = self.start('Archived.sshbuf_ptr.1 = Archived.sshbuf_ptr.1')
            self.assertEqual(self.step(node, 'rfl')['status'], 'proved')
            # Type checking must cover every persisted snapshot field, not only functions.
            for field in sorted(ROWS | SCALARS):
                row = index.db.execute('SELECT ordinal FROM fragments WHERE target=? AND section=? LIMIT 1',
                                       ('ssh', field)).fetchone()
                if row is not None:
                    self.worker.load(index, 'ssh', field, row[0], 'Archived.'+field)
        finally:
            index.close()

    def test_fragment_replacement_and_wrong_digest_rejected(self):
        path = Path(self.temporary.name)/'bad-fragment.json'
        path.write_text('null')
        result = self.worker.request(dict(op='load', section='main', name='Invalid.main',
                                         path=str(path), sha256='0'*64))
        self.assertEqual(result['status'], 'error', result)
        self.assertIn('hash mismatch', result['error'])

    def test_automatic_search_resumes_in_a_new_worker(self):
        path = Path(self.temporary.name)/'resume-job'
        query = dict(goal='∀ n : Nat, n = n', fragments=[
            fixture_fragment(alias='Selected.function')])
        with self.job(path, query) as job:
            first = job.advance()
            self.assertEqual(first['status'], 'searching')
            attempts = sum(first['attempts'].values())
        with self.job(path) as job:
            self.assertEqual(sum(job.status()['attempts'].values()), attempts)
            for _ in range(20):
                result = job.advance()
                if result['status'] != 'searching':
                    break
            self.assertEqual(result['status'], 'proved', result)
            evidence = json.loads(job.db.execute('SELECT evidence FROM results').fetchone()[0])
            self.assertIn('proof', evidence['result'])
            self.assertEqual(json.loads(evidence['identity']['fragments'])[0]['name'], 'sshbuf_ptr')
            self.assertEqual(evidence['source_mappings'], [])
        with self.job(path) as job:
            self.assertEqual(job.status()['status'], 'proved')
        with self.assertRaisesRegex(RuntimeError, 'changed'):
            self.job(path, dict(query, goal='False'))

    def test_goal_derived_constructor_choices(self):
        node = self.start('True ∨ False')
        response = self.worker.request(dict(op='choices', node=node))
        self.assertEqual(response['status'], 'choices', response)
        self.assertIn('apply Or.inl', response['tactics'])
        self.assertIn('apply Or.inr', response['tactics'])

    def test_indexed_semantic_rules_preserve_applicable_candidates(self):
        rules = ['SignalSearch.Memory.'+name for name in (
            'load_null', 'load_function', 'load_without_provenance',
            'store_null', 'store_function', 'store_without_provenance')]
        rules += ['Nat.add_comm', 'Bool.not_not']
        indexed = self.worker.request(dict(op='rules', names=rules))
        self.assertEqual(indexed['status'], 'indexed', indexed)
        node = self.start('SignalSearch.Memory.NullLoadQuery')
        for tactic in ('repeat intro', 'apply Exists.intro'):
            branch = self.step(node, tactic)
            self.assertEqual(branch['status'], 'open', branch)
            node = branch['node']
        response = self.worker.request(dict(op='choices', node=node, rule_set=indexed['rule_set']))
        self.assertEqual(response['status'], 'choices', response)
        self.assertLess(response['matching_rules'], response['rule_count'])
        applicable = []
        for rule in rules:
            tactic = 'apply '+rule
            if self.step(node, tactic)['status'] in ('open', 'proved'):
                applicable.append(tactic)
                self.assertIn(tactic, response['tactics'])
        self.assertIn('apply SignalSearch.Memory.load_null', applicable)

    def test_typed_operation_addresses_across_every_archived_binary(self):
        index = Index()
        try:
            targets = sorted(index.archive.data['models'])
            self.assertEqual(len(targets), 14)
            for target in targets:
                alias = 'Operations.'+target.replace('-', '_')
                fragment = fixture_fragment(target=target, alias=alias)
                metadata = self.worker.load(index, target, fragment['section'],
                                            fragment['ordinal'], alias)
                inspected = self.worker.sites(alias)
                selected = self.worker.sites(alias, ['load'])
                self.assertGreater(len(selected['sites']), 0, target)
                self.assertTrue(inspected['coverage_checked'], target)
                self.assertEqual(inspected['complete_node_count'], inspected['visited'], target)
                self.assertEqual(inspected['visited'], len(inspected['sites']))
                self.assertEqual(inspected['visited'], selected['visited'])
                addresses = [tuple(site['address']) for site in inspected['sites']]
                self.assertEqual(len(addresses), len(set(addresses)))
                _, raw = index.read(target, 'funs', metadata['ordinal'])
                pending, count = [json.loads(raw)], 0
                while pending:
                    value = pending.pop()
                    if isinstance(value, dict):
                        count += any(set(value) == {key} for key in ('Expr', 'Pexpr', 'Action'))
                        pending.extend(value.values())
                    elif isinstance(value, list):
                        pending.extend(value)
                self.assertEqual(inspected['visited'], count, target)
                site = selected['sites'][0]
                address = '['+', '.join(map(str, site['address']))+']'
                node = self.start('(SignalSearch.Operation.loadAt '+alias+' '+address+').isSome = true')
                self.assertEqual(self.step(node, 'rfl')['status'], 'proved', target)
                mapped = index.archive.source_map(target).resolve(dict(
                    artifact_sha256=metadata['artifact_sha256'],target=target,location=site['location']))
                self.assertIn('sshbuf.c', json.dumps(mapped))
                absent = self.start('(SignalSearch.Operation.loadAt '+alias+' [1000000]).isSome = true')
                self.assertEqual(self.step(absent, 'rfl')['status'], 'error')
        finally:
            index.close()

    def test_archived_load_has_conditional_local_fault_theorem(self):
        index = Index()
        try:
            fragment = fixture_fragment(target='ssh', alias='Potential.function')
            self.worker.load(index, fragment['target'], fragment['section'],
                             fragment['ordinal'], fragment['alias'])
            selected = self.worker.sites(fragment['alias'], ['load'])['sites']
            self.assertTrue(selected)
            address = '['+', '.join(map(str, selected[0]['address']))+']'
            goal = 'SignalSearch.Operation.NullLoadPotential '+fragment['alias']+' '+address
            node = self.start(goal)
            tactic = ('exact SignalSearch.Operation.nullLoadPotential_of_site '
                      +fragment['alias']+' '+address+' (by rfl)')
            result = self.step(node, tactic)
            self.assertEqual(result['status'], 'proved', result)
            self.assertNotIn('sorryAx', result['axioms'])
            replay = self.worker.request(dict(op='verify', goal=goal,
                proof=result['proof'], declarations=result['declarations']))
            self.assertEqual(replay['status'], 'proved', replay)
        finally:
            index.close()

    def test_archived_site_row_load_has_conditional_fault_theorem(self):
        index = Index()
        try:
            fragment = fixture_fragment(target='ssh', alias='Potential.siteFunction')
            self.worker.load(index, fragment['target'], fragment['section'],
                             fragment['ordinal'], fragment['alias'])
            selected = self.worker.sites(fragment['alias'], ['load'])['sites']
            self.assertTrue(selected)
            address = '['+', '.join(map(str, selected[0]['address']))+']'
            site = ('(SignalSearch.SiteRow.function "funs" '
                    +fragment['alias']+')')
            goal = 'SignalSearch.SiteFault.NullLoadPotential '+site+' '+address
            node = self.start(goal)
            tactic = ('exact SignalSearch.SiteFault.nullLoadPotential_of_site '
                      +site+' '+address+' (by rfl)')
            result = self.step(node, tactic)
            self.assertEqual(result['status'], 'proved', result)
            self.assertNotIn('sorryAx', result['axioms'])
        finally:
            index.close()

    def test_archived_global_store_has_conditional_fault_theorem(self):
        index = Index()
        try:
            alias = 'Potential.globalStore'
            self.worker.load(index, 'scp', 'globs', 0, alias)
            selected = self.worker.sites(alias, ['store'])['sites']
            self.assertTrue(selected)
            address = '['+', '.join(map(str, selected[0]['address']))+']'
            site = '(SignalSearch.SiteRow.global '+alias+')'
            goal = 'SignalSearch.SiteFault.NullStorePotential '+site+' '+address
            node = self.start(goal)
            tactic = ('exact SignalSearch.SiteFault.nullStorePotential_of_site '
                      +site+' '+address+' (by rfl)')
            result = self.step(node, tactic)
            self.assertEqual(result['status'], 'proved', result)
            self.assertNotIn('sorryAx', result['axioms'])
            replay = self.worker.request(dict(op='verify', goal=goal,
                proof=result['proof'], declarations=result['declarations']))
            self.assertEqual(replay['status'], 'proved', replay)
        finally:
            index.close()

    def test_catalog_retains_exact_source_mapping_for_referenced_fragment(self):
        path = Path(self.temporary.name)/'mapping-job'
        query = dict(goal='Mapped.function.1 = Mapped.function.1', fragments=[
            fixture_fragment(alias='Mapped.function')])
        with self.job(path, query) as job:
            for _ in range(20):
                state = job.advance()
                if state['status'] != 'searching':
                    break
            self.assertEqual(state['status'], 'proved', state)
            saved = job.db.execute('SELECT catalog_id FROM results').fetchone()[0]
            entry = job.catalog.read(saved)
            mappings = entry['evidence']['source_mappings']
            self.assertEqual(len(mappings), 1)
            self.assertEqual(mappings[0]['alias'], 'Mapped.function')
            self.assertIn('sshbuf.c', json.dumps(mappings))
            self.assertEqual(job.catalog.replay(saved)['status'], 'verified')

    def test_synthesize_a_faulting_pointer_from_actual_memory_semantics(self):
        path = Path(self.temporary.name)/'memory-query'
        with self.job(path, dict(goal='SignalSearch.Memory.NullLoadQuery',
                           rules=['SignalSearch.Memory.load_null'])) as job:
            for _ in range(200):
                state = job.advance()
                if state['status'] != 'searching':
                    break
            self.assertEqual(state['status'], 'proved', state)
            result = json.loads(job.db.execute('SELECT evidence FROM results').fetchone()[0])['result']
            self.assertIn('SignalSearch.Memory.load_null', result['references'])
            self.assertNotIn('sorryAx', result['axioms'])

    def test_catalog_is_automatic_replayable_and_enriched_after_discovery(self):
        catalog_path = Path(self.temporary.name)/'enumeration-catalog'
        with tempfile.TemporaryDirectory(prefix='openssh-discovery-control-') as path:
            # Two different witnesses must both survive. This tests catalog
            # mechanics, not discovery of an OpenSSH invocation or a signal.
            query = dict(goal='∃ n : Nat, n > 7', signal='test-predicate',
                         tactics=['exact ⟨8, by omega⟩', 'exact ⟨9, by omega⟩'])
            with Job(path, query, catalog=catalog_path) as job:
                for _ in range(40):
                    state = job.advance()
                    if state['discoveries'] >= 2:
                        break
                self.assertGreaterEqual(state['discoveries'], 2, state)
                self.assertEqual(state['status'], 'searching', state)
                rows = list(job.db.execute('SELECT * FROM results'))
                ids = {row['catalog_id'] for row in rows}
                self.assertNotIn(None, ids)
                self.assertGreaterEqual(len(ids), 2)
                first = json.loads(rows[0]['evidence'])
                repeated = copy.deepcopy(first)
                repeated['result']['node'] = 100000
                repeated['result']['elapsed_ns'] = 1
                self.assertEqual(job.catalog.insert(repeated), rows[0]['catalog_id'])
        # The search job no longer exists. Every certificate must be independently replayable.
        with Catalog(catalog_path) as catalog:
            for identity in ids:
                self.assertEqual(catalog.replay(identity)['status'], 'verified')
            identity = sorted(ids)[0]
            original = catalog.read(identity)
            self.assertEqual(original['importance'], dict(status='unassessed'))
            annotation = dict(importance=dict(level='low', rationale='Synthetic catalog test'),
                              interpretation='No OpenSSH behavior is asserted by this control.')
            catalog.enrich(identity, 'test-llm', annotation)
            enriched = catalog.read(identity)
            self.assertEqual(enriched['evidence'], original['evidence'])
            self.assertEqual(enriched['importance']['assessment'], annotation['importance'])
            self.assertEqual(len(enriched['enrichments']), 1)
            self.assertEqual(len(list(catalog.list('test-predicate'))), len(ids))
            with self.assertRaisesRegex(sqlite3.IntegrityError, 'immutable'):
                catalog.db.execute('UPDATE discoveries SET signal=? WHERE id=?', ('changed', identity))

    def test_catalog_outbox_recovers_after_interrupted_publication(self):
        path = Path(self.temporary.name)/'outbox-job'
        with self.job(path, dict(goal='True')) as job:
            with patch.object(job.catalog, 'insert', side_effect=OSError('catalog unavailable')):
                with self.assertRaisesRegex(OSError, 'unavailable'):
                    for _ in range(30):
                        job.advance()
            saved = job.db.execute('SELECT * FROM results').fetchone()
            self.assertIsNotNone(saved)
            self.assertIsNone(saved['catalog_id'])
        with self.job(path) as job:
            saved = job.db.execute('SELECT * FROM results').fetchone()
            self.assertIsNotNone(saved['catalog_id'])
            self.assertEqual(job.status()['status'], 'proved')
            self.assertEqual(job.catalog.replay(saved['catalog_id'])['status'], 'verified')

    def test_staged_entry_query_result_does_not_publish_as_signal(self):
        path = Path(self.temporary.name)/'staged-entry-job'
        with self.job(path, dict(goal='True', catalog_policy='staged')) as job:
            prior_discoveries = job.catalog.db.execute(
                'SELECT count(*) FROM discoveries').fetchone()[0]
            for _ in range(30):
                result = job.advance()
                if result['status'] != 'searching':
                    break
            self.assertEqual(result['status'], 'proved', result)
            self.assertIsNone(job.db.execute('SELECT catalog_id FROM results').fetchone()[0])
            self.assertEqual(job.catalog.db.execute(
                'SELECT count(*) FROM discoveries').fetchone()[0], prior_discoveries)
        with self.job(path) as job:
            self.assertEqual(job.status()['status'], 'proved')
            self.assertIsNone(job.db.execute('SELECT catalog_id FROM results').fetchone()[0])

    def test_complete_model_cannot_publish_without_site_promotion(self):
        path = Path(self.temporary.name)/'entry-publish-refusal'
        query = dict(goal='True', catalog_policy='publish',
                     snapshots=[dict(target='ssh', alias='Pinned.ssh')])
        with self.assertRaisesRegex(RuntimeError, 'remain staged'):
            self.job(path, query)


@unittest.skipUnless((WORKSPACE/'local/models/current/manifest.json').is_file(),
                     'requires the local OpenSSH model archive and Lean build')
class SavedSnapshotFixtureTests(unittest.TestCase):
    def test_model_cache_identity_ignores_unrelated_proof_builds(self):
        index = Index()
        try:
            builder = dict(source_sha256='1'*64,
                           executable_sha256='2'*64,
                           import_artifacts={'SnapshotImport.olean':'3'*64})
            cache = SnapshotModuleCache()
            with patch('snapshot_module_cache.checked_build',
                       return_value=(Path('/tmp/search-a'),
                                     dict(snapshot_builder=builder,
                                          executable_sha256='4'*64))):
                first = cache.identity(index, 'sftp-server', 'Pinned.sftp_server')
            with patch('snapshot_module_cache.checked_build',
                       return_value=(Path('/tmp/search-b'),
                                     dict(snapshot_builder=builder,
                                          executable_sha256='5'*64))):
                unrelated_proof_edit = cache.identity(
                    index, 'sftp-server', 'Pinned.sftp_server')
            self.assertEqual(cache_key(first), cache_key(unrelated_proof_edit))
            changed = copy.deepcopy(builder)
            changed['import_artifacts']['SnapshotImport.olean'] = '6'*64
            with patch('snapshot_module_cache.checked_build',
                       return_value=(Path('/tmp/search-b'),
                                     dict(snapshot_builder=changed,
                                          executable_sha256='5'*64))):
                semantic_edit = cache.identity(index, 'sftp-server',
                                               'Pinned.sftp_server')
            self.assertNotEqual(cache_key(first), cache_key(semantic_edit))
        finally:
            index.close()

    def test_cache_identity_uses_pinned_toolchain_profile_and_lean_binary(self):
        index = Index()
        try:
            identity = SnapshotModuleCache().identity(index, 'sftp-server',
                                                      'Pinned.sftp_server')
            toolchain = WORKSPACE/'work/toolchain-lock.json'
            lean = WORKSPACE/'work/lean-4.32.2-linux/bin/lean'
            pinned = json.loads(toolchain.read_bytes())['files'][str(lean)]['sha256']
            self.assertEqual(identity['toolchain_sha256'], sha(toolchain))
            self.assertEqual(identity['lean_executable_sha256'], pinned)
            self.assertEqual(sha(lean), pinned)
        finally:
            index.close()

    def test_small_exact_format_import_and_entry_theorem(self):
        with tempfile.TemporaryDirectory(prefix='openssh-small-snapshot-') as directory:
            index = Index()
            try:
                all_queries = list(all_memory_access_queries(index))
                self.assertEqual(len(all_queries), len(index.archive.data['models']))
                self.assertEqual({q['snapshots'][0]['target'] for q in all_queries},
                                 set(index.archive.data['models']))
                self.assertTrue(all(q['catalog_policy'] == 'staged' for q in all_queries))
                header = json.loads(index.model('sftp-server')['header'])
                snapshot = {section: [] for section in ROWS}
                for section in SCALARS:
                    snapshot[section] = json.loads(index.read('sftp-server', section, 0)[1])
                artifact = dict(header, linkedFunctionCount=0, linkedGlobalCount=0,
                                snapshot=snapshot)
                path = Path(directory)/'synthetic.json.gz'
                path.write_bytes(gzip.compress(json.dumps(artifact,
                    separators=(',', ':')).encode(), mtime=0))
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                query = memory_access_query(index, 'sftp-server')
                alias = query['snapshots'][0]['alias']
                with Worker(directory) as worker:
                    wrong = worker.request(dict(op='load_snapshot', name='Fixture.wrong',
                        path=str(path), sha256='0'*64))
                    self.assertEqual(wrong['status'], 'error', wrong)
                    loaded = worker.request(dict(op='load_snapshot', name=alias,
                        path=str(path), sha256=digest))
                    self.assertEqual(loaded['status'], 'snapshot-loaded', loaded)
                    cache_root = Path(directory)/'snapshot-cache'
                    module, olean = cache_location(cache_root, dict(fixture=digest))
                    olean.parent.mkdir(parents=True)
                    generated = worker.request(dict(op='start', goal=query['goal']))
                    self.assertEqual(generated['status'], 'open', generated)
                    goal = ('∀ [LemFuel] [CerbGlobal.Switches] '
                            '(supply : Nat) (top : Int) (digest : String) '
                            '(fs : CerbFS.FsState) (wanted : kill_reason driver_error → Prop), '
                            'SignalSearch.CoreExecution.IndexedFaultFromEntry '
                            + alias + '.core supply top digest fs wanted → '
                            'SignalSearch.CoreExecution.ReachedRoundFaultFromEntry '
                            + alias + '.core supply top digest fs wanted')
                    node = worker.request(dict(op='start', goal=goal))
                    self.assertEqual(node['status'], 'open', node)
                    intro = worker.request(dict(op='step', node=node['node'],
                        tactic='intro _ _ supply top digest fs wanted candidate'))
                    self.assertEqual(intro['status'], 'open', intro)
                    proof = worker.request(dict(op='step', node=intro['node'], tactic=(
                        'exact SignalSearch.CoreExecution.IndexedFaultFromEntry.sound '
                        + alias + '.core supply top digest fs wanted candidate')))
                    self.assertEqual(proof['status'], 'proved', proof)
                    self.assertNotIn('sorryAx', proof['axioms'])
                    selected_goal = (
                        '∀ [LemFuel] [CerbGlobal.Switches] '
                        '(site : SignalSearch.SiteRow) (address : List Nat) '
                        '(location : CerbLocation.Loc) '
                        '(kind : SignalSearch.SelectedRequestFault.AccessKind) '
                        '(before after : driver_state) (choices : List Nat) '
                        '(reason : kill_reason driver_error) (trace : List String), '
                        'SignalSearch.SelectedRequestFault.SelectedInitialActionFault '
                        + alias + '.core site address location kind before choices '
                        'after reason trace → '
                        'SignalSearch.CoreExecution.RoundFault '+alias+
                        '.core before reason trace after ∧ '
                        'SignalSearch.SelectedRequestFault.accessReason kind reason')
                    selected_node = worker.request(dict(op='start', goal=selected_goal))
                    self.assertEqual(selected_node['status'], 'open', selected_node)
                    selected_intro = worker.request(dict(op='step',
                        node=selected_node['node'], tactic=(
                        'intro _ _ site address location kind before after choices reason trace certificate')))
                    self.assertEqual(selected_intro['status'], 'open', selected_intro)
                    selected_proof = worker.request(dict(op='step',
                        node=selected_intro['node'], tactic=(
                        'exact SignalSearch.SelectedRequestFault.SelectedInitialActionFault.sound '
                        + alias + '.core site address location kind before choices '
                        'after reason trace certificate')))
                    self.assertEqual(selected_proof['status'], 'proved', selected_proof)
                    self.assertNotIn('sorryAx', selected_proof['axioms'])
                    print(json.dumps(dict(fixture_import=loaded['timing'],
                        entry_query_ns=generated['elapsed_ns'],
                        theorem_start_ns=node['elapsed_ns'],
                        theorem_intro_ns=intro['elapsed_ns'],
                        theorem_proof_ns=proof['elapsed_ns'])), flush=True)
                with Worker(Path(directory)/'minimal-builder',
                            role='snapshot-builder') as builder:
                    minimal = builder.request(dict(op='load_snapshot', name=alias,
                        path=str(path), sha256=digest))
                    self.assertEqual(minimal['status'], 'snapshot-loaded', minimal)
                    written = builder.request(dict(op='write_snapshot_module',
                        module=module, name=alias, path=str(olean)))
                    self.assertEqual(written['status'], 'snapshot-module-written', written)
                    self.assertGreater(olean.stat().st_size, 0)
                cached_directory = Path(directory)/'cached-worker'
                try:
                    cached_worker = Worker(cached_directory, modules=[module],
                                           lean_path=[cache_root])
                except BaseException as error:
                    stderr = (cached_directory/'worker.stderr').read_text()
                    raise AssertionError('Cached module import failed: '+stderr) from error
                with cached_worker as cached:
                    selected = cached.request(dict(op='use_snapshot', name=alias))
                    self.assertEqual(selected['status'], 'snapshot-in-use', selected)
                    warm = cached.request(dict(op='start', goal=query['goal']))
                    self.assertEqual(warm['status'], 'open', warm)
                    print(json.dumps(dict(cached_entry_query_ns=warm['elapsed_ns'])),
                          flush=True)
            finally:
                index.close()

    def test_cache_receipt_rejects_changed_identity_and_bytes(self):
        with tempfile.TemporaryDirectory(prefix='openssh-cache-receipt-') as directory:
            identity = dict(module_format=FORMAT, target='synthetic', artifact_sha256='a'*64,
                            archive_manifest_sha256='b'*64, binding_path='/synthetic.json',
                            binding_sha256='c'*64, translator_path='/translator',
                            translator_sha256='d'*64, declaration_name='Pinned.synthetic',
                            builder_dependencies_sha256='e'*64, toolchain_sha256='f'*64)
            identity['lean_executable_sha256'] = '0'*64
            module, path = cache_location(directory, identity)
            path.parent.mkdir(parents=True)
            path.write_bytes(b'fixture olean bytes')
            receipt_path = path.with_suffix('.json')
            receipt = dict(schema=FORMAT, identity=identity, key=cache_key(identity),
                           module=module, declaration=identity['declaration_name'],
                           olean_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                           olean_bytes=path.stat().st_size)
            receipt_path.write_text(json.dumps(receipt))
            self.assertTrue(valid_receipt(path, receipt_path, identity, module))
            for field in identity:
                changed = dict(identity, **{field: 'changed'})
                self.assertFalse(valid_receipt(path, receipt_path, changed, module), field)
            self.assertFalse(valid_receipt(path, receipt_path, identity, module+'.changed'))
            for field in ('schema', 'key', 'declaration', 'olean_sha256', 'olean_bytes'):
                changed = dict(receipt, **{field: 'changed'})
                receipt_path.write_text(json.dumps(changed))
                self.assertFalse(valid_receipt(path, receipt_path, identity, module), field)
            receipt_path.write_text('[]')
            self.assertFalse(valid_receipt(path, receipt_path, identity, module))
            receipt_path.write_text(json.dumps(receipt))
            path.write_bytes(path.read_bytes()+b'tamper')
            self.assertFalse(valid_receipt(path, receipt_path, identity, module))


if __name__ == '__main__':
    unittest.main()
