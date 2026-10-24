"""Derive native fault seeds automatically from verified catalog reproducers.

A native seed is an observed C invocation and a replay recipe. It is useful
input to entry-proof search, but it is not a Lean path witness. No program is
executed while deriving these seeds.
"""

import argparse
import fcntl
import hashlib
import json
from pathlib import Path
import re
import signal
import sqlite3
import zlib

from common import WORKSPACE, installed_path, need, sha
from model_archive import Archive
from native_fatal_reproducer import render_native_fatal_script
from native_reproducer import input_identity
from native_signal_replay import (check_invocation, parse_signal_traces,
                                  primary_fault_sites, verify_receipt)
from signal_catalog import Catalog


DEFAULT_ARCHIVE = WORKSPACE / 'local/models/current'
DEFAULT_CATALOG = WORKSPACE / 'local/search/catalog'
DEFAULT_STORE = WORKSPACE / 'local/search/native-entry-seeds'
SCHEMA = """
CREATE TABLE IF NOT EXISTS identity(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS seeds(
 id TEXT PRIMARY KEY,
 reproducer_id TEXT NOT NULL UNIQUE,
 target TEXT NOT NULL,
 signal TEXT NOT NULL,
 payload BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS seeds_target_signal ON seeds(target,signal,id);
CREATE TRIGGER IF NOT EXISTS immutable_seed_update BEFORE UPDATE ON seeds
 BEGIN SELECT RAISE(ABORT,'Native seed is immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_seed_delete BEFORE DELETE ON seeds
 BEGIN SELECT RAISE(ABORT,'Native seed is immutable'); END;
"""


def packed(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False)


def record_sha256(value):
    return hashlib.sha256(packed(value).encode('utf-8')).hexdigest()


def verified_asset_bytes(record, role):
    """Read exactly the versioned bytes already checked by the catalog."""
    asset = record['assets'][role]
    path = Path(asset['path'])
    need(path.is_absolute() and path.is_file() and not path.is_symlink(),
         'Reproducer asset is missing or is a symlink: ' + role)
    raw = path.read_bytes()
    need(len(raw) == asset['bytes'] and
         hashlib.sha256(raw).hexdigest() == asset['sha256'],
         'Reproducer asset changed during seed derivation: ' + role)
    return raw


def verified_asset(record, role):
    return json.loads(verified_asset_bytes(record, role))


def derive_seed(record, profile, result, archive):
    """Bind one observed invocation to the exact archived target and input."""
    need(record.get('schema') == 1 and
         record.get('kind') == 'generated-native-sigsegv-reproducer',
         'Unsupported catalog reproducer schema')
    target = record['target']
    need(target in archive.data['models'] and profile['target'] == target and
         result['target'] == target, 'Native seed target differs from archive')
    model = archive.model(target)
    binding = archive.read_json(model['binding_sha256'])
    native = record['native']
    binary = native['binary']
    pinned = binding['native_target']
    installed_binary = str(installed_path(pinned['path']))
    need(binding['target'] == target and
         binary == {'path': installed_binary, 'sha256': pinned['sha256']} and
         result['native_binary'] == installed_binary and
         result['native_binary_sha256'] == pinned['sha256'],
         'Native binary differs from archived translation input')
    need(Path(binary['path']).is_file() and
         sha(Path(binary['path'])) == binary['sha256'],
         'Pinned native binary changed')
    need(native['signal'] == profile['expect_signal'] == 'SIGSEGV' and
         record['search']['witness_depth'] == result['witness_depth'],
         'Reproducer signal or witness depth differs')
    depth = result['witness_depth']
    size, digest = input_identity(profile, depth)
    need(native['stdin'] == {'bytes': size, 'sha256': digest},
         'Native observed stdin differs from the reproducible input recipe')
    need(record['search']['profile_sha256'] ==
         record['assets']['profile']['sha256'] ==
         result['profile_sha256'], 'Native search profile identity differs')
    need(result['receipt']['id'] == native['observation_id'] and
         result['receipt']['receipt_sha256'] == native['receipt_sha256'],
         'Native observation identity differs')
    formal = record.get('formal') or {}
    core = formal.get('archived_core_candidate')
    if core is not None:
        need(core['target'] == target and
             core['archive_manifest_sha256'] == archive.manifest_sha256 and
             formal.get('native_core_link_id') is not None,
             'Core source hint belongs to a different archive or target')
    script = record['assets']['script']
    replay = record['replay']
    need(replay['command'][-1] == script['path'],
         'Native replay command differs from pinned script')
    seed = dict(
        schema=1,
        kind='verified-native-fault-seed',
        target=target,
        signal=native['signal'],
        archive_manifest_sha256=archive.manifest_sha256,
        model_artifact_sha256=model['artifact_sha256'],
        native_binary=binary,
        invocation=dict(argv=native['argv'], env=native['env'],
                        cwd=native['cwd']),
        stdin=dict(kind='repeated-record', prefix_base64=profile['prefix_base64'],
                   record_base64=profile['record_base64'],
                   suffix_base64=profile['suffix_base64'], depth=depth,
                   bytes=size, sha256=digest),
        replay=dict(command=replay['command'], script_path=script['path'],
                    script_sha256=script['sha256']),
        provenance=dict(
            catalog_reproducer_id=record['id'],
            observation_id=native['observation_id'],
            native_receipt_path=native['receipt'],
            native_receipt_sha256=native['receipt_sha256'],
            profile_sha256=record['assets']['profile']['sha256'],
            search_result_sha256=record['assets']['search-result']['sha256'],
            native_core_link_id=formal.get('native_core_link_id'),
            archived_core_site=core),
        scope=('Observed native C fault and replayable input. Lean entry '
               'reachability, model filesystem state, driver branch indices, '
               'and C/Core execution correspondence remain to be checked.'))
    return seed


def verified_generic_replay(observation, replays):
    """Choose the earliest checked Bash replay with an exact fatal fault PC."""
    for replay in sorted(replays, key=lambda row: (row['created_ns'],row['id'])):
        script = replay.get('script') or {}
        if (replay.get('reproducer_verified') and
                replay.get('exact_site_verified') and
                script.get('status') == 'reproduced' and
                script.get('pinned_target_attributed') is True and
                script.get('exact_pc_sites')):
            need(replay.get('observation_id') == observation['id'],
                 'Verified native replay belongs to another observation')
            return replay
    return None


def verify_generic_replay_evidence(record, replay):
    """Recheck saved trace bytes and the independent exact-PC receipt."""
    script = replay['script']
    capture = Path(script['capture_directory']).resolve(strict=True)
    need(capture.is_dir() and not capture.is_symlink(),
         'Verified Bash capture directory is unavailable')
    descriptions = script['capture_files']
    need(type(descriptions) is list and descriptions,
         'Verified Bash capture has no file inventory')
    described = set()
    for entry in descriptions:
        name = entry['name']
        need(type(name) is str and Path(name).name == name and
             name not in described,
             'Verified Bash capture has an unsafe file name')
        path = capture/name
        need(path.is_file() and not path.is_symlink() and
             path.stat().st_size == entry['bytes'] and
             sha(path) == entry['sha256'],
             'Verified Bash capture file changed: '+name)
        described.add(name)
    need({path.name for path in capture.iterdir()} == described,
         'Verified Bash capture inventory changed')
    deliveries, terminations, traces = parse_signal_traces(capture)
    need({row['file'] for row in traces} | {'stdout.bin','stderr.bin'} ==
         described,
         'Verified Bash signal trace inventory changed')
    terminal_deliveries = {}
    for row in deliveries:
        terminal_deliveries[(row['pid'],row['signal'])] = row
    fatal_pairs = set(terminal_deliveries) & {
        (row['pid'],row['signal']) for row in terminations}
    pinned = record['binary']
    pairs = {(pid,name) for pid,name in fatal_pairs
             if name == record['signal'] and
             any(frame.get('module') == pinned['path'] for frame in
                 terminal_deliveries[(pid,name)].get('stack_frames',[]))}
    need(pairs, 'Bash trace has no pinned-target fatal signal delivery')
    current_sites = [site for site in primary_fault_sites(
        deliveries,terminations,record['signal'])
        if (site.get('pid'),site.get('signal')) in pairs and
           site.get('status') == 'captured' and
           isinstance(site.get('module_sha256'),str)]
    need(current_sites and current_sites == script['exact_pc_sites'],
         'Bash exact PC sites differ from saved trace')
    exact = replay.get('exact_pc_replay') or {}
    if exact.get('status') == 'reproduced':
        need(exact.get('receipt_verified') is True,
             'Claimed independent replay has no verified receipt')
        receipt = verify_receipt(exact['receipt'],exact['receipt_sha256'])
        need(receipt['status'] == 'verified' and
             receipt['id'] == exact['receipt_id'],
             'Independent exact-PC receipt identity changed')
        separate_sites = [site for site in receipt['observation']['primary_sites']
                          if site.get('status') == 'captured' and
                          site.get('signal') == record['signal'] and
                          isinstance(site.get('module_sha256'),str)]
        need(separate_sites == exact['sites'],
             'Independent exact-PC replay sites differ from receipt')
        if replay.get('cross_run_same_site_observed'):
            need({site['stable_site_key'] for site in current_sites} &
                 {site['stable_site_key'] for site in separate_sites},
                 'Claimed same native site differs across the two replays')
    return current_sites


def derive_generic_seed(record, replay, archive):
    """Bind a verified literal-input crash to its archived native C target."""
    need(record.get('schema') == 1 and
         record.get('kind') == 'native-fatal-signal-observation' and
         replay.get('schema') == 1 and
         replay.get('kind') == 'native-fatal-replay-attempt' and
         replay.get('observation_id') == record['id'],
         'Unsupported generic native fatal evidence')
    replay_payload = {key: value for key, value in replay.items()
                      if key not in ('id','created_ns')}
    need(record_sha256(replay_payload) == replay['id'],
         'Generic native replay identity changed')
    target, signal_name = record['target'], record['signal']
    need(target in archive.data['models'] and
         signal_name in signal.Signals.__members__,
         'Generic native fatal target or signal is unknown')
    model = archive.model(target)
    binding = archive.read_json(model['binding_sha256'])
    pinned = binding['native_target']
    installed_binary = str(installed_path(pinned['path']))
    need(record['archive'] == dict(
            manifest_sha256=archive.manifest_sha256,
            model_artifact_sha256=model['artifact_sha256']) and
         binding['target'] == target and
         binding['openssh_commit'] == archive.data['openssh_commit'] and
         record['binary'] == {'path':installed_binary,
                              'sha256':pinned['sha256']} and
         Path(installed_binary).is_file() and
         sha(Path(installed_binary)) == pinned['sha256'],
         'Generic native fatal differs from archived binary/model/source')
    stdin = verified_asset_bytes(record,'stdin')
    script = verified_asset_bytes(record,'script')
    outcome = verified_asset_bytes(record,'outcome')
    for role in ('stdin','script','outcome'):
        need(record['assets'][role].get('role') == role,
             'Generic native asset role differs: '+role)
    recipe, recipe_stdin = check_invocation(record['first_run']['recipe'])
    need(recipe == record['first_run']['recipe'] and
         recipe['target'] == target and recipe['expect_signal'] is None and
         recipe_stdin == stdin and
         record['frontier']['outcome_sha256'] ==
         record['assets']['outcome']['sha256'] and
         hashlib.sha256(outcome).hexdigest() ==
         record['frontier']['outcome_sha256'],
         'Generic native literal input differs from its first observation')
    spec = record['script_spec']
    need(spec['target'] == target and spec['signal'] == signal_name and
         spec['binary'] == record['binary'] and spec['recipe'] == recipe and
         spec['stdin'] == record['assets']['stdin'] and
         spec['archive_manifest_sha256'] == archive.manifest_sha256 and
         spec.get('first_run_isolation') ==
         record['first_run'].get('isolation') and
         script == render_native_fatal_script(spec),
         'Generic native Bash reproducer differs from observed invocation')
    need(replay['reproducer_verified'] is True and
         replay['exact_site_verified'] is True and
         replay['script']['status'] == 'reproduced' and
         replay['script']['pinned_target_attributed'] is True,
         'Generic native fatal has no verified pinned-target replay')
    sites = verify_generic_replay_evidence(record,replay)
    site_keys = {site['stable_site_key'] for site in sites}
    source_link = replay.get('source_link') or {'status':'unmapped'}
    if source_link.get('status') == 'native-dwarf-line-mapped':
        source_root = (WORKSPACE/'work/reference-source').resolve(strict=True)
        inventory = archive.data['source_snapshot']['files']
        links = source_link.get('sites')
        need(type(links) is list and links,
             'Mapped C source link has no exact sites')
        for link in links:
            source = Path(link['source']).resolve(strict=True)
            need(source.is_relative_to(source_root) and
                 link['stable_site_key'] in site_keys and
                 link['module_sha256'] == pinned['sha256'] and
                 inventory.get(str(source.relative_to(source_root))) ==
                 link['source_sha256'] and sha(source) == link['source_sha256'],
                 'C source link does not match a pinned exact native site')
    else:
        need(source_link.get('status') == 'unmapped',
             'Unsupported C source-link status')
    script_asset = record['assets']['script']
    stdin_asset = record['assets']['stdin']
    return dict(
        schema=1, kind='verified-native-fault-seed', target=target,
        signal=signal_name,
        archive_manifest_sha256=archive.manifest_sha256,
        model_artifact_sha256=model['artifact_sha256'],
        model_binding_sha256=model['binding_sha256'],
        source_identity=dict(
            openssh_commit=archive.data['openssh_commit'],
            configuration_profile=archive.data['configuration_profile'],
            source_snapshot_inventory_sha256=archive.data['source_snapshot']
                                               ['inventory_sha256']),
        native_binary=record['binary'],
        invocation=dict(argv=recipe['argv'],env=recipe['env'],cwd=recipe['cwd']),
        stdin=dict(kind='literal-catalog-asset',path=stdin_asset['path'],
                   bytes=stdin_asset['bytes'],sha256=stdin_asset['sha256']),
        replay=dict(command=['/usr/bin/bash',script_asset['path']],
                    script_path=script_asset['path'],
                    script_sha256=script_asset['sha256'],
                    verified_replay_id=replay['id']),
        crash_sites=sites, source_link=source_link,
        provenance=dict(catalog_observation_id=record['id'],
                        catalog_replay_id=replay['id'],
                        frontier=record['frontier'],
                        outcome_asset_sha256=record['assets']['outcome']['sha256']),
        scope=('Bash-reproduced native C fatal signal at an exact module PC. '
               'A pinned OpenSSH C line is available only when source_link is '
               'mapped; Lean entry '
               'reachability and C/Core execution correspondence remain separate.'))


class SeedStore:
    def __init__(self, directory=DEFAULT_STORE, *,
                 catalog_dir=DEFAULT_CATALOG, archive_dir=DEFAULT_ARCHIVE):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.catalog_dir = Path(catalog_dir).resolve()
        self.archive_dir = Path(archive_dir).resolve()
        self.lock = (self.directory / 'seeds.lock').open('a')
        self.db = None
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.db = sqlite3.connect(self.directory / 'seeds.sqlite')
            self.db.row_factory = sqlite3.Row
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.executescript(SCHEMA)
        except BaseException:
            self.close()
            raise

    def _identity(self, archive):
        return dict(schema='1', catalog=str(self.catalog_dir),
                    archive=str(self.archive_dir),
                    archive_manifest_sha256=archive.manifest_sha256)

    def _check_identity(self, archive):
        wanted = self._identity(archive)
        prior = dict(self.db.execute('SELECT key,value FROM identity'))
        need(not prior or prior == wanted,
             'Native seed store belongs to another catalog or archive')
        if not prior:
            with self.db:
                self.db.executemany('INSERT INTO identity VALUES(?,?)',
                                    wanted.items())

    def sync(self, catalog_factory=Catalog, archive_factory=Archive):
        """Ingest every available verified reproducer with no target selector."""
        archive = archive_factory(self.archive_dir)
        self._check_identity(archive)
        inserted = 0
        with catalog_factory(self.catalog_dir) as catalog:
            for summary in catalog.list_native_reproducers():
                record = catalog.read_native_reproducer(summary['id'])
                profile = verified_asset(record, 'profile')
                result = verified_asset(record, 'search-result')
                seed = derive_seed(record, profile, result, archive)
                inserted += self._insert_seed(record['id'], seed)
            for record in catalog.list_native_fatal_observations():
                replay = verified_generic_replay(
                    record, list(catalog.list_native_fatal_replays(record['id'])))
                if replay is None:
                    continue
                seed = derive_generic_seed(record,replay,archive)
                inserted += self._insert_seed(record['id'],seed)
        return dict(inserted=inserted, **self.status())

    def _insert_seed(self, catalog_id, seed):
        identity = record_sha256(seed)
        payload = packed(seed).encode('utf-8')
        prior = self.db.execute(
            'SELECT id,payload FROM seeds WHERE reproducer_id=?',
            (catalog_id,)).fetchone()
        if prior is not None:
            need(prior['id'] == identity and
                 zlib.decompress(prior['payload']) == payload,
                 'Existing native seed differs from verified catalog evidence')
            return 0
        with self.db:
            self.db.execute('INSERT INTO seeds VALUES(?,?,?,?,?)',
                            (identity,catalog_id,seed['target'],seed['signal'],
                             zlib.compress(payload)))
        return 1

    def read(self, identity):
        need(isinstance(identity, str) and re.fullmatch(r'[0-9a-f]{64}', identity),
             'Native seed ID must be SHA-256')
        row = self.db.execute(
            'SELECT payload FROM seeds WHERE id=?', (identity,)).fetchone()
        need(row is not None, 'Unknown native seed')
        raw = zlib.decompress(row['payload'])
        seed = json.loads(raw)
        need(raw == packed(seed).encode('utf-8') and
             record_sha256(seed) == identity,
             'Native seed payload changed')
        if seed['stdin']['kind'] == 'literal-catalog-asset':
            for key, expected in (('stdin',seed['stdin']),
                                  ('script',dict(path=seed['replay']['script_path'],
                                                 sha256=seed['replay']['script_sha256']))):
                path = Path(expected['path'])
                need(path.is_file() and not path.is_symlink() and
                     sha(path) == expected['sha256'] and
                     (key != 'stdin' or path.stat().st_size == expected['bytes']),
                     'Native seed literal '+key+' asset changed')
        return seed

    def ids(self):
        """Enumerate every persisted seed in stable order for autonomous work."""
        return tuple(row[0] for row in self.db.execute(
            'SELECT id FROM seeds ORDER BY target,signal,id'))

    def status(self):
        rows = [dict(target=target, signal=sig, count=count)
                for target, sig, count in self.db.execute(
                    'SELECT target,signal,count(*) FROM seeds '
                    'GROUP BY target,signal ORDER BY target,signal')]
        return dict(kind='native-seed-inventory', count=sum(r['count'] for r in rows),
                    by_target_signal=rows,
                    scope='Native C fault seeds; no Lean entry reachability claim')

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.lock is not None:
            self.lock.close()
            self.lock = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('sync', 'status', 'read'))
    parser.add_argument('--directory', type=Path, default=DEFAULT_STORE)
    parser.add_argument('--catalog', type=Path, default=DEFAULT_CATALOG)
    parser.add_argument('--archive', type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument('--id')
    args = parser.parse_args()
    with SeedStore(args.directory, catalog_dir=args.catalog,
                   archive_dir=args.archive) as store:
        if args.command == 'sync':
            result = store.sync()
        elif args.command == 'read':
            result = store.read(args.id)
        else:
            result = store.status()
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
