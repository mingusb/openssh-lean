"""Promote committed native fatal observations into immutable catalog records.

The first run is retained even when the separate Bash and exact-PC replays fail.
No Lean proposition is needed to ingest a native fatal signal.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import subprocess
import tempfile
import zlib

from common import WORKSPACE, need, sha
from model_archive import Archive
from native_fatal_reproducer import render_native_fatal_script
from native_signal_replay import (check_invocation, native_binary, parse_signal_traces,
                                  primary_fault_sites, replay_binary, verify_receipt)
from signal_catalog import Catalog, DEFAULT as DEFAULT_CATALOG, packed


ARCHIVE = WORKSPACE/'local/models/current'
DEFAULT_FRONTIER = WORKSPACE/'local/search/jobs/native-input-frontier'
HEX = re.compile(r'[0-9a-f]{64}\Z')


def _capture_files(sandbox, observation):
    capture = sandbox/'capture'
    need(capture.is_dir() and not capture.is_symlink(),
         'Fatal capture directory is missing or linked')
    descriptions = [observation['stdout'], observation['stderr'],
                    *observation['trace_files']]
    saved = {}
    for item in descriptions:
        name = item['file']
        need(type(name) is str and name not in ('', '.', '..') and
             Path(name).name == name and name not in saved and
             re.fullmatch(r'[A-Za-z0-9._-]{1,100}', name) and
             type(item.get('bytes')) is int and item['bytes'] >= 0 and
             type(item.get('sha256')) is str and HEX.fullmatch(item['sha256']),
             'Fatal capture has an unsafe file descriptor')
        path = capture/name
        need(path.is_file() and not path.is_symlink() and
             path.stat().st_size == item['bytes'] and sha(path) == item['sha256'],
             'Fatal capture bytes differ from the committed outcome: '+name)
        saved[name] = path.read_bytes()
    deliveries, terminations, traces = parse_signal_traces(capture)
    need((deliveries, terminations, traces) ==
         (observation['signal_deliveries'], observation['signal_terminations'],
          observation['trace_files']),
         'Fatal signal trace differs from the committed outcome')
    return saved


def _validate_frontier_row(root, archive, binaries, generator_identity,
                           row, evidence, binary_resolver):
    raw_recipe = evidence['recipe']
    checked, stdin = check_invocation(raw_recipe)
    need(checked == raw_recipe and evidence.get('schema') == 1 and
         evidence.get('input_id') == row['id'] and
         evidence.get('attempt') == row['attempt'] and
         evidence.get('target') == row['target'] and
         evidence.get('binary_sha256') == row['binary_sha256'] and
         checked['target'] == row['target'] and
         checked['argv'] == json.loads(row['argv']) and
         checked['stdin_base64'] == row['stdin_base64'] and
         checked['timeout_seconds'] == row['timeout_seconds'] and
         checked['expect_signal'] is None,
         'Fatal outcome differs from its committed frontier input')
    selected = binaries.get(row['target'])
    need(type(selected) is list and len(selected) == 3 and
         selected == [row['binary_path'], row['binary_sha256'], row['model_sha256']],
         'Fatal target differs from frontier binary/model identity')
    binary, binary_digest, model_digest = binary_resolver(archive, row['target'])
    need((str(binary), binary_digest, model_digest) ==
         (row['binary_path'], row['binary_sha256'], row['model_sha256']),
         'Fatal target differs from the current pinned archive')
    sandbox = Path(evidence['sandbox'])
    base = (root/'sandboxes').resolve()
    need(sandbox.is_absolute() and sandbox.is_dir() and not sandbox.is_symlink() and
         sandbox.parent.resolve() == base and sandbox.name.startswith('probe-') and
         sandbox.resolve() == sandbox and
         checked['cwd'] == str(sandbox/'cwd') and
         checked['env'].get('HOME') == str(sandbox/'home') and
         checked['env'].get('TMPDIR') == str(sandbox/'cwd') and
         (sandbox/'home').is_dir() and (sandbox/'cwd').is_dir() and
         not (sandbox/'home').is_symlink() and not (sandbox/'cwd').is_symlink(),
         'Fatal outcome does not have its retained private sandbox')
    need(not any(str(sandbox) in argument for argument in checked['argv']) and
         not any(str(sandbox) in value for key, value in checked['env'].items()
                 if key not in ('HOME', 'TMPDIR')),
         'Native recipe embeds a sandbox path that cannot be privately recreated')
    isolation = evidence.get('isolation')
    if isolation is not None:
        bwrap = Path('/usr/bin/bwrap')
        prlimit = Path('/usr/bin/prlimit')
        need(bwrap.is_file() and not bwrap.is_symlink() and
             prlimit.is_file() and not prlimit.is_symlink() and
             generator_identity.get('prlimit_sha256') == sha(prlimit) and
             generator_identity.get('schema') == '1' and
             generator_identity.get('isolation') == 'bwrap-local-v1' and
             generator_identity.get('bwrap_sha256') == sha(bwrap) and
             isolation == dict(schema=1, kind='bwrap-local-v1',
                               executable_sha256=generator_identity['bwrap_sha256'],
                               prlimit_sha256=generator_identity['prlimit_sha256'],
                               network='unshared', pid='unshared', ipc='unshared',
                               root='read-only', writable_sandbox=str(sandbox),
                               tmpfs_bytes=16*1024*1024,
                               file_bytes=16*1024*1024),
             'Fatal native isolation differs from the pinned frontier envelope')
    observation = evidence['observation']
    need(type(observation) is dict and observation.get('timed_out') is False and
         observation.get('tracer') is True and
         type(observation.get('signal_terminations')) is list,
         'Timed-out or untraced native outcome cannot be cataloged as fatal')
    deliveries = {(event['pid'], event['signal'])
                  for event in observation['signal_deliveries']}
    terminations = {(event['pid'], event['signal'])
                    for event in observation['signal_terminations']}
    fatal = sorted({name for _, name in deliveries & terminations}
                   - {'SIGXFSZ'})
    reported = evidence.get('fatal_signals')
    need(type(reported) is list and reported and
         all(type(name) is str and name in signal.Signals.__members__
             for name in reported) and set(fatal) <= set(reported),
         'Fatal-signal classification differs from the native trace')
    unqualified = sorted(set(reported) - set(fatal))
    return (checked, stdin, sandbox, fatal, unqualified,
            _capture_files(sandbox, observation))


def _source_identity(archive, target, model_digest):
    return dict(kind='openssh-archive', target=target,
                archive_manifest_sha256=archive.manifest_sha256,
                openssh_commit=archive.data['openssh_commit'],
                configuration_profile=archive.data['configuration_profile'],
                model_artifact_sha256=model_digest)


def _source_link_for_sites(record, sites, source_identity, *,
                           archive_factory=Archive,
                           source_root=WORKSPACE/'work/reference-source'):
    """Map only a pinned executable instruction to a hash-pinned C source line."""
    if source_identity.get('kind') != 'openssh-archive':
        return dict(status='unmapped')
    pinned_binary = Path(record['binary']['path'])
    candidates = [site for site in sites
                  if site.get('module_path') == str(pinned_binary) and
                     site.get('module_sha256') == record['binary']['sha256'] and
                     site.get('source_line_context', {}).get('status') == 'reported']
    if not candidates:
        return dict(status='unmapped')
    archive = archive_factory(ARCHIVE)
    need(archive.manifest_sha256 == record['archive']['manifest_sha256'],
         'Native source link archive changed')
    source_root = Path(source_root).resolve(strict=True)
    inventory = archive.data['source_snapshot']['files']
    links = []
    for site in candidates:
        for frame in site['source_line_context']['frames']:
            location = frame.get('location')
            matched = re.match(r'^(.*?):([0-9]+)(?:\b|\s|$)', location or '')
            if not matched:
                continue
            source_name, line = matched[1], int(matched[2])
            candidate = Path(source_name)
            candidate = (candidate if candidate.is_absolute() else
                         source_root/candidate).resolve()
            if not candidate.is_relative_to(source_root) or line < 1 or not candidate.is_file():
                continue
            relative = str(candidate.relative_to(source_root))
            expected_sha = inventory.get(relative)
            if expected_sha is None or sha(candidate) != expected_sha:
                continue
            links.append(dict(stable_site_key=site['stable_site_key'],
                              module_sha256=site['module_sha256'],
                              file_offset=site['file_offset'],
                              source=str(candidate), source_sha256=expected_sha,
                              line=line, function=frame.get('function')))
    if not links:
        return dict(status='unmapped')
    return dict(status='native-dwarf-line-mapped', sites=links,
                exact_original_c_expression_verified=False)


def _qualified_native_sites(deliveries, terminations, sites, signal_name,
                            binary_path):
    """Keep only captured PCs from the attributed fatal process and signal."""
    terminated_pairs = {(row['pid'], row['signal']) for row in terminations}
    last_delivery = {}
    for row in deliveries:
        pair = (row['pid'], row['signal'])
        if pair in terminated_pairs:
            last_delivery[pair] = row
    qualified_pairs = {
        pair for pair, row in last_delivery.items()
        if any(frame.get('module') == binary_path
               for frame in row.get('stack_frames', []))}
    matched = [site for site in sites
               if site.get('status') == 'captured' and
                  site.get('signal') == signal_name and
                  (site.get('pid'), site.get('signal')) in qualified_pairs]
    return qualified_pairs, matched


def _run_replays(catalog, observation_id, record, source_identity):
    """Execute the stored Bash program and independently capture an exact PC."""
    script = Path(record['assets']['script']['path'])
    recipe = record['first_run']['recipe']
    signal_name = record['signal']
    expected_marker = ('REPRODUCED_FATAL_SIGNAL '+signal_name+
                       ' target='+record['target']+
                       ' binary_sha256='+record['binary']['sha256'])
    script_result = dict(status='not_reproduced')
    script_trace_root = catalog.directory/'native-fatal-script-traces'
    script_trace_root.mkdir(parents=True, exist_ok=True)
    need(not script_trace_root.is_symlink(), 'Script trace directory is linked')
    script_capture = Path(tempfile.mkdtemp(
        prefix=observation_id[:16]+'-', dir=script_trace_root))
    try:
        completed = subprocess.run(
            ['/usr/bin/bash', str(script)], capture_output=True, text=True,
            env=dict(PATH='/usr/bin:/bin', LC_ALL='C',
                     OPENSSH_FATAL_CAPTURE_DIR=str(script_capture)),
            timeout=max(30, recipe['timeout_seconds']*3+20))
        reproduced = (completed.returncode == 0 and
                      expected_marker in completed.stdout.splitlines())
        script_result = dict(
            status='reproduced' if reproduced else 'not_reproduced',
            returncode=completed.returncode,
            stdout_sha256=hashlib.sha256(completed.stdout.encode()).hexdigest(),
            stderr_sha256=hashlib.sha256(completed.stderr.encode()).hexdigest(),
            stdout_tail=completed.stdout[-1000:],
            stderr_tail=completed.stderr[-1000:])
        if reproduced:
            deliveries, terminations, traces = parse_signal_traces(script_capture)
            qualified_pairs, sites = _qualified_native_sites(
                deliveries, terminations,
                primary_fault_sites(deliveries, terminations, signal_name),
                signal_name, record['binary']['path'])
            need(any(name == signal_name for _, name in qualified_pairs),
                 'Stored Bash trace lacks a pinned-target fatal delivery')
            files = [dict(name=path.name, sha256=sha(path), bytes=path.stat().st_size)
                     for path in sorted(script_capture.iterdir()) if path.is_file()]
            need({row['name'] for row in files} ==
                 {row['file'] for row in traces} | {'stdout.bin', 'stderr.bin'},
                 'Stored Bash trace file inventory differs')
            script_result.update(
                capture_directory=str(script_capture), capture_files=files,
                pinned_target_attributed=True, exact_pc_sites=sites,
                native_source_line_contexts=[
                    site.get('source_line_context') for site in sites
                    if site.get('source_line_context') is not None])
    except (OSError, RuntimeError, KeyError, ValueError,
            subprocess.TimeoutExpired) as error:
        script_result = dict(status='error', error=type(error).__name__+': '+str(error))
    replay = dict(status='not_reproduced')
    replay_root = catalog.directory/'native-fatal-replay-workspaces'
    replay_root.mkdir(parents=True, exist_ok=True)
    need(not replay_root.is_symlink(), 'Native replay workspace directory is linked')
    workspace = Path(tempfile.mkdtemp(prefix=observation_id[:16]+'-', dir=replay_root))
    home, cwd = workspace/'home', workspace/'cwd'
    home.mkdir()
    cwd.mkdir()
    selected = dict(recipe)
    selected['env'] = dict(recipe['env'], HOME=str(home), TMPDIR=str(cwd))
    selected['cwd'] = str(cwd)
    selected['expect_signal'] = signal_name
    try:
        summary = replay_binary(
            record['binary']['path'], record['binary']['sha256'],
            selected, source_identity, catalog.directory,
            trace_signals=True, capture_crash_site=True)
        receipt = verify_receipt(summary['receipt'], summary['receipt_sha256'])
        delivered_pairs = {(item['pid'], item['signal'])
                           for item in summary['signal_deliveries']}
        terminated_pairs = {(item['pid'], item['signal'])
                            for item in summary['signal_terminations']}
        observed = bool(summary['expected_observed'] and not summary['timed_out'] and
                        any(name == signal_name for _, name in
                            delivered_pairs & terminated_pairs))
        sites = [site for site in summary['primary_sites']
                 if site.get('signal') == signal_name and
                    site.get('status') == 'captured' and
                    any(item['pid'] == site.get('pid') and
                        item['signal'] == signal_name
                        for item in summary['signal_terminations'])]
        replay = dict(
            status='reproduced' if observed else 'not_reproduced',
            receipt=summary['receipt'], receipt_sha256=summary['receipt_sha256'],
            receipt_id=summary['id'],
            receipt_verified=receipt['status'] == 'verified',
            exact_pc_status='captured' if sites else 'pending',
            sites=sites,
            native_source_line_contexts=[
                site.get('source_line_context') for site in sites
                if site.get('source_line_context') is not None])
    except (OSError, RuntimeError, KeyError, ValueError) as error:
        replay = dict(status='error', error=type(error).__name__+': '+str(error))
    result = dict(schema=1, kind='native-fatal-replay-attempt',
                  observation_id=observation_id,
                  script=script_result, exact_pc_replay=replay,
                  reproducer_verified=script_result['status'] == 'reproduced',
                  exact_site_verified=(script_result['status'] == 'reproduced' and
                                       bool(script_result.get('exact_pc_sites'))),
                  cross_run_same_site_observed=bool(
                      {site['stable_site_key'] for site in
                       script_result.get('exact_pc_sites', [])} &
                      {site['stable_site_key'] for site in replay.get('sites', [])}),
                  source_link=_source_link_for_sites(
                      record, script_result.get('exact_pc_sites', []),
                      source_identity),
                  original_c_expression_verified=False,
                  lean_entry_to_signal_proved=False)
    catalog.add_native_fatal_replay(observation_id, result)
    return result


def ingest_fatal_outcomes(frontier_dir=DEFAULT_FRONTIER, catalog_dir=DEFAULT_CATALOG, *,
                          input_id=None, attempt=None, archive_factory=Archive,
                          binary_resolver=native_binary, source_identity_factory=None,
                          retry_observation_id=None):
    """Ingest committed fatalities; optionally append one selected replay."""
    need(retry_observation_id is None or
         (type(retry_observation_id) is str and HEX.fullmatch(retry_observation_id)),
         'Retry requires a native fatal observation ID')
    root = Path(frontier_dir).resolve(strict=True)
    catalog_dir = Path(catalog_dir).resolve()
    catalog_dir.mkdir(parents=True, exist_ok=True)
    lock_path = catalog_dir/'native-fatal-ingest.lock'
    with lock_path.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        database = sqlite3.connect(
            (root/'frontier.sqlite').as_uri()+'?mode=ro', uri=True)
        database.row_factory = sqlite3.Row
        try:
            identity = dict(database.execute('SELECT key,value FROM identity'))
            archive = archive_factory(ARCHIVE)
            need(identity.get('archive') == archive.manifest_sha256 and
                 identity.get('schema') == '1',
                 'Frontier archive identity differs from current archive')
            binaries = json.loads(identity['binaries'])
            generator_identity = dict(database.execute(
                'SELECT key,value FROM generator_identity'))
            need(set(binaries) == set(archive.data['models']),
                 'Frontier target inventory differs from archive')
            statement = '''SELECT f.*,t.binary_path,t.binary_sha256,t.model_sha256,
                           o.attempt,o.sha256 AS outcome_sha256,o.payload
                           FROM frontier f JOIN targets t ON t.name=f.target
                           JOIN outcomes o ON o.input_id=f.id AND o.attempt=f.attempts
                           WHERE f.status='fatal' '''
            values = []
            if input_id is not None:
                statement += ' AND f.id=?'
                values.append(input_id)
            if attempt is not None:
                statement += ' AND o.attempt=?'
                values.append(attempt)
            statement += ' ORDER BY f.target,f.id,o.attempt'
            rows = list(database.execute(statement, values))
        finally:
            database.close()
        added = []
        retried = False
        with Catalog(catalog_dir) as catalog:
            for row in rows:
                raw = zlib.decompress(row['payload'])
                need(hashlib.sha256(raw).hexdigest() == row['outcome_sha256'] and
                     packed(json.loads(raw)).encode() == raw,
                     'Compressed frontier outcome hash or canonical JSON differs')
                evidence = json.loads(raw)
                recipe, stdin, sandbox, signals, unqualified, captures = (
                    _validate_frontier_row(
                        root, archive, binaries, generator_identity, row,
                        evidence, binary_resolver))
                source_identity = (source_identity_factory(
                    archive, row['target'], row['model_sha256'])
                    if source_identity_factory is not None else
                    _source_identity(archive, row['target'], row['model_sha256']))
                outcome_asset = catalog.store_native_fatal_asset('outcome', raw)
                stdin_asset = catalog.store_native_fatal_asset('stdin', stdin)
                capture_assets = {
                    name: catalog.store_native_fatal_asset('capture-'+name.lower(), contents)
                    for name, contents in sorted(captures.items())}
                if unqualified:
                    rejection = dict(
                        schema=1, kind='native-fatal-ingest-rejection',
                        input_id=row['id'], attempt=row['attempt'],
                        target=row['target'], reported_signals=evidence['fatal_signals'],
                        unqualified_signals=unqualified,
                        reason='no matching delivery and fatal termination for one PID',
                        outcome_sha256=row['outcome_sha256'],
                        outcome_asset=outcome_asset, capture_assets=capture_assets)
                    rejection_id = catalog.add_native_fatal_rejection(rejection)
                    added.append(dict(status='rejected', id=rejection_id,
                                      target=row['target'], signals=unqualified))
                for signal_name in signals:
                    script_spec = dict(
                        schema=1, target=row['target'], signal=signal_name,
                        archive_manifest_sha256=archive.manifest_sha256,
                        binary=dict(path=row['binary_path'],
                                    sha256=row['binary_sha256']),
                        recipe=recipe,
                        stdin=stdin_asset,
                        first_run_isolation=evidence.get('isolation'))
                    script = render_native_fatal_script(script_spec)
                    script_asset = catalog.store_native_fatal_asset('script', script)
                    record = dict(
                        schema=1, kind='native-fatal-signal-observation',
                        target=row['target'], signal=signal_name,
                        archive=dict(manifest_sha256=archive.manifest_sha256,
                                     model_artifact_sha256=row['model_sha256']),
                        binary=dict(path=row['binary_path'],
                                    sha256=row['binary_sha256']),
                        frontier=dict(directory=str(root), input_id=row['id'],
                                      attempt=row['attempt'],
                                      outcome_sha256=row['outcome_sha256']),
                        first_run=dict(recipe=recipe, observation=evidence['observation'],
                                       sandbox=str(sandbox),
                                       isolation=evidence.get('isolation'),
                                       scope='First native observation; replay is separate'),
                        assets=dict(outcome=outcome_asset, stdin=stdin_asset,
                                    script=script_asset, **{
                                        'capture-'+name.lower(): item
                                        for name, item in capture_assets.items()}),
                        script_spec=script_spec,
                        importance=dict(status='unassessed'),
                        source_link=dict(status='unmapped',
                                         original_c_expression_verified=False))
                    if retry_observation_id is not None and hashlib.sha256(
                            packed(record).encode()).hexdigest() != retry_observation_id:
                        continue
                    observation_id = catalog.add_native_fatal_observation(record)
                    previous = list(catalog.list_native_fatal_replays(observation_id))
                    replay = (previous[-1] if previous and retry_observation_id is None else
                              _run_replays(catalog, observation_id, record,
                                           source_identity))
                    retried = retried or retry_observation_id is not None
                    added.append(dict(id=observation_id, target=row['target'],
                                      signal=signal_name, replay=replay))
        need(retry_observation_id is None or retried,
             'Selected native fatal observation is no longer in the committed frontier')
        return added


def retry_fatal_observation(observation_id, frontier_dir=DEFAULT_FRONTIER,
                            catalog_dir=DEFAULT_CATALOG, *,
                            archive_factory=Archive, binary_resolver=native_binary,
                            source_identity_factory=None):
    """Append a fresh replay of one cataloged fatality, retaining prior attempts."""
    need(type(observation_id) is str and HEX.fullmatch(observation_id),
         'Retry requires a native fatal observation ID')
    with Catalog(catalog_dir) as catalog:
        record = catalog.read_native_fatal_observation(observation_id)
    return ingest_fatal_outcomes(
        frontier_dir, catalog_dir,
        input_id=record['frontier']['input_id'],
        attempt=record['frontier']['attempt'],
        archive_factory=archive_factory, binary_resolver=binary_resolver,
        source_identity_factory=source_identity_factory,
        retry_observation_id=observation_id)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('ingest','retry','list'))
    parser.add_argument('--frontier', type=Path, default=DEFAULT_FRONTIER)
    parser.add_argument('--catalog', type=Path, default=DEFAULT_CATALOG)
    parser.add_argument('--input-id')
    parser.add_argument('--attempt', type=int)
    parser.add_argument('--observation-id')
    args = parser.parse_args()
    if args.command == 'ingest':
        need(args.observation_id is None,
             '--observation-id applies only to retry')
        result = ingest_fatal_outcomes(args.frontier, args.catalog,
                                       input_id=args.input_id, attempt=args.attempt)
    elif args.command == 'retry':
        need(args.observation_id is not None and args.input_id is None and
             args.attempt is None,
             'retry requires only --observation-id')
        result = retry_fatal_observation(
            args.observation_id, args.frontier, args.catalog)
    else:
        with Catalog(args.catalog) as catalog:
            result = list(catalog.list_native_fatal_observations())
    print(packed(result), flush=True)


if __name__ == '__main__':
    main()
