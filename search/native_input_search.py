"""Durable, target-fair local probes of the pinned native OpenSSH tools.

Archived C parser options supply the grammar; conservative policy selects
concrete, local-only invocations. A probe is a native observation, not a Lean
proof or catalog finding. Fatal sandboxes are retained for exact replay.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import time
import uuid
import zlib

from common import WORKSPACE, need, sha
from model_archive import Archive
from native_input_grammar import archive_grammars, atoms
import native_input_values
from native_signal_replay import (check_invocation, native_binary, observe)

ARCHIVE = WORKSPACE / 'local/models/current'
DEFAULT = WORKSPACE / 'local/search/jobs/native-input-frontier'
BASELINES = (('-h',), ('-V',))
INITIAL_TIMEOUT_SECONDS = 2.0
ISOLATION = 'bwrap-local-v1'
LEGACY_VALUE_POLICY_SHA256 = (
    'b12b278ce2035a4360f34d12e1f615a26374724c994e289207a29224e08879bb')
LEGACY_VALUE_MODES = (
    ('scp', 'number:P'), ('sftp', 'number:P'), ('sftp-server', 'stdin'),
    ('ssh', 'number:p'), ('ssh-keyscan', 'number:p'),
    ('ssh-keyscan', 'number:T'), ('ssh-keysign', 'stdin'),
    ('ssh-pkcs11-helper', 'stdin'), ('ssh-sk-helper', 'stdin'),
    ('sshd', 'number:p'),
)
MAX_FEEDBACK_BYTES = 65536
MAX_PROBE_FILE_BYTES = 16*1024*1024
SCHEMA = """
CREATE TABLE IF NOT EXISTS identity(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS targets(
 name TEXT PRIMARY KEY, binary_path TEXT NOT NULL, binary_sha256 TEXT NOT NULL,
 model_sha256 TEXT NOT NULL, last_turn INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS frontier(
 id TEXT PRIMARY KEY, target TEXT NOT NULL REFERENCES targets(name),
 argv TEXT NOT NULL, stdin_base64 TEXT NOT NULL, status TEXT NOT NULL,
 timeout_seconds REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
 origin TEXT NOT NULL, parent_id TEXT);
CREATE INDEX IF NOT EXISTS frontier_queue ON frontier(status,target,id);
CREATE TABLE IF NOT EXISTS outcomes(
 input_id TEXT NOT NULL REFERENCES frontier(id), attempt INTEGER NOT NULL,
 sha256 TEXT NOT NULL, payload BLOB NOT NULL,
 PRIMARY KEY(input_id,attempt));
CREATE TABLE IF NOT EXISTS signatures(
 signature TEXT PRIMARY KEY, first_input_id TEXT NOT NULL, seen INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS generator_identity(
 key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS grammars(
 target TEXT PRIMARY KEY REFERENCES targets(name), source TEXT NOT NULL,
 source_sha256 TEXT NOT NULL, source_line INTEGER, option_spec TEXT NOT NULL,
 flags TEXT NOT NULL, arguments TEXT NOT NULL, ambiguous TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS generators(
 target TEXT PRIMARY KEY REFERENCES targets(name), phase INTEGER NOT NULL,
 cursor INTEGER NOT NULL, last_turn INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS mutation_seeds(
 input_id TEXT PRIMARY KEY REFERENCES frontier(id), target TEXT NOT NULL,
 cursor INTEGER NOT NULL DEFAULT 0, last_turn INTEGER NOT NULL DEFAULT 0,
 depth INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS outcome_classifications(
 input_id TEXT NOT NULL, attempt INTEGER NOT NULL,
 classification TEXT NOT NULL, reason TEXT NOT NULL,
 PRIMARY KEY(input_id,attempt),
 FOREIGN KEY(input_id,attempt) REFERENCES outcomes(input_id,attempt));
CREATE TABLE IF NOT EXISTS value_identity(
 key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS value_generators(
 slot INTEGER PRIMARY KEY, target TEXT NOT NULL REFERENCES targets(name),
 mode TEXT NOT NULL, cursor TEXT NOT NULL,
 UNIQUE(target,mode));
CREATE TABLE IF NOT EXISTS value_policy_migrations(
 migration_id TEXT PRIMARY KEY, from_policy_sha256 TEXT NOT NULL,
 to_policy_sha256 TEXT NOT NULL, from_modes TEXT NOT NULL,
 to_modes TEXT NOT NULL, verified_inputs INTEGER NOT NULL,
 input_rows_sha256 TEXT NOT NULL, committed_ns INTEGER NOT NULL);
CREATE TRIGGER IF NOT EXISTS value_migration_no_update
 BEFORE UPDATE ON value_policy_migrations BEGIN
 SELECT RAISE(ABORT, 'value migration receipts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS value_migration_no_delete
 BEFORE DELETE ON value_policy_migrations BEGIN
 SELECT RAISE(ABORT, 'value migration receipts are immutable'); END;
"""


def packed(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(packed(value).encode('utf-8')).hexdigest()


def baseline_id(archive_sha, target, argv):
    return digest(dict(archive=archive_sha, target=target, argv=list(argv),
                       stdin_base64='', sandbox='private-empty-home-v1'))


def normalized_output(path, sandbox):
    """Bounded feedback that removes volatile paths and process identifiers."""
    with Path(path).open('rb') as stream:
        prefix = stream.read(MAX_FEEDBACK_BYTES + 1)
    truncated = len(prefix) > MAX_FEEDBACK_BYTES
    prefix = prefix[:MAX_FEEDBACK_BYTES]
    prefix = prefix.replace(str(sandbox).encode(), b'<SANDBOX>')
    prefix = re.sub(rb'0x[0-9a-fA-F]{6,}', b'<HEX>', prefix)
    prefix = re.sub(rb'(?i)\b(pid|process)\s*[:=]?\s*[0-9]+\b',
                    rb'\1 <ID>', prefix)
    return dict(sha256=hashlib.sha256(prefix).hexdigest(),
                truncated=truncated)


def behavior_signature(observation, capture=None, sandbox=None):
    """Heuristic outcome feedback; not a measure of C control-flow coverage."""
    outputs = (dict(stdout=normalized_output(Path(capture)/'stdout.bin', sandbox),
                    stderr=normalized_output(Path(capture)/'stderr.bin', sandbox))
               if capture is not None else
               dict(stdout=(observation['stdout']['bytes'],
                            observation['stdout']['sha256']),
                    stderr=(observation['stderr']['bytes'],
                            observation['stderr']['sha256'])))
    return digest(dict(
        returncode=observation['tracer_returncode'],
        timed_out=observation['timed_out'],
        **outputs,
        fatal_signals=sorted({r['signal'] for r in
                              observation['signal_terminations']})))


def unpaired_runner_kills(observation):
    """A wrapper SIGKILL without delivery cannot be attributed to native C."""
    delivered = {(r['pid'],r['signal']) for r in
                 observation.get('signal_deliveries',[])}
    return [r for r in observation.get('signal_terminations',[])
            if r['signal'] == 'SIGKILL' and
            (r['pid'],r['signal']) not in delivered]


def bwrap_identity():
    path = shutil.which('bwrap')
    need(path is not None, 'bubblewrap is required for local-only native probes')
    path = Path(path).resolve(strict=True)
    need(path.is_file() and os.access(path, os.X_OK), 'bubblewrap is unavailable')
    return path, sha(path)


def isolation_descriptor(bwrap_sha, prlimit_sha, sandbox):
    return dict(schema=1, kind=ISOLATION, executable_sha256=bwrap_sha,
                prlimit_sha256=prlimit_sha,
                network='unshared', pid='unshared', ipc='unshared',
                root='read-only', writable_sandbox=str(sandbox),
                tmpfs_bytes=MAX_PROBE_FILE_BYTES,
                file_bytes=MAX_PROBE_FILE_BYTES)


def isolated_recipe(program, checked, sandbox):
    """Run the verified native binary directly under bubblewrap, never a shell."""
    argv = ['--unshare-user', '--unshare-net', '--unshare-pid',
            '--unshare-ipc', '--disable-userns', '--die-with-parent',
            '--ro-bind', '/', '/', '--dev-bind', '/dev', '/dev',
            '--proc', '/proc', '--bind', str(sandbox), str(sandbox),
            '--size', str(MAX_PROBE_FILE_BYTES), '--tmpfs', '/tmp',
            '--', '/usr/bin/prlimit',
            '--fsize='+str(MAX_PROBE_FILE_BYTES)+':'+str(MAX_PROBE_FILE_BYTES),
            '--', str(program), *checked['argv']]
    return {**checked, 'argv': argv}


def preflight_isolation(bwrap):
    """Fail closed before claiming generated behavior if namespaces fail."""
    checked = subprocess.run(
        [str(bwrap), '--unshare-user', '--unshare-net', '--unshare-pid',
         '--unshare-ipc', '--disable-userns', '--die-with-parent',
         '--ro-bind', '/', '/', '--dev-bind', '/dev', '/dev',
         '--proc', '/proc', '--', '/usr/bin/prlimit',
         '--fsize='+str(MAX_PROBE_FILE_BYTES)+':'+str(MAX_PROBE_FILE_BYTES),
         '--', '/usr/bin/true'],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=5, check=False)
    need(checked.returncode == 0,
         'Local-only namespace setup failed: '+checked.stderr[:300].decode(
             'utf-8', errors='replace'))


def cleanup_sandbox(root, sandbox):
    """Remove only a completed nonfatal sandbox allocated under this frontier."""
    root, sandbox = Path(root).resolve(), Path(sandbox)
    base = root / 'sandboxes'
    need(sandbox.is_absolute() and sandbox.parent == base and
         sandbox.name.startswith('probe-'),
         'Refusing to remove an unrecognized probe sandbox')
    need(shutil.rmtree.avoids_symlink_attacks,
         'Safe directory cleanup is unavailable on this platform')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root_fd = os.open(root, flags)
    try:
        base_fd = os.open('sandboxes', flags, dir_fd=root_fd)
        try:
            mode = os.stat(sandbox.name, dir_fd=base_fd,
                           follow_symlinks=False).st_mode
            need(stat.S_ISDIR(mode),
                 'Refusing to remove an unrecognized probe sandbox')
            shutil.rmtree(sandbox.name, dir_fd=base_fd)
        finally:
            os.close(base_fd)
    finally:
        os.close(root_fd)


class NativeFrontier:
    def __init__(self, directory=DEFAULT, *, archive_factory=Archive,
                 binary_resolver=native_binary, observer=observe,
                 grammar_resolver=archive_grammars,
                 isolation_resolver=bwrap_identity,
                 isolation_preflight=preflight_isolation,
                 value_modes_resolver=native_input_values.modes,
                 value_candidate=native_input_values.candidate):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.lock = (self.directory / 'frontier.lock').open('a')
        self.db = None
        self.observer = observer
        self.value_candidate = value_candidate
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.bwrap, self.bwrap_sha = isolation_resolver()
            prlimit = Path('/usr/bin/prlimit')
            need(prlimit.is_file() and os.access(prlimit, os.X_OK),
                 'prlimit is required for bounded native probes')
            self.prlimit_sha = sha(prlimit)
            isolation_preflight(self.bwrap)
            self.db = sqlite3.connect(self.directory / 'frontier.sqlite')
            self.db.row_factory = sqlite3.Row
            self.db.execute('PRAGMA foreign_keys=ON')
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.executescript(SCHEMA)
            self.archive = archive_factory(ARCHIVE)
            names = sorted(self.archive.data['models'])
            need(len(names) == 14, 'The pinned archive must contain all 14 tools')
            self.grammars = grammar_resolver(self.archive, names)
            self.atom_layers = {name: atoms(self.grammars[name]) for name in names}
            self.value_modes = tuple(value_modes_resolver(self.grammars))
            need(self.value_modes and len(set(self.value_modes)) == len(self.value_modes)
                 and all(target in names and type(mode) is str and
                         re.fullmatch(r'[A-Za-z0-9:_-]+',mode)
                         for target, mode in self.value_modes),
                 'Open-ended value modes are incomplete or duplicated')
            binaries = {}
            for target in names:
                binary, binary_sha, model_sha = binary_resolver(self.archive, target)
                binaries[target] = (str(binary), binary_sha, model_sha)
            wanted = dict(schema='1', archive=self.archive.manifest_sha256,
                          binaries=packed(binaries),
                          baseline_policy='private-home-help-and-version-v1')
            prior = dict(self.db.execute('SELECT key,value FROM identity'))
            need(not prior or prior == wanted,
                 'Frontier belongs to another archive, binary set, or baseline policy')
            if not prior:
                with self.db:
                    self.db.executemany('INSERT INTO identity VALUES(?,?)',
                                        wanted.items())
                    self.db.executemany('INSERT INTO targets(name,binary_path,'
                                        'binary_sha256,model_sha256) VALUES(?,?,?,?)',
                                        ((name,*binaries[name]) for name in names))
            else:
                stored = {row['name']: (row['binary_path'],
                                        row['binary_sha256'], row['model_sha256'])
                          for row in self.db.execute('SELECT * FROM targets')}
                need(stored == binaries, 'Frontier target identities changed')
            generator_identity = dict(
                schema='1', isolation=ISOLATION,
                bwrap_sha256=self.bwrap_sha,
                prlimit_sha256=self.prlimit_sha,
                grammar_policy_sha256=digest({name: dict(
                    grammar=vars(self.grammars[name]),
                    atom_layers=self.atom_layers[name]) for name in names}))
            previous_generator = dict(self.db.execute(
                'SELECT key,value FROM generator_identity'))
            need(not previous_generator or previous_generator == generator_identity,
                 'Generator grammar, policy, or isolation binary changed')
            value_identity = dict(schema='2',
                policy_sha256=sha(Path(native_input_values.__file__)),
                modes=packed(self.value_modes))
            previous_values = dict(self.db.execute(
                'SELECT key,value FROM value_identity'))
            legacy_values = dict(schema='1',
                policy_sha256=LEGACY_VALUE_POLICY_SHA256,
                modes=packed(LEGACY_VALUE_MODES),
                next_slot=previous_values.get('next_slot','0'),
                next_source=previous_values.get('next_source','0'))
            current_values = dict(value_identity,
                next_slot=previous_values.get('next_slot','0'),
                next_source=previous_values.get('next_source','0'))
            migrate_values = previous_values == legacy_values
            need(not previous_values or migrate_values or
                 previous_values == current_values,
                 'Open-ended value policy changed without a verified migration')
            with self.db:
                for target in names:
                    for argv in BASELINES:
                        identity = baseline_id(self.archive.manifest_sha256,
                                               target, argv)
                        serialized = packed(list(argv))
                        previous = self.db.execute(
                            'SELECT target,argv,stdin_base64,origin FROM frontier '
                            'WHERE id=?', (identity,)).fetchone()
                        if previous is None:
                            self.db.execute('''INSERT INTO frontier
                                (id,target,argv,stdin_base64,status,
                                 timeout_seconds,origin)
                                VALUES(?,?,?,'','queued',?,'baseline')''',
                                (identity,target,serialized,INITIAL_TIMEOUT_SECONDS))
                        else:
                            need((previous['target'],previous['argv'],
                                  previous['stdin_base64'],previous['origin']) ==
                                 (target,serialized,'','baseline'),
                                 'Baseline input identity changed')
                if not previous_generator:
                    self.db.executemany('INSERT INTO generator_identity VALUES(?,?)',
                                        generator_identity.items())
                    self.db.executemany('''INSERT INTO grammars VALUES(?,?,?,?,?,?,?,?)''',
                        ((name, self.grammars[name].source,
                          self.grammars[name].source_sha256,
                          self.grammars[name].source_line,
                          self.grammars[name].option_spec,
                          packed(self.grammars[name].flags),
                          packed(self.grammars[name].arguments),
                          packed(self.grammars[name].ambiguous)) for name in names))
                    self.db.executemany(
                        'INSERT INTO generators(target,phase,cursor) VALUES(?,0,0)',
                        ((name,) for name in names))
                else:
                    stored_grammars = {row['target']: dict(row) for row in
                                       self.db.execute('SELECT * FROM grammars')}
                    need(len(stored_grammars) == len(names),
                         'Generator grammar inventory is incomplete')
                    for name in names:
                        row = stored_grammars[name]
                        grammar = self.grammars[name]
                        need((row['source'], row['source_sha256'],
                              row['source_line'], row['option_spec'],
                              row['flags'], row['arguments'], row['ambiguous']) ==
                             (grammar.source, grammar.source_sha256,
                              grammar.source_line, grammar.option_spec,
                              packed(grammar.flags), packed(grammar.arguments),
                              packed(grammar.ambiguous)),
                             'Pinned generator grammar changed: '+name)
                if not previous_values:
                    self.db.executemany('INSERT INTO value_identity VALUES(?,?)',
                        (*value_identity.items(),('next_slot','0'),
                         ('next_source','0')))
                    self.db.executemany('''INSERT INTO value_generators
                        (slot,target,mode,cursor) VALUES(?,?,?,'0')''',
                        ((index,target,mode) for index,(target,mode)
                         in enumerate(self.value_modes)))
                else:
                    if migrate_values:
                        self._migrate_value_policy(previous_values,
                                                   value_identity)
                    stored_modes = tuple((row['target'],row['mode']) for row in
                        self.db.execute('SELECT target,mode FROM value_generators '
                                        'ORDER BY slot'))
                    need(stored_modes == self.value_modes,
                         'Open-ended value generator roster changed')
                self._verify_value_policy_receipt(value_identity)
                # The exclusive lock proves no other owner is still probing.
                self.db.execute("UPDATE frontier SET status='queued' "
                                "WHERE status='running'")
                self._adjudicate_prior_runner_kills()
            (self.directory / 'sandboxes').mkdir(exist_ok=True)
        except BaseException:
            self.close()
            raise

    def _migrate_value_policy(self, previous, current):
        """Append source-checked modes after validating every retained value row."""
        need(self.value_modes[:len(LEGACY_VALUE_MODES)] == LEGACY_VALUE_MODES,
             'New value policy changed an existing generator slot')
        rows = list(self.db.execute(
            'SELECT slot,target,mode,cursor FROM value_generators ORDER BY slot'))
        need(tuple((row['target'],row['mode']) for row in rows) ==
             LEGACY_VALUE_MODES and
             tuple(row['slot'] for row in rows) ==
             tuple(range(len(LEGACY_VALUE_MODES))),
             'Legacy generator roster differs from its pinned policy')
        need(all(row['cursor'].isascii() and row['cursor'].isdecimal() and
                 str(int(row['cursor'])) == row['cursor'] for row in rows),
             'Legacy generator cursor is not canonical')
        hint = previous['next_slot']
        need(hint.isascii() and hint.isdecimal() and str(int(hint)) == hint and
             int(hint) < len(rows) and previous['next_source'] in ('0','1'),
             'Legacy scheduler cursor is invalid')
        prior_inputs = list(self.db.execute('''SELECT id,target,argv,
            stdin_base64,origin,parent_id FROM frontier
            WHERE origin LIKE 'value/%' ORDER BY id'''))
        row_hash = hashlib.sha256()
        for row in prior_inputs:
            identity = re.fullmatch(r'value/([0-9]+)/([0-9]+):(.+)',
                                    row['origin'])
            need(identity is not None and int(identity[1]) < len(rows)
                 and int(identity[2]) < int(rows[int(identity[1])]['cursor'])
                 and row['parent_id'] is None,
                 'Legacy value input references a changed slot')
            argv = json.loads(row['argv'])
            need(type(argv) is list and all(type(arg) is str for arg in argv)
                 and row['argv'] == packed(argv),
                 'Legacy value argv changed or is not canonical')
            stdin = base64.b64decode(row['stdin_base64'], validate=True)
            need(base64.b64encode(stdin).decode('ascii') == row['stdin_base64']
                 and self._input_id(row['target'],argv,stdin) == row['id']
                 and self._check_generated_input(row,argv,stdin) == 1,
                 'Legacy value input differs from its original generator')
            encoded = packed(dict(row)).encode('utf-8')
            row_hash.update(len(encoded).to_bytes(8,'big'))
            row_hash.update(encoded)
        migration = dict(from_policy_sha256=previous['policy_sha256'],
                         to_policy_sha256=current['policy_sha256'],
                         from_modes=previous['modes'],to_modes=current['modes'],
                         verified_inputs=len(prior_inputs),
                         input_rows_sha256=row_hash.hexdigest())
        migration_id = digest(migration)
        need(self.db.execute('SELECT count(*) FROM value_policy_migrations')
             .fetchone()[0] == 0, 'Value policy was already migrated')
        self.db.executemany('UPDATE value_identity SET value=? WHERE key=?',
            ((value,key) for key,value in current.items()))
        self.db.executemany('''INSERT INTO value_generators
            (slot,target,mode,cursor) VALUES(?,?,?,'0')''',
            ((slot,target,mode) for slot,(target,mode) in
             enumerate(self.value_modes) if slot >= len(rows)))
        self.db.execute('''INSERT INTO value_policy_migrations VALUES(
            ?,?,?,?,?,?,?,?)''',
            (migration_id,*migration.values(),time.time_ns()))

    def _verify_value_policy_receipt(self, current):
        rows = list(self.db.execute('SELECT * FROM value_policy_migrations'))
        need(len(rows) <= 1, 'Unexpected value policy migration chain')
        if not rows:
            return
        receipt = dict(rows[0])
        fields = ('from_policy_sha256','to_policy_sha256','from_modes',
                  'to_modes','verified_inputs','input_rows_sha256')
        recorded = {key: receipt[key] for key in fields}
        need(receipt['migration_id'] == digest(recorded) and
             receipt['from_policy_sha256'] == LEGACY_VALUE_POLICY_SHA256 and
             receipt['from_modes'] == packed(LEGACY_VALUE_MODES) and
             receipt['to_policy_sha256'] == current['policy_sha256'] and
             receipt['to_modes'] == current['modes'] and
             receipt['verified_inputs'] >= 0 and
             receipt['committed_ns'] > 0 and
             re.fullmatch(r'[0-9a-f]{64}',receipt['input_rows_sha256']) and
             receipt['verified_inputs'] <= self.db.execute(
                 "SELECT count(*) FROM frontier WHERE origin LIKE 'value/%'")
                 .fetchone()[0],
             'Recorded value policy migration is inconsistent')

    def _adjudicate_prior_runner_kills(self):
        """Append a classification; never rewrite a committed observation."""
        rows = self.db.execute('''SELECT f.id,o.attempt,o.payload
            FROM frontier f JOIN outcomes o ON o.input_id=f.id
            WHERE f.status='fatal' AND o.attempt=(
                SELECT max(o2.attempt) FROM outcomes o2 WHERE o2.input_id=f.id)
            ''').fetchall()
        for row in rows:
            evidence = json.loads(zlib.decompress(row['payload']))
            if (evidence.get('fatal_signals') != ['SIGKILL'] or not
                    unpaired_runner_kills(evidence['observation'])):
                continue
            self.db.execute('''INSERT OR IGNORE INTO outcome_classifications
                VALUES(?,?,?,?)''',
                (row['id'],row['attempt'],'runner_signal',
                 'SIGKILL termination lacks same-run signal delivery'))
            self.db.execute("UPDATE frontier SET status='runner_signal' WHERE id=?",
                            (row['id'],))

    def status(self):
        self.db.execute('BEGIN')
        try:
            by_status = dict(self.db.execute(
                'SELECT status,count(*) FROM frontier GROUP BY status'))
            target_count = self.db.execute('SELECT count(*) FROM targets').fetchone()[0]
            outcome_count = self.db.execute('SELECT count(*) FROM outcomes').fetchone()[0]
            signature_count = self.db.execute('SELECT count(*) FROM signatures').fetchone()[0]
            generated = self.db.execute(
                "SELECT count(*) FROM frontier WHERE origin!='baseline'").fetchone()[0]
            grammar_atoms = sum(sum(map(len, self.atom_layers[name]))
                                for name in self.atom_layers)
            completed_atoms = self.db.execute(
                "SELECT count(*) FROM frontier WHERE origin LIKE 'generated:%' "
                "AND status IN ('done','fatal')").fetchone()[0]
            mutation_seeds = self.db.execute(
                'SELECT count(*) FROM mutation_seeds').fetchone()[0]
            value_inputs = self.db.execute(
                "SELECT count(*) FROM frontier WHERE origin LIKE 'value/%'").fetchone()[0]
            value_cursors = {row['target']+':'+row['mode']: row['cursor']
                             for row in self.db.execute(
                                 'SELECT target,mode,cursor FROM value_generators '
                                 'ORDER BY slot')}
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        return dict(targets=target_count, inputs=sum(by_status.values()),
                    states=by_status, outcomes=outcome_count,
                    generated_inputs=generated, grammar_atoms=grammar_atoms,
                    completed_grammar_atoms=completed_atoms,
                    behavior_signatures=signature_count,
                    mutation_seeds=mutation_seeds,
                    value_inputs=value_inputs, value_cursors=value_cursors,
                    open_ended_value_modes=len(self.value_modes),
                    scope='native C observations, finite option-atom coverage, '
                          'and open-ended value-cursor progress; no Lean proof '
                          'or catalog finding')

    def _input_id(self, target, argv, stdin):
        return digest(dict(archive=self.archive.manifest_sha256,
                           target=target, argv=list(argv),
                           stdin_base64=base64.b64encode(stdin).decode('ascii'),
                           isolation=ISOLATION))

    def _offer_input(self, target, argv, origin, parent_id=None, stdin=b''):
        need(type(stdin) is bytes, 'Generated native stdin must be literal bytes')
        encoded = base64.b64encode(stdin).decode('ascii')
        identity = self._input_id(target, argv, stdin)
        prior = self.db.execute(
            'SELECT target,argv,stdin_base64,origin,parent_id FROM frontier '
            'WHERE id=?', (identity,)).fetchone()
        if prior is not None:
            need(prior['target'] == target and prior['argv'] == packed(list(argv))
                 and prior['stdin_base64'] == encoded,
                 'Generated input digest collision or changed payload')
            return False
        self.db.execute('''INSERT INTO frontier
            (id,target,argv,stdin_base64,status,timeout_seconds,origin,parent_id)
            VALUES(?,?,?,?,'queued',?,?,?)''',
            (identity,target,packed(list(argv)),encoded,INITIAL_TIMEOUT_SECONDS,
             origin,parent_id))
        return True

    def _generate_atom(self):
        """Advance exactly one durable parser-atom cursor."""
        row = self.db.execute('''SELECT * FROM generators WHERE phase<3
            ORDER BY phase,last_turn,target LIMIT 1''').fetchone()
        if row is None:
            return None
        target, phase, cursor = row['target'], row['phase'], row['cursor']
        layer = self.atom_layers[target][phase]
        turn = self.db.execute(
            'SELECT coalesce(max(last_turn),0)+1 FROM generators').fetchone()[0]
        with self.db:
            if cursor >= len(layer):
                self.db.execute(
                    'UPDATE generators SET phase=phase+1,cursor=0,last_turn=? '
                    'WHERE target=?', (turn,target))
                return False
            argv, tag = layer[cursor]
            inserted = self._offer_input(target, argv, 'generated:'+tag)
            self.db.execute(
                'UPDATE generators SET cursor=cursor+1,last_turn=? '
                'WHERE target=?', (turn,target))
        return inserted

    def _generate_feedback(self):
        """One extension per novel seed at a time; no option cross product."""
        seed = self.db.execute('''SELECT * FROM mutation_seeds
            ORDER BY last_turn,target,input_id LIMIT 1''').fetchone()
        if seed is None:
            return None
        target = seed['target']
        choices = self.atom_layers[target][1] + self.atom_layers[target][2]
        turn = self.db.execute(
            'SELECT coalesce(max(last_turn),0)+1 FROM mutation_seeds').fetchone()[0]
        with self.db:
            if seed['cursor'] >= len(choices):
                self.db.execute('DELETE FROM mutation_seeds WHERE input_id=?',
                                (seed['input_id'],))
                return False
            atom_argv, tag = choices[seed['cursor']]
            parent = self.db.execute(
                'SELECT argv,stdin_base64 FROM frontier WHERE id=?',
                (seed['input_id'],)).fetchone()
            need(parent is not None, 'Feedback parent disappeared')
            prior_argv = json.loads(parent['argv'])
            prior_stdin = base64.b64decode(parent['stdin_base64'],validate=True)
            option = atom_argv[-2] if tag.startswith('arg:') else atom_argv[-1]
            inserted = False
            if option not in prior_argv:
                argv = prior_argv + list(atom_argv)
                inserted = self._offer_input(target, argv,
                                             'feedback:'+tag,
                                             seed['input_id'],stdin=prior_stdin)
            self.db.execute(
                'UPDATE mutation_seeds SET cursor=cursor+1,last_turn=? '
                'WHERE input_id=?', (turn,seed['input_id']))
        return inserted

    def _generate_value(self):
        """Advance the least-served target, then its least-served value mode."""
        hint = int(self.db.execute(
            "SELECT value FROM value_identity WHERE key='next_slot'").fetchone()[0])
        rows = list(self.db.execute('SELECT * FROM value_generators ORDER BY slot'))
        need(len(rows) == len(self.value_modes) and 0 <= hint < len(rows),
             'Open-ended generator roster changed')
        turns = {}
        for item in rows:
            turns[item['target']] = turns.get(item['target'],0) + int(item['cursor'])
        row = min(rows, key=lambda item: (
            turns[item['target']], int(item['cursor']),
            (item['slot']-hint)%len(rows)))
        slot = row['slot']
        index = int(row['cursor'])
        need(index >= 0 and str(index) == row['cursor'],
             'Open-ended generator cursor changed')
        argv, stdin, tag = self.value_candidate(row['target'],row['mode'],index)
        need(type(argv) is tuple and all(type(arg) is str for arg in argv)
             and type(stdin) is bytes and type(tag) is str and tag,
             'Open-ended generator returned an invalid native input')
        origin = 'value/'+str(slot)+'/'+str(index)+':'+tag
        with self.db:
            inserted = self._offer_input(row['target'],argv,origin,stdin=stdin)
            self.db.execute('UPDATE value_generators SET cursor=? WHERE slot=?',
                            (str(index+1),slot))
            self.db.execute("UPDATE value_identity SET value=? WHERE key='next_slot'",
                            (str((slot+1)%len(rows)),))
        return inserted

    def _generate_dynamic(self):
        next_source = int(self.db.execute(
            "SELECT value FROM value_identity WHERE key='next_source'").fetchone()[0])
        need(next_source in (0,1), 'Open-ended generator schedule changed')
        with self.db:
            self.db.execute(
                "UPDATE value_identity SET value=? WHERE key='next_source'",
                (str(1-next_source),))
        if next_source == 0:
            result = self._generate_feedback()
            return self._generate_value() if result is None else result
        result = self._generate_value()
        return self._generate_feedback() if result is None else result

    def generate(self, count=14):
        """Persist the next deterministic work slice before executing any probe."""
        need(type(count) is int and count >= 0,
             'Generation quantum must be nonnegative')
        inserted = 0
        while inserted < count:
            advance = self._generate_atom()
            if advance is None:
                advance = self._generate_dynamic()
            inserted += bool(advance)
        return inserted

    def _next(self):
        row = self.db.execute('''SELECT f.*,t.binary_path,t.binary_sha256
            FROM frontier f JOIN targets t ON t.name=f.target
            WHERE f.status='queued'
            ORDER BY t.last_turn,f.target,f.id LIMIT 1''').fetchone()
        if row is None:
            return None
        turn = self.db.execute(
            'SELECT coalesce(max(last_turn),0)+1 FROM targets').fetchone()[0]
        with self.db:
            self.db.execute("UPDATE frontier SET status='running',attempts=attempts+1 "
                            'WHERE id=?', (row['id'],))
            self.db.execute('UPDATE targets SET last_turn=? WHERE name=?',
                            (turn,row['target']))
        return dict(row), row['attempts']+1

    def _sandbox(self, identity, attempt):
        root = self.directory / 'sandboxes'
        sandbox = root / ('probe-' + identity[:16] + '-' +
                          str(attempt) + '-' + uuid.uuid4().hex)
        sandbox.mkdir()
        for name in ('home','cwd','capture'):
            (sandbox/name).mkdir()
        return sandbox

    def _check_generated_input(self, row, argv, stdin):
        origin = row['origin']
        if origin == 'baseline':
            need(tuple(argv) in BASELINES and not stdin,
                 'Baseline probe escaped its argument set')
            return 0
        if origin.startswith('generated:'):
            need(not stdin and
                 any(tuple(argv) == candidate and origin == 'generated:'+tag
                     for layer in self.atom_layers[row['target']]
                     for candidate, tag in layer),
                 'Generated probe differs from the pinned safe grammar')
            return 1
        if origin.startswith('value/'):
            matched = re.fullmatch(r'value/([0-9]+)/([0-9]+):(.+)',origin)
            need(matched is not None and
                 str(int(matched[1])) == matched[1] and
                 str(int(matched[2])) == matched[2] and
                 int(matched[1]) < len(self.value_modes),
                 'Unknown open-ended native input origin')
            mode_target, mode = self.value_modes[int(matched[1])]
            need(mode_target == row['target'],
                 'Open-ended native input selected another target')
            candidate_argv, candidate_stdin, tag = self.value_candidate(
                row['target'],mode,int(matched[2]))
            need(tuple(argv) == candidate_argv and stdin == candidate_stdin
                 and matched[3] == tag,
                 'Open-ended native input differs from its durable cursor')
            return 1
        need(origin.startswith('feedback:') and row['parent_id'],
             'Unknown native probe origin')
        parent = self.db.execute(
            'SELECT argv,stdin_base64 FROM frontier WHERE id=? AND target=?',
            (row['parent_id'], row['target'])).fetchone()
        need(parent is not None, 'Feedback probe has no parent')
        need(base64.b64encode(stdin).decode('ascii') == parent['stdin_base64'],
             'Feedback probe changed its parent stdin')
        parent_argv = json.loads(parent['argv'])
        need(any(argv == parent_argv + list(candidate) and
                 origin == 'feedback:'+tag
                 for layer in self.atom_layers[row['target']][1:]
                 for candidate, tag in layer),
             'Feedback probe differs from one safe grammar extension')
        prior = self.db.execute(
            'SELECT depth FROM mutation_seeds WHERE input_id=?',
            (row['parent_id'],)).fetchone()
        return (prior['depth'] + 1) if prior is not None else 2

    def run_one(self):
        selected = self._next()
        if selected is None:
            self.generate(14)
            selected = self._next()
            if selected is None:
                return dict(state='idle')
        row, attempt = selected
        sandbox = self._sandbox(row['id'], attempt)
        environment = dict(LC_ALL='C', PATH='/usr/bin:/bin',
                           HOME=str(sandbox/'home'), TMPDIR=str(sandbox/'cwd'))
        recipe = dict(schema=1, target=row['target'],
                      argv=json.loads(row['argv']), env=environment,
                      cwd=str(sandbox/'cwd'), stdin_base64=row['stdin_base64'],
                      timeout_seconds=row['timeout_seconds'],
                      expect_signal=None)
        checked, stdin = check_invocation(recipe)
        started = time.time_ns()
        try:
            depth = self._check_generated_input(row, checked['argv'], stdin)
            wrapped = isolated_recipe(Path(row['binary_path']), checked,
                                      sandbox)
            observation = self.observer(
                self.bwrap, wrapped, stdin,
                sandbox/'capture', True, False)
            stderr_path = sandbox/'capture'/'stderr.bin'
            with stderr_path.open('rb') as stream:
                wrapper_failed = stream.read(32).startswith(b'bwrap:')
            if wrapper_failed:
                raise RuntimeError('bubblewrap failed before native execution: '+
                                   stderr_path.read_text(errors='replace')[:300])
            terminations = {r['signal'] for r in
                            observation['signal_terminations']}
            file_limit_hit = 'SIGXFSZ' in terminations
            runner_kills = unpaired_runner_kills(observation)
            runner_signals = sorted({row['signal'] for row in runner_kills})
            runner_pairs = {(row['pid'],row['signal']) for row in runner_kills}
            fatal = sorted({row['signal'] for row in
                            observation['signal_terminations']
                            if row['signal'] != 'SIGXFSZ' and
                            (row['pid'],row['signal']) not in runner_pairs})
            need(not observation['timed_out'] or not fatal,
                 'Harness timeout was classified as a native fatal signal')
            signature = behavior_signature(observation,
                                           sandbox/'capture', sandbox)
            state = ('queued' if observation['timed_out'] else
                     'fatal' if fatal else
                     'resource_limit' if file_limit_hit else
                     'runner_signal' if runner_signals else 'done')
            evidence = dict(schema=1, input_id=row['id'], target=row['target'],
                            attempt=attempt, binary_sha256=row['binary_sha256'],
                            recipe=checked,
                            isolation=isolation_descriptor(self.bwrap_sha,
                                                           self.prlimit_sha,sandbox),
                            origin=row['origin'], parent_id=row['parent_id'],
                            search_depth=depth, observation=observation,
                            resource_limit='file_bytes' if file_limit_hit else None,
                            runner_signals=runner_signals,
                            fatal_signals=fatal, behavior_signature=signature,
                            sandbox=str(sandbox) if state in ('fatal','runner_signal')
                            else None,
                            probe_started_ns=started,
                            scope='Native probe only; fatal signal needs exact-PC replay')
            raw = packed(evidence).encode()
            with self.db:
                seen = self.db.execute(
                    'SELECT seen FROM signatures WHERE signature=?',
                    (signature,)).fetchone()
                if seen is None:
                    self.db.execute('INSERT INTO signatures VALUES(?,?,1)',
                                    (signature,row['id']))
                else:
                    self.db.execute('UPDATE signatures SET seen=seen+1 '
                                    'WHERE signature=?', (signature,))
                if seen is None and state == 'done' and row['origin'] != 'baseline':
                    self.db.execute('''INSERT OR IGNORE INTO mutation_seeds
                        (input_id,target,depth) VALUES(?,?,?)''',
                        (row['id'],row['target'],depth))
                self.db.execute('INSERT INTO outcomes VALUES(?,?,?,?)',
                                (row['id'],attempt,hashlib.sha256(raw).hexdigest(),
                                 zlib.compress(raw)))
                if state == 'runner_signal':
                    self.db.execute('''INSERT INTO outcome_classifications
                        VALUES(?,?,?,?)''',
                        (row['id'],attempt,'runner_signal',
                         'SIGKILL termination lacks same-run signal delivery'))
                self.db.execute('UPDATE frontier SET status=?,timeout_seconds=? '
                                'WHERE id=?',
                                (state, row['timeout_seconds']*2
                                 if state == 'queued' else row['timeout_seconds'],
                                 row['id']))
            cleanup_error = None
            if state not in ('fatal','runner_signal'):
                try:
                    cleanup_sandbox(self.directory,sandbox)
                except (OSError, RuntimeError) as error:
                    # The probe outcome has already committed. A cleanup
                    # failure must not be reinserted as a second outcome.
                    cleanup_error = type(error).__name__ + ': ' + str(error)
            return dict(state=state, target=row['target'], input_id=row['id'],
                        attempt=attempt, fatal_signals=fatal,
                        novel_behavior=seen is None,
                        cleanup_error=cleanup_error)
        except BaseException as error:
            evidence = dict(schema=1, input_id=row['id'], target=row['target'],
                            attempt=attempt, error=type(error).__name__+': '+str(error),
                            sandbox=str(sandbox), probe_started_ns=started,
                            scope='Probe error; sandbox retained for inspection')
            raw = packed(evidence).encode()
            with self.db:
                self.db.execute('INSERT INTO outcomes VALUES(?,?,?,?)',
                                (row['id'],attempt,hashlib.sha256(raw).hexdigest(),
                                 zlib.compress(raw)))
                self.db.execute("UPDATE frontier SET status='error' WHERE id=?",
                                (row['id'],))
            return dict(state='error', target=row['target'], input_id=row['id'],
                        attempt=attempt, error=evidence['error'],
                        sandbox=str(sandbox))

    def run(self, work_items=28):
        need(type(work_items) is int and work_items >= 0,
             'Work-item quantum must be nonnegative')
        results = []
        for _ in range(work_items):
            result = self.run_one()
            if result['state'] == 'idle':
                break
            results.append(result)
        return dict(processed=len(results), results=results, status=self.status())

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.lock is not None:
            self.lock.close()
            self.lock = None

    def __enter__(self):
        return self

    def __exit__(self,*_):
        self.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('init','run','status'))
    parser.add_argument('--directory', type=Path, default=DEFAULT)
    parser.add_argument('--work-items', type=int, default=28)
    args = parser.parse_args()
    with NativeFrontier(args.directory) as frontier:
        result = (frontier.status() if args.command != 'run'
                  else frontier.run(args.work_items))
    print(packed(result), flush=True)


if __name__ == '__main__':
    main()
