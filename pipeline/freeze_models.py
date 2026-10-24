#!/usr/bin/env python3
"""Freeze one complete, current 14-tool translation in a portable local archive.

No parser, translator or OpenSSH program is run. Inputs are copied by content,
never linked to temporary files. Publication requires complete input provenance,
one shared producer/profile, and an independent readback of the staged archive.
"""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"search"))
from model_archive import binding_references, cohort_identity, sha
from saved_program_provenance import OPENSSH_PIN, need
from source_locations import checked_sha, read_verified
from verified_file_cache import signature

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = Path(__file__).resolve().parents[1] / "local/runtime"
TOOLS = ('model_archive.py', 'source_locations.py', 'saved_program_provenance.py',
         'verified_file_cache.py')


def write_bytes(path, data):
    with path.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    return write_bytes(path, (json.dumps(value, indent=2, sort_keys=True)+'\n').encode())


class Store:
    def __init__(self, root):
        self.root = root
        self.objects = {}
        self.references = {}
        self.observed = {}

    def add(self, path, expected=None, original=None):
        path = Path(path).absolute()
        original = str(path) if original is None else str(original)
        expected = checked_sha(expected or sha(path))
        need(original not in self.references or self.references[original] == expected,
             'Conflicting versions of an input: '+original)
        before = path.stat()
        need(stat.S_ISREG(before.st_mode), 'Expected a regular input: '+str(path))
        if self.observed.get((str(path), expected)) == signature(before):
            self.references[original] = expected
            return expected
        output = self.root/'objects'/expected[:2]/expected
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix('.part')
        digest = hashlib.sha256()
        size = 0
        # Deduplicate payload bytes, while still verifying every input alias.
        destination = temporary.open('xb') if expected not in self.objects else None
        try:
            with path.open('rb') as source:
                opened = os.fstat(source.fileno())
                need(signature(before) == signature(opened), 'Input replaced before copy')
                while chunk := source.read(8*1024*1024):
                    digest.update(chunk)
                    size += len(chunk)
                    if destination:
                        destination.write(chunk)
                need(signature(opened) == signature(os.fstat(source.fileno())) ==
                     signature(path.stat()), 'Input changed during copy: '+str(path))
            need(digest.hexdigest() == expected, 'Input hash differs: '+str(path))
            if destination:
                destination.flush()
                os.fsync(destination.fileno())
                destination.close()
                temporary.chmod(0o444)
                temporary.rename(output)
            self.objects[expected] = dict(bytes=size)
            self.references[original] = expected
            self.observed[(str(path), expected)] = signature(path.stat())
            return expected
        finally:
            if destination and not destination.closed:
                destination.close()
            if temporary.exists():
                temporary.unlink()


def sample_query(path, artifact_sha, binding):
    """Extract one literal recorded region without decoding a multi-GB model."""
    names = {s['source'] for s in binding['frontend_order']}
    names.update(s['original_path'] for s in binding['frontend_order'])
    pattern = re.compile(rb'\{"region":\[\{"col":\d+,"file":"[^"\\]+","line":\d+\},'
                         rb'\{"col":\d+,"file":"[^"\\]+","line":\d+\},"noCursor"\]\}')
    tail = b''
    with gzip.open(path, 'rb') as stream:
        while chunk := stream.read(1024*1024):
            data = tail+chunk
            for match in pattern.finditer(data):
                location = json.loads(match.group())
                start, end, _ = location['region']
                if start['file'] in names and end['file'] in names:
                    return dict(artifact_sha256=artifact_sha, target=binding['target'], location=location)
            tail = data[-4096:]
    raise RuntimeError('No bound source region found in '+str(path))


def git(fork, *args):
    return subprocess.check_output(['git', '-C', str(fork), *args]).decode().strip()


def freeze(report_path, destination):
    from build_guard import workflow_lock
    from run_pointer_check_plan import check_build
    report_path = report_path.resolve(strict=True)
    destination = destination.absolute()
    need(destination == ROOT/'local/models/current',
         'The maintained archive has one location: local/models/current')
    need(not destination.exists() and not destination.is_symlink(),
         'Current archive already exists; verify it instead of making another version')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with workflow_lock():
        report_sha = sha(report_path)
        report = json.loads(read_verified(report_path, report_sha))
        need(report.get('terminal') is True and report.get('passed') is True and
             report.get('artifact_format') == 'core-data' and report.get('target_count') == 14 and
             report.get('passed_count') == 14 and len(report.get('targets', [])) == 14,
             'Require a completed current export of all 14 model tools')
        check_build(ROOT, RUNTIME, report['build_receipt_sha256'])
        need(len({r['target'] for r in report['targets']}) == 14, 'Duplicate target in export')
        staging = destination.parent/('.building-'+uuid.uuid4().hex)
        staging.mkdir()
        store = Store(staging)
        data = dict(schema=1, kind='openssh-model-archive', openssh_commit=OPENSSH_PIN,
            created_utc=datetime.now(timezone.utc).isoformat(), models={}, tools={},
            export_report_sha256=store.add(report_path, report_sha),
            scope='One current model per configured tool. Source correspondence is not semantic equivalence.')
        shared = None
        for row in sorted(report['targets'], key=lambda r: r['target']):
            target = row['target']
            need(row['artifact_format'] == 'core-data' and row['passed'] is True and
                 row['encoding'] == 'gzip+json', 'Incomplete model: '+target)
            binding_sha = store.add(row['artifact_binding_path'], row['artifact_binding_sha256'])
            binding = json.loads(read_verified(Path(row['artifact_binding_path']), binding_sha))
            identity = cohort_identity(binding)
            need(identity['build_receipt_sha256'] == report['build_receipt_sha256'],
                 'Model does not belong to the current checked build: '+target)
            if shared is None:
                shared = identity
                data['cohort'] = identity
                data['target_inventory_sha256'] = binding['target_manifest_sha256']
            need(identity == shared, 'Mixed translation generations: '+target)
            for path, expected in binding_references(binding):
                store.add(path, expected)
            model_sha = store.add(row['output'], row['output_sha256'])
            model_path = staging/'objects'/model_sha[:2]/model_sha
            data['models'][target] = dict(target=target, artifact_sha256=model_sha,
                binding_sha256=binding_sha, report_sha256=report_sha,
                encoding='gzip+json', linked_units=row['linked_unit_count'],
                sample_query=sample_query(model_path, model_sha, binding))
            print(json.dumps(dict(stage='captured', target=target)), flush=True)
        # Preserve all pinned upstream files, including files changed by configure.
        inventory_path = ROOT/'outputs/openssh-lean/evidence/source-inventory.json'
        inventory_sha = store.add(inventory_path)
        inventory = json.loads(read_verified(inventory_path, inventory_sha))
        need(inventory['upstream_commit'] == OPENSSH_PIN, 'Wrong pinned source inventory')
        files = {}
        source_tree = ROOT/'work/reference-source'
        need(git(source_tree, 'rev-parse', 'HEAD') == OPENSSH_PIN,
             'Pinned OpenSSH checkout changed')
        with tempfile.TemporaryDirectory(prefix='source-recovery-', dir=RUNTIME) as recovered:
            for item in inventory['files']:
                relative = item['path']
                need(not Path(relative).is_absolute() and '..' not in Path(relative).parts,
                     'Invalid pinned source path')
                source = source_tree/relative
                if not source.is_file() or sha(source) != item['sha256']:
                    source = Path(recovered)/relative
                    source.parent.mkdir(parents=True, exist_ok=True)
                    with source.open('xb') as output:
                        subprocess.run(['git', '-C', str(source_tree), 'show',
                                        OPENSSH_PIN+':'+relative], stdout=output, check=True)
                files[relative] = store.add(source, item['sha256'],
                    original='git:'+OPENSSH_PIN+':'+relative)
        data['source_snapshot'] = dict(inventory_sha256=inventory_sha, files=files)
        census = json.loads(read_verified(Path(binding['census_path']), binding['census_sha256']))
        data['configuration'] = {name: store.add(ROOT/'work/reference-source'/name, census[key])
            for name, key in (('config.h', 'configuration_sha256'),
                              ('config.status', 'config_status_sha256'), ('Makefile', 'makefile_sha256'))}
        data['configuration_profile'] = census['profile']
        # Keep the current formalization sources and generated Lean modules with
        # the data. These are source files, not a second translation or a runner.
        fork = ROOT/'work/cerberus-lean'
        from build_models import verify_actual_tree
        verify_actual_tree()
        head = git(fork, 'rev-parse', 'HEAD')
        need(git(fork, 'rev-parse', 'HEAD') == 'c4284b08f80c4461f97d179896868106e510327e',
             'Formalization base differs')
        subprocess.run(['git', '-C', str(fork), 'apply', '--reverse', '--check',
            str(ROOT/'cerberus/patch.patch')], check=True)
        formal = {}
        for relative in git(fork, 'ls-files', '-z').split('\0'):
            if relative:
                path = fork/relative
                need(path.is_file(), 'Missing formalization source: '+relative)
                formal[relative] = store.add(path)
        generated = RUNTIME/'cerberus-lean/lean_frontend/generated'
        for path in sorted(generated.rglob('*.lean')):
            relative = 'lean_frontend/generated/'+str(path.relative_to(generated))
            digest = store.add(path)
            need(relative not in formal or formal[relative] == digest,
                 'Generated formalization differs from checked-in source')
            formal[relative] = digest
        need(git(fork, 'rev-parse', 'HEAD') == head,
             'Formalization base changed during archive capture')
        data['proof_sources'] = dict(git_commit=head, patch_sha256=sha(ROOT/'cerberus/patch.patch'), files=formal,
            toolchain_lock_sha256=store.add(ROOT/'work/toolchain-lock.json'))
        # Retain the binding inventory and current build sources used by the
        # producer receipt, without copying compilers' mutable caches.
        store.add(report['binding_receipt_path'], report['binding_receipt_sha256'])
        build = json.loads(read_verified(Path(binding['build_receipt_path']), binding['build_receipt_sha256']))
        for relative, expected in build['inputs_after']['mirrored_source'].items():
            store.add(RUNTIME/'cerberus-lean'/relative, expected)
        tools_dir = staging/'tools'
        tools_dir.mkdir()
        for name in TOOLS:
            source = ROOT/'work'/name
            digest = store.add(source)
            payload = read_verified(source, digest)
            write_bytes(tools_dir/name, payload)
            (tools_dir/name).chmod(0o444)
            data['tools'][name] = digest
        data['objects'] = store.objects
        data['references'] = [dict(original_path=p, sha256=d) for p,d in sorted(store.references.items())]
        manifest_sha = save(staging/'manifest.json', data)
        write_bytes(staging/'manifest.sha256', (manifest_sha+'  manifest.json\n').encode())
        table = ['| Tool | C input units | Compressed model (MiB) |',
                 '| --- | ---: | ---: |']
        for target, entry in data['models'].items():
            size = data['objects'][entry['artifact_sha256']]['bytes']/1024**2
            table.append(f"| {target} | {entry['linked_units']} | {size:.1f} |")
        write_bytes(staging/'README.md', (
            '# Current OpenSSH proof models\n\n'
            'This is the single maintained set: 14 models from one translator, shared semantics and build.\n'
            'The pinned C revision is `'+OPENSSH_PIN+'`. No whole-program Lean runner is included.\n\n'+
            '\n'.join(table)+'\n\n'
            'From this directory, use Python 3.11 or later:\n\n'
            '    python3 tools/model_archive.py list\n'
            '    python3 tools/model_archive.py locate --target ssh --sample\n'
            '    python3 tools/model_archive.py model-path --target ssh\n'
            '    python3 tools/model_archive.py verify --deep --offline\n\n'
            'The model path names a gzip-compressed Core JSON object. Source queries use JSONL; '
            'each query names the exact artifact SHA-256 and a structured location. '
            'Use `--cache /path/outside/archive/digests.json` for repeated lookups.\n\n'
            'All payloads are deduplicated copies under objects/. The manifest records their hashes, '
            'original provenance paths, all pinned C files and formalization sources. Original paths '
            'are identities only; the reader never falls back to them. Copy this whole directory '
            'to relocate or back up the models. The source repository tracks the generator and reader; '
            'this archive carries its own manifest and payload objects. This is persistent local storage, not an off-device backup.\n\n'
            'Verification checks saved bytes and provenance. It does not prove translation '
            'preservation, annotation membership or OpenSSH correctness. The configured profile '
            'and external-call assumptions remain part of each proof.\n').encode())
        print(json.dumps(dict(stage='archive-readback', objects=len(store.objects))), flush=True)
        # Independent process uses only the bundled reader. Its audit boundary
        # rejects access to the original sources and temporary export directory.
        result = subprocess.run([sys.executable, '-B', str(tools_dir/'model_archive.py'),
            '--archive', str(staging), '--manifest-sha256', manifest_sha,
            'verify', '--deep', '--offline'], capture_output=True, text=True)
        need(result.returncode == 0, 'Frozen archive readback failed: '+result.stderr[-4000:])
        verified = json.loads(result.stdout)
        need(verified['passed'] and verified['targets'] == 14, 'Archive readback failed')
        verified['verification_mode'] = 'independent-process-original-workspace-reads-denied'
        save(staging/'verification.json', verified)
        check_build(ROOT, RUNTIME, report['build_receipt_sha256'])
        need(sha(report_path) == report_sha, 'Export report changed during archive creation')
        for parent, _, _ in os.walk(staging, topdown=False):
            directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        staging.rename(destination)
        directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        print(json.dumps(dict(passed=True, archive=str(destination), manifest_sha256=manifest_sha,
                              targets=14, bytes=verified['stored_bytes'])), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--result', type=Path, required=True)
    args = parser.parse_args()
    freeze(args.result, ROOT/'local/models/current')


if __name__ == '__main__':
    main()
