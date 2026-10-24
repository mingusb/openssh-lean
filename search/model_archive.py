"""Read frozen OpenSSH models using only this archive and Python's standard library."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import sys

from saved_program_provenance import OPENSSH_PIN, need, verify as verify_inputs
from source_locations import SourceMap, checked_sha, read_verified, resolve_stream
from verified_file_cache import VerifiedDigests


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def binding_references(binding):
    """Every input named by a target binding, including its producing tools."""
    for key in ('target_manifest', 'target_link_map', 'shared_libc_binding',
                'build_receipt', 'binding_generator', 'census'):
        yield binding[key+'_path'], binding[key+'_sha256']
    for key in ('native_target', 'translator', 'parser', 'cpp_adapter'):
        yield binding[key]['path'], binding[key]['sha256']
    for source in binding['frontend_order']:
        for key in ('original', 'preprocessed', 'cabs'):
            yield source[key+'_path'], source[key+'_sha256']
    for value in binding['runtime'].values():
        yield value['path'], value['sha256']
    yield binding['libc']['core']['path'], binding['libc']['core']['sha256']
    for source in binding['libc']['metadata_order']:
        for key in ('source', 'cabs'):
            yield source[key+'_path'], source[key+'_sha256']


def cohort_identity(binding):
    """The shared translation inputs must be identical for every maintained tool."""
    return dict(openssh_commit=binding['openssh_commit'],
        build_receipt_sha256=binding['build_receipt_sha256'],
        translator_sha256=binding['translator']['sha256'],
        parser_sha256=binding['parser']['sha256'],
        semantic_switches=binding['semantic_switches'], host_abi=binding['host_abi'],
        address_space_top=binding['address_space_top'], fuel=binding['fuel'],
        runtime={k: v['sha256'] for k, v in binding['runtime'].items()},
        libc_core_sha256=binding['libc']['core']['sha256'],
        libc_metadata=[(s['name'], s['source_sha256'], s['cabs_sha256'])
                       for s in binding['libc']['metadata_order']])


class Archive:
    def __init__(self, root, expected_manifest=None, cache=None):
        self.root = Path(root).resolve(strict=True)
        manifest = self.root/'manifest.json'
        need(not manifest.is_symlink(), 'Manifest cannot be a symbolic link')
        expected = expected_manifest or (self.root/'manifest.sha256').read_text().split()[0]
        self.manifest_sha256 = checked_sha(expected)
        self.data = json.loads(read_verified(manifest, expected))
        need(self.data.get('schema') == 1 and self.data.get('kind') == 'openssh-model-archive',
             'Unrecognized model archive')
        need(self.data.get('openssh_commit') == OPENSSH_PIN, 'Archive source revision differs')
        self.references = {(r['original_path'], r['sha256']) for r in self.data['references']}
        if cache is not None:
            need(not Path(cache).resolve().is_relative_to(self.root),
                 'Digest cache must be outside the frozen archive')
        self.digests = VerifiedDigests(cache or self.root/'.unused-digest-cache')
        self.cache = cache
        for digest, row in self.data['objects'].items():
            checked_sha(digest)
            need(type(row['bytes']) is int and row['bytes'] >= 0, 'Invalid object size')
        for _, digest in self.references:
            need(digest in self.data['objects'], 'Reference names a missing object')
        for target, row in self.data['models'].items():
            need(row['target'] == target, 'Invalid model target')
        need(self.data['models'], 'Archive has no models')

    def object_path(self, digest):
        checked_sha(digest)
        need(digest in self.data['objects'], 'Object is absent from archive: '+digest)
        path = self.root/'objects'/digest[:2]/digest
        need(not any(p.is_symlink() for p in (path, path.parent, path.parent.parent)),
             'Archive object cannot be a symbolic link')
        need(path.is_file() and path.stat().st_size == self.data['objects'][digest]['bytes'],
             'Archive object is missing or has changed size: '+digest)
        return path

    def resolve(self, original, expected):
        need((str(original), expected) in self.references,
             'Recorded file is not captured in this archive: '+str(original))
        return self.object_path(expected)

    def read_json(self, digest):
        return json.loads(read_verified(self.object_path(digest), digest))

    def model(self, target):
        need(target in self.data['models'], 'Unknown target; use list')
        return self.data['models'][target]

    def source_map(self, target):
        entry = self.model(target)
        report = self.read_json(entry['report_sha256'])
        rows = [r for r in report['targets'] if r.get('target') == target]
        need(len(rows) == 1 and rows[0]['output_sha256'] == entry['artifact_sha256'] and
             rows[0]['artifact_binding_sha256'] == entry['binding_sha256'],
             'Archived report/model selection differs')
        mapper = SourceMap(self.object_path(entry['report_sha256']), target,
                           self.digests, resolve_path=self.resolve)
        need(mapper.artifact_sha256 == entry['artifact_sha256'] and
             mapper.identity['export_report_sha256'] == entry['report_sha256'],
             'Mapper selected another model/report')
        return mapper

    def verify(self, deep=False, progress=None):
        # Full verification deliberately hashes every object. Ordinary lookups
        # verify only their selected model/binding/source and can use a digest cache.
        self.digests.entries.clear()
        for digest in self.data['objects']:
            need(self.digests.digest(self.object_path(digest)) == digest, 'Corrupt archived object: '+digest)
        for name, digest in self.data['tools'].items():
            need(Path(name).name == name, 'Invalid archive tool name')
            path = self.root/'tools'/name
            need(not path.is_symlink() and not path.parent.is_symlink() and sha(path) == digest,
                 'Archived reader changed: '+name)
        source = self.data['source_snapshot']
        inventory = self.read_json(source['inventory_sha256'])
        need(inventory['upstream_commit'] == OPENSSH_PIN and
             {r['path']: r['sha256'] for r in inventory['files']} == source['files'],
             'Pinned source inventory is incomplete')
        for digest in source['files'].values():
            self.object_path(digest)
        report = self.read_json(self.data['export_report_sha256'])
        inventory = self.read_json(self.data['target_inventory_sha256'])
        targets = {row['target'] for row in report['targets']}
        need(targets == set(self.data['models']) and len(report['targets']) == len(targets) ==
             report['target_count'] == inventory['target_count'], 'Target inventory is incomplete')
        need({row['target'] for row in inventory['targets']} == targets, 'Configured targets differ')
        for name, digest in self.data['proof_sources']['files'].items():
            need(not Path(name).is_absolute() and '..' not in Path(name).parts,
                 'Invalid proof source path')
            self.object_path(digest)
        mapped = 0
        for key, entry in self.data['models'].items():
            binding = self.read_json(entry['binding_sha256'])
            # JSON normalization gives the same list representation after loading.
            need(json.loads(json.dumps(cohort_identity(binding))) == self.data['cohort'],
                 'Models were produced with different translation inputs: '+key)
            for original, expected in binding_references(binding):
                self.resolve(original, expected)
            row = next(r for r in report['targets'] if r['target'] == key)
            refs = dict(binding_references(binding))
            verify_inputs(report, row, binding,
                          lambda path: self.digests.digest(self.resolve(path, refs[str(path)])))
            mapper = self.source_map(entry['target'])
            result = mapper.resolve(entry['sample_query'])
            need(result['status'] == 'mapped', 'Archived source sample failed: '+key)
            mapped += 1
            if deep:
                digest, size = hashlib.sha256(), 0
                with gzip.open(self.object_path(entry['artifact_sha256']), 'rb') as stream:
                    while chunk := stream.read(8*1024*1024):
                        digest.update(chunk)
                        size += len(chunk)
                need(digest.hexdigest() == row['raw_output_sha256'] and size == row['raw_output_bytes'],
                     'Decompressed model differs from its export receipt: '+key)
            if progress:
                progress(dict(verified_model=key, deep=deep))
        return dict(passed=True, manifest_sha256=self.manifest_sha256,
            targets=len(self.data['models']),
            source_files=len(source['files']), objects=len(self.data['objects']),
            stored_bytes=sum(r['bytes'] for r in self.data['objects'].values()),
            mapped_samples=mapped, decompressed_models_verified=deep,
            complete_binding_inputs=True, consistent_translation_inputs=True,
            scope='Frozen models and source bytes verified; no retranslation, OpenSSH execution or semantic equivalence claim.')

    def flush(self):
        if self.cache:
            self.digests.flush()


def offline_reads(root):
    """Integration-test boundary: archive operations cannot read the old workspace."""
    root = Path(root).resolve()
    def audit(event, args):
        if event != 'open' or not isinstance(args[0], (str, bytes)):
            return
        path = Path(args[0].decode() if isinstance(args[0], bytes) else args[0]).absolute()
        if path.is_relative_to(root):
            return
        if path.is_relative_to(Path(__file__).resolve().parents[1]):
            raise RuntimeError('Offline archive attempted to read its former workspace: '+str(path))
    sys.addaudithook(audit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parent = Path(__file__).resolve().parent
    default = parent.parent if parent.name == 'tools' else parent.parent/'local/models/current'
    parser.add_argument('--archive', type=Path, default=default)
    parser.add_argument('--manifest-sha256', help='Expected manifest hash from a trusted archive index')
    parser.add_argument('--cache', type=Path, help='Optional writable digest cache outside the frozen archive')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('list')
    check = commands.add_parser('verify')
    check.add_argument('--deep', action='store_true', help='Also stream and hash decompressed models')
    check.add_argument('--offline', action='store_true', help='Refuse reads from the original workspace/cache')
    for name in ('locate', 'model-path'):
        command = commands.add_parser(name)
        command.add_argument('--target', required=True)
        if name == 'locate':
            command.add_argument('--queries', type=Path, help='JSONL queries; stdin unless --sample is used')
            command.add_argument('--sample', action='store_true')
    args = parser.parse_args()
    if getattr(args, 'offline', False):
        offline_reads(args.archive)
    archive = Archive(args.archive, args.manifest_sha256, args.cache)
    try:
        if args.command == 'list':
            print(json.dumps(dict(manifest_sha256=archive.manifest_sha256,
                cohort=archive.data['cohort'], models={target: dict(
                    artifact_sha256=row['artifact_sha256'], linked_units=row.get('linked_units'),
                    compressed_bytes=archive.data['objects'][row['artifact_sha256']]['bytes'])
                    for target, row in archive.data['models'].items()}), indent=2))
        elif args.command == 'verify':
            result = archive.verify(args.deep, lambda row: print(json.dumps(row), file=sys.stderr, flush=True))
            print(json.dumps(result, indent=2))
        elif args.command == 'model-path':
            entry = archive.model(args.target)
            path = archive.object_path(entry['artifact_sha256'])
            need(archive.digests.digest(path) == entry['artifact_sha256'], 'Model bytes changed')
            print(path)
        else:
            mapper = archive.source_map(args.target)
            if args.sample:
                print(json.dumps(mapper.resolve(archive.model(args.target)['sample_query'])))
            else:
                if args.queries:
                    with args.queries.open() as stream:
                        counts = resolve_stream(mapper, stream, sys.stdout)
                else:
                    counts = resolve_stream(mapper, sys.stdin, sys.stdout)
                return int(any(counts[k] for k in ('partial', 'unmapped', 'error')))
    finally:
        archive.flush()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        print(json.dumps(dict(status='error', error=str(error))), file=sys.stderr)
        sys.exit(2)
