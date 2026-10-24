"""Resolve recorded Core locations against a saved export's original C bytes.

This is an analysis-side source locator, not a C/Core equivalence certificate.
Queries carry the compressed export's output_sha256 and a CerbLocation.Loc JSON
value. No model decoding, interpreter execution or native invocation is needed.
Use the workflow lease when supplying the shared VerifiedDigests cache.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import time

from saved_program_provenance import OPENSSH_PIN, need
from verified_file_cache import VerifiedDigests, signature


def checked_sha(value):
    need(isinstance(value, str) and len(value) == 64 and
         all(c in '0123456789abcdef' for c in value), 'Invalid SHA-256 identity')
    return value


def tu_digest(value):
    # Cerberus renders the MD5 as a natural number, omitting leading zeroes.
    need(isinstance(value, str) and 1 <= len(value) <= 32 and
         all(c in '0123456789abcdef' for c in value), 'Invalid translation-unit digest')
    return value.zfill(32)


def file_key(value):
    need(isinstance(value, str) and value and '\0' not in value,
         'Invalid source filename')
    path = PurePosixPath(value)
    need('..' not in path.parts, 'Parent traversal is not a source alias')
    return str(path)


def position(value):
    need(isinstance(value, dict) and set(value) == {'file', 'line', 'col'},
         'Expected a structured CerbLocation.Pos')
    file_key(value['file'])
    for field in ('line', 'col'):
        need(type(value[field]) is int and value[field] >= 1,
             'Source positions must be positive integers')
    return value


def pair(value):
    need(isinstance(value, list) and len(value) == 2, 'Expected two source positions')
    start, end = map(position, value)
    if file_key(start['file']) == file_key(end['file']):
        need((start['line'], start['col']) <= (end['line'], end['col']),
             'Reversed source region')
    return start, end


def location_parts(value):
    """Keep disjoint regions and the cursor separate; never invent a bounding box."""
    if value == 'unknown':
        return [], [], 'unknown'
    need(isinstance(value, dict) and len(value) == 1, 'Expected a structured CerbLocation.Loc')
    tag, data = next(iter(value.items()))
    if tag == 'other':
        need(isinstance(data, str), 'Invalid synthetic location')
        return [], [], 'synthetic'
    if tag == 'point':
        p = position(data)
        return [(p, p)], [], None
    need(tag in ('region', 'regions') and isinstance(data, list) and
         len(data) == (3 if tag == 'region' else 2), 'Invalid Core source region')
    if tag == 'region':
        regions, cursor = [pair(data[:2])], data[2]
    else:
        need(isinstance(data[0], list), 'Invalid disjoint source regions')
        regions, cursor = [pair(p) for p in data[0]], data[1]
    cursors = []
    if cursor != 'noCursor':
        need(isinstance(cursor, dict) and len(cursor) == 1, 'Invalid source cursor')
        cursor_tag, content = next(iter(cursor.items()))
        if cursor_tag == 'pointCursor':
            p = position(content)
            cursors = [(p, p)]
        else:
            need(cursor_tag == 'regionCursor', 'Invalid source cursor constructor')
            cursors = [pair(content)]
    return regions, cursors, None if regions or cursors else 'empty_regions'


def read_verified(path, expected):
    """Hash the same bytes that will be decoded; reject replacement during read."""
    path = Path(path)
    need(path.is_absolute(), 'Expected an absolute recorded artifact path')
    checked_sha(expected)
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode), 'Expected a regular source artifact')
        data = stream.read()
        need(signature(before) == signature(os.fstat(stream.fileno())) == signature(path.stat()),
             'Source artifact changed during read: ' + str(path))
    need(hashlib.sha256(data).hexdigest() == expected, 'Recorded bytes changed: ' + str(path))
    return data


class SourceMap:
    def __init__(self, report_path, target, digests, resolve_path=None):
        self.digests = digests
        self.resolve_path = resolve_path or (lambda path, expected: Path(path))
        self.lines = {}
        report_bytes = Path(report_path).read_bytes()
        report = json.loads(report_bytes)
        need(report.get('terminal') is True and report.get('passed') is True and
             report.get('artifact_format') in ('core-data', 'runnable'), 'Expected a completed Core data export')
        rows = [r for r in report['targets'] if r.get('target') == target]
        need(len(rows) == 1, 'Target must identify exactly one saved export')
        row = rows[0]
        need(row.get('passed') is True and row.get('artifact_format') in ('core-data', 'runnable'),
             'Selected target is not a successful Core data export')
        self.artifact_sha256 = checked_sha(row['output_sha256'])
        self.binding_sha256 = checked_sha(row['artifact_binding_sha256'])
        binding = json.loads(read_verified(self.resolve_path(row['artifact_binding_path'], self.binding_sha256), self.binding_sha256))
        need(binding.get('schema_version') == 2 and
             binding.get('scope') == 'configured-openssh-target-link-input-provenance' and
             binding.get('receipt_mode') == 'target-inputs-only' and
             binding.get('input_provenance_verified') is True and
             binding.get('openssh_commit') == OPENSSH_PIN and binding.get('target') == target,
             'Saved source binding identity differs')
        producer = checked_sha(binding['translator']['sha256'])
        need(row.get('translator_sha256') == producer, 'Export producer differs from source binding')
        sources = binding['frontend_order']
        need(sources and len(sources) == row['linked_unit_count'] and
             len({s['source'] for s in sources}) == len(sources), 'Source closure differs')
        self.files, self.units = {}, {}
        for source in sources:
            relative = file_key(source['source'])
            original = file_key(source['original_path'])
            need(not PurePosixPath(relative).is_absolute() and Path(original).is_absolute(),
                 'Invalid recorded source paths')
            checked_sha(source['original_sha256'])
            unit = tu_digest(source['preprocessed_digest_md5'])
            need(tu_digest(source['cabs_digest_md5']) == unit, 'Parser translation-unit identity differs')
            self.units.setdefault(unit, []).append(source['source'])
            # Exact recorded relative/absolute names only. No basename guessing.
            for name in {relative, original}:
                self.files.setdefault(name, []).append(source)
        artifact = self.resolve_path(row['output'], self.artifact_sha256)
        need(artifact.is_absolute() and digests.digest(artifact) == self.artifact_sha256,
             'Saved model bytes changed')
        self.identity = dict(target=target, artifact_sha256=self.artifact_sha256,
                             binding_sha256=self.binding_sha256,
                             export_report_sha256=hashlib.sha256(report_bytes).hexdigest(),
                             openssh_commit=OPENSSH_PIN, producer_sha256=producer,
                             host_abi=binding['host_abi'], semantic_switches=binding['semantic_switches'])

    def _point(self, point):
        candidates = self.files.get(file_key(point['file']), [])
        if len(candidates) != 1:
            return dict(status='unmapped', reason='ambiguous_file' if candidates else 'unbound_file',
                        reported_position=point)
        source = candidates[0]
        original, expected = source['original_path'], source['original_sha256']
        path = str(self.resolve_path(original, expected))
        # Recheck each lookup, including cache hits. A long-lived batch must not
        # silently serve a location after its C file has been edited or replaced.
        need(self.digests.digest(path) == expected, 'Original C bytes changed: ' + path)
        if path not in self.lines:
            self.lines[path] = read_verified(path, expected).split(b'\n')
        lines = self.lines[path]
        line = point['line']
        if line > len(lines):
            return dict(status='unmapped', reason='line_out_of_range', reported_position=point)
        return dict(status='mapped', source=source['source'], path=path, original_path=original, sha256=expected,
                    line=line, text=lines[line - 1].decode('utf-8', errors='replace'))

    def _region(self, positions):
        start = self._point(positions[0])
        same_line = (file_key(positions[0]['file']) == file_key(positions[1]['file']) and
                     positions[0]['line'] == positions[1]['line'])
        end = start if same_line and start['status'] == 'mapped' else self._point(positions[1])
        mapped = sum(p['status'] == 'mapped' for p in (start, end))
        cross_file = file_key(positions[0]['file']) != file_key(positions[1]['file'])
        return dict(status=('mapped' if mapped == 2 else 'partial' if mapped else 'unmapped'),
                    shape='endpoints_only' if cross_file else 'region', start=start, end=end)

    def resolve(self, query):
        need(isinstance(query, dict) and query.get('artifact_sha256') == self.artifact_sha256,
             'Query must name this exact saved model SHA-256')
        need(query.get('target', self.identity['target']) == self.identity['target'],
             'Query target differs from saved export')
        unit = None
        if 'translation_unit_digest' in query:
            digest = tu_digest(query['translation_unit_digest'])
            candidates = self.units.get(digest, [])
            need(len(candidates) == 1, 'Unknown or ambiguous translation-unit digest')
            unit = dict(source=candidates[0], digest=digest)
        regions, cursors, reason = location_parts(query['location'])
        mapped_regions = [self._region(p) for p in regions]
        mapped_cursors = [self._region(p) for p in cursors]
        all_regions = mapped_regions + mapped_cursors
        statuses = {p['status'] for p in all_regions}
        status = ('mapped' if statuses == {'mapped'} else
                  'partial' if 'mapped' in statuses or 'partial' in statuses else 'unmapped')
        return dict(schema_version=1, id=query.get('id'), **self.identity, status=status,
                    reason=reason, translation_unit=unit, model_location=query['location'],
                    regions=mapped_regions, cursor=mapped_cursors, precision='source_lines',
                    column_note='Model columns retained; macro-expanded columns are not certified C columns.',
                    annotation_membership_verified=False, semantic_correspondence_proved=False,
                    scope='Recorded source-location lookup; not a finding, proof or behavioral validation.')


def resolve_stream(mapper, incoming, outgoing):
    """Drain independent queries, including after a bad query; never hide errors."""
    counts = dict(mapped=0, partial=0, unmapped=0, error=0)
    for number, line in enumerate(incoming, 1):
        if not line.strip():
            continue
        try:
            result = mapper.resolve(json.loads(line))
        except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
            result = dict(schema_version=1, status='error', input_line=number, error=str(error))
        counts[result['status']] += 1
        outgoing.write(json.dumps(result, separators=(',', ':'), ensure_ascii=True) + '\n')
        outgoing.flush()
    return counts


def main():
    from common import RUNTIME, workflow_lock
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--result', type=Path, required=True, help='Completed Core data export result.json')
    parser.add_argument('--target', required=True)
    parser.add_argument('--queries', type=Path, help='JSONL queries; stdin when omitted')
    args = parser.parse_args()
    started = time.perf_counter()
    with workflow_lock():
        digests = VerifiedDigests(RUNTIME/'runnable-core-cache/verified-files.json')
        try:
            mapper = SourceMap(args.result, args.target, digests)
            ready = time.perf_counter()
            if args.queries:
                with args.queries.open(encoding='utf-8') as incoming:
                    counts = resolve_stream(mapper, incoming, sys.stdout)
            else:
                counts = resolve_stream(mapper, sys.stdin, sys.stdout)
        finally:
            digests.flush()
    print(json.dumps(dict(scope='Source lookup only', counts=counts,
                          setup_seconds=ready-started,
                          query_io_seconds=time.perf_counter()-ready)), file=sys.stderr)
    return int(any(counts[k] for k in ('partial', 'unmapped', 'error')))


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        print(json.dumps(dict(status='error', error=str(error))), file=sys.stderr)
        sys.exit(2)
