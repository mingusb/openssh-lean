"""Map a Lean-identified Core operation to the pinned original C bytes.

A site address is the child-index path reported by SignalSearch.Inspect.sites.
The live Lean worker verifies that the site belongs to its loaded, typed
function, global initializer, or implementation expression. The indexed
fragment is checked again against its archive identity before SourceMap
resolves the site's reported CerbLocation.Loc.
"""
import hashlib
import json

from saved_program_provenance import need
from source_locations import (checked_sha, file_key, location_parts,
                              tu_digest as normalized_tu_digest)


SITE_ROWS = {
    'funs': {'Proc', 'Fun'},
    'stdlib': {'Proc', 'Fun'},
    'globs': {'GlobalDef'},
    'impl0': {'Def', 'IFun'},
}


def _address(value):
    need(isinstance(value, list) and all(type(i) is int and i >= 0 for i in value),
         'A typed site needs a nonnegative child-index address')
    return tuple(value)


def _focus(mapped):
    """Select a single C line only when the recorded cursor/region warrants it."""
    for field in ('cursor', 'regions'):
        pieces = mapped.get(field, [])
        if len(pieces) != 1:
            continue
        region = pieces[0]
        if region['status'] != 'mapped':
            continue
        start, end = region['start'], region['end']
        if start['source'] == end['source'] and start['sha256'] == end['sha256'] and \
                start['line'] == end['line']:
            regions, cursors, _ = location_parts(mapped['model_location'])
            selected = cursors if field == 'cursor' else regions
            model_start, model_end = selected[0]
            return dict(source=start['source'], original_path=start['original_path'],
                        path=start['path'], sha256=start['sha256'],
                        line=start['line'], text=start['text'],
                        location_part=field,
                        model_columns=dict(start=model_start['col'], end=model_end['col'],
                            provenance='parsed-input columns; original C columns unverified'))
    return None


def _line_byte_span(mapper, focus):
    """Locate the full line in the verified original C bytes, without columns.

    SourceMap has already checked the file hash and decoded the same bytes into
    newline-separated lines. Keep cumulative offsets on that mapper so mapping
    many sites in one file remains linear in file size rather than line number.
    The half-open range excludes the newline; it is not an expression span.
    """
    cache = getattr(mapper, '_fault_line_offsets', None)
    if cache is None:
        cache = mapper._fault_line_offsets = {}
    path = focus['path']
    if path not in cache:
        offsets = [0]
        for line in mapper.lines[path][:-1]:
            offsets.append(offsets[-1] + len(line) + 1)
        cache[path] = offsets
    line = focus['line']
    raw = mapper.lines[path][line - 1]
    start = cache[path][line - 1]
    return dict(start=start, end=start + len(raw),
                sha256=hashlib.sha256(raw).hexdigest(),
                scope='entire original C source line, not an expression')


def _core_site_identity(manifest, target, section, ordinal, fragment, address):
    """Name one typed syntax node independently of its possibly shared line."""
    identity = dict(archive_manifest_sha256=manifest, target=target,
                    section=section, row_ordinal=ordinal,
                    fragment_sha256=fragment, address=list(address))
    encoded = json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()
    return dict(**identity, sha256=hashlib.sha256(encoded).hexdigest(),
                scope='one archived typed Core node; dynamic reachability unproved')


def _row_line_collisions(mapper, observed_sites, focus):
    """Count selected-kind own annotations touching a C line within one row.

    The worker may have filtered kinds. This is a diagnostic over that result,
    not a uniqueness proof over the whole row or snapshot.
    Model columns are not certified original C byte offsets, so a count of
    one cannot certify a unique C span either.
    """
    if focus is None:
        return None
    matches = []
    for row in observed_sites:
        if row.get('location_origin') != 'own':
            continue
        location = row.get('location')
        if location is None:
            continue
        try:
            regions, cursors, _ = location_parts(location)
        except RuntimeError as error:
            if str(error) == 'Source positions must be positive integers':
                continue
            raise
        for start, end in regions + cursors:
            first = mapper.files.get(file_key(start['file']), [])
            last = mapper.files.get(file_key(end['file']), [])
            if len(first) != 1 or len(last) != 1:
                continue
            first, last = first[0], last[0]
            if (first['original_sha256'] != focus['sha256'] or
                    last['original_sha256'] != focus['sha256'] or
                    first['source'] != focus['source'] or
                    last['source'] != focus['source']):
                continue
            if start['file'] == end['file']:
                touches = start['line'] <= focus['line'] <= end['line']
            else:
                touches = (start['line'] == focus['line'] or
                           end['line'] == focus['line'])
            if touches:
                matches.append(row['address'])
                break
    return dict(scope='selected-kind own annotations in this typed row only',
                source=focus['source'], sha256=focus['sha256'], line=focus['line'],
                selected_kinds=sorted({row['kind'] for row in observed_sites}),
                count=len(matches), addresses=matches,
                globally_unique_verified=False)


def _exact_crash_site_receipt(origin, focused, collisions):
    """Keep syntax locations separate from dynamic C fault attribution."""
    missing = []
    if origin != 'own':
        missing.append('site_has_no_own_core_location')
    if focused is None:
        missing.append('no_pinned_c_line_focus')
    if collisions is not None and collisions['count'] > 1:
        missing.append('multiple_selected_kind_own_sites_touch_row_source_line')
    missing.extend(('dynamic_structural_address_not_verified',
                    'unique_original_c_byte_span_not_verified',
                    'native_signal_and_c_core_correspondence_not_verified'))
    return dict(verified=False, status='unestablished',
                typed_structural_address_verified=True,
                dynamic_structural_address_verified=False,
                unique_original_c_byte_span_verified=False,
                missing_evidence=missing)


def resolve_typed_sites(index, worker, alias, sites, expected_fragment_sha256,
                        *, expected_target=None, expected_section=None,
                        expected_ordinal=None, expected_function_ordinal=None):
    """Authenticate and map several sites with one typed traversal.

    The site records must be the exact records returned by Worker.sites.
    Repeating the live request prevents a caller-supplied location from being
    presented as a location carried by the archived Core syntax.
    """
    need(isinstance(alias, str) and alias, 'Loaded row alias is required')
    need(isinstance(sites, list) and sites, 'At least one typed site is required')
    checked_sha(expected_fragment_sha256)
    need(alias in worker.loaded, 'Row is not loaded in the Lean worker')
    loaded = worker.loaded[alias]
    if expected_target is not None:
        need(loaded['target'] == expected_target, 'Loaded row target differs')
    if expected_section is not None:
        need(loaded['section'] == expected_section, 'Loaded row section differs')
    if expected_ordinal is not None:
        need(loaded['ordinal'] == expected_ordinal, 'Loaded row ordinal differs')
    if expected_function_ordinal is not None:
        need(loaded['ordinal'] == expected_function_ordinal,
             'Loaded function ordinal differs')
    need(loaded['section'] in SITE_ROWS and loaded['kind'] in SITE_ROWS[loaded['section']],
         'A typed site requires an expression-bearing Core row')
    need(loaded['sha256'] == expected_fragment_sha256,
         'Expected row fragment SHA-256 differs')
    target, section, ordinal = loaded['target'], loaded['section'], loaded['ordinal']
    indexed, _ = index.read(target, section, ordinal)
    need(indexed == loaded, 'Worker row differs from the indexed archive fragment')
    need(indexed['sha256'] == expected_fragment_sha256,
         'Indexed row fragment differs from expected identity')
    kinds = sorted({site['kind'] for site in sites})
    need(all(isinstance(kind, str) and kind for kind in kinds),
         'Typed site kinds must be nonempty strings')
    observed = worker.sites(alias, kinds)
    need(observed.get('status') == 'sites' and observed.get('section') == section and
         isinstance(observed.get('sites'), list),
         'Lean did not return typed sites for this section')
    by_address = {}
    for row in observed['sites']:
        address = _address(row['address'])
        need(address not in by_address, 'Lean returned duplicate typed site addresses')
        by_address[address] = row
    mapper = index.archive.source_map(target)
    symbol = json.loads(indexed['symbol_key'])
    tu_digest = None
    if isinstance(symbol, dict) and isinstance(symbol.get('Symbol'), list) and \
            len(symbol['Symbol']) == 3:
        possible = symbol['Symbol'][0]
        if isinstance(possible, str) and possible:
            normalized = normalized_tu_digest(possible)
            if normalized in mapper.units:
                tu_digest = normalized
    results = []
    for site in sites:
        address = _address(site['address'])
        actual = by_address.get(address)
        need(actual is not None and site == actual,
             'Site address, kind, or location differs from the loaded typed row')
        origin = actual.get('location_origin')
        need(origin in ('own', 'inherited', 'none'),
             'Lean site did not classify its source-location origin')
        location = actual.get('location')
        need((origin == 'none') == (location is None),
             'Typed site location and origin disagree')
        if origin == 'none':
            mapped = dict(status='unmapped', reason='no_site_location')
        else:
            query = dict(target=target,
                         artifact_sha256=indexed['artifact_sha256'], location=location)
            if tu_digest is not None:
                query['translation_unit_digest'] = tu_digest
            try:
                mapped = mapper.resolve(query)
            except RuntimeError as error:
                # Runtime Core definitions can carry a synthetic zero line and
                # column. Those are genuine typed sites without a C line.
                if str(error) != 'Source positions must be positive integers':
                    raise
                mapped = dict(status='unmapped', reason='non_source_position',
                              model_location=location)
            # The typed worker proves the selected site is in the fragment.
            # An inherited annotation belongs to an ancestor, not this site.
            mapped['annotation_membership_verified'] = origin == 'own'
        focused = _focus(mapped)
        own_focus = focused if origin == 'own' else None
        if own_focus is not None:
            own_focus['line_byte_span'] = _line_byte_span(mapper, own_focus)
        elif focused is not None:
            focused['line_byte_span'] = _line_byte_span(mapper, focused)
        collisions = _row_line_collisions(mapper, observed['sites'], own_focus)
        identity = _core_site_identity(index.archive.manifest_sha256, target,
                                       section, ordinal, expected_fragment_sha256,
                                       address)
        results.append(dict(schema_version=1,
            archive_manifest_sha256=index.archive.manifest_sha256,
            target=target, artifact_sha256=indexed['artifact_sha256'],
            section=section, row_ordinal=ordinal, row_name=indexed['name'],
            row_kind=indexed['kind'], row_symbol_key=indexed['symbol_key'],
            translation_unit_digest=tu_digest,
            function_ordinal=ordinal if section in ('funs', 'stdlib') else None,
            function_name=indexed['name'] if section in ('funs', 'stdlib') else None,
            function_symbol_key=indexed['symbol_key'] if section in ('funs', 'stdlib') else None,
            fragment_sha256=expected_fragment_sha256, alias=alias, site=actual,
            core_site_identity=identity,
            typed_site_membership_verified=True, source=mapped,
            site_source_mapping_verified=origin == 'own' and mapped['status'] == 'mapped',
            source_location_origin=origin,
            source_focus=own_focus,
            context_focus=focused if origin == 'inherited' else None,
            row_source_line_diagnostic=collisions,
            exact_crash_site=_exact_crash_site_receipt(origin, own_focus, collisions),
            scope='Typed archived operation and pinned C location; inherited locations '
                  'are context only. Source focus is a line, not an exact C byte span. '
                  'Execution reachability, C/Core semantic correspondence, and native '
                  'SIGSEGV remain separate claims.'))
    return results


def resolve_typed_site(index, worker, alias, site, expected_fragment_sha256,
                       *, expected_target=None, expected_section=None,
                       expected_ordinal=None, expected_function_ordinal=None):
    """Authenticate and map one Lean-identified operation."""
    return resolve_typed_sites(index, worker, alias, [site], expected_fragment_sha256,
                               expected_target=expected_target,
                               expected_section=expected_section,
                               expected_ordinal=expected_ordinal,
                               expected_function_ordinal=expected_function_ordinal)[0]
