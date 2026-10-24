"""Check typed Core ancestry against an exact archived Cabs/original-C call.

An own-located Core ancestor can identify the precise source expression
containing an inherited-location call. Structural ancestry and equal source
regions are checked facts; translation and execution equivalence are not.
"""
import argparse
from pathlib import Path
import json
from tempfile import TemporaryDirectory

from common import WORKSPACE, need
from cabs_call_witness import (DEFAULT_ARCHIVE,
                               digest, packed, save_call_witness,
                               verify_call_witness, build_call_witness,
                               NoExactMapping, require_match)
from core_index import Index
from fault_source_map import _core_site_identity
from model_archive import Archive
from signal_search import Worker


DEFAULT_BRIDGES = WORKSPACE/'local/search/catalog/core-cabs-bridges'


def core_region(cabs_region):
    need(cabs_region['tag'] == 'Loc_region' and
         cabs_region['cursor'] == 'NoCursor',
         'Cabs call does not have a plain region')
    return dict(region=[cabs_region['begin'], cabs_region['end'], 'noCursor'])


def build_context_bridge(archive, source_record, section, ordinal,
                         core_site_sha256, site_kind='indirect-call'):
    """Link one checked Core site to an own-located ancestor and C call span."""
    verify_call_witness(archive, source_record)
    need(type(section) is str and section and type(ordinal) is int and ordinal >= 0
         and type(core_site_sha256) is str and len(core_site_sha256) == 64,
         'Invalid Core site selector')
    need(site_kind in ('call', 'indirect-call', 'pure-call'),
         'Expected a typed Core call site')
    expected_location = core_region(source_record['cabs']['region'])
    index = Index(archive=archive)
    try:
        with TemporaryDirectory(prefix='core-cabs-bridge-') as directory:
            with Worker(directory) as worker:
                alias = 'CoreCabsBridge.selected'
                metadata = worker.load(
                    index, source_record['target'], section, ordinal, alias)
                require_match(metadata['name'] == source_record['caller'],
                              'Core row name differs from the Cabs caller')
                observed = worker.sites(alias, [site_kind, 'effect'])
                matches = [site for site in observed['sites']
                           if site['kind'] == site_kind and
                           _core_site_identity(archive.manifest_sha256,
                               source_record['target'], section, ordinal,
                               metadata['sha256'], site['address'])['sha256'] ==
                               core_site_sha256]
                require_match(len(matches) == 1, 'Core call site is missing or ambiguous')
                site = matches[0]
                require_match(site['location_origin'] == 'inherited' and
                              site['location'] == expected_location,
                              'Core call does not inherit the Cabs expression region')
                ancestors = [candidate for candidate in observed['sites']
                    if candidate['kind'] == 'effect' and
                    candidate['location_origin'] == 'own' and
                    candidate['location'] == expected_location and
                    len(candidate['address']) < len(site['address']) and
                    site['address'][:len(candidate['address'])] ==
                        candidate['address']]
                require_match(len(ancestors) == 1,
                              'Owning Core expression ancestor is missing or ambiguous')
                owner = ancestors[0]
        content = dict(schema=1, kind='core-cabs-source-context-bridge',
            archive_manifest_sha256=archive.manifest_sha256,
            source_call_witness_id=source_record['id'],
            target=source_record['target'], section=section, row_ordinal=ordinal,
            row_name=metadata['name'], fragment_sha256=metadata['sha256'],
            core_site_sha256=core_site_sha256, core_site_kind=site_kind,
            core_site_address=site['address'],
            core_call_location_origin=site['location_origin'],
            owning_core_ancestor=dict(kind=owner['kind'],
                address=owner['address'], location=owner['location'],
                location_origin=owner['location_origin']),
            exact_original_c_expression=dict(
                source=source_record['source'], line=source_record['line'],
                byte_span=source_record['original_c']['byte_span'],
                expression_sha256=source_record['original_c']['expression_sha256']),
            checks=dict(typed_core_site_membership_verified=True,
                typed_ancestor_membership_verified=True,
                structural_ancestry_verified=True,
                inherited_call_location_matches_cabs_region=True,
                own_ancestor_location_matches_cabs_region=True,
                original_c_call_bytes_verified=True,
                cabs_to_core_translation_proved=False,
                core_execution_reachability_proved=False,
                core_to_native_fault_correspondence_proved=False),
            scope='Typed Core call lies under an own-located expression matching '
                  'the exact Cabs/original-C source region; semantic preservation '
                  'and native SIGSEGV remain separate obligations')
        return dict(id=digest(packed(content).encode()), **content)
    finally:
        index.close()


def verify_context_bridge(archive, bridge, source_record):
    need(type(bridge) is dict and type(bridge.get('id')) is str and
         bridge.get('source_call_witness_id') == source_record.get('id'),
         'Core-Cabs bridge does not identify the supplied C source witness')
    expected = build_context_bridge(
        archive, source_record, bridge['section'], bridge['row_ordinal'],
        bridge['core_site_sha256'], bridge['core_site_kind'])
    need(bridge == expected, 'Core-Cabs bridge differs from checked source and typed Core')
    return expected


def save_context_bridge(directory, record):
    return save_call_witness(directory, record)


def ensure_core_cabs_context_bridge(target, source_file, source_line, symbol,
                                    catalog_dir, section, ordinal,
                                    core_site_sha256, site_kind='indirect-call'):
    """Produce both replayable source and Core ancestry records for a catalog."""
    archive = Archive(DEFAULT_ARCHIVE)
    try:
        source_record = build_call_witness(
            archive, target, source_file, symbol, symbol, source_line)
    except NoExactMapping as error:
        return dict(status='not_found', reason=str(error),
                    source_call_witness_id=None, core_cabs_bridge_id=None)
    source_id = source_record['id']
    save_call_witness(Path(catalog_dir)/'source-call-witnesses', source_record)
    try:
        bridge = build_context_bridge(
            archive, source_record, section, ordinal, core_site_sha256, site_kind)
    except NoExactMapping as error:
        return dict(status='source_only', reason=str(error),
                    source_call_witness_id=source_id, core_cabs_bridge_id=None)
    save_context_bridge(Path(catalog_dir)/'core-cabs-bridges', bridge)
    return dict(status='verified', source_call_witness_id=source_id,
                core_cabs_bridge_id=bridge['id'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, default=DEFAULT_ARCHIVE)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('create')
    create.add_argument('--source-witness', type=Path, required=True)
    create.add_argument('--section', required=True)
    create.add_argument('--ordinal', type=int, required=True)
    create.add_argument('--core-site-sha256', required=True)
    create.add_argument('--site-kind', default='indirect-call')
    create.add_argument('--directory', type=Path, default=DEFAULT_BRIDGES)
    verify = commands.add_parser('verify')
    verify.add_argument('file', type=Path)
    verify.add_argument('--source-witness', type=Path, required=True)
    args = parser.parse_args()
    archive = Archive(args.archive)
    source_record = json.loads(args.source_witness.read_text())
    if args.command == 'create':
        record = build_context_bridge(
            archive, source_record, args.section, args.ordinal,
            args.core_site_sha256, args.site_kind)
        file = save_context_bridge(args.directory, record)
        print(packed(dict(id=record['id'], path=str(file),
                          source_call_witness_id=source_record['id'],
                          owning_core_ancestor=record['owning_core_ancestor'],
                          scope=record['scope'])))
    else:
        record = json.loads(args.file.read_text())
        verify_context_bridge(archive, record, source_record)
        print(packed(dict(id=record['id'], status='verified', path=str(args.file))))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        print(packed(dict(status='error', error=str(error))))
        raise SystemExit(2)
