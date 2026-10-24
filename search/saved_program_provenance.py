"""Validate saved translation evidence without confusing producer and consumer.

All original artifact/binding hashes remain unchanged. The caller records the
consumer separately; this never promotes a historical translation to a
new full build, export, equivalence claim or regression pass.
"""
from pathlib import Path

def need(condition, message):
    if not condition:
        raise RuntimeError(message)

OPENSSH_PIN = 'a8c72b842423f0774f542d3c2197247c3dd28d74'


def verify(report, row, binding, digest):
    need(report.get('terminal') is True and report.get('passed') is True and
         report.get('artifact_format') in ('core-data', 'runnable') and row.get('passed') is True and
         row.get('artifact_format') in ('core-data', 'runnable'), 'Saved model needs a successful Core data export')
    need(binding.get('scope') == 'configured-openssh-target-link-input-provenance' and
         binding.get('receipt_mode') == 'target-inputs-only' and
         binding.get('input_provenance_verified') is True and
         binding.get('linked_core_certified') is False and binding.get('lean_argv_executed') is False and
         binding.get('openssh_commit') == OPENSSH_PIN and
         binding.get('target') == row['target'] and
         binding.get('semantic_switches') == ['gnu_pointer_conversions'] and
         binding.get('host_abi') == 'linux-amd64', 'Saved program source binding differs')
    producer = binding['translator']['sha256']
    need(row.get('translator_sha256') == producer and len(producer) == 64 and
         all(c in '0123456789abcdef' for c in producer), 'Saved program producer identity differs')
    sources = binding['frontend_order']
    need(sources and len(sources) == row['linked_unit_count'] and
         len({s['source'] for s in sources}) == len(sources), 'Saved program translation closure differs')
    count = 0
    def check(path, expected):
        nonlocal count
        need(Path(path).is_absolute() and digest(path) == expected,
             'Saved program input bytes changed: '+str(path))
        count += 1
    for key in ('target_manifest', 'target_link_map', 'shared_libc_binding'):
        check(binding[key+'_path'], binding[key+'_sha256'])
    check(binding['native_target']['path'], binding['native_target']['sha256'])
    for source in sources:
        for key in ('original', 'preprocessed', 'cabs'):
            check(source[key+'_path'], source[key+'_sha256'])
    for row in binding['runtime'].values():
        check(row['path'], row['sha256'])
    libc = binding['libc']
    check(libc['core']['path'], libc['core']['sha256'])
    need(len(libc['metadata_order']) == 12, 'Saved program libc metadata count differs')
    for row in libc['metadata_order']:
        for key in ('source', 'cabs'):
            check(row[key+'_path'], row[key+'_sha256'])
    return dict(producer_sha256=producer, producer_build_sha256=binding['build_receipt_sha256'],
                verified_input_count=count,
                scope='Original saved translation inputs verified; no new translation or equivalence claimed.')
