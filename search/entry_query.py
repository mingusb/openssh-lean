"""Generate entry-fault proof jobs from the current pinned model catalog.

No caller supplies a Lean proposition or a faulting state. The generated goal
still requires an independently checked concrete entry path before discovery.
"""
import re
import json

from common import need


def memory_access_query(index, target):
    """Create the model memory-access query for one archived OpenSSH program."""
    model = index.model(target)
    need(model['artifact_sha256'] == index.archive.model(target)['artifact_sha256'],
         'Entry query model identity differs from the current archive')
    alias = 'Pinned.'+re.sub(r'[^A-Za-z0-9_]', '_', target)
    need(re.fullmatch(r'Pinned\.[A-Za-z_][A-Za-z0-9_]*', alias) is not None,
         'Target has no valid Lean model alias')
    return dict(
        goal='SignalSearch.EntryQuery.memoryAccessFromEntry '+alias,
        snapshots=[dict(target=target, alias=alias)],
        catalog_policy='staged',
        stop_after_first=True)


def all_memory_access_queries(index):
    """Lazily generate one entry query for every configured archived program."""
    for target in sorted(index.archive.data['models']):
        yield memory_access_query(index, target)


if __name__ == '__main__':
    from core_index import Index

    index = Index()
    try:
        for query in all_memory_access_queries(index):
            print(json.dumps(query, sort_keys=True))
    finally:
        index.close()
