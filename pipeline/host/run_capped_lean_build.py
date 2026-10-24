#!/usr/bin/env python3
"""Observe the live build's memory environment without imposing a cap, then replace this process with Lake."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

runtime = Path(sys.argv[1])
command = sys.argv[2:]
if command != ['lake', 'build', 'CerberusLean', 'cerberus-lean', 'statement-region-test']:
    raise SystemExit('Unexpected Lean build command')
group = next(line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
folder = Path('/sys/fs/cgroup') / group.lstrip('/')
limits = {}
for ancestor in [folder, *folder.parents]:
    limit = ancestor / 'memory.max'
    if limit.is_file():
        limits[str(ancestor)] = limit.read_text().strip()
finite = [int(value) for value in limits.values() if value.isdecimal()]
effective = min(finite) if finite else None
receipt = {'recorded_at_utc': datetime.now(timezone.utc).isoformat(),
           'pid': os.getpid(), 'cgroup': str(folder),
           'project_memory_limit_bytes': None, 'memory_max_bytes': effective,
           'ancestor_memory_limits': limits,
           'command': command, 'working_directory': str(Path.cwd())}
(runtime / 'logs/observed-build-memory.max').write_text(str(effective) + '\n' if effective is not None else 'max\n')
(runtime / 'logs/observed-build-memory.json').write_text(json.dumps(receipt, indent=2) + '\n')
os.execvp(command[0], command)
