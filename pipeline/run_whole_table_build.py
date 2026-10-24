"""Run one coordinated build and bind its terminal result to the exact inputs."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from build_guard import workflow_lock, verify_tools, record_child
from native_compiler_cache import configure as configure_native_cache, identity as native_cache_identity


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


workspace, runtime = [Path(value).resolve() for value in sys.argv[1:]]
with workflow_lock(runtime):
    verify_tools()
    configure_native_cache(workspace, runtime)
    repo = runtime/'cerberus-lean'
    project = workspace/'outputs/openssh-lean'
    bootstrap = project/'scripts/bootstrap_cerberus.sh'
    patch = project/'patches/cerberus-gnu-keywords.patch'
    manifest = workspace/'work/cerberus-changed-files.txt'
    paths = manifest.read_text(encoding='utf-8-sig').splitlines()
    pin = 'c4284b08f80c4461f97d179896868106e510327e'
    assert subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip() == pin
    subprocess.run(['git', '-C', str(repo), 'apply', '--reverse', '--check', str(patch)], check=True)


    def inputs():
        return dict(toolchain_lock=verify_tools(), compiler_cache=native_cache_identity(workspace, runtime),
                    guard=sha(Path(__file__).with_name('build_guard.py')), patch=sha(patch), bootstrap=sha(bootstrap), runner=sha(Path(__file__)),
                    lean_build_runner=sha(project/'scripts/run_capped_lean_build.py'),
                    generation_runner=sha(project/'scripts/preserve_generated_timestamps.py'),
                    source_manifest=sha(manifest),
                    mirrored_source={name: sha(repo/name) for name in paths})


    before = inputs()
    for name in paths:
        # The mirror intentionally normalizes maintained Windows text to LF.
        original = (workspace/'work/cerberus-lean'/name).read_text(encoding='utf-8').encode('utf-8')
        assert hashlib.sha256(original).hexdigest() == before['mirrored_source'][name], name
    started = datetime.now(timezone.utc)
    log = runtime/'logs'/('whole-table-build-'+started.strftime('%Y%m%dT%H%M%SZ')+'.log')
    receipt_path = runtime/'logs/whole-table-build.json'
    command = ['bash', str(bootstrap), str(runtime), str(workspace/'work/lean-4.32.2-linux')]
    receipt = dict(started_utc=started.isoformat(), pid=os.getpid(), command=command,
                   terminal=False, passed=False, inputs_before=before, log=str(log))
    receipt_path.write_text(json.dumps(receipt, indent=2)+'\n')
    with log.open('w') as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
        record_child(process, runtime)
        receipt['child_pid'] = process.pid
        receipt_path.write_text(json.dumps(receipt, indent=2)+'\n')
        print(json.dumps({'pid': os.getpid(), 'child_pid': process.pid, 'log': str(log)}), flush=True)
        status = process.wait()
    after = inputs()
    receipt.update(terminal=True, exit_code=status, finished_utc=datetime.now(timezone.utc).isoformat(),
                   inputs_after=after, passed=status == 0 and before == after, log_sha256=sha(log))
    if status == 0:
        receipt['outputs'] = {str(path.relative_to(repo)): sha(path) for path in [
            repo/'_build/default/backend/driver/main.exe', repo/'lean_frontend/.lake/build/bin/cerberus-lean',
            repo/'lean_frontend/.lake/build/bin/statement-region-test']}
    receipt_path.write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps({'passed': receipt['passed'], 'exit_code': status, 'receipt': str(receipt_path)}), flush=True)
    raise SystemExit(0 if receipt['passed'] else status or 1)
