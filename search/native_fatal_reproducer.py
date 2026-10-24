"""Deterministic Bash programs for generic native fatal-signal observations."""
import base64
import json


SCRIPT = r'''#!/usr/bin/bash
# Generated from a pinned native fatal-signal observation.
# The original run and this replay are separate evidence.
set -euo pipefail
PATH=/usr/bin:/bin
umask 077
scratch=$(/usr/bin/mktemp -d /var/tmp/openssh-fatal-replay.XXXXXXXX)
trap '/usr/bin/rm -rf -- "$scratch"' EXIT
/usr/bin/mkdir -- "$scratch/home" "$scratch/cwd"
/usr/bin/python3 -I - "$scratch" <<'REPLAY_NATIVE_FATAL'
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys

spec = json.loads(base64.b64decode("@@SPEC_BASE64@@", validate=True))
scratch = Path(sys.argv[1])
binary = Path(spec["binary"]["path"])
if not binary.is_file() or binary.is_symlink() or not os.access(binary, os.X_OK):
    raise SystemExit("Pinned native executable is unavailable")
with binary.open("rb") as stream:
    binary_sha = hashlib.file_digest(stream, "sha256").hexdigest()
if binary_sha != spec["binary"]["sha256"]:
    raise SystemExit("Pinned native executable changed")
asset = Path(spec["stdin"]["path"])
if not asset.is_file() or asset.is_symlink():
    raise SystemExit("Catalog stdin asset is unavailable")
stdin = asset.read_bytes()
if len(stdin) != spec["stdin"]["bytes"] or hashlib.sha256(stdin).hexdigest() != spec["stdin"]["sha256"]:
    raise SystemExit("Catalog stdin asset changed")
recipe = spec["recipe"]
environment = dict(recipe["env"])
environment["HOME"] = str(scratch / "home")
environment["TMPDIR"] = str(scratch / "cwd")
expected = spec["signal"]
if expected not in signal.Signals.__members__:
    raise SystemExit("Unknown expected signal")
trace_prefix = scratch / "trace"
strace = Path("/usr/bin/strace")
if not strace.is_file():
    raise SystemExit("strace is required to observe all launched processes")
native_command = [str(binary), *recipe["argv"]]
isolation = spec.get("first_run_isolation")
if isolation is not None:
    if (isolation.get("schema") != 1 or isolation.get("kind") != "bwrap-local-v1"
            or isolation.get("network") != "unshared"
            or isolation.get("pid") != "unshared"
            or isolation.get("ipc") != "unshared"
            or isolation.get("root") != "read-only"
            or isolation.get("tmpfs_bytes") != 16777216
            or isolation.get("file_bytes") != 16777216):
        raise SystemExit("Unsupported native isolation descriptor")
    bwrap = Path("/usr/bin/bwrap")
    if not bwrap.is_file() or bwrap.is_symlink():
        raise SystemExit("Pinned bubblewrap executable is unavailable")
    with bwrap.open("rb") as stream:
        bwrap_sha = hashlib.file_digest(stream, "sha256").hexdigest()
    if bwrap_sha != isolation["executable_sha256"]:
        raise SystemExit("Pinned bubblewrap executable changed")
    prlimit = Path("/usr/bin/prlimit")
    if not prlimit.is_file() or prlimit.is_symlink():
        raise SystemExit("Pinned prlimit executable is unavailable")
    with prlimit.open("rb") as stream:
        prlimit_sha = hashlib.file_digest(stream, "sha256").hexdigest()
    if prlimit_sha != isolation["prlimit_sha256"]:
        raise SystemExit("Pinned prlimit executable changed")
    native_command = [
        str(bwrap), "--unshare-user", "--unshare-net", "--unshare-pid",
        "--unshare-ipc", "--disable-userns", "--die-with-parent",
        "--ro-bind", "/", "/", "--dev-bind", "/dev", "/dev",
        "--proc", "/proc", "--bind", str(scratch), str(scratch),
        "--size", "16777216", "--tmpfs", "/tmp", "--",
        str(prlimit), "--fsize=16777216:16777216", "--",
        *native_command]
command = [str(strace), "-ff", "-i", "-k", "-e", "trace=none",
           "-e", "signal=all", "-o", str(trace_prefix), "--", *native_command]
with (scratch / "stdout.bin").open("wb") as stdout, (scratch / "stderr.bin").open("wb") as stderr:
    process = subprocess.Popen(command, cwd=scratch / "cwd", env=environment,
                               stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                               start_new_session=True)
    try:
        process.communicate(input=stdin, timeout=recipe["timeout_seconds"])
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise SystemExit("Native invocation timed out; no fatal signal reproduced")
delivery = re.compile(r"^(?:\[[0-9a-fA-F?]+\] )?--- (SIG[A-Z0-9]+) ")
termination = re.compile(r"^(?:\[[^]]+\] )?\+\+\+ killed by (SIG[A-Z0-9]+)(?: \(core dumped\))? \+\+\+$")
delivered, terminated, last_attributed = set(), set(), {}
traces = sorted(scratch.glob("trace.*"))
if not traces:
    raise SystemExit("No native signal trace was captured")
for trace in traces:
    pid = trace.name.removeprefix("trace.")
    active_signal = None
    with trace.open(errors="replace") as lines:
        for line in lines:
            line = line.rstrip("\n")
            if match := delivery.match(line):
                active_signal = match[1]
                pair = (pid, active_signal)
                delivered.add(pair)
                last_attributed[pair] = False
                continue
            if active_signal and line.startswith(" > "):
                if line.startswith(" > " + str(binary) + "("):
                    last_attributed[(pid, active_signal)] = True
                continue
            if match := termination.match(line):
                terminated.add((pid, match[1]))
            active_signal = None
if not any(name == expected and last_attributed.get((pid, name), False)
           for pid, name in delivered & terminated):
    raise SystemExit(f"Expected fatal {expected} in pinned C executable was not observed for one PID")
capture_name = os.environ.get("OPENSSH_FATAL_CAPTURE_DIR")
if capture_name:
    capture = Path(capture_name)
    if not capture.is_absolute() or not capture.is_dir() or capture.is_symlink() or any(capture.iterdir()):
        raise SystemExit("Replay capture destination must be a new empty directory")
    for source in [*traces, scratch / "stdout.bin", scratch / "stderr.bin"]:
        with source.open("rb") as original, (capture / source.name).open("xb") as stored:
            shutil.copyfileobj(original, stored)
print(f"REPRODUCED_FATAL_SIGNAL {expected} target={spec['target']} binary_sha256={binary_sha}")
REPLAY_NATIVE_FATAL
'''


def render_native_fatal_script(spec):
    """Embed immutable invocation metadata, while retaining stdin as a hashed asset."""
    raw = json.dumps(spec, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    encoded = base64.b64encode(raw).decode('ascii')
    return SCRIPT.replace('@@SPEC_BASE64@@', encoded).encode('utf-8')
