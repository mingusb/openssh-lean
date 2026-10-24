#!/usr/bin/env bash
# Linux-only rebuild of the existing pinned environment. Never installs tools.
# Usage: bootstrap_cerberus.sh RUNTIME_DIRECTORY LEAN_4_32_2_DIRECTORY
# Prerequisites: OCaml 5.4.0, opam 2, libgmp-dev, C compiler, make, Git,
# Python 3, and a working systemd user scope or delegated cgroup v2.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
if [[ $# != 2 ]]; then
  printf '%s\n' 'Usage: bootstrap_cerberus.sh RUNTIME_DIRECTORY LEAN_4_32_2_DIRECTORY' >&2
  exit 2
fi
test -n "${OPENSSH_LEAN_LOCK_TOKEN:-}" || { echo 'Use ./work/check_batch.sh; a workflow lease is required.' >&2; exit 2; }
test -d "$1" || { echo 'Pinned runtime is missing; automatic bootstrap is forbidden.' >&2; exit 2; }
runtime=$(cd -- "$1" && pwd)
if [[ "$(findmnt -n -o FSTYPE -T "$runtime")" = tmpfs ]]; then
  printf '%s\n' 'Use persistent Linux storage (for example /var/tmp), not tmpfs.' >&2
  exit 2
fi
lean_root=$(cd -- "$2" && pwd)
export PATH="$lean_root/bin:$runtime/cerberus-lean/_opam/bin:$PATH"
# The checked runner configures ccache around the same verified /usr/bin/cc.
# Keep its persistent cache and exact compiler identity for every Lake/leanc call.
test "${LEAN_CC:-}" = /usr/lib/ccache/cc
test "${CCACHE_COMPILER:-}" = /usr/bin/cc
export OPAMROOT="$runtime/opam-root"
export OPAMJOBS=4 OPAMDOWNLOADJOBS=4
export CERB_MEM_MAX=none LEAN_NUM_THREADS=4
test "$(ocamlc -version)" = 5.4.0
lean --version | grep -F 'version 4.32.2' >/dev/null
repo="$runtime/cerberus-lean"
mkdir -p "$runtime/logs"
test -d "$repo/.git"
test "$(git -C "$repo" rev-parse HEAD)" = c4284b08f80c4461f97d179896868106e510327e
support_patch="$script_dir/../patches/cerberus-gnu-keywords.patch"
if ! git -C "$repo" apply --reverse --check "$support_patch" 2>/dev/null; then
  printf '%s\n' 'The local Cerberus changes do not match the support patch.' >&2
  exit 2
fi
test -f "$OPAMROOT/config"
cd -- "$repo"
test -d _opam/.opam-switch
python3 "$script_dir/../../../work/build_guard.py" verify
python3 "$script_dir/preserve_generated_timestamps.py" --reuse-verified ocaml --directory "$repo/ocaml_frontend/generated" --receipt "$runtime/logs/generate-ocaml-timestamps.json" -- opam exec --switch=. -- make -W frontend/model/translation.lem prelude-src > "$runtime/logs/generate-ocaml.log" 2>&1
# Sibylfs has its own Make dependencies and is outside the Lem content stamp.
opam exec --switch=. -- make sibylfs-src >> "$runtime/logs/generate-ocaml.log" 2>&1
opam exec --switch=. -- dune build -j 4 backend/driver/main.exe cerberus-lib.install > "$runtime/logs/build-ocaml.log" 2>&1
opam exec --switch=. -- dune install --prefix "$repo/_build/local-install" cerberus-lib > "$runtime/logs/install-runtime.log" 2>&1
opam exec --switch=. -- dune build -j 4 cerberus.install > "$runtime/logs/build-libc.log" 2>&1
python3 scripts/test_openssh_gnu_keywords.py --output "$runtime/logs/gnu-keywords.json"
python3 "$script_dir/preserve_generated_timestamps.py" --reuse-verified lean --directory "$repo/lean_frontend/generated" --receipt "$runtime/logs/generate-lean-timestamps.json" -- opam exec --switch=. -- make lean-prelude-src > "$runtime/logs/generate-lean.log" 2>&1
opam exec --switch=. -- ./scripts/capped make lean-native-obj > "$runtime/logs/build-native.log" 2>&1
cd lean_frontend
../scripts/capped python3 "$script_dir/run_capped_lean_build.py" "$runtime" lake build CerberusLean cerberus-lean statement-region-test > "$runtime/logs/build-lean.log" 2>&1
printf '%s\n' "$repo/lean_frontend/.lake/build/bin/cerberus-lean"
