#!/usr/bin/env bash
# Build only the C comparison oracle and C sshbuf baseline; never installs SSH.
set -euo pipefail
if [ "$#" -ne 2 ]; then
  echo 'usage: build-reference.sh GIT_SOURCE_CHECKOUT SCRATCH_DIRECTORY' >&2
  exit 2
fi
project=$(cd -- "$(dirname -- "$0")/.." && pwd)
source_repo=$(cd -- "$1" && pwd)
mkdir -p -- "$2"
scratch=$(cd -- "$2" && pwd)
expected=a8c72b842423f0774f542d3c2197247c3dd28d74
actual=$(git -C "$source_repo" rev-parse HEAD)
test "$actual" = "$expected"
reference="$scratch/reference-source"
if [ -e "$reference" ]; then
  echo 'Use a new scratch directory: reference-source already exists.' >&2
  exit 2
fi
mkdir -- "$reference"
git -C "$source_repo" archive "$expected" | tar -x -C "$reference"
cd -- "$reference"
autoreconf > "$scratch/openssh-autoreconf.log" 2>&1
./configure --without-openssl --without-zlib > "$scratch/openssh-configure.log" 2>&1
make -j4 libssh.a openbsd-compat/libopenbsd-compat.a > "$scratch/openssh-build.log" 2>&1
make -j4 regress/unittests/sshbuf/test_sshbuf > "$scratch/openssh-unit-build.log" 2>&1
regress/unittests/sshbuf/test_sshbuf > "$scratch/openssh-unit.log" 2>&1
gcc -O2 -Wall -Wextra -D_XOPEN_SOURCE=600 -D_BSD_SOURCE -D_DEFAULT_SOURCE \
  -D_GNU_SOURCE -DHAVE_CONFIG_H -I. -Iopenbsd-compat/include \
  "$project/tests/Oracle.c" -L. -Lopenbsd-compat \
  -lssh -lopenbsd-compat -lssh -lopenbsd-compat -Wl,--wrap=malloc \
  -o "$scratch/sshbuf-oracle"
printf 'C baseline and oracle built in %s\n' "$scratch"
