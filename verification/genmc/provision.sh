#!/usr/bin/env bash
# Rebuilds the pinned, patched GenMC checker and records its identity.
#
# Usage: verification/genmc/provision.sh PREFIX
#
# Runner provisioning supplies LLVM and clang 22.1.8 and GCC 14. This recipe
# never installs system packages or Rust toolchains. The lane builds the
# checker under its unprivileged UID, within its 40-minute deadline and shared
# resource limits. Every recipe or patch change selects a fresh cache entry.
# The identity binds the upstream commit, patches, recipe, checker, loaded
# libLLVM, rustc and shipped genmc-std to the versions used for qualification.
set -Eeuo pipefail

GENMC_REPOSITORY=https://github.com/MPI-SWS/genmc
GENMC_COMMIT=9f6c4c0772d0c42b325681581acc6a0f3eb9b5f7
LLVM_VERSION=22.1.8
: "${NIGHTLY:?the pinned nightly toolchain}"

prefix=${1:?usage: provision.sh PREFIX}
recipe=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$prefix"
prefix=$(cd "$prefix" && pwd)

llvm_config=$(command -v llvm-config-22)
clang=$(command -v clang-22)
cc=$(command -v gcc-14)
cxx=$(command -v g++-14)
[ "$("$llvm_config" --version)" = "$LLVM_VERSION" ]
[ "$("$clang" -dumpversion)" = "$LLVM_VERSION" ]
[ "$("$cc" -dumpversion)" = 14 ]
[ "$("$cxx" -dumpversion)" = 14 ]
llvm_cmake=$("$llvm_config" --cmakedir)

toolchain=$(rustc "+$NIGHTLY" --print sysroot)

rm -rf "$prefix/src" "$prefix/build"
git init -q "$prefix/src"
git -C "$prefix/src" fetch -q --depth 1 "$GENMC_REPOSITORY" "$GENMC_COMMIT"
git -C "$prefix/src" checkout -q FETCH_HEAD
[ "$(git -C "$prefix/src" rev-parse HEAD)" = "$GENMC_COMMIT" ]
for patch in "$recipe"/patches/*.patch; do
  git -C "$prefix/src" apply "$patch"
done

# CMake seeds its compiler and linker flags from CFLAGS, CXXFLAGS, LDFLAGS and
# a CMAKE_TOOLCHAIN_FILE in the environment at the first configure; the
# explicit empty flags and the cleared variables leave the build type's own.
env -u CFLAGS -u CXXFLAGS -u CPPFLAGS -u LDFLAGS -u CMAKE_TOOLCHAIN_FILE \
  cmake -S "$prefix/src" -B "$prefix/build" -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="$cc" -DCMAKE_CXX_COMPILER="$cxx" \
  -DCMAKE_C_FLAGS= -DCMAKE_CXX_FLAGS= -DCMAKE_EXE_LINKER_FLAGS= -DCMAKE_SHARED_LINKER_FLAGS= -DCMAKE_MODULE_LINKER_FLAGS= \
  -DCMAKE_PREFIX_PATH="$llvm_cmake;$toolchain/bin" \
  -DCLANGPATH="$clang" -DENABLE_RUST=ON > "$prefix/cmake.log"
cmake --build "$prefix/build" --parallel 2 > "$prefix/build.log"

python3 - "$prefix" "$recipe" "$GENMC_COMMIT" "$toolchain" "$NIGHTLY" "$llvm_config" "$clang" "$cxx" <<'EOF'
import hashlib, json, subprocess, sys
from pathlib import Path

prefix, recipe, commit, toolchain, name = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]), sys.argv[5]
llvm_config, clang, cxx = sys.argv[6:9]


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# The same digest as scripts/judge-genmc.py's tree(), which checks it.
def tree(root):
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file() and "target" not in p.relative_to(root).parts):
        digest.update(str(path.relative_to(root)).encode() + b"\0" + sha256(path).encode() + b"\n")
    return digest.hexdigest()


def first_line(*argv):
    return subprocess.run(argv, capture_output=True, text=True, check=True).stdout.splitlines()[0].strip()


def loaded_llvm(binary):
    """Return the resolved path of the libLLVM the dynamic loader binds `binary` to."""
    for line in subprocess.run(["ldd", str(binary)], capture_output=True, text=True, check=True).stdout.splitlines():
        name, _, target = line.strip().partition(" => ")
        if name.startswith("libLLVM"):
            return Path(target.rsplit(" (", 1)[0]).resolve()
    raise SystemExit(f"provision: {binary} loads no libLLVM")


rustc = dict(
    line.split(": ", 1)
    for line in subprocess.run([str(toolchain / "bin/rustc"), "-vV"], capture_output=True, text=True, check=True).stdout.splitlines()
    if ": " in line
)
std = prefix / "src/lli/runtime-include/rust/rust/genmc-std"
library = loaded_llvm(prefix / "build/bin/genmc")
identity = {
    "upstream": commit,
    "patches": {path.name: sha256(path) for path in sorted((recipe / "patches").glob("*.patch"))},
    "recipe": sha256(recipe / "provision.sh"),
    "binary": {"path": str(prefix / "build/bin/genmc"), "sha256": sha256(prefix / "build/bin/genmc")},
    "libllvm": {"path": str(library), "sha256": sha256(library)},
    "genmc_std": {"path": str(std), "tree": tree(std)},
    "llvm": first_line(llvm_config, "--version"),
    "clang": first_line(clang, "--version"),
    "cxx": first_line(cxx, "--version"),
    "rustc": {"release": rustc["release"], "commit": rustc["commit-hash"], "llvm": rustc["LLVM version"],
              "name": name, "toolchain": str(toolchain), "sha256": sha256(toolchain / "bin/rustc")},
}
(prefix / "identity.json").write_text(json.dumps(identity, indent=2, sort_keys=True) + "\n")
print(json.dumps(identity, sort_keys=True))
EOF
