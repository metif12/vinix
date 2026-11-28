#!/bin/sh
# Bootstrap a pinned, known-working V compiler for the Wi-Fi build.
# Refuse an existing destination; never reset/clean a user's compiler checkout.
#
# The pin must agree with the kernel's platform integer types. The kernel
# migrated `usize`/`isize` to `uint`/`int` in fcdf20313; a V older than
# fca9fad345 still declares builtin `C.memcpy`/`C.memset` with `usize`, so it
# rejects the kernel's `uint` declarations as conflicting signatures. This
# pin is from after that compiler change and is paired with the vc snapshot
# generated from it, so a clean bootstrap is reproducible.
#
# V's own bootstrap compiler ("vc") is pinned too, not left to `make`'s
# default `latest_vc` target: without `local=1`, a clean destination runs
# `fresh_vc`, which clones vlang/vc with no revision pinned at all, so the
# V pin above could silently get built by a different, later vc snapshot
# on a later clean run -- and a later vc can become incompatible with
# these historical V sources with nothing here to explain why the build
# suddenly stopped working. Clone vc ourselves at a revision already
# confirmed to build this exact V pin successfully, and pass local=1 so
# V's own make leaves it alone instead of pulling a fresh one.
set -eu
DEST=${1:-build-tools/v-m1-wifi}
HOST_CC=${HOST_CC:-clang}
PIN=eab77e7ec31516521d26b6d5e525aefe5987367b
VC_PIN=0781dbf8ed16a8e9ebce3771a645b814456c0103
if [ -e "$DEST" ]; then
    echo "Destination already exists: $DEST (set V to its v executable instead)" >&2
    exit 1
fi
mkdir -p "$DEST"
DEST=$(CDPATH= cd -- "$DEST" && pwd)
git -C "$DEST" init
git -C "$DEST" remote add origin https://github.com/vlang/v.git
git -C "$DEST" fetch --depth=1 origin "$PIN"
git -C "$DEST" checkout --detach FETCH_HEAD
test "$(git -C "$DEST" rev-parse HEAD)" = "$PIN"
git init "$DEST/vc"
git -C "$DEST/vc" remote add origin https://github.com/vlang/vc.git
git -C "$DEST/vc" fetch --depth=1 origin "$VC_PIN"
git -C "$DEST/vc" checkout --detach FETCH_HEAD
test "$(git -C "$DEST/vc" rev-parse HEAD)" = "$VC_PIN"
# A shallow source checkout has no bundled Boehm GC archive, but the freshly
# built compiler runs GC-enabled tools at the end of `make` and fails to link
# them without it. Build the bundled amalgamation into the TCC library folder
# first; the thread-enabled defines provide the GC_pthread_* and GC_dlopen
# symbols the compiler's runtime helpers expect.
mkdir -p "$DEST/thirdparty/tcc/lib"
"$HOST_CC" -c -O2 -DGC_THREADS=1 -DTHREAD_LOCAL_ALLOC=1 -DGC_BUILTIN_ATOMIC=1 \
    -I "$DEST/thirdparty/libgc/include" \
    "$DEST/thirdparty/libgc/gc.c" -o "$DEST/thirdparty/tcc/lib/gc.o"
ar rcs "$DEST/thirdparty/tcc/lib/libgc.a" "$DEST/thirdparty/tcc/lib/gc.o"
CC="$HOST_CC" make -C "$DEST" local=1 VEXE="$DEST/v"
"$DEST/v" version
printf 'Compiler ready: %s/v\n' "$DEST"
