#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Host tests of the kernel KDF: kernel/kdf/pbkdf2.v, without the kernel.
# tests/kdf/kdf is that module, linked from the kernel tree, beside its tests.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$here/../../build-support/find-v.sh"
exec "$V" -cc cc test "$here/kdf"
