#!/bin/sh
# Build and test on a platform with no hosted GitHub runner. Driven by the
# freebsd/openbsd/netbsd/dragonflybsd/solaris/haiku jobs in
# .github/workflows/ci.yml, which reach their platform through a VM, and by the
# cygwin and linux-distro jobs, which are not VMs - a Cygwin installation and
# RHEL/SLES/Arch containers - but want exactly the same build matrix.
#
# Booting the VM dominates the runtime of those jobs, so everything the Linux
# and macOS jobs spread across a matrix is done here in a single boot: both
# CMake link configurations plus the Makefile build.
#
# Strictly POSIX sh. /bin/sh is the Almquist shell on FreeBSD, NetBSD and
# DragonFly, pdksh on OpenBSD, ksh93 on Solaris and bash on Haiku and Cygwin;
# not all of them are bash, and the workflow-level "shell: bash" default in
# ci.yml applies to the runner, not to the guest.
#
# MAKE is overridden by the jobs whose GNU make is not called gmake - Haiku and
# Cygwin ship it as plain make - and CC by those where the default choice would
# be wrong.

set -e

os=$(uname -s)

# cc(1) is not a given, and where it exists it is not always the one wanted: on
# Solaris /usr/bin/cc can be the Oracle Studio compiler, which the GCC-specific
# Makefile cannot be driven by, so that job passes CC in rather than relying on
# this search. Exported so that CMake, the Makefile and the smoke-test link
# below all agree on one compiler - the Makefile's "CC ?=" does not override
# make's built-in default, but an environment value does.
if [ -z "${CC:-}" ]; then
	for c in cc gcc clang; do
		if command -v "$c" > /dev/null 2>&1; then CC=$c; break; fi
	done
fi
if [ -z "${CC:-}" ]; then
	echo "no C compiler found (looked for cc, gcc, clang)" >&2
	exit 1
fi
export CC

echo "==> $(uname -a)"
echo "==> cc: $($CC --version 2>&1 | head -n 1)"
echo "==> using CC=$CC"

# ---------------------------------------------------------------------------
# CMake, static and shared
# ---------------------------------------------------------------------------
for shared in shared static both; do
	build="build-shared-$shared"
	echo "==> Meson build (BUILD_SHARED_LIBS=$shared)"

	rm -rf "$build"
	meson setup $build -Ddefault_library=$shared -Dslh_dsa_ascon_128s=enabled -Dslh_dsa_ascon_128f=enabled
	meson compile -C $build

	meson test -v -C $build --suite regression
done
