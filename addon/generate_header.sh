#!/bin/bash

OUTFILE=$1
shift
TARGETDIR=$1
shift

rm -f $OUTFILE

header='/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * This is an auto-generated header file including all leancrypto
 * header files for easy use.
 */

/** \mainpage Leancrypto Post-Quantum Cryptographic Library
 *
 * \section intro_sec Introduction
 *
 * The leancrypto library is a cryptographic library that exclusively contains
 * only PQC-resistant cryptographic algorithms. The algorithm implementations
 * have the following properties:
 *
 * * minimal dependencies: only minimal POSIX environment needed - function
 *   calls are abstracted into helper code that may need to be replaced for
 *   other environments (see the Linux kernel support in `linux_kernel` for
 *   replacing the POSIX calls)
 *
 * * extractable: the algorithms can be extracted and compiled as part of a
 *   separate project,
 *
 * * flexible: you can disable algorithms on an as-needed basis using
 *   `meson configure`,
 *
 * * fully thread-safe when using different cipher contexts for an invocation:
 *   there is no global state maintained for the algorithms,
 *
 * * stack-only support: all algorithms can be allocated on stack if needed. In
 *   addition, allocation functions for a usage on heap is also supported,
 *
 * * size: minimizing footprint when statically linking by supporting dead-code
 *   stripping,
 *
 * * performance: provide optimized code invoked with minimal overhead, thus
 *   significantly faster than other libraries like OpenSSL,
 *
 * * testable: all algorithm implementations are directly accessible via their
 *   data structures at runtime, and
 *
 * * side-channel-resistant: A valgrind-based dynamic side channel analysis is
 *   applied to find time-variant code paths based on secret data.
 *
 * \section install_sec Installation
 *
 * \subsection lib_subsec Library Build
 *
 * If you want to build the leancrypto shared library, use the provided `Meson`
 * build system:
 *
 * 1. Setup: `meson setup build`
 *
 * 2. Compile: `meson compile -C build`
 *
 * 3. Test: `meson test -C build`
 *
 * 4. Install: `meson install -C build`
 *
 * \subsection linux_subsec Library Build for Linux Kernel
 *
 * The leancrypto library can also be built as an independent Linux kernel
 * module. This kernel module offers the same APIs and functions as the user
 * space version of the library. This implies that a developer wanting to
 * develop kernel and user space users of cryptographic mechanisms do not need
 * to adjust to a new API.
 *
 * Note: The user space and kernel space versions of leancrypto are fully
 * independent of each other. Neither requires the presence of the other for
 * full operation.
 *
 * To build the leancrypto Linux kernel module, use the `Makefile` in the
 * directory `linux_kernel`:
 *
 * 1. cd `linux_kernel`
 *
 * 2. make
 *
 * 3. the leancrypto library is provided with `leancrypto.ko`
 *
 * Note, the compiled test kernel modules are only provided for regression
 * testing and are not required for production use. Insert the kernel modules
 * and check `dmesg` for the results. Unload the kernel modules afterwards.
 *
 * The API specified by the header files installed as part of the
 * `meson install -C build` command for the user space library is applicable to
 * the kernel module as well. When compiling kernel code, the flag
 * `-DLINUX_KERNEL` needs to be set.
 *
 * For more details, see `linux_kernel/README.md` in the source code
 * distribution.
 *
 * \subsection win_subsec Library Build for Windows
 *
 * The `leancrypto` library can be built on Windows using
 * [MSYS2](https://www.msys2.org/). Once `MSYS2` is installed along with `meson`
 * and the `mingw` compiler, the standard compilation procedure outlined above
 * for `meson` can be used.
 *
 * The support for full assembler acceleration is enabled.
 *
 * \section devel_sec Development with Leancrypto
 *
 * The leancrypto API is documented in the exported header files. The only
 * header file that needs to be included in the target code is
 * `#include <leancrypto.h>`. This header file includes all algorithm-specific
 * header files for the compiled and supported algorithms.
 *
 * To fully understand the API, please consider the following base concept of
 * leancrypto: Different algorithm implementations are accessible via common
 * APIs. For example, different random number generator algorithms are
 * accessible via the RNG API. To ensure the common APIs act on the proper
 * algorithm, the caller must use algorithm-specific initialization functions.
 * The initialization logic returns a "cipher handle" that can be used with the
 * common API for all subequent operations.
 *
 * \note The various header files contain data structures which are provided
 * solely for the purpose that appropriate memory on stack can be allocated.
 * These data structures do not consititute an API in the sense that calling
 * applications should access member variables directly. If access to member
 * variables is desired, proper accessor functions are available. This implies
 * that changes to the data structures in newer versions of the library are not
 * considered as API changes!
 */
'

echo "$header" > $OUTFILE
for i in $@
do
	if (echo $i | grep -q "lc_hmac_drbg.h")
	then
		continue
	fi
	i=$(basename $i)
	echo "#include <${TARGETDIR}/${i}>" >> $OUTFILE
done
