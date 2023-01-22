/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#include <sys/auxv.h>

#include "cpufeatures.h"
#include "ext_headers.h"
#include "visibility.h"

#define HWCAP_ASIMD  (1 << 1)
#define HWCAP_AES    (1 << 3)
#define HWCAP_PMULL  (1 << 4)
#define HWCAP_SHA1   (1 << 5)
#define HWCAP_SHA2   (1 << 6)
#define HWCAP_SHA3   (1 << 17)
#define HWCAP_SHA512 (1 << 21)

LC_INTERFACE_FUNCTION(
enum lc_cpu_features, lc_cpu_feature_available, void)
{
	unsigned long c;

	c = getauxval(AT_HWCAP);
	if (c & HWCAP_ASIMD)
		return LC_CPU_FEATURE_ARM_NEON;
	if (c & HWCAP_AES)
		return LC_CPU_FEATURE_NONE;
	if (c & HWCAP_PMULL)
		return LC_CPU_FEATURE_NONE;
	if (c & HWCAP_SHA1)
		return LC_CPU_FEATURE_NONE;
	if (c & HWCAP_SHA2)
		return LC_CPU_FEATURE_NONE;
	if (c & HWCAP_SHA512)
		return LC_CPU_FEATURE_NONE;
	return LC_CPU_FEATURE_NONE;
}