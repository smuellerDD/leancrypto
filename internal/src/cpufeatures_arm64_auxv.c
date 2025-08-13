/*
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

#include <sys/auxv.h>

#include "cpufeatures.h"
#include "ext_headers_internal.h"
#include "visibility.h"

#define HWCAP_ASIMD (1 << 1)
#define HWCAP_AES (1 << 3)
#define HWCAP_PMULL (1 << 4)
#define HWCAP_SHA1 (1 << 5)
#define HWCAP_SHA2 (1 << 6)
#define HWCAP_SHA3 (1 << 17)
#define HWCAP_SHA512 (1 << 21)

static enum lc_cpu_features features = LC_CPU_FEATURE_UNSET;

LC_INTERFACE_FUNCTION(void, lc_cpu_feature_disable, void)
{
	features = LC_CPU_FEATURE_ARM;
}

LC_INTERFACE_FUNCTION(void, lc_cpu_feature_enable, void)
{
	features = LC_CPU_FEATURE_UNSET;
}

LC_INTERFACE_FUNCTION(void, lc_cpu_feature_set, enum lc_cpu_features feature)
{
	features = feature;
}

LC_INTERFACE_FUNCTION(enum lc_cpu_features, lc_cpu_feature_available, void)
{
	if (features == LC_CPU_FEATURE_UNSET) {
		unsigned long c = getauxval(AT_HWCAP);

		features = LC_CPU_FEATURE_ARM | LC_CPU_FEATURE_ARM_NEON;

		if (c & HWCAP_ASIMD)
			features |= LC_CPU_FEATURE_ARM_NEON;
		if (c & HWCAP_AES)
			features |= LC_CPU_FEATURE_ARM_AES;
		if (c & HWCAP_SHA2)
			features |= LC_CPU_FEATURE_ARM_SHA2;
		if (c & HWCAP_SHA512)
			features |= LC_CPU_FEATURE_ARM_SHA2_512;
		if (c & HWCAP_SHA3)
			features |= LC_CPU_FEATURE_ARM_SHA3;
	}

	return features;
}
