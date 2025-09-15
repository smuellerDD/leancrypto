/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef FIPS_MODE_H
#define FIPS_MODE_H

#include "ext_headers_internal.h"
#include "status_algorithms.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Is FIPS 140 Mode enabled?
 *
 * return 0 == false, 1 == true
 */
int fips140_mode_enabled(void);

void fips140_mode_enable(void);

#define FIPS140_PCT_LOOP(func, algo)                                           \
	if (fips140_mode_enabled()) {                                          \
		unsigned int __i;                                              \
		int __ret;                                                     \
                                                                               \
		for (__i = 0; __i < 5; __i++) {                                \
			__ret = func;                                          \
			if (!__ret)                                            \
				return __ret;                                  \
		}                                                              \
		alg_status_set_result(lc_alg_status_result_failed, algo);      \
		return -EOPNOTSUPP;                                            \
	}

#ifdef LC_FIPS140_DEBUG
#define FIPS140_MOD(x) (x ^ 0x01)
#else
#define FIPS140_MOD(x) (x)
#endif

#ifdef __cplusplus
}
#endif

#endif /* FIPS_MODE_H */
