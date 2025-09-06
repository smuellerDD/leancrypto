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

#ifndef COMPARE_H
#define COMPARE_H

#include "ext_headers_internal.h"
#include "status_algorithms.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LC_SELFTEST_ENABLED
#define LC_SELFTEST_RUN(flag)                                                  \
	if (alg_status_get_result(flag) != lc_alg_status_result_pending)       \
		return;                                                        \
	alg_status_set_result(lc_alg_status_result_ongoing, flag)

#define LC_SELFTEST_COMPLETED(flag)                                            \
	if (alg_status_get_result(flag) != lc_alg_status_result_passed)        \
	return -EAGAIN

#else /* LC_SELFTEST_ENABLED */

#define LC_SELFTEST_RUN(x)                                                     \
	(void)x;                                                               \
	if (1)                                                                 \
		return;
#define LC_SELFTEST_COMPLETED(flag)

#endif /* LC_SELFTEST_ENABLED */

int lc_compare(const uint8_t *act, const uint8_t *exp, const size_t len,
	       const char *info);

/*
 * The return code must be checked and in case of != 0 the continued checks
 * for one given self test must be prevented.
 */
int lc_compare_selftest(uint64_t flag, const uint8_t *act, const uint8_t *exp,
			const size_t len, const char *info);
void lc_disable_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* COMPARE_H */
