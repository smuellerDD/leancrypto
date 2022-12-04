/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#include "ext_headers.h"

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef LC_SELFTEST_ENABLED
#define LC_SELFTEST_RUN(x)						       \
	if (*x)								       \
		return;							       \
	*x = 1;
#else /* LC_SELFTEST_ENABLED */
#define LC_SELFTEST_RUN(x)						       \
	(void)x;							       \
	if (1)								       \
		return;
#endif /* LC_SELFTEST_ENABLED */

int compare(const uint8_t *act, const uint8_t *exp, const size_t len,
	    const char *info);
void compare_selftest(const uint8_t *act, const uint8_t *exp, const size_t len,
		      const char *info);

#ifdef __cplusplus
}
#endif

#endif /* COMPARE_H */
