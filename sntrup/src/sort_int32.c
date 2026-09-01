/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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
 * The SNTRUP code is derived in parts from the code base
 * https://libntruprime.cr.yp.to/ which uses the following license:
 *
 * Copyright (C) 2024 Free Software Foundation, Inc.; This is free software;
 * see the source for copying conditions. There is NO; warranty; not even for
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * SPDX-License-Identifier: LicenseRef-PD-hp OR CC0-1.0 OR 0BSD OR MIT-0 OR MIT
 */

#include "sntrup_sort_int32.h"
#include "sntrup_int32.h"
#define int32_MINMAX(a, b) sntrup_int32_minmax(&(a), &(b))

void sntrup_sort_int32(void *array, long long n)
{
	int32_t *x = (int32_t *)array;
	long long top, p, q, r, i, j;

	if (n < 2)
		return;
	top = 1;
	while (top < n - top)
		top += top;

	for (p = top; p >= 1; p >>= 1) {
		i = 0;
		while (i + 2 * p <= n) {
			for (j = i; j < i + p; ++j)
				int32_MINMAX(x[j], x[j + p]);
			i += 2 * p;
		}
		for (j = i; j < n - p; ++j)
			int32_MINMAX(x[j], x[j + p]);

		i = 0;
		j = 0;
		for (q = top; q > p; q >>= 1) {
			if (j != i)
				for (;;) {
					if (j == n - q)
						goto done;
					int32_t a = x[j + p];
					for (r = q; r > p; r >>= 1)
						int32_MINMAX(a, x[j + r]);
					x[j + p] = a;
					++j;
					if (j == i + p) {
						i += 2 * p;
						break;
					}
				}
			while (i + p <= n - q) {
				for (j = i; j < i + p; ++j) {
					int32_t a = x[j + p];
					for (r = q; r > p; r >>= 1)
						int32_MINMAX(a, x[j + r]);
					x[j + p] = a;
				}
				i += 2 * p;
			}
			/* now i + p > n - q */
			j = i;
			while (j < n - q) {
				int32_t a = x[j + p];
				for (r = q; r > p; r >>= 1)
					int32_MINMAX(a, x[j + r]);
				x[j + p] = a;
				++j;
			}

		done:;
		}
	}
}
