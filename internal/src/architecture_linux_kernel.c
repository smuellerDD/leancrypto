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

#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include "ext_headers.h"

/******************************************************************************
 * Linux Kernel
 ******************************************************************************/

int lc_get_time(time64_t *time_since_epoch, time64_t *n_sec)
{
	u64 now = ktime_get_real_ns();

	if (!time_since_epoch)
		return -EINVAL;

	//*time_since_epoch = (time64_t)(jiffies / HZ);
	*time_since_epoch =
		(time64_t)div_u64(ktime_get_real_ns(), NSEC_PER_SEC);
	if (n_sec)
		*n_sec = (time64_t)(now - *time_since_epoch);

	return 0;
}
