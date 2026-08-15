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
 * POSIX
 ******************************************************************************/

int lc_get_time(time64_t *time_since_epoch, time64_t *n_sec)
{
	struct timespec tp = { 0 };

	if (!time_since_epoch)
		return -EINVAL;

	if (clock_gettime(CLOCK_REALTIME, &tp) == 0) {
		*time_since_epoch = tp.tv_sec;
		if (n_sec)
			*n_sec = tp.tv_nsec;
		return 0;
	}

	*time_since_epoch = (time64_t)-1;
	return -errno;
}

#ifdef __MACH__

int lc_get_cpu(unsigned int *cpu)
{
	//TODO: is there an equivalent of sched_getcpu on macOS?
	static unsigned int ctr = 0;

	*cpu = ctr++;

	return 0;
}

#else /* __MACH__ */

int lc_get_cpu(unsigned int *cpu)
{
	int ret = sched_getcpu();

	if (ret < 0)
		return -errno;

	*cpu = (unsigned int)ret;
	return 0;
}

#endif /* __MACH__ */
