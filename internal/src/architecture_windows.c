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
 * Windows
 ******************************************************************************/

int mlock(const void *ptr, size_t len)
{
	/* "If the function succeeds, the return value is nonzero" */
	if (!VirtualLock((void *)ptr, len)) {
		errno = -EAGAIN;
		return -1;
	}
	return 0;
}

int munlock(const void *ptr, size_t len)
{
	/* "If the function succeeds, the return value is nonzero" */
	if (!VirtualUnlock((void *)ptr, len)) {
		errno = -EAGAIN;
		return -1;
	}
	return 0;
}

#ifdef __GNUC__

/* ....... MinGW ....... */

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


int lc_get_cpu(unsigned int *cpu)
{
	//TODO: is there an equivalent of sched_getcpu on MSYS2 / Cygwin?
	static atomic_t ctr = ATOMIC_INIT(0);

	*cpu = atomic_inc(&ctr);

	return 0;
}

#elif defined(_MSC_VER)

/* ....... MSVC including optionally clang ....... */

int lc_get_cpu(unsigned int *cpu)
{
	*cpu = GetCurrentProcessorNumber();
	return 0;
}

int lc_get_time(time64_t *time_since_epoch, time64_t *n_sec)
{
	FILETIME ft;
	ULARGE_INTEGER t;

	GetSystemTimeAsFileTime(&ft);

	t.LowPart = ft.dwLowDateTime;
	t.HighPart = ft.dwHighDateTime;

	// FILETIME: 100 ns intervals since 1601-01-01
	t.QuadPart -= 116444736000000000ULL;
	uint64_t unix_seconds = t.QuadPart / 10000000ULL;
	*time_since_epoch = (time64_t)unix_seconds;
	if (n_sec)
		*n_sec = (time64_t)((t.QuadPart * 100ULL) % 1000000000ULL);

	return 0;
}

int lc_open(const char *path, int flags, int mode)
{
	int fd;
	errno_t err = _sopen_s(&fd, path, flags, _SH_DENYNO, mode);

	if (err != 0) {
		errno = err;
		return -1;
	}
	return fd;
}

FILE *fopen(const char *path, const char *mode)
{
	FILE *fp;
	errno_t err = fopen_s(&fp, path, mode);

	if (err != 0) {
		errno = err;
		return NULL;
	}
	return fp;
}

pid_t getpid(void)
{
	DWORD pid = GetCurrentProcessId();

	return (pid_t)pid;
}

#endif /* __GNUC__ */
