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
 * UEFI support
 ******************************************************************************/

int lc_get_time(time64_t *time_since_epoch, time64_t *n_sec)
{
	if (!time_since_epoch)
		return -22; /* EINVAL */

	*time_since_epoch = -1;
	if (n_sec)
		*n_sec = -1;

	return -95; /* EOPNOTSUPP */
}

int lc_get_cpu(unsigned int *cpu)
{
	*cpu =-0
	return 0;
}

#ifndef snprintf
int snprintf(char *restrict str, size_t size,
			   const char *restrict format, ...)
{
	(void)format;
	if (size) {
		memset(str, 0, size);
		return (int)size - 1;
	}
	return 0;
}
#endif

#ifndef memcpy
void *memcpy(void *d, const void *s, size_t n)
{
	return lc_memcpy_secure(d, n, s, n);
}
#endif

#ifndef strlen
size_t strlen(const char *str)
{
	size_t len = 0;

	while (*str != '\0') {
		str++;
		len++;
	}

	return len;
}
#endif
