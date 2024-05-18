/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include <windows.h>

#include "ext_headers.h"
#include "math_helper.h"
#include "seeded_rng.h"

static inline ssize_t __getentropy(uint8_t *buffer, size_t bufferlen)
{
	BOOL ret;
	HCRYPTPROV hProvider;

	if (bufferlen > INT_MAX)
		return -EINVAL;

	ret = CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL,
				  CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
	if (ret) {
		ret = CryptGenRandom(hProvider, (unsigned int)bufferlen,
				     buffer);
		CryptReleaseContext(hProvider, 0);
	}

	return ret ? (size_t)bufferlen : -EFAULT;
}

ssize_t get_full_entropy(uint8_t *buffer, size_t bufferlen)
{
	return __getentropy(buffer, bufferlen);
}

void seeded_rng_noise_fini(void)
{
}

int seeded_rng_noise_init(void)
{
	return 0;
}
