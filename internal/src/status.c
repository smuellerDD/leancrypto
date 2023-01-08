/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#include "ext_headers.h"
#include "lc_status.h"
#include "sha3_c.h"
#include "sha3_arm8_neon.h"
#include "sha3_avx2.h"
#include "sha3_avx512.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(
void, lc_status, char *outbuf, size_t outlen)
{
	size_t len;

	snprintf(outbuf, outlen, "leancrypto %u.%u.%u\n",
		 MAJVERSION, MINVERSION, PATCHLEVEL);

	len = strlen(outbuf);
	snprintf(outbuf + len, outlen - len, "Acceleration support: %s%s%s\n",
		 (lc_sha3_512_avx512 != lc_sha3_512_c) ? "AVX512 " : "",
		 (lc_sha3_512_avx2 != lc_sha3_512_c) ? "AVX2 " : "",
		 (lc_sha3_512_arm8_neon != lc_sha3_512_c) ? "ARMv8 Neon " : "");

}
