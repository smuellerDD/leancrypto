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

#ifndef LC_HOTP_H
#define LC_HOTP_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief HMAC-Based One-Time Password Algorithm - RFC 4226
 *
 * The HOTP algorithm uses HMAC SHA-256
 *
 * @param hmac_key [in] Seed key / HMAC key K - shared secret between client
 *			and server; each HOTP generator has a different and
 *			unique secret K.
 * @param hmac_key_len [in] Seed key / HMAC key length
 * @param counter [in] Counter C - 8-byte counter value, the moving factor.
 *		       This counter MUST be synchronized between the HOTP
 *		       generator (client) and the HOTP validator (server).
 * @param digits [in] number of digits in an HOTP value; system parameter.
 * @param hotp_val [out] HOTP output value
 */
void lc_hotp(const uint8_t *hmac_key, size_t hmac_key_len, uint64_t counter,
	     uint32_t digits, uint32_t *hotp_val);

#ifdef __cplusplus
}
#endif

#endif /* LC_HOTP_H */
