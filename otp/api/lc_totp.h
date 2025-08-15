/*
 * Copyright (C) 2018 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_TOTP_H
#define LC_TOTP_H

#include "ext_headers.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup OneTimePad One-Time Pad Algorithms
 */

/**
 * @ingroup OneTimePad
 * @brief Time-Based One-Time Password Algorithm - RFC 6238
 *
 * The TOTP algorithm uses HMAC SHA-256
 *
 * @param [in] hmac_key Seed key / HMAC key K - shared secret between client
 *			and server; each HOTP generator has a different and
 *			unique secret K.
 * @param [in] hmac_key_len Seed key / HMAC key length
 * @param [in] step Time step in seconds - to use the default value of 30
 *		    seconds, use 30
 * @param [in] digits number of digits in a TOTP value; system parameter.
 * @param [out] totp_val TOTP output value
 */
int lc_totp(const uint8_t *hmac_key, size_t hmac_key_len, uint32_t step,
	    uint32_t digits, uint32_t *totp_val);

#ifdef __cplusplus
}
#endif

#endif /* LC_TOTP_H */
