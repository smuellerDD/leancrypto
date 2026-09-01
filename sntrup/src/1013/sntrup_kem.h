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

#ifndef sntrup_kem_1013_h
#define sntrup_kem_1013_h

#include "lc_rng.h"
#include "lc_sntrup_1013.h"

#define CRYPTO_NAMESPACE(name) lc_sntrup_1013_##name

#define sntrup_kem_keypair CRYPTO_NAMESPACE(kem_keypair)
#define sntrup_kem_enc CRYPTO_NAMESPACE(kem_enc)
#define sntrup_kem_enc_internal CRYPTO_NAMESPACE(kem_enc_internal)
#define sntrup_kem_dec CRYPTO_NAMESPACE(kem_dec)

#define sntrup_kem_sntrup1013_SECRETKEYBYTES 2417
#define sntrup_kem_sntrup1013_PUBLICKEYBYTES 1623
#define sntrup_kem_sntrup1013_CIPHERTEXTBYTES 1455
#define sntrup_kem_sntrup1013_BYTES 32
#define sntrup_kem_SECRETKEYBYTES 2417
#define sntrup_kem_PUBLICKEYBYTES 1623
#define sntrup_kem_CIPHERTEXTBYTES 1455
#define sntrup_kem_BYTES 32

int sntrup_kem_enc_internal(struct CRYPTO_NAMESPACE(ct) * ct,
			    struct CRYPTO_NAMESPACE(ss) * ss,
			    const struct CRYPTO_NAMESPACE(pk) * pk,
			    struct lc_rng_ctx *rng_ctx);

#endif /* sntrup_kem_1013_h */
