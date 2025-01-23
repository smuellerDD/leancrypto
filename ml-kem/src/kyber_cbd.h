/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#ifndef KYBER_CBD_H
#define KYBER_CBD_H

#include "ext_headers.h"

#include "kyber_type.h"
#include "kyber_poly.h"

#ifdef __cplusplus
extern "C" {
#endif

void cbd2(poly *r, const uint8_t buf[2 * LC_KYBER_N / 4]);
void cbd3(poly *r, const uint8_t buf[3 * LC_KYBER_N / 4]);

static inline void
poly_cbd_eta1(poly *r, const uint8_t buf[LC_KYBER_ETA1 * LC_KYBER_N / 4])
{
#if LC_KYBER_ETA1 == 2
	cbd2(r, buf);
#elif LC_KYBER_ETA1 == 3
	cbd3(r, buf);
#else
#error "This implementation requires eta1 in {2,3}"
#endif
}

static inline void
poly_cbd_eta2(poly *r, const uint8_t buf[LC_KYBER_ETA2 * LC_KYBER_N / 4])
{
#if LC_KYBER_ETA2 == 2
	cbd2(r, buf);
#else
#error "This implementation requires eta2 = 2"
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_CBD_H */
