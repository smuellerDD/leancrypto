/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef STATIC_RNG_H
#define STATIC_RNG_H

#include "lc_rng.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This "RNG" provides static data to the caller as set during its
 * initialization.
 *
 * WARNING: This RNG state is NOT meant to be used for any other purpose than
 * for internal operation of Kyber and Dilithium!
 */
struct lc_static_rng_data {
	const uint8_t *seed;
	size_t seedlen;
};

extern const struct lc_rng *lc_static_drng;

#define LC_STATIC_DRNG_ON_STACK(name, static_data)                                            \
	_Pragma("GCC diagnostic push") _Pragma(                                               \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") struct lc_rng_ctx \
		name = { .rng = lc_static_drng, .rng_state = static_data };                   \
	_Pragma("GCC diagnostic pop")

#ifdef __cplusplus
}
#endif

#endif /* KYBER_STATIC_RNG_H */
