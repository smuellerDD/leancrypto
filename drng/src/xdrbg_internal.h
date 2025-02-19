/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef XDRBG_INTERNAL_H
#define XDRBG_INTERNAL_H

/* Select the type of DRNG */

#ifdef LINUX_KERNEL
#ifdef CONFIG_LEANCRYPTO_SHA3
#define LC_DRNG_XDRBG256
#endif
#ifdef CONFIG_LEANCRYPTO_ASCON_HASH
#define LC_DRNG_XDRBG128
#endif
#else /* LINUX_KERNEL */
#include "lc_drng_config.h"
#endif /* LINUX_KERNEL */

#ifdef __cplusplus
extern "C" {
#endif

#if (!defined(LC_DRNG_XDRBG256) && !defined(LC_DRNG_XDRBG128))
#pragma message                                                                \
	"XDRBG compiled but without support for either XDRBG256 or XDRBG128"
#endif

#ifdef LC_DRNG_XDRBG256
void xdrbg256_drng_selftest(int *tested, const char *impl);
#else
static inline void xdrbg256_drng_selftest(int *tested, const char *impl)
{
	(void)tested;
	(void)impl;
}
#endif

#ifdef LC_DRNG_XDRBG128
void xdrbg128_drng_selftest(int *tested, const char *impl);
#else
static inline void xdrbg128_drng_selftest(int *tested, const char *impl)
{
	(void)tested;
	(void)impl;
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* XDRBG_INTERNAL_H */
