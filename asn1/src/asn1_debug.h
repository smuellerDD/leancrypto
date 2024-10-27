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

#ifndef ASN1_DEBUG_H
#define ASN1_DEBUG_H

#include "binhexbin.h"
#include "ext_headers.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LC_PKCS7_DEBUG
#define LC_ASN1_DEBUG
#else
#undef LC_ASN1_DEBUG
#endif

#ifdef LC_ASN1_DEBUG

#define bin2print_debug(a, b, c, d) bin2print((a), (b), (c), (d))
#define printf_debug(...) printf(__VA_ARGS__)

#else /* LC_ASN1_DEBUG */

#define bin2print_debug(a, b, c, d)                                            \
	(void)a;                                                               \
	(void)b;                                                               \
	(void)c;                                                               \
	(void)d;
#define printf_debug(...)                                                      \
	do {                                                                   \
	} while (0)

#endif /* LC_ASN1_DEBUG */

#ifdef __cplusplus
}
#endif

#endif /* ASN1_DEBUG_H */
