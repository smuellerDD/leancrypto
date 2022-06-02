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

#ifndef LC_HASH_DRBG_SHA3_512_H
#define LC_HASH_DRBG_SHA3_512_H

#include "lc_sha3.h"

#ifdef __cplusplus
extern "C"
{
#endif

#if defined(LC_DRBG_HASH_STATELEN) ||					\
    defined(LC_DRBG_HASH_BLOCKLEN) ||					\
    defined(LC_DRBG_HASH_CORE)
# error "You have included more than one DRBG header file!"
#endif

#warning "drbg_hash_alloc will use the wrong hash algo - modify the include in hash_drbg.c if you want to use SHA3 Hash DRBG with a heap allocation"

#define LC_DRBG_HASH_STATELEN 111
#define LC_DRBG_HASH_BLOCKLEN 64

#define LC_DRBG_HASH_CORE lc_sha3_512

#include "lc_hash_drbg.h"

#ifdef __cplusplus
}
#endif

#endif /* LC_HASH_DRBG_SHA3_512_H */
