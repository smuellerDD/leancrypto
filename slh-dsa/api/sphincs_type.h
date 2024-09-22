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

#ifndef SPHINCS_TYPE_H
#define SPHINCS_TYPE_H

#ifdef __cplusplus
extern "C" {
#endif

#define SPHINCS_F(name) lc_sphincs_shake_256s_##name
#define lc_sphincs_pk lc_sphincs_shake_256s_pk
#define lc_sphincs_sk lc_sphincs_shake_256s_sk
#define lc_sphincs_sig lc_sphincs_shake_256s_sig

#include "lc_sphincs_shake_256s.h"



#define lc_sphincs_keypair SPHINCS_F(keypair)
#define lc_sphincs_keypair_from_seed SPHINCS_F(keypair_from_seed)
#define lc_sphincs_sign SPHINCS_F(sign)
#define lc_sphincs_verify SPHINCS_F(verify)

#ifdef __cplusplus
}
#endif

#endif /* SPHINCS_TYPE_H */
