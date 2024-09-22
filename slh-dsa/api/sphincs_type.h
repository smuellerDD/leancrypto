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

/*
 * This define replaces all symbol names accordingly to allow double compilation
 * of the same code base.
 *
 * Due to the replacement operation, this header file must be included as the
 * first header file in the entire stack.
 *
 * This file can easily be replaced with lc_sphincs.h to achieve the common
 * functionality without symbol duplication. But in this case, only the
 * Dilithium security strength is compiled defined in lc_sphincs.h. Duplicate
 * compilation different sizes would not be possible.
 */

#ifdef LC_SPHINCS_TYPE_192S

#define SPHINCS_F(name) lc_sphincs_shake_192s_##name
#define lc_sphincs_pk lc_sphincs_shake_192s_pk
#define lc_sphincs_sk lc_sphincs_shake_192s_sk
#define lc_sphincs_sig lc_sphincs_shake_192s_sig

#include "lc_sphincs_shake_192s.h"

#elif defined(LC_SPHINCS_TYPE_256F)

#define SPHINCS_F(name) lc_sphincs_shake_256f_##name
#define lc_sphincs_pk lc_sphincs_shake_256f_pk
#define lc_sphincs_sk lc_sphincs_shake_256f_sk
#define lc_sphincs_sig lc_sphincs_shake_256f_sig

#include "lc_sphincs_shake_256f.h"

#else

#define SPHINCS_F(name) lc_sphincs_shake_256s_##name
#define lc_sphincs_pk lc_sphincs_shake_256s_pk
#define lc_sphincs_sk lc_sphincs_shake_256s_sk
#define lc_sphincs_sig lc_sphincs_shake_256s_sig

#include "lc_sphincs_shake_256s.h"

#endif

#define lc_sphincs_keypair SPHINCS_F(keypair)
#define lc_sphincs_keypair_from_seed SPHINCS_F(keypair_from_seed)
#define lc_sphincs_sign SPHINCS_F(sign)
#define lc_sphincs_verify SPHINCS_F(verify)

#define set_layer_addr SPHINCS_F(set_layer_addr)
#define set_tree_addr SPHINCS_F(set_tree_addr)
#define set_type SPHINCS_F(set_type)
#define copy_subtree_addr SPHINCS_F(copy_subtree_addr)
#define set_keypair_addr SPHINCS_F(set_keypair_addr)
#define copy_keypair_addr SPHINCS_F(copy_keypair_addr)
#define set_chain_addr SPHINCS_F(set_chain_addr)
#define set_hash_addr SPHINCS_F(set_hash_addr)
#define set_tree_height SPHINCS_F(set_tree_height)
#define set_tree_index SPHINCS_F(set_tree_index)
#define fors_sign SPHINCS_F(fors_sign)
#define fors_pk_from_sig SPHINCS_F(fors_pk_from_sig)
#define prf_addr SPHINCS_F(prf_addr)
#define gen_message_random SPHINCS_F(gen_message_random)
#define hash_message SPHINCS_F(hash_message)
#define sphincs_merkle_sign SPHINCS_F(sphincs_merkle_sign)
#define sphincs_merkle_gen_root SPHINCS_F(sphincs_merkle_gen_root)
#define thash SPHINCS_F(thash)
#define ull_to_bytes SPHINCS_F(ull_to_bytes)
#define bytes_to_ull SPHINCS_F(bytes_to_ull)
#define compute_root SPHINCS_F(compute_root)
#define treehash SPHINCS_F(treehash)
#define treehashx1 SPHINCS_F(treehashx1)
#define chain_lengths SPHINCS_F(chain_lengths)
#define wots_pk_from_sig SPHINCS_F(wots_pk_from_sig)
#define wots_gen_leafx1 SPHINCS_F(wots_gen_leafx1)

#ifdef __cplusplus
}
#endif

#endif /* SPHINCS_TYPE_H */
