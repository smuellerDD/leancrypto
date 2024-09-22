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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/sphincs/sphincsplus
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#ifndef SPHINCS_ADDRESS_H
#define SPHINCS_ADDRESS_H

#include "ext_headers.h"
#include "sphincs_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The hash types that are passed to set_type */
#define LC_SPX_ADDR_TYPE_WOTS 0
#define LC_SPX_ADDR_TYPE_WOTSPK 1
#define LC_SPX_ADDR_TYPE_HASHTREE 2
#define LC_SPX_ADDR_TYPE_FORSTREE 3
#define LC_SPX_ADDR_TYPE_FORSPK 4
#define LC_SPX_ADDR_TYPE_WOTSPRF 5
#define LC_SPX_ADDR_TYPE_FORSPRF 6

void set_layer_addr(uint32_t addr[8], uint32_t layer);

void set_tree_addr(uint32_t addr[8], uint64_t tree);

void set_type(uint32_t addr[8], uint32_t type);

/* Copies the layer and tree part of one address into the other */
void copy_subtree_addr(uint32_t out[8], const uint32_t in[8]);

/* These functions are used for WOTS and FORS addresses. */

void set_keypair_addr(uint32_t addr[8], uint32_t keypair);

void set_chain_addr(uint32_t addr[8], uint32_t chain);

void set_hash_addr(uint32_t addr[8], uint32_t hash);

void copy_keypair_addr(uint32_t out[8], const uint32_t in[8]);

/* These functions are used for all hash tree addresses (including FORS). */
void set_tree_height(uint32_t addr[8], uint32_t tree_height);

void set_tree_index(uint32_t addr[8], uint32_t tree_index);

#ifdef __cplusplus
}
#endif

#endif /* SPHINCS_ADDRESS_H */

