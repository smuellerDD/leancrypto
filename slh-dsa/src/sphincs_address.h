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

#include "bitshift_be.h"
#include "ext_headers.h"
#include "sphincs_shake_offsets.h"
#include "sphincs_utils.h"

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

/*
 * Specify which level of Merkle tree (the "layer") we're working on
 */
static inline void set_layer_addr(uint32_t addr[8], uint32_t layer)
{
	((unsigned char *)addr)[LC_SPX_OFFSET_LAYER] = (unsigned char)layer;
}

/*
 * Specify which Merkle tree within the level (the "tree address") we're working on
 */
static inline void set_tree_addr(uint32_t addr[8], uint64_t tree)
{
//#if (LC_SPX_TREE_HEIGHT * (LC_SPX_D - 1)) > 64
//#error Subtree addressing is currently limited to at most 2^64 trees
//#endif
	ull_to_bytes(&((unsigned char *)addr)[LC_SPX_OFFSET_TREE], 8, tree);
}

/*
 * Specify the reason we'll use this address structure for, that is, what
 * hash will we compute with it.  This is used so that unrelated types of
 * hashes don't accidentally get the same address structure.  The type will be
 * one of the LC_SPX_ADDR_TYPE constants
 */
static inline void set_type(uint32_t addr[8], uint32_t type)
{
	((unsigned char *)addr)[LC_SPX_OFFSET_TYPE] = (unsigned char)type;
}

/*
 * Copy the layer and tree fields of the address structure.  This is used
 * when we're doing multiple types of hashes within the same Merkle tree
 */
static inline void copy_subtree_addr(uint32_t out[8], const uint32_t in[8])
{
	memcpy(out, in, LC_SPX_OFFSET_TREE + 8);
}

/* These functions are used for OTS addresses. */

/*
 * Specify which Merkle leaf we're working on; that is, which OTS keypair
 * we're talking about.
 */
static inline void set_keypair_addr(uint32_t addr[8], uint32_t keypair)
{
	be32_to_ptr(&((unsigned char *)addr)[LC_SPX_OFFSET_KP_ADDR], keypair);
}

/*
 * Specify which Merkle chain within the OTS we're working with
 * (the chain address)
 */
static inline void set_chain_addr(uint32_t addr[8], uint32_t chain)
{
	((unsigned char *)addr)[LC_SPX_OFFSET_CHAIN_ADDR] =
		(unsigned char)chain;
}

/*
 * Specify where in the Merkle chain we are
 * (the hash address)
 */
static inline void set_hash_addr(uint32_t addr[8], uint32_t hash)
{
	((unsigned char *)addr)[LC_SPX_OFFSET_HASH_ADDR] = (unsigned char)hash;
}

/*
 * Copy the layer, tree and keypair fields of the address structure.  This is
 * used when we're doing multiple things within the same OTS keypair
 */
static inline void copy_keypair_addr(uint32_t out[8], const uint32_t in[8])
{
	memcpy(out, in, LC_SPX_OFFSET_TREE + 8);
	memcpy((unsigned char *)out + LC_SPX_OFFSET_KP_ADDR,
	       (unsigned char *)in + LC_SPX_OFFSET_KP_ADDR, 4);
}

/* These functions are used for all hash tree addresses (including FORS). */

/*
 * Specify the height of the node in the Merkle/FORS tree we are in
 * (the tree height)
 */
static inline void set_tree_height(uint32_t addr[8], uint32_t tree_height)
{
	((unsigned char *)addr)[LC_SPX_OFFSET_TREE_HGT] =
		(unsigned char)tree_height;
}

/*
 * Specify the distance from the left edge of the node in the Merkle/FORS tree
 * (the tree index)
 */
static inline void set_tree_index(uint32_t addr[8], uint32_t tree_index)
{
	be32_to_ptr(&((unsigned char *)addr)[LC_SPX_OFFSET_TREE_INDEX],
		    tree_index);
}

#ifdef __cplusplus
}
#endif

#endif /* SPHINCS_ADDRESS_H */
