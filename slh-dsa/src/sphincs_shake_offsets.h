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

#ifndef SPHINCS_SHAKE_OFFSETS_H
#define SPHINCS_SHAKE_OFFSETS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Offsets of various fields in the address structure when we use SHAKE as
 * the Sphincs+ hash function
 */
#define LC_SPX_OFFSET_LAYER                                                    \
	3 /* The byte used to specify the Merkle tree layer */
#define LC_SPX_OFFSET_TREE                                                     \
	8 /* The start of the 8 byte field used to specify the tree */
#define LC_SPX_OFFSET_TYPE                                                     \
	19 /* The byte used to specify the hash type (reason) */
#define LC_SPX_OFFSET_KP_ADDR                                                  \
	20 /* The start of the 4 byte field used to specify the key pair address */
#define LC_SPX_OFFSET_CHAIN_ADDR                                               \
	27 /* The byte used to specify the chain address (which Winternitz chain) */
#define LC_SPX_OFFSET_HASH_ADDR                                                \
	31 /* The byte used to specify the hash address (where in the Winternitz chain) */
#define LC_SPX_OFFSET_TREE_HGT                                                 \
	27 /* The byte used to specify the height of this node in the FORS or Merkle tree */
#define LC_SPX_OFFSET_TREE_INDEX                                               \
	28 /* The start of the 4 byte field used to specify the node in the FORS or Merkle tree */

#define LC_SPX_SHAKE 1

#ifdef __cplusplus
}
#endif

#endif /* SPHINCS_SHAKE_OFFSETS_H */
