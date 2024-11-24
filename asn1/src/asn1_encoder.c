/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING ANY WAY OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "asn1_encoder.h"
#include "lc_memory_support.h"
#include "ret_checkers.h"

#define MAX_LEVEL_STACK_HIERARCHY 10
#define MAX_STACK_MEM_PER_HIERARCHY ASN1_MAX_DATASIZE
struct lc_asn1_enc_stack {
	uint8_t data[MAX_LEVEL_STACK_HIERARCHY][MAX_STACK_MEM_PER_HIERARCHY];
	uint8_t *data_p[MAX_LEVEL_STACK_HIERARCHY];
	size_t data_len[MAX_LEVEL_STACK_HIERARCHY];
	uint8_t tag[MAX_LEVEL_STACK_HIERARCHY];
	uint8_t jump_stack[MAX_LEVEL_STACK_HIERARCHY];
	uint8_t max_level;
	unsigned int max_stack;
};

#include "asn1_encoder_impl.h"

int asn1_ber_encoder(const struct asn1_encoder *encoder, void *context,
		     uint8_t *data, size_t *in_out_avail_datalen)
{
	struct lc_asn1_enc_stack *ws;
	int ret;

	CKINT(lc_alloc_aligned((void **)&ws, 8,
			       sizeof(struct lc_asn1_enc_stack)));
	ws->max_level = MAX_LEVEL_STACK_HIERARCHY;
	ws->max_stack = MAX_STACK_MEM_PER_HIERARCHY;

	CKINT(asn1_ber_encoder_ws(encoder, context, data, in_out_avail_datalen,
				  ws));

out:
	lc_free(ws);
	return ret;
}
