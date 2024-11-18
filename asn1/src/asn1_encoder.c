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

#include "asn1_debug.h"
#include "asn1_encoder.h"
#include "asn1_ber_bytecode.h"
#include "helper.h"
#include "math_helper.h"

/*
 * Constructed data implies a new collection which we track with  a new data
 * stack level.
 */
#define ASN1_BER_ENCODE_CHECK_FOR_SEQUENCE                                     \
	if (!(op & ASN1_OP_MATCH__ANY) &&                                      \
	    (machine[pc + 1] & (ASN1_CONS << 5)) == (ASN1_CONS << 5)) {        \
		printf_debug("Start constructed data\n");                      \
		if (unlikely(dsp == NR_DATA_STACK))                            \
			goto data_stack_overflow;                              \
		dsp++;                                                         \
		tmp_data_p[dsp] = tmp_data[dsp];                               \
		tmp_data_len[dsp] = maxlen;                                    \
	}

/*
* Copy data to the master data buffer as we reached
* the end of the outermost sequence / set.
*/
#define ASN1_BER_ENCODE_WRITE_DATA(dstbuffer, available_datalength, srcbuffer) \
	if (available_datalength < 1) {                                        \
		printf_debug(                                                  \
			"Insufficient space (wanted %zu, available %u)\n",     \
			available_datalength, 1);                              \
		return -EOVERFLOW;                                             \
	}                                                                      \
	dstbuffer[0] = tmp_tag[dsp];                                           \
	printf_debug("Set tag %x\n", tmp_tag[dsp]);                            \
	dstbuffer++;                                                           \
	available_datalength--;                                                \
                                                                               \
	ret = asn1_encode_length(&dstbuffer, &available_datalength, len);      \
	if (ret)                                                               \
		return ret;                                                    \
                                                                               \
	if (available_datalength < len) {                                      \
		printf_debug(                                                  \
			"Insufficient space (wanted %zu, available %zu)\n",    \
			available_datalength, len);                            \
		return -EOVERFLOW;                                             \
	}                                                                      \
                                                                               \
	memcpy(dstbuffer, srcbuffer, len);                                     \
                                                                               \
	dstbuffer += len;                                                      \
	available_datalength -= len;                                           \
                                                                               \
	tmp_data_p[dsp] = tmp_data[dsp];                                       \
	tmp_data_len[dsp] = maxlen

/**
 * @brief Encode BER/DER/CER ASN.1 according to pattern
 *
 * Encode BER/DER/CER data according to a bytecode pattern produced by
 * asn1_compiler. Action functions are called on marked tags to allow the
 * caller to set significant data.
 *
 * @param [in] encoder The encoder definition (produced by asn1_compiler)
 * @param [in] context The caller's context (to be passed to the action
 *		       functions)
 * @param [out] data: The encoded data - the caller must have sufficient space
 * @param [in,out] in_out_avail_datalen Size of the available data in the
 *					\p data buffer (the input would refer
 *					to the maxumum size this function can
 *					write to, the returned value contains
 *					the information how much data space is
 *					still left for further consumption)
 *
 * @return 0 on success, < 0 on error
 */
int asn1_ber_encoder(const struct asn1_encoder *encoder, void *context,
		     uint8_t *data, size_t *in_out_avail_datalen)
{
	const unsigned char *machine = encoder->machine;
	const asn1_action_enc_t *actions = encoder->actions;
	size_t machlen = encoder->machlen;
	enum asn1_opcode op;
	unsigned char jsp = 0, dsp = 0;
	const char *errmsg;
	size_t pc = 0, len;
	int ret;

	unsigned char flags = 0;
#define FLAG_MATCHED 0x01
#define FLAG_LAST_MATCHED 0x02 /* Last tag matched */
#define FLAG_OF_CONTINUE 0x04
#define FLAG_SET_ZERO_CONTENT 0x08

	/*
	 * Concept of the data stack:
	 *
	 * Each sequence / set is a separate hierarchy in the ASN.1 tree. Each
	 * hierarchy stores all data in a separate stack level where each
	 * level corresponds to the hierarchy level we have in the ASN.1 tree.
	 * I.e. every time a new sequence / set is started, a new leel of
	 * the stack is taken.
	 *
	 * When the sequence / set completes the data along with the tag is
	 * written to the hierarchically higher stack entry. This is continued
	 * until the last sequence / set completes and all data of the stack
	 * level 0 is copied into the main \p data pointer along with the tag.
	 *
	 * Note, the generator does not enforce any kind of rules. E.g. if
	 * an X.509 certificate shall be generated, and RFC5280 requires the
	 * presence of some field (which is also marked accordingly in the
	 * correxponding x509.asn1 file), this generator does not enforce such
	 * rules. This allows the caller a great degree of freedom when
	 * generating an ASN.1 sequence, but also requires the caller to ensure
	 * that all required data fields are present.
	 *
	 * TODO: reduce amount of temporary data that is retained.
	 */
#define NR_DATA_STACK 10
	uint8_t tmp_data[NR_DATA_STACK][65536];
	uint8_t *tmp_data_p[NR_DATA_STACK];
	size_t tmp_data_len[NR_DATA_STACK] = { 0 };
	unsigned char tmp_tag[NR_DATA_STACK] = { 0 };

#define NR_JUMP_STACK 10
	unsigned char jump_stack[NR_JUMP_STACK];

	size_t maxlen = min_size(sizeof(tmp_data[0]), *in_out_avail_datalen);
	size_t avail_datalen = maxlen;
	size_t in_out_unused_len = *in_out_avail_datalen - avail_datalen;

	(void)errmsg;

	for (len = 0; len < NR_DATA_STACK; len++)
		tmp_data_p[len] = tmp_data[len];

	printf_debug("---- Start encoder\n");

next_op:
	printf_debug("next_op: pc=\x1B[32m%zu\x1B[m/%zu t=%zu J=%u D=%u\n", pc,
		     machlen, tmp_data_len[dsp], jsp, dsp);
	if (unlikely(pc >= machlen))
		goto machine_overrun_error;
	op = machine[pc];
	if (unlikely(pc + asn1_op_lengths[op] > machlen))
		goto machine_overrun_error;

	/* Decide how to handle the operation */
	switch (op) {
	case ASN1_OP_MATCH:
	case ASN1_OP_MATCH_OR_SKIP:
	case ASN1_OP_MATCH_ACT:
	case ASN1_OP_MATCH_ACT_OR_SKIP:
	case ASN1_OP_MATCH_ANY:
	case ASN1_OP_MATCH_ANY_OR_SKIP:
	case ASN1_OP_MATCH_ANY_ACT:
	case ASN1_OP_MATCH_ANY_ACT_OR_SKIP:
	case ASN1_OP_COND_MATCH_OR_SKIP:
	case ASN1_OP_COND_MATCH_ACT_OR_SKIP:
	case ASN1_OP_COND_MATCH_ANY:
	case ASN1_OP_COND_MATCH_ANY_OR_SKIP:
	case ASN1_OP_COND_MATCH_ANY_ACT:
	case ASN1_OP_COND_MATCH_ANY_ACT_OR_SKIP:
		/*
		 * Starting fresh for a match target: Either the previous
		 * match target completed, or we see the first match target.
		 */
		tmp_data_p[dsp] = tmp_data[dsp];
		tmp_data_len[dsp] = maxlen;

		/*
		 * Retain the current tag - it will be written out if there is
		 * data found to be written.
		 */
		tmp_tag[dsp] = machine[pc + 1];

		ASN1_BER_ENCODE_CHECK_FOR_SEQUENCE

		if (op & ASN1_OP_MATCH__ACT) {
			unsigned char act;

			if (op & ASN1_OP_MATCH__ANY)
				act = machine[pc + 1];
			else
				act = machine[pc + 2];

			ret = actions[act](context, tmp_data_p[dsp],
					   &tmp_data_len[dsp], &tmp_tag[dsp]);
			if (ret < 0)
				return ret;
			if (ret == LC_ASN1_RET_CONTINUE)
				flags |= FLAG_OF_CONTINUE;
			if (ret == LC_ASN1_RET_SET_ZERO_CONTENT)
				flags |= FLAG_SET_ZERO_CONTENT;

			/*
			 * Track the consumed data size.
			 */
			len = maxlen - tmp_data_len[dsp];
			printf_debug("action match consumed = %zu\n", len);
			tmp_data_p[dsp] = tmp_data[dsp] + len;

			/*
			 * Any match is written out here except the
			 * sequence or set which is written out at the
			 * end marker. This implies that also NULL
			 * matches are written out.
			 */
			if (!((machine[pc + 1] & (ASN1_CONS << 5)) ==
			      (ASN1_CONS << 5)))
				goto write_data_out;

		} else {
			/*
			 * Any match is written out here except the sequence or
			 * set which is written out at the end marker. This
			 * implies that also NULL matches are written out.
			 *
			 * Also, if there is an ASN1_OP_MATCH, we do not write
			 * it out now, but expect the next op will handle
			 * the writing.
			 */
			if (!((machine[pc + 1] & (ASN1_CONS << 5)) ==
			      (ASN1_CONS << 5)) &&
			    !(op == ASN1_OP_MATCH))
				goto write_data_out;
		}

		pc += asn1_op_lengths[op];
		goto next_op;

	case ASN1_OP_COND_MATCH_JUMP_OR_SKIP:
		if ((flags & FLAG_LAST_MATCHED)) {
			flags &= (unsigned char)~FLAG_LAST_MATCHED;
			printf_debug(
				"Skippking conditional JUMP as last JUMP yielded data\n");
			pc += asn1_op_lengths[op];
			goto next_op;
		}
		fallthrough;
	case ASN1_OP_MATCH_JUMP:
	case ASN1_OP_MATCH_JUMP_OR_SKIP:
		printf_debug("- MATCH_JUMP\n");
		if (unlikely(jsp == NR_JUMP_STACK))
			goto jump_stack_overflow;
		jump_stack[jsp++] = (unsigned char)(pc + asn1_op_lengths[op]);

		/*
		 * Retain the current tag - it will be written out if there is
		 * data found to be written.
		 */
		tmp_tag[dsp] = machine[pc + 1];

		ASN1_BER_ENCODE_CHECK_FOR_SEQUENCE

		pc = machine[pc + 2];
		goto next_op;

	case ASN1_OP_COND_FAIL:
		if (unlikely(!(flags & FLAG_MATCHED)))
			goto tag_mismatch;
		pc += asn1_op_lengths[op];
		goto next_op;

	case ASN1_OP_COMPLETE:
		if (unlikely(jsp != 0))
			goto jump_stack_not_empty;
		if (unlikely(dsp != 0))
			goto data_stack_not_empty;

		*in_out_avail_datalen = avail_datalen + in_out_unused_len;

		printf_debug("---- End encoder\n");
		return 0;

	case ASN1_OP_END_SET:
	case ASN1_OP_END_SET_ACT:
	case ASN1_OP_END_SEQ:
	case ASN1_OP_END_SET_OF:
	case ASN1_OP_END_SEQ_OF:
	case ASN1_OP_END_SEQ_ACT:
	case ASN1_OP_END_SET_OF_ACT:
	case ASN1_OP_END_SEQ_OF_ACT:
		if (op & ASN1_OP_END__OF) {
			if (flags & FLAG_OF_CONTINUE) {
				flags &= (unsigned char)~FLAG_OF_CONTINUE;
				printf_debug("- continue (D=%u)\n", dsp);
				pc = machine[pc + 1];
				goto next_op;
			}
			printf_debug("- no continue (D=%u)\n", dsp);
		}

		if (op & ASN1_OP_END__ACT) {
			unsigned char act;

			if (op & ASN1_OP_END__OF)
				act = machine[pc + 2];
			else
				act = machine[pc + 1];

			ret = actions[act](context, tmp_data_p[dsp],
					   &tmp_data_len[dsp], &tmp_tag[dsp]);
			if (ret < 0)
				return ret;

			if (ret == LC_ASN1_RET_CONTINUE)
				flags |= FLAG_OF_CONTINUE;
			if (ret == LC_ASN1_RET_SET_ZERO_CONTENT)
				flags |= FLAG_SET_ZERO_CONTENT;

			/*
			 * Track the consumed data size.
			 */
			len = maxlen - tmp_data_len[dsp];
			printf_debug("action end consumed = %zu\n", len);
			tmp_data_p[dsp] = tmp_data[dsp] + len;
		}

		if (unlikely(dsp <= 0))
			goto data_stack_underflow;

		dsp--;

	write_data_out:
		len = maxlen - tmp_data_len[dsp];

		if (!len && !(flags & FLAG_SET_ZERO_CONTENT)) {
			printf_debug("Skiping zero-length data encoding\n");
			pc += asn1_op_lengths[op];
			goto next_op;
		}
		if (flags & FLAG_SET_ZERO_CONTENT)
			printf_debug("Zero-length requested to be created\n");

		/* Unset the flag */
		flags &= (unsigned char)~FLAG_SET_ZERO_CONTENT;

		printf_debug("encoded len %zu (D=%u)\n", len, dsp);
		if (!dsp) {
			/*
			 * Copy data to the master data buffer as we reached
			 * the end of the outermost sequence / set.
			 */
			ASN1_BER_ENCODE_WRITE_DATA(data, avail_datalen,
						   tmp_data[dsp]);
			printf_debug(
				"available len %zu, consumed len %zu (D=main)\n",
				avail_datalen, maxlen - avail_datalen);
		} else {
			/*
			 * Copy data to the hierarchically higher stack buffer
			 * as we reached the end of an inner sequence / set.
			 */
			ASN1_BER_ENCODE_WRITE_DATA(tmp_data_p[dsp - 1],
						   tmp_data_len[dsp - 1],
						   tmp_data[dsp]);
			printf_debug(
				"available len %zu, consumed len %zu (D=%u)\n",
				avail_datalen, maxlen - tmp_data_len[dsp - 1],
				dsp - 1);
		}

		pc += asn1_op_lengths[op];
		goto next_op;

	case ASN1_OP_MAYBE_ACT:
		if (!(flags & FLAG_LAST_MATCHED)) {
			pc += asn1_op_lengths[op];
			goto next_op;
		}
		fallthrough;

	case ASN1_OP_ACT:
		ret = actions[machine[pc + 1]](context, tmp_data_p[dsp],
					       &tmp_data_len[dsp],
					       &tmp_tag[dsp]);
		if (ret < 0)
			return ret;
		if (ret == LC_ASN1_RET_CONTINUE)
			flags |= FLAG_OF_CONTINUE;
		if (ret == LC_ASN1_RET_SET_ZERO_CONTENT)
			flags |= FLAG_SET_ZERO_CONTENT;

		len = maxlen - tmp_data_len[dsp];
		printf_debug("action act consumed = %zu\n", len);

		tmp_data_p[dsp] = tmp_data[dsp] + len;

		/* Write out the data */
		goto write_data_out;

	case ASN1_OP_RETURN:
		printf_debug("- RETURN_JUMP\n");

		if (dsp)
			len = maxlen - tmp_data_len[dsp - 1];
		else
			len = maxlen - avail_datalen;

		/*
		 * TODO This matches all entries in the current hierarchy level
		 * whether they have added data. But the conditional actually
		 * only matches the previous one.
		 */
		if (len)
			flags |= FLAG_LAST_MATCHED;

		if (unlikely(jsp <= 0))
			goto jump_stack_underflow;

		pc = jump_stack[--jsp];
		flags |= FLAG_MATCHED;
		goto next_op;

	case ASN1_OP__NR:
	default:
		break;
	}

	/* Shouldn't reach here */
	printf_debug("ASN.1 encoder error: Found reserved opcode (%u) pc=%zu\n",
		     op, pc);
	return -EBADMSG;

jump_stack_not_empty:
	errmsg = "ASN.1 encoder error: Jump stacks not empty at completion";
	goto error;
data_stack_not_empty:
	errmsg = "ASN.1 encoder error: Data stack not empty at completion";
	goto error;
machine_overrun_error:
	errmsg = "Machine overrun error";
	goto error;
jump_stack_underflow:
	errmsg = "Jump stack underflow";
	goto error;
data_stack_underflow:
	errmsg = "Data stack underflow";
	goto error;
jump_stack_overflow:
	errmsg = "Jump stack overflow";
	goto error;
data_stack_overflow:
	errmsg = "Data stack overflow";
	goto error;
tag_mismatch:
	errmsg = "Unexpected tag";
	goto error;
error:
	(void)errmsg;
	printf_debug("\nASN1: %s [m=%zu] [D=%u] [J=%u]\n", errmsg, pc, dsp,
		     jsp);
	return -EBADMSG;
}
