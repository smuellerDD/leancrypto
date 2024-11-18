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

#ifndef ASN1_ENCODER_H
#define ASN1_ENCODER_H

#include "asn1.h"
#include "ext_headers.h"

#ifdef __cplusplus
extern "C" {
#endif

struct asn1_encoder;

#define LC_ASN1_RET_CONTINUE 1
#define LC_ASN1_RET_SET_ZERO_CONTENT 2

int asn1_ber_encoder(const struct asn1_encoder *encoder, void *context,
		     uint8_t *data, size_t *in_out_avail_datalen);

#define asn1_oid_len(oid) (sizeof(oid) / sizeof(uint32_t))
int asn1_encode_integer(uint8_t *data, size_t *datalen, int64_t integer,
			uint8_t **retptr);
int asn1_encode_oid(uint8_t *data, size_t *datalen, uint32_t oid[],
		    size_t oid_len, uint8_t **retptr);
int asn1_encode_binary_oid(uint8_t *data, size_t *datalen,
			   const uint8_t *oid_data, size_t oid_data_len,
			   uint8_t **retptr);
int asn1_encode_tag(uint8_t *data, size_t *datalen, uint32_t tag,
		    const uint8_t *string, size_t len, uint8_t **retptr);
int asn1_encode_octet_string(uint8_t *data, size_t *datalen,
			     const uint8_t *string, size_t len,
			     uint8_t **retptr);
int asn1_encode_sequence(uint8_t *data, size_t *datalen, const uint8_t *seq,
			 size_t len, uint8_t **retptr);
int asn1_encode_boolean(uint8_t *data, size_t *datalen, int val,
			uint8_t **retptr);

int asn1_encode_length(uint8_t **data, size_t *data_len, size_t len);

int asn1_encode_length_size(size_t len, size_t *len_len);

#ifdef __cplusplus
}
#endif

#endif /* ASN1_DECODER_H */
