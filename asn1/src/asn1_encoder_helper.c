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
/*
 * This code is derived in parts from the Linux kernel
 * License: SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2019 James.Bottomley@HansenPartnership.com
 */

#include "asn1_debug.h"
#include "asn1_encoder.h"
#include "asn1_ber_bytecode.h"
#include "ret_checkers.h"

/**
 * asn1_encode_integer() - encode positive integer to ASN.1
 * @data:	pointer to the pointer to the data
 * @end_data:	end of data pointer, points one beyond last usable byte in @data
 * @integer:	integer to be encoded
 * @param [out] retptr Pointer to the data buffer new data can be placed into
 *
 * This is a simplified encoder: it only currently does
 * positive integers, but it should be simple enough to add the
 * negative case if a use comes along.
 */
int asn1_encode_integer(uint8_t *data, size_t *datalen, int64_t integer,
			uint8_t **retptr)
{
	size_t i;
	uint8_t *d = &data[2];
	int ret = 0;
	int found = 0;

	if (integer < 0) {
		printf("BUG: integer encode only supports positive integers");
		ret = -EINVAL;
		goto out;
	}

	CKNULL(data, -EINVAL);

	/* need at least 3 bytes for tag, length and integer encoding */
	if (*datalen < 3) {
		ret = -EINVAL;
		goto out;
	}

	/* remaining length where at d (the start of the integer encoding) */
	*datalen -= 2;

	data[0] = _tag(UNIV, PRIM, INT);
	if (integer == 0) {
		*d++ = 0;
		goto out;
	}

	for (i = sizeof(integer); i > 0; i--) {
		int64_t byte = integer >> (8 * (i - 1));

		if (!found && byte == 0)
			continue;

		/*
		 * for a positive number the first byte must have bit
		 * 7 clear in two's complement (otherwise it's a
		 * negative number) so prepend a leading zero if
		 * that's not the case
		 */
		if (!found && (byte & 0x80)) {
			/*
			 * no check needed here, we already know we
			 * have len >= 1
			 */
			*d++ = 0;
			*datalen -= 1;
		}

		found = 1;
		if (*datalen == 0) {
			ret = -EINVAL;
			goto out;
		}

		*d++ = (uint8_t)byte;
		*datalen -= 1;
	}

out:
	data[1] = (uint8_t)(d - data - 2);
	*retptr = d;

	return ret;
}

/* calculate the base 128 digit values setting the top bit of the first octet */
static int asn1_encode_oid_digit(uint8_t **_data, size_t *data_len,
				 uint32_t oid)
{
	unsigned char *data = *_data;
	int start = 7 + 7 + 7 + 7;
	int ret = 0;

	if (*data_len < 1)
		return -EINVAL;

	/* quick case */
	if (oid == 0) {
		*data++ = 0x80;
		(*data_len)--;
		goto out;
	}

	while (oid >> start == 0)
		start -= 7;

	while (start > 0 && *data_len > 0) {
		uint8_t byte;

		byte = (uint8_t)(oid >> start);
		oid = oid - (uint32_t)(byte << start);
		start -= 7;
		byte |= 0x80;
		*data++ = byte;
		(*data_len)--;
	}

	if (*data_len > 0) {
		*data++ = (uint8_t)oid;
		(*data_len)--;
	} else {
		ret = -EINVAL;
	}

out:
	*_data = data;
	return ret;
}

/**
 * asn1_encode_oid() - encode an oid to ASN.1
 * @data:	position to begin encoding at
 * @end_data:	end of data pointer, points one beyond last usable byte in @data
 * @oid:	array of oids
 * @oid_len:	length of oid array
 * @param [out] retptr Pointer to the data buffer new data can be placed into
 *
 * this encodes an OID up to ASN.1 when presented as an array of OID values
 */
int asn1_encode_oid(uint8_t *data, size_t *datalen, uint32_t oid[],
		    size_t oid_len, uint8_t **retptr)
{
	size_t i;
	unsigned char *d = data;
	int ret = 0;

	if (oid_len < 2) {
		printf("OID must have at least two elements");
		ret = -EINVAL;
		goto out;
	}

	if (oid_len > 32) {
		printf("OID is too large");
		ret = -EINVAL;
		goto out;
	}

	CKNULL(data, -EINVAL);

	/* need at least 3 bytes for tag, length and OID encoding */
	if (*datalen < 3) {
		ret = -EINVAL;
		goto out;
	}

	data[0] = _tag(UNIV, PRIM, OID);
	*d++ = (uint8_t)(oid[0] * 40 + oid[1]);

	*datalen -= 3;

	for (i = 2; i < oid_len; i++) {
		CKINT(asn1_encode_oid_digit(&d, datalen, oid[i]));
	}

	data[1] = (uint8_t)(d - data - 2);

out:
	*retptr = d;
	return ret;
}

/**
 * asn1_encode_binary_oid() - encode a binary OID to ASN.1
 * @data:	position to begin encoding at
 * @end_data:	end of data pointer, points one beyond last usable byte in @data
 * @oid:	array of oids
 * @oid_len:	length of oid array
 * @param [out] retptr Pointer to the data buffer new data can be placed into
 *
 * this encodes an OID up to ASN.1 when presented as an array of OID values
 */
int asn1_encode_binary_oid(uint8_t *data, size_t *datalen,
			   const uint8_t *oid_data, size_t oid_data_len,
			   uint8_t **retptr)
{
	unsigned char *d = data;
	int ret = 0;

	if (oid_data_len < 2) {
		printf("OID must have at least two elements");
		ret = -EINVAL;
		goto out;
	}

	if (oid_data_len >= 128) {
		printf("OID is too large");
		ret = -EINVAL;
		goto out;
	}

	CKNULL(data, -EINVAL);

	/* need at least 3 bytes for tag, length and OID encoding */
	if (*datalen < 2 + oid_data_len) {
		ret = -EINVAL;
		goto out;
	}

	data[0] = _tag(UNIV, PRIM, OID);
	data[1] = (uint8_t)oid_data_len;
	memcpy(&data[2], oid_data, oid_data_len);
	*datalen -= oid_data_len + 2;
	d += oid_data_len + 2;

out:
	*retptr = d;
	return ret;
}

/**
 * asn1_encode_length() - encode a length to follow an ASN.1 tag
 * @data: pointer to encode at
 * @data_len: pointer to remaining length (adjusted by routine)
 * @len: length to encode
 *
 * This routine can encode lengths up to 65535 using the ASN.1 rules.
 * It will accept a negative length and place a zero length tag
 * instead (to keep the ASN.1 valid).  This convention allows other
 * encoder primitives to accept negative lengths as singalling the
 * sequence will be re-encoded when the length is known.
 */
int asn1_encode_length(uint8_t **data, size_t *data_len, size_t len)
{
	if (*data_len < 1)
		return -EINVAL;

	if (len <= 0x7f) {
		*((*data)++) = (uint8_t)len;
		(*data_len)--;
		return 0;
	}

	if (*data_len < 2)
		return -EINVAL;

	if (len <= 0xff) {
		*((*data)++) = 0x81;
		*((*data)++) = len & 0xff;
		*data_len -= 2;
		return 0;
	}

	if (*data_len < 3)
		return -EINVAL;

	if (len <= 0xffff) {
		*((*data)++) = 0x82;
		*((*data)++) = (len >> 8) & 0xff;
		*((*data)++) = len & 0xff;
		*data_len -= 3;
		return 0;
	}

	if (len > 0xffffff) {
		printf("ASN.1 length can't be > 0xffffff");
		return -EINVAL;
	}

	if (*data_len < 4)
		return -EINVAL;
	*((*data)++) = 0x83;
	*((*data)++) = (len >> 16) & 0xff;
	*((*data)++) = (len >> 8) & 0xff;
	*((*data)++) = len & 0xff;
	*data_len -= 4;

	return 0;
}

/**
 * asn1_encode_tag() - add a tag for optional or explicit value
 * @data:	pointer to place tag at
 * @end_data:	end of data pointer, points one beyond last usable byte in @data
 * @tag:	tag to be placed
 * @string:	the data to be tagged
 * @len:	the length of the data to be tagged
 * @param [out] retptr Pointer to the data buffer new data can be placed into
 *
 * Note this currently only handles short form tags < 31.
 *
 * Standard usage is to pass in a @tag, @string and @length and the
 * @string will be ASN.1 encoded with @tag and placed into @data.  If
 * the encoding would put data past @end_data then an error is
 * returned, otherwise a pointer to a position one beyond the encoding
 * is returned.
 *
 * To encode in place pass a NULL @string and -1 for @len and the
 * maximum allowable beginning and end of the data; all this will do
 * is add the current maximum length and update the data pointer to
 * the place where the tag contents should be placed is returned.  The
 * data should be copied in by the calling routine which should then
 * repeat the prior statement but now with the known length.  In order
 * to avoid having to keep both before and after pointers, the repeat
 * expects to be called with @data pointing to where the first encode
 * returned it and still NULL for @string but the real length in @len.
 */
int asn1_encode_tag(uint8_t *data, size_t *datalen, uint32_t tag,
		    const uint8_t *string, size_t len, uint8_t **retptr)
{
	int ret;

	if (tag > 30) {
		printf("ASN.1 tag can't be > 30");
		ret = -EINVAL;
		goto out;
	}

	if (!string && (len > 127)) {
		printf("BUG: recode tag is too big (>127)");
		ret = -EINVAL;
		goto out;
	}

	CKNULL(data, -EINVAL);

	if (!string && len > 0) {
		/*
		 * we're recoding, so move back to the start of the
		 * tag and install a dummy length because the real
		 * data_len should be NULL
		 */
		data -= 2;
	}

	if (*datalen < 2) {
		ret = -EINVAL;
		goto out;
	}

	*(data++) = (uint8_t)_tagn(CONT, CONS, tag);
	*datalen -= 1;
	CKINT(asn1_encode_length(&data, datalen, len));

	if (!string)
		goto out;

	if (*datalen < len) {
		ret = -EINVAL;
		goto out;
	}

	memcpy(data, string, len);
	data += len;
	*datalen -= len;

out:
	*retptr = data;
	return ret;
}

/**
 * asn1_encode_octet_string() - encode an ASN.1 OCTET STRING
 * @data:	pointer to encode at
 * @end_data:	end of data pointer, points one beyond last usable byte in @data
 * @string:	string to be encoded
 * @len:	length of string
 * @param [out] retptr Pointer to the data buffer new data can be placed into
 *
 * Note ASN.1 octet strings may contain zeros, so the length is obligatory.
 */
int asn1_encode_octet_string(uint8_t *data, size_t *datalen,
			     const uint8_t *string, size_t len,
			     uint8_t **retptr)
{
	int ret;

	CKNULL(data, -EINVAL);

	/* need minimum of 2 bytes for tag and length of zero length string */
	if (*datalen < 2) {
		ret = -EINVAL;
		goto out;
	}

	*(data++) = _tag(UNIV, PRIM, OTS);
	*datalen -= 1;

	CKINT(asn1_encode_length(&data, datalen, len));

	if (*datalen < len) {
		ret = -EINVAL;
		goto out;
	}

	memcpy(data, string, len);
	data += len;
	*datalen -= len;

out:
	*retptr = data;
	return ret;
}

/**
 * asn1_encode_sequence() - wrap a byte stream in an ASN.1 SEQUENCE
 * @data:	pointer to encode at
 * @end_data:	end of data pointer, points one beyond last usable byte in @data
 * @seq:	data to be encoded as a sequence
 * @len:	length of the data to be encoded as a sequence
 * @param [out] retptr Pointer to the data buffer new data can be placed into
 *
 * Fill in a sequence.  To encode in place, pass NULL for @seq and -1
 * for @len; then call again once the length is known (still with NULL
 * for @seq). In order to avoid having to keep both before and after
 * pointers, the repeat expects to be called with @data pointing to
 * where the first encode placed it.
 */
int asn1_encode_sequence(uint8_t *data, size_t *datalen, const uint8_t *seq,
			 size_t len, uint8_t **retptr)
{
	int ret;

	if (!seq && len > 127) {
		printf("BUG: recode sequence is too big (>127)");
		ret = -EINVAL;
		goto out;
	}

	CKNULL(data, -EINVAL);

	if (!seq) {
		/*
		 * we're recoding, so move back to the start of the
		 * sequence and install a dummy length because the
		 * real length should be NULL
		 */
		data -= 2;
	}

	if (*datalen < 2) {
		ret = -EINVAL;
		goto out;
	}

	*(data++) = _tag(UNIV, CONS, SEQ);
	*datalen -= 1;

	CKINT(asn1_encode_length(&data, datalen, len));

	if (!seq)
		goto out;

	if (*datalen < len) {
		ret = -EINVAL;
		goto out;
	}

	memcpy(data, seq, len);
	data += len;
	*datalen -= len;

out:
	*retptr = data;
	return ret;
}

/**
 * asn1_encode_boolean() - encode a boolean value to ASN.1
 * @data:	pointer to encode at
 * @end_data:	end of data pointer, points one beyond last usable byte in @data
 * @val:	the boolean true/false value
 * @param [out] retptr Pointer to the data buffer new data can be placed into
 */
int asn1_encode_boolean(uint8_t *data, size_t *datalen, int val,
			uint8_t **retptr)
{
	int ret;

	CKNULL(data, -EINVAL);

	/* booleans are 3 bytes: tag, length == 1 and value == 0 or 1 */
	if (*datalen < 3) {
		ret = -EINVAL;
		goto out;
	}

	*(data++) = _tag(UNIV, PRIM, BOOL);
	*datalen -= 1;

	CKINT(asn1_encode_length(&data, datalen, 1));

	if (val)
		*(data++) = ASN1_TRUE;
	else
		*(data++) = ASN1_FALSE;

	*datalen -= 1;

out:
	*retptr = data;
	return ret;
}
