/* Base64 encoder and decoder
 *
 * Copyright (C) 2018 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "base64.h"
#include "initialization.h"
#include "ret_checkers.h"
#include "visibility.h"

static const char encoding_table[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

static char decoding_table[256];

#ifdef LC_BASE64_URLSAFE
/* Filename and URL safe */
static const char encoding_table_safe[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
};
static char decoding_table_safe[256];
#endif

int lc_base64_encode_len(size_t ilen, size_t *olen, enum lc_base64_flags flags)
{
	size_t elen = 4 * ((ilen + 2) / 3);

	switch (flags) {
	case lc_base64_flag_pem:
		/* after 64 characters we have a LF */
		elen += (elen >> 6);
		break;
	case lc_base64_flag_unknown:
		break;
	default:
		return -EINVAL;
	};

	*olen = elen;
	return 0;
}

int lc_base64_decode_len(const char *idata, size_t ilen, size_t *olen,
			 uint8_t *blank_chars, enum lc_base64_flags flags)
{
	size_t dlen, numlf = 0;

	*blank_chars = 0;

	switch (flags) {
	case lc_base64_flag_pem:
		/* after 64 characters we have an LF, CR or CRLF */
		if (ilen > 65 && (idata[64] == 0x0d) && (idata[65] == 0x0a)) {
			/* We have a CRLF. */
			numlf = ilen / 66;
			/*
			 * As we have 2 characters per line feed, multiply
			 * numlf by two
			 */
			numlf <<= 1;
			if ((ilen - numlf) % 4 != 0)
				return -EINVAL;
			*blank_chars = 2;
		} else if (ilen > 64 &&
			   ((idata[64] == 0x0a) || (idata[64] == 0x0d))) {
			/* We have only an LF or a CR. */
			numlf = ilen / 65;
			if ((ilen - numlf) % 4 != 0)
				return -EINVAL;
			*blank_chars = 1;
		} else {
			return -EINVAL;
		}
		break;
	case lc_base64_flag_unknown:
		break;
	default:
		return -EINVAL;
	};

	dlen = (ilen - numlf) / 4 * 3;

	if (idata[ilen - 1] == '=')
		dlen--;
	if (idata[ilen - 2] == '=')
		dlen--;

	*olen = dlen;

	return 0;
}

static int __base64_encode(const uint8_t *idata, size_t ilen, char *odata,
			   size_t olen, enum lc_base64_flags flags,
			   const char table[])
{
	size_t elen, i, j;
	unsigned int mod_table[] = { 0, 2, 1 };
	int ret;
	uint8_t chars;

	if (!ilen)
		return 0;

	CKINT(lc_base64_encode_len(ilen, &elen, flags));
	if (olen < elen)
		return -EOVERFLOW;

	for (i = 0, j = 0, chars = 0; i < ilen;) {
		uint32_t octet_a = i < ilen ? idata[i++] : 0;
		uint32_t octet_b = i < ilen ? idata[i++] : 0;
		uint32_t octet_c = i < ilen ? idata[i++] : 0;
		uint32_t triple =
			(octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		/* Add LF after 64 Base64 characters in PEM format */
		if ((flags == lc_base64_flag_pem) && chars == 64) {
			odata[j++] = 0x0a;
			chars = 0;
		}

		odata[j++] = table[(triple >> 3 * 6) & 0x3F];
		odata[j++] = table[(triple >> 2 * 6) & 0x3F];
		odata[j++] = table[(triple >> 1 * 6) & 0x3F];
		odata[j++] = table[(triple >> 0 * 6) & 0x3F];
		chars += 4;
	}

	for (i = 0; i < mod_table[ilen % 3]; i++)
		odata[elen - 1 - i] = '=';

out:
	return ret;
}

static int __base64_decode(const char *idata, size_t ilen, uint8_t *odata,
			   size_t olen, enum lc_base64_flags flags,
			   const char table[])
{
	size_t dlen, i, j;
	int ret;
	uint8_t blank_chars, chars;

	if (!ilen)
		return 0;

	CKINT(lc_base64_decode_len(idata, ilen, &dlen, &blank_chars, flags));
	if (olen < dlen)
		return -EOVERFLOW;

	for (i = 0, j = 0, chars = 0; i < ilen;) {
		/* Add LF after 64 Base64 characters in PEM format */
		if ((flags == lc_base64_flag_pem) && chars == 64) {
			if (blank_chars == 1) {
				/*
				 * We reached the last character without any
				 * trailing CR or LF
				 */
				if (i >= ilen - 1)
					return 0;

				if ((idata[i++] != 0x0a) &&
				    (idata[i] != 0x0d))
					return -EINVAL;
			}
			if (blank_chars == 2) {
				/*
				 * We reached the last character without any
				 * trailing CR/LF
				 */
				if (i >= ilen - 2)
					return 0;

				if ((idata[i++] != 0x0d) ||
				    (idata[i++] != 0x0a))
					return -EINVAL;
			}

			chars = 0;
		}

		uint32_t sextet_a =
			idata[i] == '=' ?
				0 & i++ :
				(uint32_t)table[(unsigned char)idata[i++]];
		uint32_t sextet_b =
			idata[i] == '=' ?
				0 & i++ :
				(uint32_t)table[(unsigned char)idata[i++]];
		uint32_t sextet_c =
			idata[i] == '=' ?
				0 & i++ :
				(uint32_t)table[(unsigned char)idata[i++]];
		uint32_t sextet_d =
			idata[i] == '=' ?
				0 & i++ :
				(uint32_t)table[(unsigned char)idata[i++]];
		uint32_t triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) +
				  (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

		chars += 4;

		if (j < dlen)
			odata[j++] = (triple >> 2 * 8) & 0xFF;
		if (j < dlen)
			odata[j++] = (triple >> 1 * 8) & 0xFF;
		if (j < dlen)
			odata[j++] = (triple >> 0 * 8) & 0xFF;
	}

out:
	return ret;
}

int lc_base64_decode(const char *idata, size_t ilen, uint8_t *odata,
		     size_t olen, enum lc_base64_flags flags)
{
	return __base64_decode(idata, ilen, odata, olen, flags, decoding_table);
}

int lc_base64_encode(const uint8_t *idata, size_t ilen, char *odata,
		     size_t olen, enum lc_base64_flags flags)
{
	return __base64_encode(idata, ilen, odata, olen, flags, encoding_table);
}

#ifdef LC_BASE64_URLSAFE

int lc_base64_encode_safe(const uint8_t *idata, size_t ilen, char **odata,
			  size_t *olen, enum lc_base64_flags flags)
{
	return __base64_encode(idata, ilen, odata, olen, flags,
			       encoding_table_safe);
}

int lc_base64_decode_safe(const char *idata, size_t ilen, uint8_t **odata,
			  size_t *olen, enum lc_base64_flags flags)
{
	return __base64_decode(idata, ilen, odata, olen, flags,
			       decoding_table_safe);
}
#endif

LC_CONSTRUCTOR(lc_base64_init, LC_INIT_PRIO_ALGO)
{
	unsigned char i;

	for (i = 0; i < 64; i++)
		decoding_table[(unsigned char)encoding_table[i]] = (char)i;

#ifdef LC_BASE64_URLSAFE
	for (i = 0; i < 64; i++)
		decoding_table_safe[(unsigned char)encoding_table_safe[i]] =
			(char)i;
#endif
}
