/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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
 * PEM encoding / decoding according to RFC 7468
 */

#include "base64.h"
#include "lc_memcmp_secure.h"
#include "lc_memcpy_secure.h"
#include "lc_pem.h"
#include "ret_checkers.h"
#include "visibility.h"

static const char lc_pem_marker_begin[] = "-----BEGIN ";
static const size_t lc_pem_marker_begin_len = 11;
static const char lc_pem_marker_end[] = "-----END ";
static const size_t lc_pem_marker_end_len = 9;
static const char lc_pem_marker_trailer[] = "-----";
static const size_t lc_pem_marker_trailer_len = 5;
static const char lc_pem_marker_certificate[] = "CERTIFICATE";
static const size_t lc_pem_marker_certificate_len = 11;
static const char lc_pem_marker_priv_key[] = "PRIVATE KEY";
static const size_t lc_pem_marker_priv_key_len = 11;
static const char lc_pem_marker_cms[] = "CMS";
static const size_t lc_pem_marker_cms_len = 3;

#if 0
static const char lc_pem_marker_pkcs7[] = "PKCS7";
static const size_t lc_pem_marker_pkcs7_len = 5;

static const char lc_pem_marker_x509_crl[] = "X509 CRL";
static const char lc_pem_marker_cert_req[] = "CERTIFICATE REQUEST";
static const char lc_pem_marker_enc_priv_key[] = "ENCRYPTED PRIVATE KEY";
static const char lc_pem_marker_attr_cert[] = "ATTRIBUTE CERTIFICATE";
static const char lc_pem_marker_pub_key[] = "PUBLIC KEY";
#endif

static int lc_pem_envelope_label_len(size_t *olen, enum lc_pem_flags flags)
{
	switch (flags) {
	case lc_pem_flag_certificate:
		*olen += lc_pem_marker_certificate_len;
		break;
	case lc_pem_flag_priv_key:
		*olen += lc_pem_marker_priv_key_len;
		break;
	case lc_pem_flag_cms:
		*olen += lc_pem_marker_cms_len;
		break;
	case lc_pem_flag_nopem:
	default:
		return -EINVAL;
	}

	return 0;
}

static int lc_pem_envelope_begin_len(size_t *olen, enum lc_pem_flags flags)
{
	/* Header without label, but with LF */
	*olen += lc_pem_marker_begin_len + lc_pem_marker_trailer_len + 1;

	return lc_pem_envelope_label_len(olen, flags);
}

static int lc_pem_envelope_end_len(size_t *olen, enum lc_pem_flags flags)
{
	/* End without label, but with LF at the beginning */
	*olen += 1 + lc_pem_marker_end_len + lc_pem_marker_trailer_len;

	return lc_pem_envelope_label_len(olen, flags);
}

static int lc_pem_envelope_len(size_t *olen, enum lc_pem_flags flags)
{
	int ret;

	CKINT(lc_pem_envelope_begin_len(olen, flags));
	CKINT(lc_pem_envelope_end_len(olen, flags));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_pem_encode_len, size_t ilen, size_t *olen,
		      enum lc_pem_flags flags)
{
	int ret;

	*olen = 0;

	/* Pure Base64 data */
	CKINT(lc_base64_encode_len(ilen, olen, lc_base64_flag_pem));

	/* PEM data */
	CKINT(lc_pem_envelope_len(olen, flags));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_pem_decode_len, const char *idata, size_t ilen,
		      size_t *olen, uint8_t *blank_chars,
		      enum lc_pem_flags flags)
{
	size_t len = 0, begin_len = 0;
	int ret;

	CKINT(lc_pem_envelope_begin_len(&begin_len, flags));

	if (ilen <= begin_len)
		return -EINVAL;

	if (idata[begin_len - 1] == 0x0d && idata[begin_len] == 0x0a) {
		/*
		 * lc_pem_envelope_begin_len accounts only for LF, but when
		 * having CRLF, add one more char.
		 */
		begin_len++;
		len++; /* one for adjusting lc_pem_envelope_begin_len */
		len++; /* one for adjusting lc_pem_envelope_end_len */
	} else if (idata[begin_len - 1] != 0x0d &&
		   idata[begin_len - 1] != 0x0a) {
		/* The last character of the start is not a CR or LF -> error */
		return -EINVAL;
	}

	/* PEM data */
	CKINT(lc_pem_envelope_len(&len, flags));

	/* Remove all trailing characters beyond the last hyphen */
	while (ilen) {
		if (idata[ilen - 1] == 0x2d)
			break;
		ilen--;
	}

	if (ilen <= len)
		return -EINVAL;
	/* Base64 data - reduced by PEM wrapper */
	CKINT(lc_base64_decode_len(idata + begin_len, ilen - len, &len,
				   blank_chars, lc_base64_flag_pem));
	*olen = len;

out:
	return ret;
}

static int lc_pem_encode_type(char **odata, size_t *olen,
			      enum lc_pem_flags flags)
{
	switch (flags) {
	case lc_pem_flag_certificate:
		lc_memcpy_secure(*odata, *olen, lc_pem_marker_certificate,
				 lc_pem_marker_certificate_len);
		*olen -= lc_pem_marker_certificate_len;
		*odata += lc_pem_marker_certificate_len;
		break;
	case lc_pem_flag_priv_key:
		lc_memcpy_secure(*odata, *olen, lc_pem_marker_priv_key,
				 lc_pem_marker_priv_key_len);
		*olen -= lc_pem_marker_priv_key_len;
		*odata += lc_pem_marker_priv_key_len;
		break;
	case lc_pem_flag_cms:
		lc_memcpy_secure(*odata, *olen, lc_pem_marker_cms,
				 lc_pem_marker_cms_len);
		*olen -= lc_pem_marker_cms_len;
		*odata += lc_pem_marker_cms_len;
		break;
	case lc_pem_flag_nopem:
	default:
		return -EINVAL;
	}

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_pem_encode, const uint8_t *idata, size_t ilen,
		      char *odata, size_t olen, enum lc_pem_flags flags)
{
	size_t elen, base64_len, len;
	int ret;

	if (!ilen)
		return 0;

	/* Pure Base64 data */
	CKINT(lc_base64_encode_len(ilen, &base64_len, lc_base64_flag_pem));
	elen = base64_len;

	CKINT(lc_pem_envelope_len(&len, flags));
	elen += len;
	if (olen < elen)
		return -EOVERFLOW;

	/* Encode header with LF */
	lc_memcpy_secure(odata, olen, lc_pem_marker_begin,
			 lc_pem_marker_begin_len);
	olen -= lc_pem_marker_begin_len;
	odata += lc_pem_marker_begin_len;
	CKINT(lc_pem_encode_type(&odata, &olen, flags));
	lc_memcpy_secure(odata, olen, lc_pem_marker_trailer,
			 lc_pem_marker_trailer_len);
	olen -= lc_pem_marker_trailer_len;
	odata += lc_pem_marker_trailer_len;
	odata[0] = 0x0a;
	olen--;
	odata++;

	/* Encode Base64 data */
	CKINT(lc_base64_encode(idata, ilen, odata, olen, lc_base64_flag_pem));
	olen -= base64_len;
	odata += base64_len;

	odata[0] = 0x0a;
	olen--;
	odata++;

	/* Encode end */
	lc_memcpy_secure(odata, olen, lc_pem_marker_end, lc_pem_marker_end_len);
	olen -= lc_pem_marker_end_len;
	odata += lc_pem_marker_end_len;
	CKINT(lc_pem_encode_type(&odata, &olen, flags));
	lc_memcpy_secure(odata, olen, lc_pem_marker_trailer,
			 lc_pem_marker_trailer_len);

out:
	return ret;
}

static int lc_pem_decode_type(const char **idata, size_t *ilen,
			      enum lc_pem_flags flags)
{
	switch (flags) {
	case lc_pem_flag_certificate:
		if (*ilen < lc_pem_marker_certificate_len)
			return -EINVAL;
		if (lc_memcmp_secure(*idata, lc_pem_marker_certificate_len,
				     lc_pem_marker_certificate,
				     lc_pem_marker_certificate_len))
			return -EINVAL;
		*ilen -= lc_pem_marker_certificate_len;
		*idata += lc_pem_marker_certificate_len;
		break;
	case lc_pem_flag_priv_key:
		if (*ilen < lc_pem_marker_priv_key_len)
			return -EINVAL;
		if (lc_memcmp_secure(*idata, lc_pem_marker_priv_key_len,
				     lc_pem_marker_priv_key,
				     lc_pem_marker_priv_key_len))
			return -EINVAL;
		*ilen -= lc_pem_marker_priv_key_len;
		*idata += lc_pem_marker_priv_key_len;
		break;
	case lc_pem_flag_cms:
		if (*ilen < lc_pem_marker_cms_len)
			return -EINVAL;
		if (lc_memcmp_secure(*idata, lc_pem_marker_cms_len,
				     lc_pem_marker_cms, lc_pem_marker_cms_len))
			return -EINVAL;
		*ilen -= lc_pem_marker_cms_len;
		*idata += lc_pem_marker_cms_len;
		break;
	case lc_pem_flag_nopem:
	default:
		return -EINVAL;
	}

	return 0;
}

/* Verify header */
static int lc_pem_decode_verify_header(const char **idata, size_t *ilen,
				       enum lc_pem_flags flags)
{
	size_t ilen_local = *ilen;
	const char *idata_local = *idata;
	int ret;

	/* Verify header */
	if (ilen_local < lc_pem_marker_begin_len)
		return -EINVAL;
	if (lc_memcmp_secure(idata_local, lc_pem_marker_begin_len,
			     lc_pem_marker_begin, lc_pem_marker_begin_len))
		return -EINVAL;
	ilen_local -= lc_pem_marker_begin_len;
	idata_local += lc_pem_marker_begin_len;
	CKINT(lc_pem_decode_type(&idata_local, &ilen_local, flags));
	if (ilen_local < lc_pem_marker_trailer_len)
		return -EINVAL;
	if (lc_memcmp_secure(idata_local, lc_pem_marker_trailer_len,
			     lc_pem_marker_trailer, lc_pem_marker_trailer_len))
		return -EINVAL;
	ilen_local -= lc_pem_marker_trailer_len;
	idata_local += lc_pem_marker_trailer_len;

	*ilen = ilen_local;
	*idata = idata_local;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_pem_is_encoded, const char *idata, size_t ilen,
		      enum lc_pem_flags flags)
{
	size_t envelope_begin_len;
	int ret;

	CKINT(lc_pem_envelope_begin_len(&envelope_begin_len, flags));

	if (ilen < envelope_begin_len)
		return -EOVERFLOW;

	CKINT(lc_pem_decode_verify_header(&idata, &ilen, flags));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_pem_decode, const char *idata, size_t ilen,
		      uint8_t *odata, size_t olen, enum lc_pem_flags flags)
{
	size_t dlen, envelope_begin_len, envelope_end_len;
	int ret;
	uint8_t blank_chars;

	if (!ilen)
		return 0;

	/* Get the actual output data size */
	CKINT(lc_pem_decode_len(idata, ilen, &dlen, &blank_chars, flags));
	if (olen < dlen)
		return -EOVERFLOW;

	CKINT(lc_pem_envelope_begin_len(&envelope_begin_len, flags));
	CKINT(lc_pem_envelope_end_len(&envelope_end_len, flags));

	/* Remove all trailing characters beyond the last hyphen */
	while (ilen) {
		if (idata[ilen - 1] == 0x2d)
			break;
		ilen--;
	}

	if (ilen < (envelope_begin_len + envelope_end_len))
		return -EOVERFLOW;

	CKINT(lc_pem_decode_verify_header(&idata, &ilen, flags));

	/* Check the possible CR/LF combinations */
	if (blank_chars == 1 && ((idata[0] != 0x0a) && (idata[0] != 0x0d)))
		return -EINVAL;
	if (blank_chars == 2) {
		/* one for adjusting lc_pem_envelope_end_len */
		envelope_end_len++;
		if ((idata[0] != 0x0d) || (idata[1] != 0x0a)) {
			/*
			 * We do not need to recheck
			 * (ilen >= envelope_begin_len + envelope_end_len + 1)
			 * here, because if the caller has a wrong formatted
			 * input, the lc_memcmp_secure will catch it as the
			 * final ilen is too short for the different markers and
			 * thus the match will error out.
			 */
			return -EINVAL;
		}
	}
	ilen -= blank_chars;
	idata += blank_chars;

	/*
	 * Now Base64-decode all data between current pointer until the start
	 * of the PEM envelope end
	 */
	CKINT(lc_base64_decode(idata, ilen - envelope_end_len, odata, olen,
			       lc_base64_flag_pem));
	idata += ilen - envelope_end_len;
	ilen = envelope_end_len;

	/* Check the possible CR/LF combinations */
	if (blank_chars == 1 && ((idata[0] != 0x0a) && (idata[0] != 0x0d)))
		return -EINVAL;
	if (blank_chars == 2 && ((idata[0] != 0x0d) || (idata[1] != 0x0a))) {
		/*
		 * We do not need to recheck (ilen >= envelope_end_len + 1)
		 * here, because if the caller has a wrong formatted input, the
		 * lc_memcmp_secure will catch it as the final ilen is too short
		 * for the different markers and thus the match will error out.
		 */
		return -EINVAL;
	}
	ilen -= blank_chars;
	idata += blank_chars;

	/* Verify end */
	if (ilen < lc_pem_marker_end_len)
		return -EINVAL;
	if (lc_memcmp_secure(idata, lc_pem_marker_end_len, lc_pem_marker_end,
			     lc_pem_marker_end_len))
		return -EINVAL;
	ilen -= lc_pem_marker_end_len;
	idata += lc_pem_marker_end_len;
	CKINT(lc_pem_decode_type(&idata, &ilen, flags));
	if (ilen < lc_pem_marker_trailer_len)
		return -EINVAL;
	if (lc_memcmp_secure(idata, lc_pem_marker_trailer_len,
			     lc_pem_marker_trailer, lc_pem_marker_trailer_len))
		return -EINVAL;
	ilen -= lc_pem_marker_trailer_len;
	idata += lc_pem_marker_trailer_len;

out:
	return ret;
}
