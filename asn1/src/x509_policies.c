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

#include "asn1_debug.h"
#include "lc_x509.h"
#include "lc_memcmp_secure.h"
#include "public_key.h"
#include "ret_checkers.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(x509_pol_ret_t, lc_x509_policy_is_ca,
		      const struct x509_certificate *cert)
{
	const struct public_key *pub;

	if (!cert)
		return -EINVAL;

	pub = &cert->pub;

	/*
	 * RFC 5280 section 4.2.1.3: when key usage is present, the
	 * keyCertSign must be asserted. We do not mark non-conforming
	 * certificates as CA.
	 */
	if ((pub->key_usage & LC_KEY_USAGE_EXTENSION_PRESENT) &&
	    !(pub->key_usage & LC_KEY_USAGE_KEYCERTSIGN))
		return LC_X509_POL_FALSE;

	/* RFC 5280 section 4.2.1.9 */
	if ((pub->ca_pathlen & LC_KEY_CA_MASK) &&
	    !(pub->ca_pathlen & LC_KEY_CA_CRITICAL))
		return LC_X509_POL_FALSE;

	/* Check whether it is a CA */
	if (pub->ca_pathlen & LC_KEY_CA_MASK)
		return LC_X509_POL_TRUE;

	return LC_X509_POL_FALSE;
}

LC_INTERFACE_FUNCTION(x509_pol_ret_t, lc_x509_policy_is_root_ca,
		      const struct x509_certificate *cert)
{
	x509_pol_ret_t ret;

	CKINT(lc_x509_policy_is_ca(cert));

	if (ret != LC_X509_POL_TRUE)
		return ret;

	if (!cert->self_signed)
		return LC_X509_POL_FALSE;

	return LC_X509_POL_TRUE;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(x509_pol_ret_t, lc_x509_policy_can_validate_crls,
		      const struct x509_certificate *cert)
{
	const struct public_key *pub;

	if (!cert)
		return -EINVAL;

	pub = &cert->pub;

	/*
	 * RFC 5280 section 4.2.1.3: when key usage is present, the
	 * cRLSign must be asserted. We do not mark non-conforming
	 * certificates as CA.
	 */
	if ((pub->key_usage & LC_KEY_USAGE_EXTENSION_PRESENT) &&
	    !(pub->key_usage & LC_KEY_USAGE_CRLSIGN))
		return LC_X509_POL_FALSE;

	return LC_X509_POL_TRUE;
}

LC_INTERFACE_FUNCTION(x509_pol_ret_t, lc_x509_policy_match_akid,
		      const struct x509_certificate *cert,
		      const uint8_t *reference_akid, size_t reference_akid_len)
{
	const uint8_t *akid;
	size_t akid_len;
	x509_pol_ret_t ret;

	CKNULL(cert, -EINVAL);

	if (!reference_akid)
		return LC_X509_POL_FALSE;

	akid = cert->raw_akid;
	akid_len = cert->raw_akid_size;

	/* CAs may omit the AKID - in this case use the subject key ID */
	CKINT(lc_x509_policy_is_ca(cert));
	if (!akid) {
		CKINT(lc_x509_policy_is_ca(cert));
		if (ret == LC_X509_POL_TRUE) {
			akid = cert->raw_skid;
			akid_len = cert->raw_skid_size;
		}
	}

	if (!akid)
		return -LC_X509_POL_FALSE;

	if (lc_memcmp_secure(akid, akid_len, reference_akid,
			     reference_akid_len))
		return LC_X509_POL_FALSE;

	return LC_X509_POL_TRUE;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(x509_pol_ret_t, lc_x509_policy_match_skid,
		      const struct x509_certificate *cert,
		      const uint8_t *reference_skid, size_t reference_skid_len)
{
	const uint8_t *skid;
	size_t skid_len;
	x509_pol_ret_t ret;

	CKNULL(cert, -EINVAL);

	if (!reference_skid)
		return LC_X509_POL_FALSE;

	skid = cert->raw_skid;
	skid_len = cert->raw_skid_size;

	/* CAs may omit the AKID - in this case use the subject key ID */
	CKINT(lc_x509_policy_is_ca(cert));
	if (!skid) {
		CKINT(lc_x509_policy_is_ca(cert));
		if (ret == LC_X509_POL_TRUE) {
			skid = cert->raw_skid;
			skid_len = cert->raw_skid_size;
		}
	}

	if (!skid)
		return -LC_X509_POL_FALSE;

	if (lc_memcmp_secure(skid, skid_len, reference_skid,
			     reference_skid_len))
		return LC_X509_POL_FALSE;

	return LC_X509_POL_TRUE;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(x509_pol_ret_t, lc_x509_policy_match_key_usage,
		      const struct x509_certificate *cert,
		      uint16_t required_key_usage)
{
	const struct public_key *pub;

	if (!cert)
		return -EINVAL;

	pub = &cert->pub;

	if ((pub->key_usage & required_key_usage) == required_key_usage)
		return LC_X509_POL_TRUE;

	return LC_X509_POL_FALSE;
}

LC_INTERFACE_FUNCTION(x509_pol_ret_t, lc_x509_policy_match_extended_key_usage,
		      const struct x509_certificate *cert,
		      uint16_t required_eku)
{
	const struct public_key *pub;
	uint16_t eku;

	if (!cert)
		return -EINVAL;

	pub = &cert->pub;

	eku = pub->key_eku;

	/* If extension is not present at all, we do not match any EKU */
	if (!(eku & LC_KEY_EKU_EXTENSION_PRESENT))
		return LC_X509_POL_FALSE;

	if ((pub->key_eku & required_eku) == required_eku)
		return LC_X509_POL_TRUE;

	return LC_X509_POL_FALSE;
}

LC_INTERFACE_FUNCTION(x509_pol_ret_t, lc_x509_policy_time_valid,
		      const struct x509_certificate *cert,
		      time64_t current_time)
{
	if (!cert || current_time < 9)
		return -EINVAL;

	/*
	 * Reject negative time values in the certificate.
	 */
	if (cert->valid_from < 0 || cert->valid_to < 0)
		return LC_X509_POL_FALSE;

	/*
	 * If we have a valid_from time and the given time is smaller, reject
	 * it.
	 */
	if (cert->valid_from && cert->valid_from > current_time)
		return LC_X509_POL_FALSE;

	/*
	 * If we have a valid_to time and the given time is larger, reject
	 * it.
	 */
	if (cert->valid_to && cert->valid_to < current_time)
		return LC_X509_POL_FALSE;

	/*
	 * The time either falls within the range of the certificate time.
	 * Note, if the certificate does not give either a lower or upper
	 * boundary, there is no match performed (i.e. implicit success).
	 */
	return LC_X509_POL_TRUE;
}

LC_INTERFACE_FUNCTION(x509_pol_ret_t, lc_x509_policy_cert_valid,
		      const struct x509_certificate *cert)
{
	const struct public_key *pub;
	x509_pol_ret_t ret;

	if (!cert)
		return -EINVAL;

	pub = &cert->pub;

	/* RFC5280 section 4.2.1.2: CA must have SKID */
	if ((pub->ca_pathlen & LC_KEY_CA_MASK) && !cert->raw_skid_size) {
		printf_debug("X509 Policy %s: CA does not have an SKID\n",
			     __func__);
		return LC_X509_POL_FALSE;
	}

	/* RFC5280 section 4.2.1.2: match AKID and SKID for root CA */
	CKINT(lc_x509_policy_is_root_ca(cert));
	if ((ret == LC_X509_POL_TRUE) && cert->raw_akid) {
		CKINT(lc_x509_policy_match_akid(cert, cert->raw_skid,
						cert->raw_skid_size));

		if (ret != LC_X509_POL_TRUE) {
			printf_debug(
				"X509 Policy %s: root CA does not have matching SKID and AKID\n",
				__func__);
			return ret;
		}
	}

	/*
	 * RFC5280 section 4.2.1.3: SKID must always be present.
	 */
	if (!cert->raw_skid_size) {
		printf_debug(
			"X509 Policy %s: certificate does not have an SKID\n",
			__func__);
		return LC_X509_POL_FALSE;
	}

	/*
	 * RFC5280 section 4.2.1.6: If a SAN is present, a subject may be
	 * omitted.
	 */
	if (!cert->raw_subject && !cert->san_dns && !cert->san_ip) {
		printf_debug(
			"X509 Policy %s: certificate does not have any identification\n",
			__func__);
		return LC_X509_POL_FALSE;
	}

	return LC_X509_POL_TRUE;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_policy_cert_verify,
		      const struct public_key *pkey,
		      const struct x509_certificate *cert, uint64_t flags)
{
	time64_t time_since_epoch = 0;
	int ret;

	(void)flags;

	ret = lc_get_time(&time_since_epoch);
	/*
	 * If gathering of time is not supported on local system, do not check
	 * it.
	 */
	if (ret == -EOPNOTSUPP) {
		ret = 0;
		time_since_epoch = 0;
	} else if (ret)
		return ret;

	/*
	 * Certificate validation: Check validity of time (if the underlying
	 * platform offers a time stamp)
	 */
	if (time_since_epoch) {
		CKINT(lc_x509_policy_time_valid(cert, time_since_epoch));
		if (ret == LC_X509_POL_FALSE) {
			printf_debug("Certificate's time not valid\n");
			return -EKEYREJECTED;
		}
		printf_debug("Certificate's time valid\n");
	}

	/*
	 * Certificate validation: Check signature
	 */
	CKINT_SIGCHECK(public_key_verify_signature(pkey, &cert->sig));

out:
	return ret;
}
