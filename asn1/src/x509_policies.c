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
#include "lc_x509_parser.h"
#include "lc_memcmp_secure.h"
#include "public_key.h"
#include "ret_checkers.h"
#include "visibility.h"

static x509_pol_ret_t
lc_509_policy_cert_contains_signature(const struct lc_x509_certificate *cert)
{
	const struct lc_public_key_signature *sig;

	if (!cert)
		return -EINVAL;

	sig = &cert->sig;
	if (sig->s && sig->s_size)
		return LC_X509_POL_TRUE;

	return LC_X509_POL_FALSE;
}

static x509_pol_ret_t
lc_x509_policy_version_ge(const struct lc_x509_certificate *cert,
			  uint8_t requested_version)
{
	if (!cert)
		return -EINVAL;

	if (cert->x509_version >= requested_version)
		return LC_X509_POL_TRUE;

	return LC_X509_POL_FALSE;
}

LC_INTERFACE_FUNCTION(x509_pol_ret_t, lc_x509_policy_is_ca,
		      const struct lc_x509_certificate *cert)
{
	const struct lc_public_key *pub;
	int ret;

	if (!cert)
		return -EINVAL;

	CKINT(lc_x509_policy_cert_valid(cert))
	if (ret != LC_X509_POL_TRUE)
		return ret;

	pub = &cert->pub;

	/* RFC5280 section 4.2.1.2: CA must have SKID */
	if (!cert->raw_skid_size) {
		printf_debug("X509 Policy %s: CA does not have an SKID\n",
			     __func__);
		return LC_X509_POL_FALSE;
	}

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

	/* BSI TR02102-3 chapter 3 */
	CKINT(lc_x509_policy_version_ge(cert, 3));
	if (ret != LC_X509_POL_TRUE)
		return ret;

	/* BSI TR02102-3 chapter 3 */
	CKINT(lc_509_policy_cert_contains_signature(cert));
	if (ret != LC_X509_POL_TRUE)
		return ret;

	/* Check whether it is a CA */
	if (pub->ca_pathlen & LC_KEY_CA_MASK)
		return LC_X509_POL_TRUE;

	ret = LC_X509_POL_FALSE;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(x509_pol_ret_t, lc_x509_policy_is_selfsigned,
		      const struct lc_x509_certificate *cert)
{
	if (!cert)
		return -EINVAL;

	if (!cert->self_signed)
		return LC_X509_POL_FALSE;

	return LC_X509_POL_TRUE;
}

LC_INTERFACE_FUNCTION(x509_pol_ret_t, lc_x509_policy_is_root_ca,
		      const struct lc_x509_certificate *cert)
{
	x509_pol_ret_t ret;

	if (!cert)
		return -EINVAL;

	if (cert->raw_akid) {
		CKINT(lc_x509_policy_match_akid(cert, cert->raw_skid,
						cert->raw_skid_size));
		if (ret != LC_X509_POL_TRUE) {
			printf_debug(
				"X509 Policy %s: root CA does not have matching SKID and AKID\n",
				__func__);
			return ret;
		}
	}

	CKINT(lc_x509_policy_is_ca(cert));
	if (ret != LC_X509_POL_TRUE)
		return ret;

	CKINT(lc_x509_policy_is_selfsigned(cert));
	if (ret != LC_X509_POL_TRUE)
		return ret;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(x509_pol_ret_t, lc_x509_policy_can_validate_crls,
		      const struct lc_x509_certificate *cert)
{
	const struct lc_public_key *pub;

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
		      const struct lc_x509_certificate *cert,
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
		      const struct lc_x509_certificate *cert,
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
		      const struct lc_x509_certificate *cert,
		      uint16_t required_key_usage)
{
	const struct lc_public_key *pub;
	uint16_t set_keyusage;

	if (!cert)
		return -EINVAL;

	/* If the caller does not requests the checking, return true */
	if (!required_key_usage)
		return LC_X509_POL_TRUE;

	pub = &cert->pub;
	set_keyusage =
		pub->key_usage & (uint16_t)~LC_KEY_USAGE_EXTENSION_PRESENT;

	/* If extension is not present at all, we do not match any EKU */
	if (!(pub->key_usage & LC_KEY_USAGE_EXTENSION_PRESENT)) {
		if (required_key_usage)
			return LC_X509_POL_FALSE;
		return LC_X509_POL_TRUE;
	}

	if ((set_keyusage & required_key_usage) == required_key_usage)
		return LC_X509_POL_TRUE;

	return LC_X509_POL_FALSE;
}

LC_INTERFACE_FUNCTION(x509_pol_ret_t, lc_x509_policy_match_extended_key_usage,
		      const struct lc_x509_certificate *cert,
		      uint16_t required_eku)
{
	const struct lc_public_key *pub;
	uint16_t eku;

	if (!cert)
		return -EINVAL;

	/* If the caller does not requests the checking, return true */
	if (!required_eku)
		return LC_X509_POL_TRUE;

	pub = &cert->pub;

	eku = pub->key_eku & (uint16_t)~LC_KEY_EKU_EXTENSION_PRESENT;

	/* If extension is not present at all, we do not match any EKU */
	if (!(pub->key_eku & LC_KEY_EKU_EXTENSION_PRESENT)) {
		if (required_eku)
			return LC_X509_POL_FALSE;
		return LC_X509_POL_TRUE;
	}

	/* The required EKU must be a subset of all EKU flags */
	if ((eku & required_eku) == required_eku)
		return LC_X509_POL_TRUE;

	return LC_X509_POL_FALSE;
}

LC_INTERFACE_FUNCTION(x509_pol_ret_t, lc_x509_policy_time_valid,
		      const struct lc_x509_certificate *cert,
		      time64_t current_time)
{
	if (!cert || current_time < 0)
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
		      const struct lc_x509_certificate *cert)
{
	if (!cert)
		return -EINVAL;

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
}

LC_INTERFACE_FUNCTION(int, lc_x509_policy_cert_verify,
		      const struct lc_public_key *pkey,
		      const struct lc_x509_certificate *cert, uint64_t flags)
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
