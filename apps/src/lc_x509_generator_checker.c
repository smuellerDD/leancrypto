/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "binhexbin.h"
#include "ext_headers_internal.h"
#include "lc_x509_parser.h"
#include "math_helper.h"
#include "ret_checkers.h"
#include "x509_checker.h"
#include "x509_print.h"

/******************************************************************************
 * X.509 tests
 ******************************************************************************/

int apply_checks_x509(const struct lc_x509_certificate *x509,
		      const struct x509_checker_options *parsed_opts)
{
	const struct lc_public_key *pub = &x509->pub;
	lc_x509_pol_ret_t ret;

	CKINT(lc_x509_policy_cert_valid(x509));
	if (ret == LC_X509_POL_FALSE) {
		printf("Invalid certificate detected\n");
		if (!parsed_opts->cert_may_be_invalid)
			return -EINVAL;
	}

	if (parsed_opts->check_ca) {
		/* Check whether CA basic constraint is present */
		if ((pub->basic_constraint & LC_KEY_IS_CA) != LC_KEY_IS_CA) {
			printf("Certificate is not marked as CA\n");
			return -EINVAL;
		} else {
			printf("Certificate is marked as CA\n");
		}
	}

	if (parsed_opts->check_ca_conformant) {
		CKINT(lc_x509_policy_is_ca(x509));

		if (ret == LC_X509_POL_FALSE) {
			printf("Certificate is not marked as an RFC5280 conformant CA\n");
			return -EINVAL;
		} else {
			printf("Certificate is marked as an RFC5280 conformant CA\n");
		}
	}

	if (parsed_opts->check_root_ca) {
		CKINT(lc_x509_policy_is_root_ca(x509));

		if (ret == LC_X509_POL_FALSE) {
			printf("Certificate is not marked as an RFC5280 conformant root CA\n");
			return -EINVAL;
		} else {
			printf("Certificate is marked as an RFC5280 conformant root CA\n");
		}
	}

	if (parsed_opts->check_no_ca) {
		CKINT(lc_x509_policy_is_ca(x509));

		if (ret == LC_X509_POL_TRUE) {
			printf("Certificate is marked as CA\n");
			return -EINVAL;
		} else {
			printf("Certificate is not marked as CA\n");
		}
	}

	if (parsed_opts->check_selfsigned) {
		/*
		 * The signature is only verified for self-signed certificates.
		 * For other certificates, the certificate chain needs to be
		 * followed using the PKCS7 handling.
		 */
		if (parsed_opts->unsupported_sig) {
			if (!x509->unsupported_sig) {
				printf("Certificate has supported signature\n");
				return -EINVAL;
			} else {
				printf("Certificate has unsupported signature\n");
			}
		} else {
			if (!x509->self_signed) {
				printf("Certificate is not self-signed\n");
				return -EINVAL;
			} else {
				printf("Certificate is self-signed\n");
			}
		}
	}
	if (parsed_opts->check_no_selfsigned) {
		if (x509->self_signed) {
			printf("Certificate is self-signed\n");
			return -EINVAL;
		} else {
			printf("Certificate is not self-signed\n");
		}
	}

	if (parsed_opts->valid_from) {
		if (parsed_opts->valid_from != (uint64_t)x509->valid_from) {
			struct tm *exp_detail, *act_detail;

			// localtime_r(&x509->valid_from, &act_detail);
			// localtime_r((int64_t *)&parsed_opts->valid_from,
			// 	    &exp_detail);
			act_detail = localtime((time_t *)&x509->valid_from);
			exp_detail =
				localtime((time_t *)&parsed_opts->valid_from);
			printf("Certificate valid_from time mismatch, expected %d-%.2d-%.2d %.2d:%.2d:%.2d (%" PRIu64
			       "), actual %d-%.2d-%.2d %.2d:%.2d:%.2d (%" PRId64
			       ")\n",
			       exp_detail->tm_year + 1900,
			       exp_detail->tm_mon + 1, exp_detail->tm_mday,
			       exp_detail->tm_hour, exp_detail->tm_min,
			       exp_detail->tm_sec, parsed_opts->valid_from,
			       act_detail->tm_year + 1900,
			       act_detail->tm_mon + 1, act_detail->tm_mday,
			       act_detail->tm_hour, act_detail->tm_min,
			       act_detail->tm_sec, x509->valid_from);
			return -EINVAL;
		} else {
			printf("Certificate valid_from time successfully verified\n");
		}
	}

	if (parsed_opts->valid_to) {
		if (parsed_opts->valid_to != (uint64_t)x509->valid_to) {
			struct tm *exp_detail, *act_detail;

			// localtime_r(&x509->valid_to, &act_detail);
			// localtime_r((int64_t *)&parsed_opts->valid_to,
			// 	    &exp_detail);
			act_detail = localtime((time_t *)&x509->valid_to);
			exp_detail =
				localtime((time_t *)&parsed_opts->valid_to);
			printf("Certificate valid_to time mismatch, expected %d-%.2d-%.2d %.2d:%.2d:%.2d (%" PRIu64
			       "), actual %d-%.2d-%.2d %.2d:%.2d:%.2d (%" PRId64
			       ")\n",
			       exp_detail->tm_year + 1900,
			       exp_detail->tm_mon + 1, exp_detail->tm_mday,
			       exp_detail->tm_hour, exp_detail->tm_min,
			       exp_detail->tm_sec, parsed_opts->valid_to,
			       act_detail->tm_year + 1900,
			       act_detail->tm_mon + 1, act_detail->tm_mday,
			       act_detail->tm_hour, act_detail->tm_min,
			       act_detail->tm_sec, x509->valid_to);
			return -EINVAL;
		} else {
			printf("Certificate valid_to time successfully verified\n");
		}
	}

	if (parsed_opts->issuer_cn) {
		struct lc_x509_certificate_name
			search_name = { .cn = {
						.value = parsed_opts->issuer_cn,
						.size = (uint8_t)strlen(
							parsed_opts->issuer_cn),
					} };

		if (lc_x509_policy_cert_subject_match(
			    x509, &search_name,
			    lc_x509_policy_cert_subject_match_issuer_only) ==
		    LC_X509_POL_FALSE) {
			printf("Issuers mismatch, expected %s, actual %s\n",
			       parsed_opts->issuer_cn, x509->issuer);
			return -EINVAL;
		} else {
			printf("Issuer matches expected value\n");
		}
	}
	if (parsed_opts->subject_cn) {
		struct lc_x509_certificate_name
			search_name = { .cn = {
						.value =
							parsed_opts->subject_cn,
						.size = (uint8_t)strlen(
							parsed_opts->subject_cn),
					} };

		if (lc_x509_policy_cert_subject_match(
			    x509, &search_name,
			    lc_x509_policy_cert_subject_match_dn_only) ==
		    LC_X509_POL_FALSE) {
			printf("Subject mismatch, expected %s, actual %s\n",
			       parsed_opts->subject_cn, x509->subject);
			return -EINVAL;
		} else {
			printf("Subject matches expected value\n");
		}
	}

	if (parsed_opts->print_cert_details) {
		ret = print_x509_cert(x509);

		if (ret)
			return ret;
	}

	if (parsed_opts->eku) {
		CKINT(lc_x509_policy_match_extended_key_usage(
			x509, (uint16_t)parsed_opts->eku));

		if (ret == LC_X509_POL_TRUE) {
			printf("EKU field matches\n");
		} else {
			printf("EKU field mismatches (expected %u, actual %u)\n",
			       parsed_opts->eku, pub->key_eku);
			return -EINVAL;
		}
	}

	if (parsed_opts->keyusage) {
		CKINT(lc_x509_policy_match_key_usage(
			x509, (uint16_t)parsed_opts->keyusage));

		if (ret == LC_X509_POL_TRUE) {
			printf("Key usage field matches\n");
		} else {
			printf("Key usage field mismatches (expected %u, actual %u)\n",
			       parsed_opts->keyusage,
			       pub->key_usage &
				       (uint16_t)~LC_KEY_USAGE_EXTENSION_PRESENT);
			return -EINVAL;
		}
	}

	if (parsed_opts->san_email) {
		struct lc_x509_certificate_name
			search_name = { .cn = {
						.value = parsed_opts->san_email,
						.size = (uint8_t)strlen(
							parsed_opts->san_email),
					} };

		if (lc_x509_policy_cert_subject_match(
			    x509, &search_name,
			    lc_x509_policy_cert_subject_match_san_email_only) ==
		    LC_X509_POL_FALSE) {
			printf("SAN Email: names mismatch (expected %s, actual %s)\n",
			       parsed_opts->san_email, x509->san_email);
			return -EINVAL;
		} else {
			printf("SAN Email match\n");
		}
	}

	if (parsed_opts->san_email) {
		struct lc_x509_certificate_name
			search_name = { .cn = {
						.value = parsed_opts->san_email,
						.size = (uint8_t)strlen(
							parsed_opts->san_email),
					} };

		if (lc_x509_policy_cert_subject_match(
			    x509, &search_name,
			    lc_x509_policy_cert_subject_match_san_email_only) ==
		    LC_X509_POL_FALSE) {
			printf("SAN Email: names mismatch (expected %s, actual %s)\n",
			       parsed_opts->san_email, x509->san_email);
			return -EINVAL;
		} else {
			printf("SAN Email match\n");
		}
	}
	if (parsed_opts->san_dns) {
		struct lc_x509_certificate_name
			search_name = { .cn = {
						.value = parsed_opts->san_dns,
						.size = (uint8_t)strlen(
							parsed_opts->san_dns),
					} };

		if (lc_x509_policy_cert_subject_match(
			    x509, &search_name,
			    lc_x509_policy_cert_subject_match_san_dns_only) ==
		    LC_X509_POL_FALSE) {
			printf("SAN DNS: names mismatch (expected %s, actual %s)\n",
			       parsed_opts->san_dns, x509->san_dns);
			return -EINVAL;
		} else {
			printf("SAN DNS match\n");
		}
	}
	if (parsed_opts->san_ip) {
		struct lc_x509_certificate_name
			search_name = { .cn = {
						.value = parsed_opts->san_ip,
						.size = (uint8_t)strlen(
							parsed_opts->san_ip),
					} };

		if (lc_x509_policy_cert_subject_match(
			    x509, &search_name,
			    lc_x509_policy_cert_subject_match_issuer_only) ==
		    LC_X509_POL_FALSE) {
			char buf[33] = { 0 };

			bin2hex(x509->san_ip, x509->san_ip_len, buf,
				sizeof(buf) - 1, 1);

			printf("SAN IP: names mismatch (expected %s, actual %s)\n",
			       parsed_opts->san_ip, buf);
			return -EINVAL;
		} else {
			printf("SAN IP match\n");
		}
	}

	if (parsed_opts->skid) {
		uint8_t exp_id_bin[32];
		size_t exp_id_len = strlen(parsed_opts->skid);

		hex2bin(parsed_opts->skid, exp_id_len, exp_id_bin,
			sizeof(exp_id_bin));

		if (exp_id_len / 2 != x509->raw_skid_size) {
			printf("SKID: lengths differ (expected %zu, actual %zu)\n",
			       exp_id_len, x509->raw_skid_size);
			return -EINVAL;
		}

		if (memcmp(exp_id_bin, x509->raw_skid, x509->raw_skid_size)) {
			char buf[65] = { 0 };

			bin2hex(x509->raw_skid, x509->raw_skid_size, buf,
				sizeof(buf) - 1, 1);

			printf("SKID: names mismatch (expected %s, actual %s)\n",
			       parsed_opts->skid, buf);
			return -EINVAL;
		} else {
			CKINT(lc_x509_policy_match_skid(x509, exp_id_bin,
							exp_id_len / 2));

			if (ret == LC_X509_POL_FALSE) {
				printf("SKID x509_policy_match_skid failed\n");
				return -EINVAL;
			}

			printf("SKID match\n");
		}
	}
	if (parsed_opts->akid) {
		uint8_t exp_id_bin[32];
		size_t exp_id_len = strlen(parsed_opts->akid);

		hex2bin(parsed_opts->akid, exp_id_len, exp_id_bin,
			sizeof(exp_id_bin));

		if (exp_id_len / 2 != x509->raw_akid_size) {
			printf("AKID: lengths differ (expected %zu, actual %zu)\n",
			       exp_id_len, x509->raw_akid_size);
			return -EINVAL;
		}

		if (memcmp(exp_id_bin, x509->raw_akid, x509->raw_akid_size)) {
			char buf[65] = { 0 };

			bin2hex(x509->raw_akid, x509->raw_akid_size, buf,
				sizeof(buf) - 1, 1);

			printf("AKID: names mismatch (expected %s, actual %s)\n",
			       parsed_opts->akid, buf);
			return -EINVAL;
		} else {
			/* Check the API */
			CKINT(lc_x509_policy_match_akid(x509, exp_id_bin,
							exp_id_len / 2));

			if (ret == LC_X509_POL_FALSE) {
				printf("AKID x509_policy_match_akid failed\n");
				return -EINVAL;
			}

			printf("AKID match\n");
		}
	}

	if (parsed_opts->check_time) {
		time64_t time_since_epoch;

		CKINT(lc_get_time(&time_since_epoch));
		CKINT(lc_x509_policy_time_valid(x509, time_since_epoch));

		if (ret == LC_X509_POL_FALSE) {
			printf("Time check: certificate is currently not valid\n");
			return -EINVAL;
		}

		CKINT(lc_x509_policy_time_valid(x509, 1));
		if (ret == LC_X509_POL_TRUE) {
			printf("Time check: certificate marked as valid with unlikely time (1 second after EPOCH)\n");
			return -EINVAL;
		}
		CKINT(lc_x509_policy_time_valid(x509, 9999999999));
		if (ret == LC_X509_POL_TRUE) {
			printf("Time check: certificate marked as valid with unlikely time (way in the future)\n");
			return -EINVAL;
		}

		printf("Time check: certificate is valid\n");
	}

	return 0;

out:
	return ret;
}

/******************************************************************************
 * PKCS7 load tests
 ******************************************************************************/

int apply_checks_pkcs7(const struct lc_pkcs7_message *pkcs7_msg,
		       const struct x509_checker_options *parsed_opts)
{
	int ret = 0;

	if (parsed_opts->print_cert_details) {
		print_pkcs7_data(pkcs7_msg);
	}

	if (parsed_opts->check_ca) {
		const struct lc_x509_certificate *x509 = pkcs7_msg->certs;
		int found = 0;

		while (x509) {
			const struct lc_public_key *pub = &x509->pub;

			if ((pub->basic_constraint & LC_KEY_IS_CA) ==
			    LC_KEY_IS_CA) {
				found = 1;
				break;
			}

			x509 = x509->next;
		}

		/* Check whether CA basic constraint is present */
		if (!found) {
			printf("Certificate is not marked as CA\n");
			return -EINVAL;
		} else {
			printf("Certificate is marked as CA\n");
		}
	}

	if (parsed_opts->check_ca_conformant) {
		const struct lc_x509_certificate *x509 = pkcs7_msg->certs;

		while (x509) {
			ret = lc_x509_policy_is_ca(x509);
			if (ret == LC_X509_POL_TRUE)
				break;

			x509 = x509->next;
		}

		if (ret == LC_X509_POL_FALSE) {
			printf("Certificate is not marked as an RFC5280 conformant CA\n");
			return -EINVAL;
		} else {
			printf("Certificate is marked as an RFC5280 as CA\n");
		}
	}

	if (parsed_opts->check_root_ca) {
		const struct lc_x509_certificate *x509 = pkcs7_msg->certs;

		while (x509) {
			ret = lc_x509_policy_is_root_ca(x509);
			if (ret == LC_X509_POL_TRUE)
				break;

			x509 = x509->next;
		}

		if (ret == LC_X509_POL_FALSE) {
			printf("Certificate is not marked as an RFC5280 conformant root CA\n");
			return -EINVAL;
		} else {
			printf("Certificate is marked as an RFC5280 conformant root CA\n");
		}
	}

	if (parsed_opts->check_no_ca) {
		const struct lc_x509_certificate *x509 = pkcs7_msg->certs;

		while (x509) {
			ret = lc_x509_policy_is_ca(x509);
			if (ret == LC_X509_POL_FALSE)
				break;

			x509 = x509->next;
		}
		if (ret < 0)
			return ret;

		if (ret == LC_X509_POL_TRUE) {
			printf("Certificate is marked as CA\n");
			return -EINVAL;
		} else {
			printf("Certificate is not marked as CA\n");
		}
	}

	if (parsed_opts->check_selfsigned) {
		/*
		 * The signature is only verified for self-signed certificates.
		 * For other certificates, the certificate chain needs to be
		 * followed using the PKCS7 handling.
		 */
		const struct lc_x509_certificate *x509 = pkcs7_msg->certs;
		int found = 0;

		while (x509) {
			if (parsed_opts->unsupported_sig) {
				if (x509->unsupported_sig) {
					found = 1;
					break;
				}
			} else {
				if (x509->self_signed) {
					found = 1;
					break;
				}
			}

			x509 = x509->next;
		}

		if (parsed_opts->unsupported_sig) {
			if (!found) {
				printf("Certificate has supported signature\n");
				return -EINVAL;
			} else {
				printf("Certificate has unsupported signature\n");
			}
		} else {
			if (!found) {
				printf("Certificate is not self-signed\n");
				return -EINVAL;
			} else {
				printf("Certificate is self-signed\n");
			}
		}
	}

	if (parsed_opts->check_no_selfsigned) {
		const struct lc_x509_certificate *x509 = pkcs7_msg->certs;
		int found = 0;

		while (x509) {
			if (!x509->self_signed) {
				found = 1;
				break;
			}

			x509 = x509->next;
		}

		if (found) {
			printf("Certificate is not self-signed\n");
		} else {
			printf("Certificate is not self-signed\n");
			return -EINVAL;
		}
	}

	if (parsed_opts->issuer_cn) {
		const struct lc_x509_certificate *x509 = pkcs7_msg->certs;
		int found = 0;

		while (x509) {
			if (!strncmp(x509->issuer, parsed_opts->issuer_cn,
				     sizeof(x509->issuer))) {
				found = 1;
				break;
			}

			x509 = x509->next;
		}

		if (!found) {
			printf("Issuers mismatch\n");
			return -EINVAL;
		} else {
			printf("Issuer matches expected value\n");
		}
	}
	if (parsed_opts->subject_cn) {
		const struct lc_x509_certificate *x509 = pkcs7_msg->certs;
		int found = 0;

		while (x509) {
			if (!strncmp(x509->subject, parsed_opts->subject_cn,
				     sizeof(x509->subject))) {
				found = 1;
				break;
			}

			x509 = x509->next;
		}

		if (!found) {
			printf("Subject mismatch\n");
			return -EINVAL;
		} else {
			printf("Subject matches expected value\n");
		}
	}

	if (parsed_opts->eku) {
		const struct lc_x509_certificate *x509 = pkcs7_msg->certs;

		while (x509) {
			ret = lc_x509_policy_match_extended_key_usage(
				x509, (uint16_t)parsed_opts->eku);
			if (ret == LC_X509_POL_TRUE)
				break;

			x509 = x509->next;
		}

		if (ret == LC_X509_POL_TRUE) {
			printf("EKU field matches\n");
		} else {
			printf("EKU field mismatches\n");
			return -EINVAL;
		}
	}

	if (parsed_opts->keyusage) {
		const struct lc_x509_certificate *x509 = pkcs7_msg->certs;

		while (x509) {
			ret = lc_x509_policy_match_key_usage(
				x509, (uint16_t)parsed_opts->keyusage);
			if (ret == LC_X509_POL_TRUE)
				break;

			x509 = x509->next;
		}

		if (ret == LC_X509_POL_TRUE) {
			printf("Key usage field matches\n");
		} else {
			printf("Key usage field mismatches\n");
			return -EINVAL;
		}
	}

	return 0;
}
