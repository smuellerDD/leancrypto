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

#ifndef X509_CERT_GENERATOR_H
#define X509_CERT_GENERATOR_H

#include "asn1_debug.h"

#ifdef __cplusplus
extern "C" {
#endif

enum sig_algo_settings {
	sig_algo_unset,
	sig_algo_tbs_inner,
	sig_algo_pubkey,
	sig_algo_tbs_outer,
};

struct x509_generate_privkey_context {
	const struct lc_x509_key_data *keys;
	unsigned int sk_seed_written : 1;
	unsigned int sk_seed_skip_first : 1;
	unsigned int sk_full_written : 1;
	unsigned int sk_full_skip_first : 1;
	unsigned int sk_write_both : 1;
};

struct x509_generate_context {
	const struct lc_x509_certificate
		*cert; /* Certificate being constructed */

	time64_t time_to_set;

	uint16_t key_eku_processed;
	uint16_t key_usage_processed;
	uint8_t pathlen_processed;
	uint8_t basic_constraint_processed;

	uint16_t san_processed;
#define X509_CN_PROCESSED (1 << 0)
#define X509_O_PROCESSED (1 << 1)
#define X509_EMAIL_PROCESSED (1 << 2)
#define X509_C_PROCESSED (1 << 3)
#define X509_ST_PROCESSED (1 << 4)
#define X509_OU_PROCESSED (1 << 5)
#define X509_SAN_DNS_PROCESSED (1 << 6)
#define X509_SAN_IP_PROCESSED (1 << 7)
#define X509_SAN_EMAIL_PROCESSED (1 << 8)

	uint8_t *akid_raw_issuer;
	size_t akid_raw_issuer_size;

	uint8_t *tbs;
	size_t tbs_len;

	unsigned int skid_processed : 1;
	unsigned int akid_processed : 1;
	unsigned int akid_serial_processed : 1;
	unsigned int issuer_attribute_processing : 1;
	unsigned int subject_attribute_processing : 1;
	unsigned int time_already_set : 1;
	enum sig_algo_settings sig_algo_set;
	uint16_t subject_attrib_processed;
	uint16_t issuer_attrib_processed;
};

int lc_x509_concatenate_bit_string(uint8_t **dst_data,
				   size_t *dst_avail_datalen,
				   const uint8_t *src_data, size_t src_datalen);
int lc_x509_set_bit_string(uint8_t **dst_data, size_t *dst_avail_datalen,
			   const uint8_t *src_data, size_t src_datalen);

int lc_x509_name_segment_enc(const struct lc_x509_certificate_name *name,
			     uint16_t *processed, uint8_t *data,
			     size_t *avail_datalen);
int lc_x509_name_OID_enc(const struct lc_x509_certificate_name *name,
			 uint16_t processed, uint8_t *data,
			 size_t *avail_datalen);
int lc_x509_name_unprocessed(const struct lc_x509_certificate_name *name,
			     uint16_t processed);
int lc_x509_signature_reserve_room(uint8_t *data, size_t *avail_datalen,
				   size_t siglen);

#ifdef __cplusplus
}
#endif

#endif /* X509_CERT_GENERATOR_H */
