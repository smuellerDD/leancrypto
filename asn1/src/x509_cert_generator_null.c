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

#include "x509.asn1.h"
#include "x509_akid.asn1.h"
#include "x509_basic_constraints.asn1.h"
#include "x509_eku.asn1.h"
#include "x509_keyusage.asn1.h"
#include "x509_san.asn1.h"
#include "x509_skid.asn1.h"

#define X509_FUNC_UNDEF                                                        \
	(void)context;                                                         \
	(void)data;                                                            \
	(void)avail_datalen;                                                   \
	(void)tag;                                                             \
	return -EOPNOTSUPP;

int x509_eku_enc(void *context, uint8_t *data, size_t *avail_datalen,
		 uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_basic_constraints_ca_enc(void *context, uint8_t *data,
				  size_t *avail_datalen, uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_basic_constraints_pathlen_enc(void *context, uint8_t *data,
				       size_t *avail_datalen, uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_san_OID_enc(void *context, uint8_t *data, size_t *avail_datalen,
		     uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_extract_name_segment_enc(void *context, uint8_t *data,
				  size_t *avail_datalen, uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_san_dns_enc(void *context, uint8_t *data, size_t *avail_datalen,
		     uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_san_ip_enc(void *context, uint8_t *data, size_t *avail_datalen,
		    uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_keyusage_enc(void *context, uint8_t *data, size_t *avail_datalen,
		      uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_skid_enc(void *context, uint8_t *data, size_t *avail_datalen,
		  uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_akid_note_kid_enc(void *context, uint8_t *data, size_t *avail_datalen,
			   uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_akid_note_name_enc(void *context, uint8_t *data, size_t *avail_datalen,
			    uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_akid_note_serial_enc(void *context, uint8_t *data,
			      size_t *avail_datalen, uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_akid_note_OID_enc(void *context, uint8_t *data, size_t *avail_datalen,
			   uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_extension_continue_enc(void *context, uint8_t *data,
				size_t *avail_datalen, uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_extension_OID_enc(void *context, uint8_t *data, size_t *avail_datalen,
			   uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_extension_critical_enc(void *context, uint8_t *data,
				size_t *avail_datalen, uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_process_extension_enc(void *context, uint8_t *data,
			       size_t *avail_datalen, uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_note_tbs_certificate_enc(void *context, uint8_t *data,
				  size_t *avail_datalen, uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_signature_algorithm_enc(void *context, uint8_t *data,
				 size_t *avail_datalen, uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_note_algorithm_OID_enc(void *context, uint8_t *data,
				size_t *avail_datalen, uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_note_signature_enc(void *context, uint8_t *data, size_t *avail_datalen,
			    uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_note_serial_enc(void *context, uint8_t *data, size_t *avail_datalen,
			 uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_note_sig_algo_enc(void *context, uint8_t *data, size_t *avail_datalen,
			   uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_note_issuer_enc(void *context, uint8_t *data, size_t *avail_datalen,
			 uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_note_subject_enc(void *context, uint8_t *data, size_t *avail_datalen,
			  uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_note_params_enc(void *context, uint8_t *data, size_t *avail_datalen,
			 uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_extract_attribute_name_segment_enc(void *context, uint8_t *data,
					    size_t *avail_datalen, uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_note_attribute_type_OID_enc(void *context, uint8_t *data,
				     size_t *avail_datalen, uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_attribute_value_continue_enc(void *context, uint8_t *data,
				      size_t *avail_datalen, uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_set_uct_time_enc(void *context, uint8_t *data, size_t *avail_datalen,
			  uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_set_gen_time_enc(void *context, uint8_t *data, size_t *avail_datalen,
			  uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_note_not_before_enc(void *context, uint8_t *data,
			     size_t *avail_datalen, uint8_t *tag)
{
	X509_FUNC_UNDEF
}

/*
 * Process the time when the certificate becomes invalid
 */
int x509_note_not_after_enc(void *context, uint8_t *data, size_t *avail_datalen,
			    uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_extract_key_data_enc(void *context, uint8_t *data,
			      size_t *avail_datalen, uint8_t *tag)
{
	X509_FUNC_UNDEF
}

int x509_version_enc(void *context, uint8_t *data, size_t *avail_datalen,
		     uint8_t *tag)
{
	X509_FUNC_UNDEF
}
