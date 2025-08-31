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

#include "ext_headers_internal.h"
#include "pkcs7_asn1.h"
#include "pkcs7_aa_asn1.h"

#define PKCS7_FUNC_UNDEF                                                        \
	(void)context;                                                         \
	(void)data;                                                            \
	(void)avail_datalen;                                                   \
	(void)tag;                                                             \
	return -EOPNOTSUPP;

int pkcs7_sig_note_pkey_algo_OID_enc(void *context, uint8_t *data,
				     size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_digest_algorithm_OID_enc(void *context, uint8_t *data,
				   size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_sig_note_digest_algo_enc(void *context, uint8_t *data,
				   size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_sig_note_pkey_algo_enc(void *context, uint8_t *data,
				 size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_check_content_type_OID_enc(void *context, uint8_t *data,
				     size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_check_content_type_enc(void *context, uint8_t *data,
				 size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_note_signeddata_version_enc(void *context, uint8_t *data,
				      size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_note_signerinfo_version_enc(void *context, uint8_t *data,
				      size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_extract_cert_continue_enc(void *context, uint8_t *data,
				    size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_extract_cert_enc(void *context, uint8_t *data, size_t *avail_datalen,
			   uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_extract_crl_cert_enc(void *context, uint8_t *data,
			       size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_extract_extended_cert_enc(void *context, uint8_t *data,
				    size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_note_certificate_list_enc(void *context, uint8_t *data,
				    size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_note_content_enc(void *context, uint8_t *data, size_t *avail_datalen,
			   uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_data_OID_enc(void *context, uint8_t *data, size_t *avail_datalen,
		       uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_note_data_enc(void *context, uint8_t *data, size_t *avail_datalen,
			uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_external_aa_continue_enc(void *context, uint8_t *data,
				   size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_external_aa_OID_enc(void *context, uint8_t *data,
			      size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_external_aa_enc(void *context, uint8_t *data, size_t *avail_datalen,
			  uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_note_attribute_type_OID_enc(void *context, uint8_t *data,
				      size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_extract_attribute_name_segment_enc(void *context, uint8_t *data,
					     size_t *avail_datalen,
					     uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_attribute_value_continue_enc(void *context, uint8_t *data,
				       size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_sig_note_set_of_authattrs_enc(void *context, uint8_t *data,
					size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_sig_note_serial_enc(void *context, uint8_t *data,
			      size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_sig_note_issuer_enc(void *context, uint8_t *data,
			      size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_sig_note_authenticated_attr_enc(void *context, uint8_t *data,
					  size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_authenticated_attr_OID_enc(void *context, uint8_t *data,
				     size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_sig_note_skid_enc(void *context, uint8_t *data, size_t *avail_datalen,
			    uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_sig_note_signature_enc(void *context, uint8_t *data,
				 size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}

int pkcs7_note_signed_info_enc(void *context, uint8_t *data,
			       size_t *avail_datalen, uint8_t *tag)
{
	PKCS7_FUNC_UNDEF
}
