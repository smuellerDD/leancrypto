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
 * License: SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef X509_PARSER_H
#define X509_PARSER_H

#include "ext_headers.h"

#include "asymmetric_type.h"
#include "lc_x509.h"
#include "public_key.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Decode an X.509 time ASN.1 object
 * @param [out] _t The time to fill in
 * @param [in] hdrlen: The length of the object header
 * @param [in] tag The object tag
 * @param [in] value The object value
 * @param [in] vlen The size of the object value
 *
 * Decode an ASN.1 universal time or generalised time field into a struct the
 * kernel can handle and check it for validity.  The time is decoded thus:
 *
 *	[RFC5280 §4.1.2.5]
 *	CAs conforming to this profile MUST always encode certificate validity
 *	dates through the year 2049 as UTCTime; certificate validity dates in
 *	2050 or later MUST be encoded as GeneralizedTime.  Conforming
 *	applications MUST be able to process validity dates that are encoded in
 *	either UTCTime or GeneralizedTime.
 */
int x509_decode_time(time64_t *_t, size_t hdrlen, unsigned char tag,
		     const uint8_t *value, size_t vlen);
/*
 * x509_public_key.c
 */
int x509_get_sig_params(struct x509_certificate *cert);
int x509_check_for_self_signed(struct x509_certificate *cert);

#ifdef __cplusplus
}
#endif

#endif /* X509_PARSER_H */
