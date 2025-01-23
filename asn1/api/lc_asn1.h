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
/*
 * This code is derived in parts from the Linux kernel
 * License: SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef LC_ASN1_H
#define LC_ASN1_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * OIDs are turned into these values if possible, or OID__NR if not held here.
 *
 * NOTE!  Do not mess with the format of each line as this is read by
 *	  build_OID_registry.pl to generate the data for look_up_OID().
 */
enum OID {
	OID_id_dsa_with_sha1, /* 1.2.840.10030.4.3 */
	OID_id_dsa, /* 1.2.840.10040.4.1 */
	OID_id_ecPublicKey, /* 1.2.840.10045.2.1 */
	OID_id_prime192v1, /* 1.2.840.10045.3.1.1 */
	OID_id_prime256v1, /* 1.2.840.10045.3.1.7 */
	OID_id_ecdsa_with_sha1, /* 1.2.840.10045.4.1 */
	OID_id_ecdsa_with_sha224, /* 1.2.840.10045.4.3.1 */
	OID_id_ecdsa_with_sha256, /* 1.2.840.10045.4.3.2 */
	OID_id_ecdsa_with_sha384, /* 1.2.840.10045.4.3.3 */
	OID_id_ecdsa_with_sha512, /* 1.2.840.10045.4.3.4 */

	/* PKCS#1 {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1)} */
	OID_rsaEncryption, /* 1.2.840.113549.1.1.1 */
	OID_sha1WithRSAEncryption, /* 1.2.840.113549.1.1.5 */
	OID_sha256WithRSAEncryption, /* 1.2.840.113549.1.1.11 */
	OID_sha384WithRSAEncryption, /* 1.2.840.113549.1.1.12 */
	OID_sha512WithRSAEncryption, /* 1.2.840.113549.1.1.13 */
	OID_sha224WithRSAEncryption, /* 1.2.840.113549.1.1.14 */
	/* PKCS#7 {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-7(7)} */
	OID_data, /* 1.2.840.113549.1.7.1 */
	OID_signed_data, /* 1.2.840.113549.1.7.2 */
	/* PKCS#9 {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)} */
	OID_email_address, /* 1.2.840.113549.1.9.1 */
	OID_contentType, /* 1.2.840.113549.1.9.3 */
	OID_messageDigest, /* 1.2.840.113549.1.9.4 */
	OID_signingTime, /* 1.2.840.113549.1.9.5 */
	OID_smimeCapabilites, /* 1.2.840.113549.1.9.15 */
	OID_smimeAuthenticatedAttrs, /* 1.2.840.113549.1.9.16.2.11 */

	OID_mskrb5, /* 1.2.840.48018.1.2.2 */
	OID_krb5, /* 1.2.840.113554.1.2.2 */
	OID_krb5u2u, /* 1.2.840.113554.1.2.2.3 */

	/* Microsoft Authenticode & Software Publishing */
	OID_msIndirectData, /* 1.3.6.1.4.1.311.2.1.4 */
	OID_msStatementType, /* 1.3.6.1.4.1.311.2.1.11 */
	OID_msSpOpusInfo, /* 1.3.6.1.4.1.311.2.1.12 */
	OID_msPeImageDataObjId, /* 1.3.6.1.4.1.311.2.1.15 */
	OID_msIndividualSPKeyPurpose, /* 1.3.6.1.4.1.311.2.1.21 */
	OID_msOutlookExpress, /* 1.3.6.1.4.1.311.16.4 */

	OID_ntlmssp, /* 1.3.6.1.4.1.311.2.2.10 */
	OID_negoex, /* 1.3.6.1.4.1.311.2.2.30 */

	OID_spnego, /* 1.3.6.1.5.5.2 */

	OID_IAKerb, /* 1.3.6.1.5.2.5 */
	OID_PKU2U, /* 1.3.5.1.5.2.7 */
	OID_Scram, /* 1.3.6.1.5.5.14 */
	OID_certAuthInfoAccess, /* 1.3.6.1.5.5.7.1.1 */
	OID_sha1, /* 1.3.14.3.2.26 */
	OID_id_ansip384r1, /* 1.3.132.0.34 */
	OID_id_ansip521r1, /* 1.3.132.0.35 */
	OID_sha256, /* 2.16.840.1.101.3.4.2.1 */
	OID_sha384, /* 2.16.840.1.101.3.4.2.2 */
	OID_sha512, /* 2.16.840.1.101.3.4.2.3 */
	OID_sha224, /* 2.16.840.1.101.3.4.2.4 */

	/* Distinguished Name attribute IDs [RFC 2256] */
	OID_commonName, /* 2.5.4.3 */
	OID_surname, /* 2.5.4.4 */
	OID_countryName, /* 2.5.4.6 */
	OID_locality, /* 2.5.4.7 */
	OID_stateOrProvinceName, /* 2.5.4.8 */
	OID_organizationName, /* 2.5.4.10 */
	OID_organizationUnitName, /* 2.5.4.11 */
	OID_title, /* 2.5.4.12 */
	OID_description, /* 2.5.4.13 */
	OID_name, /* 2.5.4.41 */
	OID_givenName, /* 2.5.4.42 */
	OID_initials, /* 2.5.4.43 */
	OID_generationalQualifier, /* 2.5.4.44 */

	/* Certificate extension IDs */
	OID_subjectKeyIdentifier, /* 2.5.29.14 */
	OID_keyUsage, /* 2.5.29.15 */
	OID_subjectAltName, /* 2.5.29.17 */
	OID_issuerAltName, /* 2.5.29.18 */
	OID_basicConstraints, /* 2.5.29.19 */
	OID_crlDistributionPoints, /* 2.5.29.31 */
	OID_certPolicies, /* 2.5.29.32 */
	OID_authorityKeyIdentifier, /* 2.5.29.35 */
	OID_extKeyUsage, /* 2.5.29.37 */

	/* Extended Key Usage */
	OID_anyExtendedKeyUsage, /* 2.5.29.37.0 */
	OID_id_kp_serverAuth, /* 1.3.6.1.5.5.7.3.1 */
	OID_id_kp_clientAuth, /* 1.3.6.1.5.5.7.3.2 */
	OID_id_kp_codeSigning, /* 1.3.6.1.5.5.7.3.3 */
	OID_id_kp_emailProtection, /* 1.3.6.1.5.5.7.3.4 */
	OID_id_kp_timeStamping, /* 1.3.6.1.5.5.7.3.8 */
	OID_id_kp_OCSPSigning, /* 1.3.6.1.5.5.7.3.9 */

	/* Heimdal mechanisms */
	OID_NetlogonMechanism, /* 1.2.752.43.14.2 */
	OID_appleLocalKdcSupported, /* 1.2.752.43.14.3 */

	/* EC-RDSA */
	OID_gostCPSignA, /* 1.2.643.2.2.35.1 */
	OID_gostCPSignB, /* 1.2.643.2.2.35.2 */
	OID_gostCPSignC, /* 1.2.643.2.2.35.3 */
	OID_gost2012PKey256, /* 1.2.643.7.1.1.1.1 */
	OID_gost2012PKey512, /* 1.2.643.7.1.1.1.2 */
	OID_gost2012Digest256, /* 1.2.643.7.1.1.2.2 */
	OID_gost2012Digest512, /* 1.2.643.7.1.1.2.3 */
	OID_gost2012Signature256, /* 1.2.643.7.1.1.3.2 */
	OID_gost2012Signature512, /* 1.2.643.7.1.1.3.3 */
	OID_gostTC26Sign256A, /* 1.2.643.7.1.2.1.1.1 */
	OID_gostTC26Sign256B, /* 1.2.643.7.1.2.1.1.2 */
	OID_gostTC26Sign256C, /* 1.2.643.7.1.2.1.1.3 */
	OID_gostTC26Sign256D, /* 1.2.643.7.1.2.1.1.4 */
	OID_gostTC26Sign512A, /* 1.2.643.7.1.2.1.2.1 */
	OID_gostTC26Sign512B, /* 1.2.643.7.1.2.1.2.2 */
	OID_gostTC26Sign512C, /* 1.2.643.7.1.2.1.2.3 */

	/* OSCCA */
	OID_sm2, /* 1.2.156.10197.1.301 */
	OID_sm3, /* 1.2.156.10197.1.401 */
	OID_SM2_with_SM3, /* 1.2.156.10197.1.501 */
	OID_sm3WithRSAEncryption, /* 1.2.156.10197.1.504 */

	/* TCG defined OIDS for TPM based keys */
	OID_TPMLoadableKey, /* 2.23.133.10.1.3 */
	OID_TPMImportableKey, /* 2.23.133.10.1.4 */
	OID_TPMSealedData, /* 2.23.133.10.1.5 */

	/* CSOR FIPS-202 SHA-3 */
	OID_sha3_256, /* 2.16.840.1.101.3.4.2.8 */
	OID_sha3_384, /* 2.16.840.1.101.3.4.2.9 */
	OID_sha3_512, /* 2.16.840.1.101.3.4.2.10 */
	OID_shake128, /* 2.16.840.1.101.3.4.2.11 */
	OID_shake256, /* 2.16.840.1.101.3.4.2.12 */
	OID_id_ecdsa_with_sha3_256, /* 2.16.840.1.101.3.4.3.10 */
	OID_id_ecdsa_with_sha3_384, /* 2.16.840.1.101.3.4.3.11 */
	OID_id_ecdsa_with_sha3_512, /* 2.16.840.1.101.3.4.3.12 */
	OID_id_rsassa_pkcs1_v1_5_with_sha3_256, /* 2.16.840.1.101.3.4.3.14 */
	OID_id_rsassa_pkcs1_v1_5_with_sha3_384, /* 2.16.840.1.101.3.4.3.15 */
	OID_id_rsassa_pkcs1_v1_5_with_sha3_512, /* 2.16.840.1.101.3.4.3.16 */

	/* OIDs from https://github.com/IETF-Hackathon/pqc-certificates/blob/master/docs/oid_mapping.md */
	OID_id_MLDSA44, /* 2.16.840.1.101.3.4.3.17 */
	OID_id_MLDSA65, /* 2.16.840.1.101.3.4.3.18 */
	OID_id_MLDSA87, /* 2.16.840.1.101.3.4.3.19 */

	/* https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-03.html */
	OID_id_MLDSA44_Ed25519, /* 2.16.840.1.114027.80.8.1.23 */
	OID_id_MLDSA65_Ed25519, /* 2.16.840.1.114027.80.8.1.30 */
	OID_id_MLDSA87_Ed448, /* 2.16.840.1.114027.80.8.1.33 */

	/* OIDs from https://github.com/IETF-Hackathon/pqc-certificates/blob/master/docs/oid_mapping.md */
	OID_id_SLHDSA_SHAKE_128S, /* 2.16.840.1.101.3.4.3.26 */
	OID_id_SLHDSA_SHAKE_128F, /* 2.16.840.1.101.3.4.3.27 */
	OID_id_SLHDSA_SHAKE_192S, /* 2.16.840.1.101.3.4.3.28 */
	OID_id_SLHDSA_SHAKE_192F, /* 2.16.840.1.101.3.4.3.29 */
	OID_id_SLHDSA_SHAKE_256S, /* 2.16.840.1.101.3.4.3.30 */
	OID_id_SLHDSA_SHAKE_256F, /* 2.16.840.1.101.3.4.3.31 */

	OID__NR
};

#ifdef __cplusplus
}
#endif

#endif /* LC_ASN1_H */
