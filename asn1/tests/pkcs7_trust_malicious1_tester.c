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

#include "lc_pkcs7_generator.h"
#include "lc_pkcs7_parser.h"
#include "lc_x509_generator.h"
#include "lc_x509_parser.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "visibility.h"

#include "../../apps/src/lc_x509_generator_helper.h"

/*
 * This is a large memory buffer - use heap to allocate it as stack may
 * explode on some platforms like macOS.
 */
struct workspace {
	struct lc_pkcs7_trust_store trust_store;
	struct lc_x509_certificate ca1, ca2, ca3, ca1_dec, ca2_dec, ca3_dec;
	struct lc_pkcs7_message pkcs7, pkcs7_dec;
	struct lc_x509_key_input_data key_input_data1, key_input_data2,
		key_input_data3;
	uint8_t pkcs7_blob[65536], ca1_blob[65536], ca2_blob[65536],
		ca3_blob[65536];
	struct lc_x509_key_data keys1, keys2, keys3;
};

static const uint8_t id[] = { 0x01, 0x02, 0x03, 0x04 };
static const uint8_t id2[] = { 0x02, 0x03, 0x04, 0x05 };

static int pkcs7_malicious_set_cert(struct lc_x509_certificate *cert)
{
	int ret;

	CKINT(lc_x509_cert_set_akid(cert, id, sizeof(id)));
	CKINT(lc_x509_cert_set_skid(cert, id, sizeof(id)));
	CKINT(lc_x509_cert_set_serial(cert, id, sizeof(id)));
	CKINT(lc_x509_cert_set_valid_from(cert, 1729527728));
	CKINT(lc_x509_cert_set_valid_to(cert, 2044210606));
	CKINT(lc_x509_cert_set_subject_cn(cert, "testCA", 6));

	CKINT(lc_x509_cert_set_keyusage(cert, "digitalSignature"));
	CKINT(lc_x509_cert_set_keyusage(cert, "keyEncipherment"));
	CKINT(lc_x509_cert_set_keyusage(cert, "keyCertSign"));
	CKINT(lc_x509_cert_set_keyusage(cert, "critical"));

	CKINT(lc_x509_cert_set_ca(cert));

out:
	return ret;
}

static int pkcs7_malicious_set_cert2(struct lc_x509_certificate *cert)
{
	int ret;

	CKINT(lc_x509_cert_set_serial(cert, id2, sizeof(id2)));
	CKINT(lc_x509_cert_set_valid_from(cert, 1729527728));
	CKINT(lc_x509_cert_set_valid_to(cert, 2044210606));
	CKINT(lc_x509_cert_set_subject_cn(cert, "testCA2", 7));

	CKINT(lc_x509_cert_set_keyusage(cert, "digitalSignature"));
	CKINT(lc_x509_cert_set_keyusage(cert, "keyEncipherment"));
	CKINT(lc_x509_cert_set_keyusage(cert, "keyCertSign"));
	CKINT(lc_x509_cert_set_keyusage(cert, "critical"));

out:
	return ret;
}

static int pkcs7_maclious_gen_certs(struct workspace *ws, int set_ca3_akid_null)
{
	size_t blob_len;
	int ret;

	LC_X509_LINK_INPUT_DATA(&ws->keys1, &ws->key_input_data1);
	LC_X509_LINK_INPUT_DATA(&ws->keys2, &ws->key_input_data2);
	LC_X509_LINK_INPUT_DATA(&ws->keys3, &ws->key_input_data3);

	/* Set identical identifiers for both certs */
	CKINT(pkcs7_malicious_set_cert(&ws->ca1));
	CKINT(pkcs7_malicious_set_cert(&ws->ca2));
	CKINT(pkcs7_malicious_set_cert2(&ws->ca3));

	/* Generate keypair */
	CKINT(lc_x509_keypair_gen(&ws->ca1, &ws->keys1, LC_SIG_DILITHIUM_44));
	CKINT(lc_x509_keypair_gen(&ws->ca2, &ws->keys2, LC_SIG_DILITHIUM_44));
	CKINT(lc_x509_keypair_gen(&ws->ca3, &ws->keys3, LC_SIG_DILITHIUM_44));

	/*
	 * Encode / decode certs - and generate self-signed signatures
	 *
	 * It is important that only freshly decoded certs are continued to be
	 * used for PKCS#7 operations as TBSCertificate is needed for signature
	 * operations.
	 *
	 * Thus we set the private keys again to the certificate.
	 */
	blob_len = sizeof(ws->ca1_blob);
	CKINT_LOG(lc_x509_cert_encode(&ws->ca1, ws->ca1_blob, &blob_len),
		  "X.509 encode CA1\n");
	CKINT_LOG(lc_x509_cert_decode(&ws->ca1_dec, ws->ca1_blob,
				      sizeof(ws->ca2_blob) - blob_len),
		  "X.509 decode CA1\n");
	/* Set the full key pair again to the parsed certificate */
	CKINT(lc_x509_keypair_load(&ws->ca1_dec, &ws->keys1));

	blob_len = sizeof(ws->ca2_blob);
	CKINT_LOG(lc_x509_cert_encode(&ws->ca2, ws->ca2_blob, &blob_len),
		  "X.509 encode CA2\n");
	CKINT_LOG(lc_x509_cert_decode(&ws->ca2_dec, ws->ca2_blob,
				      sizeof(ws->ca2_blob) - blob_len),
		  "X.509 decode CA2\n");
	/* Set the full key pair again to the parsed certificate */
	CKINT(lc_x509_keypair_load(&ws->ca2_dec, &ws->keys2));

	/* Set signer for CA3 */
	CKINT(lc_x509_cert_set_signer(&ws->ca3, &ws->keys2, &ws->ca2_dec));

	if (set_ca3_akid_null) {
		ws->ca3.raw_akid = NULL;
		ws->ca3.raw_akid_size = 0;
	}

	blob_len = sizeof(ws->ca2_blob);
	CKINT_LOG(lc_x509_cert_encode(&ws->ca3, ws->ca3_blob, &blob_len),
		  "X.509 encode CA3\n");
	CKINT_LOG(lc_x509_cert_decode(&ws->ca3_dec, ws->ca3_blob,
				      sizeof(ws->ca3_blob) - blob_len),
		  "X.509 decode CA3\n");
	CKINT(lc_x509_cert_set_signer(&ws->ca3_dec, &ws->keys3, &ws->ca2_dec));

out:
	return ret;
}

/* Create PKCS#7 msg signed with CA2 */
static int pkcs7_maclious_gen_msg(struct workspace *ws)
{
	size_t blob_len;
	int ret;

	/* Set the data */
	CKINT_LOG(lc_pkcs7_set_data(&ws->pkcs7, id, sizeof(id), 0),
		  "PKCS7 set data\n");

	/* Load CA2 into the PKCS#7 msg */
	CKINT_LOG(lc_pkcs7_set_certificate(&ws->pkcs7, &ws->ca2_dec),
		  "Adding loaded X.509 certificate to PKCS#7 message failed\n");

	/* Set CA3 as signer */
	CKINT_LOG(lc_pkcs7_set_signer(&ws->pkcs7, &ws->ca3_dec, NULL, 0),
		  "PKCS7 set signer\n");

	/* Encode PKCS7 blob and generate signature */
	blob_len = sizeof(ws->pkcs7_blob);
	CKINT_LOG(lc_pkcs7_encode(&ws->pkcs7, ws->pkcs7_blob, &blob_len),
		  "PKCS7 encode\n");

	/* Decode the PKCS7 blob */
	CKINT_LOG(lc_pkcs7_decode(&ws->pkcs7_dec, ws->pkcs7_blob,
				  sizeof(ws->pkcs7_blob) - blob_len),
		  "PKCS7 decode\n");

	/* Set the data */
	CKINT_LOG(lc_pkcs7_supply_detached_data(&ws->pkcs7_dec, id, sizeof(id)),
		  "PKCS7 supply detached\n");

out:
	return ret;
}

static void pkcs7_malicious_clear(struct workspace *ws)
{
	/* Clear the PKCS#7 messages first as they may use the certs */
	lc_pkcs7_message_clear(&ws->pkcs7);
	lc_pkcs7_message_clear(&ws->pkcs7_dec);

	/* Now clean the certificates */
	lc_x509_cert_clear(&ws->ca1);
	lc_x509_cert_clear(&ws->ca2);
	lc_x509_cert_clear(&ws->ca3);
	lc_x509_cert_clear(&ws->ca1_dec);
	lc_x509_cert_clear(&ws->ca2_dec);
	lc_x509_cert_clear(&ws->ca3_dec);

	/* Do not clear trust store all all its certs are cleared before */
	//lc_pkcs7_trust_store_clear(&ws->trust_store);
}

/*
 * Test goal: Just like test 0, but CA 3 has no AKID
 */
static int pkcs7_maclious_certs8(void)
{
	int ret = 0;
	__LC_DECLARE_MEM_HEAP(ws, struct workspace, sizeof(uint64_t));

	CKINT(pkcs7_maclious_gen_certs(ws, 1));
	CKINT(pkcs7_maclious_gen_msg(ws));

	/* Load CA2 into trust store */
	CKINT_LOG(lc_pkcs7_trust_store_add(&ws->trust_store, &ws->ca2_dec),
		  "Loading certificate CA2 into trust store\n");

	CKINT_LOG(lc_pkcs7_verify(&ws->pkcs7_dec, &ws->trust_store, NULL),
		  "PKCS#7 verification failure: %d\n", ret);

out:
	pkcs7_malicious_clear(ws);
	__LC_RELEASE_MEM_HEAP(ws);
	return ret;
}

/*
 * Same as pkcs7_maclious_certs5, but no trust store -> chain validation fails
 * due to wrong signature in root CA.
 */
static int pkcs7_maclious_certs7(void)
{
	uint8_t *pk;
	int ret = 0;
	__LC_DECLARE_MEM_HEAP(ws, struct workspace, sizeof(uint64_t));

	CKINT(pkcs7_maclious_gen_certs(ws, 0));
	CKINT(pkcs7_maclious_gen_msg(ws));

	/* Modify pub key in the message */
	pk = (uint8_t *)ws->pkcs7_dec.certs->pub.key;
	pk[0] ^= 0x01;

	CKINT_LOG(lc_pkcs7_verify(&ws->pkcs7_dec, NULL, NULL),
		  "PKCS#7 verification failure: %d\n", ret);

out:
	pkcs7_malicious_clear(ws);
	__LC_RELEASE_MEM_HEAP(ws);
	return ret;
}

/*
 * Test goal: CA2 is in the trust store and signed the data, but modify the
 * CA2 instance in the PKCS#7 msg -> as the certificate from the trust store
 * is used and not from the PKCS#7 msg, the test succeeds.
 */
static int pkcs7_maclious_certs6(void)
{
	uint8_t *pk;
	int ret = 0;
	__LC_DECLARE_MEM_HEAP(ws, struct workspace, sizeof(uint64_t));

	CKINT(pkcs7_maclious_gen_certs(ws, 0));
	CKINT(pkcs7_maclious_gen_msg(ws));

	/* Load CA2 into trust store */
	CKINT_LOG(lc_pkcs7_trust_store_add(&ws->trust_store, &ws->ca2_dec),
		  "Loading certificate CA2 into trust store\n");

	/* Modify pub key in the message */
	pk = (uint8_t *)ws->pkcs7_dec.certs->pub.key;
	pk[0] ^= 0x01;

	CKINT_LOG(lc_pkcs7_verify(&ws->pkcs7_dec, &ws->trust_store, NULL),
		  "PKCS#7 verification failure: %d\n", ret);

out:
	pkcs7_malicious_clear(ws);
	__LC_RELEASE_MEM_HEAP(ws);
	return ret;
}

/*
 * Test goal: check that signature verification is in place when no trust store
 * is used
 * Use no trust store, but modify pub key
 *	-> expect -EBADMSG due to signature verification failure
 */
static int pkcs7_maclious_certs5(void)
{
	uint8_t *pk;
	int ret = 0;
	__LC_DECLARE_MEM_HEAP(ws, struct workspace, sizeof(uint64_t));

	CKINT(pkcs7_maclious_gen_certs(ws, 0));
	CKINT(pkcs7_maclious_gen_msg(ws));

	/* Modify pub key */
	pk = (uint8_t *)ws->pkcs7_dec.certs->pub.key;
	pk[0] ^= 0x01;

	CKINT_LOG(lc_pkcs7_verify(&ws->pkcs7_dec, NULL, NULL),
		  "PKCS#7 verification failure: %d\n", ret);

out:
	pkcs7_malicious_clear(ws);
	__LC_RELEASE_MEM_HEAP(ws);
	return ret;
}

/*
 * Test goal: check that signature verification is in place when no trust store
 * is used
 * Use no trust store, but modify signature
 *	-> expect -EBADMSG due to signature verification failure
 */
static int pkcs7_maclious_certs4(void)
{
	uint8_t *sig;
	int ret = 0;
	__LC_DECLARE_MEM_HEAP(ws, struct workspace, sizeof(uint64_t));

	CKINT(pkcs7_maclious_gen_certs(ws, 0));
	CKINT(pkcs7_maclious_gen_msg(ws));

	/* Modify signature */
	sig = (uint8_t *)ws->pkcs7_dec.list_head_sinfo->sig.s;
	sig[0] ^= 0x01;

	CKINT_LOG(lc_pkcs7_verify(&ws->pkcs7_dec, NULL, NULL),
		  "PKCS#7 verification failure: %d\n", ret);

out:
	pkcs7_malicious_clear(ws);
	__LC_RELEASE_MEM_HEAP(ws);
	return ret;
}

/*
 * Test goal: Check that forging of CA in trust store is detected
 * Have a valid CA certificate 1 in trust store
 * Have a valid CA certificate 2 with identical SKID/AKID signing data:
 *	-> certificate allegedly signing the message is found in the trust
 *	   store but this certificate cannot verify the message.
 *	-> validation falure due to signature verification failure
 *	-> expected error: -EBADMSG
 */
static int pkcs7_maclious_certs2(void)
{
	int ret = 0;
	__LC_DECLARE_MEM_HEAP(ws, struct workspace, sizeof(uint64_t));

	CKINT(pkcs7_maclious_gen_certs(ws, 0));
	CKINT(pkcs7_maclious_gen_msg(ws));

	/*
	 * Load CA1 into trust store: This part is the key issue that causes
	 * the signature verification to fail.
	 */
	CKINT_LOG(lc_pkcs7_trust_store_add(&ws->trust_store, &ws->ca1_dec),
		  "Loading certificate CA2 into trust store\n");

	CKINT_LOG(lc_pkcs7_verify(&ws->pkcs7_dec, &ws->trust_store, NULL),
		  "PKCS#7 verification failure: %d\n", ret);

out:
	pkcs7_malicious_clear(ws);
	__LC_RELEASE_MEM_HEAP(ws);
	return ret;
}

/*
 * Same as test 0, but no trust store -> success
 */
static int pkcs7_maclious_certs1(void)
{
	int ret = 0;
	__LC_DECLARE_MEM_HEAP(ws, struct workspace, sizeof(uint64_t));

	CKINT(pkcs7_maclious_gen_certs(ws, 0));
	CKINT(pkcs7_maclious_gen_msg(ws));

	CKINT_LOG(lc_pkcs7_verify(&ws->pkcs7_dec, NULL, NULL),
		  "PKCS#7 verification failure: %d\n", ret);

out:
	pkcs7_malicious_clear(ws);
	__LC_RELEASE_MEM_HEAP(ws);
	return ret;
}

/*
 * Test goal: Successful test case
 * Have a valid CA certificate 2 in trust store
 *	-> success
 */
static int pkcs7_maclious_certs0(void)
{
	int ret = 0;
	__LC_DECLARE_MEM_HEAP(ws, struct workspace, sizeof(uint64_t));

	CKINT(pkcs7_maclious_gen_certs(ws, 0));
	CKINT(pkcs7_maclious_gen_msg(ws));

	/* Load CA2 into trust store */
	CKINT_LOG(lc_pkcs7_trust_store_add(&ws->trust_store, &ws->ca2_dec),
		  "Loading certificate CA2 into trust store\n");

	CKINT_LOG(lc_pkcs7_verify(&ws->pkcs7_dec, &ws->trust_store, NULL),
		  "PKCS#7 verification failure: %d\n", ret);

out:
	pkcs7_malicious_clear(ws);
	__LC_RELEASE_MEM_HEAP(ws);
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret = 0;

	(void)argv;
	(void)argc;

	CKINT_LOG(pkcs7_maclious_certs0(),
		  "PKCS#7 processing with trust store failed\n");
	CKINT_LOG(pkcs7_maclious_certs1(),
		  "PKCS#7 processing without trust store failed\n");

	ret = pkcs7_maclious_certs2();
	if (ret != -EBADMSG) {
		printf("Test 1: Expected failure of EBADMSG not received, received return code: %d\n",
		       ret);
		ret = -EFAULT;
		goto out;
	}

	ret = pkcs7_maclious_certs4();
	if (ret != -EBADMSG) {
		printf("Test 3: Expected failure of EBADMSG not received, received return code: %d\n",
		       ret);
		ret = -EFAULT;
		goto out;
	}

	ret = pkcs7_maclious_certs5();
	if (ret != -EBADMSG) {
		printf("Test 4: Expected failure of EBADMSG not received, received return code: %d\n",
		       ret);
		ret = -EFAULT;
		goto out;
	}

	CKINT_LOG(
		pkcs7_maclious_certs6(),
		"PKCS#7 processing modified PK but with trust store failed\n");

	ret = pkcs7_maclious_certs7();
	if (ret != -EBADMSG) {
		printf("Test 6: Expected failure of EBADMSG not received, received return code: %d\n",
		       ret);
		ret = -EFAULT;
		goto out;
	}

	ret = pkcs7_maclious_certs8();
	if (ret != -EKEYREJECTED) {
		printf("Test 6: Expected failure of EKEYREJECTED not received, received return code: %d\n",
		       ret);
		ret = -EFAULT;
		goto out;
	}

	ret = 0;

out:
	return -ret;
}
