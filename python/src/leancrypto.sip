// Define the SIP wrapper to the leancrypto library.

%Module(name=leancrypto, language="C")

%ModuleCode
#include <leancrypto.h>
%End

void lc_status(char *outbuf, size_t outlen);

/******************************************************************************
 * ML-KEM / Kyber
 ******************************************************************************/

enum lc_kyber_type {
	LC_KYBER_UNKNOWN, /** Unknown key type */
	LC_KYBER_1024, /** Kyber 1024 */
	LC_KYBER_768, /** Kyber 768 */
	LC_KYBER_512, /** Kyber 512 */
};

struct lc_kyber_pk {
%TypeHeaderCode
#include <leancrypto.h>
%End
};

struct lc_kyber_sk {
%TypeHeaderCode
#include <leancrypto.h>
%End
};

int lc_kyber_keypair(struct lc_kyber_pk *pk, struct lc_kyber_sk *sk,
		      lc_kyber_type kyber_type);
%MethodCode
	sipRes = lc_kyber_keypair(a0, a1, lc_seeded_rng, a2);
%End
// int lc_kyber_enc(struct lc_kyber_ct *ct, struct lc_kyber_ss *ss,
// 		 const struct lc_kyber_pk *pk);
// int lc_kyber_dec(struct lc_kyber_ss *ss, const struct lc_kyber_ct *ct,
// 		 const struct lc_kyber_sk *sk);
