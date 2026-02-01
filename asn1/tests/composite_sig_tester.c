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
 * The test implements the validation of the test vectors provided by
 * https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>

#include "base64.h"
#include "helper.h"
#include "lc_dilithium.h"
#include "lc_pkcs8_parser.h"
#include "lc_x509_generator.h"
#include "lc_x509_parser.h"
#include "ret_checkers.h"
#include "small_stack_support.h"

static const uint8_t m[] = "The quick brown fox jumps over the lazy dog.";
static const uint8_t ctx[] =
	"The lethargic, colorless dog sat beneath the energetic, stationary fox.";

struct comp_sig_test {
	const char *pk;
	const char *x5c;
	const char *sk;
	const char *sk_pkcs8;
	const char *s;
	const char *s_with_context;
};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"

#if (defined(LC_DILITHIUM_ED25519) && defined(LC_DILITHIUM_44_ENABLED))
static const struct comp_sig_test tests_44_ed25519 = {
	//"tcId": "id-MLDSA44-Ed25519-SHA512",
	.pk = "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"
	      "mQKojolj5EQlQIYptCzHjq0kVVout5a",
	.x5c = "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"
	       "xlegjff7ITdfD/+E72PMBdWQ8IxROkOp7m1RJgo=",
	.sk = "AdjfWRUtikTjmiXmd17xigBEsg5YwsQ0asN8J9FSF2xb6mwkVGF7+0hHnrixO"
	      "3EamBFrc/fsrDD68d2bT6F9aA==",
	.sk_pkcs8 = "MFECAQAwCgYIKwYBBQUHBicEQAHY31kVLYpE45ol5nde8YoARLIOWML"
		    "ENGrDfCfRUhdsW+psJFRhe/tIR564sTtxGpgRa3P37Kww+vHdm0+hfWg=",
	.s = "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",
	.s_with_context =
		"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"
};
#endif

#if (defined(LC_DILITHIUM_ED25519) && defined(LC_DILITHIUM_65_ENABLED))
static const struct comp_sig_test tests_65_ed25519 = {
	//"tcId": "id-MLDSA44-Ed25519-SHA512",
	.pk = "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"
	      "mQKojolj5EQlQIYptCzHjq0kVVout5a",
	.x5c = "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"
	       "xlegjff7ITdfD/+E72PMBdWQ8IxROkOp7m1RJgo=",
	.sk = "AdjfWRUtikTjmiXmd17xigBEsg5YwsQ0asN8J9FSF2xb6mwkVGF7+0hHnrixO"
	      "3EamBFrc/fsrDD68d2bT6F9aA==",
	.sk_pkcs8 = "MFECAQAwCgYIKwYBBQUHBicEQAHY31kVLYpE45ol5nde8YoARLIOWML"
		    "ENGrDfCfRUhdsW+psJFRhe/tIR564sTtxGpgRa3P37Kww+vHdm0+hfWg=",
	.s = "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",
	.s_with_context =
		"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"
};
#endif

#if (defined(LC_DILITHIUM_ED448) && defined(LC_DILITHIUM_87_ENABLED))
static const struct comp_sig_test tests_87_ed448 = {
	//"tcId": "id-MLDSA87-Ed448-SHAKE256",
	.pk = "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"
	      "FEA",
	.x5c = "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"
	       "XH4D1RMve4CAJtKbNxC6ctlOKy4A",
	.sk = "cvodaRlkcpyalK+R9rqUSD95CNbLedGQ/ls9u5sVo9fJE1xKda+msIkoZg7WZ"
	      "IASEGW1KfueHwKx/i6G3jiIndchxOl12t7AiIaMupaEgZtneMHfuPKlFgY=",
	.sk_pkcs8 =
		"MGoCAQAwCgYIKwYBBQUHBjMEWXL6HWkZZHKcmpSvkfa6lEg/eQjWy3n"
		"RkP5bPbubFaPXyRNcSnWvprCJKGYO1mSAEhBltSn7nh8Csf4uht44iJ3XIcTpddrewIi"
		"GjLqWhIGbZ3jB37jypRYG",
	.s = "6Ee2aGK+8ZebApp+wiRoszatM2NOG8hzOBAQeIi8fdIE15aP4PuO++JvWNKM0+"
	     "ZnKp5GwQHpVnj6JwcbYVGDN58UBDETPBksfYv8smTaqvMAylGgY11avw1PkcDc18EDG5"
	     "9Vb8Z7ovgab7l143As5eQ1+gPsjZqvrmBChL5Pmwypj1B72ZLXOrLTpLnwpIX+Duihah"
	     "zHAnvZ08YM0APEfWy6On1/UA/ubOsaD/TugAvfHHNsL19K6TqMet/xOYdoXf1Lm0DtrZ"
	     "NGhE2Q8SoRyCNc3jEPyQ9eCehlbxJTxMdu2PigVQndRqrMBhjfG4o400MeClliUopjz5"
	     "NcVwuhS1nScudPDUWroA0YY5IWL1m9NGYKGxlXQe/x3BOV3yjZh388DuyRN7VbC3oc25"
	     "miOS8np3Jowmci+4/8lrgIvSQIszv1K/powbRNEeN2FAIHcOd3SGW0hv99qxoxFPraJH"
	     "AepsWEIfxbEkbLR9+vRYXJ4L0LEBXrsvkRrGggKIruTZjJYoRqQUOGVSJB5zugiOb6yY"
	     "nkUlaoQEtlcA+lrQWj2WFQf9cFTxqtMQgWYxVEE0DHvYB6JCr9pcYwt8qv87DFk+T5Hd"
	     "fNU1lpkbBAlD4PZ1Zx1bojoplwhqRVirQSf6b9ELAKaK5yjDHHTRFWR+bCLnhj/l4eS4"
	     "fzMl2M3anKaxUiFzwTyj/w2p6cGZ7MV0xAsYlV6tx6ETnxnsy0Q0zFKScCdkNLv9sP4u"
	     "bZUg1BhVcm6IFSi44WETmMG6ptESDTrQzWue5SM3D1MdZvZNt5s/U833CDUP6MYn4HaV"
	     "fO4AToGOG7cwwwJflSwKR9Iw+hUaOk0VHgI8mZVu11oKkOEOQtDvaSQGakHnvDNWj7Bf"
	     "zAw6Znxaf0JwVbCiRnkemQQVODeLC0UtkY6Qi9yUD9yI3eHvItvGaXpN8sgpN65ukCHb"
	     "c7+QbfYi/9R/CwGatOrdJa1drDdWwM9rj7ej+EQ8Hpfr1D5UTRiot4H4Bw3fKbrVEf/A"
	     "ZvkxqkC5c9gzsctnIJzgyIycgNilnMPeJLDS8WPtNkE5nWykE07d4u46YCxEr2eOKzpZ"
	     "wegGRHBkVHtOCpT958ycVfuZEbdWoZKqC0DhHx5ctS/k60eZb1mwurDnSOTBbK8KAuBa"
	     "6btZeFoZnx6/5e5v4nEqEFCv4bHIz4/7N5haVHkohwQMTi92UWRJi+YBfrO+cmie/P2I"
	     "9KXsqQL3RSGLrMLEBP2utdcDoltYGg6LPveQBVcKg++WS/+95TpSFLjGlB1r3TV3P2IP"
	     "OGts7BjR2gukByBhYF2NjFoFyYaXIs5EmMMYV6EtF7mjjkbMRrGfQ6TgdhU8+LOY2cIM"
	     "25aVbKNtuDrs39pyC4RiqRTJdD8jSexGlPuGzjB5XGK13QGuDKkdN6J65hvq3d2oo6GL"
	     "yylp9WMy2Hc552BiFAigROMLsrhmRjP72HMkQWfamIP2Ru5vbM8v5Ye2BEbBjGWQMACD"
	     "DVszSevlAmPWb9z/gWseaE9fUAspkJeW8oKPUuGP/WTZEJMFfk8nWTI/ywSZ94oSMOvZ"
	     "9t6yCS0JwIx1RuZy7K8LMu2TSoio2OwYnejxPdTPdI25IppZl+NAmIUo1aqMW3R5x0Ye"
	     "lKjblEe8TTMMzzunBgMdhGnSjOr+tqlPYBTXAcjeQkJEwVVK3JqxGeB/3Qb+ZDAjARYM"
	     "EdWKVzgKjnwtzaGL6Hxoqig+2J+7BXvT44/VtA++mPybX1rZsyqwZmEDuYmXiEdYgZ+B"
	     "9hwVMQFs1Lwz3vlnztigIl+8OS/jnIHq6+VDBt4UF3lN9kWl7tXiWkUj4zKYnTmGWjGy"
	     "w5UJw187dM5Kn75k60Sgs1qjlqAbZx4i/AoHDx0es1TMXcgnMawuBgflMoInFGRF3Y1V"
	     "HU82muCvR4aMjM3Wui+0HQz1Ynt6ayScRlbj11HyMMBprf45ym96di1il5KN8X2q6t8g"
	     "ZSdeIY2ydDWNo5ayqkg6mIeToyR2BR27IPA6/nJ7bZCLm6XawWUruYXULtlMZKyB5TgO"
	     "EDrsnVFTBAoC1Q+f8SWdPp1HYbSD+pt/mEVDQRRS8078v3NnZLS73ZuuvpWDsSWhG5ED"
	     "FpCtU3DyY7EMfb8ud9JXbe+22GgraHigllc8pnSC7HqlFwbqC6bl4smhKTFvsbIloaLf"
	     "OGC/cWc1b4vjT3xqinABdBIWvbujU6jhMJBNumupFaaumSs02zW7NMYirttQgjDFikBM"
	     "zNUIsimzjRx3XxfeqH7li1GxO1gpWhhkiV/4mbZhr5Ajpag/6tiSZ4BOicPj4VMWX2f+"
	     "4b4dCmjoPDCNsutblQeop7SKIRYni1FvpT94DT07blfWfJZs8RZGnuVDCCZt3liP17CX"
	     "14S2G0i87VGBRsVE50ttYMazyF5qslqOLr9704uPE3maNVqHOs4Rh7QZULic6Y9oalen"
	     "/qkQ9+i7V42g/gQWAaIyIJ2ta4MT+AGnHdVp+zwlZ4sN3G7U4LX3SAs1n9Fo7haqFkUB"
	     "Sf/BIwKsTHTJM9bCGPYNMv79dBeH1IsfIFBLkRRirPytB95POh2a8/IwX45Ql5Yr3k6v"
	     "dgXCyNOtgRNPZ5yx2adNgWm9MSK84ATK6ij92+570hHfek/PWbgxTdCQMtylFVRYOF6N"
	     "ItTu/NX3FLYpF8Fr6TX+B4oh4/KBlIWCZZEm7J5rcKdmoGcpG4ynfxntqrpBuHgFqj5G"
	     "VHedN1yoaYh+hxyluuG/vZ/DvqTZ8LCtpvhGhTex8mTRrjT3G9aIlLfUUz+rmbv9KIjk"
	     "HfhTMBNwISZ9YjiC4A29QqLqqT6k3k/i2I3ts7wjxnfcAtJb3s3q6eERLBUJi9g392ra"
	     "NJRe4Phrt9S3UiJmvCTas/A+LEtSSiX5d7W2iqWnKYZlViNljdNtkqm1QkUjqIwP45ul"
	     "TUkm9q2AJBj1U7Ha6zvm4lyQ+VzjE9kebqPNrVvu66dMMGMzuiiSexw7gsFuRWhhE6Zy"
	     "zwnZhoVcDAzH6rnDHi41GILY4AERRw7Stn7iIR5l4SJxz7EquBnc1mKrJiqgq3AqJpgy"
	     "w+eXJPFu5Yuprxoo3KpJ3VFHQP7XBx9CSJM9klIZjNkjn3c+0hkz1MzncAiDpwIed6jY"
	     "2DKasaMlVIyKVWj+PdOKtUAEhA3TLZ3lahtCB6+vTQuopJFz4fE1UrV6bKtD1L3Wkasc"
	     "ZVSwlx6Wgf6CQbGevDGqLIhH/2rcmAJJtVQPFXZBBYd5GvIw4TVXsbQLGSG2/HsgYBfZ"
	     "+npPNnl69BBI9XZ+VcGy5ddJMEcg75t6YgGxn5ykkw+m1TiNhVBJMK6t9ZxJ0kzu+a5F"
	     "Swo71O32WP6kVakBwIuECG/Onn0rAFqxbu4e3HJMdOPMj4AwCFfxdTkxjZqpUbVVyE5w"
	     "+r7MZ4ixSDP6fJlC5RCf+5mLxtnRAfrzV4I0kWdLqL7LemNV6K3ZsfIT10nOVgFZlCSD"
	     "2h9ZUHJS78Hs9csIT/3cQ4T7vfjDX6yAH1YGpmhnYajaIH1kC1PGO2+0+xfBC1KeWqEc"
	     "y0Amaouh+S6KmsRd8tYPKNUvW39p4PT/YtpxIb8jpv9adQqS5HXn5TrpjCnIDWCqnykl"
	     "DdF48miS/EtJlvFX7UcLpFZnhj4fxLKnhL4vFZb7pCkzS12Tk6RH4/BbL+8La/prBQ+3"
	     "ZIFhiPwBgnHCWWfGx+nMQgoI4nDs3HKpdokGJOlP5gcyPnGvWCpI2wxBs7SRtexk5Qbv"
	     "WqYmmNDKbbuhJw0q/QM/GN46UvupUHLX8s1jj2jb5zfLiApDmBvDq1lBQ9KaSUQbxYqY"
	     "gut90bhDYI7Pbhq6TC8Ykb6PxdWkiY0ybc8AiuMDXRRQfhwpMN3Dv9R9ubxHUfQxiAkL"
	     "PpVP2QKG4j2iDpJvx7kHXgbP9lyPR8OI3BHiyUxFZSgY1bwduco/1RuJwmHypgRM1NHC"
	     "mOE02oIbihGOOsR+b2WCbizdfl8onLRFA5NvjEeMFTyG6yaB/4/yZpunNFwi/2+cnYYo"
	     "HA6PYhx7Itk1cryWoD3+P+prjtK9lywXp5bPQmutGlJBNRklHEmMTYWFH4tXWDHdbp06"
	     "yCgal61Hlql51dZNggos2Ai+frWOvepeywv/4sV3jmPqWUEYjGGBCxDMl+tShuolrQVA"
	     "7/Dmf0soelOeANPla/7JWaWuHZf4qxPY/gWOdv4stOl5MNPLHh27Hx8ACpTa0gcL1odD"
	     "HIM1oCd1M2LE1SFCocSiZ7a5lvmkVV6qQAbsN/IqpHCGmwWcIqZlS1js5HYLJhue86UG"
	     "3eAnrptjymLHV+JJxR7hye9O5trigs+eb+sRGp2BHUJmMwIxt0ZyzcqoHB55XTfwwU/2"
	     "3ueeTQv59vjWVLirEDzMyy1/NAFd0DnEdGSgno3SkgbW9osHz1sQJGYOGLOwEwMstbPR"
	     "+4EdJkkZuEFAfGU9KipYAbRwWkCx/bs3TWa+3oG/JBv+DorWNCnYdJDJrfaUjbxi4Lve"
	     "DffsHS3vebZZVxOZR+PASWZqoF1+iTNu4/V3gixub2Loit1ccx9SE7eKMcnAau1QcvJZ"
	     "ce2eJek+Y7hXHEdJQoWs1U/K37pmudjHgFowTB8yXbLfg/DWCWaVwOz9Ax222KSVtJen"
	     "21HXi3U5w4ZRgjRJXvcRgicxl6XyJwHMssMv7oPjzwoieJab9DaCNbqF656Yx2R7NWEp"
	     "qnpXA88dZOqSqJYS/beof3iJ8k2UN8CFWpo/nHFZazW3tonXI/4UXTD9f4upVUPT3kJo"
	     "HmCxf24iHASZAeUC7SMFKhCsuevyMMWMPW/s92nmHIqbwuF1SDlAPWXLOZuYaj5kXe8/"
	     "dti08pZ132xgYHx+uPnhtMTSQGONZJVT1VwEj/n2aAHXW08RH1fxpxrsVLs6a0WnO3mC"
	     "j4Oitxk6P9KYWuG/KrRhgzuCsDo1TN08+F6nawrnfp7zL+pounolai6kdyFsEzFjC3+y"
	     "zkVnXTc+1VQu9ZtzO0GdiZWiG9lN5lZti0cwInO1gLyrO2fdfG4YJ3UG8Gmt999J9r5R"
	     "6S0Y8OHYr5IZvW2GVDVQiL9XwAF5v2xiHJLEFf4ZwpE+cOe47XgXKs+dFIzQrF1g5QHb"
	     "PbqGDBDYlysQFcJtyylSg6YLxNoOCAvzyO7njPShzMfaiJnNn04f2M/W7lMgDSOeqfbp"
	     "9gTK0ZWQnEBAvEzkh9NVzIXlRfXJcbNLVNIp1DaH/MeV201DeHBPXZXFi2evdzjrulUY"
	     "InoOGL1AaNCubJvfAqe7hALbud+j5PM4a+n1buqFYXjdT8tJ9sD3nadLEyQo8uKd0Q2/"
	     "LBWUKXGep6JHk1ezRvP40BTqmOW6ROQGhsAxxITpZoBSSyy0n/ayHmcJQgKQTZnE/AxG"
	     "vQebnud7kitblOF84BO0AzRWBXiiKoXV98bENw7Tkb83KSpbAafkIHlJloqfNzs77BT4"
	     "legnUu6h7Odkcp7Rgb5rX/cF7L91QMK2A8ksUA6tSnDrb2+YVg9pYSOKZvMLnrUiCoNe"
	     "oa3igbvkiHk184EJTLdReCIKhksyFIjUsltBpVxCdSgAV29fFRboogOiL77geJRtGEbQ"
	     "VrMxHYm3vw/emnrofSbKM9JiblCJvfU6SsFnMPd4N+UL7DseDFcLIz8BmYIsG5xFXRXe"
	     "cBzhYfFhOSSlG20YASf3rlnOW2tL6SsirVZU/VzAavuldmU94y1fmUC5+iyyD6ryOzbp"
	     "DyiY6HUaKBRMYw4pxQZl2cHlfPYnG0NvoyMc4ebY3zxjGEQ5WHy6+mcr5vIDesHFirzU"
	     "reF0jybn+8s2Dap4MgEYay5cXtm/HFHjwgwVlbeZXpbV6tYy1UJ8BEnTR2f0vXNXPHf/"
	     "EjVJId8t/xP2obXEecVE9Kp0gBKE9An8LdjCAUn02EE4tpczoJ9JvADqpLEwWiMuhpcQ"
	     "CXvMofKfX3+UyTFZLXN5AiTrSxgkGtZnoSnLEbZg+qW1QucCvJrtWOxx1cB2PlFqQ0CP"
	     "PSkGmiCtC/Dfl4fkz8V6WS/mEDF2gLfJWUtJn9XopgUSqL6wxKaivdq6D2vRPdji7ysU"
	     "wK0EVAflw37RYgXmRpjNnb3/sBBC4wxfMXITo/VID6DhscnaC66us/iJq+5PYcJyua0u"
	     "YvQUVLXXqSm+hWgcTr/gAAAAAAAAAAAAAAAAAAAAAAAAAJDxYeJCozOOMh6OwJzT8/MX"
	     "wOYgEeYUu5IbdhO9LwlgBBz7E2iCtqY0r+7meA3QWLaw7L05IewbsQuP84dCKpgJrRMI"
	     "qutPbBcr09GyJ8iZvF3/M+fsbaQtFpLtWzZ0mYxJAerEQlGn/Pb/4AuTHN5IoUQ4a3tw"
	     "IBAA==",
	.s_with_context =
		"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"
		"9tnaePB3gS+w+AA=="
};
#endif

#pragma GCC diagnostic pop

static int comp_sig_25519_test_one(const struct comp_sig_test *test)
{
	struct workspace {
		uint8_t pk[sizeof(struct lc_dilithium_ed25519_pk)];
		uint8_t sk[sizeof(struct lc_dilithium_ed25519_sk)];
		uint8_t sk_pkcs8[sizeof(struct lc_dilithium_ed25519_sk) + 30];
		uint8_t sig[sizeof(struct lc_dilithium_ed25519_sig)];
		uint8_t x5c[sizeof(struct lc_dilithium_ed25519_pk) +
			    sizeof(struct lc_dilithium_ed25519_sig) + 1000];

		struct lc_dilithium_ed25519_pk lc_pk;
		struct lc_dilithium_ed25519_sk lc_sk;
		struct lc_dilithium_ed25519_sig lc_sig;
		struct lc_x509_certificate lc_cert;
		struct lc_pkcs8_message lc_pkcs8;
		struct lc_x509_key_data lc_pkcs8_keys;

		struct lc_dilithium_pk lc_mldsa_pk;
		struct lc_dilithium_sk lc_mldsa_sk;
	};
	size_t olen, ilen, siglen;
	int ret = 0;
	uint8_t blank_chars;
	LC_DILITHIUM_ED25519_CTX_ON_STACK(sign_ctx);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	/* Parse PK */
	ilen = strlen(test->pk);
	/* Parse PK: get length of Base64 decoding output */
	CKINT(lc_base64_decode_len(test->pk, ilen, &olen, &blank_chars,
				   lc_base64_flag_unknown));
	/* Parse PK: is our buffer large enough? */
	if (olen > sizeof(ws->pk)) {
		printf("PK length overflow - found length %zu, avilable space %zu\n",
		       olen, sizeof(ws->pk));
		ret = -EOVERFLOW;
		goto out;
	}
	/* Parse PK: Base64-decode */
	CKINT(lc_base64_decode(test->pk, ilen, ws->pk, sizeof(ws->pk),
			       lc_base64_flag_unknown));
	/* Parse PK: Load PK into internal representation */
	CKINT(lc_dilithium_ed25519_pk_load(
		&ws->lc_pk, ws->pk, olen - LC_ED25519_PUBLICKEYBYTES,
		ws->pk + olen - LC_ED25519_PUBLICKEYBYTES,
		LC_ED25519_PUBLICKEYBYTES));

	/* Parse sig: Same approach as PK */
	ilen = strlen(test->s);
	CKINT(lc_base64_decode_len(test->s, ilen, &siglen, &blank_chars,
				   lc_base64_flag_unknown));
	if (siglen > sizeof(ws->sig)) {
		printf("SK length overflow - found length %zu, avilable space %zu\n",
		       siglen, sizeof(ws->sig));
		ret = -EOVERFLOW;
		goto out;
	}
	CKINT(lc_base64_decode(test->s, ilen, ws->sig, sizeof(ws->sig),
			       lc_base64_flag_unknown));
	CKINT(lc_dilithium_ed25519_sig_load(
		&ws->lc_sig, ws->sig, siglen - LC_ED25519_SIGBYTES,
		ws->sig + siglen - LC_ED25519_SIGBYTES, LC_ED25519_SIGBYTES));

	/* Parse PKCS#8 with context: Same approach as PK */
	ilen = strlen(test->sk_pkcs8);
	CKINT(lc_base64_decode_len(test->sk_pkcs8, ilen, &olen, &blank_chars,
				   lc_base64_flag_unknown));
	if (olen > sizeof(ws->sk_pkcs8)) {
		printf("SK length overflow - found length %zu, avilable space %zu\n",
		       olen, sizeof(ws->sig));
		ret = -EOVERFLOW;
		goto out;
	}
	CKINT(lc_base64_decode(test->sk_pkcs8, ilen, ws->sk_pkcs8,
			       sizeof(ws->sk_pkcs8), lc_base64_flag_unknown));
	ws->lc_pkcs8_keys.sk.dilithium_ed25519_sk = &ws->lc_sk;
	CKINT(lc_pkcs8_set_privkey(&ws->lc_pkcs8, &ws->lc_pkcs8_keys));
	CKINT_LOG(lc_pkcs8_decode(&ws->lc_pkcs8, ws->sk_pkcs8, olen),
		  "Loading of PKCS#8 private key failed\n");

	/* Parse certificate with context: Same approach as PK */
	ilen = strlen(test->x5c);
	CKINT(lc_base64_decode_len(test->x5c, ilen, &olen, &blank_chars,
				   lc_base64_flag_unknown));
	if (olen > sizeof(ws->x5c)) {
		printf("SK length overflow - found length %zu, avilable space %zu\n",
		       olen, sizeof(ws->sig));
		ret = -EOVERFLOW;
		goto out;
	}
	CKINT(lc_base64_decode(test->x5c, ilen, ws->x5c, sizeof(ws->x5c),
			       lc_base64_flag_unknown));
	CKINT_LOG(lc_x509_cert_decode(&ws->lc_cert, ws->x5c, olen),
		  "Loading of X.509 certificate failed\n");

	/**********************************************************************
	 * Test 1: perform signature verification with PK and signature input.
	 **********************************************************************/

	/* Perform init / update / final test */
	CKINT(lc_dilithium_ed25519_verify_init(sign_ctx, &ws->lc_pk));
	CKINT(lc_dilithium_ed25519_verify_update(sign_ctx, m, sizeof(m) - 1));
	CKINT(lc_dilithium_ed25519_verify_final(&ws->lc_sig, sign_ctx,
						&ws->lc_pk));

	/* Perform one-shot test */
	CKINT(lc_dilithium_ed25519_verify(&ws->lc_sig, m, sizeof(m) - 1,
					  &ws->lc_pk));

	/**********************************************************************/

	/**********************************************************************
	 * Test 2: perform signature verification with PKCS#8, signature.
	 **********************************************************************/
	CKINT_LOG(lc_x509_signature_verify(ws->sig, siglen, &ws->lc_cert, m,
					   sizeof(m) - 1, NULL),
		  "Verification of data failed\n");

	/**********************************************************************/

	/**********************************************************************
	 * Test 3: perform signature generation and verification with PKCS#8,
	 * certificate.
	 **********************************************************************/
	CKINT_LOG(lc_x509_signature_gen(ws->sig, &siglen, &ws->lc_pkcs8_keys, m,
					sizeof(m) - 1, NULL),
		  "Signature generation failed\n");
	CKINT_LOG(lc_x509_signature_verify(ws->sig, siglen, &ws->lc_cert, m,
					   sizeof(m) - 1, NULL),
		  "Verification of data failed\n");

	/**********************************************************************/

	/* Parse SK: same as PK - deviations are noted below */
	ilen = strlen(test->sk);
	CKINT(lc_base64_decode_len(test->sk, ilen, &olen, &blank_chars,
				   lc_base64_flag_unknown));
	if (olen > sizeof(ws->sk)) {
		printf("SK length overflow - found length %zu, avilable space %zu\n",
		       olen, sizeof(ws->sk));
		ret = -EOVERFLOW;
		goto out;
	}
	CKINT(lc_base64_decode(test->sk, ilen, ws->sk, sizeof(ws->sk),
			       lc_base64_flag_unknown));
	/* Parse SK: check if we got a seed instead of a full SK */
	if (olen == LC_ED25519_RAW_SECRETKEYBYTES + LC_X509_PQC_SK_SEED_SIZE) {
		uint8_t *dilithium_src_key;
		size_t dilithium_src_key_len;
		enum lc_dilithium_type dilithium_type;

		/* Fetch the ML-DSA type from the already parsed PK */
		dilithium_type = lc_dilithium_ed25519_pk_type(&ws->lc_pk);
		/* Derive the key */
		CKINT(lc_dilithium_keypair_from_seed(
			&ws->lc_mldsa_pk, &ws->lc_mldsa_sk, ws->sk,
			LC_X509_PQC_SK_SEED_SIZE, dilithium_type));

		/* Get the ML-DSA SK pointer */
		CKINT(lc_dilithium_sk_ptr(&dilithium_src_key,
					  &dilithium_src_key_len,
					  &ws->lc_mldsa_sk));

		/*
		 * Load the newly established ML-DSA SK with the decoded ED25519
		 * SK into internal representation.
		 */
		CKINT_LOG(
			lc_dilithium_ed25519_sk_load(
				&ws->lc_sk, dilithium_src_key,
				dilithium_src_key_len,
				ws->sk + olen - LC_ED25519_RAW_SECRETKEYBYTES,
				LC_ED25519_RAW_SECRETKEYBYTES),
			"Cannot load ML-DSA-ED25519 secret key of length %zu\n",
			olen);
	} else {
		CKINT_LOG(
			lc_dilithium_ed25519_sk_load(
				&ws->lc_sk, ws->sk,
				olen - LC_ED25519_RAW_SECRETKEYBYTES,
				ws->sk + olen - LC_ED25519_RAW_SECRETKEYBYTES,
				LC_ED25519_RAW_SECRETKEYBYTES),
			"Cannot load ML-DSA-ED25519 secret key of length %zu\n",
			olen);
	}

	/**********************************************************************
	 * Test 4: perform signature generation and verification with SK and PK
	 * input.
	 **********************************************************************/

	/* Perform one-shot test with parsed SK */
	CKINT(lc_dilithium_ed25519_sign(&ws->lc_sig, m, sizeof(m) - 1,
					&ws->lc_sk, lc_seeded_rng));
	CKINT(lc_dilithium_ed25519_verify(&ws->lc_sig, m, sizeof(m) - 1,
					  &ws->lc_pk));

	/**********************************************************************/

	/* Parse sig with context: Same approach as PK */
	ilen = strlen(test->s_with_context);
	CKINT(lc_base64_decode_len(test->s_with_context, ilen, &olen,
				   &blank_chars, lc_base64_flag_unknown));
	if (olen > sizeof(ws->sig)) {
		printf("SK length overflow - found length %zu, avilable space %zu\n",
		       olen, sizeof(ws->sig));
		ret = -EOVERFLOW;
		goto out;
	}
	CKINT(lc_base64_decode(test->s_with_context, ilen, ws->sig,
			       sizeof(ws->sig), lc_base64_flag_unknown));
	CKINT(lc_dilithium_ed25519_sig_load(
		&ws->lc_sig, ws->sig, olen - LC_ED25519_SIGBYTES,
		ws->sig + olen - LC_ED25519_SIGBYTES, LC_ED25519_SIGBYTES));

	/**********************************************************************
	 * Test 5: perform signature verification with PK, signature and context
	 * input.
	 **********************************************************************/

	LC_DILITHIUM_ED25519_SET_CTX(sign_ctx);
	lc_dilithium_ed25519_ctx_userctx(sign_ctx, ctx, sizeof(ctx) - 1);
	/* Perform init / update / final test */
	CKINT(lc_dilithium_ed25519_verify_ctx(&ws->lc_sig, sign_ctx, m,
					      sizeof(m) - 1, &ws->lc_pk));

	/**********************************************************************/

	/**********************************************************************
	 * Test 6: perform signature generation and verification with SK, PK,
	 * and context input.
	 **********************************************************************/

	LC_DILITHIUM_ED25519_SET_CTX(sign_ctx);
	lc_dilithium_ed25519_ctx_userctx(sign_ctx, ctx, sizeof(ctx) - 1);
	/* Perform one-shot test with parsed SK */
	CKINT(lc_dilithium_ed25519_sign_ctx(&ws->lc_sig, sign_ctx, m,
					    sizeof(m) - 1, &ws->lc_sk,
					    lc_seeded_rng));
	CKINT(lc_dilithium_ed25519_verify_ctx(&ws->lc_sig, sign_ctx, m,
					      sizeof(m) - 1, &ws->lc_pk));

	/**********************************************************************/

out:
	lc_x509_cert_clear(&ws->lc_cert);
	lc_pkcs8_message_clear(&ws->lc_pkcs8);
	LC_RELEASE_MEM(ws);
	return ret;
}

static int comp_sig_448_test_one(const struct comp_sig_test *test)
{
	struct workspace {
		uint8_t pk[sizeof(struct lc_dilithium_ed448_pk)];
		uint8_t sk[sizeof(struct lc_dilithium_ed448_sk)];
		uint8_t sk_pkcs8[sizeof(struct lc_dilithium_ed448_sk) + 30];
		uint8_t sig[sizeof(struct lc_dilithium_ed448_sig)];
		uint8_t x5c[sizeof(struct lc_dilithium_ed448_pk) +
			    sizeof(struct lc_dilithium_ed448_sig) + 1000];

		struct lc_dilithium_ed448_pk lc_pk;
		struct lc_dilithium_ed448_sk lc_sk;
		struct lc_dilithium_ed448_sig lc_sig;
		struct lc_x509_certificate lc_cert;
		struct lc_pkcs8_message lc_pkcs8;
		struct lc_x509_key_data lc_pkcs8_keys;

		struct lc_dilithium_pk lc_mldsa_pk;
		struct lc_dilithium_sk lc_mldsa_sk;
	};
	size_t olen, ilen, siglen;
	int ret = 0;
	uint8_t blank_chars;
	LC_DILITHIUM_ED448_CTX_ON_STACK(sign_ctx);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	/* Parse PK */
	ilen = strlen(test->pk);
	/* Parse PK: get length of Base64 decoding output */
	CKINT(lc_base64_decode_len(test->pk, ilen, &olen, &blank_chars,
				   lc_base64_flag_unknown));
	/* Parse PK: is our buffer large enough? */
	if (olen > sizeof(ws->pk)) {
		printf("PK length overflow - found length %zu, avilable space %zu\n",
		       olen, sizeof(ws->pk));
		ret = -EOVERFLOW;
		goto out;
	}
	/* Parse PK: Base64-decode */
	CKINT(lc_base64_decode(test->pk, ilen, ws->pk, sizeof(ws->pk),
			       lc_base64_flag_unknown));
	/* Parse PK: Load PK into internal representation */
	CKINT(lc_dilithium_ed448_pk_load(
		&ws->lc_pk, ws->pk, olen - LC_ED448_PUBLICKEYBYTES,
		ws->pk + olen - LC_ED448_PUBLICKEYBYTES,
		LC_ED448_PUBLICKEYBYTES));

	/* Parse sig: Same approach as PK */
	ilen = strlen(test->s);
	CKINT(lc_base64_decode_len(test->s, ilen, &siglen, &blank_chars,
				   lc_base64_flag_unknown));
	if (siglen > sizeof(ws->sig)) {
		printf("SK length overflow - found length %zu, avilable space %zu\n",
		       siglen, sizeof(ws->sig));
		ret = -EOVERFLOW;
		goto out;
	}
	CKINT(lc_base64_decode(test->s, ilen, ws->sig, sizeof(ws->sig),
			       lc_base64_flag_unknown));
	CKINT(lc_dilithium_ed448_sig_load(
		&ws->lc_sig, ws->sig, siglen - LC_ED448_SIGBYTES,
		ws->sig + siglen - LC_ED448_SIGBYTES, LC_ED448_SIGBYTES));

	/* Parse PKCS#8 with context: Same approach as PK */
	ilen = strlen(test->sk_pkcs8);
	CKINT(lc_base64_decode_len(test->sk_pkcs8, ilen, &olen, &blank_chars,
				   lc_base64_flag_unknown));
	if (olen > sizeof(ws->sk_pkcs8)) {
		printf("SK length overflow - found length %zu, avilable space %zu\n",
		       olen, sizeof(ws->sig));
		ret = -EOVERFLOW;
		goto out;
	}
	CKINT(lc_base64_decode(test->sk_pkcs8, ilen, ws->sk_pkcs8,
			       sizeof(ws->sk_pkcs8), lc_base64_flag_unknown));
	ws->lc_pkcs8_keys.sk.dilithium_ed448_sk = &ws->lc_sk;
	CKINT(lc_pkcs8_set_privkey(&ws->lc_pkcs8, &ws->lc_pkcs8_keys));
	CKINT_LOG(lc_pkcs8_decode(&ws->lc_pkcs8, ws->sk_pkcs8, olen),
		  "Loading of PKCS#8 private key failed\n");

	/* Parse certificate with context: Same approach as PK */
	ilen = strlen(test->x5c);
	CKINT(lc_base64_decode_len(test->x5c, ilen, &olen, &blank_chars,
				   lc_base64_flag_unknown));
	if (olen > sizeof(ws->x5c)) {
		printf("SK length overflow - found length %zu, avilable space %zu\n",
		       olen, sizeof(ws->sig));
		ret = -EOVERFLOW;
		goto out;
	}
	CKINT(lc_base64_decode(test->x5c, ilen, ws->x5c, sizeof(ws->x5c),
			       lc_base64_flag_unknown));
	CKINT_LOG(lc_x509_cert_decode(&ws->lc_cert, ws->x5c, olen),
		  "Loading of X.509 certificate failed\n");

	/**********************************************************************
	 * Test 1: perform signature verification with PK and signature input.
	 **********************************************************************/

	/* Perform init / update / final test */
	CKINT(lc_dilithium_ed448_verify_init(sign_ctx, &ws->lc_pk));
	CKINT(lc_dilithium_ed448_verify_update(sign_ctx, m, sizeof(m) - 1));
	CKINT(lc_dilithium_ed448_verify_final(&ws->lc_sig, sign_ctx,
					      &ws->lc_pk));

	/* Perform one-shot test */
	CKINT(lc_dilithium_ed448_verify(&ws->lc_sig, m, sizeof(m) - 1,
					&ws->lc_pk));

	/**********************************************************************/

	/**********************************************************************
	 * Test 2: perform signature verification with PKCS#8, signature.
	 **********************************************************************/
	CKINT_LOG(lc_x509_signature_verify(ws->sig, siglen, &ws->lc_cert, m,
					   sizeof(m) - 1, NULL),
		  "Verification of data failed\n");

	/**********************************************************************/

	/**********************************************************************
	 * Test 3: perform signature generation and verification with PKCS#8,
	 * certificate.
	 **********************************************************************/
	CKINT_LOG(lc_x509_signature_gen(ws->sig, &siglen, &ws->lc_pkcs8_keys, m,
					sizeof(m) - 1, NULL),
		  "Signature generation failed\n");
	CKINT_LOG(lc_x509_signature_verify(ws->sig, siglen, &ws->lc_cert, m,
					   sizeof(m) - 1, NULL),
		  "Verification of data failed\n");

	/**********************************************************************/

	/* Parse SK: same as PK - deviations are noted below */
	ilen = strlen(test->sk);
	CKINT(lc_base64_decode_len(test->sk, ilen, &olen, &blank_chars,
				   lc_base64_flag_unknown));
	if (olen > sizeof(ws->sk)) {
		printf("SK length overflow - found length %zu, avilable space %zu\n",
		       olen, sizeof(ws->sk));
		ret = -EOVERFLOW;
		goto out;
	}
	CKINT(lc_base64_decode(test->sk, ilen, ws->sk, sizeof(ws->sk),
			       lc_base64_flag_unknown));
	/* Parse SK: check if we got a seed instead of a full SK */
	if (olen == LC_ED448_SECRETKEYBYTES + LC_X509_PQC_SK_SEED_SIZE) {
		uint8_t *dilithium_src_key;
		size_t dilithium_src_key_len;
		enum lc_dilithium_type dilithium_type;

		/* Fetch the ML-DSA type from the already parsed PK */
		dilithium_type = lc_dilithium_ed448_pk_type(&ws->lc_pk);
		/* Derive the key */
		CKINT(lc_dilithium_keypair_from_seed(
			&ws->lc_mldsa_pk, &ws->lc_mldsa_sk, ws->sk,
			LC_X509_PQC_SK_SEED_SIZE, dilithium_type));

		/* Get the ML-DSA SK pointer */
		CKINT(lc_dilithium_sk_ptr(&dilithium_src_key,
					  &dilithium_src_key_len,
					  &ws->lc_mldsa_sk));

		/*
		 * Load the newly established ML-DSA SK with the decoded ED448
		 * SK into internal representation.
		 */
		CKINT_LOG(lc_dilithium_ed448_sk_load(
				  &ws->lc_sk, dilithium_src_key,
				  dilithium_src_key_len,
				  ws->sk + olen - LC_ED448_SECRETKEYBYTES,
				  LC_ED448_SECRETKEYBYTES),
			  "Cannot load ML-DSA-ED448 secret key of length %zu\n",
			  olen);
	} else {
		CKINT_LOG(lc_dilithium_ed448_sk_load(
				  &ws->lc_sk, ws->sk,
				  olen - LC_ED448_SECRETKEYBYTES,
				  ws->sk + olen - LC_ED448_SECRETKEYBYTES,
				  LC_ED448_SECRETKEYBYTES),
			  "Cannot load ML-DSA-ED448 secret key of length %zu\n",
			  olen);
	}

	/**********************************************************************
	 * Test 4: perform signature generation and verification with SK and PK
	 * input.
	 **********************************************************************/

	/* Perform one-shot test with parsed SK */
	CKINT(lc_dilithium_ed448_sign(&ws->lc_sig, m, sizeof(m) - 1, &ws->lc_sk,
				      lc_seeded_rng));
	CKINT(lc_dilithium_ed448_verify(&ws->lc_sig, m, sizeof(m) - 1,
					&ws->lc_pk));

	/**********************************************************************/

	/* Parse sig with context: Same approach as PK */
	ilen = strlen(test->s_with_context);
	CKINT(lc_base64_decode_len(test->s_with_context, ilen, &olen,
				   &blank_chars, lc_base64_flag_unknown));
	if (olen > sizeof(ws->sig)) {
		printf("SK length overflow - found length %zu, avilable space %zu\n",
		       olen, sizeof(ws->sig));
		ret = -EOVERFLOW;
		goto out;
	}
	CKINT(lc_base64_decode(test->s_with_context, ilen, ws->sig,
			       sizeof(ws->sig), lc_base64_flag_unknown));
	CKINT(lc_dilithium_ed448_sig_load(
		&ws->lc_sig, ws->sig, olen - LC_ED448_SIGBYTES,
		ws->sig + olen - LC_ED448_SIGBYTES, LC_ED448_SIGBYTES));

	/**********************************************************************
	 * Test 5: perform signature verification with PK, signature and context
	 * input.
	 **********************************************************************/

	LC_DILITHIUM_ED448_SET_CTX(sign_ctx);
	lc_dilithium_ed448_ctx_userctx(sign_ctx, ctx, sizeof(ctx) - 1);
	/* Perform init / update / final test */
	CKINT(lc_dilithium_ed448_verify_ctx(&ws->lc_sig, sign_ctx, m,
					    sizeof(m) - 1, &ws->lc_pk));

	/**********************************************************************/

	/**********************************************************************
	 * Test 6: perform signature generation and verification with SK, PK,
	 * and context input.
	 **********************************************************************/

	LC_DILITHIUM_ED448_SET_CTX(sign_ctx);
	lc_dilithium_ed448_ctx_userctx(sign_ctx, ctx, sizeof(ctx) - 1);
	/* Perform one-shot test with parsed SK */
	CKINT(lc_dilithium_ed448_sign_ctx(&ws->lc_sig, sign_ctx, m,
					  sizeof(m) - 1, &ws->lc_sk,
					  lc_seeded_rng));
	CKINT(lc_dilithium_ed448_verify_ctx(&ws->lc_sig, sign_ctx, m,
					    sizeof(m) - 1, &ws->lc_pk));

	/**********************************************************************/

out:
	lc_x509_cert_clear(&ws->lc_cert);
	lc_pkcs8_message_clear(&ws->lc_pkcs8);
	LC_RELEASE_MEM(ws);
	return ret;
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

#if (defined(LC_DILITHIUM_ED25519) && defined(LC_DILITHIUM_44_ENABLED))
	CKINT(comp_sig_25519_test_one(&tests_44_ed25519));
#endif
#if (defined(LC_DILITHIUM_ED25519) && defined(LC_DILITHIUM_65_ENABLED))
	CKINT(comp_sig_25519_test_one(&tests_65_ed25519));
#endif
#if (defined(LC_DILITHIUM_ED448) && defined(LC_DILITHIUM_87_ENABLED))
	CKINT(comp_sig_448_test_one(&tests_87_ed448));
#endif

out:
	return -ret;
}
