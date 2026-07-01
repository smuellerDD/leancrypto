/*
 * Copyright (C) 2025 - 2026, Stephan Mueller <smueller@chronox.de>
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

use leancrypto_sys::lcr_dilithium::lcr_dilithium;
use wycheproof::{
    mldsa_sign::{TestName, TestSet},
    TestResult,
};

fn wycheproof_dilithium_sign_noseed(test_name: TestName) {
    let test_set = TestSet::load(test_name).unwrap();
    for test_group in &test_set.test_groups {
        let mut dilithium = lcr_dilithium::new();

        let privkey = &test_group.privkey;
        if let Some(privkey) = privkey {
            let result = dilithium.sk_load(&privkey);
            if result.is_err() {
                /* The test vector may give us strange keys which we reject */
                continue;
            }
        }

        let pubkey = &test_group.pubkey;
        if let Some(pubkey) = pubkey {
            let result = dilithium.pk_load(&pubkey);
            if result.is_err() {
                /* The test vector may give us strange keys which we reject */
                continue;
            }
        }

        for test in &test_group.tests {
            let rnd = &test.rnd;
            if let Some(rnd) = rnd {
                if rnd.len() > 0 {
                    /*
                     * We do not test the vectors with rnd as the Rust API
                     * does not offer test interfaces. The "randomized"
                     * siggen tests are covered with ACVP.
                     */
                    continue;
                }
            }

            println!("Test case {}: {}", test.tc_id, test.comment);

            let ctx = &test.ctx;
            if let Some(ctx) = ctx {
                if ctx.len() > 0 {
                    let result = dilithium.ctx_userctx(&ctx.to_vec());
                    assert_eq!(result, Ok(()));
                }
            }

            let mu = &test.mu;
            if let Some(mu) = mu {
                if mu.len() > 0 {
                    let result = dilithium.ctx_external_mu(&mu.to_vec());
                    assert_eq!(result, Ok(()));
                }
            }

            let msg = &test.msg;
            let mut result;
            if let Some(msg) = msg {
                result = dilithium.sign_deterministic(&msg);
                if !result.is_err() {
                    result = dilithium.verify(&msg);
                }
            } else {
                println!(
                    "Test case {} without message: {}",
                    test.tc_id, test.comment
                );
                /*
                 * TODO See
                 * https://github.com/bleichenbacher-daniel/Rooterberg/issues/7
                 */
                continue;
            }

            match &test.result {
                TestResult::Invalid => {
                    if !result.is_err() {
                        let sig_slice = match dilithium.get_sig() {
                            Ok(ret) => ret,
                            Err(_) => &[],
                        };

                        /*
                         * TODO: Allegedly S1 and S2 are malformed. The parsing
                         * of it by leancrypto ensures it is in the right bounds
                         * but then basically changes the malformed s1 and s2
                         * into correct representations. The signature is
                         * naturally different than the one in the test.
                         */
                        assert_ne!(test.sig[..], sig_slice[..]);
                    }
                }
                TestResult::Valid | TestResult::Acceptable => {
                    assert_eq!(result, Ok(()));
                    let sig_slice = match dilithium.get_sig() {
                        Ok(ret) => ret,
                        Err(_) => &[],
                    };
                    assert_eq!(test.sig[..], sig_slice[..]);
                }
            }

            let _ = dilithium.ctx_zero();
        }
    }
}

#[test]
fn wycheproof_dilithium_sign_noseed_44() {
    wycheproof_dilithium_sign_noseed(TestName::MlDsa44SignNoSeed)
}

#[test]
fn wycheproof_dilithium_sign_noseed_65() {
    wycheproof_dilithium_sign_noseed(TestName::MlDsa65SignNoSeed)
}

#[test]
fn wycheproof_dilithium_sign_noseed_87() {
    wycheproof_dilithium_sign_noseed(TestName::MlDsa87SignNoSeed)
}
