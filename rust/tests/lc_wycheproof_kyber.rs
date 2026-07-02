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

use leancrypto_sys::lcr_kyber::{lcr_kyber, lcr_kyber_type};
use wycheproof::{
    TestResult,
    mlkem::{TestName, TestSet},
};

fn wycheproof_kyber(
    kyber_type: lcr_kyber_type,
    test_name: TestName,
) {
    let test_set = TestSet::load(test_name).unwrap();
    for test_group in &test_set.test_groups {
        let mut kyber = lcr_kyber::new();

        for test in &test_group.tests {
            let mut encap = 0;
            let mut decap = 0;
            println!("Test case {}: {}", test.tc_id, test.comment);

            let privseed = &test.seed;
            let privkey = &test.decaps_key;
            let pubkey = &test.encaps_key;
            let ct = &test.ct;
            let ss = &test.shared_secret;
            if let Some(privseed) = privseed {
                let result = kyber.sk_seed_load(&privseed, kyber_type);
                if result.is_err() {
                    /* The test vector may give us strange keys which we reject */
                    println!(
                        "Test vector with key that cannot be imported, ignore"
                    );
                    continue;
                }
                encap = 1;
                decap = 1;

                /* Check the key */
                if let Some(privkey) = privkey {
                    assert_eq!(
                        privkey[..],
                        kyber.get_sk().expect("get_sk")[..]
                    );
                }

                if let Some(pubkey) = pubkey {
                    assert_eq!(pubkey[..], kyber.get_pk().expect("get_sk")[..]);
                }
            } else {
                if let Some(privkey) = privkey {
                    let result = kyber.sk_load(&privkey);
                    if result.is_err() {
                        /* The test vector may give us strange keys which we reject */
                        println!(
                            "Test vector with key that cannot be imported, ignore"
                        );
                        continue;
                    }

                    decap = 1;
                }

                if let Some(pubkey) = pubkey {
                    let result = kyber.pk_load(&pubkey);
                    if result.is_err() {
                        /* The test vector may give us strange keys which we reject */
                        println!(
                            "Test vector with key that cannot be imported, ignore"
                        );
                        continue;
                    }

                    encap = 1;
                }
            }

            let mut encap_invalid = 0;
            if encap == 1 {
                println!("Test ML-KEM encap");

                let result = kyber.encapsulate();

                match &test.result {
                    TestResult::Invalid => {
                        if !result.is_err() {
                            encap_invalid = 1;
                        }
                    }
                    TestResult::Valid | TestResult::Acceptable => {
                        assert_eq!(result, Ok(()));
                    }
                }
            }

            if decap == 1 {
                println!("Test ML-KEM decap");

                if let Some(ct) = ct {
                    let result = kyber.ct_load(&ct);
                    if result.is_err() {
                        /* The test vector may give us strange keys which we reject */
                        println!(
                            "Test vector with key that cannot be imported, ignore"
                        );
                        continue;
                    }
                } else {
                    /*
                     * If decap is requested, but we have no ct from encap, we
                     * assert.
                     */
                    assert_eq!(encap, 1);
                }

                let result = kyber.decapsulate();

                match &test.result {
                    TestResult::Invalid => {
                        if !result.is_err() {
                            if let Some(ss) = ss {
                                let ss_slice = match kyber.get_ss() {
                                    Ok(ret) => ret,
                                    Err(_) => &[],
                                };
                                assert_ne!(ss[..], ss_slice[..]);
                            }
                        }
                        assert_ne!(result, Ok(()));
                    }
                    TestResult::Valid | TestResult::Acceptable => {
                        assert_eq!(result, Ok(()));
                        if let Some(ss) = ss {
                            let ss_slice = match kyber.get_ss() {
                                Ok(ret) => ret,
                                Err(_) => &[],
                            };
                            assert_eq!(ss[..], ss_slice[..]);
                        }
                    }
                }
            } else {
                /*
                 * Error out if we have only encap, and there was an encap error
                 * expected, and no encap error was detected.
                 */
                assert_eq!(encap_invalid, 0);
            }
        }
    }
}

#[test]
fn wycheproof_kyber_512() {
    wycheproof_kyber(lcr_kyber_type::lcr_kyber_512, TestName::MlKem512)
}

#[test]
fn wycheproof_kyber_512_encaps() {
    wycheproof_kyber(lcr_kyber_type::lcr_kyber_512, TestName::MlKem512Encaps)
}

#[test]
fn wycheproof_kyber_512_keygen() {
    wycheproof_kyber(
        lcr_kyber_type::lcr_kyber_512,
        TestName::MlKem512KeyGenSeed,
    )
}

#[test]
fn wycheproof_kyber_512_semi() {
    wycheproof_kyber(
        lcr_kyber_type::lcr_kyber_512,
        TestName::MlKem512SemiExpandedDecaps,
    )
}

#[test]
fn wycheproof_kyber_768() {
    wycheproof_kyber(lcr_kyber_type::lcr_kyber_768, TestName::MlKem768)
}

#[test]
fn wycheproof_kyber_768_encaps() {
    wycheproof_kyber(lcr_kyber_type::lcr_kyber_768, TestName::MlKem768Encaps)
}

#[test]
fn wycheproof_kyber_768_keygen() {
    wycheproof_kyber(
        lcr_kyber_type::lcr_kyber_768,
        TestName::MlKem768KeyGenSeed,
    )
}

#[test]
fn wycheproof_kyber_768_semi() {
    wycheproof_kyber(
        lcr_kyber_type::lcr_kyber_768,
        TestName::MlKem768SemiExpandedDecaps,
    )
}

#[test]
fn wycheproof_kyber_1024() {
    wycheproof_kyber(lcr_kyber_type::lcr_kyber_1024, TestName::MlKem1024)
}

#[test]
fn wycheproof_kyber_1024_encaps() {
    wycheproof_kyber(lcr_kyber_type::lcr_kyber_1024, TestName::MlKem1024Encaps)
}

#[test]
fn wycheproof_kyber_1024_keygen() {
    wycheproof_kyber(
        lcr_kyber_type::lcr_kyber_1024,
        TestName::MlKem1024KeyGenSeed,
    )
}

#[test]
fn wycheproof_kyber_1024_semi() {
    wycheproof_kyber(
        lcr_kyber_type::lcr_kyber_1024,
        TestName::MlKem1024SemiExpandedDecaps,
    )
}
