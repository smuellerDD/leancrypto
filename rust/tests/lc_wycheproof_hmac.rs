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

use leancrypto_sys::lcr_hash::lcr_hash_type;
use leancrypto_sys::lcr_hmac::lcr_hmac;
use wycheproof::{
    mac::{TestName, TestSet},
    TestResult,
};

fn test_hmac(
    hmac: &mut lcr_hmac,
    test_name: TestName,
) {
    let test_set = TestSet::load(test_name).unwrap();

    for test_group in test_set.test_groups {
        for test in test_group.tests {
            println!("Test case {}: {}", test.tc_id, test.comment);

            let mut mac = vec![0; test.tag.len()];
            let result = hmac.hmac(&test.key, &test.msg, &mut mac);
            if result != Ok(()) {
                /*
                 * We do not support truncated hashes.
                 */
                println!("Ignore wrong input data");
                continue;
            }

            match &test.result {
                TestResult::Acceptable | TestResult::Valid => {
                    assert!(result.is_ok());
                    assert_eq!(
                        mac[..],
                        test.tag[..],
                        "Failed test: {}",
                        test.comment
                    );
                }
                TestResult::Invalid => {
                    if !result.is_err() {
                        assert_ne!(
                            mac[..],
                            test.tag[..],
                            "Failed test: {}",
                            test.comment
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn wycheproof_hmac_sha256() {
    let mut hmac = lcr_hmac::new(lcr_hash_type::lcr_sha2_256);
    test_hmac(&mut hmac, TestName::HmacSha256);
}

#[test]
fn wycheproof_hmac_sha384() {
    let mut hmac = lcr_hmac::new(lcr_hash_type::lcr_sha2_384);
    test_hmac(&mut hmac, TestName::HmacSha384);
}

#[test]
fn wycheproof_hmac_sha512() {
    let mut hmac = lcr_hmac::new(lcr_hash_type::lcr_sha2_512);
    test_hmac(&mut hmac, TestName::HmacSha512);
}

#[test]
fn wycheproof_hmac_sha3_224() {
    let mut hmac = lcr_hmac::new(lcr_hash_type::lcr_sha3_224);
    test_hmac(&mut hmac, TestName::HmacSha3_224);
}

#[test]
fn wycheproof_hmac_sha3_256() {
    let mut hmac = lcr_hmac::new(lcr_hash_type::lcr_sha3_256);
    test_hmac(&mut hmac, TestName::HmacSha3_256);
}

#[test]
fn wycheproof_hmac_sha3_384() {
    let mut hmac = lcr_hmac::new(lcr_hash_type::lcr_sha3_384);
    test_hmac(&mut hmac, TestName::HmacSha3_384);
}

#[test]
fn wycheproof_hmac_sha3_512() {
    let mut hmac = lcr_hmac::new(lcr_hash_type::lcr_sha3_512);
    test_hmac(&mut hmac, TestName::HmacSha3_512);
}
