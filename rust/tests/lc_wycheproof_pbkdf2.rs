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
use leancrypto_sys::lcr_pbkdf2::lcr_pbkdf2;
use wycheproof::{
    pbkdf2::{TestName, TestSet},
    TestResult,
};

fn test_pbkdf2(
    pbkdf2: &mut lcr_pbkdf2,
    test_name: TestName,
) {
    let test_set = TestSet::load(test_name).unwrap();

    for test_group in test_set.test_groups {
        for test in test_group.tests {
            println!("Test case {}: {}", test.tc_id, test.comment);

            let mut dk = vec![0; test.dk_len];
            println!("{} {}", test.dk_len, test.dk.len());
            let result = pbkdf2.derive(
                &test.password,
                &test.salt,
                test.iteration_count as u32,
                &mut dk,
            );

            match &test.result {
                TestResult::Acceptable | TestResult::Valid => {
                    assert!(result.is_ok());
                    assert_eq!(
                        dk[..],
                        test.dk[..],
                        "Failed test: {}",
                        test.comment
                    );
                }
                TestResult::Invalid => {
                    if !result.is_err() {
                        assert_ne!(
                            dk[..],
                            test.dk[..],
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
fn wycheproof_pbkdf2_hmac256() {
    let mut pbkdf2 = lcr_pbkdf2::new(lcr_hash_type::lcr_sha2_256);
    test_pbkdf2(&mut pbkdf2, TestName::Pbkdf2HmacSha256);
}

#[test]
fn wycheproof_pbkdf2_hmac384() {
    let mut pbkdf2 = lcr_pbkdf2::new(lcr_hash_type::lcr_sha2_384);
    test_pbkdf2(&mut pbkdf2, TestName::Pbkdf2HmacSha384);
}

#[test]
fn wycheproof_pbkdf2_hmac512() {
    let mut pbkdf2 = lcr_pbkdf2::new(lcr_hash_type::lcr_sha2_512);
    test_pbkdf2(&mut pbkdf2, TestName::Pbkdf2HmacSha512);
}
