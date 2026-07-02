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
use leancrypto_sys::lcr_hkdf::lcr_hkdf;
use wycheproof::{TestResult, hkdf::TestName};

fn test_hkdf(
    hkdf: &mut lcr_hkdf,
    test_name: TestName,
) {
    let test_set = wycheproof::hkdf::TestSet::load(test_name).unwrap();

    for test_group in test_set.test_groups {
        for test in test_group.tests {
            dbg!(&test);

            let result = hkdf.extract(&test.ikm, &test.salt);
            assert_eq!(result, Ok(()));

            let mut okm = vec![0; test.size];
            let result = hkdf.expand(&test.info, &mut okm);

            match &test.result {
                TestResult::Acceptable | TestResult::Valid => {
                    assert!(result.is_ok());
                    assert_eq!(
                        okm[..],
                        test.okm[..],
                        "Failed test: {}",
                        test.comment
                    );
                }
                TestResult::Invalid => {
                    dbg!(&result);
                    assert!(result.is_err(), "Failed test: {}", test.comment)
                }
            }
        }
    }
}

#[test]
fn wycheproof_hkdf_sha256() {
    let mut hkdf = lcr_hkdf::new(lcr_hash_type::lcr_sha2_256);
    test_hkdf(&mut hkdf, TestName::HkdfSha256);
}

#[test]
fn wycheproof_hkdf_sha384() {
    let mut hkdf = lcr_hkdf::new(lcr_hash_type::lcr_sha2_384);
    test_hkdf(&mut hkdf, TestName::HkdfSha384);
}

#[test]
fn wycheproof_hkdf_sha512() {
    let mut hkdf = lcr_hkdf::new(lcr_hash_type::lcr_sha2_512);
    test_hkdf(&mut hkdf, TestName::HkdfSha512);
}
