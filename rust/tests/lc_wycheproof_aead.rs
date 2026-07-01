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

use leancrypto_sys::lcr_aead::lcr_aead;
use leancrypto_sys::lcr_aead::lcr_aead_type;
use wycheproof::{
    aead::{TestFlag, TestName},
    TestResult,
};

fn wycheproof_test_aead(
    aead: &mut lcr_aead,
    nonce_size: usize,
    test_name: TestName,
) {
    let test_set = wycheproof::aead::TestSet::load(test_name).unwrap();

    for group in test_set
        .test_groups
        .into_iter()
        .filter(|group| group.nonce_size == nonce_size)
        .filter(|group| group.tag_size >= 8)
    {
        for test in group.tests {
            println!("Test case {}: {}", test.tc_id, test.comment);

            let mut tag = test.tag.to_vec();
            let mut actual_ciphertext = test.pt.to_vec();
            // One-shot encrypt
            let result = aead.setkey(&test.key, &test.nonce);
            assert_eq!(result, Ok(()));
            let _result = aead.encrypt(
                &test.pt.to_vec(),
                &mut actual_ciphertext,
                &test.aad,
                &mut tag,
            );

            match &test.result {
                TestResult::Invalid => {
                    if test
                        .flags
                        .iter()
                        .any(|flag| *flag == TestFlag::ModifiedTag)
                    {
                        assert_ne!(
                            tag[..],
                            test.tag[..],
                            "Expected incorrect tag. Id {}: {}",
                            test.tc_id,
                            test.comment
                        );
                    }
                }
                TestResult::Valid | TestResult::Acceptable => {
                    assert_eq!(
                        actual_ciphertext[..],
                        test.ct[..],
                        "Test case failed {}: {}",
                        test.tc_id,
                        test.comment
                    );
                    assert_eq!(
                        tag[..],
                        test.tag[..],
                        "Test case failed {}: {}",
                        test.tc_id,
                        test.comment
                    );
                }
            }

            let mut actual_plaintext = test.ct.to_vec();

            // One-shot decrypt
            let result = aead.setkey(&test.key, &test.nonce);
            assert_eq!(result, Ok(()));

            let result = aead.decrypt(
                &test.ct.to_vec(),
                &mut actual_plaintext,
                &test.aad,
                &test.tag,
            );

            match &test.result {
                TestResult::Invalid => {
                    assert!(result.is_err());
                }
                TestResult::Valid | TestResult::Acceptable => {
                    assert_eq!(result, Ok(()));
                    assert_eq!(test.pt[..], actual_plaintext[..]);
                    assert_eq!(
                        actual_plaintext[..],
                        test.pt[..],
                        "Test case failed {}: {}",
                        test.tc_id,
                        test.comment
                    );
                }
            }
        }
    }
}

#[test]
fn wycheproof_test_aes_gcm32() {
    let mut aead = lcr_aead::new(lcr_aead_type::lcr_aes_gcm);
    wycheproof_test_aead(&mut aead, 32, TestName::AesGcm);
}

#[test]
fn wycheproof_test_aes_gcm64() {
    let mut aead = lcr_aead::new(lcr_aead_type::lcr_aes_gcm);
    wycheproof_test_aead(&mut aead, 64, TestName::AesGcm);
}

#[test]
fn wycheproof_test_aes_gcm96() {
    let mut aead = lcr_aead::new(lcr_aead_type::lcr_aes_gcm);
    wycheproof_test_aead(&mut aead, 96, TestName::AesGcm);
}

#[test]
fn wycheproof_test_aes_gcm128() {
    let mut aead = lcr_aead::new(lcr_aead_type::lcr_aes_gcm);
    wycheproof_test_aead(&mut aead, 128, TestName::AesGcm);
}

#[test]
fn wycheproof_test_chacha96() {
    let mut aead = lcr_aead::new(lcr_aead_type::lcr_chacha20_poly1305);
    wycheproof_test_aead(&mut aead, 96, TestName::ChaCha20Poly1305);
}

#[test]
fn wycheproof_test_chacha64() {
    let mut aead = lcr_aead::new(lcr_aead_type::lcr_chacha20_poly1305);
    wycheproof_test_aead(&mut aead, 64, TestName::ChaCha20Poly1305);
}

// #[test]
// fn wycheproof_test_ascon128() {
//     let mut aead = lcr_aead::new(lcr_aead_type::lcr_ascon_128);
//     wycheproof_test_aead(&mut aead, 128, TestName::Ascon128);
// }
