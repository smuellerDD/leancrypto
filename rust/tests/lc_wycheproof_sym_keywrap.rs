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

use leancrypto_sys::lcr_sym::lcr_sym;
use leancrypto_sys::lcr_sym::lcr_sym_type;
use wycheproof::{keywrap::TestName, TestResult};

fn wycheproof_test_sym(
    sym: &mut lcr_sym,
    test_name: TestName,
) {
    let test_set = wycheproof::keywrap::TestSet::load(test_name).unwrap();

    for group in test_set.test_groups.into_iter() {
        for test in group.tests {
            println!("Test case {}: {}", test.tc_id, test.comment);

            if test.pt.len() < 16 {
                continue;
            }

            let mut actual_ciphertext = vec![0u8; test.pt.len() + 8];
            let result = sym.setkey(&test.key);
            assert_eq!(result, Ok(()));

            assert_eq!(result, Ok(()));
            let result =
                sym.kw_encrypt(&test.pt.to_vec(), &mut actual_ciphertext);

            match &test.result {
                TestResult::Invalid => {
                    assert_ne!(actual_ciphertext[..], test.ct[..]);
                }
                TestResult::Valid | TestResult::Acceptable => {
                    assert!(result.is_ok());
                    assert_eq!(
                        actual_ciphertext[..],
                        test.ct[..],
                        "Test case failed {}: {}",
                        test.tc_id,
                        test.comment
                    );
                }
            }

            let mut actual_plaintext = vec![0u8; test.pt.len()];

            let result = sym.setkey(&test.key);
            assert_eq!(result, Ok(()));

            let result =
                sym.kw_decrypt(&test.ct.to_vec(), &mut actual_plaintext);

            match &test.result {
                TestResult::Invalid => {
                    assert!(result.is_err());
                }
                TestResult::Valid | TestResult::Acceptable => {
                    assert_eq!(result, Ok(()));
                    assert_eq!(test.pt[..], actual_plaintext[..]);
                }
            }
        }
    }
}

#[test]
fn wycheproof_test_aes_keywrap() {
    let mut sym = lcr_sym::new(lcr_sym_type::lcr_aes_kw);
    wycheproof_test_sym(&mut sym, TestName::AesKeyWrap);
}
