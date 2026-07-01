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
use wycheproof::{cipher::TestName, TestResult};

fn wycheproof_test_sym(
    sym: &mut lcr_sym,
    iv_size: usize,
    test_name: TestName,
) {
    let test_set = wycheproof::cipher::TestSet::load(test_name).unwrap();

    for group in test_set
        .test_groups
        .into_iter()
        .filter(|group| group.nonce_size == iv_size)
    {
        for test in group.tests {
            println!("Test case {}: {}", test.tc_id, test.comment);

            let mut actual_ciphertext = test.pt.to_vec();
            let result = sym.setkey(&test.key);
            assert_eq!(result, Ok(()));

            let mut iv = test.nonce.to_vec();
            for _i in iv.len()..16 {
                iv.push(0);
            }
            let result = sym.setiv(&iv);
            assert_eq!(result, Ok(()));
            let result = sym.encrypt(&test.pt.to_vec(), &mut actual_ciphertext);

            match &test.result {
                TestResult::Invalid => {
                    assert!(result.is_err());
                }
                TestResult::Valid | TestResult::Acceptable => {
                    assert_eq!(
                        actual_ciphertext[..],
                        test.ct[..],
                        "Test case failed {}: {}",
                        test.tc_id,
                        test.comment
                    );
                }
            }

            let mut actual_plaintext = test.ct.to_vec();

            let result = sym.setkey(&test.key);
            assert_eq!(result, Ok(()));
            let result = sym.setiv(&iv);
            assert_eq!(result, Ok(()));

            let result = sym.decrypt(&test.ct.to_vec(), &mut actual_plaintext);

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
fn wycheproof_test_aes_xts() {
    let mut sym = lcr_sym::new(lcr_sym_type::lcr_aes_xts);
    wycheproof_test_sym(&mut sym, 16, TestName::AesXts);
}
