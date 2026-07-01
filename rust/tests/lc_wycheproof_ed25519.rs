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

use leancrypto_sys::lcr_ed25519::lcr_ed25519;
use wycheproof::{
    eddsa::{TestName, TestSet},
    TestResult,
};

#[test]
fn wycheproof_ed25519_verify() {
    let test_set = TestSet::load(TestName::Ed25519).unwrap();
    for test_group in &test_set.test_groups {
        let mut ed25519 = lcr_ed25519::new();
        let result = ed25519.enable();
        assert_eq!(result, Ok(()));

        let result = ed25519.pk_load(&test_group.key.pk);
        assert_eq!(result, Ok(()));

        for test in &test_group.tests {
            println!("Test case {}: {}", test.tc_id, test.comment);

            let mut result = ed25519.sig_load(&test.sig);
            if result == Ok(()) {
                result = ed25519.verify(&test.msg);
            }

            match &test.result {
                TestResult::Invalid => {
                    assert!(result.is_err());
                }
                TestResult::Valid | TestResult::Acceptable => {
                    assert_eq!(result, Ok(()));
                }
            }
        }
    }
}
