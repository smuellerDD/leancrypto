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

use leancrypto_sys::lcr_ed448::lcr_ed448;
use wycheproof::{
    TestResult,
    eddsa::{TestName, TestSet},
};

#[test]
fn wycheproof_ed448_verify() {
    let test_set = TestSet::load(TestName::Ed448).unwrap();
    for test_group in &test_set.test_groups {
        let mut ed448 = lcr_ed448::new();
        let result = ed448.enable();
        assert_eq!(result, Ok(()));

        let result = ed448.pk_load(&test_group.key.pk);
        assert_eq!(result, Ok(()));

        for test in &test_group.tests {
            /*
             * Under discussion at
             * https://github.com/bleichenbacher-daniel/Rooterberg/issues/6
             */
            match test.tc_id {
                63..66 => continue,
                76 => continue,
                _ => (),
            }

            println!("Test case {}: {}", test.tc_id, test.comment);

            let mut result = ed448.sig_load(&test.sig);
            if result == Ok(()) {
                result = ed448.verify(&test.msg);
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
