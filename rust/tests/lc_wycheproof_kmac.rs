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

use leancrypto_sys::lcr_kmac::{lcr_kmac, lcr_kmac_type};
use wycheproof::{
    TestResult,
    mac::{TestName, TestSet},
};

fn test_kmac(
    kmac: &mut lcr_kmac,
    test_name: TestName,
) {
    let test_set = TestSet::load(test_name).unwrap();

    for test_group in test_set.test_groups {
        for test in test_group.tests {
            println!("Test case {}: {}", test.tc_id, test.comment);

            let mut mac = vec![0; test.tag.len()];
            let result = kmac.kmac(&test.key, &[], &test.msg, &mut mac);
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
fn wycheproof_kmac128() {
    let mut kmac = lcr_kmac::new(lcr_kmac_type::lcr_kmac_128);
    test_kmac(&mut kmac, TestName::Kmac128);
}

#[test]
fn wycheproof_kmac256() {
    let mut kmac = lcr_kmac::new(lcr_kmac_type::lcr_kmac_256);
    test_kmac(&mut kmac, TestName::Kmac256);
}
