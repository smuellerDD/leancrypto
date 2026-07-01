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

use leancrypto_sys::lcr_dilithium::lcr_dilithium;
use wycheproof::{
    mldsa_verify::{TestName, TestSet},
    TestResult,
};

fn wycheproof_dilithium_verify(test_name: TestName) {
    let test_set = TestSet::load(test_name).unwrap();
    for test_group in &test_set.test_groups {
        let mut dilithium = lcr_dilithium::new();

        let result = dilithium.pk_load(&test_group.pubkey);
        if result.is_err() {
            /* The test vector may give us strange keys which we reject */
            continue;
        }

        for test in &test_group.tests {
            println!("Test case {}: {}", test.tc_id, test.comment);

            let ctx = &test.ctx;
            if let Some(ctx) = ctx {
                if ctx.len() > 0 {
                    let result = dilithium.ctx_userctx(&ctx.to_vec());
                    assert_eq!(result, Ok(()));
                }
            }

            let mut result = dilithium.sig_load(&test.sig);
            if result == Ok(()) {
                result = dilithium.verify(&test.msg);
            }

            match &test.result {
                TestResult::Invalid => {
                    assert!(result.is_err());
                }
                TestResult::Valid | TestResult::Acceptable => {
                    assert_eq!(result, Ok(()));
                }
            }

            let _ = dilithium.ctx_zero();
        }
    }
}

#[test]
fn wycheproof_dilithium_verify_44() {
    wycheproof_dilithium_verify(TestName::MlDsa44Verify)
}

#[test]
fn wycheproof_dilithium_verify_65() {
    wycheproof_dilithium_verify(TestName::MlDsa65Verify)
}
#[test]
fn wycheproof_dilithium_verify_87() {
    wycheproof_dilithium_verify(TestName::MlDsa87Verify)
}
