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

use leancrypto_sys::lcr_x448::lcr_x448;
use wycheproof::{
    xdh::{TestName, TestSet},
    TestResult,
};

fn lc_rust_x448_one() {
    let mut x448_local = lcr_x448::new();
    let mut x448_remote = lcr_x448::new();

    let result = x448_local.enable();
    assert_eq!(result, Ok(()));

    /* Generate local key pair */
    let result = x448_local.keypair();
    assert_eq!(result, Ok(()));

    /* Export local public key */
    let pk_local_slice = x448_local.get_pk().expect("get_pk");
    let pk_local = pk_local_slice.to_vec();

    /* Generate remote key pair */
    let result = x448_remote.keypair();
    assert_eq!(result, Ok(()));

    /* Export remote public key */
    let pk_remote_slice = x448_remote.get_pk().expect("get_pk");
    let pk_remote = pk_remote_slice.to_vec();

    /* Load remote PK into local context */
    let result = x448_local.pk_remote_load(&pk_remote);
    assert_eq!(result, Ok(()));

    /* Load local PK into remote context */
    let result = x448_remote.pk_remote_load(&pk_local);
    assert_eq!(result, Ok(()));

    /* Generate local shared secret */
    let result = x448_local.shared_secret();
    assert_eq!(result, Ok(()));

    /* Export local shared secret */
    let ss_local_slice = x448_local.get_ss().expect("get_ss");
    let ss_local = ss_local_slice.to_vec();

    /* Generate remote shared secret */
    let result = x448_remote.shared_secret();
    assert_eq!(result, Ok(()));

    /* Export remote shared secret */
    let ss_remote_slice = x448_remote.get_ss().expect("get_ss");
    assert_eq!(result, Ok(()));
    let ss_remote = ss_remote_slice.to_vec();

    /* Check that local and remote shared secrets match */
    assert_eq!(ss_local, ss_remote);
    //println!("ss local {:x?}",  ss_local);
    //println!("ss remote {:x?}",  ss_remote);
}

#[test]
fn lc_rust_x448() {
    lc_rust_x448_one();
}

#[test]
fn wycheproof_x448() {
    let test_set = TestSet::load(TestName::X448).unwrap();
    for test_group in &test_set.test_groups {
        for test in &test_group.tests {
            println!("Test case {}: {}", test.tc_id, test.comment);

            let mut x448 = leancrypto_sys::lcr_x448::lcr_x448::new();
            let result = x448.enable();
            assert_eq!(result, Ok(()));

            let result = x448.sk_load(&test.private_key);
            assert_eq!(result, Ok(()));
            let mut result = x448.pk_remote_load(&test.public_key);

            if result == Ok(()) {
                result = x448.shared_secret();
            }

            match &test.result {
                TestResult::Invalid => {
                    assert!(result.is_err());
                }
                TestResult::Valid | TestResult::Acceptable => {
                    assert_eq!(result, Ok(()));
                    let ss_slice = x448.get_ss().expect("get_ss");
                    assert_eq!(
                        ss_slice[..],
                        test.shared_secret[..],
                        "Derived incorrect secret: {:?}",
                        test
                    );
                }
            }
        }
    }
}
