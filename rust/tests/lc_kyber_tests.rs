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

use leancrypto_sys::lcr_kyber::lcr_kyber;
use leancrypto_sys::lcr_kyber::lcr_kyber_type;

fn lc_rust_kyber_one(kyber_type: lcr_kyber_type) {
    let mut kyber = lcr_kyber::new();

    let result = kyber.keypair(kyber_type);
    assert_eq!(result, Ok(()));

    let result = kyber.encapsulate();
    assert_eq!(result, Ok(()));

    let ct_slice = kyber.get_ct().expect("get_ct");
    let ct = ct_slice.to_vec();
    let sk_slice = kyber.get_sk().expect("get_sk");
    let sk = sk_slice.to_vec();

    let mut kyber2 = lcr_kyber::new();
    let result = kyber2.sk_load(&sk);
    assert_eq!(result, Ok(()));
    assert_eq!(
        kyber.get_sk().expect("get_sk"),
        kyber2.get_sk().expect("get_sk")
    );

    let result = kyber2.ct_load(&ct);
    assert_eq!(result, Ok(()));
    assert_eq!(
        kyber.get_ct().expect("get_ct"),
        kyber2.get_ct().expect("get_ct")
    );

    let result = kyber2.decapsulate();
    assert_eq!(result, Ok(()));
    assert_eq!(
        kyber.get_ss().expect("get_ss"),
        kyber2.get_ss().expect("get_ss")
    );
    //println!("ct {:x?}",  kyber2.ct().to_vec().chunks(10).next());
}

#[test]
fn lc_rust_kyber_512() {
    lc_rust_kyber_one(lcr_kyber_type::lcr_kyber_512);
}

#[test]
fn lc_rust_kyber_768() {
    lc_rust_kyber_one(lcr_kyber_type::lcr_kyber_768);
}

#[test]
fn lc_rust_kyber_1024() {
    lc_rust_kyber_one(lcr_kyber_type::lcr_kyber_1024);
}
/*

#[test]
fn x25519() {
    let test_set = TestSet::load(TestName::X25519).unwrap();
    for test_group in &test_set.test_groups {
        for test in &test_group.tests {
            let mut x25519 = leancrypto_sys::lcr_x25519::lcr_x25519::new();
            let result = x25519.enable();
            assert_eq!(result, Ok(()));

            let result = x25519.sk_load(&test.private_key);
            assert_eq!(result, Ok(()));
            let result = x25519.pk_remote_load(&test.public_key);
            assert_eq!(result, Ok(()));

            let result = x25519.shared_secret();

            match result {
                Ok(()) => {
                    let ss_slice = x25519.get_ss().expect("get_ss");
                    assert_eq!(result, Ok(()));
                    assert_eq!(
                        ss_slice[..],
                        test.shared_secret[..],
                        "Derived incorrect secret: {:?}",
                        test
                    );
                }
                Err(e) => {
                    panic!("Test failed: {:?}. Error {:?}", test, e);
                }
            }
        }
    }
}*/
