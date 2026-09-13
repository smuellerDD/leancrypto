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

use leancrypto_sys::lcr_sntrup::lcr_sntrup;
use leancrypto_sys::lcr_sntrup::lcr_sntrup_type;

fn lc_rust_sntrup_one(sntrup_type: lcr_sntrup_type) {
    let mut sntrup = lcr_sntrup::new();

    let result = sntrup.keypair(sntrup_type);
    assert_eq!(result, Ok(()));

    let result = sntrup.encapsulate();
    assert_eq!(result, Ok(()));

    let ct_slice = sntrup.get_ct().expect("get_ct");
    let ct = ct_slice.to_vec();
    let sk_slice = sntrup.get_sk().expect("get_sk");
    let sk = sk_slice.get_ref().to_vec();

    let mut sntrup2 = lcr_sntrup::new();
    let result = sntrup2.sk_load(&sk);
    assert_eq!(result, Ok(()));
    assert_eq!(
        sntrup.get_sk().expect("get_sk").get_ref(),
        sntrup2.get_sk().expect("get_sk").get_ref()
    );

    let result = sntrup2.ct_load(&ct);
    assert_eq!(result, Ok(()));
    assert_eq!(
        sntrup.get_ct().expect("get_ct"),
        sntrup2.get_ct().expect("get_ct")
    );

    let result = sntrup2.decapsulate();
    assert_eq!(result, Ok(()));
    assert_eq!(
        sntrup.get_ss().expect("get_ss").get_ref(),
        sntrup2.get_ss().expect("get_ss").get_ref()
    );
    //println!("ct {:x?}",  sntrup2.ct().to_vec().chunks(10).next());
}

#[test]
fn lc_rust_sntrup_761() {
    lc_rust_sntrup_one(lcr_sntrup_type::lcr_sntrup_761);
}

#[test]
fn lc_rust_sntrup_857() {
    lc_rust_sntrup_one(lcr_sntrup_type::lcr_sntrup_857);
}

#[test]
fn lc_rust_sntrup_953() {
    lc_rust_sntrup_one(lcr_sntrup_type::lcr_sntrup_953);
}

#[test]
fn lc_rust_sntrup_1013() {
    lc_rust_sntrup_one(lcr_sntrup_type::lcr_sntrup_1013);
}

#[test]
fn lc_rust_sntrup_1277() {
    lc_rust_sntrup_one(lcr_sntrup_type::lcr_sntrup_1277);
}
