/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

//! Key Encapsulation Mechanism (KEM) key exchange groups.
use leancrypto_sys::lcr_kyber_x25519::{
    lcr_kyber_x25519, lcr_kyber_x25519_type,
};
use rustls::crypto::{
    ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup,
};
use rustls::{Error, NamedGroup, ProtocolVersion};

/// This is the [X25519MLKEM768] key exchange.
///
/// [X25519MLKEM768]: <https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/>
pub const X25519MLKEM768: &dyn SupportedKxGroup = &KxGroupX25519 {
    named_group: NamedGroup::X25519MLKEM768,
    algorithm_name: lcr_kyber_x25519_type::lcr_kyber_768,
};

/// A key exchange group based on a key encapsulation mechanism.
#[derive(Debug, Copy, Clone)]
struct KxGroupX25519 {
    named_group: NamedGroup,
    algorithm_name: lcr_kyber_x25519_type,
}

struct KeyExchangeX25519 {
    priv_key: lcr_kyber_x25519,
    pub_key: Vec<u8>,
    group: KxGroupX25519,
}

impl KxGroupX25519 {
    /// [KxGroup::start] but returns a concrete `KeyExchange` instead of a trait object.
    fn start_internal(&self) -> Result<KeyExchangeX25519, Error> {
        let mut kyber_x25519 = lcr_kyber_x25519::new();

        /*
         * Generate the ephemeral ML-KEM and X25519 key pairs.
         */
        kyber_x25519.keypair(self.algorithm_name).map_err(|e| {
            Error::General(format!(
                "lc:MLKEM-X25519: key pair generation error: {e}"
            ))
        })?;

        /*
         * Extract the public keys and concatenate them.
         */
        let (pk_slice, pk_x25519_slice) = match kyber_x25519.get_pk() {
            Ok((ret1, ret2)) => (ret1, ret2),
            Err(e) => {
                return Err(Error::General(format!(
                    "lc:MLKEM-X25519: public key extraction error: {e}"
                )));
            }
        };
        let mut public_key = vec![];
        public_key.extend_from_slice(pk_slice);
        public_key.extend_from_slice(pk_x25519_slice);
        Ok(KeyExchangeX25519 {
            priv_key: kyber_x25519,
            pub_key: public_key,
            group: *self,
        })
    }
}

impl SupportedKxGroup for KxGroupX25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        self.start_internal()
            .map(|kx| Box::new(kx) as Box<dyn ActiveKeyExchange>)
    }

    fn name(&self) -> NamedGroup {
        self.named_group
    }

    fn usable_for_version(
        &self,
        version: ProtocolVersion,
    ) -> bool {
        version == ProtocolVersion::TLSv1_3
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    /*
     * Start the key establishment operation - initiator side
     */
    fn start_and_complete(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<rustls::crypto::CompletedKeyExchange, Error> {
        let mut kyber_x25519 = lcr_kyber_x25519::new();

        /*
         * Load the local public key data which is the concatenation of
         * the ML-KEM public key and the X25519 public key.
         */
        kyber_x25519
            .pk_load(
                &peer_pub_key[..peer_pub_key.len() - 32],
                &peer_pub_key[peer_pub_key.len() - 32..],
            )
            .map_err(|e| {
                Error::General(format!(
                    "lc:MLKEM-X25519: loading local pub key error: {e}"
                ))
            })?;

        /*
         * Perform the actual encapsulation operation for both,
         * the ML-KEM and X25519.
         */
        kyber_x25519.encapsulate().map_err(|e| {
            Error::General(format!("lc:MLKEM-X25519: encapsulation error: {e}"))
        })?;

        /*
         * Generate the actual key establishment data sent to the peer
         * is a concatenation of the ML-KEM ciphertext and the X25519
         * ephemeral public key.
         */
        let (ct_slice, ct_x25519_slice) = match kyber_x25519.get_ct() {
            Ok((ret1, ret2)) => (ret1, ret2),
            Err(e) => {
                return Err(Error::General(format!(
                    "lc:MLKEM-X25519: ciphertext extraction error: {e}"
                )));
            }
        };
        let mut ct = vec![];
        ct.extend_from_slice(ct_slice);
        ct.extend_from_slice(ct_x25519_slice);

        /*
         * Get the generated shared secret data as a concatenation of
         * the ML-KEM shared secret and the X25519 shared secret.
         */
        let (ss_slice, ss_x25519_slice) = match kyber_x25519.get_ss() {
            Ok((ret1, ret2)) => (ret1, ret2),
            Err(e) => {
                return Err(Error::General(format!(
                    "lc:MLKEM-X25519 shared secret extraction error: {e}"
                )));
            }
        };
        let mut ss = vec![];
        ss.extend_from_slice(ss_slice);
        ss.extend_from_slice(ss_x25519_slice);

        Ok(CompletedKeyExchange {
            group: self.named_group,
            pub_key: ct,
            secret: SharedSecret::from(ss),
        })
    }

    fn fips(&self) -> bool {
        crate::fips::enabled()
    }
}

impl ActiveKeyExchange for KeyExchangeX25519 {
    /*
     * Complete the key establishment operation - receiver side
     */
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        let mut kyber_x25519 = self.priv_key;

        /*
         * Receive the remote key agreement data which is a
         * concatenation of the ML-KEM ciphertext and the X25519
         * ephemeral public key and load it into our context.
         */
        kyber_x25519
            .ct_load(
                &peer_pub_key[..peer_pub_key.len() - 32],
                &peer_pub_key[peer_pub_key.len() - 32..],
            )
            .map_err(|e| {
                Error::General(format!(
                    "lc:MLKEM-X25519: loading ciphertext error: {e}"
                ))
            })?;

        /*
         * Perform the decapsulation of the received data to obtain the
         * shared secret.
         */
        kyber_x25519.decapsulate().map_err(|e| {
            Error::General(format!("lc:MLKEM-X25519: decapsulation error: {e}"))
        })?;

        /*
         * Extract the just calculated shared secrets and concatenate
         * both: first the ML-KEM followed by the X25519 shared secret.
         */
        let (ss_slice, ss_x25519_slice) = match kyber_x25519.get_ss() {
            Ok((ret1, ret2)) => (ret1, ret2),
            Err(e) => {
                return Err(Error::General(format!(
                    "lc:MLKEM-X25519 shared secret extraction error: {e}"
                )));
            }
        };
        let mut ss = vec![];
        ss.extend_from_slice(ss_slice);
        ss.extend_from_slice(ss_x25519_slice);

        Ok(SharedSecret::from(ss))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        self.group.named_group
    }
}
