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

use leancrypto_sys::lcr_hash::{lcr_hash, lcr_hash_type};
use rustls::Error;
use rustls::crypto::hash::HashAlgorithm;
use rustls::crypto::{self};

pub(crate) static SHA256: Hash =
    Hash(lcr_hash_type::lcr_sha2_256, HashAlgorithm::SHA256, 32);
pub(crate) static SHA384: Hash =
    Hash(lcr_hash_type::lcr_sha2_384, HashAlgorithm::SHA384, 48);

pub(crate) struct Hash(lcr_hash_type, HashAlgorithm, usize);

impl crypto::hash::Hash for Hash {
    // Initialize the Hash context
    fn start(&self) -> Box<dyn crypto::hash::Context> {
        let mut hash = lcr_hash::new(self.0);
        let _ = hash.init();
        Box::new(Context(hash))
    }

    // One-shot digest calculation
    fn hash(
        &self,
        bytes: &[u8],
    ) -> crypto::hash::Output {
        let mut ctx = lcr_hash::new(self.0);
        let _ = ctx.init().map_err(|e| {
            Error::General(format!("lc:Hash: initalization error: {e}"))
        });
        let _ = ctx
            .update(bytes)
            .map_err(|e| Error::General(format!("lc:Hash: update error: {e}")));

        let mut digest = vec![0u8; ctx.digestsize()];
        let _ = ctx.fini(&mut digest).map_err(|e| {
            Error::General(format!("lc:Hash: finalization error: {e}"))
        });
        convert(digest)
    }

    fn output_len(&self) -> usize {
        self.2
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.1
    }

    fn fips(&self) -> bool {
        crate::fips::enabled()
    }
}

struct Context(lcr_hash);

impl crypto::hash::Context for Context {
    // Duplicate the state and calculate digest on the state
    fn fork_finish(&self) -> crypto::hash::Output {
        let mut ctx = self.0.clone();
        let mut digest = vec![0u8; ctx.digestsize()];
        let _ = ctx.fini(&mut digest).map_err(|e| {
            Error::General(format!("lc:Hash: finalization error: {e}"))
        });
        convert(digest)
    }

    // Duplicate the state
    fn fork(&self) -> Box<dyn crypto::hash::Context> {
        Box::new(Self(self.0.clone()))
    }

    // Calculate digest on the state
    fn finish(self: Box<Self>) -> crypto::hash::Output {
        let mut ctx = self.0;
        let mut digest = vec![0u8; ctx.digestsize()];
        let _ = ctx.fini(&mut digest).map_err(|e| {
            Error::General(format!("lc:Hash: finalization error: {e}"))
        });
        convert(digest)
    }

    // Hash update
    fn update(
        &mut self,
        data: &[u8],
    ) {
        let _ = self
            .0
            .update(data)
            .map_err(|e| Error::General(format!("lc:Hash: update error: {e}")));
    }
}

fn convert(val: Vec<u8>) -> crypto::hash::Output {
    crypto::hash::Output::new(val.as_ref())
}
