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

#[derive(Debug, PartialEq)]
pub enum HashError {
    AllocationError,
    UninitializedContext,
    ProcessingError,
}

impl std::error::Error for HashError {}

impl std::fmt::Display for HashError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            HashError::AllocationError => {
                write!(f, "failed to allocate hash context")
            }
            HashError::UninitializedContext => {
                write!(f, "hash context is not initialized")
            }
            HashError::ProcessingError => {
                write!(f, "hash processing error occurred")
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum SignatureError {
    AllocationError,
    UninitializedContext,
    ProcessingError,
    VerificationError,
}

impl std::error::Error for SignatureError {}

impl std::fmt::Display for SignatureError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            SignatureError::AllocationError => {
                write!(f, "failed to allocate signature context")
            }
            SignatureError::UninitializedContext => {
                write!(f, "Signature context is not initialized")
            }
            SignatureError::ProcessingError => {
                write!(f, "Signature processing error occurred")
            }
            SignatureError::VerificationError => {
                write!(f, "Signature signature verification failed")
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum KemError {
    AllocationError,
    UninitializedContext,
    ProcessingError,
}

impl std::error::Error for KemError {}

impl std::fmt::Display for KemError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            KemError::AllocationError => {
                write!(f, "failed to allocate KEM context")
            }
            KemError::UninitializedContext => {
                write!(f, "KEM context is not initialized")
            }
            KemError::ProcessingError => {
                write!(f, "KEM processing error occurred")
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum RngError {
    AllocationError,
    UninitializedContext,
    ProcessingError,
    NotSeeded,
}

impl std::error::Error for RngError {}

impl std::fmt::Display for RngError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            RngError::AllocationError => {
                write!(f, "failed to allocate RNG context")
            }
            RngError::UninitializedContext => {
                write!(f, "RNG context is not initialized")
            }
            RngError::ProcessingError => {
                write!(f, "RNG processing error occurred")
            }
            RngError::NotSeeded => write!(f, "RNG context is not seeded"),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum AeadError {
    AllocationError,
    UninitializedContext,
    ProcessingError,
    AuthenticationError,
}

impl std::error::Error for AeadError {}

impl std::fmt::Display for AeadError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            AeadError::AllocationError => {
                write!(f, "failed to allocate AEAD context")
            }
            AeadError::UninitializedContext => {
                write!(f, "AEAD context is not initialized")
            }
            AeadError::ProcessingError => {
                write!(f, "AEAD processing error occurred")
            }
            AeadError::AuthenticationError => {
                write!(f, "AEAD decryption authentication error")
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum SymError {
    AllocationError,
    UninitializedContext,
    ProcessingError,
    AuthenticationError,
}

impl std::error::Error for SymError {}

impl std::fmt::Display for SymError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            SymError::AllocationError => {
                write!(f, "failed to allocate Symmetric context")
            }
            SymError::UninitializedContext => {
                write!(f, "Symmetric context is not initialized")
            }
            SymError::ProcessingError => {
                write!(f, "Symmetric processing error occurred")
            }
            SymError::AuthenticationError => {
                write!(f, "Symmetric decryption authentication error")
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum X25519Error {
    AllocationError,
    UninitializedContext,
    ProcessingError,
    KeyRejectedError,
}

impl std::error::Error for X25519Error {}

impl std::fmt::Display for X25519Error {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            X25519Error::AllocationError => {
                write!(f, "failed to allocate XDH context")
            }
            X25519Error::UninitializedContext => {
                write!(f, "XDH context is not initialized")
            }
            X25519Error::ProcessingError => {
                write!(f, "XDH processing error occurred")
            }
            X25519Error::KeyRejectedError => {
                write!(f, "XDH key rejected error occurred")
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum X448Error {
    AllocationError,
    UninitializedContext,
    ProcessingError,
}

impl std::error::Error for X448Error {}

impl std::fmt::Display for X448Error {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            X448Error::AllocationError => {
                write!(f, "failed to allocate XDH context")
            }
            X448Error::UninitializedContext => {
                write!(f, "XDH context is not initialized")
            }
            X448Error::ProcessingError => {
                write!(f, "XDH processing error occurred")
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum KdfError {
    AllocationError,
    UninitializedContext,
    ProcessingError,
}

impl std::error::Error for KdfError {}

impl std::fmt::Display for KdfError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            KdfError::AllocationError => {
                write!(f, "failed to allocate HKDF context")
            }
            KdfError::UninitializedContext => {
                write!(f, "HKDF context is not initialized")
            }
            KdfError::ProcessingError => {
                write!(f, "HKDF processing error occurred")
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum X509Error {
    AllocationError,
    UninitializedContext,
    ProcessingError,
    VerifyError,
}

impl std::error::Error for X509Error {}

impl std::fmt::Display for X509Error {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            X509Error::AllocationError => {
                write!(f, "failed to allocate X509 context")
            }
            X509Error::UninitializedContext => {
                write!(f, "X.509 context is not initialized")
            }
            X509Error::ProcessingError => {
                write!(f, "X.509 processing error occurred")
            }
            X509Error::VerifyError => {
                write!(f, "X.509 signature verification error")
            }
        }
    }
}
