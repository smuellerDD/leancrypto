/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#[derive(Debug)]
#[derive(PartialEq)]
pub enum HashError {
	AllocationError,
	UninitializedContext,
	ProcessingError,
}

impl std::error::Error for HashError {}

impl std::fmt::Display for HashError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			HashError::AllocationError =>
				write!(f, "failed to allocate hash context"),
			HashError::UninitializedContext =>
				write!(f, "hash context is not initialized"),
			HashError::ProcessingError =>
				write!(f, "hash processing error occurred"),
		}
	}
}

#[derive(Debug)]
#[derive(PartialEq)]
pub enum SignatureError {
	AllocationError,
	UninitializedContext,
	ProcessingError,
	VerificationError,
}

impl std::error::Error for SignatureError {}

impl std::fmt::Display for SignatureError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			SignatureError::AllocationError =>
				write!(f, "failed to allocate signature context"),
			SignatureError::UninitializedContext =>
				write!(f, "Signature context is not initialized"),
			SignatureError::ProcessingError =>
				write!(f, "Signature processing error occurred"),
			SignatureError::VerificationError =>
				write!(f, "Signature signature verification failed"),
		}
	}
}

#[derive(Debug)]
#[derive(PartialEq)]
pub enum KemError {
	AllocationError,
	UninitializedContext,
	ProcessingError,
}

impl std::error::Error for KemError {}

impl std::fmt::Display for KemError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			KemError::AllocationError =>
				write!(f, "failed to allocate KEM context"),
			KemError::UninitializedContext =>
				write!(f, "KEM context is not initialized"),
			KemError::ProcessingError =>
				write!(f, "KEM processing error occurred"),
		}
	}
}

#[derive(Debug)]
#[derive(PartialEq)]
pub enum RngError {
	AllocationError,
	UninitializedContext,
	ProcessingError,
	NotSeeded,
}

impl std::error::Error for RngError {}

impl std::fmt::Display for RngError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			RngError::AllocationError =>
				write!(f, "failed to allocate RNG context"),
			RngError::UninitializedContext =>
				write!(f, "RNG context is not initialized"),
			RngError::ProcessingError =>
				write!(f, "RNG processing error occurred"),
			RngError::NotSeeded =>
				write!(f, "RNG context is not seeded"),
		}
	}
}

#[derive(Debug)]
#[derive(PartialEq)]
pub enum AeadError {
	AllocationError,
	UninitializedContext,
	ProcessingError,
	AuthenticationError,
}

impl std::error::Error for AeadError {}

impl std::fmt::Display for AeadError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			AeadError::AllocationError =>
				write!(f, "failed to allocate AEAD context"),
			AeadError::UninitializedContext =>
				write!(f, "AEAD context is not initialized"),
			AeadError::ProcessingError =>
				write!(f, "AEAD processing error occurred"),
			AeadError::AuthenticationError =>
				write!(f, "AEAD decryption authentication error"),
		}
	}
}

#[derive(Debug)]
#[derive(PartialEq)]
pub enum SymError {
	AllocationError,
	UninitializedContext,
	ProcessingError,
	AuthenticationError
}

impl std::error::Error for SymError {}

impl std::fmt::Display for SymError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			SymError::AllocationError =>
				write!(f, "failed to allocate Symmetric context"),
			SymError::UninitializedContext =>
				write!(f, "Symmetric context is not initialized"),
			SymError::ProcessingError =>
				write!(f, "Symmetric processing error occurred"),
			SymError::AuthenticationError =>
				write!(f, "Symmetric decryption authentication error"),
		}
	}
}
