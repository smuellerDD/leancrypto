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
			HashError::AllocationError => write!(f, "failed to allocate hash context"),
			HashError::UninitializedContext => write!(f, "hash context is not initialized"),
			HashError::ProcessingError => write!(f, "hash processing error occurred"),
		}
	}
}

#[derive(Debug)]
#[derive(PartialEq)]
pub enum DilithiumError {
	AllocationError,
	UninitializedContext,
	ProcessingError,
	VerificationError,
}

impl std::error::Error for DilithiumError {}

impl std::fmt::Display for DilithiumError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			DilithiumError::AllocationError => write!(f, "failed to allocate dilithium context"),
			DilithiumError::UninitializedContext => write!(f, "Dilithium context is not initialized"),
			DilithiumError::ProcessingError => write!(f, "Dilithium processing error occurred"),
			DilithiumError::VerificationError => write!(f, "Dilithium signature verification failed"),
		}
	}
}
