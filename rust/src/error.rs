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
