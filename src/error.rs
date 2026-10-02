//! Error types for Rugra
//!
//! This module defines all error types used throughout the decompiler.
//! We use `thiserror` for ergonomic error handling.

use thiserror::Error;

/// Result type alias for Rugra operations
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for Rugra
#[derive(Error, Debug)]
pub enum Error {
    /// Low-level decompiler failure that aborts the current operation.
    #[error("{0}")]
    Lowlevel(String),

    /// Binary parsing errors
    #[error("Failed to parse binary: {0}")]
    BinaryParse(String),

    /// Binary format not supported
    #[error("Unsupported binary format: {0}")]
    UnsupportedFormat(String),

    /// No binary has been loaded
    #[error("No binary loaded")]
    NoBinaryLoaded,

    /// Invalid address
    #[error("Invalid address: 0x{0:x}")]
    InvalidAddress(u64),

    /// Address not found in binary
    #[error("Address not found: 0x{0:x}")]
    AddressNotFound(u64),

    /// Function not found
    #[error("Function not found at address: 0x{0:x}")]
    FunctionNotFound(u64),

    /// Disassembly errors
    #[error("Disassembly failed: {0}")]
    DisassemblyError(String),

    /// Architecture not supported
    #[error("Unsupported architecture: {0}")]
    UnsupportedArchitecture(String),

    /// P-code generation error
    #[error("P-code generation failed: {0}")]
    PcodeGeneration(String),

    /// Invalid P-code operation
    #[error("Invalid P-code operation: {0}")]
    InvalidPcode(String),

    /// Control flow analysis error
    #[error("Control flow analysis failed: {0}")]
    ControlFlowAnalysis(String),

    /// Data flow analysis error
    #[error("Data flow analysis failed: {0}")]
    DataFlowAnalysis(String),

    /// Type inference error
    #[error("Type inference failed: {0}")]
    TypeInference(String),

    /// SSA construction error
    #[error("SSA construction failed: {0}")]
    SSAConstruction(String),

    /// Code generation error
    #[error("Code generation failed: {0}")]
    CodeGeneration(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Generic error with context
    #[error("{0}")]
    Generic(String),

    /// Multiple errors occurred
    #[error("Multiple errors: {0:?}")]
    Multiple(Vec<Error>),
}

// Implement From for common error conversions

impl From<goblin::error::Error> for Error {
    // RUDRA-GLUE: from (no Ghidra counterpart found)
    fn from(err: goblin::error::Error) -> Self {
        Error::BinaryParse(err.to_string())
    }
}

impl From<String> for Error {
    // RUDRA-GLUE: from (no Ghidra counterpart found)
    fn from(msg: String) -> Self {
        Error::Generic(msg)
    }
}

impl From<&str> for Error {
    // RUDRA-GLUE: from (no Ghidra counterpart found)
    fn from(msg: &str) -> Self {
        Error::Generic(msg.to_string())
    }
}

/// Helper trait for adding context to errors
pub trait ErrorContext<T> {
    // RUDRA-GLUE: context (no Ghidra counterpart found)
    /// Add context to an error
    fn context(self, msg: impl Into<String>) -> Result<T>;

    // RUDRA-GLUE: with_context (no Ghidra counterpart found)
    /// Add context using a closure (lazy evaluation)
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String;
}

impl<T, E> ErrorContext<T> for std::result::Result<T, E>
where
    E: Into<Error>,
{
    // RUDRA-GLUE: context (no Ghidra counterpart found)
    fn context(self, msg: impl Into<String>) -> Result<T> {
        self.map_err(|e| {
            let base_error = e.into();
            Error::Generic(format!("{}: {}", msg.into(), base_error))
        })
    }

    // RUDRA-GLUE: with_context (no Ghidra counterpart found)
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| {
            let base_error = e.into();
            Error::Generic(format!("{}: {}", f(), base_error))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::InvalidAddress(0x1000);
        assert_eq!(err.to_string(), "Invalid address: 0x1000");
    }

    #[test]
    fn test_error_from_string() {
        let err: Error = "test error".into();
        assert!(matches!(err, Error::Generic(_)));
    }

    #[test]
    fn test_error_context() {
        let result: Result<()> = Err(Error::Generic("base".into()));
        let result = result.context("additional context");

        match result {
            Err(Error::Generic(msg)) => {
                assert!(msg.contains("additional context"));
                assert!(msg.contains("base"));
            }
            _ => panic!("Expected Generic error"),
        }
    }
}
