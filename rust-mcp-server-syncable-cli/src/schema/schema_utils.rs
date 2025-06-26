// src/schema/schema_utils.rs

use std::fmt;

/// An error returned when calling a tool fails.
pub struct CallToolError(Box<dyn std::error::Error + Send + Sync + 'static>);

impl CallToolError {
    /// Wrap any `Error + Send + Sync + 'static` into a `CallToolError`.
    pub fn new<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        CallToolError(Box::new(e))
    }
}

impl fmt::Debug for CallToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&*self.0, f)
    }
}

impl fmt::Display for CallToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&*self.0, f)
    }
}

impl std::error::Error for CallToolError {}
