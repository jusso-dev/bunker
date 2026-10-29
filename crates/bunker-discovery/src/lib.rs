//! Agent setup discovery. No implicit environment reads, hook installation, or network I/O.
//! Callers supply roots and must snapshot `PreparedFile::bytes`, never reread source paths.

mod adapters;
mod safety;
mod sanitize;

pub use adapters::*;
pub use safety::*;
pub use sanitize::*;
