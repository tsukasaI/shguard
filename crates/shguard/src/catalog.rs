//! The catalog loader: TOML text in, the kernel's [`Catalog`] and rules out.
//!
//! [`dto`] holds the serde shapes (adapters only), [`load`] turns them into
//! kernel values through the checked constructors and runs every semantic
//! check, and [`error`] has the one error type of this seam.
//!
//! [`Catalog`]: shguard_kernel::catalog::Catalog

mod dto;
mod error;
mod load;

pub use error::LoadError;
pub use load::{Loaded, Source, load};
