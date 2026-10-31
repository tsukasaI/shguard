//! The catalog loader: TOML text in, the kernel's [`Catalog`] and rules out.
//!
//! [`dto`] holds the serde shapes (adapters only), [`load`] turns them into
//! kernel values through the checked constructors and runs every semantic
//! check, [`error`] has the one error type of this seam, and [`embedded`]
//! the catalog files compiled into the binary.
//!
//! [`Catalog`]: shguard_kernel::catalog::Catalog

mod dto;
mod embedded;
mod error;
mod load;

pub use dto::AskOutcome;
pub use embedded::EMBEDDED;
pub use error::LoadError;
pub use load::{
    ConfigHead, Loaded, ParsedFile, Source, load, load_files, parse_config, parse_file,
};
