//! The Claude Code hook: reads the hook input, loads the configuration and
//! catalog, and renders the kernel's verdict as the hook output.

pub mod catalog;
pub mod config;
pub mod decision_log;
pub mod hook;
pub mod init;
pub mod respond;
