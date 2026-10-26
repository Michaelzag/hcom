//! Platform-abstraction layer.
//!
//! Every OS-specific primitive the rest of hcom needs lives behind this module
//! so call sites never touch `nix`, `libc`, `std::os::unix`, or Windows APIs
//! directly. Each capability is a thin, platform-neutral function API; the
//! per-OS implementation is selected inline with `#[cfg]`. This turns the
//! historically scattered `#[cfg]` blocks into a single, auditable boundary and
//! keeps Unix and Windows behavior side by side.

pub mod fs;
pub mod io;
pub(crate) mod kill_group;
#[cfg(any(target_os = "macos", test))]
mod kill_tree_apple;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) mod kill_tree_linux;
pub mod net;
pub mod process;
pub(crate) mod process_args;
pub(crate) mod seat_root;
pub mod signal;
