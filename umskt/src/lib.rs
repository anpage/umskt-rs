//! # Universal MS Key Toolkit (UMSKT) Rust Edition Rust Edition
//!
//! This is an unofficial Rust port of the [UMSKT project](https://github.com/UMSKT/UMSKT/).
//!  It is a pure Rust implementation rather than a binding, so it does not require any C or
//! C++ dependencies and can be built for any platform supported by Rust and `std`.
//!
//! It does not include the required `keys.json` file used by UMSKT. That needs to be found elsewhere.
//!
//! See `README.md` for more information.
//!
pub mod confid;
pub mod crypto;
mod key;
mod math;
pub mod pidgen2;
pub mod pidgen3;
