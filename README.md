# Universal MS Key Toolkit (UMSKT) Rust Edition

This is an unofficial Rust port of the [UMSKT project](https://github.com/UMSKT/UMSKT/). It is a pure Rust implementation rather than a binding, so it does not require any C or C++ dependencies and can be built for any platform supported by Rust and std.

It does not include the required keys.json file used by UMSKT. That needs to be found elsewhere, most likely in the UMSKT codebase.

## Credits
These contributors helped create the UMSKT project that this codebase was based on:
* z22
* MSKey
* sk00ter
* diamondggg
* pottzman
* Endermanch
* Neo-Desktop
* WitherOrNot
* TheTank20

## Development Requirements
* [The Rust toolchain](https://rustup.rs/)

## Build Steps
1. `cargo build`