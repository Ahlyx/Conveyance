//! Bindgen entry point, kept in-crate so the generator and the UniFFI
//! runtime compiled into the `.so` are always the same version.
//!
//! Usage (library mode — no UDL):
//!   cargo run -p conveyance-crypto-ffi --bin uniffi-bindgen -- \
//!     generate --library <path/to/libconveyance_crypto_ffi.so> \
//!     --language kotlin --out-dir <dir>

fn main() {
    uniffi::uniffi_bindgen_main()
}
