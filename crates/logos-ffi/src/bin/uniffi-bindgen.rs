//! UniFFI binding generator entrypoint. Generate Swift bindings (on Linux) with:
//!   cargo run -p logos-ffi --bin uniffi-bindgen -- \
//!     generate --library target/debug/liblogos_ffi.so --language swift --out-dir bindings
fn main() {
    uniffi::uniffi_bindgen_main()
}
