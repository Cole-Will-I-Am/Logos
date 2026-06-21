//! AUDIT PoC: server signing-key persistence (V5).
//!
//! A present-but-invalid key file must NOT be silently overwritten with a fresh
//! key — doing so rotates `server_vk` and breaks every client that pinned it.

use std::io::Write;

fn tmp(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("logos-keypoc-{}-{}", std::process::id(), name))
}

#[test]
fn poc_v5_invalid_key_file_is_silently_overwritten() {
    let path = tmp("corrupt-key");
    // Simulate a truncated / partially-written key file (wrong length).
    {
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&[0xAB; 31]).unwrap(); // 31 bytes, not 32
        f.flush().unwrap();
    }
    let before = std::fs::read(&path).unwrap();

    // Booting the relay against a present-but-invalid key file must FAIL rather
    // than silently overwrite it (which would rotate the signing key).
    let result = logos_server::new_state_at(
        path.to_str().unwrap(),
        std::env::temp_dir().to_str().unwrap(),
    );
    assert!(
        result.is_err(),
        "present-but-invalid key file should be a fatal startup error, not a silent rotation"
    );
    let after = std::fs::read(&path).unwrap();
    assert_eq!(
        before, after,
        "invalid key file must NOT be overwritten (signing key must not silently rotate)"
    );
}

#[test]
fn poc_v5_valid_key_file_is_preserved() {
    let path = tmp("valid-key");
    std::fs::write(&path, [0x07; 32]).unwrap();
    assert!(logos_server::new_state_at(
        path.to_str().unwrap(),
        std::env::temp_dir().to_str().unwrap()
    )
    .is_ok());
    // A valid 32-byte key is kept across boots.
    assert_eq!(std::fs::read(&path).unwrap(), vec![0x07; 32]);
}

#[test]
fn poc_v5_missing_key_file_is_generated_once() {
    let path = tmp("fresh-key");
    let _ = std::fs::remove_file(&path);
    assert!(logos_server::new_state_at(
        path.to_str().unwrap(),
        std::env::temp_dir().to_str().unwrap()
    )
    .is_ok());
    let first = std::fs::read(&path).unwrap();
    assert_eq!(first.len(), 32, "a fresh 32-byte key should be generated");
    // A second boot reuses the same key (stable server_vk).
    assert!(logos_server::new_state_at(
        path.to_str().unwrap(),
        std::env::temp_dir().to_str().unwrap()
    )
    .is_ok());
    assert_eq!(std::fs::read(&path).unwrap(), first);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "generated key file must be owner-only");
    }
}
