use std::{error::Error, fs};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

use crucksware::{
    input::InputKind,
    inspection::{ContentKind, DEFAULT_MAX_BYTES_READ, inspect_file},
};

#[test]
fn reports_basic_facts_for_unknown_binary_files_without_changing_them() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("payload.dat");
    let contents = b"\0\x80firmware";
    fs::write(&path, contents).unwrap();

    let inspection = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap();

    assert_eq!(inspection.kind, InputKind::UnknownBinary);
    assert_eq!(inspection.content, ContentKind::Binary);
    assert_eq!(inspection.size_bytes, contents.len() as u64);
    assert_eq!(fs::read(path).unwrap(), contents);
}

#[test]
fn identifies_text_from_the_bounded_sample_and_reports_file_size() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("notes.txt");
    fs::write(&path, b"a readable note\n").unwrap();

    let inspection = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap();

    assert_eq!(inspection.kind, InputKind::Text);
    assert_eq!(inspection.content, ContentKind::Text);
    assert_eq!(inspection.size_bytes, 16);
}

#[test]
fn rejects_directories_and_reports_missing_inputs() {
    let temporary = tempfile::tempdir().unwrap();
    let directory_error = inspect_file(temporary.path(), DEFAULT_MAX_BYTES_READ).unwrap_err();
    let missing_error =
        inspect_file(&temporary.path().join("missing"), DEFAULT_MAX_BYTES_READ).unwrap_err();

    assert!(
        directory_error
            .to_string()
            .contains("unsupported input type")
    );
    assert!(missing_error.to_string().contains("inspect input"));
    assert!(missing_error.source().is_some());
}

#[test]
fn enforces_the_actual_read_budget() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("long.txt");
    fs::write(&path, vec![b'a'; 32]).unwrap();

    let error = inspect_file(&path, 4).unwrap_err();

    assert!(error.to_string().contains("bytes read limit exceeded"));
}

#[test]
fn pe_signature_outside_the_sample_uses_the_remaining_read_budget() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("candidate.bin");
    let mut contents = vec![0; 8_196];
    contents[..2].copy_from_slice(b"MZ");
    contents[0x3c..0x40].copy_from_slice(&8_192_u32.to_le_bytes());
    contents[8_192..].copy_from_slice(b"PE\0\0");
    fs::write(&path, contents).unwrap();

    let error = inspect_file(&path, 8_196).unwrap_err();
    assert!(error.to_string().contains("invalid PE input"));

    let error = inspect_file(&path, 8_195).unwrap_err();
    assert!(error.to_string().contains("bytes read limit exceeded"));
}

#[test]
#[cfg(unix)]
fn inspects_files_with_non_utf8_paths() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary
        .path()
        .join(std::ffi::OsStr::from_bytes(b"data-\xff"));
    fs::write(&path, b"bytes").unwrap();

    let inspection = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap();

    assert_eq!(inspection.kind, InputKind::Text);
    assert_eq!(inspection.size_bytes, 5);
}

#[test]
fn deterministic_unrecognized_binary_inputs_do_not_panic() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("random-input");
    let mut state = 0x6a09_e667_f3bc_c909_u64;

    for sample in 0..256 {
        let length = sample * 17 % 2_049;
        let mut bytes = Vec::with_capacity(length);
        while bytes.len() < length {
            bytes.extend_from_slice(&next_random(&mut state).to_le_bytes());
        }
        bytes.truncate(length);
        if bytes.starts_with(b"\x7fELF") || bytes.starts_with(b"MZ") {
            bytes[0] = b'X';
        }
        fs::write(&path, &bytes).unwrap();

        let outcome = std::panic::catch_unwind(|| inspect_file(&path, DEFAULT_MAX_BYTES_READ));
        let inspection = outcome
            .unwrap_or_else(|_| panic!("inspection panicked for sample {sample}"))
            .unwrap();

        assert!(matches!(
            inspection.kind,
            InputKind::Text | InputKind::UnknownBinary
        ));
        assert_eq!(inspection.size_bytes, length as u64);
    }
}

fn next_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
