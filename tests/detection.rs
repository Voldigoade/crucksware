use std::{error::Error, fs};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

use crucksware::input::{InputKind, detect_input};

#[test]
fn detects_directories_without_considering_their_name() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("rootfs.exe");
    fs::create_dir(&directory).unwrap();

    assert_eq!(detect_input(&directory).unwrap(), InputKind::Directory);
}

#[test]
fn detects_elf_magic_without_requiring_a_file_extension_or_complete_header() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("program.data");
    fs::write(&path, b"\x7fELF").unwrap();

    assert_eq!(detect_input(&path).unwrap(), InputKind::Elf);
}

#[test]
fn detects_pe_from_its_dos_offset_and_signature() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("payload.bin");
    let mut bytes = vec![0; 68];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&64_u32.to_le_bytes());
    bytes[64..68].copy_from_slice(b"PE\0\0");
    fs::write(&path, bytes).unwrap();

    assert_eq!(detect_input(&path).unwrap(), InputKind::Pe);
}

#[test]
fn detects_pe_signatures_beyond_the_text_sample() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("image");
    let offset = 9_000_usize;
    let mut bytes = vec![0; offset + 4];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&u32::try_from(offset).unwrap().to_le_bytes());
    bytes[offset..].copy_from_slice(b"PE\0\0");
    fs::write(&path, bytes).unwrap();

    assert_eq!(detect_input(&path).unwrap(), InputKind::Pe);
}

#[test]
fn rejects_a_dos_header_whose_pe_signature_is_out_of_bounds() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("program.exe");
    let mut bytes = vec![0; 64];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(&path, bytes).unwrap();

    assert_eq!(detect_input(&path).unwrap(), InputKind::UnknownBinary);
}

#[test]
fn text_and_unknown_binary_classification_uses_content_not_extensions() {
    let temp = tempfile::tempdir().unwrap();
    let text = temp.path().join("program.exe");
    let binary = temp.path().join("notes.txt");
    fs::write(&text, b"fn main() {}\n").unwrap();
    fs::write(&binary, b"\0\xff\x10\x80").unwrap();

    assert_eq!(detect_input(&text).unwrap(), InputKind::Text);
    assert_eq!(detect_input(&binary).unwrap(), InputKind::UnknownBinary);
}

#[test]
fn rejects_incomplete_utf8_at_the_end_of_a_short_file() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("truncated-text");
    fs::write(&path, [0xc3]).unwrap();

    assert_eq!(detect_input(&path).unwrap(), InputKind::UnknownBinary);
}

#[test]
fn tolerates_a_utf8_character_split_at_the_sample_boundary() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("split-text");
    let mut bytes = vec![b'a'; 8_191];
    bytes.extend_from_slice("é".as_bytes());
    fs::write(&path, bytes).unwrap();

    assert_eq!(detect_input(&path).unwrap(), InputKind::Text);
}

#[test]
#[cfg(unix)]
fn input_errors_preserve_io_sources_and_encode_non_utf8_paths() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp
        .path()
        .join(std::ffi::OsStr::from_bytes(b"missing\xff"));

    let error = detect_input(&path).unwrap_err();

    assert!(error.to_string().contains("missing%FF"));
    assert!(error.source().is_some());
}
