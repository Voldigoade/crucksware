#![no_main]

use std::fs;

use crucksware::{compare_semantic_tree, limits::Limits};
use libfuzzer_sys::fuzz_target;
use tempfile::TempDir;

const MAX_INPUT_BYTES: usize = 256 * 1024;
const MAX_SOURCE_BYTES: u64 = 3 * MAX_INPUT_BYTES as u64;
const MAX_BYTES_READ: u64 = 2 * MAX_SOURCE_BYTES + 64 * 1024;

thread_local! {
    static WORKSPACE: TempDir = tempfile::tempdir().expect("create fuzz workspace");
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let source = String::from_utf8_lossy(data)
        .chars()
        .map(|character| {
            if character.is_control() && !matches!(character, '\n' | '\r' | '\t') {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();

    WORKSPACE.with(|workspace| {
        let old_root = workspace.path().join("old");
        let new_root = workspace.path().join("new");
        let old_file = old_root.join("src/lib.rs");
        let new_file = new_root.join("src/lib.rs");
        fs::create_dir_all(old_file.parent().unwrap()).expect("create old source directory");
        fs::create_dir_all(new_file.parent().unwrap()).expect("create new source directory");
        fs::write(&old_file, "fn baseline() {}\n").expect("write baseline source");
        fs::write(&new_file, source).expect("write fuzz source");

        let limits = Limits {
            max_entries: 32,
            max_depth: 8,
            max_path_bytes: 4096,
            max_bytes_read: MAX_BYTES_READ,
        };
        let _ = compare_semantic_tree(&old_root, &new_root, limits, MAX_SOURCE_BYTES);
    });
});
