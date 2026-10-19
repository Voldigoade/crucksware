#![no_main]

use std::fs;

use crucksware::inspection::inspect_file_with_limits;
use libfuzzer_sys::fuzz_target;
use tempfile::TempDir;

const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_ENTRIES: u64 = 4096;

thread_local! {
    static WORKSPACE: TempDir = tempfile::tempdir().expect("create fuzz workspace");
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    WORKSPACE.with(|workspace| {
        let path = workspace.path().join("input");
        fs::write(&path, data).expect("write fuzz input");
        let _ = inspect_file_with_limits(&path, MAX_INPUT_BYTES as u64, MAX_ENTRIES);
    });
});
