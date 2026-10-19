#![no_main]

use std::fs;

use crucksware::binary_compare::compare_files;
use libfuzzer_sys::fuzz_target;
use tempfile::TempDir;

const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_ENTRIES: u64 = 4096;
const MAX_BYTES_READ: u64 = 2 * MAX_INPUT_BYTES as u64;

thread_local! {
    static WORKSPACE: TempDir = tempfile::tempdir().expect("create fuzz workspace");
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES || data.len() < 4 {
        return;
    }

    let payload = &data[4..];
    let requested_split =
        u32::from_le_bytes(data[..4].try_into().expect("four-byte split prefix")) as usize;
    let split = requested_split % (payload.len() + 1);

    WORKSPACE.with(|workspace| {
        let old_path = workspace.path().join("old");
        let new_path = workspace.path().join("new");
        fs::write(&old_path, &payload[..split]).expect("write old fuzz input");
        fs::write(&new_path, &payload[split..]).expect("write new fuzz input");
        let _ = compare_files(&old_path, &new_path, MAX_BYTES_READ, MAX_ENTRIES);
    });
});
