use std::fs;

use crucksware::{
    binary_compare::{SemanticComparisonStatus, compare_files, compare_files_with_progress},
    input::InputKind,
    inspection::{DEFAULT_MAX_BYTES_READ, DEFAULT_MAX_ENTRIES, inspect_file_with_progress},
    progress::{ProgressEvent, ProgressPhase},
};

mod common;

#[test]
fn compares_unknown_files_exactly_without_inventing_semantics() {
    let temporary = tempfile::tempdir().unwrap();
    let old = temporary.path().join("old.bin");
    let new = temporary.path().join("new.bin");
    fs::write(&old, b"\0abc").unwrap();
    fs::write(&new, b"\0abd").unwrap();

    let comparison = compare_files(&old, &new, 16, 100).unwrap();

    assert_eq!(comparison.old_kind, InputKind::UnknownBinary);
    assert_eq!(comparison.new_kind, InputKind::UnknownBinary);
    assert!(comparison.bytes_changed);
    assert_eq!(
        comparison.semantic_status,
        SemanticComparisonStatus::Unsupported
    );
    assert!(comparison.semantic_changes.is_empty());
}

#[test]
fn identical_files_consume_one_shared_read_budget_exactly() {
    let temporary = tempfile::tempdir().unwrap();
    let old = temporary.path().join("old.bin");
    let new = temporary.path().join("new.bin");
    fs::write(&old, b"same").unwrap();
    fs::write(&new, b"same").unwrap();

    let comparison = compare_files(&old, &new, 16, 100).unwrap();

    assert!(!comparison.bytes_changed);
}

#[test]
fn file_comparison_progress_reports_real_bytes_in_bounded_batches() {
    let temporary = tempfile::tempdir().unwrap();
    let old = temporary.path().join("old.bin");
    let new = temporary.path().join("new.bin");
    let mut data = vec![b'x'; 256 * 1024];
    data[0] = 0;
    fs::write(&old, &data).unwrap();
    fs::write(&new, &data).unwrap();
    let mut events = Vec::new();

    let comparison =
        compare_files_with_progress(&old, &new, 600_000, 100, |event| events.push(event)).unwrap();

    assert!(!comparison.bytes_changed);
    assert_eq!(comparison.bytes_read, (data.len() * 2 + 2 * 8_192) as u64);
    let reported_bytes: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            ProgressEvent::BytesRead { total_bytes_read } => Some(*total_bytes_read),
            _ => None,
        })
        .collect();
    assert!(reported_bytes.windows(2).all(|pair| pair[0] <= pair[1]));
    assert_eq!(reported_bytes.last(), Some(&comparison.bytes_read));
    assert_eq!(
        events.first(),
        Some(&ProgressEvent::PhaseStarted {
            phase: ProgressPhase::FileComparison,
            total: None,
        })
    );
    assert_eq!(
        events.last(),
        Some(&ProgressEvent::PhaseCompleted {
            phase: ProgressPhase::FileComparison,
        })
    );
}

#[test]
fn file_comparison_progress_byte_count_is_cumulative_across_inputs() {
    let temporary = tempfile::tempdir().unwrap();
    let old = temporary.path().join("old-elf");
    let new = temporary.path().join("new-text");
    let mut old_contents = common::minimal_elf64(0x401000);
    old_contents.resize(256 * 1024, 0);
    fs::write(&old, old_contents).unwrap();
    fs::write(&new, b"short text input").unwrap();
    let mut events = Vec::new();

    let comparison = compare_files_with_progress(
        &old,
        &new,
        DEFAULT_MAX_BYTES_READ,
        DEFAULT_MAX_ENTRIES,
        |event| events.push(event),
    )
    .unwrap();

    let reported_bytes: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            ProgressEvent::BytesRead { total_bytes_read } => Some(*total_bytes_read),
            _ => None,
        })
        .collect();
    assert!(reported_bytes.windows(2).all(|pair| pair[0] <= pair[1]));
    assert_eq!(reported_bytes.last(), Some(&comparison.bytes_read));
}

#[test]
fn inspection_progress_reports_actual_bytes_while_reading_a_known_format() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("large-elf");
    let mut contents = common::minimal_elf64(0x401000);
    contents.resize(256 * 1024, 0);
    fs::write(&path, contents).unwrap();
    let mut events = Vec::new();

    let inspection = inspect_file_with_progress(
        &path,
        DEFAULT_MAX_BYTES_READ,
        DEFAULT_MAX_ENTRIES,
        |event| events.push(event),
    )
    .unwrap();

    let reported_bytes: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            ProgressEvent::BytesRead { total_bytes_read } => Some(*total_bytes_read),
            _ => None,
        })
        .collect();
    assert!(reported_bytes.len() > 3);
    assert!(reported_bytes.windows(2).all(|pair| pair[0] <= pair[1]));
    assert_eq!(reported_bytes.last(), Some(&inspection.bytes_read));
    assert_eq!(
        events.first(),
        Some(&ProgressEvent::PhaseStarted {
            phase: ProgressPhase::Inspection,
            total: None,
        })
    );
    assert_eq!(
        events.last(),
        Some(&ProgressEvent::PhaseCompleted {
            phase: ProgressPhase::Inspection,
        })
    );
}

#[test]
fn file_comparison_fails_when_shared_read_budget_is_too_small() {
    let temporary = tempfile::tempdir().unwrap();
    let old = temporary.path().join("old.bin");
    let new = temporary.path().join("new.bin");
    fs::write(&old, b"same").unwrap();
    fs::write(&new, b"same").unwrap();

    let error = compare_files(&old, &new, 15, 100).unwrap_err();

    assert!(error.to_string().contains("bytes read limit exceeded (15)"));
}

#[test]
fn differing_file_sizes_need_no_content_reads_after_inspection() {
    let temporary = tempfile::tempdir().unwrap();
    let old = temporary.path().join("old.bin");
    let new = temporary.path().join("new.bin");
    fs::write(&old, b"x").unwrap();
    fs::write(&new, b"longer").unwrap();

    let comparison = compare_files(&old, &new, 7, 100).unwrap();

    assert!(comparison.bytes_changed);
    assert_eq!(comparison.old_size_bytes, 1);
    assert_eq!(comparison.new_size_bytes, 6);
}

#[test]
fn compares_elf_bytes_and_reports_semantic_fact_changes() {
    let temporary = tempfile::tempdir().unwrap();
    let old = temporary.path().join("old-elf");
    let new = temporary.path().join("new-elf");
    fs::write(&old, common::minimal_elf64(0x401000)).unwrap();
    fs::write(&new, common::minimal_elf64(0x402000)).unwrap();

    let comparison = compare_files(&old, &new, 256, 100).unwrap();

    assert!(comparison.bytes_changed);
    assert_eq!(
        comparison.semantic_status,
        SemanticComparisonStatus::Compared
    );
    assert_eq!(comparison.semantic_changes.len(), 1);
    assert_eq!(comparison.semantic_changes[0].field, "entry_point");
    assert_eq!(fs::read(&old).unwrap(), common::minimal_elf64(0x401000));
    assert_eq!(fs::read(&new).unwrap(), common::minimal_elf64(0x402000));
}

#[test]
fn semantic_entry_limit_is_shared_across_both_files() {
    let temporary = tempfile::tempdir().unwrap();
    let old = temporary.path().join("old-elf");
    let new = temporary.path().join("new-elf");
    fs::write(&old, elf_with_one_segment()).unwrap();
    fs::write(&new, elf_with_one_segment()).unwrap();

    let error = compare_files(&old, &new, 480, 1).unwrap_err();

    assert!(error.to_string().contains("ELF entries limit exceeded (0)"));
}

#[test]
fn compares_pe_bytes_and_reports_semantic_fact_changes() {
    let temporary = tempfile::tempdir().unwrap();
    let old = temporary.path().join("old-pe");
    let new = temporary.path().join("new-pe");
    fs::write(&old, common::minimal_pe64(0x1000)).unwrap();
    fs::write(&new, common::minimal_pe64(0x2000)).unwrap();

    let comparison = compare_files(&old, &new, 4_096, 2).unwrap();

    assert!(comparison.bytes_changed);
    assert_eq!(comparison.old_kind, InputKind::Pe);
    assert_eq!(
        comparison.semantic_status,
        SemanticComparisonStatus::Compared
    );
    assert_eq!(comparison.semantic_changes.len(), 1);
    assert_eq!(comparison.semantic_changes[0].field, "entry_point_rva");
}

#[test]
fn reports_different_known_formats_without_cross_format_fact_changes() {
    let temporary = tempfile::tempdir().unwrap();
    let elf = temporary.path().join("program-elf");
    let pe = temporary.path().join("program-pe");
    fs::write(&elf, common::minimal_elf64(0x401000)).unwrap();
    fs::write(&pe, common::minimal_pe64(0x1000)).unwrap();

    let comparison = compare_files(&elf, &pe, 1_088, 1).unwrap();

    assert_eq!(
        comparison.semantic_status,
        SemanticComparisonStatus::FormatMismatch
    );
    assert!(comparison.semantic_changes.is_empty());
    assert!(comparison.bytes_changed);
}

fn elf_with_one_segment() -> Vec<u8> {
    let mut bytes = common::minimal_elf64(0x401000);
    bytes.resize(120, 0);
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
    bytes
}
