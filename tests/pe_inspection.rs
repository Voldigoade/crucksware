use std::fs;

use crucksware::inspection::inspect_file_with_limits;
use crucksware::{
    binary_compare::compare_files,
    inspection::{DEFAULT_MAX_BYTES_READ, MAX_PE_FILE_BYTES, inspect_file},
    report,
};

#[test]
fn inspects_pe32_plus_structure_without_using_the_extension() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("program.data");
    fs::write(&path, pe_image(true, None)).unwrap();

    let inspection = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap();
    let mut output = Vec::new();
    report::inspection::write_inspection(&inspection, &mut output).unwrap();
    let output = String::from_utf8(output).unwrap();

    assert!(output.contains("Detected kind: PE32+\n"));
    assert!(output.contains("PE structural inspection: performed\n"));
    assert!(output.contains("Architecture: X86_64\n"));
    assert!(output.contains("Machine: 0x8664\n"));
    assert!(output.contains("Entry point RVA: 0x1010\n"));
    assert!(output.contains("Image base: 0x140000000\n"));
    assert!(output.contains("Subsystem: WINDOWS_CUI (3)\n"));
    assert!(output.contains("Section .text"));
    assert!(output.contains("EXECUTE"));
    assert!(output.contains("Certificate table: absent\n"));
}

#[test]
fn inspects_pe32_and_reports_certificate_table_location_without_trusting_it() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("program.exe");
    fs::write(&path, pe_image(false, Some((0x3e0, 16)))).unwrap();

    let inspection = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap();
    let mut output = Vec::new();
    report::inspection::write_inspection(&inspection, &mut output).unwrap();
    let output = String::from_utf8(output).unwrap();

    assert!(output.contains("Detected kind: PE32\n"));
    assert!(output.contains("Architecture: I386\n"));
    assert!(output.contains("Image base: 0x400000\n"));
    assert!(output.contains("Certificate table: present at file offset 0x3e0 (16 bytes)\n"));
    assert!(!output.to_ascii_lowercase().contains("signature valid"));
    assert!(!output.to_ascii_lowercase().contains("trusted"));
}

#[test]
fn rejects_truncated_pe_candidates_without_a_partial_inspection() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("not-an-executable");
    let mut bytes = vec![0; 0x84];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    fs::write(&path, bytes).unwrap();

    let result = inspect_file(&path, DEFAULT_MAX_BYTES_READ);

    assert!(result.unwrap_err().to_string().contains("invalid PE input"));
}

#[test]
fn pe_inspection_respects_the_configured_full_file_read_limit() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("program.exe");
    fs::write(&path, pe_image(true, None)).unwrap();

    let error = inspect_file(&path, 512).unwrap_err();

    assert!(error.to_string().contains("bytes read limit exceeded"));
}

#[test]
fn inspection_restores_the_stream_after_a_pe_signature_probe_past_the_sample() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("large-dos-stub");
    let contents = pe_image_at(true, None, 0x3000);
    let size = contents.len() as u64;
    fs::write(&path, contents).unwrap();

    let inspection = inspect_file(&path, size).unwrap();

    assert_eq!(inspection.pe.unwrap().format, "PE32+");
}

#[test]
fn malformed_certificate_and_section_ranges_fail_without_partial_facts() {
    let temporary = tempfile::tempdir().unwrap();
    let certificate_path = temporary.path().join("invalid-certificate.exe");
    fs::write(&certificate_path, pe_image(true, Some((0x3f0, 0x40)))).unwrap();
    let error = inspect_file(&certificate_path, DEFAULT_MAX_BYTES_READ).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("invalid PE certificate table range")
    );

    let section_path = temporary.path().join("invalid-section.exe");
    let mut section = pe_image(true, None);
    let section_header = 0x80 + 4 + 20 + 240;
    section[section_header + 20..section_header + 24].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(&section_path, section).unwrap();
    let error = inspect_file(&section_path, DEFAULT_MAX_BYTES_READ).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("PE section data exceeds the file")
    );
}

#[test]
fn malformed_imports_and_cyclic_resources_fail_cleanly() {
    let temporary = tempfile::tempdir().unwrap();
    let import_path = temporary.path().join("invalid-import.exe");
    let mut imports = pe_with_tables();
    let import_directory = 0x80 + 4 + 20 + 112 + 8;
    imports[import_directory..import_directory + 4].copy_from_slice(&0xffff_0000_u32.to_le_bytes());
    fs::write(&import_path, imports).unwrap();
    let error = inspect_file(&import_path, DEFAULT_MAX_BYTES_READ).unwrap_err();
    assert!(error.to_string().contains("invalid PE input"));

    let resource_path = temporary.path().join("cyclic-resource.exe");
    let mut resources = pe_with_tables();
    let resource_directory = 0x80 + 4 + 20 + 112 + 2 * 8;
    resources[resource_directory..resource_directory + 4]
        .copy_from_slice(&0x1160_u32.to_le_bytes());
    let resource_root = 0x200 + 0x160;
    resources[resource_root + 20..resource_root + 24]
        .copy_from_slice(&0x8000_0000_u32.to_le_bytes());
    fs::write(&resource_path, resources).unwrap();
    let error = inspect_file(&resource_path, DEFAULT_MAX_BYTES_READ).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("cyclic or shared PE resource table")
    );
}

#[test]
fn rejects_pe_files_above_the_hard_size_limit_before_reading_the_body() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("large.exe");
    fs::write(&path, pe_image(true, None)).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(MAX_PE_FILE_BYTES + 1)
        .unwrap();

    let error = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap_err();

    assert!(error.to_string().contains("PE file size limit exceeded"));
}

#[test]
fn pe_semantic_records_share_the_entry_limit() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("tables.exe");
    fs::write(&path, pe_with_tables()).unwrap();

    let error = inspect_file_with_limits(&path, DEFAULT_MAX_BYTES_READ, 1).unwrap_err();

    assert!(error.to_string().contains("PE entries limit exceeded (1)"));
}

#[test]
fn reports_codeview_path_guid_and_age_as_debug_metadata() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("debug.exe");
    fs::write(&path, pe_with_codeview()).unwrap();

    let inspection = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap();
    let mut output = Vec::new();
    report::inspection::write_inspection(&inspection, &mut output).unwrap();
    let output = String::from_utf8(output).unwrap();

    assert!(output.contains("PDB path: C%3A%5Cbuild%5Capp.pdb"));
    assert!(output.contains("PDB GUID: 000102030405060708090a0b0c0d0e0f"));
    assert!(output.contains("PDB age: 3"));
}

#[test]
fn reports_imports_delay_imports_exports_and_resource_metadata() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("tables.exe");
    fs::write(&path, pe_with_tables()).unwrap();

    let inspection = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap();
    let mut output = Vec::new();
    report::inspection::write_inspection(&inspection, &mut output).unwrap();
    let output = String::from_utf8(output).unwrap();

    assert!(output.contains("Import kernel32.dll!CreateFileW"));
    assert!(output.contains("Delay import user32.dll!MessageBoxW"));
    assert!(output.contains("Export ordinal 1: Initialize"));
    assert!(output.contains("Resource 10/1/1033: RVA=0x11d0 size=4 code-page=1200"));
}

#[test]
fn rejects_distinct_invalid_utf16_resource_names_instead_of_collapsing_them() {
    let temporary = tempfile::tempdir().unwrap();
    let old_path = temporary.path().join("old.exe");
    let new_path = temporary.path().join("new.exe");
    fs::write(&old_path, pe_with_resource_name(0xd800)).unwrap();
    fs::write(&new_path, pe_with_resource_name(0xd801)).unwrap();

    let error = compare_files(&old_path, &new_path, DEFAULT_MAX_BYTES_READ, 1_000).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("invalid UTF-16 PE resource name")
    );
}

#[test]
fn deterministic_pe_mutations_never_panic() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("mutated-pe");
    let seeds = [pe_image(true, None), pe_with_tables(), pe_with_codeview()];
    let mut state = 0x0ddc_0ffe_e15e_beef_u64;

    for (seed_index, seed) in seeds.iter().enumerate() {
        let mutable_offsets: Vec<_> = (4..seed.len())
            .filter(|offset| !(0x3c..0x40).contains(offset) && !(0x80..0x84).contains(offset))
            .collect();
        for mutation_index in 0..64 {
            let mut bytes = seed.clone();
            for _ in 0..1 + mutation_index % 4 {
                let offset =
                    mutable_offsets[next_random(&mut state) as usize % mutable_offsets.len()];
                bytes[offset] = next_random(&mut state) as u8;
            }
            fs::write(&path, bytes).unwrap();

            let outcome = std::panic::catch_unwind(|| inspect_file(&path, DEFAULT_MAX_BYTES_READ));

            assert!(
                outcome.is_ok(),
                "PE parser panicked for seed {seed_index}, mutation {mutation_index}"
            );
        }
    }
}

#[test]
fn overlapping_pe_section_ranges_do_not_panic() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("overlapping-sections");
    let mut bytes = pe_image(true, None);
    bytes[0x86..0x88].copy_from_slice(&2_u16.to_le_bytes());
    bytes[0x98 + 56..0x98 + 60].copy_from_slice(&0x3000_u32.to_le_bytes());
    let second_section = 0x98 + 240 + 40;
    bytes[second_section..second_section + 6].copy_from_slice(b".other");
    bytes[second_section + 8..second_section + 12].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[second_section + 12..second_section + 16].copy_from_slice(&0x2000_u32.to_le_bytes());
    bytes[second_section + 16..second_section + 20].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[second_section + 20..second_section + 24].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[second_section + 36..second_section + 40].copy_from_slice(&0x40000040_u32.to_le_bytes());
    fs::write(&path, bytes).unwrap();

    let outcome = std::panic::catch_unwind(|| inspect_file(&path, DEFAULT_MAX_BYTES_READ));

    assert!(
        outcome.is_ok(),
        "PE parser panicked on overlapping section data"
    );
}

fn next_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn pe_image(is_64: bool, certificate: Option<(u32, u32)>) -> Vec<u8> {
    pe_image_at(is_64, certificate, 0x80)
}

fn pe_image_at(is_64: bool, certificate: Option<(u32, u32)>, nt_offset: usize) -> Vec<u8> {
    let optional_size = if is_64 { 240 } else { 224 };
    let optional_offset = nt_offset + 4 + 20;
    let section_offset = optional_offset + optional_size;
    let raw_offset = (section_offset + 40).div_ceil(0x200) * 0x200;
    let mut bytes = vec![0; raw_offset + 0x200];

    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&(nt_offset as u32).to_le_bytes());
    bytes[nt_offset..nt_offset + 4].copy_from_slice(b"PE\0\0");

    let file_header = nt_offset + 4;
    bytes[file_header..file_header + 2]
        .copy_from_slice(&(if is_64 { 0x8664_u16 } else { 0x14c_u16 }).to_le_bytes());
    bytes[file_header + 2..file_header + 4].copy_from_slice(&1_u16.to_le_bytes());
    bytes[file_header + 16..file_header + 18]
        .copy_from_slice(&(optional_size as u16).to_le_bytes());
    bytes[file_header + 18..file_header + 20].copy_from_slice(&0x0022_u16.to_le_bytes());

    bytes[optional_offset..optional_offset + 2]
        .copy_from_slice(&(if is_64 { 0x20b_u16 } else { 0x10b_u16 }).to_le_bytes());
    bytes[optional_offset + 16..optional_offset + 20].copy_from_slice(&0x1010_u32.to_le_bytes());
    if is_64 {
        bytes[optional_offset + 24..optional_offset + 32]
            .copy_from_slice(&0x140000000_u64.to_le_bytes());
    } else {
        bytes[optional_offset + 28..optional_offset + 32]
            .copy_from_slice(&0x400000_u32.to_le_bytes());
    }
    bytes[optional_offset + 32..optional_offset + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[optional_offset + 36..optional_offset + 40].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[optional_offset + 56..optional_offset + 60].copy_from_slice(&0x2000_u32.to_le_bytes());
    bytes[optional_offset + 60..optional_offset + 64]
        .copy_from_slice(&(raw_offset as u32).to_le_bytes());
    bytes[optional_offset + 68..optional_offset + 70].copy_from_slice(&3_u16.to_le_bytes());
    let directory_count_offset = if is_64 { 108 } else { 92 };
    let directories_offset = if is_64 { 112 } else { 96 };
    bytes[optional_offset + directory_count_offset..optional_offset + directory_count_offset + 4]
        .copy_from_slice(&16_u32.to_le_bytes());
    if let Some((offset, size)) = certificate {
        let directory = optional_offset + directories_offset + 4 * 8;
        bytes[directory..directory + 4].copy_from_slice(&offset.to_le_bytes());
        bytes[directory + 4..directory + 8].copy_from_slice(&size.to_le_bytes());
    }

    bytes[section_offset..section_offset + 5].copy_from_slice(b".text");
    bytes[section_offset + 8..section_offset + 12].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[section_offset + 12..section_offset + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[section_offset + 16..section_offset + 20].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[section_offset + 20..section_offset + 24]
        .copy_from_slice(&(raw_offset as u32).to_le_bytes());
    bytes[section_offset + 36..section_offset + 40].copy_from_slice(&0x60000020_u32.to_le_bytes());

    bytes
}

fn pe_with_tables() -> Vec<u8> {
    let mut bytes = pe_image(true, None);
    let nt_offset = 0x80;
    let optional_offset = nt_offset + 4 + 20;
    let directories = optional_offset + 112;
    set_directory(&mut bytes, directories, 1, 0x1000, 40);
    set_directory(&mut bytes, directories, 0, 0x1100, 0x50);
    set_directory(&mut bytes, directories, 2, 0x1160, 0x80);
    set_directory(&mut bytes, directories, 13, 0x1080, 64);

    let raw = 0x200;
    write_u32(&mut bytes, raw, 0x1040);
    write_u32(&mut bytes, raw + 12, 0x1030);
    write_u32(&mut bytes, raw + 16, 0x1050);
    bytes[raw + 0x30..raw + 0x30 + 13].copy_from_slice(b"kernel32.dll\0");
    write_u64(&mut bytes, raw + 0x40, 0x1060);
    write_u16(&mut bytes, raw + 0x60, 7);
    bytes[raw + 0x62..raw + 0x62 + 12].copy_from_slice(b"CreateFileW\0");

    write_u32(&mut bytes, raw + 0x80, 1);
    write_u32(&mut bytes, raw + 0x84, 0x10c0);
    write_u32(&mut bytes, raw + 0x8c, 0x10e0);
    write_u32(&mut bytes, raw + 0x90, 0x10d0);
    bytes[raw + 0xc0..raw + 0xc0 + 11].copy_from_slice(b"user32.dll\0");
    write_u64(&mut bytes, raw + 0xd0, 0x10f0);
    write_u16(&mut bytes, raw + 0xf0, 4);
    bytes[raw + 0xf2..raw + 0xf2 + 12].copy_from_slice(b"MessageBoxW\0");

    write_u32(&mut bytes, raw + 0x100 + 16, 1);
    write_u32(&mut bytes, raw + 0x100 + 20, 1);
    write_u32(&mut bytes, raw + 0x100 + 24, 1);
    write_u32(&mut bytes, raw + 0x100 + 28, 0x1130);
    write_u32(&mut bytes, raw + 0x100 + 32, 0x1134);
    write_u32(&mut bytes, raw + 0x100 + 36, 0x1138);
    write_u32(&mut bytes, raw + 0x130, 0x1010);
    write_u32(&mut bytes, raw + 0x134, 0x1140);
    write_u16(&mut bytes, raw + 0x138, 0);
    bytes[raw + 0x140..raw + 0x140 + 11].copy_from_slice(b"Initialize\0");

    let resource = raw + 0x160;
    write_u16(&mut bytes, resource + 14, 1);
    write_u32(&mut bytes, resource + 16, 10);
    write_u32(&mut bytes, resource + 20, 0x8000_0020);
    write_u16(&mut bytes, resource + 0x20 + 14, 1);
    write_u32(&mut bytes, resource + 0x30, 1);
    write_u32(&mut bytes, resource + 0x34, 0x8000_0040);
    write_u16(&mut bytes, resource + 0x40 + 14, 1);
    write_u32(&mut bytes, resource + 0x50, 1033);
    write_u32(&mut bytes, resource + 0x54, 0x60);
    write_u32(&mut bytes, resource + 0x60, 0x11d0);
    write_u32(&mut bytes, resource + 0x64, 4);
    write_u32(&mut bytes, resource + 0x68, 1200);
    bytes[raw + 0x1d0..raw + 0x1d4].copy_from_slice(b"data");
    bytes
}

fn pe_with_codeview() -> Vec<u8> {
    let mut bytes = pe_image(true, None);
    let directories = 0x80 + 4 + 20 + 112;
    set_directory(&mut bytes, directories, 6, 0x1180, 28);

    let raw = 0x200;
    let debug = raw + 0x180;
    write_u32(&mut bytes, debug + 12, 2);
    write_u32(&mut bytes, debug + 16, 41);
    write_u32(&mut bytes, debug + 20, 0x11c0);
    write_u32(&mut bytes, debug + 24, (raw + 0x1c0) as u32);
    let codeview = raw + 0x1c0;
    bytes[codeview..codeview + 4].copy_from_slice(b"RSDS");
    for byte in 0..16_u8 {
        bytes[codeview + 4 + usize::from(byte)] = byte;
    }
    write_u32(&mut bytes, codeview + 20, 3);
    bytes[codeview + 24..codeview + 24 + 17].copy_from_slice(b"C:\\build\\app.pdb\0");
    bytes
}

fn pe_with_resource_name(code_unit: u16) -> Vec<u8> {
    let mut bytes = pe_image(true, None);
    let directories = 0x80 + 4 + 20 + 112;
    set_directory(&mut bytes, directories, 2, 0x1160, 0x60);

    let resource = 0x200 + 0x160;
    write_u16(&mut bytes, resource + 12, 1);
    write_u32(&mut bytes, resource + 16, 0x8000_0018);
    write_u32(&mut bytes, resource + 20, 0x8000_0028);
    write_u16(&mut bytes, resource + 24, 1);
    write_u16(&mut bytes, resource + 26, code_unit);

    write_u16(&mut bytes, resource + 40 + 14, 1);
    write_u32(&mut bytes, resource + 56, 1);
    write_u32(&mut bytes, resource + 60, 72);
    write_u32(&mut bytes, resource + 72, 0x11d0);

    bytes
}

fn set_directory(bytes: &mut [u8], directories: usize, index: usize, rva: u32, size: u32) {
    let offset = directories + index * 8;
    write_u32(bytes, offset, rva);
    write_u32(bytes, offset + 4, size);
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
