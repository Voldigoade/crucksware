use std::fs;

use crucksware::{
    inspection::{
        DEFAULT_MAX_BYTES_READ, MAX_ELF_FILE_BYTES, inspect_file, inspect_file_with_limits,
    },
    report,
};

#[test]
fn inspects_header_facts_from_a_minimal_elf_without_running_it() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("sample.bin");
    fs::write(&path, minimal_elf64()).unwrap();

    let inspection = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap();
    let mut output = Vec::new();
    report::inspection::write_inspection(&inspection, &mut output).unwrap();
    let output = String::from_utf8(output).unwrap();

    assert!(output.contains("Detected kind: ELF\n"));
    assert!(output.contains("ELF class: ELF64\n"));
    assert!(output.contains("Byte order: little-endian\n"));
    assert!(output.contains("Architecture: X86_64\n"));
    assert!(output.contains("ELF type: Dynamic\n"));
    assert!(output.contains("Entry point: 0x401000\n"));
    assert!(output.contains("Sections: 0\n"));
    assert!(output.contains("Segments: 0\n"));
    assert!(output.contains("ELF structural inspection: performed\n"));
}

#[test]
fn rejects_truncated_elf_candidates_without_a_partial_inspection() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("truncated");
    fs::write(&path, b"\x7fELF").unwrap();

    let error = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap_err();

    assert!(error.to_string().contains("ELF"));
}

#[test]
fn bounds_full_elf_reads_by_the_configured_byte_limit() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("large-elf");
    let mut contents = minimal_elf64();
    contents.resize(16 * 1024, 0);
    fs::write(&path, contents).unwrap();

    let error = inspect_file(&path, 8 * 1024).unwrap_err();

    assert!(error.to_string().contains("bytes read limit exceeded"));
}

#[test]
fn reports_the_read_limit_before_a_short_detection_sample_as_mutation() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("sample.bin");
    fs::write(&path, minimal_elf64()).unwrap();

    let error = inspect_file(&path, 4).unwrap_err();

    assert!(error.to_string().contains("bytes read limit exceeded (4)"));
}

#[test]
fn reports_program_segments_interpreter_and_gnu_stack_metadata() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("program");
    let elf = elf_with_segments();
    fs::write(&path, elf).unwrap();

    let inspection = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap();
    let elf = inspection.elf.unwrap();

    assert_eq!(elf.segments.len(), 3);
    assert_eq!(elf.interpreters, [b"/lib64/ld-linux-x86-64.so.2".to_vec()]);
    assert_eq!(elf.gnu_stack_executable, [true]);
    assert_eq!(elf.gnu_relro_segments, 1);
}

#[test]
fn reports_dynamic_dependencies_from_program_headers_without_sections() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("dynamic-only");
    fs::write(&path, elf_with_dynamic_segment()).unwrap();

    let inspection = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap();

    assert_eq!(
        inspection.elf.unwrap().dependencies,
        [b"libalpha.so".to_vec()]
    );
}

#[test]
fn rejects_invalid_dynamic_dependency_metadata_without_a_partial_inspection() {
    let temporary = tempfile::tempdir().unwrap();
    let dynamic_offset = 64 + 2 * 56;
    let cases = [
        (
            "needed-offset",
            dynamic_offset + 8,
            u64::MAX.to_le_bytes().to_vec(),
        ),
        (
            "string-table-address",
            dynamic_offset + 16 + 8,
            u64::MAX.to_le_bytes().to_vec(),
        ),
        (
            "missing-terminator",
            dynamic_offset + 3 * 16,
            4_i64.to_le_bytes().to_vec(),
        ),
    ];

    for (name, offset, replacement) in cases {
        let path = temporary.path().join(name);
        let mut bytes = elf_with_dynamic_segment();
        bytes[offset..offset + replacement.len()].copy_from_slice(&replacement);
        fs::write(&path, bytes).unwrap();

        let error = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap_err();

        assert!(
            error.to_string().contains("invalid ELF input"),
            "{name}: {error}"
        );
    }
}

#[test]
fn enforces_the_semantic_entry_limit() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("program");
    fs::write(&path, elf_with_segments()).unwrap();

    let error = inspect_file_with_limits(&path, DEFAULT_MAX_BYTES_READ, 0).unwrap_err();

    assert!(error.to_string().contains("ELF entries limit exceeded (0)"));
}

#[test]
fn enforces_the_hard_elf_file_size_limit_before_allocating_the_file() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("large-elf");
    fs::write(&path, b"\x7fELF").unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(MAX_ELF_FILE_BYTES + 1)
        .unwrap();

    let error = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap_err();

    assert!(error.to_string().contains("ELF file size limit exceeded"));
}

#[test]
fn escapes_non_utf8_section_names_in_text_output() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("sections");
    fs::write(&path, elf_with_section_name()).unwrap();

    let inspection = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap();
    let mut output = Vec::new();
    report::inspection::write_inspection(&inspection, &mut output).unwrap();

    assert!(String::from_utf8(output).unwrap().contains(".section%FF"));
}

#[test]
fn rejects_invalid_section_table_offsets_without_a_partial_inspection() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("invalid-offset");
    let mut contents = minimal_elf64();
    contents[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
    contents[58..60].copy_from_slice(&64_u16.to_le_bytes());
    contents[60..62].copy_from_slice(&1_u16.to_le_bytes());
    fs::write(&path, contents).unwrap();

    let error = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap_err();

    assert!(error.to_string().contains("invalid ELF input"));
}

#[test]
fn rejects_program_segments_with_out_of_bounds_file_ranges() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("invalid-segment-range");
    let mut contents = elf_with_segments();
    let load_header = 64;
    let invalid_offset = contents.len() as u64 + 1;
    contents[load_header..load_header + 4].copy_from_slice(&1_u32.to_le_bytes());
    contents[load_header + 8..load_header + 16].copy_from_slice(&invalid_offset.to_le_bytes());
    fs::write(&path, contents).unwrap();

    let error = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap_err();

    assert!(error.to_string().contains("invalid ELF input"));
}

#[test]
fn rejects_load_segments_larger_on_disk_than_in_memory() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("invalid-load-size");
    let mut contents = elf_with_segments();
    let load_header = 64;
    contents[load_header..load_header + 4].copy_from_slice(&1_u32.to_le_bytes());
    contents[load_header + 40..load_header + 48].copy_from_slice(&0_u64.to_le_bytes());
    fs::write(&path, contents).unwrap();

    let error = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap_err();

    assert!(error.to_string().contains("invalid ELF input"));
}

#[test]
fn rejects_out_of_bounds_non_name_section_data() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("invalid-section-range");
    fs::write(&path, elf_with_invalid_data_section()).unwrap();

    let error = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap_err();

    assert!(error.to_string().contains("invalid ELF input"));
}

#[test]
fn limits_each_copied_elf_name_to_four_kibibytes() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("long-section-name");
    fs::write(&path, elf_with_repeated_section_names(3, 4 * 1024 + 1)).unwrap();

    let error = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("ELF field bytes limit exceeded (4096)")
    );
}

#[test]
fn limits_total_copied_elf_names_to_sixteen_mebibytes() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("many-long-section-names");
    fs::write(&path, elf_with_repeated_section_names(4_099, 4 * 1024)).unwrap();

    let error = inspect_file(&path, DEFAULT_MAX_BYTES_READ).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("ELF copied name bytes limit exceeded (16777216)")
    );
}

#[test]
fn rejects_inconsistent_elf_header_version_and_size_fields() {
    let temporary = tempfile::tempdir().unwrap();
    let version_path = temporary.path().join("version");
    let mut invalid_version = minimal_elf64();
    invalid_version[20..24].copy_from_slice(&0_u32.to_le_bytes());
    fs::write(&version_path, invalid_version).unwrap();

    let header_size_path = temporary.path().join("header-size");
    let mut invalid_header_size = minimal_elf64();
    invalid_header_size[52..54].copy_from_slice(&0_u16.to_le_bytes());
    fs::write(&header_size_path, invalid_header_size).unwrap();

    for path in [&version_path, &header_size_path] {
        let error = inspect_file(path, DEFAULT_MAX_BYTES_READ).unwrap_err();
        assert!(error.to_string().contains("inconsistent ELF header"));
    }
}

#[test]
fn deterministic_elf_mutations_never_panic() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("mutated-elf");
    let seeds = [
        minimal_elf64(),
        elf_with_segments(),
        elf_with_dynamic_segment(),
        elf_with_section_name(),
    ];
    let mut state = 0x5eed_f00d_cafe_babe_u64;

    for (seed_index, seed) in seeds.iter().enumerate() {
        for mutation_index in 0..64 {
            let mut bytes = seed.clone();
            for _ in 0..1 + mutation_index % 4 {
                let start = 16 + (next_random(&mut state) as usize % (bytes.len() - 16));
                let width =
                    [1, 2, 4, 8][next_random(&mut state) as usize % 4].min(bytes.len() - start);
                let replacement = next_random(&mut state).to_le_bytes();
                bytes[start..start + width].copy_from_slice(&replacement[..width]);
            }
            fs::write(&path, bytes).unwrap();

            let outcome = std::panic::catch_unwind(|| inspect_file(&path, DEFAULT_MAX_BYTES_READ));

            assert!(
                outcome.is_ok(),
                "ELF parser panicked for seed {seed_index}, mutation {mutation_index}"
            );
        }
    }
}

#[test]
fn overlapping_elf_section_ranges_do_not_panic() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("overlapping-sections");
    let mut bytes = elf_with_invalid_data_section();
    let string_table_offset = 64 + 3 * 64;
    let data_section = 64 + 2 * 64;
    bytes[data_section + 24..data_section + 32]
        .copy_from_slice(&(string_table_offset as u64).to_le_bytes());
    bytes[data_section + 32..data_section + 40].copy_from_slice(&4_u64.to_le_bytes());
    fs::write(&path, bytes).unwrap();

    let outcome = std::panic::catch_unwind(|| inspect_file(&path, DEFAULT_MAX_BYTES_READ));

    assert!(
        outcome.is_ok(),
        "ELF parser panicked on overlapping section data"
    );
}

fn next_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn minimal_elf64() -> Vec<u8> {
    let mut bytes = vec![0; 64];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x401000_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
    bytes
}

fn elf_with_segments() -> Vec<u8> {
    let interpreter = b"/lib64/ld-linux-x86-64.so.2\0";
    let program_headers_end = 64 + 3 * 56;
    let mut bytes = vec![0; program_headers_end + interpreter.len()];
    bytes[..64].copy_from_slice(&minimal_elf64());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&3_u16.to_le_bytes());

    let interp = 64;
    bytes[interp..interp + 4].copy_from_slice(&3_u32.to_le_bytes());
    bytes[interp + 4..interp + 8].copy_from_slice(&4_u32.to_le_bytes());
    bytes[interp + 8..interp + 16].copy_from_slice(&(program_headers_end as u64).to_le_bytes());
    bytes[interp + 16..interp + 24].copy_from_slice(&0x400000_u64.to_le_bytes());
    bytes[interp + 24..interp + 32].copy_from_slice(&0x400000_u64.to_le_bytes());
    bytes[interp + 32..interp + 40].copy_from_slice(&(interpreter.len() as u64).to_le_bytes());
    bytes[interp + 40..interp + 48].copy_from_slice(&(interpreter.len() as u64).to_le_bytes());
    bytes[interp + 48..interp + 56].copy_from_slice(&1_u64.to_le_bytes());
    bytes[program_headers_end..].copy_from_slice(interpreter);

    let stack = interp + 56;
    bytes[stack..stack + 4].copy_from_slice(&0x6474_e551_u32.to_le_bytes());
    bytes[stack + 4..stack + 8].copy_from_slice(&7_u32.to_le_bytes());
    bytes[stack + 48..stack + 56].copy_from_slice(&16_u64.to_le_bytes());

    let relro = stack + 56;
    bytes[relro..relro + 4].copy_from_slice(&0x6474_e552_u32.to_le_bytes());
    bytes[relro + 4..relro + 8].copy_from_slice(&4_u32.to_le_bytes());
    bytes
}

fn elf_with_section_name() -> Vec<u8> {
    let names = b"\0.section\xff\0";
    let section_table_offset = 64;
    let strings_offset = section_table_offset + 2 * 64;
    let mut bytes = vec![0; strings_offset + names.len()];
    bytes[..64].copy_from_slice(&minimal_elf64());
    bytes[40..48].copy_from_slice(&(section_table_offset as u64).to_le_bytes());
    bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
    bytes[60..62].copy_from_slice(&2_u16.to_le_bytes());
    bytes[62..64].copy_from_slice(&1_u16.to_le_bytes());

    let section = section_table_offset + 64;
    bytes[section..section + 4].copy_from_slice(&1_u32.to_le_bytes());
    bytes[section + 4..section + 8].copy_from_slice(&3_u32.to_le_bytes());
    bytes[section + 24..section + 32].copy_from_slice(&(strings_offset as u64).to_le_bytes());
    bytes[section + 32..section + 40].copy_from_slice(&(names.len() as u64).to_le_bytes());
    bytes[section + 48..section + 56].copy_from_slice(&1_u64.to_le_bytes());
    bytes[strings_offset..].copy_from_slice(names);
    bytes
}

fn elf_with_invalid_data_section() -> Vec<u8> {
    let names = b"\0.names\0.data\0";
    let section_table_offset = 64;
    let strings_offset = section_table_offset + 3 * 64;
    let mut bytes = vec![0; strings_offset + names.len()];
    bytes[..64].copy_from_slice(&minimal_elf64());
    bytes[40..48].copy_from_slice(&(section_table_offset as u64).to_le_bytes());
    bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
    bytes[60..62].copy_from_slice(&3_u16.to_le_bytes());
    bytes[62..64].copy_from_slice(&1_u16.to_le_bytes());

    let strings = section_table_offset + 64;
    bytes[strings..strings + 4].copy_from_slice(&1_u32.to_le_bytes());
    bytes[strings + 4..strings + 8].copy_from_slice(&3_u32.to_le_bytes());
    bytes[strings + 24..strings + 32].copy_from_slice(&(strings_offset as u64).to_le_bytes());
    bytes[strings + 32..strings + 40].copy_from_slice(&(names.len() as u64).to_le_bytes());
    bytes[strings + 48..strings + 56].copy_from_slice(&1_u64.to_le_bytes());

    let data = section_table_offset + 2 * 64;
    bytes[data..data + 4].copy_from_slice(&8_u32.to_le_bytes());
    bytes[data + 4..data + 8].copy_from_slice(&1_u32.to_le_bytes());
    bytes[data + 24..data + 32].copy_from_slice(&u64::MAX.to_le_bytes());
    bytes[data + 32..data + 40].copy_from_slice(&4_u64.to_le_bytes());
    bytes[data + 48..data + 56].copy_from_slice(&1_u64.to_le_bytes());
    bytes[strings_offset..].copy_from_slice(names);
    bytes
}

fn elf_with_repeated_section_names(section_count: u16, name_size: usize) -> Vec<u8> {
    let section_table_offset = 64;
    let strings_offset = section_table_offset + usize::from(section_count) * 64;
    let mut names = Vec::with_capacity(name_size + 2);
    names.push(0);
    names.extend(std::iter::repeat_n(b'n', name_size));
    names.push(0);

    let mut bytes = vec![0; strings_offset + names.len()];
    bytes[..64].copy_from_slice(&minimal_elf64());
    bytes[40..48].copy_from_slice(&(section_table_offset as u64).to_le_bytes());
    bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
    bytes[60..62].copy_from_slice(&section_count.to_le_bytes());
    bytes[62..64].copy_from_slice(&1_u16.to_le_bytes());

    let string_table = section_table_offset + 64;
    bytes[string_table + 4..string_table + 8].copy_from_slice(&3_u32.to_le_bytes());
    bytes[string_table + 24..string_table + 32]
        .copy_from_slice(&(strings_offset as u64).to_le_bytes());
    bytes[string_table + 32..string_table + 40]
        .copy_from_slice(&(names.len() as u64).to_le_bytes());
    bytes[string_table + 48..string_table + 56].copy_from_slice(&1_u64.to_le_bytes());

    for index in 2..usize::from(section_count) {
        let section = section_table_offset + index * 64;
        bytes[section..section + 4].copy_from_slice(&1_u32.to_le_bytes());
        bytes[section + 4..section + 8].copy_from_slice(&1_u32.to_le_bytes());
    }
    bytes[strings_offset..].copy_from_slice(&names);
    bytes
}

fn elf_with_dynamic_segment() -> Vec<u8> {
    let strings = b"\0libalpha.so\0";
    let program_headers_end = 64 + 2 * 56;
    let dynamic_size = 4 * 16;
    let mut bytes = vec![0; program_headers_end + dynamic_size + strings.len()];
    bytes[..64].copy_from_slice(&minimal_elf64());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&2_u16.to_le_bytes());

    let load = 64;
    bytes[load..load + 4].copy_from_slice(&1_u32.to_le_bytes());
    bytes[load + 4..load + 8].copy_from_slice(&4_u32.to_le_bytes());
    bytes[load + 8..load + 16].copy_from_slice(&(program_headers_end as u64).to_le_bytes());
    bytes[load + 16..load + 24].copy_from_slice(&0x400000_u64.to_le_bytes());
    bytes[load + 24..load + 32].copy_from_slice(&0x400000_u64.to_le_bytes());
    let load_size = (dynamic_size + strings.len()) as u64;
    bytes[load + 32..load + 40].copy_from_slice(&load_size.to_le_bytes());
    bytes[load + 40..load + 48].copy_from_slice(&load_size.to_le_bytes());
    bytes[load + 48..load + 56].copy_from_slice(&1_u64.to_le_bytes());

    let dynamic = load + 56;
    bytes[dynamic..dynamic + 4].copy_from_slice(&2_u32.to_le_bytes());
    bytes[dynamic + 4..dynamic + 8].copy_from_slice(&4_u32.to_le_bytes());
    bytes[dynamic + 8..dynamic + 16].copy_from_slice(&(program_headers_end as u64).to_le_bytes());
    bytes[dynamic + 16..dynamic + 24].copy_from_slice(&0x400000_u64.to_le_bytes());
    bytes[dynamic + 24..dynamic + 32].copy_from_slice(&0x400000_u64.to_le_bytes());
    bytes[dynamic + 32..dynamic + 40].copy_from_slice(&(dynamic_size as u64).to_le_bytes());
    bytes[dynamic + 40..dynamic + 48].copy_from_slice(&(dynamic_size as u64).to_le_bytes());
    bytes[dynamic + 48..dynamic + 56].copy_from_slice(&8_u64.to_le_bytes());

    let records = program_headers_end;
    bytes[records..records + 8].copy_from_slice(&1_i64.to_le_bytes());
    bytes[records + 8..records + 16].copy_from_slice(&1_u64.to_le_bytes());
    bytes[records + 16..records + 24].copy_from_slice(&5_i64.to_le_bytes());
    bytes[records + 24..records + 32]
        .copy_from_slice(&(0x400000_u64 + dynamic_size as u64).to_le_bytes());
    bytes[records + 32..records + 40].copy_from_slice(&10_i64.to_le_bytes());
    bytes[records + 40..records + 48].copy_from_slice(&(strings.len() as u64).to_le_bytes());
    bytes[records + 48..records + 56].copy_from_slice(&0_i64.to_le_bytes());
    bytes[records + 56..records + 64].copy_from_slice(&0_u64.to_le_bytes());
    bytes[records + dynamic_size..].copy_from_slice(strings);
    bytes
}
