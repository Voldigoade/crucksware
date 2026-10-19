use crate::{
    binary_compare::{SemanticComparisonStatus, compare_inspections},
    input::InputKind,
    inspection::{
        ContentKind, ElfInspection, ElfSection, FileInspection, PeImport, PeImportName,
        PeInspection,
    },
};

fn elf(entry_point: u64, sections: Vec<ElfSection>) -> FileInspection {
    FileInspection {
        kind: InputKind::Elf,
        size_bytes: 1_024,
        bytes_read: 0,
        semantic_entries: 0,
        input_stamp: None,
        content: ContentKind::Binary,
        elf: Some(ElfInspection {
            entries_read: 0,
            class: "ELF64",
            byte_order: "little-endian",
            architecture: "X86_64".to_owned(),
            machine: "62".to_owned(),
            elf_type: "DYN".to_owned(),
            entry_point,
            sections,
            segments: Vec::new(),
            interpreters: Vec::new(),
            dependencies: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            symbols: Vec::new(),
            build_id: None,
            gnu_stack_executable: Vec::new(),
            gnu_relro_segments: 0,
        }),
        pe: None,
    }
}

fn section(name: &[u8], address: u64) -> ElfSection {
    ElfSection {
        index: 1,
        name: name.to_vec(),
        section_type: "PROGBITS".to_owned(),
        flags: "ALLOC|EXEC".to_owned(),
        address,
        size: 16,
    }
}

fn pe(entry_point_rva: u32, imports: Vec<PeImport>) -> FileInspection {
    FileInspection {
        kind: InputKind::Pe,
        size_bytes: 1_024,
        bytes_read: 0,
        semantic_entries: 0,
        input_stamp: None,
        content: ContentKind::Binary,
        elf: None,
        pe: Some(PeInspection {
            entries_read: 0,
            format: "PE32+",
            architecture: "X86_64".to_owned(),
            machine: 0x8664,
            entry_point_rva,
            image_base: 0x140000000,
            subsystem: 3,
            sections: Vec::new(),
            imports,
            delay_imports: Vec::new(),
            exports: Vec::new(),
            resources: Vec::new(),
            pdb_info: None,
            certificate_table: None,
        }),
    }
}

#[test]
fn byte_changes_are_separate_from_normalized_semantic_changes() {
    let old = elf(
        0x1000,
        vec![section(b".text", 0x1000), section(b".data", 0x2000)],
    );
    let new = elf(
        0x1000,
        vec![section(b".data", 0x2000), section(b".text", 0x1000)],
    );

    let comparison = compare_inspections(&old, &new, true);

    assert!(comparison.bytes_changed);
    assert_eq!(
        comparison.semantic_status,
        SemanticComparisonStatus::Compared
    );
    assert!(comparison.semantic_changes.is_empty());
}

#[test]
fn reports_named_elf_fact_changes_in_deterministic_order() {
    let old = elf(0x1000, vec![section(b".text", 0x1000)]);
    let new = elf(0x2000, vec![section(b".text", 0x2000)]);

    let comparison = compare_inspections(&old, &new, true);

    let fields: Vec<_> = comparison
        .semantic_changes
        .iter()
        .map(|change| change.field.as_str())
        .collect();
    assert_eq!(fields, ["entry_point", "sections"]);
}

#[test]
fn reports_format_mismatch_without_comparing_unrelated_facts() {
    let old = elf(0x1000, Vec::new());
    let new = FileInspection {
        kind: InputKind::Pe,
        size_bytes: 1_024,
        bytes_read: 0,
        semantic_entries: 0,
        input_stamp: None,
        content: ContentKind::Binary,
        elf: None,
        pe: Some(PeInspection {
            entries_read: 0,
            format: "PE32+",
            architecture: "X86_64".to_owned(),
            machine: 0x8664,
            entry_point_rva: 0x1000,
            image_base: 0x140000000,
            subsystem: 3,
            sections: Vec::new(),
            imports: Vec::new(),
            delay_imports: Vec::new(),
            exports: Vec::new(),
            resources: Vec::new(),
            pdb_info: None,
            certificate_table: None,
        }),
    };

    let comparison = compare_inspections(&old, &new, true);

    assert_eq!(
        comparison.semantic_status,
        SemanticComparisonStatus::FormatMismatch
    );
    assert!(comparison.semantic_changes.is_empty());
}

#[test]
fn generic_files_report_byte_changes_without_semantic_claims() {
    let old = FileInspection {
        kind: InputKind::UnknownBinary,
        size_bytes: 3,
        bytes_read: 0,
        semantic_entries: 0,
        input_stamp: None,
        content: ContentKind::Binary,
        elf: None,
        pe: None,
    };
    let new = FileInspection {
        kind: InputKind::UnknownBinary,
        size_bytes: 3,
        bytes_read: 0,
        semantic_entries: 0,
        input_stamp: None,
        content: ContentKind::Binary,
        elf: None,
        pe: None,
    };

    let comparison = compare_inspections(&old, &new, true);

    assert_eq!(
        comparison.semantic_status,
        SemanticComparisonStatus::Unsupported
    );
    assert!(comparison.semantic_changes.is_empty());
    assert!(comparison.bytes_changed);
}

#[test]
fn normalizes_pe_record_order_and_reports_entry_point_changes() {
    let old = pe(
        0x1000,
        vec![
            PeImport {
                library: b"z.dll".to_vec(),
                name: PeImportName::Ordinal(2),
            },
            PeImport {
                library: b"a.dll".to_vec(),
                name: PeImportName::Name(b"Start".to_vec()),
            },
        ],
    );
    let new = pe(
        0x2000,
        vec![
            PeImport {
                library: b"a.dll".to_vec(),
                name: PeImportName::Name(b"Start".to_vec()),
            },
            PeImport {
                library: b"z.dll".to_vec(),
                name: PeImportName::Ordinal(2),
            },
        ],
    );

    let comparison = compare_inspections(&old, &new, true);

    assert_eq!(
        comparison.semantic_status,
        SemanticComparisonStatus::Compared
    );
    assert_eq!(comparison.semantic_changes.len(), 1);
    assert_eq!(comparison.semantic_changes[0].field, "entry_point_rva");
}
