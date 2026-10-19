use serde_json::json;

use crate::{
    binary_compare::{FileComparison, SemanticChange, SemanticComparisonStatus},
    input::InputKind,
    model::{Category, Change, ChangedField, Diff, Entry, Summary},
    path::RelPath,
    readable::{
        EvidenceError, EvidenceFact, select_file_comparison, select_filesystem,
        select_semantic_tree,
    },
    semantic_tree::{BinaryAnalysisStatus, BinaryFileChange, SemanticTreeDiff},
    source::{
        SourceAnalysisStatus, SourceFileChange, SourceLanguage, StructuralAction, StructuralChange,
        StructuralKind, StructuralStatus,
    },
};

fn source_change(path: &[u8], structural_changes: Vec<StructuralChange>) -> SourceFileChange {
    SourceFileChange {
        path: RelPath::new(path.to_vec()).unwrap(),
        analysis_status: SourceAnalysisStatus::Compared,
        language: Some(SourceLanguage::Rust),
        lines_added: Some(1),
        lines_removed: Some(0),
        hunk_count: Some(1),
        structural_status: StructuralStatus::Complete,
        structural_changes,
    }
}

fn structural_change(name: String) -> StructuralChange {
    StructuralChange {
        action: StructuralAction::Added,
        kind: StructuralKind::Function,
        name,
        before_signature: None,
        after_signature: Some("fn added()".to_owned()),
    }
}

#[test]
fn semantic_packet_prioritizes_binary_and_source_facts_with_encoded_paths() {
    let diff = SemanticTreeDiff {
        filesystem: Diff::default(),
        source_changes: vec![source_change(
            b"src/\x80auth.rs",
            vec![structural_change("validate_token".to_owned())],
        )],
        binary_changes: vec![BinaryFileChange {
            path: RelPath::new(b"bin/\xfftool".to_vec()).unwrap(),
            old_kind: Some(InputKind::Elf),
            new_kind: Some(InputKind::Elf),
            old_size_bytes: Some(64),
            new_size_bytes: Some(65),
            byte_level_changed: Some(true),
            semantic_status: BinaryAnalysisStatus::Compared,
            semantic_changes: vec![SemanticChange {
                field: "entry_point".to_owned(),
                before: json!(4096),
                after: json!(8192),
            }],
        }],
    };

    let packet = select_semantic_tree(&diff).unwrap();

    assert_eq!(packet.records.len(), 4);
    assert_eq!(packet.records[0].id.to_string(), "E0001");
    assert_eq!(packet.records[0].path.as_deref(), Some("bin/%FFtool"));
    assert!(matches!(
        &packet.records[0].fact,
        EvidenceFact::BinarySemanticChange { field, .. } if field == "entry_point"
    ));
    assert_eq!(packet.records[1].path.as_deref(), Some("bin/%FFtool"));
    assert!(matches!(
        &packet.records[1].fact,
        EvidenceFact::BinaryBytesChanged { .. }
    ));
    assert_eq!(packet.records[2].path.as_deref(), Some("src/%80auth.rs"));
    assert!(matches!(
        &packet.records[2].fact,
        EvidenceFact::SourceStructuralChange { name, .. } if name == "validate_token"
    ));
    assert!(matches!(
        &packet.records[3].fact,
        EvidenceFact::SourceTextChange {
            lines_added: Some(1),
            ..
        }
    ));
    assert_eq!(packet.totals.eligible_records, 4);
    assert_eq!(packet.totals.omitted_records, 0);
}

#[test]
fn evidence_selection_caps_records_and_reports_omissions() {
    let source_changes = (0..9)
        .map(|index| {
            let path = format!("src/file_{index:02}.rs");
            let facts = (0..8)
                .map(|fact| structural_change(format!("function_{fact}")))
                .collect();
            source_change(path.as_bytes(), facts)
        })
        .collect();
    let diff = SemanticTreeDiff {
        filesystem: Diff::default(),
        source_changes,
        binary_changes: vec![],
    };

    let packet = select_semantic_tree(&diff).unwrap();
    let encoded = serde_json::to_vec(&packet).unwrap();

    assert_eq!(packet.records.len(), 64);
    assert_eq!(packet.totals.eligible_records, 81);
    assert_eq!(packet.totals.omitted_records, 17);
    assert!(encoded.len() <= 32 * 1024);
    assert_eq!(packet.records.first().unwrap().id.to_string(), "E0001");
    assert_eq!(packet.records.last().unwrap().id.to_string(), "E0064");
}

#[test]
fn oversized_evidence_is_omitted_as_a_whole_without_losing_counts() {
    let mut change = source_change(b"src/large.rs", vec![structural_change("x".repeat(40_000))]);
    change.lines_added = None;
    change.lines_removed = None;
    change.hunk_count = None;
    let diff = SemanticTreeDiff {
        filesystem: Diff::default(),
        source_changes: vec![change],
        binary_changes: vec![],
    };

    let packet = select_semantic_tree(&diff).unwrap();

    assert!(packet.records.is_empty());
    assert_eq!(packet.totals.eligible_records, 1);
    assert_eq!(packet.totals.omitted_records, 1);
}

#[test]
fn filesystem_evidence_preserves_encoded_symlink_targets_and_device_metadata() {
    let diff = Diff {
        changes: vec![
            Change {
                path: RelPath::new(b"dev/device".to_vec()).unwrap(),
                category: Category::MetadataChanged,
                changed_fields: vec![ChangedField::Mode, ChangedField::DeviceId],
                before: Some(Entry::CharDevice {
                    mode: 0o20600,
                    device_id: 17,
                }),
                after: Some(Entry::CharDevice {
                    mode: 0o20640,
                    device_id: 23,
                }),
            },
            Change {
                path: RelPath::new(b"etc/current".to_vec()).unwrap(),
                category: Category::MetadataChanged,
                changed_fields: vec![ChangedField::SymlinkTarget],
                before: Some(Entry::Symlink {
                    target: b"old/\xff".to_vec(),
                }),
                after: Some(Entry::Symlink {
                    target: b"new/\x80".to_vec(),
                }),
            },
        ],
        summary: Summary {
            metadata_changed: 2,
            ..Summary::default()
        },
    };

    let packet = select_filesystem(&diff).unwrap();

    assert_eq!(packet.totals.filesystem_entries, 2);
    assert_eq!(packet.totals.filesystem_changes, 2);
    assert_eq!(packet.records.len(), 2);
    let EvidenceFact::FilesystemChange {
        before: Some(before),
        after: Some(after),
        changed_fields,
        ..
    } = &packet.records[0].fact
    else {
        panic!("expected filesystem metadata evidence");
    };
    assert_eq!(changed_fields, &["mode", "device_id"]);
    assert_eq!(before.device_id, Some(17));
    assert_eq!(after.device_id, Some(23));
    assert_eq!(before.mode, Some(0o600));
    assert_eq!(after.mode, Some(0o640));

    let EvidenceFact::FilesystemChange {
        before: Some(before),
        after: Some(after),
        ..
    } = &packet.records[1].fact
    else {
        panic!("expected symlink evidence");
    };
    assert_eq!(before.symlink_target.as_deref(), Some("old/%FF"));
    assert_eq!(after.symlink_target.as_deref(), Some("new/%80"));
}

#[test]
fn filesystem_summary_count_overflow_is_rejected() {
    let diff = Diff {
        summary: Summary {
            added: u64::MAX,
            removed: 1,
            ..Summary::default()
        },
        ..Diff::default()
    };

    assert_eq!(select_filesystem(&diff), Err(EvidenceError::CountOverflow));
}

#[test]
fn standalone_file_evidence_has_stable_ids_and_no_path() {
    let comparison = FileComparison {
        old_kind: InputKind::Elf,
        new_kind: InputKind::Elf,
        old_size_bytes: 64,
        new_size_bytes: 72,
        bytes_read: 136,
        bytes_changed: true,
        semantic_status: SemanticComparisonStatus::Compared,
        semantic_changes: vec![SemanticChange {
            field: "entry_point".to_owned(),
            before: json!(4096),
            after: json!(8192),
        }],
    };

    let packet = select_file_comparison(&comparison).unwrap();

    assert_eq!(packet.records.len(), 2);
    assert_eq!(packet.records[0].id.to_string(), "E0001");
    assert_eq!(packet.records[0].path, None);
    assert!(matches!(
        &packet.records[0].fact,
        EvidenceFact::BinarySemanticChange { field, .. } if field == "entry_point"
    ));
    assert_eq!(packet.records[1].id.to_string(), "E0002");
    assert!(matches!(
        &packet.records[1].fact,
        EvidenceFact::BinaryBytesChanged {
            old_size_bytes: Some(64),
            new_size_bytes: Some(72),
            ..
        }
    ));
}

#[test]
fn evidence_order_is_independent_of_input_and_fact_order() {
    let first_source = source_change(
        b"src/zeta.rs",
        vec![
            structural_change("zeta".to_owned()),
            structural_change("alpha".to_owned()),
        ],
    );
    let second_source = source_change(b"src/alpha.rs", vec![structural_change("first".to_owned())]);
    let make_binary = |path: &[u8], semantic_changes| BinaryFileChange {
        path: RelPath::new(path.to_vec()).unwrap(),
        old_kind: Some(InputKind::Elf),
        new_kind: Some(InputKind::Elf),
        old_size_bytes: Some(64),
        new_size_bytes: Some(64),
        byte_level_changed: Some(true),
        semantic_status: BinaryAnalysisStatus::Compared,
        semantic_changes,
    };
    let left = SemanticTreeDiff {
        filesystem: Diff::default(),
        source_changes: vec![first_source.clone(), second_source.clone()],
        binary_changes: vec![make_binary(
            b"bin/zeta",
            vec![
                SemanticChange {
                    field: "zeta".to_owned(),
                    before: json!(1),
                    after: json!(2),
                },
                SemanticChange {
                    field: "alpha".to_owned(),
                    before: json!(3),
                    after: json!(4),
                },
            ],
        )],
    };
    let right = SemanticTreeDiff {
        filesystem: Diff::default(),
        source_changes: vec![second_source, first_source],
        binary_changes: vec![make_binary(
            b"bin/zeta",
            vec![
                SemanticChange {
                    field: "alpha".to_owned(),
                    before: json!(3),
                    after: json!(4),
                },
                SemanticChange {
                    field: "zeta".to_owned(),
                    before: json!(1),
                    after: json!(2),
                },
            ],
        )],
    };

    assert_eq!(
        select_semantic_tree(&left).unwrap(),
        select_semantic_tree(&right).unwrap()
    );
}

#[test]
fn executable_additions_precede_routine_file_additions() {
    let mut changes = (0..9)
        .map(|index| Change {
            path: RelPath::new(format!("assets/file_{index:02}.dat").into_bytes()).unwrap(),
            category: Category::Added,
            changed_fields: vec![ChangedField::Type],
            before: None,
            after: Some(Entry::File {
                size: 12,
                mode: 0o644,
            }),
        })
        .collect::<Vec<_>>();
    changes.push(Change {
        path: RelPath::new(b"bin/service".to_vec()).unwrap(),
        category: Category::Added,
        changed_fields: vec![ChangedField::Type],
        before: None,
        after: Some(Entry::File {
            size: 128,
            mode: 0o755,
        }),
    });
    let diff = Diff {
        changes,
        summary: Summary {
            added: 10,
            ..Summary::default()
        },
    };

    let packet = select_filesystem(&diff).unwrap();

    assert_eq!(packet.records.len(), 8);
    assert!(
        packet
            .records
            .iter()
            .any(|record| record.path.as_deref() == Some("bin/service"))
    );
    assert!(
        !packet
            .records
            .iter()
            .any(|record| record.path.as_deref() == Some("assets/file_08.dat"))
    );
    assert_eq!(packet.totals.eligible_records, 10);
    assert_eq!(packet.totals.omitted_records, 2);
}

#[test]
fn packet_byte_limit_omits_complete_records_and_keeps_total_counts() {
    let changes = (0..3)
        .map(|index| Change {
            path: RelPath::new(format!("links/item_{index}").into_bytes()).unwrap(),
            category: Category::MetadataChanged,
            changed_fields: vec![ChangedField::SymlinkTarget],
            before: Some(Entry::Symlink {
                target: vec![0xff; 2_500],
            }),
            after: Some(Entry::Symlink {
                target: vec![0x80; 2_500],
            }),
        })
        .collect();
    let diff = Diff {
        changes,
        summary: Summary {
            metadata_changed: 3,
            ..Summary::default()
        },
    };

    let packet = select_filesystem(&diff).unwrap();
    let encoded = serde_json::to_vec(&packet).unwrap();

    assert_eq!(packet.records.len(), 2);
    assert_eq!(packet.totals.eligible_records, 3);
    assert_eq!(packet.totals.omitted_records, 1);
    assert!(encoded.len() <= super::MAX_EVIDENCE_BYTES);
    assert_eq!(packet.records[0].path.as_deref(), Some("links/item_0"));
    assert_eq!(packet.records[1].path.as_deref(), Some("links/item_1"));
}
