use crate::{
    model::Diff,
    path::RelPath,
    report::source::{write_json, write_text},
    source::{
        SourceAnalysisStatus, SourceDiff, SourceFileChange, SourceLanguage, StructuralAction,
        StructuralChange, StructuralKind, StructuralStatus,
    },
};

#[test]
fn source_report_wraps_the_unchanged_filesystem_schema() {
    let diff = SourceDiff {
        filesystem: Diff::default(),
        source_changes: vec![SourceFileChange {
            path: RelPath::new(b"src/auth.rs".to_vec()).unwrap(),
            analysis_status: SourceAnalysisStatus::Compared,
            language: Some(SourceLanguage::Rust),
            lines_added: Some(1),
            lines_removed: Some(1),
            hunk_count: Some(1),
            structural_status: StructuralStatus::Complete,
            structural_changes: vec![StructuralChange {
                action: StructuralAction::SignatureChanged,
                kind: StructuralKind::Function,
                name: "login".to_owned(),
                before_signature: Some("fn login ( user : & str )".to_owned()),
                after_signature: Some("fn login ( user : & str , otp : u32 )".to_owned()),
            }],
        }],
    };
    let mut output = Vec::new();

    write_json(&diff, &mut output).unwrap();

    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["schema_version"], 3);
    assert_eq!(report["analysis_type"], "source_tree_comparison");
    assert_eq!(report["filesystem"]["schema_version"], 1);
    assert_eq!(report["source_changes"][0]["path"], "src/auth.rs");
    assert_eq!(report["source_changes"][0]["language"], "rust");
    assert_eq!(
        report["source_changes"][0]["structural_changes"][0]["action"],
        "signature_changed"
    );
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/json/schema-3.json")).unwrap();
    assert_eq!(schema["properties"]["schema_version"]["const"], 3);
    assert!(schema["properties"]["source_changes"]["items"]["properties"]["structural_changes"]["items"]["properties"]["kind"]["enum"]
        .as_array()
        .unwrap()
        .contains(&serde_json::Value::String("union".to_owned())));
    assert_eq!(output.last(), Some(&b'\n'));
}

#[test]
fn source_text_report_encodes_paths_and_quotes_structural_values() {
    let diff = SourceDiff {
        filesystem: Diff::default(),
        source_changes: vec![SourceFileChange {
            path: RelPath::new(b"src/a\tb.rs".to_vec()).unwrap(),
            analysis_status: SourceAnalysisStatus::Compared,
            language: Some(SourceLanguage::Rust),
            lines_added: Some(1),
            lines_removed: Some(1),
            hunk_count: Some(1),
            structural_status: StructuralStatus::Complete,
            structural_changes: vec![StructuralChange {
                action: StructuralAction::SignatureChanged,
                kind: StructuralKind::Function,
                name: "login".to_owned(),
                before_signature: Some("fn login".to_owned()),
                after_signature: Some("fn login ( otp )".to_owned()),
            }],
        }],
    };
    let mut output = Vec::new();

    write_text(&diff, &mut output).unwrap();

    assert_eq!(
        String::from_utf8(output).unwrap(),
        concat!(
            "Summary: added=0 removed=0 modified=0 type_changed=0 metadata_changed=0 unchanged=0\n",
            "SOURCE\tsrc/a%09b.rs\tlines_added=1,lines_removed=1,hunks=1\tlanguage=rust\tstructural_status=complete\n",
            "STRUCTURE\tsignature_changed\tfunction\t\"login\"\tbefore=\"fn login\"\tafter=\"fn login ( otp )\"\n",
        )
    );
}
