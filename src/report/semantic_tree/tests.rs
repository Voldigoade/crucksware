use crate::{
    binary_compare::SemanticChange,
    input::InputKind,
    model::Diff,
    path::RelPath,
    report::semantic_tree::{write_html, write_json, write_markdown, write_text},
    semantic_tree::{BinaryAnalysisStatus, BinaryFileChange, SemanticTreeDiff},
    source::{
        SourceAnalysisStatus, SourceFileChange, SourceLanguage, StructuralAction, StructuralChange,
        StructuralKind, StructuralStatus,
    },
};

#[test]
fn source_report_wraps_the_unchanged_filesystem_schema() {
    let diff = SemanticTreeDiff {
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
        binary_changes: vec![],
    };
    let mut output = Vec::new();

    write_json(&diff, &mut output).unwrap();

    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["schema_version"], 4);
    assert_eq!(report["analysis_type"], "semantic_tree_comparison");
    assert_eq!(report["filesystem"]["schema_version"], 1);
    assert_eq!(report["source_changes"][0]["path"], "src/auth.rs");
    assert_eq!(report["source_changes"][0]["language"], "rust");
    assert_eq!(
        report["source_changes"][0]["structural_changes"][0]["action"],
        "signature_changed"
    );
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/json/schema-4.json")).unwrap();
    assert_eq!(schema["properties"]["schema_version"]["const"], 4);
    assert!(schema["properties"]["source_changes"]["items"]["properties"]["structural_changes"]["items"]["properties"]["kind"]["enum"]
        .as_array()
        .unwrap()
        .contains(&serde_json::Value::String("union".to_owned())));
    assert_eq!(output.last(), Some(&b'\n'));
}

#[test]
fn source_text_report_encodes_paths_and_quotes_structural_values() {
    let diff = SemanticTreeDiff {
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
        binary_changes: vec![],
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

#[test]
fn semantic_tree_json_encodes_binary_paths_and_preserves_large_sizes() {
    let diff = SemanticTreeDiff {
        filesystem: Diff::default(),
        source_changes: vec![],
        binary_changes: vec![BinaryFileChange {
            path: RelPath::new(b"usr/bin/a\tb".to_vec()).unwrap(),
            old_kind: Some(InputKind::Elf),
            new_kind: Some(InputKind::Elf),
            old_size_bytes: Some(u64::MAX),
            new_size_bytes: Some(u64::MAX),
            byte_level_changed: Some(true),
            semantic_status: BinaryAnalysisStatus::Compared,
            semantic_changes: vec![SemanticChange {
                field: "entry_point".to_owned(),
                before: serde_json::json!("4096"),
                after: serde_json::json!("8192"),
            }],
        }],
    };
    let mut output = Vec::new();

    write_json(&diff, &mut output).unwrap();

    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let binary = &report["binary_changes"][0];
    assert_eq!(report["schema_version"], 4);
    assert_eq!(binary["path"], "usr/bin/a%09b");
    assert_eq!(binary["old_size_bytes"], u64::MAX.to_string());
    assert_eq!(binary["new_size_bytes"], u64::MAX.to_string());
    assert_eq!(binary["semantic_changes"][0]["before"], "4096");
    assert_eq!(binary["semantic_changes"][0]["after"], "8192");

    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/json/schema-4.json")).unwrap();
    assert_eq!(schema["properties"]["schema_version"]["const"], 4);
    assert_eq!(
        schema["properties"]["analysis_type"]["const"],
        "semantic_tree_comparison"
    );
    assert_eq!(
        schema["properties"]["binary_changes"]["items"]["properties"]["semantic_status"]["enum"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    assert_eq!(
        schema["properties"]["binary_changes"]["items"]["properties"]["semantic_changes"]["items"]
            ["$ref"],
        "schema-2.json#/$defs/semanticChange"
    );
    assert_eq!(output.last(), Some(&b'\n'));
}

#[test]
fn semantic_tree_text_reports_binary_format_and_fact_changes() {
    let diff = SemanticTreeDiff {
        filesystem: Diff::default(),
        source_changes: vec![],
        binary_changes: vec![BinaryFileChange {
            path: RelPath::new(b"bin/tool".to_vec()).unwrap(),
            old_kind: Some(InputKind::Elf),
            new_kind: Some(InputKind::Elf),
            old_size_bytes: Some(64),
            new_size_bytes: Some(64),
            byte_level_changed: Some(true),
            semantic_status: BinaryAnalysisStatus::Compared,
            semantic_changes: vec![SemanticChange {
                field: "entry_point".to_owned(),
                before: serde_json::json!(4096_u64),
                after: serde_json::json!(8192_u64),
            }],
        }],
    };
    let mut output = Vec::new();

    write_text(&diff, &mut output).unwrap();

    assert_eq!(
        String::from_utf8(output).unwrap(),
        concat!(
            "Summary: added=0 removed=0 modified=0 type_changed=0 metadata_changed=0 unchanged=0\n",
            "BINARY\tbin/tool\told_kind=elf\tnew_kind=elf\told_size_bytes=64\tnew_size_bytes=64\tbyte_level_changed=true\tsemantic_status=compared\n",
            "BINARY_SEMANTIC\tbin/tool\t\"entry_point\"\tbefore=4096\tafter=8192\n",
        )
    );
}

#[test]
fn semantic_tree_markdown_is_deterministic_and_escapes_untrusted_values() {
    let diff = SemanticTreeDiff {
        filesystem: Diff::default(),
        source_changes: vec![SourceFileChange {
            path: RelPath::new(b"src/a|b.rs".to_vec()).unwrap(),
            analysis_status: SourceAnalysisStatus::Compared,
            language: Some(SourceLanguage::Rust),
            lines_added: Some(1),
            lines_removed: Some(2),
            hunk_count: Some(1),
            structural_status: StructuralStatus::Complete,
            structural_changes: vec![StructuralChange {
                action: StructuralAction::SignatureChanged,
                kind: StructuralKind::Function,
                name: "<script>|login\u{1}".to_owned(),
                before_signature: Some("fn login | old".to_owned()),
                after_signature: Some("fn login | new".to_owned()),
            }],
        }],
        binary_changes: vec![BinaryFileChange {
            path: RelPath::new(b"bin/tool".to_vec()).unwrap(),
            old_kind: Some(InputKind::Elf),
            new_kind: Some(InputKind::Elf),
            old_size_bytes: Some(12),
            new_size_bytes: Some(13),
            byte_level_changed: Some(true),
            semantic_status: BinaryAnalysisStatus::Compared,
            semantic_changes: vec![SemanticChange {
                field: "entry|point".to_owned(),
                before: serde_json::json!("<old>"),
                after: serde_json::json!("<new>"),
            }],
        }],
    };
    let mut output = Vec::new();

    write_markdown(&diff, &mut output).unwrap();
    let markdown = String::from_utf8(output.clone()).unwrap();

    assert_eq!(
        markdown,
        concat!(
            "# Crucksware report\n\n",
            "## Summary\n\n",
            "| Category | Count |\n|:--|--:|\n",
            "| Added | 0 |\n| Removed | 0 |\n| Modified | 0 |\n",
            "| Type changed | 0 |\n| Metadata changed | 0 |\n",
            "| Total filesystem changes | 0 |\n| Unchanged | 0 |\n\n",
            "## Changes\n\nNo filesystem changes.\n\n",
            "## Source analysis\n\n",
            "| Path | Status | Language | Lines added | Lines removed | Hunks | Structural status |\n",
            "|:--|:--|:--|--:|--:|--:|:--|\n",
            "| `src/a%7Cb.rs` | compared | rust | 1 | 2 | 1 | complete |\n\n",
            "### Structural changes\n\n",
            "| Path | Action | Kind | Name | Before signature | After signature |\n",
            "|:--|:--|:--|:--|:--|:--|\n",
            "| `src/a%7Cb.rs` | signature_changed | function | &lt;script&gt;\\|login\\u{1} | ",
            "fn login \\| old | fn login \\| new |\n\n",
            "## Binary analysis\n\n",
            "| Path | Old kind | New kind | Old size bytes | New size bytes | Byte-level changed | Semantic status |\n",
            "|:--|:--|:--|--:|--:|:--|:--|\n",
            "| `bin/tool` | elf | elf | 12 | 13 | true | compared |\n\n",
            "### Binary semantic changes\n\n",
            "| Path | Field | Before | After |\n|:--|:--|:--|:--|\n",
            "| `bin/tool` | entry\\|point | &quot;&lt;old&gt;&quot; | &quot;&lt;new&gt;&quot; |\n",
        )
    );
    assert!(!markdown.contains("<script>"));

    let mut repeated = Vec::new();
    write_markdown(&diff, &mut repeated).unwrap();
    assert_eq!(repeated, output);
}

#[test]
fn semantic_tree_html_is_deterministic_and_escapes_untrusted_values() {
    let diff = SemanticTreeDiff {
        filesystem: Diff::default(),
        source_changes: vec![SourceFileChange {
            path: RelPath::new(b"src/auth.rs".to_vec()).unwrap(),
            analysis_status: SourceAnalysisStatus::Compared,
            language: Some(SourceLanguage::Rust),
            lines_added: Some(1),
            lines_removed: Some(0),
            hunk_count: Some(1),
            structural_status: StructuralStatus::Complete,
            structural_changes: vec![StructuralChange {
                action: StructuralAction::Added,
                kind: StructuralKind::Function,
                name: "<script>alert(1)</script>".to_owned(),
                before_signature: None,
                after_signature: Some("fn <img src=x onerror=alert(1)>()\u{1}".to_owned()),
            }],
        }],
        binary_changes: vec![BinaryFileChange {
            path: RelPath::new(b"bin/tool".to_vec()).unwrap(),
            old_kind: Some(InputKind::Elf),
            new_kind: Some(InputKind::Elf),
            old_size_bytes: Some(64),
            new_size_bytes: Some(64),
            byte_level_changed: Some(true),
            semantic_status: BinaryAnalysisStatus::Compared,
            semantic_changes: vec![SemanticChange {
                field: "entry_point".to_owned(),
                before: serde_json::json!(4096_u64),
                after: serde_json::json!(8192_u64),
            }],
        }],
    };
    let mut output = Vec::new();

    write_html(&diff, &mut output).unwrap();
    let html = String::from_utf8(output.clone()).unwrap();

    assert!(html.contains("<title>Crucksware report</title>"));
    assert!(html.contains("Total filesystem changes"));
    assert!(html.contains("<option value=\"SOURCE\">SOURCE</option>"));
    assert!(html.contains("<option value=\"BINARY\">BINARY</option>"));
    assert!(html.contains("data-category=\"SOURCE\""));
    assert!(html.contains("data-category=\"BINARY\""));
    assert!(html.contains("fn &lt;img src=x onerror=alert(1)&gt;()\\u{1}"));
    assert!(!html.contains("<script>alert(1)</script>"));
    assert!(!html.contains("<img src=x"));
    assert!(!html.contains("https://"));
    assert!(html.contains("entry_point"));
    assert!(html.contains("4096"));
    assert!(html.contains("8192"));

    let mut repeated = Vec::new();
    write_html(&diff, &mut repeated).unwrap();
    assert_eq!(repeated, output);
}
