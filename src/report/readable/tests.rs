use crate::{
    model::Diff,
    path::RelPath,
    readable::select_semantic_tree,
    semantic_tree::SemanticTreeDiff,
    source::{
        SourceAnalysisStatus, SourceFileChange, SourceLanguage, StructuralAction, StructuralChange,
        StructuralKind, StructuralStatus,
    },
};

fn packet(name: &str, path: &[u8]) -> crate::readable::EvidencePacket {
    select_semantic_tree(&SemanticTreeDiff {
        filesystem: Diff::default(),
        source_changes: vec![SourceFileChange {
            path: RelPath::new(path.to_vec()).unwrap(),
            analysis_status: SourceAnalysisStatus::Compared,
            language: Some(SourceLanguage::Rust),
            lines_added: Some(4),
            lines_removed: Some(2),
            hunk_count: Some(1),
            structural_status: StructuralStatus::Complete,
            structural_changes: vec![
                StructuralChange {
                    action: StructuralAction::Removed,
                    kind: StructuralKind::Function,
                    name: "legacy_auth".to_owned(),
                    before_signature: Some("legacy_auth(token)".to_owned()),
                    after_signature: None,
                },
                StructuralChange {
                    action: StructuralAction::Added,
                    kind: StructuralKind::Function,
                    name: name.to_owned(),
                    before_signature: None,
                    after_signature: Some(format!("{name}(token)")),
                },
            ],
        }],
        binary_changes: Vec::new(),
    })
    .unwrap()
}

#[test]
fn text_summary_is_compact_and_deterministic() {
    let packet = packet("validate_token", b"src/auth.rs");
    let mut first = Vec::new();
    let mut second = Vec::new();

    super::write_text(&packet, &mut first).unwrap();
    super::write_text(&packet, &mut second).unwrap();

    assert_eq!(first, second);
    assert_eq!(
        String::from_utf8(first).unwrap(),
        "Readable summary\nSource analysis: 1 changed file, 2 structural changes.\nNotable changes:\n- `src/auth.rs`\n  - E0001: function \"validate_token\" added.\n  - E0002: function \"legacy_auth\" removed.\n  - E0003: text changed (+4 lines, -2 lines across 1 hunk).\n"
    );
}

#[test]
fn markdown_summary_escapes_untrusted_identifiers_and_uses_encoded_paths() {
    let packet = packet("check|token", b"src/\xffauth.rs");
    let mut output = Vec::new();

    super::write_markdown(&packet, &mut output).unwrap();

    let rendered = String::from_utf8(output).unwrap();
    assert!(rendered.starts_with("## Readable summary\n\nSource analysis:"));
    assert!(rendered.contains("`src/%FFauth.rs`"));
    assert!(rendered.contains("function \"check\\|token\" added."));
}

#[test]
fn html_summary_escapes_markup_and_control_characters() {
    let packet = packet("<script>\u{0007}", b"src/\xffauth.rs");
    let mut output = Vec::new();

    super::write_html(&packet, &mut output).unwrap();

    let rendered = String::from_utf8(output).unwrap();
    assert!(rendered.contains("src/%FFauth.rs"));
    assert!(rendered.contains("&lt;script&gt;\\u{7}"));
    assert!(!rendered.contains("<script>"));
}

#[test]
fn empty_summary_and_omitted_count_are_explicit() {
    let empty = crate::readable::select_filesystem(&Diff::default()).unwrap();
    let mut output = Vec::new();
    super::write_text(&empty, &mut output).unwrap();
    assert_eq!(
        String::from_utf8(output).unwrap(),
        "Readable summary\nNo changes were found.\n"
    );

    let source_changes = (0..9)
        .map(|index| SourceFileChange {
            path: RelPath::new(format!("src/file_{index}.rs").into_bytes()).unwrap(),
            analysis_status: SourceAnalysisStatus::Compared,
            language: Some(SourceLanguage::Rust),
            lines_added: None,
            lines_removed: None,
            hunk_count: None,
            structural_status: StructuralStatus::Complete,
            structural_changes: vec![StructuralChange {
                action: StructuralAction::Added,
                kind: StructuralKind::Function,
                name: format!("function_{index}"),
                before_signature: None,
                after_signature: Some(format!("function_{index}()")),
            }],
        })
        .collect();
    let packet = select_semantic_tree(&SemanticTreeDiff {
        filesystem: Diff::default(),
        source_changes,
        binary_changes: Vec::new(),
    })
    .unwrap();
    let mut output = Vec::new();
    super::write_text(&packet, &mut output).unwrap();
    assert!(
        String::from_utf8(output)
            .unwrap()
            .contains("1 evidence record is not shown; see technical details.")
    );
}
