use serde_json::json;

use crate::{
    binary_compare::{FileComparison, SemanticChange, SemanticComparisonStatus},
    input::InputKind,
    report::binary::{write_html, write_json, write_markdown, write_text},
};

fn comparison() -> FileComparison {
    FileComparison {
        old_kind: InputKind::Elf,
        new_kind: InputKind::Elf,
        old_size_bytes: 10,
        new_size_bytes: 11,
        bytes_read: 21,
        bytes_changed: true,
        semantic_status: SemanticComparisonStatus::Compared,
        semantic_changes: vec![SemanticChange {
            field: "entry_point".to_owned(),
            before: json!(4096),
            after: json!(8192),
        }],
    }
}

#[test]
fn text_report_distinguishes_byte_and_semantic_changes() {
    let mut output = Vec::new();

    write_text(&comparison(), &mut output).unwrap();

    assert_eq!(
        String::from_utf8(output).unwrap(),
        "Binary comparison\nOld: ELF (10 bytes)\nNew: ELF (11 bytes)\nByte-level changed: yes\nSemantic comparison: compared\nSemantic fields changed: 1\nentry_point\t4096\t8192\n"
    );
}

#[test]
fn json_report_has_a_stable_schema_two_golden_and_trailing_newline() {
    let mut output = Vec::new();

    write_json(&comparison(), &mut output).unwrap();

    assert_eq!(
        String::from_utf8(output).unwrap(),
        "{\n  \"analysis_type\": \"file_comparison\",\n  \"byte_level_changed\": true,\n  \"new_kind\": \"ELF\",\n  \"new_size_bytes\": \"11\",\n  \"old_kind\": \"ELF\",\n  \"old_size_bytes\": \"10\",\n  \"schema_version\": 2,\n  \"semantic_changes\": [\n    {\n      \"after\": 8192,\n      \"before\": 4096,\n      \"field\": \"entry_point\"\n    }\n  ],\n  \"semantic_status\": \"compared\"\n}\n"
    );
}

#[test]
fn schema_two_freezes_the_file_comparison_fields_and_statuses() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/json/schema-2.json")).unwrap();

    assert_eq!(schema["properties"]["schema_version"]["const"], 2);
    assert_eq!(
        schema["properties"]["analysis_type"]["const"],
        "file_comparison"
    );
    assert_eq!(
        schema["properties"]["semantic_status"]["enum"],
        json!(["compared", "format_mismatch", "unsupported"])
    );
    let required = schema["required"].as_array().unwrap();
    assert_eq!(required.len(), 9);
    assert!(required.iter().any(|field| field == "byte_level_changed"));
    assert!(required.iter().any(|field| field == "semantic_changes"));
}

#[test]
fn markdown_file_report_is_deterministic_and_escapes_semantic_values() {
    let mut comparison = comparison();
    comparison.semantic_changes[0].field = "entry|point".to_owned();
    comparison.semantic_changes[0].before = json!("<script>|old");
    comparison.semantic_changes[0].after = json!("new|value");
    let mut output = Vec::new();

    write_markdown(&comparison, &mut output).unwrap();

    assert_eq!(
        String::from_utf8(output.clone()).unwrap(),
        concat!(
            "# Crucksware report\n\n## Summary\n\n",
            "| Field | Value |\n|:--|:--|\n",
            "| Old kind | ELF |\n| New kind | ELF |\n",
            "| Old size bytes | 10 |\n| New size bytes | 11 |\n",
            "| Byte-level changed | yes |\n| Semantic status | compared |\n",
            "| Semantic fields changed | 1 |\n\n",
            "## Semantic changes\n\n",
            "| Field | Before | After |\n|:--|:--|:--|\n",
            "| entry\\|point | &quot;&lt;script&gt;\\|old&quot; | &quot;new\\|value&quot; |\n"
        )
    );

    let mut repeated = Vec::new();
    write_markdown(&comparison, &mut repeated).unwrap();
    assert_eq!(repeated, output);
}

#[test]
fn html_file_report_is_offline_deterministic_and_escapes_semantic_values() {
    let mut comparison = comparison();
    comparison.semantic_changes[0].before = json!("</script><img src=x onerror=alert(1)>");
    let mut output = Vec::new();

    write_html(&comparison, &mut output).unwrap();
    let html = String::from_utf8(output.clone()).unwrap();

    assert!(html.starts_with("<!doctype html>\n<html lang=\"en\">"));
    assert!(html.ends_with("</html>\n"));
    assert!(html.contains("Binary comparison"));
    assert!(html.contains("entry_point"));
    assert!(html.contains("&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;"));
    assert!(!html.contains("<img src=x"));
    assert!(!html.contains("https://"));
    assert!(!html.contains("<script src="));

    let mut repeated = Vec::new();
    write_html(&comparison, &mut repeated).unwrap();
    assert_eq!(repeated, output);
}
