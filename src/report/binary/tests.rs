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
            before: json!("4096"),
            after: json!("8192"),
        }],
    }
}

#[test]
fn text_report_distinguishes_byte_and_semantic_changes() {
    let mut output = Vec::new();

    write_text(&comparison(), &mut output).unwrap();

    let output = String::from_utf8(output).unwrap();
    assert!(output.starts_with(
        "Readable summary\nBinary analysis: 2 inputs, 1 semantic field change.\nNotable changes:\n- Binary comparison\n  - E0001: binary field \"entry_point\" changed from \"4096\" to \"8192\".\n  - E0002: byte-level comparison changed; elf (10 bytes) to elf (11 bytes); semantic comparison: compared.\n\n"
    ));
    assert!(output.ends_with(
        "Binary comparison\nOld: ELF (10 bytes)\nNew: ELF (11 bytes)\nByte-level changed: yes\nSemantic comparison: compared\nSemantic fields changed: 1\nentry_point\t\"4096\"\t\"8192\"\n"
    ));
}

#[test]
fn json_report_has_a_stable_schema_six_golden_and_trailing_newline() {
    let mut output = Vec::new();

    write_json(&comparison(), &mut output).unwrap();

    assert_eq!(
        String::from_utf8(output).unwrap(),
        "{\n  \"analysis_type\": \"file_comparison\",\n  \"byte_level_changed\": true,\n  \"new_kind\": \"ELF\",\n  \"new_size_bytes\": \"11\",\n  \"old_kind\": \"ELF\",\n  \"old_size_bytes\": \"10\",\n  \"schema_version\": 6,\n  \"semantic_changes\": [\n    {\n      \"after\": \"8192\",\n      \"before\": \"4096\",\n      \"field\": \"entry_point\"\n    }\n  ],\n  \"semantic_status\": \"compared\"\n}\n"
    );
}

#[test]
fn schema_six_freezes_the_file_comparison_fields_and_wide_fact_strings() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/json/schema-6.json")).unwrap();

    assert_eq!(schema["properties"]["schema_version"]["const"], 6);
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

    let decimal_string = &schema["$defs"]["uint64DecimalString"];
    assert_eq!(decimal_string["type"], "string");
    assert_eq!(decimal_string["pattern"], "^(0|[1-9][0-9]*)$");
    assert_eq!(
        decimal_string["description"],
        "Unsigned 64-bit facts use decimal strings to preserve exact values in consumers with limited integer precision."
    );
    for field in ["entry_point", "image_base", "gnu_relro_segments"] {
        let rule = schema["$defs"]["semanticChange"]["allOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|rule| rule["if"]["properties"]["field"]["const"] == field)
            .unwrap();
        assert_eq!(
            rule["then"]["properties"]["before"]["$ref"],
            "#/$defs/uint64DecimalString"
        );
        assert_eq!(
            rule["then"]["properties"]["after"]["$ref"],
            "#/$defs/uint64DecimalString"
        );
    }
    for (field, wide_fields) in [
        ("sections", &["address", "size"][..]),
        (
            "segments",
            &["offset", "virtual_address", "file_size", "memory_size"][..],
        ),
        ("symbols", &["value", "size"][..]),
    ] {
        let rule = schema["$defs"]["semanticChange"]["allOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|rule| rule["if"]["properties"]["field"]["const"] == field)
            .unwrap();
        for wide_field in wide_fields {
            assert_eq!(
                rule["then"]["properties"]["before"]["items"]["properties"][wide_field]["$ref"],
                "#/$defs/uint64DecimalString"
            );
            assert_eq!(
                rule["then"]["properties"]["after"]["items"]["properties"][wide_field]["$ref"],
                "#/$defs/uint64DecimalString"
            );
        }
    }
}

#[test]
fn schema_two_keeps_its_original_number_compatible_contract() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/json/schema-2.json")).unwrap();

    assert_eq!(schema["properties"]["schema_version"]["const"], 2);
    assert!(schema["$defs"].is_null());
    assert!(
        schema["properties"]["semantic_changes"]["items"]["properties"]["before"]["type"]
            .as_array()
            .unwrap()
            .contains(&json!("number"))
    );
}

#[test]
fn markdown_file_report_is_deterministic_and_escapes_semantic_values() {
    let mut comparison = comparison();
    comparison.semantic_changes[0].field = "entry|point".to_owned();
    comparison.semantic_changes[0].before = json!("<script>|old");
    comparison.semantic_changes[0].after = json!("new|value");
    let mut output = Vec::new();

    write_markdown(&comparison, &mut output).unwrap();

    let markdown = String::from_utf8(output.clone()).unwrap();
    assert!(markdown.starts_with(
        concat!(
            "# Crucksware report\n\n## Readable summary\n\n",
            "Binary analysis: 2 inputs, 1 semantic field change.\n\n",
            "### Notable changes\n\n",
            "- Binary comparison\n",
            "  - **E0001**: binary field \"entry\\|point\" changed from \"\\<script\\>\\|old\" to \"new\\|value\".\n",
            "  - **E0002**: byte-level comparison changed; elf (10 bytes) to elf (11 bytes); semantic comparison: compared.\n"
        )),
        "{markdown}"
    );
    assert!(markdown.ends_with(concat!(
        "## Summary\n\n",
        "| Field | Value |\n|:--|:--|\n",
        "| Old kind | ELF |\n| New kind | ELF |\n",
        "| Old size bytes | 10 |\n| New size bytes | 11 |\n",
        "| Byte-level changed | yes |\n| Semantic status | compared |\n",
        "| Semantic fields changed | 1 |\n\n",
        "## Semantic changes\n\n",
        "| Field | Before | After |\n|:--|:--|:--|\n",
        "| entry\\|point | &quot;&lt;script&gt;\\|old&quot; | &quot;new\\|value&quot; |\n"
    )));

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
