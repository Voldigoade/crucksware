use crate::{
    input::InputKind,
    inspection::{
        ContentKind, FileInspection, PeCertificateTable, PeExport, PeExportTarget, PeImport,
        PeImportName, PeInspection, PePdbInfo, PeResource, PeResourceId, PeSection,
    },
    report::inspection::{write_html, write_inspection_json, write_markdown},
};

fn unknown_binary(size_bytes: u64) -> FileInspection {
    FileInspection {
        kind: InputKind::UnknownBinary,
        size_bytes,
        bytes_read: 3,
        semantic_entries: 0,
        input_stamp: None,
        content: ContentKind::Binary,
        elf: None,
        pe: None,
    }
}

#[test]
fn json_inspection_uses_schema_five_and_preserves_large_sizes_as_strings() {
    let mut output = Vec::new();

    write_inspection_json(&unknown_binary(u64::MAX), &mut output).unwrap();

    assert_eq!(
        String::from_utf8(output).unwrap(),
        concat!(
            "{\n",
            "  \"analysis_type\": \"single_file_inspection\",\n",
            "  \"content\": \"binary\",\n",
            "  \"elf\": null,\n",
            "  \"kind\": \"unknown_binary\",\n",
            "  \"pe\": null,\n",
            "  \"schema_version\": 5,\n",
            "  \"size_bytes\": \"18446744073709551615\"\n",
            "}\n"
        )
    );

    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/json/schema-5.json")).unwrap();
    assert_eq!(schema["properties"]["schema_version"]["const"], 5);
    assert_eq!(
        schema["properties"]["analysis_type"]["const"],
        "single_file_inspection"
    );
    assert!(
        schema["required"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("size_bytes"))
    );
    assert_eq!(schema["$defs"]["decimal_string"]["maxLength"], 20);
    assert!(
        schema["$defs"]["decimal_string"]["pattern"]
            .as_str()
            .unwrap()
            .starts_with("^(0|[1-9]")
    );
    assert_eq!(
        schema["$defs"]["pe_export"]["properties"]["name"]["oneOf"][1]["$ref"],
        "#/$defs/encoded_bytes"
    );
}

#[test]
fn markdown_and_html_inspection_reports_are_offline_and_repeatable() {
    let inspection = unknown_binary(3);
    let mut markdown = Vec::new();
    write_markdown(&inspection, &mut markdown).unwrap();
    let markdown = String::from_utf8(markdown.clone()).unwrap();
    assert!(markdown.starts_with("# Crucksware report\n\n## Summary\n"));
    assert!(markdown.contains("unknown_binary"));
    assert!(markdown.contains("\"schema_version\": 5"));
    let mut repeated_markdown = Vec::new();
    write_markdown(&inspection, &mut repeated_markdown).unwrap();
    assert_eq!(repeated_markdown, markdown.as_bytes());

    let mut html = Vec::new();
    write_html(&inspection, &mut html).unwrap();
    let html = String::from_utf8(html.clone()).unwrap();
    assert!(html.starts_with("<!doctype html>\n<html lang=\"en\">"));
    assert!(html.ends_with("</html>\n"));
    assert!(html.contains("unknown_binary"));
    assert!(html.contains("&quot;schema_version&quot;: 5"));
    assert!(!html.contains("https://"));
    assert!(!html.contains("<script"));
    let mut repeated_html = Vec::new();
    write_html(&inspection, &mut repeated_html).unwrap();
    assert_eq!(repeated_html, html.as_bytes());
}

#[test]
fn pe_inspection_json_preserves_every_static_fact_and_encodes_byte_names() {
    let inspection = FileInspection {
        kind: InputKind::Pe,
        size_bytes: 100,
        bytes_read: 100,
        semantic_entries: 1,
        input_stamp: None,
        content: ContentKind::Binary,
        elf: None,
        pe: Some(PeInspection {
            entries_read: 7,
            format: "PE32+",
            architecture: "x86_64".to_owned(),
            machine: 0x8664,
            entry_point_rva: 0x1000,
            image_base: 0x1_4000_0000,
            subsystem: 3,
            sections: vec![PeSection {
                name: b".text\xff".to_vec(),
                virtual_address: 0x1000,
                virtual_size: 12,
                raw_offset: 0x400,
                raw_size: 512,
                characteristics: 0x6000_0020,
            }],
            imports: vec![PeImport {
                library: b"KERNEL32.dll".to_vec(),
                name: PeImportName::Name(b"ExitProcess".to_vec()),
            }],
            delay_imports: vec![PeImport {
                library: b"PLUGIN.dll".to_vec(),
                name: PeImportName::Ordinal(12),
            }],
            exports: vec![PeExport {
                ordinal: 4,
                name: Some(b"start\xff".to_vec()),
                target: PeExportTarget::ForwardedName {
                    library: b"other.dll".to_vec(),
                    name: b"entry".to_vec(),
                },
            }],
            resources: vec![PeResource {
                path: vec![
                    PeResourceId::Name(b"ICON\xff".to_vec()),
                    PeResourceId::Id(3),
                ],
                data_rva: 0x5000,
                size: 64,
                code_page: 1200,
            }],
            pdb_info: Some(PePdbInfo {
                path: b"C:\\build\\app.pdb".to_vec(),
                guid: [0xab; 16],
                age: 2,
            }),
            certificate_table: Some(PeCertificateTable {
                file_offset: 80,
                size: 20,
            }),
        }),
    };
    let mut output = Vec::new();

    write_inspection_json(&inspection, &mut output).unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let pe = &report["pe"];

    assert_eq!(report["kind"], "pe");
    assert_eq!(pe["format"], "PE32+");
    assert_eq!(pe["machine"], "34404");
    assert_eq!(pe["entry_point_rva"], "4096");
    assert_eq!(pe["image_base"], "5368709120");
    assert_eq!(pe["sections"][0]["name"], ".text%FF");
    assert_eq!(pe["imports"][0]["name"]["value"], "ExitProcess");
    assert_eq!(pe["delay_imports"][0]["name"]["value"], "12");
    assert_eq!(pe["exports"][0]["target"]["kind"], "forwarded_name");
    assert_eq!(pe["resources"][0]["path"][0]["value"], "ICON%FF");
    assert_eq!(pe["pdb_info"]["guid"], "abababababababababababababababab");
    assert_eq!(pe["certificate_table"]["size_bytes"], "20");
    assert_eq!(output.last(), Some(&b'\n'));
}
