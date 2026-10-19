use std::io::{self, Write};

use serde_json::{Value, json};

use crate::{
    model::{Category, Change, ChangedField, Diff, Entry, Summary},
    path::RelPath,
    report::json::write_json,
};

fn path(bytes: &[u8]) -> RelPath {
    RelPath::new(bytes.to_vec()).unwrap()
}

fn change(
    path_bytes: &[u8],
    category: Category,
    changed_fields: &[ChangedField],
    before: Option<Entry>,
    after: Option<Entry>,
) -> Change {
    Change {
        path: path(path_bytes),
        category,
        changed_fields: changed_fields.to_vec(),
        before,
        after,
    }
}

fn complete_diff() -> Diff {
    Diff {
        changes: vec![
            change(
                b"a/\xff",
                Category::Added,
                &[],
                None,
                Some(Entry::File {
                    size: u64::MAX,
                    mode: 0o4755,
                }),
            ),
            change(
                b"b\t\n",
                Category::Removed,
                &[],
                Some(Entry::Directory { mode: 0o755 }),
                None,
            ),
            change(
                b"c",
                Category::Modified,
                &[ChangedField::Content, ChangedField::Mode],
                Some(Entry::File {
                    size: 2,
                    mode: 0o644,
                }),
                Some(Entry::File {
                    size: 2,
                    mode: 0o755,
                }),
            ),
            change(
                b"d",
                Category::Modified,
                &[ChangedField::SymlinkTarget],
                Some(Entry::Symlink {
                    target: b"old\n".to_vec(),
                }),
                Some(Entry::Symlink {
                    target: b"new \xff".to_vec(),
                }),
            ),
            change(
                b"e",
                Category::TypeChanged,
                &[ChangedField::Type],
                Some(Entry::File {
                    size: 1,
                    mode: 0o600,
                }),
                Some(Entry::Symlink {
                    target: b"target".to_vec(),
                }),
            ),
            change(
                b"f",
                Category::MetadataChanged,
                &[ChangedField::Mode, ChangedField::DeviceId],
                Some(Entry::CharDevice {
                    mode: 0o600,
                    device_id: 1,
                }),
                Some(Entry::CharDevice {
                    mode: 0o640,
                    device_id: u64::MAX,
                }),
            ),
        ],
        summary: Summary {
            added: 1,
            removed: 1,
            modified: 2,
            type_changed: 1,
            metadata_changed: 1,
            unchanged: 0,
        },
    }
}

#[test]
fn matches_the_complete_schema_one_golden_and_preserves_json_types() {
    let expected = r#"{
  "schema_version": 1,
  "tool_version": "0.1.0-dev.0",
  "path_encoding": "unix-percent-v1",
  "summary": {
    "added": 1,
    "removed": 1,
    "modified": 2,
    "type_changed": 1,
    "metadata_changed": 1,
    "unchanged": 0
  },
  "changes": [
    {
      "path": "a/%FF",
      "category": "ADDED",
      "changed_fields": [],
      "before": null,
      "after": {
        "kind": "file",
        "size_bytes": "18446744073709551615",
        "mode": "4755",
        "symlink_target": null,
        "device_id": null
      }
    },
    {
      "path": "b%09%0A",
      "category": "REMOVED",
      "changed_fields": [],
      "before": {
        "kind": "directory",
        "size_bytes": null,
        "mode": "0755",
        "symlink_target": null,
        "device_id": null
      },
      "after": null
    },
    {
      "path": "c",
      "category": "MODIFIED",
      "changed_fields": [
        "content",
        "mode"
      ],
      "before": {
        "kind": "file",
        "size_bytes": "2",
        "mode": "0644",
        "symlink_target": null,
        "device_id": null
      },
      "after": {
        "kind": "file",
        "size_bytes": "2",
        "mode": "0755",
        "symlink_target": null,
        "device_id": null
      }
    },
    {
      "path": "d",
      "category": "MODIFIED",
      "changed_fields": [
        "symlink_target"
      ],
      "before": {
        "kind": "symlink",
        "size_bytes": null,
        "mode": null,
        "symlink_target": "old%0A",
        "device_id": null
      },
      "after": {
        "kind": "symlink",
        "size_bytes": null,
        "mode": null,
        "symlink_target": "new%20%FF",
        "device_id": null
      }
    },
    {
      "path": "e",
      "category": "TYPE_CHANGED",
      "changed_fields": [
        "type"
      ],
      "before": {
        "kind": "file",
        "size_bytes": "1",
        "mode": "0600",
        "symlink_target": null,
        "device_id": null
      },
      "after": {
        "kind": "symlink",
        "size_bytes": null,
        "mode": null,
        "symlink_target": "target",
        "device_id": null
      }
    },
    {
      "path": "f",
      "category": "METADATA_CHANGED",
      "changed_fields": [
        "mode",
        "device_id"
      ],
      "before": {
        "kind": "char_device",
        "size_bytes": null,
        "mode": "0600",
        "symlink_target": null,
        "device_id": "1"
      },
      "after": {
        "kind": "char_device",
        "size_bytes": null,
        "mode": "0640",
        "symlink_target": null,
        "device_id": "18446744073709551615"
      }
    }
  ]
}
"#;
    let expected = expected.replace("0.1.0-dev.0", env!("CARGO_PKG_VERSION"));
    let mut actual = Vec::new();
    write_json(&complete_diff(), &mut actual).unwrap();

    assert_eq!(actual, expected.as_bytes());
    assert_eq!(actual.last(), Some(&b'\n'));

    let report: Value = serde_json::from_slice(&actual).unwrap();
    assert!(report["schema_version"].is_number());
    assert!(report["summary"]["added"].is_number());
    assert_eq!(
        report["changes"][0]["after"]["size_bytes"],
        "18446744073709551615"
    );
    assert_eq!(report["changes"][0]["after"]["mode"], "4755");
    assert_eq!(report["changes"][0]["before"], Value::Null);
    assert_eq!(report["changes"][1]["after"], Value::Null);
    assert_eq!(
        report["changes"][5]["after"]["device_id"],
        "18446744073709551615"
    );
}

#[test]
fn empty_diff_has_stable_pretty_json_and_a_trailing_newline() {
    let expected = concat!(
        "{\n",
        "  \"schema_version\": 1,\n",
        "  \"tool_version\": \"0.1.0-dev.0\",\n",
        "  \"path_encoding\": \"unix-percent-v1\",\n",
        "  \"summary\": {\n",
        "    \"added\": 0,\n",
        "    \"removed\": 0,\n",
        "    \"modified\": 0,\n",
        "    \"type_changed\": 0,\n",
        "    \"metadata_changed\": 0,\n",
        "    \"unchanged\": 0\n",
        "  },\n",
        "  \"changes\": []\n",
        "}\n",
    )
    .replace("0.1.0-dev.0", env!("CARGO_PKG_VERSION"));
    let mut actual = Vec::new();
    write_json(&Diff::default(), &mut actual).unwrap();

    assert_eq!(actual, expected.as_bytes());
}

#[test]
fn schema_one_freezes_the_approved_fields_types_and_values() {
    let schema: Value =
        serde_json::from_str(include_str!("../../../docs/json/schema-1.json")).unwrap();
    let properties = schema["properties"].as_object().unwrap();
    let required: Vec<_> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(Value::as_str)
        .collect();

    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(properties.len(), 5);
    assert_eq!(
        required,
        [
            Some("schema_version"),
            Some("tool_version"),
            Some("path_encoding"),
            Some("summary"),
            Some("changes"),
        ]
    );
    assert_eq!(schema["properties"]["schema_version"]["const"], 1);
    assert_eq!(schema["properties"]["tool_version"]["type"], "string");
    assert_eq!(
        schema["properties"]["path_encoding"]["const"],
        "unix-percent-v1"
    );

    let summary = &schema["properties"]["summary"];
    assert_eq!(summary["additionalProperties"], false);
    assert_eq!(summary["properties"].as_object().unwrap().len(), 6);
    for count in [
        "added",
        "removed",
        "modified",
        "type_changed",
        "metadata_changed",
        "unchanged",
    ] {
        assert_eq!(summary["properties"][count]["type"], "integer");
        assert_eq!(summary["properties"][count]["minimum"], 0);
    }

    let change_schema = &schema["$defs"]["change"];
    assert_eq!(change_schema["properties"].as_object().unwrap().len(), 5);
    assert_eq!(
        change_schema["required"],
        json!(["path", "category", "changed_fields", "before", "after"])
    );
    assert_eq!(change_schema["properties"]["path"]["minLength"], 1);
    assert_eq!(
        change_schema["properties"]["path"]["pattern"],
        r"^(?!\.{1,2}(?:/|$))(?:[A-Za-z0-9._-]|%[0-9A-F]{2})+(?:/(?!\.{1,2}(?:/|$))(?:[A-Za-z0-9._-]|%[0-9A-F]{2})+)*$(?![\s\S])"
    );
    assert_eq!(
        change_schema["properties"]["path"]["not"]["pattern"],
        r"%(?:00|2D|2E|2F|3[0-9]|4[1-9A-F]|5[0-9A]|5F|6[1-9A-F]|7[0-9A])"
    );
    assert_eq!(
        change_schema["properties"]["category"]["enum"],
        json!([
            "ADDED",
            "REMOVED",
            "MODIFIED",
            "TYPE_CHANGED",
            "METADATA_CHANGED"
        ])
    );
    assert_eq!(
        change_schema["properties"]["changed_fields"]["items"]["enum"],
        json!(["type", "content", "symlink_target", "mode", "device_id"])
    );
    assert_eq!(
        change_schema["properties"]["before"]["oneOf"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        change_schema["properties"]["after"]["oneOf"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let change_rules = change_schema["allOf"].as_array().unwrap();
    assert_eq!(change_rules.len(), 5);
    let categories: Vec<_> = change_rules
        .iter()
        .map(|rule| rule["if"]["properties"]["category"]["const"].as_str())
        .collect();
    assert_eq!(
        categories,
        [
            Some("ADDED"),
            Some("REMOVED"),
            Some("TYPE_CHANGED"),
            Some("MODIFIED"),
            Some("METADATA_CHANGED"),
        ]
    );
    assert_eq!(
        change_rules[0]["then"]["properties"]["before"]["type"],
        "null"
    );
    assert_eq!(
        change_rules[1]["then"]["properties"]["after"]["type"],
        "null"
    );
    assert_eq!(
        change_rules[2]["then"]["properties"]["changed_fields"]["const"],
        json!(["type"])
    );

    let entry = &schema["$defs"]["entry"];
    assert_eq!(entry["additionalProperties"], false);
    assert_eq!(entry["properties"].as_object().unwrap().len(), 5);
    assert_eq!(
        entry["required"],
        json!(["kind", "size_bytes", "mode", "symlink_target", "device_id"])
    );
    assert_eq!(
        entry["properties"]["kind"]["enum"],
        json!([
            "file",
            "directory",
            "symlink",
            "fifo",
            "socket",
            "char_device",
            "block_device"
        ])
    );
    assert_eq!(
        entry["properties"]["size_bytes"]["oneOf"],
        json!([
            {"type": "null"},
            {"$ref": "#/$defs/u64_decimal"}
        ])
    );
    assert_eq!(
        entry["properties"]["mode"]["type"],
        json!(["string", "null"])
    );
    assert_eq!(
        entry["properties"]["symlink_target"]["type"],
        json!(["string", "null"])
    );
    assert_eq!(
        entry["properties"]["symlink_target"]["pattern"],
        r"^(?:[A-Za-z0-9/._-]|%[0-9A-F]{2})*$(?![\s\S])"
    );
    assert_eq!(
        entry["properties"]["symlink_target"]["not"]["pattern"],
        r"%(?:00|2D|2E|2F|3[0-9]|4[1-9A-F]|5[0-9A]|5F|6[1-9A-F]|7[0-9A])"
    );
    assert_eq!(
        entry["properties"]["device_id"]["oneOf"],
        json!([
            {"type": "null"},
            {"$ref": "#/$defs/u64_decimal"}
        ])
    );
    let u64_decimal = &schema["$defs"]["u64_decimal"];
    assert_eq!(u64_decimal["type"], "string");
    assert_eq!(u64_decimal["maxLength"], 20);
    assert_eq!(
        u64_decimal["pattern"],
        r"^(?:0|[1-9][0-9]{0,18}|1[0-7][0-9]{18}|18[0-3][0-9]{17}|184[0-3][0-9]{16}|1844[0-5][0-9]{15}|18446[0-6][0-9]{14}|184467[0-3][0-9]{13}|1844674[0-3][0-9]{12}|184467440[0-6][0-9]{10}|1844674407[0-2][0-9]{9}|18446744073[0-6][0-9]{8}|1844674407370[0-8][0-9]{6}|18446744073709[0-4][0-9]{5}|184467440737095[0-4][0-9]{4}|18446744073709550[0-9]{3}|18446744073709551[0-5][0-9]{2}|1844674407370955160[0-9]{1}|1844674407370955161[0-4][0-9]{0}|18446744073709551615)$"
    );
    let entry_rules = entry["allOf"].as_array().unwrap();
    assert_eq!(entry_rules.len(), 4);
    assert_eq!(entry_rules[0]["if"]["properties"]["kind"]["const"], "file");
    assert_eq!(
        entry_rules[1]["if"]["properties"]["kind"]["enum"],
        json!(["directory", "fifo", "socket"])
    );
    assert_eq!(
        entry_rules[2]["if"]["properties"]["kind"]["const"],
        "symlink"
    );
    assert_eq!(
        entry_rules[3]["if"]["properties"]["kind"]["enum"],
        json!(["char_device", "block_device"])
    );
}

struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn preserves_json_writer_errors() {
    let error = write_json(&Diff::default(), &mut FailingWriter).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
}
