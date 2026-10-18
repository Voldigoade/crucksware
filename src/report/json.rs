use std::io::{self, Write};

use serde::{Serialize, Serializer, ser::SerializeSeq};

use super::shared::{
    category_name, changed_field_name, device_id, file_size, format_mode, kind_name, mode,
    symlink_target,
};
use crate::{
    model::{Change, Diff, Entry, Summary},
    path::encode_bytes,
};

#[cfg(test)]
mod tests;

const SCHEMA_VERSION: u8 = 1;
const PATH_ENCODING: &str = "unix-percent-v1";

pub fn write_json(diff: &Diff, output: &mut impl Write) -> io::Result<()> {
    let report = JsonReport {
        schema_version: SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION"),
        path_encoding: PATH_ENCODING,
        summary: JsonSummary::from(&diff.summary),
        changes: JsonChanges(&diff.changes),
    };

    serde_json::to_writer_pretty(&mut *output, &report).map_err(io::Error::from)?;
    output.write_all(b"\n")
}

#[derive(Serialize)]
struct JsonReport<'a> {
    schema_version: u8,
    tool_version: &'static str,
    path_encoding: &'static str,
    summary: JsonSummary,
    changes: JsonChanges<'a>,
}

struct JsonChanges<'a>(&'a [Change]);

impl Serialize for JsonChanges<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for change in self.0 {
            sequence.serialize_element(&JsonChange::from(change))?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct JsonSummary {
    added: u64,
    removed: u64,
    modified: u64,
    type_changed: u64,
    metadata_changed: u64,
    unchanged: u64,
}

impl From<&Summary> for JsonSummary {
    fn from(summary: &Summary) -> Self {
        Self {
            added: summary.added,
            removed: summary.removed,
            modified: summary.modified,
            type_changed: summary.type_changed,
            metadata_changed: summary.metadata_changed,
            unchanged: summary.unchanged,
        }
    }
}

#[derive(Serialize)]
struct JsonChange {
    path: String,
    category: &'static str,
    changed_fields: Vec<&'static str>,
    before: Option<JsonEntry>,
    after: Option<JsonEntry>,
}

impl From<&Change> for JsonChange {
    fn from(change: &Change) -> Self {
        Self {
            path: encode_bytes(change.path.as_bytes()),
            category: category_name(change.category),
            changed_fields: change
                .changed_fields
                .iter()
                .map(|field| changed_field_name(*field))
                .collect(),
            before: change.before.as_ref().map(JsonEntry::from),
            after: change.after.as_ref().map(JsonEntry::from),
        }
    }
}

#[derive(Serialize)]
struct JsonEntry {
    kind: &'static str,
    size_bytes: Option<String>,
    mode: Option<String>,
    symlink_target: Option<String>,
    device_id: Option<String>,
}

impl From<&Entry> for JsonEntry {
    fn from(entry: &Entry) -> Self {
        Self {
            kind: kind_name(entry),
            size_bytes: file_size(entry).map(|size| size.to_string()),
            mode: mode(entry).map(format_mode),
            symlink_target: symlink_target(entry).map(encode_bytes),
            device_id: device_id(entry).map(|id| id.to_string()),
        }
    }
}
