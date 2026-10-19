use std::io::{self, Write};

use super::shared::{category_name, changed_field_name, validate_diff_summary};
use crate::{
    model::{Category, ChangedField, Diff, Entry},
    path::encode_bytes,
};

#[cfg(test)]
mod tests;

pub fn write_markdown(diff: &Diff, output: &mut impl Write) -> io::Result<()> {
    write_markdown_with_labels(diff, output, "Total changes", "No changes.")
}

pub(super) fn write_markdown_with_labels(
    diff: &Diff,
    output: &mut impl Write,
    total_label: &str,
    empty_message: &str,
) -> io::Result<()> {
    let total_changes = validate_diff_summary(diff)?;

    output.write_all(b"# Crucksware report\n\n## Summary\n\n")?;
    output.write_all(b"| Category | Count |\n|:--|--:|\n")?;
    writeln!(output, "| Added | {} |", diff.summary.added)?;
    writeln!(output, "| Removed | {} |", diff.summary.removed)?;
    writeln!(output, "| Modified | {} |", diff.summary.modified)?;
    writeln!(output, "| Type changed | {} |", diff.summary.type_changed)?;
    writeln!(
        output,
        "| Metadata changed | {} |",
        diff.summary.metadata_changed
    )?;
    writeln!(output, "| {total_label} | {total_changes} |")?;
    writeln!(output, "| Unchanged | {} |\n", diff.summary.unchanged)?;
    output.write_all(b"## Changes\n\n")?;

    if diff.changes.is_empty() {
        output.write_all(empty_message.as_bytes())?;
        return output.write_all(b"\n");
    }

    let mut wrote_group = false;
    for (category, count) in [
        (Category::Added, diff.summary.added),
        (Category::Removed, diff.summary.removed),
        (Category::Modified, diff.summary.modified),
        (Category::TypeChanged, diff.summary.type_changed),
        (Category::MetadataChanged, diff.summary.metadata_changed),
    ] {
        if count == 0 {
            continue;
        }
        if wrote_group {
            output.write_all(b"\n")?;
        }
        writeln!(output, "### {} ({count})\n", category_name(category))?;
        output.write_all(
            b"| Path | Category | Changed fields | Before | After |\n|:--|:--|:--|:--|:--|\n",
        )?;
        for change in diff
            .changes
            .iter()
            .filter(|change| change.category == category)
        {
            write_change(change, output)?;
        }
        wrote_group = true;
    }

    Ok(())
}

fn write_change(change: &crate::model::Change, output: &mut impl Write) -> io::Result<()> {
    write!(
        output,
        "| `{}` | `{}` | ",
        encode_bytes(change.path.as_bytes()),
        category_name(change.category)
    )?;
    write_changed_fields(&change.changed_fields, output)?;
    output.write_all(b" | ")?;
    write_entry(change.before.as_ref(), output)?;
    output.write_all(b" | ")?;
    write_entry(change.after.as_ref(), output)?;
    output.write_all(b" |\n")
}

fn write_changed_fields(fields: &[ChangedField], output: &mut impl Write) -> io::Result<()> {
    if fields.is_empty() {
        return output.write_all(b"none");
    }
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            output.write_all(b", ")?;
        }
        output.write_all(changed_field_name(*field).as_bytes())?;
    }
    Ok(())
}

fn write_entry(entry: Option<&Entry>, output: &mut impl Write) -> io::Result<()> {
    let Some(entry) = entry else {
        return output.write_all(b"none");
    };
    match entry {
        Entry::File { size, mode } => write!(
            output,
            "`file; size_bytes={size}; mode={:04o}`",
            mode & 0o7777
        ),
        Entry::Directory { mode } => write!(output, "`directory; mode={:04o}`", mode & 0o7777),
        Entry::Symlink { target } => {
            write!(output, "`symlink; target={}`", encode_bytes(target))
        }
        Entry::Fifo { mode } => write!(output, "`fifo; mode={:04o}`", mode & 0o7777),
        Entry::Socket { mode } => write!(output, "`socket; mode={:04o}`", mode & 0o7777),
        Entry::CharDevice { mode, device_id } => write!(
            output,
            "`char_device; mode={:04o}; device_id={}`",
            mode & 0o7777,
            device_id
        ),
        Entry::BlockDevice { mode, device_id } => write!(
            output,
            "`block_device; mode={:04o}; device_id={}`",
            mode & 0o7777,
            device_id
        ),
    }
}
