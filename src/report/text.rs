use std::io::{self, Write};

use super::shared::{category_name, device_id, format_mode, kind_name, mode, symlink_target};
use crate::{
    model::{Category, Change, ChangedField, Diff, Entry, Summary},
    path::encode_bytes,
};

#[cfg(test)]
mod tests;

pub fn write_text(diff: &Diff, output: &mut impl Write) -> io::Result<()> {
    for change in &diff.changes {
        write!(
            output,
            "{}\t{}\t",
            category_name(change.category),
            encode_bytes(change.path.as_bytes())
        )?;
        write_details(change, output)?;
        output.write_all(b"\n")?;
    }

    write_summary(&diff.summary, output)
}

fn write_details(change: &Change, output: &mut impl Write) -> io::Result<()> {
    match change.category {
        Category::Added => {
            let entry = change.after.as_ref().ok_or_else(invalid_change)?;
            write!(output, "kind={}", kind_name(entry))
        }
        Category::Removed => {
            let entry = change.before.as_ref().ok_or_else(invalid_change)?;
            write!(output, "kind={}", kind_name(entry))
        }
        Category::TypeChanged => {
            let (before, after) = entries(change)?;
            write!(output, "type={}->{}", kind_name(before), kind_name(after))
        }
        Category::Modified | Category::MetadataChanged => {
            let (before, after) = entries(change)?;
            for (index, field) in change.changed_fields.iter().enumerate() {
                if index > 0 {
                    output.write_all(b",")?;
                }
                match field {
                    ChangedField::Content => output.write_all(b"content")?,
                    ChangedField::SymlinkTarget => {
                        let (Some(old), Some(new)) =
                            (symlink_target(before), symlink_target(after))
                        else {
                            return Err(invalid_change());
                        };
                        write!(
                            output,
                            "target={}->{}",
                            encode_bytes(old),
                            encode_bytes(new)
                        )?;
                    }
                    ChangedField::Mode => {
                        let (Some(old), Some(new)) = (mode(before), mode(after)) else {
                            return Err(invalid_change());
                        };
                        write!(output, "mode={}->{}", format_mode(old), format_mode(new))?;
                    }
                    ChangedField::DeviceId => {
                        let (Some(old), Some(new)) = (device_id(before), device_id(after)) else {
                            return Err(invalid_change());
                        };
                        write!(output, "device_id={old}->{new}")?;
                    }
                    ChangedField::Type => return Err(invalid_change()),
                }
            }
            Ok(())
        }
    }
}

fn write_summary(summary: &Summary, output: &mut impl Write) -> io::Result<()> {
    writeln!(
        output,
        "Summary: added={} removed={} modified={} type_changed={} metadata_changed={} unchanged={}",
        summary.added,
        summary.removed,
        summary.modified,
        summary.type_changed,
        summary.metadata_changed,
        summary.unchanged
    )
}

fn entries(change: &Change) -> io::Result<(&Entry, &Entry)> {
    match (&change.before, &change.after) {
        (Some(before), Some(after)) => Ok((before, after)),
        _ => Err(invalid_change()),
    }
}

fn invalid_change() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid comparison change")
}
