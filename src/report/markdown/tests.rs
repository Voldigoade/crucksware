use std::io::{self, Write};

use crate::{
    model::{Category, Change, ChangedField, Diff, Entry, Summary},
    path::RelPath,
    report::markdown::write_markdown,
};

fn change(
    path_bytes: &[u8],
    category: Category,
    changed_fields: &[ChangedField],
    before: Option<Entry>,
    after: Option<Entry>,
) -> Change {
    Change {
        path: RelPath::new(path_bytes.to_vec()).unwrap(),
        category,
        changed_fields: changed_fields.to_vec(),
        before,
        after,
    }
}

fn every_category_diff() -> Diff {
    Diff {
        changes: vec![
            change(
                b"a",
                Category::Added,
                &[],
                None,
                Some(Entry::File {
                    size: 3,
                    mode: 0o644,
                }),
            ),
            change(
                b"b/\t\n|`<script>",
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
                    size: 3,
                    mode: 0o644,
                }),
                Some(Entry::File {
                    size: 3,
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
                b"e/\xff",
                Category::TypeChanged,
                &[ChangedField::Type],
                Some(Entry::File {
                    size: 0,
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
            unchanged: 8,
        },
    }
}

#[test]
fn renders_a_deterministic_golden_with_every_category_and_changed_field() {
    let diff = every_category_diff();
    let expected = concat!(
        "# Crucksware report\n\n",
        "## Summary\n\n",
        "| Category | Count |\n",
        "|:--|--:|\n",
        "| Added | 1 |\n",
        "| Removed | 1 |\n",
        "| Modified | 2 |\n",
        "| Type changed | 1 |\n",
        "| Metadata changed | 1 |\n",
        "| Total changes | 6 |\n",
        "| Unchanged | 8 |\n\n",
        "## Changes\n\n",
        "### ADDED (1)\n\n",
        "| Path | Category | Changed fields | Before | After |\n",
        "|:--|:--|:--|:--|:--|\n",
        "| `a` | `ADDED` | none | none | `file; size_bytes=3; mode=0644` |\n\n",
        "### REMOVED (1)\n\n",
        "| Path | Category | Changed fields | Before | After |\n",
        "|:--|:--|:--|:--|:--|\n",
        "| `b/%09%0A%7C%60%3Cscript%3E` | `REMOVED` | none | `directory; mode=0755` | none |\n\n",
        "### MODIFIED (2)\n\n",
        "| Path | Category | Changed fields | Before | After |\n",
        "|:--|:--|:--|:--|:--|\n",
        "| `c` | `MODIFIED` | content, mode | `file; size_bytes=3; mode=0644` | `file; size_bytes=3; mode=0755` |\n",
        "| `d` | `MODIFIED` | symlink_target | `symlink; target=old%0A` | `symlink; target=new%20%FF` |\n\n",
        "### TYPE_CHANGED (1)\n\n",
        "| Path | Category | Changed fields | Before | After |\n",
        "|:--|:--|:--|:--|:--|\n",
        "| `e/%FF` | `TYPE_CHANGED` | type | `file; size_bytes=0; mode=0600` | `symlink; target=target` |\n\n",
        "### METADATA_CHANGED (1)\n\n",
        "| Path | Category | Changed fields | Before | After |\n",
        "|:--|:--|:--|:--|:--|\n",
        "| `f` | `METADATA_CHANGED` | mode, device_id | `char_device; mode=0600; device_id=1` | `char_device; mode=0640; device_id=18446744073709551615` |\n",
    );
    let mut actual = Vec::new();
    write_markdown(&diff, &mut actual).unwrap();

    let actual_text = String::from_utf8(actual.clone()).unwrap();
    assert!(actual_text.starts_with(
        "# Crucksware report\n\n## Readable summary\n\nFilesystem: 6 changes across 14 entries (1 added, 1 removed, 2 modified, 1 type changed, 1 metadata changed, 8 unchanged).\n\n### Notable changes\n\n"
    ), "{actual_text}");
    assert!(actual_text.ends_with(expected.strip_prefix("# Crucksware report\n\n").unwrap()));
    assert!(
        !String::from_utf8(actual.clone())
            .unwrap()
            .contains("<script>")
    );

    let mut repeated = Vec::new();
    write_markdown(&diff, &mut repeated).unwrap();
    assert_eq!(repeated, actual);
}

#[test]
fn empty_diff_has_a_stable_summary_and_no_changes_message() {
    let mut actual = Vec::new();
    write_markdown(&Diff::default(), &mut actual).unwrap();

    let actual = String::from_utf8(actual).unwrap();
    assert_eq!(
        actual,
        concat!(
            "# Crucksware report\n\n",
            "## Readable summary\n\n",
            "No changes were found.\n\n",
            "## Summary\n\n",
            "| Category | Count |\n",
            "|:--|--:|\n",
            "| Added | 0 |\n",
            "| Removed | 0 |\n",
            "| Modified | 0 |\n",
            "| Type changed | 0 |\n",
            "| Metadata changed | 0 |\n",
            "| Total changes | 0 |\n",
            "| Unchanged | 0 |\n\n",
            "## Changes\n\n",
            "No changes.\n"
        )
    );
}

#[test]
fn rejects_summary_counts_that_do_not_match_changes_before_writing() {
    let mut diff = every_category_diff();
    diff.summary.added = 0;
    let mut actual = Vec::new();

    let error = write_markdown(&diff, &mut actual).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(actual.is_empty());
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
fn propagates_report_write_errors() {
    let error = write_markdown(&Diff::default(), &mut FailingWriter).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
}
