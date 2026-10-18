use std::io::{self, Write};

use crate::{
    model::{Category, Change, ChangedField, Diff, Entry, Summary},
    path::RelPath,
    report::text::write_text,
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

#[test]
fn renders_every_category_and_field_with_encoded_paths_and_targets() {
    let diff = Diff {
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
                b"b/\t\n",
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
    };

    let expected = concat!(
        "ADDED\ta\tkind=file\n",
        "REMOVED\tb/%09%0A\tkind=directory\n",
        "MODIFIED\tc\tcontent,mode=0644->0755\n",
        "MODIFIED\td\ttarget=old%0A->new%20%FF\n",
        "TYPE_CHANGED\te/%FF\ttype=file->symlink\n",
        "METADATA_CHANGED\tf\tmode=0600->0640,device_id=1->18446744073709551615\n",
        "Summary: added=1 removed=1 modified=2 type_changed=1 metadata_changed=1 unchanged=8\n",
    );
    let mut actual = Vec::new();
    write_text(&diff, &mut actual).unwrap();
    assert_eq!(actual, expected.as_bytes());

    let mut repeated = Vec::new();
    write_text(&diff, &mut repeated).unwrap();
    assert_eq!(repeated, actual);
}

#[test]
fn empty_diff_has_only_the_summary_line() {
    let mut actual = Vec::new();
    write_text(&Diff::default(), &mut actual).unwrap();

    assert_eq!(
        actual,
        b"Summary: added=0 removed=0 modified=0 type_changed=0 metadata_changed=0 unchanged=0\n"
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
fn propagates_report_write_errors() {
    let error = write_text(&Diff::default(), &mut FailingWriter).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
}
