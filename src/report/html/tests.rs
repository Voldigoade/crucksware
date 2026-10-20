use std::io::{self, Write};

use crate::{
    model::{Category, Change, ChangedField, Diff, Entry, Summary},
    path::RelPath,
    readable::Language,
    report::html::{write_html, write_html_with_languages},
};

fn injection_diff() -> Diff {
    Diff {
        changes: vec![
            Change {
                path: RelPath::new(b"</script><script>alert(1)</script>|\"'&\n\xff".to_vec())
                    .unwrap(),
                category: Category::Added,
                changed_fields: Vec::new(),
                before: None,
                after: Some(Entry::File {
                    size: 4,
                    mode: 0o644,
                }),
            },
            Change {
                path: RelPath::new(b"link".to_vec()).unwrap(),
                category: Category::Modified,
                changed_fields: vec![ChangedField::Content, ChangedField::SymlinkTarget],
                before: Some(Entry::Symlink {
                    target: b"\"><script>alert('x')</script>&".to_vec(),
                }),
                after: Some(Entry::Symlink {
                    target: b"safe target".to_vec(),
                }),
            },
            Change {
                path: RelPath::new(b"kind".to_vec()).unwrap(),
                category: Category::TypeChanged,
                changed_fields: vec![ChangedField::Type],
                before: Some(Entry::File {
                    size: 0,
                    mode: 0o600,
                }),
                after: Some(Entry::Directory { mode: 0o755 }),
            },
            Change {
                path: RelPath::new(b"device".to_vec()).unwrap(),
                category: Category::MetadataChanged,
                changed_fields: vec![ChangedField::Mode, ChangedField::DeviceId],
                before: Some(Entry::CharDevice {
                    mode: 0o600,
                    device_id: 1,
                }),
                after: Some(Entry::CharDevice {
                    mode: 0o640,
                    device_id: u64::MAX,
                }),
            },
            Change {
                path: RelPath::new(b"removed".to_vec()).unwrap(),
                category: Category::Removed,
                changed_fields: Vec::new(),
                before: Some(Entry::Directory { mode: 0o755 }),
                after: None,
            },
        ],
        summary: Summary {
            added: 1,
            removed: 1,
            modified: 1,
            type_changed: 1,
            metadata_changed: 1,
            ..Summary::default()
        },
    }
}

#[test]
fn output_is_offline_deterministic_and_has_real_search_and_category_filters() {
    let diff = injection_diff();
    let mut output = Vec::new();
    write_html(&diff, &mut output).unwrap();
    let html = String::from_utf8(output.clone()).unwrap();

    assert!(html.starts_with("<!doctype html>\n<html lang=\"en\">"));
    assert!(html.ends_with("</html>\n"));
    assert!(html.contains("<title>Crucksware report</title>"));
    assert!(html.contains("<style>"));
    assert!(html.contains("<script>"));
    assert!(html.contains("id=\"path-filter\""));
    assert!(html.contains("id=\"category-filter\""));
    assert!(html.contains("data-category=\"ADDED\""));
    assert!(html.contains("data-category=\"REMOVED\""));
    assert!(html.contains("data-category=\"MODIFIED\""));
    assert!(html.contains("data-category=\"TYPE_CHANGED\""));
    assert!(html.contains("data-category=\"METADATA_CHANGED\""));
    assert!(html.contains(
        "data-path=\"%3C/script%3E%3Cscript%3Ealert%281%29%3C/script%3E%7C%22%27%26%0A%FF\""
    ));
    assert!(html.contains("target=%22%3E%3Cscript%3Ealert%28%27x%27%29%3C/script%3E%26"));
    assert!(!html.contains("alert(1)"));
    assert!(!html.contains("alert('x')"));
    assert!(!html.contains("https://"));
    assert!(!html.contains("http://"));
    assert!(!html.contains("<script src="));
    assert!(!html.contains("<link "));
    assert!(html.contains("file; size_bytes=4; mode=0644"));
    assert!(html.contains("<code>content</code>, <code>symlink_target</code>"));
    assert!(html.contains("device_id=18446744073709551615"));
    assert!(html.contains("Total changes"));

    let mut repeated = Vec::new();
    write_html(&diff, &mut repeated).unwrap();
    assert_eq!(repeated, output);
}

#[test]
fn empty_diff_renders_a_summary_without_change_groups() {
    let mut output = Vec::new();
    write_html(&Diff::default(), &mut output).unwrap();
    let html = String::from_utf8(output).unwrap();

    assert!(html.contains(">Total changes</th><td>0</td>"));
    assert!(html.contains("No changes."));
    assert!(!html.contains("<details class=\"change-group\""));
    assert!(!html.contains("<script>"));
}

#[test]
fn escapes_all_html_special_characters() {
    assert_eq!(super::escape_html("<&>\"'"), "&lt;&amp;&gt;&quot;&#39;");
    assert_eq!(super::escape_html("<\u{1}>"), "&lt;\\u{1}&gt;");
}

#[test]
fn rejects_summary_mismatches_before_writing() {
    let mut diff = injection_diff();
    diff.summary.added = 0;
    let mut output = Vec::new();

    let error = write_html(&diff, &mut output).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(output.is_empty());
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
    let error = write_html(&Diff::default(), &mut FailingWriter).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
}

#[test]
fn html_embeds_only_requested_localized_summaries_and_switches_locally() {
    let mut output = Vec::new();
    write_html_with_languages(
        &injection_diff(),
        &[Language::French, Language::Spanish],
        &mut output,
    )
    .unwrap();
    let html = String::from_utf8(output).unwrap();

    assert!(html.contains("Langue du résumé"));
    assert!(html.contains("data-readable-summary-language=\"fr\""));
    assert!(html.contains("data-readable-summary-language=\"es\""));
    assert!(!html.contains("data-readable-summary-language=\"en\""));
    assert!(html.contains("Résumé lisible"));
    assert!(html.contains("Resumen legible"));
    assert!(html.contains("id=\"summary-language\""));
    assert!(html.contains("summary.hidden = summary.dataset.readableSummaryLanguage"));
    assert!(html.contains("<html lang=\"en\">"));
    assert!(html.contains("<h2 id=\"changes-heading\">Changes</h2>"));
    assert!(!html.contains("https://"));
}

#[test]
fn invalid_html_language_sets_do_not_write_a_document_prefix() {
    for languages in [&[][..], &[Language::French, Language::French][..]] {
        let mut output = Vec::new();
        let error = write_html_with_languages(&injection_diff(), languages, &mut output)
            .expect_err("an empty or duplicate language set is invalid");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(output.is_empty());
    }
}
