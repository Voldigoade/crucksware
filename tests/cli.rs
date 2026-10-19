#[cfg(target_os = "linux")]
use std::{collections::BTreeMap, io::Read, process::Stdio};
use std::{
    fs,
    process::{Command, Output},
};

use tempfile::TempDir;

mod common;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_crucksware"))
}

fn roots() -> (TempDir, std::path::PathBuf, std::path::PathBuf) {
    let temporary = tempfile::tempdir().unwrap();
    let old = temporary.path().join("old");
    let new = temporary.path().join("new");
    fs::create_dir(&old).unwrap();
    fs::create_dir(&new).unwrap();
    (temporary, old, new)
}

fn run_compare(old: &std::path::Path, new: &std::path::Path, options: &[&str]) -> Output {
    let mut command = binary();
    command.arg("compare").args(options).arg(old).arg(new);
    command.output().unwrap()
}

fn run_inspect(path: &std::path::Path, options: &[&str]) -> Output {
    let mut command = binary();
    command.arg("inspect").args(options).arg(path);
    command.output().unwrap()
}

#[cfg(target_os = "linux")]
fn tree_snapshot(root: &std::path::Path) -> BTreeMap<String, (Vec<u8>, u32)> {
    fs::read_dir(root)
        .unwrap()
        .map(|item| {
            let item = item.unwrap();
            let name = item.file_name().into_string().unwrap();
            let contents = fs::read(item.path()).unwrap();
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                item.metadata().unwrap().permissions().mode() & 0o7777
            };
            #[cfg(not(unix))]
            let mode = 0;
            (name, (contents, mode))
        })
        .collect()
}

#[test]
fn help_version_and_usage_errors_use_the_documented_streams_and_statuses() {
    let help = binary().arg("--help").output().unwrap();
    assert_eq!(help.status.code(), Some(0));
    assert!(help.stderr.is_empty());
    let help_text = String::from_utf8(help.stdout).unwrap();
    assert!(help_text.contains("Usage: crucksware <COMMAND>"));
    assert!(help_text.contains("compare"));
    assert!(help_text.contains("inspect"));
    assert!(!help_text.contains("Print this message or the help of the given"));
    assert!(!help_text.contains('\u{1b}'));

    let compare_help = binary().args(["compare", "--help"]).output().unwrap();
    assert_eq!(compare_help.status.code(), Some(0));
    assert!(compare_help.stderr.is_empty());
    let compare_help_text = String::from_utf8(compare_help.stdout).unwrap();
    for option in [
        "--format",
        "--max-entries",
        "--max-depth",
        "--max-path-bytes",
        "--max-bytes-read",
    ] {
        assert!(compare_help_text.contains(option), "{option}");
    }
    assert!(!compare_help_text.contains('\u{1b}'));

    let inspect_help = binary().args(["inspect", "--help"]).output().unwrap();
    assert_eq!(inspect_help.status.code(), Some(0));
    let inspect_help_text = String::from_utf8(inspect_help.stdout).unwrap();
    assert!(inspect_help_text.contains("--max-bytes-read"));
    assert!(inspect_help_text.contains("--max-entries"));
    assert!(inspect_help_text.contains("--format"));
    assert!(inspect_help_text.contains("without executing it"));

    let version = binary().arg("--version").output().unwrap();
    assert_eq!(version.status.code(), Some(0));
    assert!(version.stderr.is_empty());
    assert_eq!(
        version.stdout,
        format!("crucksware {}\n", env!("CARGO_PKG_VERSION")).as_bytes()
    );

    for args in [vec!["compare"], vec!["--unknown"]] {
        let output = binary().args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
        assert!(!output.stderr.contains(&b'\x1b'));
    }
}

#[test]
#[cfg(target_os = "linux")]
fn equal_trees_exit_zero_and_emit_only_the_default_text_report() {
    let (_temporary, old, new) = roots();
    fs::write(old.join("same"), b"same contents").unwrap();
    fs::write(new.join("same"), b"same contents").unwrap();

    let output = run_compare(&old, &new, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout,
        b"Summary: added=0 removed=0 modified=0 type_changed=0 metadata_changed=0 unchanged=1\n"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn text_output_is_deterministic_and_comparison_does_not_modify_inputs() {
    let (_temporary, old, new) = roots();
    fs::write(old.join("same"), b"same").unwrap();
    fs::write(new.join("same"), b"same").unwrap();
    fs::write(new.join("added"), b"new").unwrap();
    let old_before = tree_snapshot(&old);
    let new_before = tree_snapshot(&new);

    let first = run_compare(&old, &new, &[]);
    let second = run_compare(&old, &new, &[]);

    assert_eq!(first.status.code(), Some(1));
    assert!(first.stderr.is_empty());
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(
        first.stdout,
        b"ADDED\tadded\tkind=file\nSummary: added=1 removed=0 modified=0 type_changed=0 metadata_changed=0 unchanged=1\n"
    );
    assert_eq!(tree_snapshot(&old), old_before);
    assert_eq!(tree_snapshot(&new), new_before);
}

#[test]
#[cfg(target_os = "linux")]
fn json_output_is_complete_and_stdout_contains_no_diagnostics() {
    let (_temporary, old, new) = roots();
    fs::write(new.join("added"), b"new").unwrap();

    let output = run_compare(&old, &new, &["--format=json"]);
    let repeated = run_compare(&old, &new, &["--format=json"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, repeated.stdout);
    assert_eq!(output.stdout.last(), Some(&b'\n'));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["path_encoding"], "unix-percent-v1");
    assert_eq!(report["summary"]["added"], 1);
    assert_eq!(report["changes"][0]["path"], "added");
    assert_eq!(report["changes"][0]["category"], "ADDED");
}

#[test]
fn compare_dispatches_file_pairs_to_binary_json_reports() {
    let temporary = tempfile::tempdir().unwrap();
    let old = temporary.path().join("old.bin");
    let new = temporary.path().join("new.bin");
    fs::write(&old, b"\0old").unwrap();
    fs::write(&new, b"\0new").unwrap();

    let output = run_compare(&old, &new, &["--format=json"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 2);
    assert_eq!(report["analysis_type"], "file_comparison");
    assert_eq!(report["old_kind"], "unknown binary");
    assert_eq!(report["new_kind"], "unknown binary");
    assert_eq!(report["byte_level_changed"], true);
    assert_eq!(report["semantic_status"], "unsupported");
}

#[test]
fn compare_dispatches_file_pairs_to_the_text_report_and_exit_code() {
    let temporary = tempfile::tempdir().unwrap();
    let old = temporary.path().join("old.txt");
    let new = temporary.path().join("new.txt");
    fs::write(&old, b"same").unwrap();
    fs::write(&new, b"same").unwrap();

    let output = run_compare(&old, &new, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(report.contains("Byte-level changed: no"));
    assert!(report.contains("Semantic comparison: unsupported"));
}

#[test]
fn compare_supports_markdown_and_html_for_directory_and_file_reports() {
    let (_temporary, old, new) = roots();
    fs::write(old.join("config"), b"old\n").unwrap();
    fs::write(new.join("config"), b"new\n").unwrap();

    let markdown = run_compare(&old, &new, &["--format=markdown"]);
    assert_eq!(markdown.status.code(), Some(1));
    assert!(markdown.stderr.is_empty());
    assert!(
        String::from_utf8(markdown.stdout)
            .unwrap()
            .contains("# Crucksware report")
    );

    let html = run_compare(&old, &new, &["--format=html"]);
    assert_eq!(html.status.code(), Some(1));
    assert!(html.stderr.is_empty());
    let html = String::from_utf8(html.stdout).unwrap();
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("MODIFIED"));
    assert!(!html.contains("https://"));

    let temporary = tempfile::tempdir().unwrap();
    let old_file = temporary.path().join("old.bin");
    let new_file = temporary.path().join("new.bin");
    fs::write(&old_file, b"old").unwrap();
    fs::write(&new_file, b"new").unwrap();
    let file_report = run_compare(&old_file, &new_file, &["--format=markdown"]);
    assert_eq!(file_report.status.code(), Some(1));
    assert!(file_report.stderr.is_empty());
    let file_report = String::from_utf8(file_report.stdout).unwrap();
    assert!(file_report.starts_with("# Crucksware report"));
    assert!(file_report.contains("| Byte-level changed | yes |"));
}

#[test]
fn source_aware_reports_keep_schema_four_and_render_semantic_formats() {
    let (_temporary, old, new) = roots();
    fs::write(old.join("main.rs"), b"fn before() {}\n").unwrap();
    fs::write(new.join("main.rs"), b"fn after() {}\n").unwrap();

    let json = run_compare(&old, &new, &["--source-aware", "--format=json"]);
    assert_eq!(json.status.code(), Some(1));
    assert!(json.stderr.is_empty());
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(json["schema_version"], 4);
    assert_eq!(json["source_changes"][0]["path"], "main.rs");

    let markdown = run_compare(&old, &new, &["--source-aware", "--format=markdown"]);
    assert_eq!(markdown.status.code(), Some(1));
    assert!(markdown.stderr.is_empty());
    let markdown = String::from_utf8(markdown.stdout).unwrap();
    assert!(markdown.contains("## Source analysis"));
    assert!(markdown.contains("before"));
    assert!(markdown.contains("after"));

    let html = run_compare(&old, &new, &["--source-aware", "--format=html"]);
    assert_eq!(html.status.code(), Some(1));
    assert!(html.stderr.is_empty());
    let html = String::from_utf8(html.stdout).unwrap();
    assert!(html.contains("SOURCE (1)"));
    assert!(html.contains("before"));
    assert!(html.contains("after"));
    assert!(!html.contains("https://"));
}

#[test]
fn inspect_supports_json_markdown_and_html_without_stdout_diagnostics() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("sample.txt");
    fs::write(&input, b"plain text\n").unwrap();

    let json = run_inspect(&input, &["--format=json"]);
    assert_eq!(json.status.code(), Some(0));
    assert!(json.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report["schema_version"], 5);
    assert_eq!(report["analysis_type"], "single_file_inspection");
    assert_eq!(report["kind"], "text");

    for format in ["markdown", "html"] {
        let output = run_inspect(&input, &[&format!("--format={format}")]);
        assert_eq!(output.status.code(), Some(0), "{format}");
        assert!(output.stderr.is_empty(), "{format}");
        let output = String::from_utf8(output.stdout).unwrap();
        assert!(output.contains("Crucksware report"));
        if format == "html" {
            assert!(output.starts_with("<!doctype html>"));
            assert!(!output.contains("https://"));
        }
    }
}

#[test]
fn inspect_elf_json_includes_static_facts_in_schema_five() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("program");
    fs::write(&input, common::minimal_elf64(0x401000)).unwrap();

    let output = run_inspect(&input, &["--format=json"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 5);
    assert_eq!(report["kind"], "elf");
    assert_eq!(report["elf"]["class"], "ELF64");
    assert_eq!(report["elf"]["byte_order"], "little-endian");
    assert_eq!(report["elf"]["entry_point"], "4198400");
    assert_eq!(report["elf"]["sections"].as_array().unwrap().len(), 0);
}

#[test]
fn compare_rejects_mixed_directory_and_file_inputs_without_a_report() {
    let temporary = tempfile::tempdir().unwrap();
    let old = temporary.path().join("old-root");
    let new = temporary.path().join("new-file");
    fs::create_dir(&old).unwrap();
    fs::write(&new, b"bytes").unwrap();

    let output = run_compare(&old, &new, &[]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("two directories or two regular files")
    );
}

#[test]
fn compare_reports_elf_semantic_changes_separately_from_bytes() {
    let temporary = tempfile::tempdir().unwrap();
    let old = temporary.path().join("old-elf");
    let new = temporary.path().join("new-elf");
    fs::write(&old, common::minimal_elf64(0x401000)).unwrap();
    fs::write(&new, common::minimal_elf64(0x402000)).unwrap();

    let output = run_compare(&old, &new, &["--format=json"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["old_kind"], "ELF");
    assert_eq!(report["byte_level_changed"], true);
    assert_eq!(report["semantic_status"], "compared");
    assert_eq!(report["semantic_changes"][0]["field"], "entry_point");
    assert_eq!(report["semantic_changes"][0]["before"], "4198400");
    assert_eq!(report["semantic_changes"][0]["after"], "4202496");
}

#[test]
fn compare_serializes_wide_binary_facts_as_exact_decimal_strings() {
    let temporary = tempfile::tempdir().unwrap();
    let old_elf = temporary.path().join("old-elf");
    let new_elf = temporary.path().join("new-elf");
    let old_entry = 9_007_199_254_740_993_u64;
    fs::write(&old_elf, common::minimal_elf64(old_entry)).unwrap();
    fs::write(&new_elf, common::minimal_elf64(old_entry + 1)).unwrap();

    let elf_output = run_compare(&old_elf, &new_elf, &["--format=json"]);
    let elf_report: serde_json::Value = serde_json::from_slice(&elf_output.stdout).unwrap();
    assert_eq!(elf_output.status.code(), Some(1));
    assert_eq!(
        elf_report["semantic_changes"][0]["before"],
        old_entry.to_string()
    );
    assert_eq!(
        elf_report["semantic_changes"][0]["after"],
        (old_entry + 1).to_string()
    );

    let old_pe = temporary.path().join("old-pe");
    let new_pe = temporary.path().join("new-pe");
    let old_base = 9_007_199_254_740_993_u64;
    let mut old_image = common::minimal_pe64(0x1000);
    let mut new_image = common::minimal_pe64(0x1000);
    old_image[0xb0..0xb8].copy_from_slice(&old_base.to_le_bytes());
    new_image[0xb0..0xb8].copy_from_slice(&(old_base + 1).to_le_bytes());
    fs::write(&old_pe, old_image).unwrap();
    fs::write(&new_pe, new_image).unwrap();

    let pe_output = run_compare(&old_pe, &new_pe, &["--format=json"]);
    let pe_report: serde_json::Value = serde_json::from_slice(&pe_output.stdout).unwrap();
    assert_eq!(pe_output.status.code(), Some(1));
    let image_base = pe_report["semantic_changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["field"] == "image_base")
        .unwrap();
    assert_eq!(image_base["before"], old_base.to_string());
    assert_eq!(image_base["after"], (old_base + 1).to_string());
}

#[test]
fn compare_reports_known_format_mismatches_explicitly() {
    let temporary = tempfile::tempdir().unwrap();
    let elf = temporary.path().join("program-elf");
    let pe = temporary.path().join("program-pe");
    fs::write(&elf, common::minimal_elf64(0x401000)).unwrap();
    fs::write(&pe, common::minimal_pe64(0x1000)).unwrap();

    let output = run_compare(&elf, &pe, &["--format=json"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["old_kind"], "ELF");
    assert_eq!(report["new_kind"], "PE");
    assert_eq!(report["semantic_status"], "format_mismatch");
    assert!(report["semantic_changes"].as_array().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn compare_preserves_non_utf8_file_arguments() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let temporary = tempfile::tempdir().unwrap();
    let old = temporary.path().join(OsStr::from_bytes(b"old-\xff"));
    let new = temporary.path().join(OsStr::from_bytes(b"new-\xfe"));
    fs::write(&old, b"\0same").unwrap();
    fs::write(&new, b"\0same").unwrap();

    let output = run_compare(&old, &new, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("Byte-level changed: no")
    );
}

#[test]
#[cfg(target_os = "linux")]
fn comparison_errors_emit_no_report_and_exit_two() {
    let temporary = tempfile::tempdir().unwrap();
    let old = temporary.path().join("missing");
    let new = temporary.path().join("new");
    fs::create_dir(&new).unwrap();

    let output = run_compare(&old, &new, &[]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
#[cfg(not(target_os = "linux"))]
fn comparison_is_rejected_on_unsupported_platform() {
    let (_temporary, old, new) = roots();

    let output = run_compare(&old, &new, &[]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
#[cfg(target_os = "linux")]
fn all_resource_limits_fail_as_input_errors_without_a_partial_report() {
    let (_temporary, old, new) = roots();
    fs::create_dir_all(old.join("nested")).unwrap();
    fs::create_dir_all(new.join("nested")).unwrap();
    fs::write(old.join("nested/file"), b"same").unwrap();
    fs::write(new.join("nested/file"), b"same").unwrap();

    for options in [
        vec!["--max-entries=1"],
        vec!["--max-depth=1"],
        vec!["--max-path-bytes=1"],
        vec!["--max-bytes-read=1"],
    ] {
        let output = run_compare(&old, &new, &options);
        assert_eq!(output.status.code(), Some(2), "{options:?}");
        assert!(output.stdout.is_empty(), "{options:?}");
        assert!(!output.stderr.is_empty(), "{options:?}");
    }
}

#[test]
fn limit_values_require_positive_ascii_decimal_u64_values() {
    let (_temporary, old, new) = roots();
    for value in ["0", "-1", "+1", "1x", "18446744073709551616"] {
        let option = format!("--max-entries={value}");
        let output = run_compare(&old, &new, &[&option]);
        assert_eq!(output.status.code(), Some(2), "{value}");
        assert!(output.stdout.is_empty(), "{value}");
        assert!(!output.stderr.is_empty(), "{value}");
    }
}

#[test]
fn unknown_format_is_a_usage_error() {
    let (_temporary, old, new) = roots();

    let output = run_compare(&old, &new, &["--format=xml"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn inspect_reports_basic_file_facts_and_keeps_stdout_clean() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("notes.exe");
    fs::write(&path, b"plain text\n").unwrap();

    let output = run_inspect(&path, &[]);
    let repeated = run_inspect(&path, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Detected kind: text"));
    assert!(stdout.contains("Size: 11 bytes"));
    assert!(stdout.contains("Content: text"));
    assert_eq!(output.stdout, repeated.stdout);
}

#[test]
fn inspect_rejects_truncated_elf_without_a_partial_report() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("not-validated.exe");
    fs::write(&path, b"\x7fELF").unwrap();

    let output = run_inspect(&path, &[]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid ELF input"));
}

#[test]
fn inspect_errors_emit_no_partial_report_and_limits_are_positive() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("input");
    fs::write(&path, vec![b'x'; 32]).unwrap();

    let limited = run_inspect(&path, &["--max-bytes-read=4"]);
    assert_eq!(limited.status.code(), Some(2));
    assert!(limited.stdout.is_empty());
    assert!(String::from_utf8_lossy(&limited.stderr).contains("bytes read limit exceeded"));

    let invalid_limit = run_inspect(&path, &["--max-bytes-read=0"]);
    assert_eq!(invalid_limit.status.code(), Some(2));
    assert!(invalid_limit.stdout.is_empty());
    assert!(!invalid_limit.stderr.is_empty());

    let invalid_entry_limit = run_inspect(&path, &["--max-entries=0"]);
    assert_eq!(invalid_entry_limit.status.code(), Some(2));
    assert!(invalid_entry_limit.stdout.is_empty());
    assert!(!invalid_entry_limit.stderr.is_empty());

    let directory = run_inspect(temporary.path(), &[]);
    assert_eq!(directory.status.code(), Some(2));
    assert!(directory.stdout.is_empty());
}

#[test]
#[cfg(target_os = "linux")]
fn inspect_preserves_non_utf8_and_option_terminated_paths() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join(OsStr::from_bytes(b"payload-\xff"));
    fs::write(&path, b"text").unwrap();

    let non_utf8 = run_inspect(&path, &[]);
    assert_eq!(non_utf8.status.code(), Some(0));
    assert!(non_utf8.stderr.is_empty());
    assert!(
        String::from_utf8(non_utf8.stdout)
            .unwrap()
            .contains("Detected kind: text")
    );

    let dash_path = temporary.path().join("-payload");
    fs::write(&dash_path, b"dash").unwrap();
    let terminated = binary()
        .current_dir(temporary.path())
        .args(["inspect", "--", "-payload"])
        .output()
        .unwrap();
    assert_eq!(terminated.status.code(), Some(0));
    assert!(terminated.stderr.is_empty());
}

#[cfg(target_pointer_width = "32")]
#[test]
fn depth_limit_must_fit_usize() {
    let (_temporary, old, new) = roots();

    let output = run_compare(&old, &new, &["--max-depth=4294967296"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
#[cfg(target_os = "linux")]
fn option_terminator_allows_root_names_that_begin_with_a_dash() {
    let temporary = tempfile::tempdir().unwrap();
    let old = temporary.path().join("-old");
    let new = temporary.path().join("-new");
    fs::create_dir(&old).unwrap();
    fs::create_dir(&new).unwrap();

    let output = binary()
        .current_dir(temporary.path())
        .args(["compare", "--", "-old", "-new"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn non_utf8_root_arguments_are_preserved() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let temporary = tempfile::tempdir().unwrap();
    let old_name = OsString::from_vec(b"old-\xff".to_vec());
    let new_name = OsString::from_vec(b"new-\xfe".to_vec());
    let old = temporary.path().join(old_name);
    let new = temporary.path().join(new_name);
    fs::create_dir(&old).unwrap();
    fs::create_dir(&new).unwrap();

    let output = run_compare(&old, &new, &[]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .starts_with("Summary: added=0")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn output_write_failure_exits_two() {
    use std::fs::OpenOptions;

    let (_temporary, old, new) = roots();
    fs::write(new.join("added"), b"new").unwrap();
    let full = OpenOptions::new().write(true).open("/dev/full").unwrap();
    let mut child = binary()
        .arg("compare")
        .arg(&old)
        .arg(&new)
        .stdout(full)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let status = child.wait().unwrap();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();

    assert_eq!(status.code(), Some(2));
    assert!(!stderr.is_empty());
}
