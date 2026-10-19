#[cfg(target_os = "linux")]
use std::{collections::BTreeMap, io::Read, process::Stdio};
use std::{
    fs,
    process::{Command, Output},
};

use tempfile::TempDir;

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
