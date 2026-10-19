use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn no_arguments_starts_a_shell_that_handles_help_unknown_commands_and_exit() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_crucksware"))
        .env("TERM", "dumb")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(b"help\nunknown\nexit\nunknown-after-exit\n")
        .expect("commands are written");

    let output = child.wait_with_output().expect("shell exits");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("shell output is UTF-8");
    assert!(stdout.contains("Interactive commands:"));
    assert!(stdout.contains("anal"));
    assert!(stdout.contains("analyze"));
    assert!(!stdout.contains("\u{1b}["));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr)
            .matches("Unknown command.")
            .count(),
        1
    );
}

#[test]
fn shell_exits_normally_at_end_of_input() {
    let output = Command::new(env!("CARGO_BIN_EXE_crucksware"))
        .env("TERM", "dumb")
        .stdin(Stdio::null())
        .output()
        .expect("binary starts");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
}

#[test]
fn clear_is_silent_without_a_terminal_and_quit_exits_the_shell() {
    let output = run_shell(b"clear\nhelp\nquit\nhelp\n");
    let without_clear = run_shell(b"help\nquit\n");

    assert!(output.status.success());
    assert!(without_clear.status.success());
    let stdout = String::from_utf8(output.stdout).expect("shell output is UTF-8");
    assert_eq!(
        stdout.strip_prefix("crucksware > ").unwrap().as_bytes(),
        without_clear.stdout
    );
    assert_eq!(output.stderr, without_clear.stderr);
    assert!(stdout.contains("crucksware >"));
    assert_eq!(stdout.matches("Interactive commands:").count(), 1);
    assert!(!stdout.contains('\u{1b}'));
    assert!(output.stderr.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn anal_prompts_for_paths_with_spaces_and_reports_the_real_comparison() {
    let temporary = tempfile::tempdir().expect("temporary directory is created");
    let old = temporary.path().join("old rootfs");
    let new = temporary.path().join("new rootfs");
    std::fs::create_dir(&old).expect("old rootfs is created");
    std::fs::create_dir(&new).expect("new rootfs is created");
    std::fs::write(old.join("config file"), b"before").expect("old file is written");
    std::fs::write(new.join("config file"), b"after!").expect("new file is written");

    let input = format!("anal\n{}\n{}\nexit\n", old.display(), new.display());
    let output = run_shell(input.as_bytes());

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Analysis complete."));
    assert!(stdout.contains("1 entry compared"));
    assert!(stdout.contains("1 change"));
    assert!(stdout.contains("Modified: 1"));
    assert!(output.stderr.is_empty());
    assert_eq!(std::fs::read(old.join("config file")).unwrap(), b"before");
    assert_eq!(std::fs::read(new.join("config file")).unwrap(), b"after!");
}

#[cfg(target_os = "linux")]
#[test]
fn analyze_is_an_alias_for_anal() {
    let temporary = tempfile::tempdir().expect("temporary directory is created");
    let old = temporary.path().join("old");
    let new = temporary.path().join("new");
    std::fs::create_dir(&old).expect("old rootfs is created");
    std::fs::create_dir(&new).expect("new rootfs is created");

    let input = format!("analyze\n{}\n{}\nexit\n", old.display(), new.display());
    let output = run_shell(input.as_bytes());

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Analysis complete."));
    assert!(stdout.contains("0 entries compared"));
    assert!(stdout.contains("0 changes"));
    assert!(output.stderr.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn analysis_summary_counts_every_change_category_and_unchanged_entry() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempfile::tempdir().expect("temporary directory is created");
    let old = temporary.path().join("old");
    let new = temporary.path().join("new");
    std::fs::create_dir(&old).expect("old rootfs is created");
    std::fs::create_dir(&new).expect("new rootfs is created");
    std::fs::write(old.join("removed"), b"old").expect("removed file is written");
    std::fs::write(old.join("modified"), b"before").expect("old modified file is written");
    std::fs::write(new.join("added"), b"new").expect("added file is written");
    std::fs::write(new.join("modified"), b"after!").expect("new modified file is written");
    std::fs::write(old.join("kind"), b"file").expect("old type-change entry is written");
    std::fs::create_dir(new.join("kind")).expect("new type-change entry is created");
    std::fs::create_dir(old.join("mode")).expect("old metadata entry is created");
    std::fs::create_dir(new.join("mode")).expect("new metadata entry is created");
    std::fs::set_permissions(old.join("mode"), std::fs::Permissions::from_mode(0o700))
        .expect("old metadata mode is set");
    std::fs::set_permissions(new.join("mode"), std::fs::Permissions::from_mode(0o755))
        .expect("new metadata mode is set");
    std::fs::write(old.join("same"), b"unchanged").expect("old unchanged file is written");
    std::fs::write(new.join("same"), b"unchanged").expect("new unchanged file is written");

    let input = format!("anal\n{}\n{}\nexit\n", old.display(), new.display());
    let output = run_shell(input.as_bytes());

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("6 entries compared"));
    assert!(stdout.contains("5 changes"));
    assert!(stdout.contains("Added: 1"));
    assert!(stdout.contains("Removed: 1"));
    assert!(stdout.contains("Modified: 1"));
    assert!(stdout.contains("Type changed: 1"));
    assert!(stdout.contains("Metadata changed: 1"));
    assert!(output.stderr.is_empty());
}

#[test]
fn last_reports_when_no_analysis_has_been_completed() {
    let output = run_shell(b"last\nreport text\nexit\n");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("No analysis has been completed in this session."));
    assert!(!stdout.contains("Report output path:"));
    assert!(output.stderr.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn last_shows_the_most_recent_successful_analysis() {
    let temporary = tempfile::tempdir().expect("temporary directory is created");
    let old = temporary.path().join("old");
    let new = temporary.path().join("new");
    std::fs::create_dir(&old).expect("old rootfs is created");
    std::fs::create_dir(&new).expect("new rootfs is created");
    std::fs::write(new.join("added"), b"new").expect("new file is written");

    let input = format!("anal\n{}\n{}\nlast\nexit\n", old.display(), new.display());
    let output = run_shell(input.as_bytes());

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Analysis complete."));
    assert!(stdout.contains("Last analysis."));
    assert!(stdout.contains("1 entry compared"));
    assert!(stdout.contains("Added: 1"));
    assert!(output.stderr.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn report_exports_text_and_json_to_paths_with_spaces() {
    let temporary = tempfile::tempdir().expect("temporary directory is created");
    let old = temporary.path().join("old");
    let new = temporary.path().join("new");
    std::fs::create_dir(&old).expect("old rootfs is created");
    std::fs::create_dir(&new).expect("new rootfs is created");
    std::fs::write(new.join("added"), b"new").expect("new file is written");
    let text_path = temporary.path().join("text report.txt");
    let json_path = temporary.path().join("json report.json");

    let input = format!(
        "anal\n{}\n{}\nreport text {}\nreport json {}\nexit\n",
        old.display(),
        new.display(),
        text_path.display(),
        json_path.display()
    );
    let output = run_shell(input.as_bytes());

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let text = std::fs::read_to_string(text_path).expect("text report is written");
    assert!(text.starts_with("ADDED\tadded\tkind=file\n"));
    assert!(text.ends_with(
        "Summary: added=1 removed=0 modified=0 type_changed=0 metadata_changed=0 unchanged=0\n"
    ));
    let json = std::fs::read_to_string(json_path).expect("JSON report is written");
    assert!(json.ends_with('\n'));
    let report: serde_json::Value = serde_json::from_str(&json).expect("JSON report parses");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["changes"][0]["path"], "added");
}

#[cfg(target_os = "linux")]
#[test]
fn report_exports_markdown_with_safe_paths_and_summary() {
    let temporary = tempfile::tempdir().expect("temporary directory is created");
    let old = temporary.path().join("old");
    let new = temporary.path().join("new");
    let input_file = new.join("new | <script>");
    let report_path = temporary.path().join("markdown report.md");
    std::fs::create_dir(&old).expect("old rootfs is created");
    std::fs::create_dir(&new).expect("new rootfs is created");
    std::fs::write(&input_file, b"new").expect("new file is written");

    let input = format!(
        "anal\n{}\n{}\nreport markdown {}\nexit\n",
        old.display(),
        new.display(),
        report_path.display()
    );
    let output = run_shell(input.as_bytes());

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let markdown = std::fs::read_to_string(report_path).expect("Markdown report is written");
    assert!(markdown.starts_with("# Crucksware report\n\n## Summary\n"));
    assert!(markdown.contains("`new%20%7C%20%3Cscript%3E`"));
    assert!(!markdown.contains("<script>"));
    assert!(markdown.contains("| Total changes | 1 |"));
    assert_eq!(std::fs::read(input_file).unwrap(), b"new");
}

#[cfg(target_os = "linux")]
#[test]
fn report_exports_self_contained_html() {
    let temporary = tempfile::tempdir().expect("temporary directory is created");
    let old = temporary.path().join("old");
    let new = temporary.path().join("new");
    let input_file = new.join("input <script>");
    let report_path = temporary.path().join("html report.html");
    std::fs::create_dir(&old).expect("old rootfs is created");
    std::fs::create_dir(&new).expect("new rootfs is created");
    std::fs::write(&input_file, b"new").expect("new file is written");

    let input = format!(
        "anal\n{}\n{}\nreport html {}\nexit\n",
        old.display(),
        new.display(),
        report_path.display()
    );
    let output = run_shell(input.as_bytes());

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let html = std::fs::read_to_string(report_path).expect("HTML report is written");
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("input%20%3Cscript%3E"));
    assert!(!html.contains("input <script>"));
    assert!(html.contains("id=\"path-filter\""));
    assert!(html.contains("id=\"category-filter\""));
    assert!(!html.contains("https://"));
    assert_eq!(std::fs::read(input_file).unwrap(), b"new");
}

#[cfg(target_os = "linux")]
#[test]
fn report_preserves_leading_and_trailing_spaces_in_output_names() {
    let temporary = tempfile::tempdir().expect("temporary directory is created");
    let old = temporary.path().join("old");
    let new = temporary.path().join("new");
    let report_path = temporary.path().join(" report with spaces.txt ");
    std::fs::create_dir(&old).expect("old rootfs is created");
    std::fs::create_dir(&new).expect("new rootfs is created");
    std::fs::write(new.join("added"), b"new").expect("new file is written");

    let input = format!(
        "anal\n{}\n{}\nreport text {}\nexit\n",
        old.display(),
        new.display(),
        report_path.display()
    );
    let output = run_shell(input.as_bytes());

    assert!(output.status.success());
    assert!(
        std::fs::read_to_string(report_path)
            .expect("report with whitespace in its name is written")
            .starts_with("ADDED\tadded\tkind=file\n")
    );
    assert!(output.stderr.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn report_prompts_for_a_path_when_one_is_not_supplied() {
    let temporary = tempfile::tempdir().expect("temporary directory is created");
    let old = temporary.path().join("old");
    let new = temporary.path().join("new");
    let report_path = temporary.path().join("prompted report.md");
    std::fs::create_dir(&old).expect("old rootfs is created");
    std::fs::create_dir(&new).expect("new rootfs is created");
    std::fs::write(new.join("added"), b"new").expect("new file is written");

    let input = format!(
        "anal\n{}\n{}\nreport text\n{}\nexit\n",
        old.display(),
        new.display(),
        report_path.display()
    );
    let output = run_shell(input.as_bytes());

    assert!(output.status.success());
    assert!(
        std::fs::read_to_string(report_path)
            .expect("prompted report is written")
            .contains("ADDED\tadded\tkind=file")
    );
    assert!(output.stderr.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn report_requires_confirmation_before_overwriting_an_existing_file() {
    let temporary = tempfile::tempdir().expect("temporary directory is created");
    let old = temporary.path().join("old");
    let new = temporary.path().join("new");
    let report_path = temporary.path().join("existing report.txt");
    std::fs::create_dir(&old).expect("old rootfs is created");
    std::fs::create_dir(&new).expect("new rootfs is created");
    std::fs::write(new.join("added"), b"new").expect("new file is written");
    std::fs::write(&report_path, b"keep this report").expect("existing report is written");

    let input = format!(
        "anal\n{}\n{}\nreport text {}\nn\nexit\n",
        old.display(),
        new.display(),
        report_path.display()
    );
    let output = run_shell(input.as_bytes());

    assert!(output.status.success());
    assert_eq!(std::fs::read(&report_path).unwrap(), b"keep this report");
    assert!(String::from_utf8_lossy(&output.stdout).contains("Report export cancelled."));
    assert!(output.stderr.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn report_rejects_a_directory_destination_without_changing_it() {
    let temporary = tempfile::tempdir().expect("temporary directory is created");
    let old = temporary.path().join("old");
    let new = temporary.path().join("new");
    let destination = temporary.path().join("report directory");
    std::fs::create_dir(&old).expect("old rootfs is created");
    std::fs::create_dir(&new).expect("new rootfs is created");
    std::fs::create_dir(&destination).expect("report destination directory is created");

    let input = format!(
        "anal\n{}\n{}\nreport text {}\nexit\n",
        old.display(),
        new.display(),
        destination.display()
    );
    let output = run_shell(input.as_bytes());

    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Report written."));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a regular file"));
    assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(&old).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(&new).unwrap().count(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn report_overwrites_an_existing_file_after_explicit_confirmation() {
    let temporary = tempfile::tempdir().expect("temporary directory is created");
    let old = temporary.path().join("old");
    let new = temporary.path().join("new");
    let report_path = temporary.path().join("existing report.txt");
    std::fs::create_dir(&old).expect("old rootfs is created");
    std::fs::create_dir(&new).expect("new rootfs is created");
    std::fs::write(new.join("added"), b"new").expect("new file is written");
    std::fs::write(&report_path, b"replace this report").expect("existing report is written");

    let input = format!(
        "anal\n{}\n{}\nreport text {}\nyes\nexit\n",
        old.display(),
        new.display(),
        report_path.display()
    );
    let output = run_shell(input.as_bytes());

    assert!(output.status.success());
    assert!(
        std::fs::read_to_string(report_path)
            .expect("confirmed report is written")
            .starts_with("ADDED\tadded\tkind=file\n")
    );
    assert!(output.stderr.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn report_refuses_to_write_inside_a_compared_rootfs() {
    let temporary = tempfile::tempdir().expect("temporary directory is created");
    let old = temporary.path().join("old");
    let new = temporary.path().join("new");
    std::fs::create_dir(&old).expect("old rootfs is created");
    std::fs::create_dir(&new).expect("new rootfs is created");
    std::fs::write(new.join("added"), b"new").expect("new file is written");
    let report_path = old.join("report.txt");

    let input = format!(
        "anal\n{}\n{}\nreport text {}\nexit\n",
        old.display(),
        new.display(),
        report_path.display()
    );
    let output = run_shell(input.as_bytes());

    assert!(output.status.success());
    assert!(!report_path.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("compared rootfs"));
}

#[cfg(target_os = "linux")]
#[test]
fn report_refuses_a_symlinked_parent_that_resolves_inside_a_compared_rootfs() {
    let temporary = tempfile::tempdir().expect("temporary directory is created");
    let old = temporary.path().join("old");
    let new = temporary.path().join("new");
    let alias = temporary.path().join("output alias");
    std::fs::create_dir(&old).expect("old rootfs is created");
    std::fs::create_dir(&new).expect("new rootfs is created");
    std::fs::write(new.join("added"), b"new").expect("new file is written");
    std::os::unix::fs::symlink(&old, &alias).expect("output alias is created");
    let report_path = alias.join("report.txt");

    let input = format!(
        "anal\n{}\n{}\nreport text {}\nexit\n",
        old.display(),
        new.display(),
        report_path.display()
    );
    let output = run_shell(input.as_bytes());

    assert!(output.status.success());
    assert!(!old.join("report.txt").exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("compared rootfs"));
}

#[cfg(target_os = "linux")]
#[test]
fn report_refuses_to_replace_a_hard_linked_rootfs_file() {
    let temporary = tempfile::tempdir().expect("temporary directory is created");
    let old = temporary.path().join("old");
    let new = temporary.path().join("new");
    let source_file = old.join("source.txt");
    let report_path = temporary.path().join("report.txt");
    std::fs::create_dir(&old).expect("old rootfs is created");
    std::fs::create_dir(&new).expect("new rootfs is created");
    std::fs::write(&source_file, b"preserve source bytes").expect("source file is written");
    std::fs::hard_link(&source_file, &report_path).expect("report path is hard linked");

    let input = format!(
        "anal\n{}\n{}\nreport text {}\nexit\n",
        old.display(),
        new.display(),
        report_path.display()
    );
    let output = run_shell(input.as_bytes());

    assert!(output.status.success());
    assert_eq!(
        std::fs::read(&source_file).unwrap(),
        b"preserve source bytes"
    );
    assert_eq!(
        std::fs::read(report_path).unwrap(),
        b"preserve source bytes"
    );
    use std::os::unix::fs::MetadataExt;
    assert_eq!(std::fs::metadata(source_file).unwrap().nlink(), 2);
    assert!(String::from_utf8_lossy(&output.stderr).contains("multiple hard links"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Overwrite existing report?"));
}

#[cfg(target_os = "linux")]
#[test]
fn report_refuses_symlink_destinations_without_modifying_the_target() {
    let temporary = tempfile::tempdir().expect("temporary directory is created");
    let old = temporary.path().join("old");
    let new = temporary.path().join("new");
    let source_file = old.join("source.txt");
    let report_path = temporary.path().join("report.txt");
    std::fs::create_dir(&old).expect("old rootfs is created");
    std::fs::create_dir(&new).expect("new rootfs is created");
    std::fs::write(&source_file, b"preserve source bytes").expect("source file is written");
    std::os::unix::fs::symlink(&source_file, &report_path).expect("report link is created");

    let input = format!(
        "anal\n{}\n{}\nreport text {}\nexit\n",
        old.display(),
        new.display(),
        report_path.display()
    );
    let output = run_shell(input.as_bytes());

    assert!(output.status.success());
    assert_eq!(
        std::fs::read(source_file).unwrap(),
        b"preserve source bytes"
    );
    assert!(
        std::fs::symlink_metadata(report_path)
            .expect("report symlink remains")
            .file_type()
            .is_symlink()
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("symbolic link"));
}

#[cfg(target_os = "linux")]
#[test]
fn failed_analysis_does_not_replace_the_last_successful_result() {
    let temporary = tempfile::tempdir().expect("temporary directory is created");
    let old = temporary.path().join("old");
    let new = temporary.path().join("new");
    let missing = temporary.path().join("missing");
    std::fs::create_dir(&old).expect("old rootfs is created");
    std::fs::create_dir(&new).expect("new rootfs is created");
    std::fs::write(new.join("added"), b"new").expect("new file is written");

    let input = format!(
        "anal\n{}\n{}\nanal\n{}\n{}\nlast\nexit\n",
        old.display(),
        new.display(),
        missing.display(),
        new.display()
    );
    let output = run_shell(input.as_bytes());

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Last analysis."));
    assert!(stdout.contains("Added: 1"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("analysis failed"));
}

fn run_shell(input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_crucksware"))
        .env("TERM", "dumb")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary starts");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(input)
        .expect("commands are written");
    child.wait_with_output().expect("shell exits")
}
