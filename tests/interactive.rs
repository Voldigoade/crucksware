use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn no_arguments_starts_a_shell_that_handles_help_unknown_commands_and_exit() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_crucksware"))
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
        .stdin(Stdio::null())
        .output()
        .expect("binary starts");

    assert!(output.status.success());
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

fn run_shell(input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_crucksware"))
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
