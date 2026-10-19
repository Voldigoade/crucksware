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
