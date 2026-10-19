use std::{
    fs,
    io::{self, IsTerminal, Write},
    path::PathBuf,
    process::ExitCode,
};

mod progress;
mod reports;

use crucksware::{compare, compare_with_progress, limits::Limits, model::Diff};
use rustyline::{DefaultEditor, config::Configurer, error::ReadlineError};

#[derive(Default)]
struct Session {
    last_analysis: Option<LastAnalysis>,
}

struct LastAnalysis {
    diff: Diff,
    roots: Option<[PathBuf; 2]>,
}

pub fn run() -> ExitCode {
    let mut editor = match DefaultEditor::new() {
        Ok(editor) => editor,
        Err(error) => {
            eprintln!("crucksware: could not start interactive shell: {error}");
            return ExitCode::from(2);
        }
    };
    editor.set_auto_add_history(false);
    let mut session = Session::default();

    loop {
        match editor.readline("crucksware > ") {
            Ok(line) => {
                if !line.trim().is_empty()
                    && let Err(error) = editor.add_history_entry(line.as_str())
                {
                    eprintln!("crucksware: could not update command history: {error}");
                    return ExitCode::from(2);
                }
                if !execute(&line, &mut editor, &mut session) {
                    return ExitCode::SUCCESS;
                }
            }
            Err(ReadlineError::Interrupted) => println!(),
            Err(ReadlineError::Eof) => {
                println!();
                return ExitCode::SUCCESS;
            }
            Err(error) => {
                eprintln!("crucksware: interactive input failed: {error}");
                return ExitCode::from(2);
            }
        }
    }
}

fn execute(line: &str, editor: &mut DefaultEditor, session: &mut Session) -> bool {
    let line = line.trim_start();
    let Some((command, arguments)) = line.split_once(char::is_whitespace) else {
        if line.is_empty() {
            return true;
        }
        return execute_command(line, "", editor, session);
    };
    execute_command(command, arguments, editor, session)
}

fn execute_command(
    command: &str,
    arguments: &str,
    editor: &mut DefaultEditor,
    session: &mut Session,
) -> bool {
    match command {
        "help" if arguments.trim().is_empty() => print_help(),
        "clear" if arguments.trim().is_empty() => clear_screen(),
        "anal" | "analyze" if arguments.trim().is_empty() => analyze(editor, session),
        "last" if arguments.trim().is_empty() => show_last(session),
        "report" => reports::export_report(arguments, editor, session),
        "exit" | "quit" if arguments.trim().is_empty() => return false,
        _ => eprintln!("Unknown command. Type `help` for available commands."),
    }
    true
}

fn show_last(session: &Session) {
    match session.last_analysis.as_ref() {
        Some(last) => {
            if let Err(error) = write_summary(&last.diff, "Last analysis.") {
                eprintln!("crucksware: failed to write analysis summary: {error}");
            }
        }
        None => println!("No analysis has been completed in this session."),
    }
}

fn analyze(editor: &mut DefaultEditor, session: &mut Session) {
    let Some(old) = prompt_root(editor, "Before rootfs: ") else {
        return;
    };
    let Some(new) = prompt_root(editor, "After rootfs: ") else {
        return;
    };

    let resolved_old = fs::canonicalize(&old);
    let resolved_new = fs::canonicalize(&new);
    let compare_old = resolved_old.as_deref().unwrap_or(&old);
    let compare_new = resolved_new.as_deref().unwrap_or(&new);
    let limits = Limits::default();
    let result = match progress::ProgressRenderer::new() {
        Some(mut progress) => {
            let result = compare_with_progress(compare_old, compare_new, limits, |event| {
                progress.on_event(event);
            });
            progress.finish();
            result
        }
        None => compare(compare_old, compare_new, limits),
    };

    match result {
        Ok(diff) => {
            let roots = match (resolved_old, resolved_new) {
                (Ok(old), Ok(new)) => Some([old, new]),
                (Err(error), _) | (_, Err(error)) => {
                    eprintln!(
                        "crucksware: could not resolve input roots for report safety: {error}"
                    );
                    None
                }
            };
            session.last_analysis = Some(LastAnalysis { diff, roots });
            if let Some(last) = session.last_analysis.as_ref()
                && let Err(error) = write_summary(&last.diff, "Analysis complete.")
            {
                eprintln!("crucksware: failed to write analysis summary: {error}");
            }
        }
        Err(error) => eprintln!("crucksware: analysis failed: {error}"),
    }
}

fn prompt_root(editor: &mut DefaultEditor, prompt: &str) -> Option<PathBuf> {
    match editor.readline(prompt) {
        Ok(path) if path.is_empty() => {
            eprintln!("crucksware: rootfs path cannot be empty");
            None
        }
        Ok(path) => Some(PathBuf::from(path)),
        Err(ReadlineError::Interrupted) => {
            println!();
            eprintln!("crucksware: analysis cancelled");
            None
        }
        Err(ReadlineError::Eof) => {
            println!();
            None
        }
        Err(error) => {
            eprintln!("crucksware: could not read rootfs path: {error}");
            None
        }
    }
}

fn write_summary(diff: &Diff, heading: &str) -> io::Result<()> {
    let summary = &diff.summary;
    let entries = [
        summary.added,
        summary.removed,
        summary.modified,
        summary.type_changed,
        summary.metadata_changed,
        summary.unchanged,
    ]
    .into_iter()
    .try_fold(0_u64, u64::checked_add)
    .ok_or_else(|| io::Error::other("comparison entry count overflowed"))?;
    let changes = [
        summary.added,
        summary.removed,
        summary.modified,
        summary.type_changed,
        summary.metadata_changed,
    ]
    .into_iter()
    .try_fold(0_u64, u64::checked_add)
    .ok_or_else(|| io::Error::other("comparison change count overflowed"))?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{heading}")?;
    writeln!(output)?;
    writeln!(
        output,
        "{entries} {} compared",
        plural(entries, "entry", "entries")
    )?;
    writeln!(output, "{changes} {}", plural(changes, "change", "changes"))?;
    writeln!(output)?;
    writeln!(output, "Added: {}", summary.added)?;
    writeln!(output, "Removed: {}", summary.removed)?;
    writeln!(output, "Modified: {}", summary.modified)?;
    writeln!(output, "Type changed: {}", summary.type_changed)?;
    writeln!(output, "Metadata changed: {}", summary.metadata_changed)?;
    output.flush()
}

fn plural(count: u64, singular: &'static str, plural: &'static str) -> &'static str {
    if count == 1 { singular } else { plural }
}

fn print_help() {
    println!(
        "Interactive commands:\n  anal         Compare two extracted rootfs directories\n  analyze      Alias for anal\n  last         Show the latest successful analysis\n  report       Export the latest analysis as text or JSON\n  help         Show this help\n  clear        Clear the terminal\n  exit, quit   Leave Crucksware"
    );
}

fn clear_screen() {
    let stdout = io::stdout();
    if stdout.is_terminal() {
        let mut output = stdout.lock();
        let _ = output
            .write_all(b"\x1b[2J\x1b[H")
            .and_then(|()| output.flush());
    }
}
