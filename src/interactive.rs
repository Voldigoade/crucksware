use std::{
    io::{self, IsTerminal, Write},
    path::PathBuf,
    process::ExitCode,
};

mod progress;

use crucksware::{compare, compare_with_progress, limits::Limits, model::Diff};
use rustyline::{DefaultEditor, config::Configurer, error::ReadlineError};

#[derive(Default)]
struct Session {
    last_analysis: Option<Diff>,
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
    let mut words = line.split_whitespace();
    let Some(command) = words.next() else {
        return true;
    };

    match command {
        "help" if words.next().is_none() => print_help(),
        "clear" if words.next().is_none() => clear_screen(),
        "anal" | "analyze" if words.next().is_none() => analyze(editor, session),
        "exit" | "quit" if words.next().is_none() => return false,
        _ => eprintln!("Unknown command. Type `help` for available commands."),
    }
    true
}

fn analyze(editor: &mut DefaultEditor, session: &mut Session) {
    let Some(old) = prompt_root(editor, "Before rootfs: ") else {
        return;
    };
    let Some(new) = prompt_root(editor, "After rootfs: ") else {
        return;
    };

    let limits = Limits::default();
    let result = match progress::ProgressRenderer::new() {
        Some(mut progress) => {
            let result = compare_with_progress(&old, &new, limits, |event| {
                progress.on_event(event);
            });
            progress.finish();
            result
        }
        None => compare(&old, &new, limits),
    };

    match result {
        Ok(diff) => {
            session.last_analysis = Some(diff);
            if let Some(diff) = session.last_analysis.as_ref()
                && let Err(error) = write_analysis_summary(diff)
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

fn write_analysis_summary(diff: &Diff) -> io::Result<()> {
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
    writeln!(output, "Analysis complete.")?;
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
        "Interactive commands:\n  anal         Compare two extracted rootfs directories\n  analyze      Alias for anal\n  help         Show this help\n  clear        Clear the terminal\n  exit, quit   Leave Crucksware"
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
