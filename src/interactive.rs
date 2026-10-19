use std::{
    io::{self, IsTerminal, Write},
    process::ExitCode,
};

use rustyline::{DefaultEditor, config::Configurer, error::ReadlineError};

pub fn run() -> ExitCode {
    let mut editor = match DefaultEditor::new() {
        Ok(editor) => editor,
        Err(error) => {
            eprintln!("crucksware: could not start interactive shell: {error}");
            return ExitCode::from(2);
        }
    };
    editor.set_auto_add_history(false);

    loop {
        match editor.readline("crucksware > ") {
            Ok(line) => {
                if !line.trim().is_empty()
                    && let Err(error) = editor.add_history_entry(line.as_str())
                {
                    eprintln!("crucksware: could not update command history: {error}");
                    return ExitCode::from(2);
                }
                if !execute(&line) {
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

fn execute(line: &str) -> bool {
    let mut words = line.split_whitespace();
    let Some(command) = words.next() else {
        return true;
    };

    match command {
        "help" if words.next().is_none() => print_help(),
        "clear" if words.next().is_none() => clear_screen(),
        "exit" | "quit" if words.next().is_none() => return false,
        _ => eprintln!("Unknown command. Type `help` for available commands."),
    }
    true
}

fn print_help() {
    println!(
        "Interactive commands:\n  help         Show this help\n  clear        Clear the terminal\n  exit, quit   Leave Crucksware"
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
