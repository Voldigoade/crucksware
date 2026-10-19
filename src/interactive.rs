use std::{
    fs,
    io::{self, IsTerminal, Write},
    path::PathBuf,
    process::ExitCode,
};

mod progress;
mod reports;

use crucksware::{
    binary_compare::{FileComparison, SemanticComparisonStatus, compare_files},
    compare, compare_semantic_tree, compare_semantic_tree_with_progress, compare_with_progress,
    inspection::{
        DEFAULT_MAX_BYTES_READ, DEFAULT_MAX_ENTRIES, FileInspection, inspect_file,
        inspect_file_with_progress,
    },
    limits::Limits,
    model::Diff,
    report,
    semantic_tree::SemanticTreeDiff,
};
use rustyline::{DefaultEditor, config::Configurer, error::ReadlineError};

#[derive(Default)]
struct Session {
    last_analysis: Option<LastAnalysis>,
}

enum LastAnalysis {
    DirectoryComparison {
        diff: Diff,
        roots: Option<[PathBuf; 2]>,
    },
    SourceAwareComparison {
        diff: SemanticTreeDiff,
        roots: Option<[PathBuf; 2]>,
    },
    FileInspection {
        inspection: Box<FileInspection>,
        input: Option<PathBuf>,
    },
    FileComparison {
        comparison: FileComparison,
        inputs: Option<[PathBuf; 2]>,
    },
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
        Some(LastAnalysis::DirectoryComparison { diff, .. }) => {
            if let Err(error) = write_summary(diff, "Last analysis.") {
                eprintln!("crucksware: failed to write analysis summary: {error}");
            }
        }
        Some(LastAnalysis::FileInspection { inspection, .. }) => {
            if let Err(error) = write_inspection_summary(inspection, "Last inspection.") {
                eprintln!("crucksware: failed to write inspection summary: {error}");
            }
        }
        Some(LastAnalysis::SourceAwareComparison { diff, .. }) => {
            if let Err(error) = write_semantic_summary(diff, "Last source-aware analysis.") {
                eprintln!("crucksware: failed to write analysis summary: {error}");
            }
        }
        Some(LastAnalysis::FileComparison { comparison, .. }) => {
            if let Err(error) = write_file_comparison_summary(comparison, "Last file comparison.") {
                eprintln!("crucksware: failed to write comparison summary: {error}");
            }
        }
        None => println!("No analysis has been completed in this session."),
    }
}

fn analyze(editor: &mut DefaultEditor, session: &mut Session) {
    println!(
        "What do you want to do?\n  1. Inspect one input\n  2. Compare two files\n  3. Compare two directories"
    );
    match prompt_analysis_choice(editor) {
        Some(AnalysisChoice::Inspect) => inspect_one(editor, session),
        Some(AnalysisChoice::CompareFiles) => compare_two_files(editor, session),
        Some(AnalysisChoice::CompareDirectories) => {
            if let Some(source_aware) = prompt_directory_mode(editor) {
                compare_directories(editor, session, source_aware);
            }
        }
        None => {}
    }
}

#[derive(Clone, Copy)]
enum AnalysisChoice {
    Inspect,
    CompareFiles,
    CompareDirectories,
}

fn prompt_analysis_choice(editor: &mut DefaultEditor) -> Option<AnalysisChoice> {
    match editor.readline("Choice: ") {
        Ok(choice) => match choice.trim() {
            "1" => Some(AnalysisChoice::Inspect),
            "2" => Some(AnalysisChoice::CompareFiles),
            "3" => Some(AnalysisChoice::CompareDirectories),
            _ => {
                eprintln!("crucksware: choose 1, 2, or 3");
                None
            }
        },
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
            eprintln!("crucksware: could not read analysis choice: {error}");
            None
        }
    }
}

fn prompt_directory_mode(editor: &mut DefaultEditor) -> Option<bool> {
    println!("Directory comparison mode?\n  1. Filesystem\n  2. Source-aware");
    match editor.readline("Choice: ") {
        Ok(choice) => match choice.trim() {
            "1" => Some(false),
            "2" => Some(true),
            _ => {
                eprintln!("crucksware: choose 1 or 2");
                None
            }
        },
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
            eprintln!("crucksware: could not read directory comparison mode: {error}");
            None
        }
    }
}

fn inspect_one(editor: &mut DefaultEditor, session: &mut Session) {
    let Some(path) = prompt_path(editor, "Input: ") else {
        return;
    };
    let report_input = fs::canonicalize(&path).ok();
    let inspection = match progress::ProgressRenderer::new() {
        Some(mut progress) => {
            let result = inspect_file_with_progress(
                &path,
                DEFAULT_MAX_BYTES_READ,
                DEFAULT_MAX_ENTRIES,
                |event| progress.on_event(event),
            );
            progress.finish();
            result
        }
        None => inspect_file(&path, DEFAULT_MAX_BYTES_READ),
    };
    match inspection {
        Ok(inspection) => {
            if let Err(error) = write_inspection_summary(&inspection, "Inspection complete.") {
                eprintln!("crucksware: failed to write inspection: {error}");
            }
            session.last_analysis = Some(LastAnalysis::FileInspection {
                inspection: Box::new(inspection),
                input: report_input,
            });
        }
        Err(error) => eprintln!("crucksware: inspection failed: {error}"),
    }
}

fn compare_two_files(editor: &mut DefaultEditor, session: &mut Session) {
    let Some(old) = prompt_path(editor, "Before file: ") else {
        return;
    };
    let Some(new) = prompt_path(editor, "After file: ") else {
        return;
    };
    let report_inputs = match (fs::canonicalize(&old), fs::canonicalize(&new)) {
        (Ok(old), Ok(new)) => Some([old, new]),
        _ => None,
    };
    let max_bytes_read = Limits::default().max_bytes_read;

    let comparison = match progress::ProgressRenderer::new() {
        Some(mut progress) => {
            let result = crucksware::binary_compare::compare_files_with_progress(
                &old,
                &new,
                max_bytes_read,
                crucksware::inspection::DEFAULT_MAX_ENTRIES,
                |event| progress.on_event(event),
            );
            progress.finish();
            result
        }
        None => compare_files(
            &old,
            &new,
            max_bytes_read,
            crucksware::inspection::DEFAULT_MAX_ENTRIES,
        ),
    };
    match comparison {
        Ok(comparison) => {
            if let Err(error) =
                write_file_comparison_summary(&comparison, "File comparison complete.")
            {
                eprintln!("crucksware: failed to write comparison: {error}");
            }
            session.last_analysis = Some(LastAnalysis::FileComparison {
                comparison,
                inputs: report_inputs,
            });
        }
        Err(error) => eprintln!("crucksware: comparison failed: {error}"),
    }
}

fn compare_directories(editor: &mut DefaultEditor, session: &mut Session, source_aware: bool) {
    let Some(old) = prompt_path(editor, "Before directory: ") else {
        return;
    };
    let Some(new) = prompt_path(editor, "After directory: ") else {
        return;
    };

    let resolved_old = fs::canonicalize(&old);
    let resolved_new = fs::canonicalize(&new);
    let compare_old = resolved_old.as_deref().unwrap_or(&old);
    let compare_new = resolved_new.as_deref().unwrap_or(&new);
    let limits = Limits::default();
    let result = match progress::ProgressRenderer::new() {
        Some(mut progress) => {
            let result = if source_aware {
                compare_semantic_tree_with_progress(
                    compare_old,
                    compare_new,
                    limits,
                    crucksware::source::DEFAULT_MAX_SOURCE_FILE_BYTES,
                    |event| progress.on_event(event),
                )
                .map(DirectoryResult::SourceAware)
            } else {
                compare_with_progress(compare_old, compare_new, limits, |event| {
                    progress.on_event(event);
                })
                .map(DirectoryResult::Filesystem)
            };
            progress.finish();
            result
        }
        None if source_aware => compare_semantic_tree(
            compare_old,
            compare_new,
            limits,
            crucksware::source::DEFAULT_MAX_SOURCE_FILE_BYTES,
        )
        .map(DirectoryResult::SourceAware),
        None => compare(compare_old, compare_new, limits).map(DirectoryResult::Filesystem),
    };

    match result {
        Ok(DirectoryResult::Filesystem(diff)) => {
            let roots = report_roots(&resolved_old, &resolved_new);
            session.last_analysis = Some(LastAnalysis::DirectoryComparison { diff, roots });
            if let Some(LastAnalysis::DirectoryComparison { diff, .. }) =
                session.last_analysis.as_ref()
                && let Err(error) = write_summary(diff, "Analysis complete.")
            {
                eprintln!("crucksware: failed to write analysis summary: {error}");
            }
        }
        Ok(DirectoryResult::SourceAware(diff)) => {
            let roots = report_roots(&resolved_old, &resolved_new);
            session.last_analysis = Some(LastAnalysis::SourceAwareComparison { diff, roots });
            if let Some(LastAnalysis::SourceAwareComparison { diff, .. }) =
                session.last_analysis.as_ref()
                && let Err(error) = write_semantic_summary(diff, "Source-aware analysis complete.")
            {
                eprintln!("crucksware: failed to write analysis summary: {error}");
            }
        }
        Err(error) => eprintln!("crucksware: analysis failed: {error}"),
    }
}

fn report_roots(
    old: &Result<PathBuf, io::Error>,
    new: &Result<PathBuf, io::Error>,
) -> Option<[PathBuf; 2]> {
    match (old, new) {
        (Ok(old), Ok(new)) => Some([old.clone(), new.clone()]),
        (Err(error), _) | (_, Err(error)) => {
            eprintln!("crucksware: could not resolve input roots for report safety: {error}");
            None
        }
    }
}

enum DirectoryResult {
    Filesystem(Diff),
    SourceAware(SemanticTreeDiff),
}

fn prompt_path(editor: &mut DefaultEditor, prompt: &str) -> Option<PathBuf> {
    match editor.readline(prompt) {
        Ok(path) if path.is_empty() => {
            eprintln!("crucksware: input path cannot be empty");
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
            eprintln!("crucksware: could not read input path: {error}");
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

fn write_inspection_summary(inspection: &FileInspection, heading: &str) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{heading}")?;
    writeln!(output)?;
    report::inspection::write_inspection(inspection, &mut output)?;
    output.flush()
}

fn write_file_comparison_summary(comparison: &FileComparison, heading: &str) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{heading}")?;
    writeln!(output)?;
    writeln!(
        output,
        "Before: {} ({} bytes)",
        comparison.old_kind, comparison.old_size_bytes
    )?;
    writeln!(
        output,
        "After: {} ({} bytes)",
        comparison.new_kind, comparison.new_size_bytes
    )?;
    writeln!(output, "Bytes read: {}", comparison.bytes_read)?;
    writeln!(
        output,
        "Byte-level changed: {}",
        if comparison.bytes_changed {
            "yes"
        } else {
            "no"
        }
    )?;
    writeln!(
        output,
        "Semantic status: {}",
        match comparison.semantic_status {
            SemanticComparisonStatus::Compared => "compared",
            SemanticComparisonStatus::FormatMismatch => "format mismatch",
            SemanticComparisonStatus::Unsupported => "unsupported",
        }
    )?;
    writeln!(
        output,
        "Semantic fields changed: {}",
        comparison.semantic_changes.len()
    )?;
    output.flush()
}

fn write_semantic_summary(diff: &SemanticTreeDiff, heading: &str) -> io::Result<()> {
    write_summary(&diff.filesystem, heading)?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(
        output,
        "Source files analyzed: {}",
        diff.source_changes.len()
    )?;
    writeln!(
        output,
        "Binary files analyzed: {}",
        diff.binary_changes.len()
    )?;
    output.flush()
}

fn plural(count: u64, singular: &'static str, plural: &'static str) -> &'static str {
    if count == 1 { singular } else { plural }
}

fn print_help() {
    println!(
        "Interactive commands:\n  anal         Inspect one input or compare files/directories\n  analyze      Alias for anal\n  last         Show the latest successful analysis\n  report       Export the latest analysis\n  help         Show this help\n  clear        Clear the terminal\n  exit, quit   Leave Crucksware"
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
