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
    readable::{
        EvidenceError, EvidencePacket, Language, select_file_comparison, select_filesystem,
        select_semantic_tree,
    },
    report,
    semantic_tree::SemanticTreeDiff,
};
use rustyline::{DefaultEditor, config::Configurer, error::ReadlineError};

#[derive(Default)]
struct Session {
    last_analysis: Option<LastAnalysis>,
    evidence: Option<EvidencePacket>,
    language: Language,
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
        "language" => set_language(arguments, session),
        "explain" => explain(arguments, session),
        "report" => reports::export_report(arguments, editor, session),
        "exit" | "quit" if arguments.trim().is_empty() => return false,
        _ => eprintln!("Unknown command. Type `help` for available commands."),
    }
    true
}

fn set_language(arguments: &str, session: &mut Session) {
    let value = arguments.trim();
    if value.is_empty() {
        println!(
            "Comparison summary language: {} ({}).\nAvailable: en, fr, es, zh-CN.",
            session.language.display_name(),
            session.language.code()
        );
        return;
    }
    let Some(language) = Language::parse(value) else {
        eprintln!("Usage: language [en|fr|es|zh-CN]");
        return;
    };
    session.language = language;
    println!(
        "Comparison summary language: {} ({}).",
        language.display_name(),
        language.code()
    );
}

fn show_last(session: &Session) {
    match session.last_analysis.as_ref() {
        Some(LastAnalysis::DirectoryComparison { diff, .. }) => {
            if let Some(evidence) = &session.evidence {
                write_evidence_summary(evidence, "Last analysis.", session.language);
            } else if let Err(error) = write_summary(diff, "Last analysis.") {
                eprintln!("crucksware: failed to write analysis summary: {error}");
            }
        }
        Some(LastAnalysis::FileInspection { inspection, .. }) => {
            if let Err(error) = write_inspection_summary(inspection, "Last inspection.") {
                eprintln!("crucksware: failed to write inspection summary: {error}");
            }
        }
        Some(LastAnalysis::SourceAwareComparison { diff, .. }) => {
            if let Some(evidence) = &session.evidence {
                write_evidence_summary(evidence, "Last source-aware analysis.", session.language);
            } else if let Err(error) = write_semantic_summary(diff, "Last source-aware analysis.") {
                eprintln!("crucksware: failed to write analysis summary: {error}");
            }
        }
        Some(LastAnalysis::FileComparison { comparison, .. }) => {
            if let Some(evidence) = &session.evidence {
                write_evidence_summary(evidence, "Last file comparison.", session.language);
            } else if let Err(error) =
                write_file_comparison_summary(comparison, "Last file comparison.")
            {
                eprintln!("crucksware: failed to write comparison summary: {error}");
            }
        }
        None => println!("No analysis has been completed in this session."),
    }
}

fn explain(arguments: &str, session: &Session) {
    let selector = arguments.trim();
    if selector.is_empty() {
        eprintln!("Usage: explain ID|ENCODED_PATH|path:ENCODED_PATH|--all");
        return;
    }
    let Some(last) = session.last_analysis.as_ref() else {
        println!("No analysis has been completed in this session.");
        return;
    };
    if matches!(last, LastAnalysis::FileInspection { .. }) {
        eprintln!("crucksware: the latest session result has no comparison evidence");
        return;
    }
    let Some(evidence) = session.evidence.as_ref() else {
        eprintln!("crucksware: no selected comparison evidence is available");
        return;
    };
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let written = match report::write_evidence_explanation_in_language(
        evidence,
        selector,
        session.language,
        &mut output,
    ) {
        Ok(written) => written,
        Err(error) => {
            eprintln!("crucksware: failed to write explanation: {error}");
            return;
        }
    };
    if written == 0 {
        eprintln!("crucksware: no selected evidence matches that ID or encoded path");
        return;
    }
    if let Err(error) = output.flush() {
        eprintln!("crucksware: failed to write explanation: {error}");
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
            session.evidence = None;
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
            let evidence = select_file_comparison(&comparison);
            session.last_analysis = Some(LastAnalysis::FileComparison {
                comparison,
                inputs: report_inputs,
            });
            install_evidence(session, evidence, "File comparison complete.");
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
            let evidence = select_filesystem(&diff);
            session.last_analysis = Some(LastAnalysis::DirectoryComparison { diff, roots });
            install_evidence(session, evidence, "Analysis complete.");
        }
        Ok(DirectoryResult::SourceAware(diff)) => {
            let roots = report_roots(&resolved_old, &resolved_new);
            let evidence = select_semantic_tree(&diff);
            session.last_analysis = Some(LastAnalysis::SourceAwareComparison { diff, roots });
            install_evidence(session, evidence, "Source-aware analysis complete.");
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

fn install_evidence(
    session: &mut Session,
    evidence: Result<EvidencePacket, EvidenceError>,
    heading: &str,
) {
    match evidence {
        Ok(evidence) => {
            write_evidence_summary(&evidence, heading, session.language);
            session.evidence = Some(evidence);
        }
        Err(error) => {
            eprintln!("crucksware: could not prepare readable summary: {error}");
            session.evidence = None;
        }
    }
}

fn write_evidence_summary(evidence: &EvidencePacket, heading: &str, language: Language) {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let result = writeln!(output, "{heading}\n")
        .and_then(|()| {
            report::write_readable_summary_text_in_language(evidence, language, &mut output)
        })
        .and_then(|()| output.flush());
    if let Err(error) = result {
        eprintln!("crucksware: failed to write analysis summary: {error}");
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
        "Interactive commands:\n  anal         Inspect one input or compare files/directories\n  analyze      Alias for anal\n  last         Show the latest successful analysis\n  explain ID|ENCODED_PATH\n               Show selected evidence from the latest comparison\n  explain path:ENCODED_PATH\n               Disambiguate a path that resembles an evidence ID\n  explain --all\n               Show all selected evidence from the latest comparison\n  report       Export the latest analysis\n  language     Show or set the comparison summary language\n  help         Show this help\n  clear        Clear the terminal\n  exit, quit   Leave Crucksware"
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
