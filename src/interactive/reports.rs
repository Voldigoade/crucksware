use std::{
    fs::{self, File},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
};

use crucksware::report;
use rustyline::{DefaultEditor, error::ReadlineError};
use tempfile::NamedTempFile;

use super::{LastAnalysis, Session};

#[derive(Clone, Copy)]
enum ReportFormat {
    Text,
    Json,
    Markdown,
    Html,
}

enum ReportDestination {
    New,
    Replace,
}

pub(super) fn export_report(arguments: &str, editor: &mut DefaultEditor, session: &Session) {
    let arguments = arguments.trim_start();
    let (format, output_argument) = match arguments.split_once(char::is_whitespace) {
        Some((format, output_argument)) => (format, output_argument),
        None => (arguments, ""),
    };
    if format.is_empty() {
        eprintln!("Usage: report <text|json|markdown|html> [OUTPUT]");
        return;
    }
    let format = match format {
        "text" => ReportFormat::Text,
        "json" => ReportFormat::Json,
        "markdown" => ReportFormat::Markdown,
        "html" => ReportFormat::Html,
        _ => {
            eprintln!("crucksware: report format must be `text`, `json`, `markdown`, or `html`");
            return;
        }
    };
    let Some(last) = session.last_analysis.as_ref() else {
        println!("No analysis has been completed in this session.");
        return;
    };
    let output_path = if output_argument.is_empty() {
        match prompt_report_path(editor) {
            Some(path) => path,
            None => return,
        }
    } else {
        PathBuf::from(output_argument)
    };

    match write_report(last, &output_path, format, editor) {
        Ok(true) => println!("Report written."),
        Ok(false) => println!("Report export cancelled."),
        Err(error) => eprintln!("crucksware: failed to write report: {error}"),
    }
}

fn prompt_report_path(editor: &mut DefaultEditor) -> Option<PathBuf> {
    match editor.readline("Report output path: ") {
        Ok(path) if !path.is_empty() => Some(PathBuf::from(path)),
        Ok(_) => {
            eprintln!("crucksware: report output path cannot be empty");
            None
        }
        Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
            println!();
            None
        }
        Err(error) => {
            eprintln!("crucksware: could not read report output path: {error}");
            None
        }
    }
}

fn write_report(
    last: &LastAnalysis,
    path: &Path,
    format: ReportFormat,
    editor: &mut DefaultEditor,
) -> io::Result<bool> {
    let target = match last {
        LastAnalysis::DirectoryComparison { roots, .. }
        | LastAnalysis::SourceAwareComparison { roots, .. } => {
            let roots = roots.as_ref().ok_or_else(input_paths_unavailable)?;
            ensure_outside_roots(path, roots)?
        }
        LastAnalysis::FileInspection { input, .. } => {
            let input = input.as_ref().ok_or_else(input_paths_unavailable)?;
            ensure_not_inputs(path, std::slice::from_ref(input))?
        }
        LastAnalysis::FileComparison { inputs, .. } => {
            let inputs = inputs.as_ref().ok_or_else(input_paths_unavailable)?;
            ensure_not_inputs(path, inputs)?
        }
    };
    let Some(destination) = open_report_destination(&target, editor)? else {
        return Ok(false);
    };
    let replace = matches!(destination, ReportDestination::Replace);
    publish_report(&target, replace, |file| {
        write_report_contents(last, format, file)
    })?;
    Ok(true)
}

fn publish_report(
    path: &Path,
    replace: bool,
    render: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = NamedTempFile::new_in(parent)?;
    render(temporary.as_file_mut())?;
    temporary.as_file_mut().flush()?;

    if replace {
        temporary
            .persist(path)
            .map(|_| ())
            .map_err(|error| error.error)
    } else {
        temporary
            .persist_noclobber(path)
            .map(|_| ())
            .map_err(|error| error.error)
    }
}

fn write_report_contents(
    last: &LastAnalysis,
    format: ReportFormat,
    file: &mut File,
) -> io::Result<()> {
    let mut output = BufWriter::new(file);
    match (last, format) {
        (LastAnalysis::DirectoryComparison { diff, .. }, ReportFormat::Text) => {
            report::text::write_text(diff, &mut output)?
        }
        (LastAnalysis::DirectoryComparison { diff, .. }, ReportFormat::Json) => {
            report::json::write_json(diff, &mut output)?
        }
        (LastAnalysis::DirectoryComparison { diff, .. }, ReportFormat::Markdown) => {
            report::markdown::write_markdown(diff, &mut output)?
        }
        (LastAnalysis::DirectoryComparison { diff, .. }, ReportFormat::Html) => {
            report::html::write_html(diff, &mut output)?
        }
        (LastAnalysis::SourceAwareComparison { diff, .. }, ReportFormat::Text) => {
            report::semantic_tree::write_text(diff, &mut output)?
        }
        (LastAnalysis::SourceAwareComparison { diff, .. }, ReportFormat::Json) => {
            report::semantic_tree::write_json(diff, &mut output)?
        }
        (LastAnalysis::SourceAwareComparison { diff, .. }, ReportFormat::Markdown) => {
            report::semantic_tree::write_markdown(diff, &mut output)?
        }
        (LastAnalysis::SourceAwareComparison { diff, .. }, ReportFormat::Html) => {
            report::semantic_tree::write_html(diff, &mut output)?
        }
        (LastAnalysis::FileInspection { inspection, .. }, ReportFormat::Text) => {
            report::inspection::write_inspection(inspection, &mut output)?
        }
        (LastAnalysis::FileInspection { inspection, .. }, ReportFormat::Json) => {
            report::inspection::write_inspection_json(inspection, &mut output)?
        }
        (LastAnalysis::FileInspection { inspection, .. }, ReportFormat::Markdown) => {
            report::inspection::write_markdown(inspection, &mut output)?
        }
        (LastAnalysis::FileInspection { inspection, .. }, ReportFormat::Html) => {
            report::inspection::write_html(inspection, &mut output)?
        }
        (LastAnalysis::FileComparison { comparison, .. }, ReportFormat::Text) => {
            report::binary::write_text(comparison, &mut output)?
        }
        (LastAnalysis::FileComparison { comparison, .. }, ReportFormat::Json) => {
            report::binary::write_json(comparison, &mut output)?
        }
        (LastAnalysis::FileComparison { comparison, .. }, ReportFormat::Markdown) => {
            report::binary::write_markdown(comparison, &mut output)?
        }
        (LastAnalysis::FileComparison { comparison, .. }, ReportFormat::Html) => {
            report::binary::write_html(comparison, &mut output)?
        }
    }
    output.flush()
}

fn ensure_outside_roots(path: &Path, roots: &[PathBuf; 2]) -> io::Result<PathBuf> {
    let target = report_target(path)?;
    for root in roots {
        if target.starts_with(root) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "report output cannot be inside a compared rootfs",
            ));
        }
    }
    Ok(target)
}

fn ensure_not_inputs(path: &Path, inputs: &[PathBuf]) -> io::Result<PathBuf> {
    let target = report_target(path)?;
    if inputs.contains(&target) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "report output cannot replace an analyzed input",
        ));
    }
    Ok(target)
}

fn input_paths_unavailable() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "input paths are unavailable")
}

fn report_target(path: &Path) -> io::Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "report output cannot be a symbolic link",
            ));
        }
        Ok(_) => return fs::canonicalize(path),
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        Err(_) => {}
    }

    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "report output path has no file name",
        )
    })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(fs::canonicalize(parent)?.join(name))
}

fn open_report_destination(
    path: &Path,
    editor: &mut DefaultEditor,
) -> io::Result<Option<ReportDestination>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_replace_target(&metadata)?;
            if !confirm_overwrite(editor)? {
                return Ok(None);
            }
            let metadata = fs::symlink_metadata(path)?;
            validate_replace_target(&metadata)?;
            Ok(Some(ReportDestination::Replace))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Some(ReportDestination::New)),
        Err(error) => Err(error),
    }
}

fn ensure_regular_file(metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "existing report destination is not a regular file",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_replace_target(metadata: &fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    ensure_regular_file(metadata)?;
    if metadata.nlink() > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to replace an existing report with multiple hard links",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_replace_target(metadata: &fs::Metadata) -> io::Result<()> {
    ensure_regular_file(metadata)?;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "refusing to replace an existing report because hard links cannot be checked on this platform",
    ))
}

fn confirm_overwrite(editor: &mut DefaultEditor) -> io::Result<bool> {
    match editor.readline("Overwrite existing report? [y/N]: ") {
        Ok(answer) => Ok(matches!(
            answer.trim().to_ascii_lowercase().as_str(),
            "y" | "yes"
        )),
        Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
            println!();
            Ok(false)
        }
        Err(error) => Err(io::Error::other(format!(
            "could not read overwrite confirmation: {error}"
        ))),
    }
}

#[cfg(test)]
mod tests;
