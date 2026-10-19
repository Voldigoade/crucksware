use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crucksware::report;
use rustyline::{DefaultEditor, error::ReadlineError};

use super::{LastAnalysis, Session};

#[derive(Clone, Copy)]
enum ReportFormat {
    Text,
    Json,
    Markdown,
    Html,
}

enum ReportDestination {
    New(File),
    Replace,
}

static REPORT_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    let roots = last.roots.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "input rootfs paths are unavailable; refusing report export",
        )
    })?;
    let target = ensure_outside_roots(path, roots)?;
    let Some(destination) = open_report_destination(&target, editor)? else {
        return Ok(false);
    };
    match destination {
        ReportDestination::New(file) => write_report_contents(last, format, file)?,
        ReportDestination::Replace => {
            let (temporary_path, file) = create_temporary_report(&target)?;
            if let Err(error) = write_report_contents(last, format, file) {
                let _ = fs::remove_file(&temporary_path);
                return Err(error);
            }
            if let Err(error) = fs::rename(&temporary_path, &target) {
                let _ = fs::remove_file(&temporary_path);
                return Err(error);
            }
        }
    }
    Ok(true)
}

fn write_report_contents(last: &LastAnalysis, format: ReportFormat, file: File) -> io::Result<()> {
    let mut output = BufWriter::new(file);
    match format {
        ReportFormat::Text => report::text::write_text(&last.diff, &mut output)?,
        ReportFormat::Json => report::json::write_json(&last.diff, &mut output)?,
        ReportFormat::Markdown => report::markdown::write_markdown(&last.diff, &mut output)?,
        ReportFormat::Html => report::html::write_html(&last.diff, &mut output)?,
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
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => Ok(Some(ReportDestination::New(file))),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            validate_replace_target(&metadata)?;
            if !confirm_overwrite(editor)? {
                return Ok(None);
            }
            let metadata = fs::symlink_metadata(path)?;
            validate_replace_target(&metadata)?;
            Ok(Some(ReportDestination::Replace))
        }
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

fn create_temporary_report(destination: &Path) -> io::Result<(PathBuf, File)> {
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    for _ in 0..128 {
        let sequence = REPORT_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!(".crucksware-report-{}-{sequence}.tmp", std::process::id());
        let path = parent.join(name);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a temporary report file",
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
