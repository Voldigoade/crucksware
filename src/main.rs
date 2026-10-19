use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use crucksware::{
    binary_compare::{FileComparison, SemanticComparisonStatus, compare_files},
    compare,
    input::InputError,
    inspection::{DEFAULT_MAX_BYTES_READ, DEFAULT_MAX_ENTRIES, inspect_file_with_limits},
    limits::Limits,
    model::Diff,
    report,
    source::{DEFAULT_MAX_SOURCE_FILE_BYTES, MAX_SOURCE_FILE_BYTES, SourceDiff},
};

mod interactive;

#[derive(Debug, Parser)]
#[command(
    name = "crucksware",
    version,
    about = "Semantic firmware diff and triage in Rust.",
    disable_colored_help = true,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Compare two root filesystem directories or regular files")]
    Compare(CompareArgs),
    #[command(about = "Inspect one file without executing it")]
    Inspect(InspectArgs),
}

#[derive(Debug, Args)]
struct CompareArgs {
    #[arg(
        long,
        value_enum,
        default_value = "text",
        help = "Report format; directory JSON uses schema v1 and file JSON uses schema v2"
    )]
    format: OutputFormat,

    #[arg(
        long,
        value_parser = parse_positive_u64,
        default_value_t = Limits::default().max_entries,
        help = "Maximum total tree entries or semantic records across file inputs"
    )]
    max_entries: u64,

    #[arg(
        long,
        value_parser = parse_positive_depth,
        default_value_t = Limits::default().max_depth,
        help = "Maximum directory traversal depth"
    )]
    max_depth: u64,

    #[arg(
        long,
        value_parser = parse_positive_u64,
        default_value_t = Limits::default().max_path_bytes,
        help = "Maximum total encoded path bytes for directory comparisons"
    )]
    max_path_bytes: u64,

    #[arg(
        long,
        value_parser = parse_positive_u64,
        default_value_t = Limits::default().max_bytes_read,
        help = "Maximum total bytes read across the comparison"
    )]
    max_bytes_read: u64,

    #[arg(
        long,
        help = "Add bounded text and structural analysis for changed source files"
    )]
    source_aware: bool,

    #[arg(
        long,
        value_parser = parse_source_file_bytes,
        default_value_t = DEFAULT_MAX_SOURCE_FILE_BYTES,
        help = "Maximum bytes read from one text file in source-aware mode"
    )]
    max_source_file_bytes: u64,

    old: PathBuf,
    new: PathBuf,
}

#[derive(Debug, Args)]
struct InspectArgs {
    #[arg(
        long,
        value_parser = parse_positive_u64,
        default_value_t = DEFAULT_MAX_ENTRIES
    )]
    max_entries: u64,

    #[arg(
        long,
        value_parser = parse_positive_u64,
        default_value_t = DEFAULT_MAX_BYTES_READ
    )]
    max_bytes_read: u64,

    path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() -> ExitCode {
    if std::env::args_os().nth(1).is_none() {
        return interactive::run();
    }

    let cli = Cli::parse();
    match cli.command {
        Command::Compare(args) => run_compare(args),
        Command::Inspect(args) => run_inspect(args),
    }
}

fn run_inspect(args: InspectArgs) -> ExitCode {
    let inspection =
        match inspect_file_with_limits(&args.path, args.max_bytes_read, args.max_entries) {
            Ok(inspection) => inspection,
            Err(error) => {
                eprintln!("crucksware: inspection failed: {error}");
                return ExitCode::from(2);
            }
        };

    let stdout = io::stdout();
    let mut output = stdout.lock();
    if let Err(error) =
        report::inspection::write_inspection(&inspection, &mut output).and_then(|()| output.flush())
    {
        eprintln!("crucksware: failed to write inspection: {error}");
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

fn run_compare(args: CompareArgs) -> ExitCode {
    let old_shape = match comparison_input_shape(&args.old) {
        Ok(shape) => shape,
        Err(error) => {
            eprintln!("crucksware: {error}");
            return ExitCode::from(2);
        }
    };
    let new_shape = match comparison_input_shape(&args.new) {
        Ok(shape) => shape,
        Err(error) => {
            eprintln!("crucksware: {error}");
            return ExitCode::from(2);
        }
    };
    match (old_shape, new_shape) {
        (CompareInputShape::Directory, CompareInputShape::Directory) => {
            if args.source_aware {
                run_source_compare(&args)
            } else {
                run_tree_compare(&args)
            }
        }
        (CompareInputShape::File, CompareInputShape::File) if !args.source_aware => {
            run_file_compare(&args)
        }
        (CompareInputShape::File, CompareInputShape::File) => {
            eprintln!("crucksware: source-aware comparison requires two directories");
            ExitCode::from(2)
        }
        _ => {
            eprintln!("crucksware: compare requires two directories or two regular files");
            ExitCode::from(2)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompareInputShape {
    Directory,
    File,
}

fn comparison_input_shape(path: &Path) -> Result<CompareInputShape, InputError> {
    let metadata = fs::metadata(path).map_err(|source| InputError::Io {
        operation: "inspect input",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.is_dir() {
        Ok(CompareInputShape::Directory)
    } else if metadata.is_file() {
        Ok(CompareInputShape::File)
    } else {
        Err(InputError::UnsupportedType {
            path: path.to_path_buf(),
        })
    }
}

fn run_tree_compare(args: &CompareArgs) -> ExitCode {
    let limits = Limits {
        max_entries: args.max_entries,
        max_depth: args.max_depth,
        max_path_bytes: args.max_path_bytes,
        max_bytes_read: args.max_bytes_read,
    };

    let diff = match compare(&args.old, &args.new, limits) {
        Ok(diff) => diff,
        Err(error) => {
            eprintln!("crucksware: {error}");
            return ExitCode::from(2);
        }
    };

    if let Err(error) = write_report(&diff, args.format) {
        eprintln!("crucksware: failed to write report: {error}");
        return ExitCode::from(2);
    }

    ExitCode::from(u8::from(!diff.changes.is_empty()))
}

fn run_file_compare(args: &CompareArgs) -> ExitCode {
    let comparison =
        match compare_files(&args.old, &args.new, args.max_bytes_read, args.max_entries) {
            Ok(comparison) => comparison,
            Err(error) => {
                eprintln!("crucksware: comparison failed: {error}");
                return ExitCode::from(2);
            }
        };

    if let Err(error) = write_file_report(&comparison, args.format) {
        eprintln!("crucksware: failed to write report: {error}");
        return ExitCode::from(2);
    }

    let changed = comparison.bytes_changed
        || !comparison.semantic_changes.is_empty()
        || comparison.semantic_status == SemanticComparisonStatus::FormatMismatch;
    ExitCode::from(u8::from(changed))
}

fn run_source_compare(args: &CompareArgs) -> ExitCode {
    let limits = Limits {
        max_entries: args.max_entries,
        max_depth: args.max_depth,
        max_path_bytes: args.max_path_bytes,
        max_bytes_read: args.max_bytes_read,
    };
    let diff = match crucksware::compare_source(
        &args.old,
        &args.new,
        limits,
        args.max_source_file_bytes,
    ) {
        Ok(diff) => diff,
        Err(error) => {
            eprintln!("crucksware: {error}");
            return ExitCode::from(2);
        }
    };

    if let Err(error) = write_source_report(&diff, args.format) {
        eprintln!("crucksware: failed to write report: {error}");
        return ExitCode::from(2);
    }

    ExitCode::from(u8::from(!diff.filesystem.changes.is_empty()))
}

fn write_report(diff: &Diff, format: OutputFormat) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Text => report::text::write_text(diff, &mut output)?,
        OutputFormat::Json => report::json::write_json(diff, &mut output)?,
    }
    output.flush()
}

fn write_file_report(comparison: &FileComparison, format: OutputFormat) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Text => report::binary::write_text(comparison, &mut output)?,
        OutputFormat::Json => report::binary::write_json(comparison, &mut output)?,
    }
    output.flush()
}

fn write_source_report(diff: &SourceDiff, format: OutputFormat) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Text => report::source::write_text(diff, &mut output)?,
        OutputFormat::Json => report::source::write_json(diff, &mut output)?,
    }
    output.flush()
}

fn parse_positive_u64(value: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("must be a positive decimal integer".to_owned());
    }

    let parsed = value
        .parse::<u64>()
        .map_err(|_| "must fit in an unsigned 64-bit integer".to_owned())?;
    if parsed == 0 {
        return Err("must be greater than zero".to_owned());
    }

    Ok(parsed)
}

fn parse_positive_depth(value: &str) -> Result<u64, String> {
    let parsed = parse_positive_u64(value)?;
    usize::try_from(parsed).map_err(|_| "must fit in this platform's usize".to_owned())?;
    Ok(parsed)
}

fn parse_source_file_bytes(value: &str) -> Result<u64, String> {
    let parsed = parse_positive_u64(value)?;
    if parsed > MAX_SOURCE_FILE_BYTES {
        return Err(format!("must not exceed {MAX_SOURCE_FILE_BYTES} bytes"));
    }
    Ok(parsed)
}
