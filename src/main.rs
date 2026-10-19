use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use crucksware::{
    compare,
    inspection::{DEFAULT_MAX_BYTES_READ, inspect_file},
    limits::Limits,
    model::Diff,
    report,
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
    #[command(about = "Compare two extracted root filesystem directories")]
    Compare(CompareArgs),
    #[command(about = "Inspect one file without executing it")]
    Inspect(InspectArgs),
}

#[derive(Debug, Args)]
struct CompareArgs {
    #[arg(long, value_enum, default_value = "text")]
    format: OutputFormat,

    #[arg(
        long,
        value_parser = parse_positive_u64,
        default_value_t = Limits::default().max_entries
    )]
    max_entries: u64,

    #[arg(
        long,
        value_parser = parse_positive_depth,
        default_value_t = Limits::default().max_depth
    )]
    max_depth: u64,

    #[arg(
        long,
        value_parser = parse_positive_u64,
        default_value_t = Limits::default().max_path_bytes
    )]
    max_path_bytes: u64,

    #[arg(
        long,
        value_parser = parse_positive_u64,
        default_value_t = Limits::default().max_bytes_read
    )]
    max_bytes_read: u64,

    old: PathBuf,
    new: PathBuf,
}

#[derive(Debug, Args)]
struct InspectArgs {
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
    let inspection = match inspect_file(&args.path, args.max_bytes_read) {
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

fn write_report(diff: &Diff, format: OutputFormat) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match format {
        OutputFormat::Text => report::text::write_text(diff, &mut output)?,
        OutputFormat::Json => report::json::write_json(diff, &mut output)?,
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
