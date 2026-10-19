use std::io::{self, Write};

use crate::{input::InputKind, inspection::FileInspection};

pub fn write_inspection(inspection: &FileInspection, output: &mut impl Write) -> io::Result<()> {
    let kind = match inspection.kind {
        InputKind::Elf => "ELF candidate",
        InputKind::Pe => "PE candidate",
        InputKind::Directory => "directory",
        InputKind::Text => "text",
        InputKind::UnknownBinary => "unknown binary",
    };
    writeln!(output, "Detected kind: {kind}")?;
    writeln!(output, "Size: {} bytes", inspection.size_bytes)?;
    writeln!(
        output,
        "Content: {} (bounded inspection)",
        inspection.content
    )?;
    writeln!(output, "Semantic format parsing: not performed")
}
