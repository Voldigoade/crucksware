use std::io::{self, Write};

use crate::{
    input::InputKind,
    inspection::{ElfInspection, FileInspection},
    path::encode_bytes,
};

pub fn write_inspection(inspection: &FileInspection, output: &mut impl Write) -> io::Result<()> {
    let kind = match inspection.kind {
        InputKind::Elf => "ELF",
        InputKind::Pe => "PE candidate",
        InputKind::Directory => "directory",
        InputKind::Text => "text",
        InputKind::UnknownBinary => "unknown binary",
    };
    writeln!(output, "Detected kind: {kind}")?;
    writeln!(output, "Size: {} bytes", inspection.size_bytes)?;
    if let Some(elf) = &inspection.elf {
        writeln!(output, "Content: binary")?;
        writeln!(output, "ELF structural inspection: performed")?;
        write_elf(elf, output)?;
    } else {
        writeln!(
            output,
            "Content: {} (bounded inspection)",
            inspection.content
        )?;
        writeln!(output, "Semantic format parsing: not performed")?;
    }
    Ok(())
}

fn write_elf(elf: &ElfInspection, output: &mut impl Write) -> io::Result<()> {
    writeln!(output, "ELF class: {}", elf.class)?;
    writeln!(output, "Byte order: {}", elf.byte_order)?;
    writeln!(output, "Architecture: {}", elf.architecture)?;
    writeln!(output, "Machine: {}", elf.machine)?;
    writeln!(output, "ELF type: {}", elf.elf_type)?;
    writeln!(output, "Entry point: 0x{:x}", elf.entry_point)?;
    writeln!(output, "Sections: {}", elf.sections.len())?;
    for section in &elf.sections {
        writeln!(
            output,
            "Section {}: {} type={} flags={} address=0x{:x} size={}",
            section.index,
            encode_bytes(&section.name),
            section.section_type,
            section.flags,
            section.address,
            section.size
        )?;
    }
    writeln!(output, "Segments: {}", elf.segments.len())?;
    for segment in &elf.segments {
        writeln!(
            output,
            "Segment {}: {} flags={} offset=0x{:x} address=0x{:x} file-size={} memory-size={}",
            segment.index,
            segment.segment_type,
            segment.flags,
            segment.offset,
            segment.virtual_address,
            segment.file_size,
            segment.memory_size
        )?;
    }
    for interpreter in &elf.interpreters {
        writeln!(output, "Interpreter: {}", encode_bytes(interpreter))?;
    }
    writeln!(output, "Dependencies: {}", elf.dependencies.len())?;
    for dependency in &elf.dependencies {
        writeln!(output, "  {}", encode_bytes(dependency))?;
    }
    writeln!(output, "Imports: {}", elf.imports.len())?;
    for import in &elf.imports {
        writeln!(
            output,
            "  {}!{}",
            encode_bytes(&import.library),
            encode_bytes(&import.name)
        )?;
    }
    writeln!(output, "Exports: {}", elf.exports.len())?;
    for export in &elf.exports {
        writeln!(output, "  {}", encode_bytes(export))?;
    }
    writeln!(output, "Symbols: {}", elf.symbols.len())?;
    for symbol in &elf.symbols {
        writeln!(
            output,
            "  {} binding={} type={} value=0x{:x} size={}",
            encode_bytes(&symbol.name),
            symbol.binding,
            symbol.symbol_type,
            symbol.value,
            symbol.size
        )?;
    }
    if let Some(build_id) = &elf.build_id {
        writeln!(output, "Build ID: {}", hex(build_id))?;
    }
    for executable in &elf.gnu_stack_executable {
        writeln!(
            output,
            "GNU_STACK executable: {}",
            if *executable { "yes" } else { "no" }
        )?;
    }
    writeln!(output, "GNU_RELRO segments: {}", elf.gnu_relro_segments)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
