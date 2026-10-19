use std::io::{self, Write};

use crate::{
    input::InputKind,
    inspection::{
        ElfInspection, FileInspection, PeExportTarget, PeImportName, PeInspection, PeResourceId,
    },
    path::encode_bytes,
};

pub fn write_inspection(inspection: &FileInspection, output: &mut impl Write) -> io::Result<()> {
    let kind = match inspection.kind {
        InputKind::Elf => "ELF",
        InputKind::Pe => inspection
            .pe
            .as_ref()
            .map_or("PE candidate", |pe| pe.format),
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
    } else if let Some(pe) = &inspection.pe {
        writeln!(output, "Content: binary")?;
        writeln!(output, "PE structural inspection: performed")?;
        write_pe(pe, output)?;
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

fn write_pe(pe: &PeInspection, output: &mut impl Write) -> io::Result<()> {
    writeln!(output, "Architecture: {}", pe.architecture)?;
    writeln!(output, "Machine: 0x{:04x}", pe.machine)?;
    writeln!(output, "Entry point RVA: 0x{:x}", pe.entry_point_rva)?;
    writeln!(output, "Image base: 0x{:x}", pe.image_base)?;
    writeln!(
        output,
        "Subsystem: {} ({})",
        subsystem_name(pe.subsystem),
        pe.subsystem
    )?;
    writeln!(output, "Sections: {}", pe.sections.len())?;
    for section in &pe.sections {
        writeln!(
            output,
            "Section {}: virtual-address=0x{:x} virtual-size={} raw-offset=0x{:x} raw-size={} characteristics=0x{:08x} [{}]",
            encode_bytes(&section.name),
            section.virtual_address,
            section.virtual_size,
            section.raw_offset,
            section.raw_size,
            section.characteristics,
            section_characteristics(section.characteristics)
        )?;
    }
    writeln!(output, "Imports: {}", pe.imports.len())?;
    for import in &pe.imports {
        writeln!(
            output,
            "Import {}!{}",
            encode_bytes(&import.library),
            import_name(&import.name)
        )?;
    }
    writeln!(output, "Delay imports: {}", pe.delay_imports.len())?;
    for import in &pe.delay_imports {
        writeln!(
            output,
            "Delay import {}!{}",
            encode_bytes(&import.library),
            import_name(&import.name)
        )?;
    }
    writeln!(output, "Exports: {}", pe.exports.len())?;
    for export in &pe.exports {
        let name = export
            .name
            .as_ref()
            .map(|name| encode_bytes(name))
            .unwrap_or_else(|| "<unnamed>".to_owned());
        writeln!(
            output,
            "Export ordinal {}: {} target={}",
            export.ordinal,
            name,
            export_target(&export.target)
        )?;
    }
    writeln!(output, "Resources: {}", pe.resources.len())?;
    for resource in &pe.resources {
        let path = resource
            .path
            .iter()
            .map(resource_id)
            .collect::<Vec<_>>()
            .join("/");
        writeln!(
            output,
            "Resource {path}: RVA=0x{:x} size={} code-page={}",
            resource.data_rva, resource.size, resource.code_page
        )?;
    }
    if let Some(pdb_info) = &pe.pdb_info {
        writeln!(output, "PDB path: {}", encode_bytes(&pdb_info.path))?;
        writeln!(output, "PDB GUID: {}", hex(&pdb_info.guid))?;
        writeln!(output, "PDB age: {}", pdb_info.age)?;
    } else {
        writeln!(output, "PDB metadata: absent")?;
    }
    match &pe.certificate_table {
        Some(certificate) => writeln!(
            output,
            "Certificate table: present at file offset 0x{:x} ({} bytes)",
            certificate.file_offset, certificate.size
        ),
        None => writeln!(output, "Certificate table: absent"),
    }
}

fn import_name(name: &PeImportName) -> String {
    match name {
        PeImportName::Name(name) => encode_bytes(name),
        PeImportName::Ordinal(ordinal) => format!("ordinal #{ordinal}"),
    }
}

fn export_target(target: &PeExportTarget) -> String {
    match target {
        PeExportTarget::Address(address) => format!("RVA=0x{address:x}"),
        PeExportTarget::ForwardedName { library, name } => {
            format!("forward={}.{}", encode_bytes(library), encode_bytes(name))
        }
        PeExportTarget::ForwardedOrdinal { library, ordinal } => {
            format!("forward={} ordinal #{ordinal}", encode_bytes(library))
        }
    }
}

fn resource_id(identifier: &PeResourceId) -> String {
    match identifier {
        PeResourceId::Name(name) => encode_bytes(name),
        PeResourceId::Id(id) => id.to_string(),
    }
}

fn subsystem_name(subsystem: u16) -> &'static str {
    match subsystem {
        0 => "UNKNOWN",
        1 => "NATIVE",
        2 => "WINDOWS_GUI",
        3 => "WINDOWS_CUI",
        5 => "OS2_CUI",
        7 => "POSIX_CUI",
        8 => "NATIVE_WINDOWS",
        9 => "WINDOWS_CE_GUI",
        10 => "EFI_APPLICATION",
        11 => "EFI_BOOT_SERVICE_DRIVER",
        12 => "EFI_RUNTIME_DRIVER",
        13 => "EFI_ROM",
        14 => "XBOX",
        16 => "WINDOWS_BOOT_APPLICATION",
        17 => "XBOX_CODE_CATALOG",
        _ => "UNKNOWN_VALUE",
    }
}

fn section_characteristics(characteristics: u32) -> String {
    use object::pe;

    let mut flags = Vec::new();
    for (flag, name) in [
        (pe::IMAGE_SCN_CNT_CODE, "CODE"),
        (pe::IMAGE_SCN_CNT_INITIALIZED_DATA, "INITIALIZED_DATA"),
        (pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA, "UNINITIALIZED_DATA"),
        (pe::IMAGE_SCN_MEM_DISCARDABLE, "DISCARDABLE"),
        (pe::IMAGE_SCN_MEM_NOT_CACHED, "NOT_CACHED"),
        (pe::IMAGE_SCN_MEM_NOT_PAGED, "NOT_PAGED"),
        (pe::IMAGE_SCN_MEM_SHARED, "SHARED"),
        (pe::IMAGE_SCN_MEM_EXECUTE, "EXECUTE"),
        (pe::IMAGE_SCN_MEM_READ, "READ"),
        (pe::IMAGE_SCN_MEM_WRITE, "WRITE"),
    ] {
        if characteristics & flag.0 != 0 {
            flags.push(name);
        }
    }
    flags.join("|")
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
