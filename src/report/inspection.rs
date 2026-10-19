use std::io::{self, Write};

#[cfg(test)]
mod tests;

use crate::{
    input::InputKind,
    inspection::{
        ElfInspection, FileInspection, PeExportTarget, PeImport, PeImportName, PeInspection,
        PeResourceId,
    },
    path::encode_bytes,
};
use serde_json::{Value, json};

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

pub fn write_inspection_json(
    inspection: &FileInspection,
    output: &mut impl Write,
) -> io::Result<()> {
    let report = inspection_value(inspection);
    serde_json::to_writer_pretty(&mut *output, &report)?;
    output.write_all(b"\n")
}

pub fn write_markdown(inspection: &FileInspection, output: &mut impl Write) -> io::Result<()> {
    output.write_all(b"# Crucksware report\n\n## Summary\n\n| Field | Value |\n|:--|:--|\n")?;
    writeln!(output, "| Kind | {} |", inspection.kind.as_str())?;
    writeln!(output, "| Size bytes | {} |", inspection.size_bytes)?;
    writeln!(output, "| Content | {} |\n", inspection.content)?;
    output.write_all(b"## Structured facts\n\n")?;

    let report = inspection_value(inspection);
    let mut json = Vec::new();
    serde_json::to_writer_pretty(&mut json, &report)?;
    json.push(b'\n');
    for line in json.split_inclusive(|byte| *byte == b'\n') {
        output.write_all(b"    ")?;
        output.write_all(line)?;
    }
    Ok(())
}

pub fn write_html(inspection: &FileInspection, output: &mut impl Write) -> io::Result<()> {
    output.write_all(
        b"<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>Crucksware report</title>\n<style>",
    )?;
    output.write_all(super::html::STYLE.as_bytes())?;
    output.write_all(b"</style>\n</head>\n<body>\n<main>\n<header><h1>Crucksware report</h1></header>\n<section aria-labelledby=\"summary-heading\">\n<h2 id=\"summary-heading\">Inspection summary</h2>\n<table class=\"summary\">\n<tbody>\n")?;
    write_inspection_html_row(output, "Kind", inspection.kind.as_str())?;
    write_inspection_html_row(output, "Size bytes", &inspection.size_bytes.to_string())?;
    write_inspection_html_row(output, "Content", &inspection.content.to_string())?;
    output.write_all(b"</tbody>\n</table>\n</section>\n<section aria-labelledby=\"facts-heading\">\n<h2 id=\"facts-heading\">Structured facts</h2>\n<pre><code>")?;
    let report = inspection_value(inspection);
    let mut json = Vec::new();
    serde_json::to_writer_pretty(&mut json, &report)?;
    json.push(b'\n');
    let json = std::str::from_utf8(&json)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    super::html::write_escaped(output, json)?;
    output.write_all(b"</code></pre>\n</section>\n</main>\n</body>\n</html>\n")
}

fn write_inspection_html_row(output: &mut impl Write, label: &str, value: &str) -> io::Result<()> {
    output.write_all(b"<tr><th scope=\"row\">")?;
    super::html::write_escaped(output, label)?;
    output.write_all(b"</th><td>")?;
    super::html::write_escaped(output, value)?;
    output.write_all(b"</td></tr>\n")
}

fn inspection_value(inspection: &FileInspection) -> Value {
    json!({
        "schema_version": 5,
        "analysis_type": "single_file_inspection",
        "kind": inspection.kind.as_str(),
        "size_bytes": inspection.size_bytes.to_string(),
        "content": inspection.content.to_string(),
        "elf": inspection.elf.as_ref().map(elf_value),
        "pe": inspection.pe.as_ref().map(pe_value),
    })
}

fn elf_value(elf: &ElfInspection) -> Value {
    json!({
        "class": elf.class,
        "byte_order": elf.byte_order,
        "architecture": elf.architecture,
        "machine": elf.machine,
        "elf_type": elf.elf_type,
        "entry_point": elf.entry_point.to_string(),
        "sections": elf.sections.iter().map(|section| json!({
            "index": section.index.to_string(),
            "name": encode_bytes(&section.name),
            "type": section.section_type,
            "flags": section.flags,
            "address": section.address.to_string(),
            "size_bytes": section.size.to_string(),
        })).collect::<Vec<_>>(),
        "segments": elf.segments.iter().map(|segment| json!({
            "index": segment.index.to_string(),
            "type": segment.segment_type,
            "flags": segment.flags,
            "offset": segment.offset.to_string(),
            "virtual_address": segment.virtual_address.to_string(),
            "file_size_bytes": segment.file_size.to_string(),
            "memory_size_bytes": segment.memory_size.to_string(),
        })).collect::<Vec<_>>(),
        "interpreters": elf.interpreters.iter().map(|value| encode_bytes(value)).collect::<Vec<_>>(),
        "dependencies": elf.dependencies.iter().map(|value| encode_bytes(value)).collect::<Vec<_>>(),
        "imports": elf.imports.iter().map(|import| json!({
            "library": encode_bytes(&import.library),
            "name": encode_bytes(&import.name),
        })).collect::<Vec<_>>(),
        "exports": elf.exports.iter().map(|value| encode_bytes(value)).collect::<Vec<_>>(),
        "symbols": elf.symbols.iter().map(|symbol| json!({
            "name": encode_bytes(&symbol.name),
            "binding": symbol.binding,
            "type": symbol.symbol_type,
            "value": symbol.value.to_string(),
            "size_bytes": symbol.size.to_string(),
        })).collect::<Vec<_>>(),
        "build_id": elf.build_id.as_ref().map(|bytes| hex(bytes)),
        "gnu_stack_executable": elf.gnu_stack_executable,
        "gnu_relro_segments": elf.gnu_relro_segments.to_string(),
    })
}

fn pe_value(pe: &PeInspection) -> Value {
    json!({
        "format": pe.format,
        "architecture": pe.architecture,
        "machine": pe.machine.to_string(),
        "entry_point_rva": pe.entry_point_rva.to_string(),
        "image_base": pe.image_base.to_string(),
        "subsystem": pe.subsystem.to_string(),
        "sections": pe.sections.iter().map(|section| json!({
            "name": encode_bytes(&section.name),
            "virtual_address": section.virtual_address.to_string(),
            "virtual_size_bytes": section.virtual_size.to_string(),
            "raw_offset": section.raw_offset.to_string(),
            "raw_size_bytes": section.raw_size.to_string(),
            "characteristics": section.characteristics.to_string(),
        })).collect::<Vec<_>>(),
        "imports": pe.imports.iter().map(pe_import_value).collect::<Vec<_>>(),
        "delay_imports": pe.delay_imports.iter().map(pe_import_value).collect::<Vec<_>>(),
        "exports": pe.exports.iter().map(|export| json!({
            "ordinal": export.ordinal.to_string(),
            "name": export.name.as_ref().map(|name| encode_bytes(name)),
            "target": pe_export_target_value(&export.target),
        })).collect::<Vec<_>>(),
        "resources": pe.resources.iter().map(|resource| json!({
            "path": resource.path.iter().map(pe_resource_id_value).collect::<Vec<_>>(),
            "data_rva": resource.data_rva.to_string(),
            "size_bytes": resource.size.to_string(),
            "code_page": resource.code_page.to_string(),
        })).collect::<Vec<_>>(),
        "pdb_info": pe.pdb_info.as_ref().map(|pdb| json!({
            "path": encode_bytes(&pdb.path),
            "guid": hex(&pdb.guid),
            "age": pdb.age.to_string(),
        })),
        "certificate_table": pe.certificate_table.as_ref().map(|certificate| json!({
            "file_offset": certificate.file_offset.to_string(),
            "size_bytes": certificate.size.to_string(),
        })),
    })
}

fn pe_import_value(import: &PeImport) -> Value {
    let name = match &import.name {
        PeImportName::Name(name) => json!({"kind": "name", "value": encode_bytes(name)}),
        PeImportName::Ordinal(ordinal) => {
            json!({"kind": "ordinal", "value": ordinal.to_string()})
        }
    };
    json!({"library": encode_bytes(&import.library), "name": name})
}

fn pe_export_target_value(target: &PeExportTarget) -> Value {
    match target {
        PeExportTarget::Address(address) => {
            json!({"kind": "address", "rva": address.to_string()})
        }
        PeExportTarget::ForwardedName { library, name } => json!({
            "kind": "forwarded_name",
            "library": encode_bytes(library),
            "name": encode_bytes(name),
        }),
        PeExportTarget::ForwardedOrdinal { library, ordinal } => json!({
            "kind": "forwarded_ordinal",
            "library": encode_bytes(library),
            "ordinal": ordinal.to_string(),
        }),
    }
}

fn pe_resource_id_value(id: &PeResourceId) -> Value {
    match id {
        PeResourceId::Name(name) => json!({"kind": "name", "value": encode_bytes(name)}),
        PeResourceId::Id(id) => json!({"kind": "id", "value": id.to_string()}),
    }
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
