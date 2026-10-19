use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::{
    input::InputKind,
    inspection::{
        ElfInspection, FileInspection, PeExportTarget, PeImportName, PeInspection, PeResourceId,
    },
    path::encode_bytes,
};

use super::{FileComparison, SemanticChange, SemanticComparisonStatus};

pub(super) fn compare_inspections(
    old: &FileInspection,
    new: &FileInspection,
    bytes_changed: bool,
) -> FileComparison {
    let (semantic_status, semantic_changes) = if old.kind != new.kind {
        (SemanticComparisonStatus::FormatMismatch, Vec::new())
    } else {
        match (semantic_facts(old), semantic_facts(new)) {
            (Some(old_facts), Some(new_facts)) => (
                SemanticComparisonStatus::Compared,
                changed_facts(old_facts, new_facts),
            ),
            _ => (SemanticComparisonStatus::Unsupported, Vec::new()),
        }
    };

    FileComparison {
        old_kind: old.kind,
        new_kind: new.kind,
        old_size_bytes: old.size_bytes,
        new_size_bytes: new.size_bytes,
        bytes_read: 0,
        bytes_changed,
        semantic_status,
        semantic_changes,
    }
}

fn semantic_facts(inspection: &FileInspection) -> Option<BTreeMap<String, Value>> {
    match (inspection.kind, &inspection.elf, &inspection.pe) {
        (InputKind::Elf, Some(elf), _) => Some(elf_facts(elf)),
        (InputKind::Pe, _, Some(pe)) => Some(pe_facts(pe)),
        _ => None,
    }
}

fn changed_facts(
    old: BTreeMap<String, Value>,
    new: BTreeMap<String, Value>,
) -> Vec<SemanticChange> {
    old.into_iter()
        .filter_map(|(field, before)| {
            let after = new.get(&field)?;
            (before != *after).then(|| SemanticChange {
                field,
                before,
                after: after.clone(),
            })
        })
        .collect()
}

fn elf_facts(elf: &ElfInspection) -> BTreeMap<String, Value> {
    let mut facts = BTreeMap::new();
    facts.insert("class".to_owned(), json!(elf.class));
    facts.insert("byte_order".to_owned(), json!(elf.byte_order));
    facts.insert("architecture".to_owned(), json!(elf.architecture));
    facts.insert("machine".to_owned(), json!(elf.machine));
    facts.insert("type".to_owned(), json!(elf.elf_type));
    facts.insert("entry_point".to_owned(), json!(elf.entry_point.to_string()));

    let mut sections: Vec<_> = elf
        .sections
        .iter()
        .map(|section| {
            json!({
                "name": encode_bytes(&section.name),
                "type": section.section_type,
                "flags": section.flags,
                "address": section.address.to_string(),
                "size": section.size.to_string(),
            })
        })
        .collect();
    sort_values(&mut sections);
    facts.insert("sections".to_owned(), json!(sections));

    let mut segments: Vec<_> = elf
        .segments
        .iter()
        .map(|segment| {
            json!({
                "type": segment.segment_type,
                "flags": segment.flags,
                "offset": segment.offset.to_string(),
                "virtual_address": segment.virtual_address.to_string(),
                "file_size": segment.file_size.to_string(),
                "memory_size": segment.memory_size.to_string(),
            })
        })
        .collect();
    sort_values(&mut segments);
    facts.insert("segments".to_owned(), json!(segments));

    facts.insert(
        "interpreters".to_owned(),
        json!(sorted_encoded(elf.interpreters.iter().map(Vec::as_slice))),
    );
    facts.insert(
        "dependencies".to_owned(),
        json!(sorted_encoded(elf.dependencies.iter().map(Vec::as_slice))),
    );

    let mut imports: Vec<_> = elf
        .imports
        .iter()
        .map(|import| {
            json!({
                "library": encode_bytes(&import.library),
                "name": encode_bytes(&import.name),
            })
        })
        .collect();
    sort_values(&mut imports);
    facts.insert("imports".to_owned(), json!(imports));
    facts.insert(
        "exports".to_owned(),
        json!(sorted_encoded(elf.exports.iter().map(Vec::as_slice))),
    );

    let mut symbols: Vec<_> = elf
        .symbols
        .iter()
        .map(|symbol| {
            json!({
                "name": encode_bytes(&symbol.name),
                "binding": symbol.binding,
                "type": symbol.symbol_type,
                "value": symbol.value.to_string(),
                "size": symbol.size.to_string(),
            })
        })
        .collect();
    sort_values(&mut symbols);
    facts.insert("symbols".to_owned(), json!(symbols));
    facts.insert(
        "build_id".to_owned(),
        json!(elf.build_id.as_deref().map(encode_bytes)),
    );

    let mut gnu_stack = elf.gnu_stack_executable.clone();
    gnu_stack.sort_unstable();
    facts.insert("gnu_stack_executable".to_owned(), json!(gnu_stack));
    facts.insert(
        "gnu_relro_segments".to_owned(),
        json!(elf.gnu_relro_segments.to_string()),
    );
    facts
}

fn pe_facts(pe: &PeInspection) -> BTreeMap<String, Value> {
    let mut facts = BTreeMap::new();
    facts.insert("format".to_owned(), json!(pe.format));
    facts.insert("architecture".to_owned(), json!(pe.architecture));
    facts.insert("machine".to_owned(), json!(pe.machine));
    facts.insert("entry_point_rva".to_owned(), json!(pe.entry_point_rva));
    facts.insert("image_base".to_owned(), json!(pe.image_base.to_string()));
    facts.insert("subsystem".to_owned(), json!(pe.subsystem));

    let mut sections: Vec<_> = pe
        .sections
        .iter()
        .map(|section| {
            json!({
                "name": encode_bytes(&section.name),
                "virtual_address": section.virtual_address,
                "virtual_size": section.virtual_size,
                "raw_offset": section.raw_offset,
                "raw_size": section.raw_size,
                "characteristics": section.characteristics,
            })
        })
        .collect();
    sort_values(&mut sections);
    facts.insert("sections".to_owned(), json!(sections));
    facts.insert("imports".to_owned(), json!(pe_imports(&pe.imports)));
    facts.insert(
        "delay_imports".to_owned(),
        json!(pe_imports(&pe.delay_imports)),
    );

    let mut exports: Vec<_> = pe
        .exports
        .iter()
        .map(|export| {
            json!({
                "ordinal": export.ordinal,
                "name": export.name.as_deref().map(encode_bytes),
                "target": match &export.target {
                    PeExportTarget::Address(address) => json!({ "address": address }),
                    PeExportTarget::ForwardedName { library, name } => json!({
                        "forwarded_library": encode_bytes(library),
                        "forwarded_name": encode_bytes(name),
                    }),
                    PeExportTarget::ForwardedOrdinal { library, ordinal } => json!({
                        "forwarded_library": encode_bytes(library),
                        "forwarded_ordinal": ordinal,
                    }),
                },
            })
        })
        .collect();
    sort_values(&mut exports);
    facts.insert("exports".to_owned(), json!(exports));

    let mut resources: Vec<_> = pe
        .resources
        .iter()
        .map(|resource| {
            json!({
                "path": resource
                    .path
                    .iter()
                    .map(|identifier| match identifier {
                        PeResourceId::Name(name) => json!({ "name": encode_bytes(name) }),
                        PeResourceId::Id(id) => json!({ "id": id }),
                    })
                    .collect::<Vec<_>>(),
                "data_rva": resource.data_rva,
                "size": resource.size,
                "code_page": resource.code_page,
            })
        })
        .collect();
    sort_values(&mut resources);
    facts.insert("resources".to_owned(), json!(resources));
    facts.insert(
        "pdb_info".to_owned(),
        json!(pe.pdb_info.as_ref().map(|info| {
            json!({
                "path": encode_bytes(&info.path),
                "guid": hex(&info.guid),
                "age": info.age,
            })
        })),
    );
    facts.insert(
        "certificate_table".to_owned(),
        json!(pe.certificate_table.as_ref().map(|certificate| {
            json!({
                "file_offset": certificate.file_offset,
                "size": certificate.size,
            })
        })),
    );
    facts
}

fn pe_imports(imports: &[crate::inspection::PeImport]) -> Vec<Value> {
    let mut values: Vec<_> = imports
        .iter()
        .map(|import| {
            json!({
                "library": encode_bytes(&import.library),
                "name": match &import.name {
                    PeImportName::Name(name) => json!({ "name": encode_bytes(name) }),
                    PeImportName::Ordinal(ordinal) => json!({ "ordinal": ordinal }),
                },
            })
        })
        .collect();
    sort_values(&mut values);
    values
}

fn sorted_encoded<'a>(values: impl Iterator<Item = &'a [u8]>) -> Vec<String> {
    let mut values: Vec<_> = values.map(encode_bytes).collect();
    values.sort();
    values
}

fn sort_values(values: &mut [Value]) {
    values.sort_by_cached_key(Value::to_string);
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
