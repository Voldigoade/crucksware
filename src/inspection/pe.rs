use std::{collections::HashSet, fmt::Debug, path::Path};

use object::{
    Object,
    endian::LittleEndian as LE,
    pe,
    read::{
        File as ObjectFile, ImportFlags, NameOrOrdinal,
        pe::{
            ExportTarget as PeParserExportTarget, ImageNtHeaders, ImageOptionalHeader, PeFile,
            ResourceDirectory, ResourceDirectoryEntryData, ResourceNameOrId,
        },
    },
};

use crate::{
    input::InputError,
    inspection::{
        MAX_PE_FILE_BYTES, PeCertificateTable, PeExport, PeExportTarget, PeImport, PeImportName,
        PeInspection, PePdbInfo, PeResource, PeResourceId, PeSection,
    },
};

const MAX_FIELD_BYTES: usize = 4 * 1024;
const MAX_COPIED_NAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_RESOURCE_DEPTH: u8 = 16;

pub(super) fn inspect(
    data: &[u8],
    max_entries: u64,
    path: &Path,
) -> Result<PeInspection, InputError> {
    let file = ObjectFile::parse(data).map_err(|error| format_error(path, error))?;
    let mut budget = PeBudget {
        entries: 0,
        max_entries,
        copied_name_bytes: 0,
    };

    match file {
        ObjectFile::Pe32(file) => inspect_pe(&file, &mut budget, path),
        ObjectFile::Pe64(file) => inspect_pe(&file, &mut budget, path),
        _ => Err(format_error(path, "parser returned a non-PE format")),
    }
}

fn inspect_pe<'data, Pe>(
    file: &PeFile<'data, Pe>,
    budget: &mut PeBudget,
    path: &Path,
) -> Result<PeInspection, InputError>
where
    Pe: ImageNtHeaders,
{
    let headers = file.nt_headers();
    let optional = headers.optional_header();
    let data = file.data();
    let mut sections = Vec::new();
    for section in file.section_table().iter() {
        budget.charge()?;
        let name_end = section
            .name
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(section.name.len());
        let raw_offset = section.pointer_to_raw_data.get(LE);
        let raw_size = section.size_of_raw_data.get(LE);
        let raw_end = u64::from(raw_offset) + u64::from(raw_size);
        if raw_end > data.len() as u64 {
            return Err(format_error(path, "PE section data exceeds the file"));
        }
        sections.push(PeSection {
            name: budget.copy_bytes(&section.name[..name_end])?,
            virtual_address: section.virtual_address.get(LE),
            virtual_size: section.virtual_size.get(LE),
            raw_offset,
            raw_size,
            characteristics: section.characteristics.get(LE).0,
        });
    }

    let (imports, delay_imports) = collect_imports(file, budget, path)?;
    let exports = collect_exports(file, budget, path)?;
    let resources = collect_resources(file, budget, path)?;
    let pdb_info = file
        .pdb_info()
        .map_err(|error| format_error(path, error))?
        .map(|info| {
            Ok(PePdbInfo {
                path: budget.copy_bytes(info.path())?,
                guid: info.guid(),
                age: info.age(),
            })
        })
        .transpose()?;
    let certificate_table = certificate_table(file, data.len(), path)?;
    Ok(PeInspection {
        format: if file.is_64() { "PE32+" } else { "PE32" },
        architecture: format!("{:?}", file.architecture()),
        machine: headers.file_header().machine.get(LE).0,
        entry_point_rva: optional.address_of_entry_point(),
        image_base: optional.image_base(),
        subsystem: optional.subsystem().0,
        sections,
        imports,
        delay_imports,
        exports,
        resources,
        pdb_info,
        certificate_table,
    })
}

fn collect_imports<'data, Pe>(
    file: &PeFile<'data, Pe>,
    budget: &mut PeBudget,
    path: &Path,
) -> Result<(Vec<PeImport>, Vec<PeImport>), InputError>
where
    Pe: ImageNtHeaders,
{
    let mut imports = Vec::new();
    let mut delay_imports = Vec::new();
    for import in file.imports().map_err(|error| format_error(path, error))? {
        budget.charge()?;
        let import = import.map_err(|error| format_error(path, error))?;
        let name = match import.name() {
            NameOrOrdinal::Name(name) => PeImportName::Name(budget.copy_bytes(name)?),
            NameOrOrdinal::Ordinal(ordinal) => PeImportName::Ordinal(ordinal),
        };
        let item = PeImport {
            library: budget.copy_bytes(import.library())?,
            name,
        };
        match import.flags() {
            ImportFlags::Pe { delay: true } => delay_imports.push(item),
            _ => imports.push(item),
        }
    }
    imports.sort_by(|left, right| (&left.library, &left.name).cmp(&(&right.library, &right.name)));
    delay_imports
        .sort_by(|left, right| (&left.library, &left.name).cmp(&(&right.library, &right.name)));
    Ok((imports, delay_imports))
}

fn collect_exports<'data, Pe>(
    file: &PeFile<'data, Pe>,
    budget: &mut PeBudget,
    path: &Path,
) -> Result<Vec<PeExport>, InputError>
where
    Pe: ImageNtHeaders,
{
    let Some(table) = file
        .export_table()
        .map_err(|error| format_error(path, error))?
    else {
        return Ok(Vec::new());
    };
    budget.charge_many(table.addresses().len())?;
    budget.charge_many(table.name_pointers().len())?;
    let mut exports = Vec::new();
    for export in table.exports().map_err(|error| format_error(path, error))? {
        let target = match export.target {
            PeParserExportTarget::Address(address) => PeExportTarget::Address(address),
            PeParserExportTarget::ForwardByName(library, name) => PeExportTarget::ForwardedName {
                library: budget.copy_bytes(library)?,
                name: budget.copy_bytes(name)?,
            },
            PeParserExportTarget::ForwardByOrdinal(library, ordinal) => {
                PeExportTarget::ForwardedOrdinal {
                    library: budget.copy_bytes(library)?,
                    ordinal: ordinal.0,
                }
            }
        };
        exports.push(PeExport {
            ordinal: export.ordinal.0,
            name: export
                .name
                .map(|name| budget.copy_bytes(name))
                .transpose()?,
            target,
        });
    }
    exports.sort_by(|left, right| (left.ordinal, &left.name).cmp(&(right.ordinal, &right.name)));
    Ok(exports)
}

fn collect_resources<'data, Pe>(
    file: &PeFile<'data, Pe>,
    budget: &mut PeBudget,
    path: &Path,
) -> Result<Vec<PeResource>, InputError>
where
    Pe: ImageNtHeaders,
{
    let Some(directory) = file
        .data_directories()
        .resource_directory(file.data(), &file.section_table())
        .map_err(|error| format_error(path, error))?
    else {
        return Ok(Vec::new());
    };
    let root = directory
        .root()
        .map_err(|error| format_error(path, error))?;
    let mut pending = vec![(0_u32, 0_u8, Vec::new(), root)];
    let mut visited = HashSet::from([0_u32]);
    let mut resources = Vec::new();

    while let Some((_, depth, parents, table)) = pending.pop() {
        for entry in table.entries {
            budget.charge()?;
            let identifier = resource_identifier(entry.name_or_id(), directory, budget, path)?;
            let mut entry_path = copy_resource_path(&parents, budget)?;
            entry_path.push(identifier);
            match entry
                .data(directory)
                .map_err(|error| format_error(path, error))?
            {
                ResourceDirectoryEntryData::Table(child) => {
                    let child_depth = depth.saturating_add(1);
                    if child_depth > MAX_RESOURCE_DEPTH {
                        return Err(InputError::LimitExceeded {
                            resource: "PE resource depth",
                            limit: u64::from(MAX_RESOURCE_DEPTH),
                        });
                    }
                    let offset = entry.data_offset();
                    if !visited.insert(offset) {
                        return Err(format_error(path, "cyclic or shared PE resource table"));
                    }
                    pending.push((offset, child_depth, entry_path, child));
                }
                ResourceDirectoryEntryData::Data(data_entry) => {
                    let data_rva = data_entry.offset_to_data.get(LE);
                    let size = data_entry.size.get(LE);
                    if size > 0 {
                        let data = file
                            .section_table()
                            .pe_data_at(file.data(), data_rva)
                            .ok_or_else(|| format_error(path, "invalid PE resource data RVA"))?;
                        if data.get(..size as usize).is_none() {
                            return Err(format_error(path, "PE resource data exceeds its section"));
                        }
                    }
                    resources.push(PeResource {
                        path: entry_path,
                        data_rva,
                        size,
                        code_page: data_entry.code_page.get(LE),
                    });
                }
            }
        }
    }

    resources.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(resources)
}

fn resource_identifier(
    name_or_id: ResourceNameOrId,
    directory: ResourceDirectory<'_>,
    budget: &mut PeBudget,
    path: &Path,
) -> Result<PeResourceId, InputError> {
    match name_or_id {
        ResourceNameOrId::Id(id) => Ok(PeResourceId::Id(id)),
        ResourceNameOrId::Name(name) => {
            let units = name
                .data(directory)
                .map_err(|error| format_error(path, error))?;
            if units.len() > MAX_FIELD_BYTES / 2 {
                return Err(InputError::LimitExceeded {
                    resource: "PE field bytes",
                    limit: MAX_FIELD_BYTES as u64,
                });
            }
            let name = name
                .to_string_lossy(directory)
                .map_err(|error| format_error(path, error))?;
            Ok(PeResourceId::Name(budget.copy_bytes(name.as_bytes())?))
        }
    }
}

fn copy_resource_path(
    path: &[PeResourceId],
    budget: &mut PeBudget,
) -> Result<Vec<PeResourceId>, InputError> {
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(path.len())
        .map_err(|_| InputError::LimitExceeded {
            resource: "PE memory",
            limit: MAX_PE_FILE_BYTES,
        })?;
    for component in path {
        copied.push(match component {
            PeResourceId::Name(name) => PeResourceId::Name(budget.copy_bytes(name)?),
            PeResourceId::Id(id) => PeResourceId::Id(*id),
        });
    }
    Ok(copied)
}

fn certificate_table<Pe>(
    file: &PeFile<'_, Pe>,
    file_size: usize,
    path: &Path,
) -> Result<Option<PeCertificateTable>, InputError>
where
    Pe: ImageNtHeaders,
{
    let Some(directory) = file
        .data_directories()
        .iter()
        .nth(pe::IMAGE_DIRECTORY_ENTRY_SECURITY)
    else {
        return Ok(None);
    };
    let file_offset = directory.virtual_address.get(LE);
    let size = directory.size.get(LE);
    if file_offset == 0 && size == 0 {
        return Ok(None);
    }
    if file_offset == 0 || size == 0 || u64::from(file_offset) + u64::from(size) > file_size as u64
    {
        return Err(format_error(path, "invalid PE certificate table range"));
    }
    Ok(Some(PeCertificateTable { file_offset, size }))
}

#[derive(Debug)]
struct PeBudget {
    entries: u64,
    max_entries: u64,
    copied_name_bytes: usize,
}

impl PeBudget {
    fn charge(&mut self) -> Result<(), InputError> {
        self.entries = self
            .entries
            .checked_add(1)
            .filter(|entries| *entries <= self.max_entries)
            .ok_or(InputError::LimitExceeded {
                resource: "PE entries",
                limit: self.max_entries,
            })?;
        Ok(())
    }

    fn charge_many(&mut self, count: usize) -> Result<(), InputError> {
        let count = u64::try_from(count).map_err(|_| InputError::LimitExceeded {
            resource: "PE entries",
            limit: self.max_entries,
        })?;
        self.entries = self
            .entries
            .checked_add(count)
            .filter(|entries| *entries <= self.max_entries)
            .ok_or(InputError::LimitExceeded {
                resource: "PE entries",
                limit: self.max_entries,
            })?;
        Ok(())
    }

    fn copy_bytes(&mut self, bytes: &[u8]) -> Result<Vec<u8>, InputError> {
        if bytes.len() > MAX_FIELD_BYTES {
            return Err(InputError::LimitExceeded {
                resource: "PE field bytes",
                limit: MAX_FIELD_BYTES as u64,
            });
        }
        self.copied_name_bytes = self
            .copied_name_bytes
            .checked_add(bytes.len())
            .filter(|length| *length <= MAX_COPIED_NAME_BYTES)
            .ok_or(InputError::LimitExceeded {
                resource: "PE copied name bytes",
                limit: MAX_COPIED_NAME_BYTES as u64,
            })?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| InputError::LimitExceeded {
                resource: "PE memory",
                limit: MAX_PE_FILE_BYTES,
            })?;
        owned.extend_from_slice(bytes);
        Ok(owned)
    }
}

fn format_error(path: &Path, error: impl Debug) -> InputError {
    InputError::Format {
        format: "PE",
        path: path.to_path_buf(),
        message: format!("{error:?}"),
    }
}
