use std::{fmt::Debug, path::Path};

use object::{
    Object, elf,
    endian::Endian as _,
    read::elf::{Dyn, FileHeader, ProgramHeader, SectionHeader, Sym},
    read::{File as ObjectFile, NameOrOrdinal},
};

use crate::{
    input::InputError,
    inspection::{ElfImport, ElfInspection, ElfSection, ElfSegment, ElfSymbol, MAX_ELF_FILE_BYTES},
};

const MAX_FIELD_BYTES: usize = 4 * 1024;
const MAX_COPIED_NAME_BYTES: usize = 16 * 1024 * 1024;

pub(super) fn inspect(
    data: &[u8],
    max_entries: u64,
    path: &Path,
) -> Result<ElfInspection, InputError> {
    let file = ObjectFile::parse(data).map_err(|error| InputError::Format {
        format: "ELF",
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;
    let mut budget = FactBudget {
        entries: 0,
        max_entries,
        copied_name_bytes: 0,
    };

    match file {
        ObjectFile::Elf32(elf_file) => inspect_elf(&elf_file, &mut budget, path),
        ObjectFile::Elf64(elf_file) => inspect_elf(&elf_file, &mut budget, path),
        _ => Err(InputError::Format {
            format: "ELF",
            path: path.to_path_buf(),
            message: "parser returned a non-ELF format".to_owned(),
        }),
    }
}

fn inspect_elf<'data, Elf, R>(
    file: &object::read::elf::ElfFile<'data, Elf, R>,
    budget: &mut FactBudget,
    path: &Path,
) -> Result<ElfInspection, InputError>
where
    Elf: FileHeader,
    Elf::ProgramHeader: ProgramHeader<Elf = Elf>,
    Elf::SectionHeader: SectionHeader<Elf = Elf>,
    Elf::Dyn: Dyn<Endian = Elf::Endian, Word = Elf::Word>,
    Elf::Sym: Sym<Endian = Elf::Endian, Word = Elf::Word>,
    R: object::read::ReadRef<'data>,
{
    let endian = file.endian();
    let header = file.elf_header();
    if header.e_version(endian) != u32::from(elf::EV_CURRENT.0)
        || usize::from(header.e_ehsize(endian)) != std::mem::size_of::<Elf>()
        || (!file.elf_program_headers().is_empty()
            && usize::from(header.e_phentsize(endian)) != std::mem::size_of::<Elf::ProgramHeader>())
        || (!file.elf_section_table().is_empty()
            && usize::from(header.e_shentsize(endian)) != std::mem::size_of::<Elf::SectionHeader>())
    {
        return Err(format_error(
            path,
            "inconsistent ELF header sizes or version",
        ));
    }

    let mut sections = Vec::new();
    for (index, section) in file.elf_section_table().iter().enumerate().skip(1) {
        budget.charge()?;
        let section_type = section.sh_type(endian);
        if section_type != elf::SHT_NOBITS {
            section
                .data(endian, file.data())
                .map_err(|error| format_error(path, error))?;
        }
        let name = file
            .elf_section_table()
            .section_name(endian, section)
            .map_err(|error| format_error(path, error))?;
        sections.push(ElfSection {
            index: index as u64,
            name: budget.copy_bytes(name)?,
            section_type: section_type_name(section_type),
            flags: section_flags(section.sh_flags(endian)),
            address: section.sh_addr(endian).into(),
            size: section.sh_size(endian).into(),
        });
    }

    let mut segments = Vec::new();
    let mut interpreters = Vec::new();
    let mut gnu_stack_executable = Vec::new();
    let mut gnu_relro_segments = 0;
    for (index, segment) in file.elf_program_headers().iter().enumerate() {
        budget.charge()?;
        let segment_type = segment.p_type(endian);
        let flags = segment.p_flags(endian);
        let (offset, file_size) = segment.file_range(endian);
        let memory_size = segment.p_memsz(endian).into();
        if segment_type != elf::PT_NULL {
            segment
                .data(endian, file.data())
                .map_err(|()| format_error(path, "invalid ELF segment size or offset"))?;
        }
        if matches!(segment_type, elf::PT_LOAD | elf::PT_TLS) && file_size > memory_size {
            return Err(format_error(
                path,
                "ELF load segment file size exceeds memory size",
            ));
        }
        segments.push(ElfSegment {
            index: index as u64,
            segment_type: segment_type_name(segment_type),
            flags: program_flags(flags),
            offset,
            virtual_address: segment.p_vaddr(endian).into(),
            file_size,
            memory_size,
        });

        if segment_type == elf::PT_INTERP {
            let interpreter = segment
                .interpreter(endian, file.data())
                .map_err(|error| format_error(path, error))?
                .ok_or_else(|| format_error(path, "missing PT_INTERP data"))?;
            interpreters.push(budget.copy_bytes(interpreter)?);
        }
        if segment_type == elf::PT_GNU_STACK {
            gnu_stack_executable.push(flags.contains(elf::PF_X));
        }
        if segment_type == elf::PT_GNU_RELRO {
            gnu_relro_segments += 1;
        }
    }

    let mut dependencies = collect_dynamic_dependencies(file, budget, path)?;

    let mut imports = Vec::new();
    for import in file.imports().map_err(|error| format_error(path, error))? {
        budget.charge()?;
        let import = import.map_err(|error| format_error(path, error))?;
        let name = match import.name() {
            NameOrOrdinal::Name(name) => budget.copy_bytes(name)?,
            NameOrOrdinal::Ordinal(ordinal) => ordinal.to_string().into_bytes(),
        };
        imports.push(ElfImport {
            library: budget.copy_bytes(import.library())?,
            name,
        });
    }

    let mut exports = Vec::new();
    for export in file.exports().map_err(|error| format_error(path, error))? {
        budget.charge()?;
        let export = export.map_err(|error| format_error(path, error))?;
        match export.name() {
            NameOrOrdinal::Name(name) => exports.push(budget.copy_bytes(name)?),
            NameOrOrdinal::Ordinal(ordinal) => {
                exports.push(ordinal.to_string().into_bytes());
            }
        }
    }

    let mut symbols = Vec::new();
    collect_symbols(file.elf_symbol_table(), endian, budget, path, &mut symbols)?;
    collect_symbols(
        file.elf_dynamic_symbol_table(),
        endian,
        budget,
        path,
        &mut symbols,
    )?;
    symbols.sort_by(|left, right| {
        (
            &left.name,
            &left.binding,
            &left.symbol_type,
            left.value,
            left.size,
        )
            .cmp(&(
                &right.name,
                &right.binding,
                &right.symbol_type,
                right.value,
                right.size,
            ))
    });

    dependencies.sort();
    imports.sort_by(|left, right| (&left.library, &left.name).cmp(&(&right.library, &right.name)));
    exports.sort();
    interpreters.sort();

    let build_id = file
        .build_id()
        .map_err(|error| format_error(path, error))?
        .map(|bytes| budget.copy_bytes(bytes))
        .transpose()?;

    Ok(ElfInspection {
        class: if file.is_64() { "ELF64" } else { "ELF32" },
        byte_order: if endian.is_little_endian() {
            "little-endian"
        } else {
            "big-endian"
        },
        architecture: format!("{:?}", file.architecture()),
        machine: header.e_machine(endian).0.to_string(),
        elf_type: elf_type_name(header.e_type(endian)),
        entry_point: header.e_entry(endian).into(),
        sections,
        segments,
        interpreters,
        dependencies,
        imports,
        exports,
        symbols,
        build_id,
        gnu_stack_executable,
        gnu_relro_segments,
    })
}

fn collect_dynamic_dependencies<'data, Elf, R>(
    file: &object::read::elf::ElfFile<'data, Elf, R>,
    budget: &mut FactBudget,
    path: &Path,
) -> Result<Vec<Vec<u8>>, InputError>
where
    Elf: FileHeader,
    Elf::ProgramHeader: ProgramHeader<Elf = Elf>,
    Elf::Dyn: Dyn<Endian = Elf::Endian, Word = Elf::Word>,
    R: object::read::ReadRef<'data>,
{
    let endian = file.endian();
    let data = file.data();
    let mut dependencies = Vec::new();
    for segment in file.elf_program_headers() {
        if segment.p_type(endian) != elf::PT_DYNAMIC {
            continue;
        }
        let entries = segment
            .dynamic(endian, data)
            .map_err(|error| format_error(path, error))?
            .ok_or_else(|| format_error(path, "missing PT_DYNAMIC entries"))?;
        let mut needed_offsets = Vec::new();
        let mut string_address = None;
        let mut string_size = None;
        let mut terminated = false;
        for entry in entries {
            budget.charge()?;
            let tag = entry.d_tag(endian);
            if tag == elf::DT_NULL {
                terminated = true;
                break;
            }
            match tag {
                elf::DT_NEEDED => needed_offsets.push(entry.d_val(endian).into()),
                elf::DT_STRTAB => {
                    if string_address.replace(entry.d_val(endian).into()).is_some() {
                        return Err(format_error(path, "duplicate DT_STRTAB entry"));
                    }
                }
                elf::DT_STRSZ if string_size.replace(entry.d_val(endian).into()).is_some() => {
                    return Err(format_error(path, "duplicate DT_STRSZ entry"));
                }
                elf::DT_STRSZ => {}
                _ => {}
            }
        }
        if !terminated {
            return Err(format_error(path, "unterminated PT_DYNAMIC entries"));
        }
        if needed_offsets.is_empty() {
            continue;
        }

        let string_address = string_address
            .ok_or_else(|| format_error(path, "DT_NEEDED entries without DT_STRTAB"))?;
        let string_size =
            string_size.ok_or_else(|| format_error(path, "DT_NEEDED entries without DT_STRSZ"))?;
        let strings = dynamic_string_table(file, string_address, string_size, path)?;
        for offset in needed_offsets {
            let start = usize::try_from(offset)
                .map_err(|_| format_error(path, "invalid DT_NEEDED string offset"))?;
            let name = strings
                .get(start..)
                .and_then(|remaining| {
                    remaining
                        .iter()
                        .position(|&byte| byte == 0)
                        .map(|length| &remaining[..length])
                })
                .filter(|name| !name.is_empty())
                .ok_or_else(|| format_error(path, "invalid DT_NEEDED string"))?;
            dependencies.push(budget.copy_bytes(name)?);
        }
    }
    Ok(dependencies)
}

fn dynamic_string_table<'data, Elf, R>(
    file: &object::read::elf::ElfFile<'data, Elf, R>,
    address: u64,
    size: u64,
    path: &Path,
) -> Result<&'data [u8], InputError>
where
    Elf: FileHeader,
    Elf::ProgramHeader: ProgramHeader<Elf = Elf>,
    R: object::read::ReadRef<'data>,
{
    let endian = file.endian();
    let mut strings = None;
    for segment in file.elf_program_headers() {
        if segment.p_type(endian) != elf::PT_LOAD {
            continue;
        }
        let Some(table) = segment
            .data_range(endian, file.data(), address, size)
            .map_err(|()| format_error(path, "invalid dynamic string table range"))?
        else {
            continue;
        };
        if strings.replace(table).is_some() {
            return Err(format_error(path, "ambiguous dynamic string table range"));
        }
    }
    strings.ok_or_else(|| format_error(path, "dynamic string table is outside loadable data"))
}

fn elf_type_name(elf_type: elf::FileType) -> String {
    match elf_type {
        elf::ET_NONE => "None".to_owned(),
        elf::ET_REL => "Relocatable".to_owned(),
        elf::ET_EXEC => "Executable".to_owned(),
        elf::ET_DYN => "Dynamic".to_owned(),
        elf::ET_CORE => "Core".to_owned(),
        other => format!("{other:?}"),
    }
}

fn section_type_name(section_type: elf::SectionType) -> String {
    let name = match section_type.0 {
        value if value == elf::SHT_NULL.0 => "SHT_NULL",
        value if value == elf::SHT_PROGBITS.0 => "SHT_PROGBITS",
        value if value == elf::SHT_SYMTAB.0 => "SHT_SYMTAB",
        value if value == elf::SHT_STRTAB.0 => "SHT_STRTAB",
        value if value == elf::SHT_RELA.0 => "SHT_RELA",
        value if value == elf::SHT_HASH.0 => "SHT_HASH",
        value if value == elf::SHT_DYNAMIC.0 => "SHT_DYNAMIC",
        value if value == elf::SHT_NOTE.0 => "SHT_NOTE",
        value if value == elf::SHT_NOBITS.0 => "SHT_NOBITS",
        value if value == elf::SHT_REL.0 => "SHT_REL",
        value if value == elf::SHT_DYNSYM.0 => "SHT_DYNSYM",
        value if value == elf::SHT_INIT_ARRAY.0 => "SHT_INIT_ARRAY",
        value if value == elf::SHT_FINI_ARRAY.0 => "SHT_FINI_ARRAY",
        value if value == elf::SHT_PREINIT_ARRAY.0 => "SHT_PREINIT_ARRAY",
        value if value == elf::SHT_GROUP.0 => "SHT_GROUP",
        value if value == elf::SHT_SYMTAB_SHNDX.0 => "SHT_SYMTAB_SHNDX",
        _ => return format!("0x{:x}", section_type.0),
    };
    format!("{name} ({})", section_type.0)
}

fn section_flags(flags: elf::SectionFlags) -> String {
    let mut names = Vec::new();
    for (flag, name) in [
        (elf::SHF_WRITE, "WRITE"),
        (elf::SHF_ALLOC, "ALLOC"),
        (elf::SHF_EXECINSTR, "EXECINSTR"),
        (elf::SHF_MERGE, "MERGE"),
        (elf::SHF_STRINGS, "STRINGS"),
        (elf::SHF_INFO_LINK, "INFO_LINK"),
        (elf::SHF_LINK_ORDER, "LINK_ORDER"),
        (elf::SHF_OS_NONCONFORMING, "OS_NONCONFORMING"),
        (elf::SHF_GROUP, "GROUP"),
        (elf::SHF_TLS, "TLS"),
        (elf::SHF_COMPRESSED, "COMPRESSED"),
        (elf::SHF_GNU_RETAIN, "GNU_RETAIN"),
        (elf::SHF_EXCLUDE, "EXCLUDE"),
    ] {
        if flags.contains(flag) {
            names.push(name);
        }
    }
    format!("0x{:x} [{}]", flags.0, names.join("|"))
}

fn segment_type_name(segment_type: elf::ProgramType) -> String {
    let name = match segment_type.0 {
        value if value == elf::PT_NULL.0 => "PT_NULL",
        value if value == elf::PT_LOAD.0 => "PT_LOAD",
        value if value == elf::PT_DYNAMIC.0 => "PT_DYNAMIC",
        value if value == elf::PT_INTERP.0 => "PT_INTERP",
        value if value == elf::PT_NOTE.0 => "PT_NOTE",
        value if value == elf::PT_SHLIB.0 => "PT_SHLIB",
        value if value == elf::PT_PHDR.0 => "PT_PHDR",
        value if value == elf::PT_TLS.0 => "PT_TLS",
        value if value == elf::PT_GNU_EH_FRAME.0 => "PT_GNU_EH_FRAME",
        value if value == elf::PT_GNU_STACK.0 => "PT_GNU_STACK",
        value if value == elf::PT_GNU_RELRO.0 => "PT_GNU_RELRO",
        value if value == elf::PT_GNU_PROPERTY.0 => "PT_GNU_PROPERTY",
        _ => return format!("0x{:x}", segment_type.0),
    };
    format!("{name} (0x{:x})", segment_type.0)
}

fn program_flags(flags: elf::ProgramFlags) -> String {
    format!(
        "0x{:x} [{}{}{}]",
        flags.0,
        if flags.contains(elf::PF_R) { 'R' } else { '-' },
        if flags.contains(elf::PF_W) { 'W' } else { '-' },
        if flags.contains(elf::PF_X) { 'X' } else { '-' },
    )
}

fn symbol_binding(binding: elf::SymbolBind) -> String {
    let name = match binding.0 {
        value if value == elf::STB_LOCAL.0 => "LOCAL",
        value if value == elf::STB_GLOBAL.0 => "GLOBAL",
        value if value == elf::STB_WEAK.0 => "WEAK",
        value if value == elf::STB_GNU_UNIQUE.0 => "GNU_UNIQUE",
        _ => return format!("0x{:x}", binding.0),
    };
    format!("{name} ({})", binding.0)
}

fn symbol_type(symbol_type: elf::SymbolType) -> String {
    let name = match symbol_type.0 {
        value if value == elf::STT_NOTYPE.0 => "NOTYPE",
        value if value == elf::STT_OBJECT.0 => "OBJECT",
        value if value == elf::STT_FUNC.0 => "FUNC",
        value if value == elf::STT_SECTION.0 => "SECTION",
        value if value == elf::STT_FILE.0 => "FILE",
        value if value == elf::STT_COMMON.0 => "COMMON",
        value if value == elf::STT_TLS.0 => "TLS",
        value if value == elf::STT_GNU_IFUNC.0 => "GNU_IFUNC",
        _ => return format!("0x{:x}", symbol_type.0),
    };
    format!("{name} ({})", symbol_type.0)
}

fn collect_symbols<'data, Elf, R>(
    table: &object::read::elf::SymbolTable<'data, Elf, R>,
    endian: Elf::Endian,
    budget: &mut FactBudget,
    path: &Path,
    symbols: &mut Vec<ElfSymbol>,
) -> Result<(), InputError>
where
    Elf: FileHeader,
    Elf::Sym: Sym<Endian = Elf::Endian, Word = Elf::Word>,
    R: object::read::ReadRef<'data>,
{
    let strings = table.strings();
    for symbol in table.iter().skip(1) {
        budget.charge()?;
        let name = symbol
            .name(endian, strings)
            .map_err(|error| format_error(path, error))?;
        if name.is_empty() {
            continue;
        }
        symbols.push(ElfSymbol {
            name: budget.copy_bytes(name)?,
            binding: symbol_binding(symbol.st_bind()),
            symbol_type: symbol_type(symbol.st_type()),
            value: symbol.st_value(endian).into(),
            size: symbol.st_size(endian).into(),
        });
    }
    Ok(())
}

#[derive(Debug)]
struct FactBudget {
    entries: u64,
    max_entries: u64,
    copied_name_bytes: usize,
}

impl FactBudget {
    fn charge(&mut self) -> Result<(), InputError> {
        self.entries = self
            .entries
            .checked_add(1)
            .filter(|entries| *entries <= self.max_entries)
            .ok_or(InputError::LimitExceeded {
                resource: "ELF entries",
                limit: self.max_entries,
            })?;
        Ok(())
    }

    fn copy_bytes(&mut self, bytes: &[u8]) -> Result<Vec<u8>, InputError> {
        if bytes.len() > MAX_FIELD_BYTES {
            return Err(InputError::LimitExceeded {
                resource: "ELF field bytes",
                limit: MAX_FIELD_BYTES as u64,
            });
        }
        self.copied_name_bytes = self
            .copied_name_bytes
            .checked_add(bytes.len())
            .filter(|length| *length <= MAX_COPIED_NAME_BYTES)
            .ok_or(InputError::LimitExceeded {
                resource: "ELF copied name bytes",
                limit: MAX_COPIED_NAME_BYTES as u64,
            })?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| InputError::LimitExceeded {
                resource: "ELF memory",
                limit: MAX_ELF_FILE_BYTES,
            })?;
        owned.extend_from_slice(bytes);
        Ok(owned)
    }
}

fn format_error(path: &Path, error: impl Debug) -> InputError {
    InputError::Format {
        format: "ELF",
        path: path.to_path_buf(),
        message: format!("{error:?}"),
    }
}
