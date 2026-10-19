pub fn minimal_elf64(entry_point: u64) -> Vec<u8> {
    let mut bytes = vec![0; 64];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&entry_point.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
    bytes
}

pub fn minimal_pe64(entry_point_rva: u32) -> Vec<u8> {
    let nt_offset = 0x80;
    let optional_offset = nt_offset + 4 + 20;
    let section_offset = optional_offset + 240;
    let raw_offset = 0x200;
    let mut bytes = vec![0; raw_offset + 0x200];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&(nt_offset as u32).to_le_bytes());
    bytes[nt_offset..nt_offset + 4].copy_from_slice(b"PE\0\0");

    let file_header = nt_offset + 4;
    bytes[file_header..file_header + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
    bytes[file_header + 2..file_header + 4].copy_from_slice(&1_u16.to_le_bytes());
    bytes[file_header + 16..file_header + 18].copy_from_slice(&240_u16.to_le_bytes());
    bytes[file_header + 18..file_header + 20].copy_from_slice(&0x0022_u16.to_le_bytes());

    bytes[optional_offset..optional_offset + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
    bytes[optional_offset + 16..optional_offset + 20]
        .copy_from_slice(&entry_point_rva.to_le_bytes());
    bytes[optional_offset + 24..optional_offset + 32]
        .copy_from_slice(&0x140000000_u64.to_le_bytes());
    bytes[optional_offset + 32..optional_offset + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[optional_offset + 36..optional_offset + 40].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[optional_offset + 56..optional_offset + 60].copy_from_slice(&0x2000_u32.to_le_bytes());
    bytes[optional_offset + 60..optional_offset + 64].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[optional_offset + 68..optional_offset + 70].copy_from_slice(&3_u16.to_le_bytes());
    bytes[optional_offset + 108..optional_offset + 112].copy_from_slice(&16_u32.to_le_bytes());

    bytes[section_offset..section_offset + 5].copy_from_slice(b".text");
    bytes[section_offset + 8..section_offset + 12].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[section_offset + 12..section_offset + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
    bytes[section_offset + 16..section_offset + 20].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[section_offset + 20..section_offset + 24]
        .copy_from_slice(&(raw_offset as u32).to_le_bytes());
    bytes[section_offset + 36..section_offset + 40].copy_from_slice(&0x60000020_u32.to_le_bytes());
    bytes
}
