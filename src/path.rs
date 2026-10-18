use crate::error::DiffError;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RelPath(Vec<u8>);

impl RelPath {
    pub fn new(bytes: Vec<u8>) -> Result<Self, DiffError> {
        if bytes.contains(&0)
            || bytes
                .split(|&byte| byte == b'/')
                .any(|part| part.is_empty() || part == b"." || part == b"..")
        {
            return Err(DiffError::InvalidRelativePath);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub fn encode_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::new();
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    encoded
}
