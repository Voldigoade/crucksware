use crate::error::{DiffError, Resource};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_entries: u64,
    pub max_depth: u64,
    pub max_path_bytes: u64,
    pub max_bytes_read: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 1_000_000,
            max_depth: 256,
            max_path_bytes: 67_108_864,
            max_bytes_read: 1_099_511_627_776,
        }
    }
}

#[derive(Debug)]
pub struct Budget {
    limits: Limits,
    entries: u64,
    path_bytes: u64,
    bytes_read: u64,
}

impl Budget {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            entries: 0,
            path_bytes: 0,
            bytes_read: 0,
        }
    }

    pub fn charge_entry(&mut self, depth: u64, path_bytes: u64) -> Result<(), DiffError> {
        checked_charge(0, depth, self.limits.max_depth, Resource::Depth)?;
        let entries = checked_charge(self.entries, 1, self.limits.max_entries, Resource::Entries)?;
        let paths = checked_charge(
            self.path_bytes,
            path_bytes,
            self.limits.max_path_bytes,
            Resource::PathBytes,
        )?;
        self.entries = entries;
        self.path_bytes = paths;
        Ok(())
    }

    pub fn charge_target(&mut self, bytes: u64) -> Result<(), DiffError> {
        self.path_bytes = checked_charge(
            self.path_bytes,
            bytes,
            self.limits.max_path_bytes,
            Resource::PathBytes,
        )?;
        Ok(())
    }

    pub fn remaining_read_bytes(&self) -> u64 {
        self.limits.max_bytes_read - self.bytes_read
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn check_read(&self, bytes: u64) -> Result<(), DiffError> {
        checked_charge(
            self.bytes_read,
            bytes,
            self.limits.max_bytes_read,
            Resource::BytesRead,
        )
        .map(|_| ())
    }

    pub fn charge_read(&mut self, bytes: u64) -> Result<(), DiffError> {
        self.bytes_read = checked_charge(
            self.bytes_read,
            bytes,
            self.limits.max_bytes_read,
            Resource::BytesRead,
        )?;
        Ok(())
    }
}

fn checked_charge(
    current: u64,
    amount: u64,
    limit: u64,
    resource: Resource,
) -> Result<u64, DiffError> {
    current
        .checked_add(amount)
        .filter(|&total| total <= limit)
        .ok_or(DiffError::LimitExceeded { resource, limit })
}
