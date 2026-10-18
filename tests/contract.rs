use std::error::Error;
use std::io;
use std::path::PathBuf;

use crucksware::error::{DiffError, Resource, Side};
use crucksware::limits::{Budget, Limits};
use crucksware::path::{RelPath, encode_bytes};

#[test]
fn paths_reject_traversal_and_empty_components() {
    for raw in [
        b"".as_slice(),
        b"/a",
        b"a/",
        b"a//b",
        b".",
        b"..",
        b"a/../b",
        b"a/./b",
        b"a\0b",
    ] {
        assert!(
            matches!(
                RelPath::new(raw.to_vec()),
                Err(DiffError::InvalidRelativePath)
            ),
            "{raw:?}"
        );
    }
    let path = RelPath::new(b".hidden/\xff".to_vec()).unwrap();
    assert_eq!(path.as_bytes(), b".hidden/\xff");
}

#[test]
fn display_is_lossless_and_cannot_inject_terminal_rows() {
    assert_eq!(
        encode_bytes(b"a b%\n\xff\x1b\t\r"),
        "a%20b%25%0A%FF%1B%09%0D"
    );
    assert_eq!(encode_bytes(b"/../a-Z_0.txt"), "/../a-Z_0.txt");
    let raw: Vec<u8> = (0..=255).collect();
    let encoded = encode_bytes(&raw);
    let mut decoded = Vec::new();
    let mut chars = encoded.bytes();
    while let Some(byte) = chars.next() {
        if byte == b'%' {
            let pair = [chars.next().unwrap(), chars.next().unwrap()];
            decoded.push(u8::from_str_radix(std::str::from_utf8(&pair).unwrap(), 16).unwrap());
        } else {
            decoded.push(byte);
        }
    }
    assert_eq!(decoded, raw);
}

#[test]
fn path_order_uses_raw_bytes_instead_of_display() {
    let z = RelPath::new(b"z".to_vec()).unwrap();
    let ff = RelPath::new(vec![255]).unwrap();
    assert!(z < ff);
    assert!(encode_bytes(z.as_bytes()) > encode_bytes(ff.as_bytes()));
}

fn limited() -> Limits {
    Limits {
        max_entries: 2,
        max_depth: 2,
        max_path_bytes: 6,
        max_bytes_read: 4,
    }
}

#[test]
fn entries_and_targets_share_a_budget_and_failure_is_atomic() {
    let mut budget = Budget::new(limited());
    budget.charge_entry(1, 2).unwrap();
    budget.charge_target(2).unwrap();
    assert!(matches!(
        budget.charge_entry(2, 3),
        Err(DiffError::LimitExceeded {
            resource: Resource::PathBytes,
            limit: 6
        })
    ));
    budget.charge_entry(2, 2).unwrap();
    assert!(matches!(
        budget.charge_entry(1, 0),
        Err(DiffError::LimitExceeded {
            resource: Resource::Entries,
            limit: 2
        })
    ));
}

#[test]
fn depth_is_checked_before_charging_an_entry() {
    let mut budget = Budget::new(limited());
    assert!(matches!(
        budget.charge_entry(3, 1),
        Err(DiffError::LimitExceeded {
            resource: Resource::Depth,
            limit: 2
        })
    ));
    budget.charge_entry(1, 1).unwrap();
    budget.charge_entry(2, 1).unwrap();
}

#[test]
fn read_budget_counts_actual_bytes_and_rejects_overflow() {
    let mut budget = Budget::new(limited());
    budget.charge_read(1).unwrap();
    budget.charge_read(3).unwrap();
    assert_eq!(budget.remaining_read_bytes(), 0);
    assert!(matches!(
        budget.charge_read(1),
        Err(DiffError::LimitExceeded {
            resource: Resource::BytesRead,
            limit: 4
        })
    ));
    let mut budget = Budget::new(Limits {
        max_path_bytes: u64::MAX,
        max_bytes_read: u64::MAX,
        ..limited()
    });
    budget.charge_target(u64::MAX).unwrap();
    assert!(matches!(
        budget.charge_target(1),
        Err(DiffError::LimitExceeded {
            resource: Resource::PathBytes,
            limit: u64::MAX
        })
    ));
    budget.charge_read(u64::MAX).unwrap();
    assert!(budget.charge_read(1).is_err());
}

#[test]
fn default_budget_enforces_the_documented_depth_boundary() {
    let mut budget = Budget::new(Limits::default());
    budget.charge_entry(256, 1).unwrap();
    assert!(matches!(
        budget.charge_entry(257, 1),
        Err(DiffError::LimitExceeded {
            resource: Resource::Depth,
            limit: 256
        })
    ));
}

#[test]
fn io_errors_preserve_their_source_and_escape_input_paths() {
    let error = DiffError::Io {
        operation: "inspect",
        side: Side::New,
        path: PathBuf::from("root/line\n\x1b"),
        source: io::Error::new(io::ErrorKind::PermissionDenied, "denied"),
    };
    assert_eq!(
        error
            .source()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    let display = error.to_string();
    assert!(display.contains("root/line%0A%1B"));
    assert!(!display.contains(['\n', '\x1b']));
    assert!(display.contains("new"));
}

#[test]
#[cfg(unix)]
fn io_errors_escape_non_utf8_paths() {
    use std::os::unix::ffi::OsStringExt;
    let error = DiffError::TreeChanged {
        side: Side::Old,
        path: std::ffi::OsString::from_vec(b"root/\xff".to_vec()).into(),
    };
    assert!(error.to_string().contains("root/%FF"));
}

#[test]
fn kind_classification_keeps_special_nodes_distinct() {
    use crucksware::model::{Entry, EntryKind};
    for (entry, expected) in [
        (
            Entry::File {
                size: 1,
                mode: 0o644,
            },
            EntryKind::File,
        ),
        (Entry::Directory { mode: 0o755 }, EntryKind::Directory),
        (
            Entry::Symlink {
                target: b"a".to_vec(),
            },
            EntryKind::Symlink,
        ),
        (Entry::Fifo { mode: 0o600 }, EntryKind::Fifo),
        (Entry::Socket { mode: 0o600 }, EntryKind::Socket),
        (
            Entry::CharDevice {
                mode: 0o600,
                device_id: 1,
            },
            EntryKind::CharDevice,
        ),
        (
            Entry::BlockDevice {
                mode: 0o600,
                device_id: 2,
            },
            EntryKind::BlockDevice,
        ),
    ] {
        assert_eq!(entry.kind(), expected);
    }
}

#[test]
fn default_budgets_enforce_entry_path_and_read_boundaries() {
    let mut budget = Budget::new(Limits::default());
    for _ in 0..1_000_000 {
        budget.charge_entry(1, 0).unwrap();
    }
    assert!(matches!(
        budget.charge_entry(1, 0),
        Err(DiffError::LimitExceeded {
            resource: Resource::Entries,
            limit: 1_000_000
        })
    ));
    budget.charge_target(67_108_864).unwrap();
    assert!(matches!(
        budget.charge_target(1),
        Err(DiffError::LimitExceeded {
            resource: Resource::PathBytes,
            limit: 67_108_864
        })
    ));
    budget.charge_read(1_099_511_627_776).unwrap();
    assert!(matches!(
        budget.charge_read(1),
        Err(DiffError::LimitExceeded {
            resource: Resource::BytesRead,
            limit: 1_099_511_627_776
        })
    ));
}
