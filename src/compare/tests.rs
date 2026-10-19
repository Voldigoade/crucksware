use super::*;
use crate::{
    error::{DiffError, Resource, Side},
    limits::{Budget, Limits},
    model::{Category, ChangedField, Diff, Entry, Summary},
    path::RelPath,
    scan::scan,
};
use std::{
    fs,
    os::unix::{
        ffi::OsStringExt,
        fs::{PermissionsExt, symlink},
        net::UnixListener,
    },
};
use tempfile::tempdir;

#[test]
fn category_matrix_preserves_precedence_and_ordered_reasons() {
    use Category::*;
    use ChangedField::*;
    let cases = [
        (
            Entry::File {
                size: 1,
                mode: 0o644,
            },
            Entry::File {
                size: 1,
                mode: 0o755,
            },
            false,
            Some((Modified, vec![Content, Mode])),
        ),
        (
            Entry::File {
                size: 1,
                mode: 0o644,
            },
            Entry::File {
                size: 1,
                mode: 0o755,
            },
            true,
            Some((MetadataChanged, vec![Mode])),
        ),
        (
            Entry::File {
                size: 1,
                mode: 0o644,
            },
            Entry::File {
                size: 2,
                mode: 0o644,
            },
            true,
            Some((Modified, vec![Content])),
        ),
        (
            Entry::Symlink {
                target: b"a".to_vec(),
            },
            Entry::Symlink {
                target: b"b".to_vec(),
            },
            true,
            Some((Modified, vec![SymlinkTarget])),
        ),
        (
            Entry::Directory { mode: 0o755 },
            Entry::Directory { mode: 0o700 },
            true,
            Some((MetadataChanged, vec![Mode])),
        ),
        (
            Entry::Fifo { mode: 0o644 },
            Entry::Fifo { mode: 0o600 },
            true,
            Some((MetadataChanged, vec![Mode])),
        ),
        (
            Entry::Socket { mode: 0o644 },
            Entry::Socket { mode: 0o600 },
            true,
            Some((MetadataChanged, vec![Mode])),
        ),
        (
            Entry::CharDevice {
                mode: 0o644,
                device_id: 1,
            },
            Entry::CharDevice {
                mode: 0o600,
                device_id: 2,
            },
            true,
            Some((MetadataChanged, vec![Mode, DeviceId])),
        ),
        (
            Entry::BlockDevice {
                mode: 0o600,
                device_id: 1,
            },
            Entry::BlockDevice {
                mode: 0o600,
                device_id: 2,
            },
            true,
            Some((MetadataChanged, vec![DeviceId])),
        ),
        (
            Entry::File {
                size: 1,
                mode: 0o644,
            },
            Entry::Symlink {
                target: b"a".to_vec(),
            },
            false,
            Some((TypeChanged, vec![Type])),
        ),
        (
            Entry::File {
                size: 0,
                mode: 0o644,
            },
            Entry::File {
                size: 0,
                mode: 0o644,
            },
            true,
            None,
        ),
    ];
    for (before, after, equal, want) in cases {
        assert_eq!(classify(&before, &after, equal), want);
    }
    for entry in [
        Entry::Directory { mode: 0o755 },
        Entry::Symlink {
            target: b"a".to_vec(),
        },
        Entry::Fifo { mode: 0o600 },
        Entry::Socket { mode: 0o600 },
        Entry::CharDevice {
            mode: 0o600,
            device_id: 1,
        },
        Entry::BlockDevice {
            mode: 0o600,
            device_id: 1,
        },
    ] {
        assert_eq!(classify(&entry, &entry, true), None);
    }
}

#[test]
fn complete_tree_reports_each_category_and_subtree_replacement() {
    let old = tempdir().unwrap();
    let new = tempdir().unwrap();
    for root in [old.path(), new.path()] {
        fs::write(root.join("same"), b"same").unwrap();
        fs::write(root.join("metadata"), b"").unwrap();
        fs::set_permissions(root.join("metadata"), fs::Permissions::from_mode(0o644)).unwrap();
    }
    fs::write(old.path().join("removed"), b"").unwrap();
    fs::write(new.path().join("added"), b"").unwrap();
    fs::create_dir(old.path().join("kind")).unwrap();
    fs::write(old.path().join("kind/child"), b"").unwrap();
    fs::write(new.path().join("kind"), b"").unwrap();
    fs::write(old.path().join("modified"), b"abc").unwrap();
    fs::write(new.path().join("modified"), b"xyz").unwrap();
    fs::set_permissions(
        old.path().join("modified"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    fs::set_permissions(
        new.path().join("modified"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::set_permissions(
        new.path().join("metadata"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    symlink("old", old.path().join("link")).unwrap();
    symlink("new", new.path().join("link")).unwrap();
    let diff = compare(old.path(), new.path(), Limits::default()).unwrap();
    let actual: Vec<_> = diff
        .changes
        .iter()
        .map(|c| (c.path.as_bytes(), c.category))
        .collect();
    assert_eq!(
        actual,
        vec![
            (b"added".as_slice(), Category::Added),
            (b"kind", Category::TypeChanged),
            (b"kind/child", Category::Removed),
            (b"link", Category::Modified),
            (b"metadata", Category::MetadataChanged),
            (b"modified", Category::Modified),
            (b"removed", Category::Removed)
        ]
    );
    assert_eq!(
        diff.summary,
        Summary {
            added: 1,
            removed: 2,
            modified: 2,
            type_changed: 1,
            metadata_changed: 1,
            unchanged: 1
        }
    );
    assert_eq!(
        diff.changes[5].changed_fields,
        vec![ChangedField::Content, ChangedField::Mode]
    );
    assert!(diff.changes[0].before.is_none());
    assert!(diff.changes[0].after.is_some());
    assert!(diff.changes[2].after.is_none());
    assert!(diff.changes[2].before.is_some());
    assert_eq!(fs::read(old.path().join("modified")).unwrap(), b"abc");
    assert_eq!(
        fs::symlink_metadata(new.path().join("modified"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o755
    );
    assert_eq!(
        fs::read_link(old.path().join("link")).unwrap(),
        std::path::Path::new("old")
    );
}

#[test]
fn creation_order_and_raw_non_utf8_names_do_not_change_the_diff() {
    let old = tempdir().unwrap();
    let a = tempdir().unwrap();
    let b = tempdir().unwrap();
    let names = [b"z".as_slice(), b"\xff", b"\n\x1b", b"%"];
    for name in names {
        fs::write(
            a.path().join(std::ffi::OsString::from_vec(name.to_vec())),
            b"x",
        )
        .unwrap();
    }
    for name in names.into_iter().rev() {
        fs::write(
            b.path().join(std::ffi::OsString::from_vec(name.to_vec())),
            b"x",
        )
        .unwrap();
    }
    let first = compare(old.path(), a.path(), Limits::default()).unwrap();
    assert_eq!(
        first,
        compare(old.path(), b.path(), Limits::default()).unwrap()
    );
    assert_eq!(
        first
            .changes
            .iter()
            .map(|c| c.path.as_bytes())
            .collect::<Vec<_>>(),
        vec![b"\n\x1b".as_slice(), b"%", b"z", b"\xff"]
    );
}

#[test]
fn added_and_removed_directories_do_not_collapse_descendants() {
    let old = tempdir().unwrap();
    let new = tempdir().unwrap();
    fs::create_dir(new.path().join("d")).unwrap();
    fs::write(new.path().join("d/f"), b"").unwrap();
    let added = compare(old.path(), new.path(), Limits::default()).unwrap();
    let removed = compare(new.path(), old.path(), Limits::default()).unwrap();
    assert_eq!(added.summary.added, 2);
    assert_eq!(removed.summary.removed, 2);
    assert_eq!(added.changes[1].path.as_bytes(), b"d/f");
    assert_eq!(removed.changes[1].path.as_bytes(), b"d/f");
}

#[test]
fn timestamps_root_modes_and_hard_link_topology_are_not_semantic_changes() {
    let old = tempdir().unwrap();
    let new = tempdir().unwrap();
    fs::write(old.path().join("a"), b"same").unwrap();
    fs::hard_link(old.path().join("a"), old.path().join("b")).unwrap();
    for name in ["a", "b"] {
        fs::write(new.path().join(name), b"same").unwrap();
        fs::set_permissions(new.path().join(name), fs::Permissions::from_mode(0o644)).unwrap();
    }
    fs::set_permissions(old.path().join("a"), fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(old.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(new.path(), fs::Permissions::from_mode(0o755)).unwrap();
    fs::File::open(new.path().join("a"))
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH)
        .unwrap();
    let diff = compare(old.path(), new.path(), Limits::default()).unwrap();
    assert!(diff.changes.is_empty());
    assert_eq!(diff.summary.unchanged, 2);
}

#[test]
fn moves_remain_added_removed_and_shared_inodes_do_not_shortcut_reads() {
    let old = tempdir().unwrap();
    let new = tempdir().unwrap();
    fs::write(old.path().join("a"), b"same").unwrap();
    fs::hard_link(old.path().join("a"), new.path().join("a")).unwrap();
    fs::hard_link(old.path().join("a"), old.path().join("gone")).unwrap();
    fs::hard_link(old.path().join("a"), new.path().join("renamed")).unwrap();
    let diff = compare(old.path(), new.path(), Limits::default()).unwrap();
    assert_eq!(
        diff.summary,
        Summary {
            added: 1,
            removed: 1,
            unchanged: 1,
            ..Summary::default()
        }
    );
    assert!(matches!(
        compare(
            old.path(),
            new.path(),
            Limits {
                max_bytes_read: 1,
                ..Limits::default()
            }
        ),
        Err(DiffError::LimitExceeded {
            resource: Resource::BytesRead,
            ..
        })
    ));
}

#[test]
fn equal_and_overlapping_roots_are_compared_without_identity_shortcuts() {
    let root = tempdir().unwrap();
    fs::write(root.path().join("a"), b"x").unwrap();
    let diff = compare(root.path(), root.path(), Limits::default()).unwrap();
    assert_eq!(diff.summary.unchanged, 1);
    assert!(matches!(
        compare(
            root.path(),
            root.path(),
            Limits {
                max_entries: 1,
                ..Limits::default()
            }
        ),
        Err(DiffError::LimitExceeded {
            resource: Resource::Entries,
            ..
        })
    ));
    fs::create_dir(root.path().join("nested")).unwrap();
    fs::write(root.path().join("nested/a"), b"x").unwrap();
    let diff = compare(root.path(), &root.path().join("nested"), Limits::default()).unwrap();
    assert_eq!(diff.summary.unchanged, 1);
    assert_eq!(diff.summary.removed, 2);
}

#[test]
fn limits_are_shared_and_unneeded_content_is_not_opened() {
    let old = tempdir().unwrap();
    let new = tempdir().unwrap();
    fs::write(old.path().join("a"), b"a").unwrap();
    fs::write(new.path().join("a"), b"bb").unwrap();
    for root in [old.path(), new.path()] {
        fs::set_permissions(root.join("a"), fs::Permissions::from_mode(0o0)).unwrap();
    }
    let diff = compare(
        old.path(),
        new.path(),
        Limits {
            max_bytes_read: 1,
            max_entries: 2,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(diff.summary.modified, 1);
    assert!(matches!(
        compare(
            old.path(),
            new.path(),
            Limits {
                max_entries: 1,
                ..Limits::default()
            }
        ),
        Err(DiffError::LimitExceeded {
            resource: Resource::Entries,
            ..
        })
    ));
    assert!(matches!(
        compare(
            old.path(),
            new.path(),
            Limits {
                max_path_bytes: 1,
                ..Limits::default()
            }
        ),
        Err(DiffError::LimitExceeded {
            resource: Resource::PathBytes,
            ..
        })
    ));
    fs::remove_file(old.path().join("a")).unwrap();
    assert_eq!(
        compare(
            old.path(),
            new.path(),
            Limits {
                max_bytes_read: 1,
                ..Limits::default()
            }
        )
        .unwrap()
        .summary
        .added,
        1
    );
}

#[test]
fn special_nodes_are_metadata_only_and_child_links_are_opaque() {
    let old = tempdir().unwrap();
    let new = tempdir().unwrap();
    let _a = UnixListener::bind(old.path().join("socket")).unwrap();
    let _b = UnixListener::bind(new.path().join("socket")).unwrap();
    for root in [old.path(), new.path()] {
        symlink("/etc", root.join("external")).unwrap();
        symlink("cycle", root.join("cycle")).unwrap();
    }
    let diff = compare(
        old.path(),
        new.path(),
        Limits {
            max_bytes_read: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    assert!(diff.changes.is_empty());
    assert_eq!(diff.summary.unchanged, 3);
}

#[test]
fn final_revalidation_rejects_changes_even_when_no_contents_were_read() {
    let old = tempdir().unwrap();
    let new = tempdir().unwrap();
    fs::write(new.path().join("added"), b"x").unwrap();
    let mut budget = Budget::new(Limits::default());
    let a = scan(old.path(), Side::Old, &mut budget).unwrap();
    let b = scan(new.path(), Side::New, &mut budget).unwrap();
    fs::write(new.path().join("added"), b"changed length").unwrap();
    assert!(
        matches!(compare_snapshots(&a,&b,&mut budget),Err(DiffError::TreeChanged{side:Side::New,path}) if path==new.path().join("added"))
    );
    let empty = tempdir().unwrap();
    let mut budget = Budget::new(Limits::default());
    let a = scan(empty.path(), Side::Old, &mut budget).unwrap();
    let b = scan(old.path(), Side::New, &mut budget).unwrap();
    fs::write(empty.path().join("unexpected"), b"").unwrap();
    fs::File::open(empty.path())
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH)
        .unwrap();
    assert!(
        matches!(compare_snapshots(&a,&b,&mut budget),Err(DiffError::TreeChanged{side:Side::Old,path}) if path==empty.path())
    );
}

#[test]
fn input_and_required_content_failures_never_return_a_diff() {
    let old = tempdir().unwrap();
    let new = tempdir().unwrap();
    assert!(matches!(
        compare(old.path(), &new.path().join("missing"), Limits::default()),
        Err(DiffError::Io {
            side: Side::New,
            ..
        })
    ));
    for root in [old.path(), new.path()] {
        fs::write(root.join("a"), b"x").unwrap();
    }
    fs::set_permissions(new.path().join("a"), fs::Permissions::from_mode(0o0)).unwrap();
    assert!(
        matches!(compare(old.path(),new.path(),Limits::default()),Err(DiffError::Io{side:Side::New,source,..}) if source.kind()==std::io::ErrorKind::PermissionDenied)
    );
}

#[test]
fn summary_counters_fail_instead_of_wrapping() {
    let mut diff = Diff {
        summary: Summary {
            added: u64::MAX,
            ..Summary::default()
        },
        ..Diff::default()
    };
    let change = crate::model::Change {
        path: RelPath::new(b"a".to_vec()).unwrap(),
        category: Category::Added,
        changed_fields: vec![],
        before: None,
        after: Some(Entry::Directory { mode: 0o755 }),
    };
    assert!(matches!(
        push_change(&mut diff, change),
        Err(DiffError::LimitExceeded {
            resource: Resource::Entries,
            limit: u64::MAX
        })
    ));
    assert!(diff.changes.is_empty());
}

#[test]
fn comparison_progress_reports_real_inventory_work_and_preserves_the_diff() {
    use crate::progress::{ProgressEvent, ProgressPhase};

    let old = tempdir().unwrap();
    let new = tempdir().unwrap();
    fs::write(old.path().join("changed"), b"old").unwrap();
    fs::write(old.path().join("removed"), b"gone").unwrap();
    fs::write(new.path().join("changed"), b"new").unwrap();
    fs::write(new.path().join("added"), b"here").unwrap();

    let expected = compare(old.path(), new.path(), Limits::default()).unwrap();
    let mut events = Vec::new();
    let actual = compare_with_progress(old.path(), new.path(), Limits::default(), |event| {
        events.push(event);
    })
    .unwrap();

    assert_eq!(actual, expected);
    assert!(events.starts_with(&[
        ProgressEvent::PhaseStarted {
            phase: ProgressPhase::Inventory(Side::Old),
            total: None,
        },
        ProgressEvent::EntryDiscovered {
            side: Side::Old,
            entries: 1,
        },
        ProgressEvent::EntryDiscovered {
            side: Side::Old,
            entries: 2,
        },
        ProgressEvent::PhaseCompleted {
            phase: ProgressPhase::Inventory(Side::Old),
        },
    ]));

    assert!(events.contains(&ProgressEvent::PhaseStarted {
        phase: ProgressPhase::Comparing,
        total: None,
    }));
    assert!(events.contains(&ProgressEvent::PhaseTotalKnown {
        phase: ProgressPhase::Comparing,
        total: 3,
    }));
    let comparison_progress = events
        .iter()
        .filter_map(|event| match event {
            ProgressEvent::PhaseProgress {
                phase: ProgressPhase::Comparing,
                completed,
                total,
            } => Some((*completed, *total)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(comparison_progress, [(1, 3), (2, 3), (3, 3)]);
    let byte_counts = events
        .iter()
        .filter_map(|event| match event {
            ProgressEvent::BytesRead { total_bytes_read } => Some(*total_bytes_read),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(byte_counts, [3, 6]);
    let change_categories = events
        .iter()
        .filter_map(|event| match event {
            ProgressEvent::ChangeDiscovered { category } => Some(*category),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        change_categories,
        [Category::Modified, Category::Removed, Category::Added]
    );
    assert!(events.contains(&ProgressEvent::PhaseCompleted {
        phase: ProgressPhase::Comparing,
    }));
    for side in [Side::Old, Side::New] {
        assert!(events.contains(&ProgressEvent::PhaseStarted {
            phase: ProgressPhase::Revalidation(side),
            total: Some(3),
        }));
        let completed = events
            .iter()
            .filter_map(|event| match event {
                ProgressEvent::PhaseProgress {
                    phase: ProgressPhase::Revalidation(event_side),
                    completed,
                    total: 3,
                } if *event_side == side => Some(*completed),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(completed, [1, 2, 3]);
        assert!(events.contains(&ProgressEvent::PhaseCompleted {
            phase: ProgressPhase::Revalidation(side),
        }));
    }
}
