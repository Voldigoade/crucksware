use super::*;
use crate::{
    error::{DiffError, Resource, Side},
    limits::{Budget, Limits},
    model::{Entry, EntryKind, Snapshot},
    path::RelPath,
};
use std::{
    cell::Cell,
    ffi::OsString,
    os::unix::{
        ffi::OsStringExt,
        fs::{PermissionsExt, symlink},
        net::UnixListener,
    },
};
use std::{fs, io, path::Path};
use tempfile::tempdir;

fn inventory(root: &Path) -> Snapshot {
    scan(root, Side::Old, &mut Budget::new(Limits::default())).unwrap()
}

fn rel(raw: &[u8]) -> RelPath {
    RelPath::new(raw.to_vec()).unwrap()
}

#[test]
fn inventory_is_lossless_and_does_not_follow_links() {
    let tmp = tempdir().unwrap();
    let root = tmp.path().join(OsString::from_vec(b"root\xff".to_vec()));
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("empty")).unwrap();
    fs::write(root.join(".hidden"), b"abc").unwrap();
    fs::write(root.join(OsString::from_vec(vec![255])), b"x").unwrap();
    fs::create_dir(tmp.path().join("outside")).unwrap();
    fs::write(tmp.path().join("outside/secret"), b"never read").unwrap();
    for (name, target) in [
        ("broken", "missing"),
        ("cycle", "cycle"),
        ("escape", "../outside"),
        ("dirlink", "empty"),
        ("absolute", "/etc"),
    ] {
        symlink(target, root.join(name)).unwrap();
    }
    let snapshot = inventory(&root);
    let paths: Vec<_> = snapshot.entries.keys().map(|p| p.as_bytes()).collect();
    assert_eq!(
        paths,
        vec![
            b".hidden".as_slice(),
            b"absolute",
            b"broken",
            b"cycle",
            b"dirlink",
            b"empty",
            b"escape",
            b"\xff"
        ]
    );
    assert!(matches!(
        snapshot.entries[&rel(b"empty")].entry,
        Entry::Directory { .. }
    ));
    assert_eq!(
        snapshot.entries[&rel(b"escape")].entry,
        Entry::Symlink {
            target: b"../outside".to_vec()
        }
    );
    revalidate(&snapshot, Side::Old).unwrap();
    let alias = tmp.path().join("alias");
    symlink(&root, &alias).unwrap();
    let aliased = inventory(&alias);
    assert_eq!(aliased.root, snapshot.root);
    assert_eq!(aliased.entries, snapshot.entries);
}

#[test]
fn metadata_only_inventory_accepts_unreadable_files_and_sockets() {
    let tmp = tempdir().unwrap();
    let p = tmp.path().join("closed");
    fs::write(&p, b"abc").unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o0)).unwrap();
    let _listener = UnixListener::bind(tmp.path().join("socket")).unwrap();
    let snapshot = inventory(tmp.path());
    assert_eq!(
        snapshot.entries[&rel(b"closed")].entry,
        Entry::File { size: 3, mode: 0 }
    );
    assert!(matches!(
        snapshot.entries[&rel(b"socket")].entry,
        Entry::Socket { .. }
    ));
}

#[test]
fn masks_modes_and_classifies_special_metadata_without_opening_nodes() {
    for (kind, want) in [
        (EntryKind::Fifo, Entry::Fifo { mode: 0o4755 }),
        (EntryKind::Socket, Entry::Socket { mode: 0o4755 }),
        (
            EntryKind::CharDevice,
            Entry::CharDevice {
                mode: 0o4755,
                device_id: 123,
            },
        ),
        (
            EntryKind::BlockDevice,
            Entry::BlockDevice {
                mode: 0o4755,
                device_id: 123,
            },
        ),
    ] {
        let facts = NodeFacts {
            kind: Some(kind),
            mode: 0o104755,
            len: 999,
            device_id: 123,
            dev: 1,
        };
        assert_eq!(
            entry_from_facts(&facts, None, Side::Old, Path::new("node")).unwrap(),
            want
        );
    }
    let facts = NodeFacts {
        kind: None,
        mode: 0,
        len: 0,
        device_id: 0,
        dev: 1,
    };
    assert!(matches!(
        entry_from_facts(&facts, None, Side::New, Path::new("node")),
        Err(DiffError::UnsupportedType {
            side: Side::New,
            ..
        })
    ));
    let facts = NodeFacts {
        kind: Some(EntryKind::Symlink),
        ..facts
    };
    assert!(
        matches!(entry_from_facts(&facts,None,Side::New,Path::new("link")),Err(DiffError::Io{source,..}) if source.kind()==io::ErrorKind::InvalidData)
    );
}

#[test]
fn refuses_cross_device_entries() {
    check_device(2, 2, Side::Old, Path::new("same")).unwrap();
    assert!(
        matches!(check_device(2,3,Side::New,Path::new("mount")),Err(DiffError::FilesystemBoundary{side:Side::New,path}) if path==Path::new("mount"))
    );
}

#[test]
fn collection_propagates_late_errors_and_detects_duplicates() {
    let items = vec![
        Ok(OsString::from("a")),
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "late")),
    ];
    let result = collect_names(
        items.into_iter(),
        None,
        Side::New,
        Path::new("root"),
        &mut Budget::new(Limits::default()),
    );
    assert!(
        matches!(result,Err(DiffError::Io{side:Side::New,path,source,..}) if path==Path::new("root") && source.kind()==io::ErrorKind::PermissionDenied)
    );
    let items = vec![Ok(OsString::from("a")), Ok(OsString::from("a"))];
    assert!(matches!(
        collect_names(
            items.into_iter(),
            None,
            Side::Old,
            Path::new("root"),
            &mut Budget::new(Limits::default())
        ),
        Err(DiffError::TreeChanged { .. })
    ));
    for name in ["", ".", "..", "a/b"] {
        let items = vec![Ok(OsString::from(name))];
        assert!(matches!(
            collect_names(
                items.into_iter(),
                None,
                Side::Old,
                Path::new("root"),
                &mut Budget::new(Limits::default())
            ),
            Err(DiffError::InvalidRelativePath)
        ));
    }
}

#[test]
fn wide_directory_stops_collection_at_the_entry_limit() {
    let seen = Cell::new(0);
    let items = (0..).map(|i| {
        seen.set(seen.get() + 1);
        Ok(OsString::from(format!("file{i}")))
    });
    let result = collect_names(
        items,
        None,
        Side::Old,
        Path::new("root"),
        &mut Budget::new(Limits {
            max_entries: 2,
            ..Limits::default()
        }),
    );
    assert!(matches!(
        result,
        Err(DiffError::LimitExceeded {
            resource: Resource::Entries,
            limit: 2
        })
    ));
    assert_eq!(seen.get(), 3);
}

#[test]
fn inventory_limits_include_both_trees_and_link_targets() {
    let tmp = tempdir().unwrap();
    symlink("abc", tmp.path().join("l")).unwrap();
    for limit in [3, 4, 5] {
        let result = scan(
            tmp.path(),
            Side::Old,
            &mut Budget::new(Limits {
                max_path_bytes: limit,
                ..Limits::default()
            }),
        );
        if limit < 4 {
            assert!(matches!(
                result,
                Err(DiffError::LimitExceeded {
                    resource: Resource::PathBytes,
                    ..
                })
            ));
        } else {
            result.unwrap();
        }
    }
    let mut budget = Budget::new(Limits {
        max_entries: 1,
        ..Limits::default()
    });
    scan(tmp.path(), Side::Old, &mut budget).unwrap();
    assert!(matches!(
        scan(tmp.path(), Side::New, &mut budget),
        Err(DiffError::LimitExceeded {
            resource: Resource::Entries,
            ..
        })
    ));
    fs::create_dir(tmp.path().join("d")).unwrap();
    fs::write(tmp.path().join("d/f"), b"").unwrap();
    assert!(matches!(
        scan(
            tmp.path(),
            Side::Old,
            &mut Budget::new(Limits {
                max_depth: 1,
                ..Limits::default()
            })
        ),
        Err(DiffError::LimitExceeded {
            resource: Resource::Depth,
            ..
        })
    ));
    scan(
        tmp.path(),
        Side::Old,
        &mut Budget::new(Limits {
            max_depth: 2,
            ..Limits::default()
        }),
    )
    .unwrap();
}

#[test]
fn revalidation_detects_root_entry_identity_and_link_changes() {
    let tmp = tempdir().unwrap();
    fs::write(tmp.path().join("a"), b"x").unwrap();
    symlink("a", tmp.path().join("l")).unwrap();
    let mut snapshot = inventory(tmp.path());
    snapshot.entries.get_mut(&rel(b"a")).unwrap().stamp.ino ^= 1;
    assert!(matches!(
        revalidate(&snapshot, Side::Old),
        Err(DiffError::TreeChanged { .. })
    ));
    let mut snapshot = inventory(tmp.path());
    snapshot.entries.get_mut(&rel(b"l")).unwrap().entry = Entry::Symlink {
        target: b"other".to_vec(),
    };
    assert!(matches!(
        revalidate(&snapshot, Side::Old),
        Err(DiffError::TreeChanged { .. })
    ));
    let snapshot = inventory(tmp.path());
    fs::set_permissions(
        tmp.path(),
        fs::Permissions::from_mode(snapshot.root_stamp.mode ^ 0o100),
    )
    .unwrap();
    let result = revalidate(&snapshot, Side::Old);
    fs::set_permissions(
        tmp.path(),
        fs::Permissions::from_mode(snapshot.root_stamp.mode & 0o7777),
    )
    .unwrap();
    assert!(matches!(result, Err(DiffError::TreeChanged { .. })));
}

#[test]
fn revalidation_refuses_disappearance_and_directory_replacement() {
    let tmp = tempdir().unwrap();
    fs::create_dir(tmp.path().join("d")).unwrap();
    fs::write(tmp.path().join("d/f"), b"a").unwrap();
    let snapshot = inventory(tmp.path());
    fs::remove_file(tmp.path().join("d/f")).unwrap();
    assert!(matches!(
        revalidate(&snapshot, Side::Old),
        Err(DiffError::TreeChanged { .. })
    ));
    let snapshot = inventory(tmp.path());
    fs::remove_dir(tmp.path().join("d")).unwrap();
    symlink("/etc", tmp.path().join("d")).unwrap();
    assert!(matches!(
        revalidate(&snapshot, Side::Old),
        Err(DiffError::TreeChanged { .. })
    ));
}

#[test]
fn root_errors_and_permission_errors_keep_the_source() {
    let tmp = tempdir().unwrap();
    assert!(
        matches!(scan(&tmp.path().join("missing"),Side::New,&mut Budget::new(Limits::default())),Err(DiffError::Io{source,..}) if source.kind()==io::ErrorKind::NotFound)
    );
    fs::write(tmp.path().join("file"), b"").unwrap();
    assert!(
        matches!(scan(&tmp.path().join("file"),Side::Old,&mut Budget::new(Limits::default())),Err(DiffError::Io{source,..}) if source.kind()==io::ErrorKind::NotADirectory)
    );
    let blocked = tmp.path().join("blocked");
    fs::create_dir(&blocked).unwrap();
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o0)).unwrap();
    let result = scan(tmp.path(), Side::New, &mut Budget::new(Limits::default()));
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        matches!(result,Err(DiffError::Io{side:Side::New,source,..}) if source.kind()==io::ErrorKind::PermissionDenied),
        "permission coverage requires an unprivileged test user"
    );
}

#[test]
fn stamp_validation_identifies_the_missing_or_replaced_path() {
    let tmp = tempdir().unwrap();
    let file = tmp.path().join("a");
    fs::write(&file, b"x").unwrap();
    let expected = stamp(&fs::symlink_metadata(&file).unwrap());
    fs::remove_file(&file).unwrap();
    assert!(
        matches!(verify_stamp(&file, &expected, Side::New), Err(DiffError::TreeChanged { side: Side::New, path }) if path == file)
    );
    let directory = tmp.path().join("d");
    fs::create_dir(&directory).unwrap();
    let expected = stamp(&fs::symlink_metadata(&directory).unwrap());
    fs::remove_dir(&directory).unwrap();
    symlink("/etc", &directory).unwrap();
    assert!(
        matches!(verify_stamp(&directory, &expected, Side::Old), Err(DiffError::TreeChanged { side: Side::Old, path }) if path == directory)
    );
}
