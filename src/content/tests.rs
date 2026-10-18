use super::*;
use crate::{
    error::{DiffError, Resource, Side},
    limits::{Budget, Limits},
    model::Entry,
    path::RelPath,
    scan::{scan, stamp},
};
use std::{
    fs,
    io::{self, Cursor, Read},
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
};
use tempfile::tempdir;

struct Chunks {
    inner: Cursor<Vec<u8>>,
    max: usize,
    interrupted: bool,
}
impl Read for Chunks {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.interrupted {
            self.interrupted = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        let count = buf.len().min(self.max);
        self.inner.read(&mut buf[..count])
    }
}
fn paths() -> (&'static Path, &'static Path) {
    (Path::new("old/a"), Path::new("new/a"))
}

#[test]
fn exact_stream_equality_handles_unequal_short_reads_and_interruption() {
    for (old_max, new_max) in [(1, 3), (3, 1)] {
        let data = b"a complete stream".to_vec();
        let mut old = Chunks {
            inner: Cursor::new(data.clone()),
            max: old_max,
            interrupted: true,
        };
        let mut new = Chunks {
            inner: Cursor::new(data),
            max: new_max,
            interrupted: false,
        };
        let mut budget = Budget::new(Limits {
            max_bytes_read: 34,
            ..Limits::default()
        });
        assert!(equal_readers(&mut old, &mut new, 17, paths(), &mut budget).unwrap());
        assert_eq!(budget.remaining_read_bytes(), 0);
    }
}

#[test]
fn short_reads_detect_differences_after_matching_prefixes() {
    for position in 0..3 {
        let mut data = b"abcd".to_vec();
        data[position] = b'x';
        let mut old = Chunks {
            inner: Cursor::new(b"abcd".to_vec()),
            max: 3,
            interrupted: false,
        };
        let mut new = Chunks {
            inner: Cursor::new(data),
            max: 1,
            interrupted: false,
        };
        assert!(
            !equal_readers(
                &mut old,
                &mut new,
                4,
                paths(),
                &mut Budget::new(Limits::default())
            )
            .unwrap()
        );
    }
}

#[test]
fn differences_are_found_at_first_buffer_boundary_and_last_byte() {
    for pos in [0, 65_535, 65_536, 131_072] {
        let mut old = Cursor::new(vec![b'a'; 131_073]);
        let mut data = vec![b'a'; 131_073];
        data[pos] = b'b';
        assert!(
            !equal_readers(
                &mut old,
                &mut Cursor::new(data),
                131_073,
                paths(),
                &mut Budget::new(Limits::default())
            )
            .unwrap()
        );
    }
}

struct OneChunkThenError {
    byte: u8,
    called: bool,
}
impl Read for OneChunkThenError {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.called {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.called = true;
        buf.fill(self.byte);
        Ok(buf.len())
    }
}

#[test]
fn empty_streams_and_a_proven_difference_do_not_read_further() {
    let mut old = OneChunkThenError {
        byte: b'a',
        called: true,
    };
    let mut new = OneChunkThenError {
        byte: b'b',
        called: true,
    };
    assert!(
        equal_readers(
            &mut old,
            &mut new,
            0,
            paths(),
            &mut Budget::new(Limits::default())
        )
        .unwrap()
    );
    old.called = false;
    new.called = false;
    assert!(
        !equal_readers(
            &mut old,
            &mut new,
            65_537,
            paths(),
            &mut Budget::new(Limits::default())
        )
        .unwrap()
    );
}

#[test]
fn unexpected_eof_and_read_errors_keep_side_and_path() {
    let result = equal_readers(
        &mut Cursor::new(b"aaaa"),
        &mut Cursor::new(b"aaa"),
        4,
        paths(),
        &mut Budget::new(Limits::default()),
    );
    assert!(
        matches!(result,Err(DiffError::TreeChanged{side:Side::New,path}) if path==Path::new("new/a"))
    );
    let mut old = OneChunkThenError {
        byte: 0,
        called: true,
    };
    let result = equal_readers(
        &mut old,
        &mut Cursor::new(b"a"),
        1,
        paths(),
        &mut Budget::new(Limits::default()),
    );
    assert!(
        matches!(result,Err(DiffError::Io{side:Side::Old,path,source,..}) if path==Path::new("old/a") && source.kind()==io::ErrorKind::PermissionDenied)
    );
}

#[test]
fn read_budget_is_shared_exact_and_never_overdrawn() {
    for limit in [7, 8, 9] {
        let mut old = Chunks {
            inner: Cursor::new(b"abcd".to_vec()),
            max: 1,
            interrupted: true,
        };
        let mut new = Chunks {
            inner: Cursor::new(b"abcd".to_vec()),
            max: 3,
            interrupted: false,
        };
        let mut budget = Budget::new(Limits {
            max_bytes_read: limit,
            ..Limits::default()
        });
        let result = equal_readers(&mut old, &mut new, 4, paths(), &mut budget);
        if limit < 8 {
            assert!(matches!(
                result,
                Err(DiffError::LimitExceeded {
                    resource: Resource::BytesRead,
                    limit: 7
                })
            ));
        } else {
            assert!(result.unwrap());
        }
        assert_eq!(
            limit - budget.remaining_read_bytes(),
            old.inner.position() + new.inner.position()
        );
    }
    let mut budget = Budget::new(Limits {
        max_bytes_read: 2,
        ..Limits::default()
    });
    assert!(
        !equal_readers(
            &mut Cursor::new(b"axx"),
            &mut Cursor::new(b"bxx"),
            3,
            paths(),
            &mut budget
        )
        .unwrap()
    );
    assert_eq!(budget.remaining_read_bytes(), 0);
}

struct BoundedRepeat {
    remaining: u64,
}
impl Read for BoundedRepeat {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        assert!(buf.len() <= 65_536, "file-sized allocation/request");
        let count = self.remaining.min(buf.len() as u64) as usize;
        buf[..count].fill(7);
        self.remaining -= count as u64;
        Ok(count)
    }
}

#[test]
fn multi_buffer_comparison_uses_bounded_requests() {
    let size = 2_000_001;
    assert!(
        equal_readers(
            &mut BoundedRepeat { remaining: size },
            &mut BoundedRepeat { remaining: size },
            size,
            paths(),
            &mut Budget::new(Limits {
                max_bytes_read: 2 * size,
                ..Limits::default()
            })
        )
        .unwrap()
    );
}

#[test]
fn file_equality_ignores_matching_mtime_and_preserves_inputs() {
    let old = tempdir().unwrap();
    let new = tempdir().unwrap();
    fs::write(old.path().join("a"), b"old").unwrap();
    fs::write(new.path().join("a"), b"new").unwrap();
    let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(100);
    fs::File::open(old.path().join("a"))
        .unwrap()
        .set_modified(time)
        .unwrap();
    fs::File::open(new.path().join("a"))
        .unwrap()
        .set_modified(time)
        .unwrap();
    let old_snapshot = scan(old.path(), Side::Old, &mut Budget::new(Limits::default())).unwrap();
    let new_snapshot = scan(new.path(), Side::New, &mut Budget::new(Limits::default())).unwrap();
    let path = RelPath::new(b"a".to_vec()).unwrap();
    assert!(
        !equal_files(
            old.path(),
            new.path(),
            &path,
            &old_snapshot.entries[&path],
            &new_snapshot.entries[&path],
            &mut Budget::new(Limits::default())
        )
        .unwrap()
    );
    assert_eq!(fs::read(old.path().join("a")).unwrap(), b"old");
    assert_eq!(fs::read(new.path().join("a")).unwrap(), b"new");
    let mut expected = old_snapshot.entries[&path].clone();
    expected.stamp.ino ^= 1;
    assert!(matches!(
        equal_files(
            old.path(),
            new.path(),
            &path,
            &expected,
            &new_snapshot.entries[&path],
            &mut Budget::new(Limits::default())
        ),
        Err(DiffError::TreeChanged {
            side: Side::Old,
            ..
        })
    ));
}

#[test]
fn size_mismatch_and_empty_files_need_no_content_access() {
    for (left, right, want) in [(b"".as_slice(), b"".as_slice(), true), (b"a", b"bb", false)] {
        let old = tempdir().unwrap();
        let new = tempdir().unwrap();
        for (root, data) in [(old.path(), left), (new.path(), right)] {
            fs::write(root.join("a"), data).unwrap();
            fs::set_permissions(root.join("a"), fs::Permissions::from_mode(0o0)).unwrap();
        }
        let a = scan(old.path(), Side::Old, &mut Budget::new(Limits::default())).unwrap();
        let b = scan(new.path(), Side::New, &mut Budget::new(Limits::default())).unwrap();
        let p = RelPath::new(b"a".to_vec()).unwrap();
        let mut budget = Budget::new(Limits {
            max_bytes_read: 1,
            ..Limits::default()
        });
        assert_eq!(
            equal_files(
                old.path(),
                new.path(),
                &p,
                &a.entries[&p],
                &b.entries[&p],
                &mut budget
            )
            .unwrap(),
            want
        );
        assert_eq!(budget.remaining_read_bytes(), 1);
    }
}

#[test]
fn non_files_are_rejected_before_opening_and_handles_are_revalidated() {
    let old = tempdir().unwrap();
    let new = tempdir().unwrap();
    symlink("missing", old.path().join("a")).unwrap();
    fs::write(new.path().join("a"), b"a").unwrap();
    let a = scan(old.path(), Side::Old, &mut Budget::new(Limits::default())).unwrap();
    let b = scan(new.path(), Side::New, &mut Budget::new(Limits::default())).unwrap();
    let p = RelPath::new(b"a".to_vec()).unwrap();
    assert!(matches!(
        equal_files(
            old.path(),
            new.path(),
            &p,
            &a.entries[&p],
            &b.entries[&p],
            &mut Budget::new(Limits::default())
        ),
        Err(DiffError::UnsupportedType {
            side: Side::Old,
            ..
        })
    ));
    let path = new.path().join("a");
    let file = fs::File::open(&path).unwrap();
    let expected = stamp(&file.metadata().unwrap());
    fs::write(&path, b"longer").unwrap();
    assert!(matches!(
        verify_handle(&file, &expected, Side::New, &path),
        Err(DiffError::TreeChanged {
            side: Side::New,
            ..
        })
    ));
    assert!(matches!(b.entries[&p].entry, Entry::File { size: 1, .. }));
}

#[test]
fn required_file_access_errors_preserve_old_and_new_context() {
    for side in [Side::Old, Side::New] {
        let old = tempdir().unwrap();
        let new = tempdir().unwrap();
        for root in [old.path(), new.path()] {
            fs::write(root.join("a"), b"x").unwrap();
        }
        let blocked = match side {
            Side::Old => old.path(),
            Side::New => new.path(),
        }
        .join("a");
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o0)).unwrap();
        let a = scan(old.path(), Side::Old, &mut Budget::new(Limits::default())).unwrap();
        let b = scan(new.path(), Side::New, &mut Budget::new(Limits::default())).unwrap();
        let path = RelPath::new(b"a".to_vec()).unwrap();
        let result = equal_files(
            old.path(),
            new.path(),
            &path,
            &a.entries[&path],
            &b.entries[&path],
            &mut Budget::new(Limits::default()),
        );
        assert!(
            matches!(result, Err(DiffError::Io { side: actual, path, source, .. }) if actual == side && path == blocked && source.kind() == io::ErrorKind::PermissionDenied),
            "permission coverage requires an unprivileged user"
        );
    }
}

struct PrefixThenError {
    delivered: bool,
}
impl Read for PrefixThenError {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.delivered {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.delivered = true;
        buf[0] = b'b';
        Ok(1)
    }
}

#[test]
fn a_short_read_difference_on_old_does_not_read_a_later_error() {
    let mut old = PrefixThenError { delivered: false };
    assert!(
        !equal_readers(
            &mut old,
            &mut Cursor::new(b"aaaa"),
            4,
            paths(),
            &mut Budget::new(Limits::default())
        )
        .unwrap()
    );
}

#[test]
fn a_short_read_difference_on_new_does_not_read_a_later_error() {
    let mut new = PrefixThenError { delivered: false };
    assert!(
        !equal_readers(
            &mut Cursor::new(b"aaaa"),
            &mut new,
            4,
            paths(),
            &mut Budget::new(Limits::default())
        )
        .unwrap()
    );
}
