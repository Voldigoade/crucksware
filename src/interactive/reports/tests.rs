use std::{
    fs,
    io::{self, Write},
};

use tempfile::tempdir;

use super::publish_report;

#[test]
fn failed_render_does_not_leave_a_new_destination_or_temporary_file() {
    let directory = tempdir().expect("temporary directory is created");
    let destination = directory.path().join("report.html");

    let result = publish_report(&destination, false, |file| {
        file.write_all(b"incomplete report")?;
        Err(io::Error::other("synthetic rendering failure"))
    });

    assert_eq!(
        result
            .expect_err("failed rendering is returned")
            .to_string(),
        "synthetic rendering failure"
    );
    assert!(!destination.exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn new_report_publication_never_replaces_a_destination_created_during_rendering() {
    let directory = tempdir().expect("temporary directory is created");
    let destination = directory.path().join("report.html");

    let result = publish_report(&destination, false, |file| {
        file.write_all(b"complete report")?;
        fs::write(&destination, b"concurrent destination")?;
        Ok(())
    });

    assert_eq!(
        result
            .expect_err("no-clobber publication rejects an existing destination")
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(fs::read(&destination).unwrap(), b"concurrent destination");
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn failed_render_preserves_an_existing_report() {
    let directory = tempdir().expect("temporary directory is created");
    let destination = directory.path().join("report.html");
    fs::write(&destination, b"previous report").expect("existing report is written");

    let result = publish_report(&destination, true, |file| {
        file.write_all(b"incomplete replacement")?;
        Err(io::Error::other("synthetic rendering failure"))
    });

    assert_eq!(
        result
            .expect_err("failed rendering is returned")
            .to_string(),
        "synthetic rendering failure"
    );
    assert_eq!(fs::read(&destination).unwrap(), b"previous report");
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}
