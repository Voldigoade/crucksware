use std::{fs, process::Command};

use crucksware::{
    compare_semantic_tree_with_progress,
    limits::Limits,
    progress::{ProgressEvent, ProgressPhase},
};
use tempfile::TempDir;

mod common;

fn roots() -> (TempDir, std::path::PathBuf, std::path::PathBuf) {
    let temporary = tempfile::tempdir().unwrap();
    let old = temporary.path().join("old");
    let new = temporary.path().join("new");
    fs::create_dir(&old).unwrap();
    fs::create_dir(&new).unwrap();
    (temporary, old, new)
}

fn run_source_compare(old: &std::path::Path, new: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_crucksware"))
        .args(["compare", "--source-aware", "--format=json"])
        .arg(old)
        .arg(new)
        .output()
        .unwrap()
}

#[test]
fn source_mode_reports_bounded_line_changes_for_unrecognized_text_files() {
    let (_temporary, old, new) = roots();
    fs::write(old.join("notes.conf"), b"listen=false\nkeep").unwrap();
    fs::write(new.join("notes.conf"), b"listen=true\nadded\nkeep").unwrap();

    let output = run_source_compare(&old, &new);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 4);
    assert_eq!(report["analysis_type"], "semantic_tree_comparison");
    assert_eq!(report["source_changes"][0]["path"], "notes.conf");
    assert_eq!(report["source_changes"][0]["lines_added"], 2);
    assert_eq!(report["source_changes"][0]["lines_removed"], 1);
    assert_eq!(report["source_changes"][0]["hunk_count"], 1);
    assert_eq!(
        report["source_changes"][0]["language"],
        serde_json::Value::Null
    );
}

#[cfg(target_os = "linux")]
#[test]
fn semantic_tree_progress_reports_exact_candidate_totals() {
    let (_temporary, old, new) = roots();
    fs::write(old.join("main.rs"), "fn before() {}\n").unwrap();
    fs::write(new.join("main.rs"), "fn after() {}\n").unwrap();
    fs::create_dir(new.join("bin")).unwrap();
    fs::write(new.join("bin/service"), common::minimal_elf64(0x401000)).unwrap();
    let mut events = Vec::new();

    let result = compare_semantic_tree_with_progress(
        &old,
        &new,
        Limits::default(),
        crucksware::source::DEFAULT_MAX_SOURCE_FILE_BYTES,
        |event| events.push(event),
    );

    assert!(result.is_ok());
    assert!(events.contains(&ProgressEvent::PhaseStarted {
        phase: ProgressPhase::SourceAnalysis,
        total: None,
    }));
    assert!(events.contains(&ProgressEvent::PhaseTotalKnown {
        phase: ProgressPhase::SourceAnalysis,
        total: 2,
    }));
    let source_phase_started = events
        .iter()
        .position(|event| {
            *event
                == ProgressEvent::PhaseStarted {
                    phase: ProgressPhase::SourceAnalysis,
                    total: None,
                }
        })
        .unwrap();
    let source_total_known = events
        .iter()
        .position(|event| {
            *event
                == ProgressEvent::PhaseTotalKnown {
                    phase: ProgressPhase::SourceAnalysis,
                    total: 2,
                }
        })
        .unwrap();
    assert!(source_phase_started < source_total_known);
    assert!(events.contains(&ProgressEvent::PhaseProgress {
        phase: ProgressPhase::SourceAnalysis,
        completed: 2,
        total: 2,
    }));
    assert!(events.contains(&ProgressEvent::PhaseStarted {
        phase: ProgressPhase::BinaryAnalysis,
        total: None,
    }));
    assert!(events.contains(&ProgressEvent::PhaseTotalKnown {
        phase: ProgressPhase::BinaryAnalysis,
        total: 1,
    }));
    let binary_phase_started = events
        .iter()
        .position(|event| {
            *event
                == ProgressEvent::PhaseStarted {
                    phase: ProgressPhase::BinaryAnalysis,
                    total: None,
                }
        })
        .unwrap();
    let binary_total_known = events
        .iter()
        .position(|event| {
            *event
                == ProgressEvent::PhaseTotalKnown {
                    phase: ProgressPhase::BinaryAnalysis,
                    total: 1,
                }
        })
        .unwrap();
    assert!(binary_phase_started < binary_total_known);
    assert!(events.contains(&ProgressEvent::PhaseProgress {
        phase: ProgressPhase::BinaryAnalysis,
        completed: 1,
        total: 1,
    }));
    assert!(events.iter().any(|event| matches!(
        event,
        ProgressEvent::BytesRead { total_bytes_read } if *total_bytes_read > 0
    )));
}

#[test]
fn source_mode_reports_rust_signature_changes() {
    let (_temporary, old, new) = roots();
    fs::create_dir_all(old.join("src")).unwrap();
    fs::create_dir_all(new.join("src")).unwrap();
    fs::write(old.join("src/auth.rs"), "fn login(user: &str) {}\n").unwrap();
    fs::write(
        new.join("src/auth.rs"),
        "fn login(user: &str, otp: u32) {}\n",
    )
    .unwrap();

    let output = run_source_compare(&old, &new);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["source_changes"][0]["language"], "rust");
    assert!(
        report["source_changes"][0]["structural_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| {
                change["action"] == "signature_changed" && change["kind"] == "function"
            })
    );
}

#[test]
fn source_mode_does_not_report_rust_method_body_changes_as_signature_changes() {
    let (_temporary, old, new) = roots();
    fs::write(
        old.join("auth.rs"),
        "struct Auth;\nimpl Auth { fn login(&self) -> bool { true } }\n",
    )
    .unwrap();
    fs::write(
        new.join("auth.rs"),
        "struct Auth;\nimpl Auth { fn login(&self) -> bool { false } }\n",
    )
    .unwrap();

    let output = run_source_compare(&old, &new);

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let changes = report["source_changes"][0]["structural_changes"]
        .as_array()
        .unwrap();
    assert!(
        !changes
            .iter()
            .any(|change| change["action"] == "signature_changed"),
        "method body changes must remain in the generic line diff"
    );
}

#[test]
fn source_mode_reports_rust_method_signature_changes() {
    let (_temporary, old, new) = roots();
    fs::write(
        old.join("auth.rs"),
        "struct Auth;\nimpl Auth { fn login(&self) -> bool { true } }\n",
    )
    .unwrap();
    fs::write(
        new.join("auth.rs"),
        "struct Auth;\nimpl Auth { fn login(&self, otp: bool) -> bool { otp } }\n",
    )
    .unwrap();

    let output = run_source_compare(&old, &new);

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["source_changes"][0]["structural_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| {
                change["action"] == "signature_changed"
                    && change["kind"] == "method"
                    && change["name"] == "Auth::login"
            })
    );
}

#[test]
fn source_mode_preserves_rust_module_scope_and_function_kind() {
    let (_temporary, old, new) = roots();
    fs::write(
        old.join("lib.rs"),
        "mod auth { fn check() {} }\nmod net { fn check() {} }\n",
    )
    .unwrap();
    fs::write(new.join("lib.rs"), "mod auth { fn check() {} }\n").unwrap();

    let output = run_source_compare(&old, &new);

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["source_changes"][0]["structural_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| {
                change["action"] == "removed"
                    && change["kind"] == "function"
                    && change["name"] == "net::check"
            })
    );
}

#[test]
fn source_mode_preserves_cpp_namespace_scope() {
    let (_temporary, old, new) = roots();
    fs::write(
        old.join("api.cpp"),
        "namespace left { void ready() {} }\nnamespace right { void ready() {} }\n",
    )
    .unwrap();
    fs::write(new.join("api.cpp"), "namespace left { void ready() {} }\n").unwrap();

    let output = run_source_compare(&old, &new);

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["source_changes"][0]["structural_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| {
                change["action"] == "removed"
                    && change["kind"] == "function"
                    && change["name"] == "right::ready"
            })
    );
}

#[test]
fn source_mode_extracts_definitions_from_the_initial_language_set() {
    let cases = [
        (
            "src/auth.c",
            "int login(int user) { return user; }\n",
            "int login(int user, int otp) { return user + otp; }\n",
            "c",
        ),
        (
            "src/auth.cpp",
            "class Auth { public: bool login(int user) { return user; } };\n",
            "class Auth { public: bool login(int user, int otp) { return user && otp; } };\n",
            "cpp",
        ),
        (
            "tools/auth.py",
            "def login(user):\n    return user\n",
            "def login(user, otp):\n    return user and otp\n",
            "python",
        ),
    ];

    for (path, old_source, new_source, language) in cases {
        let (_temporary, old, new) = roots();
        let old_path = old.join(path);
        let new_path = new.join(path);
        fs::create_dir_all(old_path.parent().unwrap()).unwrap();
        fs::create_dir_all(new_path.parent().unwrap()).unwrap();
        fs::write(old_path, old_source).unwrap();
        fs::write(new_path, new_source).unwrap();

        let output = run_source_compare(&old, &new);

        assert_eq!(output.status.code(), Some(1), "{path}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let source_change = &report["source_changes"][0];
        assert_eq!(source_change["language"], language, "{path}");
        assert_eq!(source_change["structural_status"], "complete", "{path}");
        assert!(
            source_change["structural_changes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|change| change["action"] == "signature_changed"),
            "{path}"
        );
    }
}

#[test]
fn source_mode_classifies_structural_definitions_and_imports() {
    let (_temporary, old, new) = roots();
    fs::create_dir_all(old.join("src")).unwrap();
    fs::create_dir_all(new.join("src")).unwrap();
    fs::write(old.join("src/model.rs"), "").unwrap();
    fs::write(
        new.join("src/model.rs"),
        "struct User {}\nunion Raw { count: u64 }\nenum State { Ready }\ntype UserId = u64;\ntrait Auth {}\nuse std::io;\n",
    )
    .unwrap();
    fs::write(old.join("model.c"), "").unwrap();
    fs::write(
        new.join("model.c"),
        "struct User { int id; };\nunion Value { int i; };\nenum State { READY };\n#include <stdio.h>\n",
    )
    .unwrap();

    let output = run_source_compare(&old, &new);

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let rust_changes = report["source_changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["path"] == "src/model.rs")
        .unwrap()["structural_changes"]
        .as_array()
        .unwrap();
    for (name, kind) in [
        ("User", "struct"),
        ("Raw", "union"),
        ("State", "enum"),
        ("UserId", "type"),
        ("Auth", "interface"),
        ("use std :: io ;", "import"),
    ] {
        assert!(
            rust_changes
                .iter()
                .any(|change| change["name"] == name && change["kind"] == kind),
            "missing Rust {kind} {name}: {rust_changes:?}"
        );
    }
    let c_changes = report["source_changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["path"] == "model.c")
        .unwrap()["structural_changes"]
        .as_array()
        .unwrap();
    for (name, kind) in [("User", "struct"), ("Value", "union"), ("State", "enum")] {
        assert!(
            c_changes
                .iter()
                .any(|change| change["name"] == name && change["kind"] == kind),
            "missing C {kind} {name}: {c_changes:?}"
        );
    }
}

#[test]
fn source_mode_reports_added_and_removed_text_files() {
    let (_temporary, old, new) = roots();
    fs::write(old.join("removed.py"), "def old_function():\n    pass\n").unwrap();
    fs::write(
        new.join("added.py"),
        "def new_function(value):\n    return value\n",
    )
    .unwrap();

    let output = run_source_compare(&old, &new);

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let changes = report["source_changes"].as_array().unwrap();
    assert_eq!(changes.len(), 2);
    assert_eq!(changes[0]["path"], "added.py");
    assert_eq!(changes[0]["lines_added"], 2);
    assert_eq!(changes[0]["lines_removed"], 0);
    assert!(
        changes[0]["structural_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["action"] == "added" && change["name"] == "new_function")
    );
    assert_eq!(changes[1]["path"], "removed.py");
    assert_eq!(changes[1]["lines_added"], 0);
    assert_eq!(changes[1]["lines_removed"], 2);
    assert!(
        changes[1]["structural_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["action"] == "removed" && change["name"] == "old_function")
    );
}

#[test]
fn source_mode_reports_text_to_binary_transitions_without_parsing_binary_data() {
    let (_temporary, old, new) = roots();
    fs::write(old.join("module.rs"), "fn stable() {}\n").unwrap();
    fs::write(new.join("module.rs"), b"\0not Rust source").unwrap();

    let output = run_source_compare(&old, &new);

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let change = &report["source_changes"][0];
    assert_eq!(change["analysis_status"], "content_kind_changed");
    assert_eq!(change["structural_status"], "not_applicable");
    assert!(change["lines_added"].is_null());
    assert!(change["structural_changes"].as_array().unwrap().is_empty());
}

#[test]
fn source_mode_does_not_treat_a_symlink_as_removed_source() {
    use std::os::unix::fs::symlink;

    let (_temporary, old, new) = roots();
    fs::write(old.join("config.rs"), "fn enabled() {}\n").unwrap();
    symlink("target.rs", new.join("config.rs")).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_crucksware"))
        .args([
            "compare",
            "--source-aware",
            "--format=json",
            "--max-source-file-bytes=1",
        ])
        .arg(&old)
        .arg(&new)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["source_changes"].as_array().unwrap().is_empty());
}

#[test]
fn source_mode_combines_source_and_elf_analysis_for_a_mixed_tree() {
    let (_temporary, old, new) = roots();
    fs::create_dir_all(old.join("src")).unwrap();
    fs::create_dir_all(new.join("src")).unwrap();
    fs::create_dir_all(old.join("usr/bin")).unwrap();
    fs::create_dir_all(new.join("usr/bin")).unwrap();
    fs::write(old.join("src/auth.rs"), "fn login(user: &str) {}\n").unwrap();
    fs::write(
        new.join("src/auth.rs"),
        "fn login(user: &str, otp: u32) {}\n",
    )
    .unwrap();
    fs::write(old.join("usr/bin/service"), common::minimal_elf64(0x401000)).unwrap();
    fs::write(new.join("usr/bin/service"), common::minimal_elf64(0x402000)).unwrap();

    let output = run_source_compare(&old, &new);
    let repeated = run_source_compare(&old, &new);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(repeated.status.code(), Some(1));
    assert_eq!(output.stdout, repeated.stdout);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 4);
    assert_eq!(report["filesystem"]["schema_version"], 1);
    assert_eq!(report["source_changes"].as_array().unwrap().len(), 1);
    let binary = &report["binary_changes"][0];
    assert_eq!(binary["path"], "usr/bin/service");
    assert_eq!(binary["old_kind"], "elf");
    assert_eq!(binary["new_kind"], "elf");
    assert_eq!(binary["semantic_status"], "compared");
    assert_eq!(binary["byte_level_changed"], true);
    assert!(
        binary["semantic_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["field"] == "entry_point")
    );
}

#[test]
fn source_mode_adds_pe_semantics_to_a_mixed_tree() {
    let (_temporary, old, new) = roots();
    fs::create_dir_all(old.join("bin")).unwrap();
    fs::create_dir_all(new.join("bin")).unwrap();
    fs::write(old.join("bin/tool"), common::minimal_pe64(0x1000)).unwrap();
    fs::write(new.join("bin/tool"), common::minimal_pe64(0x2000)).unwrap();
    fs::create_dir_all(old.join("lib")).unwrap();
    fs::create_dir_all(new.join("lib")).unwrap();
    let unchanged_elf = common::minimal_elf64(0x401000);
    fs::write(old.join("lib/stable"), &unchanged_elf).unwrap();
    fs::write(new.join("lib/stable"), unchanged_elf).unwrap();

    let output = run_source_compare(&old, &new);

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let binary = &report["binary_changes"][0];
    assert_eq!(report["binary_changes"].as_array().unwrap().len(), 1);
    assert_eq!(binary["old_kind"], "pe");
    assert_eq!(binary["new_kind"], "pe");
    assert_eq!(binary["semantic_status"], "compared");
    assert!(
        binary["semantic_changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["field"] == "entry_point_rva")
    );
}

#[test]
fn source_mode_reports_unknown_binary_changes_without_invented_semantics() {
    let (_temporary, old, new) = roots();
    fs::create_dir_all(old.join("assets")).unwrap();
    fs::write(old.join("assets/blob.dat"), [0, 0xff, 1, 2]).unwrap();
    fs::create_dir_all(new.join("assets")).unwrap();
    fs::write(new.join("assets/blob.dat"), [0, 0xfe, 1, 2]).unwrap();

    let output = run_source_compare(&old, &new);

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let binary = &report["binary_changes"][0];
    assert_eq!(binary["old_kind"], "unknown_binary");
    assert_eq!(binary["new_kind"], "unknown_binary");
    assert_eq!(binary["semantic_status"], "unsupported");
    assert_eq!(binary["byte_level_changed"], true);
    assert!(binary["semantic_changes"].as_array().unwrap().is_empty());
}

#[test]
fn source_mode_reports_added_binary_as_one_sided_inspection() {
    let (_temporary, old, new) = roots();
    fs::create_dir_all(old.join("bin")).unwrap();
    fs::create_dir_all(new.join("bin")).unwrap();
    fs::write(new.join("bin/program"), common::minimal_elf64(0x401000)).unwrap();

    let output = run_source_compare(&old, &new);

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let binary = &report["binary_changes"][0];
    assert_eq!(binary["old_kind"], serde_json::Value::Null);
    assert_eq!(binary["new_kind"], "elf");
    assert_eq!(binary["old_size_bytes"], serde_json::Value::Null);
    assert_eq!(binary["semantic_status"], "single_input");
    assert_eq!(binary["byte_level_changed"], serde_json::Value::Null);
    assert_eq!(binary["semantic_changes"].as_array().unwrap().len(), 0);
}

#[test]
fn source_mode_shares_the_read_budget_with_binary_inspection() {
    let (_temporary, old, new) = roots();
    fs::create_dir_all(old.join("bin")).unwrap();
    fs::create_dir_all(new.join("bin")).unwrap();
    fs::write(new.join("bin/program"), common::minimal_elf64(0x401000)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_crucksware"))
        .args([
            "compare",
            "--source-aware",
            "--format=json",
            "--max-bytes-read=64",
        ])
        .arg(&old)
        .arg(&new)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("bytes read limit exceeded"));
}

#[test]
fn source_mode_requires_directories_and_produces_no_report_for_file_inputs() {
    let (_temporary, old, new) = roots();
    let old_file = old.join("file");
    let new_file = new.join("file");
    fs::write(&old_file, b"old").unwrap();
    fs::write(&new_file, b"new").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_crucksware"))
        .args(["compare", "--source-aware"])
        .arg(old_file)
        .arg(new_file)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires two directories"));
}

#[test]
fn source_mode_keeps_generic_diff_when_a_supported_file_has_syntax_errors() {
    let (_temporary, old, new) = roots();
    fs::write(old.join("auth.rs"), "fn login(user: &str) {}\n").unwrap();
    fs::write(new.join("auth.rs"), "fn login(user: &str {\n").unwrap();

    let output = run_source_compare(&old, &new);

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["source_changes"][0]["structural_status"],
        "syntax_errors"
    );
    assert!(
        report["source_changes"][0]["structural_changes"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        report["source_changes"][0]["lines_added"]
            .as_u64()
            .is_some()
    );
}

#[test]
#[cfg(target_os = "linux")]
fn source_mode_encodes_non_utf8_paths_and_ignores_unchanged_files() {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

    let (_temporary, old, new) = roots();
    let unchanged = std::path::Path::new(OsStr::from_bytes(b"src/bad-\xff.rs"));
    let changed = std::path::Path::new(OsStr::from_bytes(b"src/delta-\xfe.txt"));
    for root in [&old, &new] {
        let path = root.join(unchanged);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "fn stable() {}\n").unwrap();
    }
    fs::write(old.join(changed), b"before\n").unwrap();
    fs::write(new.join(changed), b"after\n").unwrap();
    fs::write(old.join("notes.txt"), b"before\n").unwrap();
    fs::write(new.join("notes.txt"), b"after\n").unwrap();

    let output = run_source_compare(&old, &new);

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["source_changes"].as_array().unwrap().len(), 2);
    assert_eq!(report["source_changes"][0]["path"], "notes.txt");
    assert_eq!(report["source_changes"][1]["path"], "src/delta-%FE.txt");
}

#[test]
fn source_mode_rejects_a_text_file_above_its_configured_limit_without_partial_output() {
    let (_temporary, old, new) = roots();
    fs::write(old.join("notes.txt"), b"old\n").unwrap();
    fs::write(new.join("notes.txt"), b"longer\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_crucksware"))
        .args(["compare", "--source-aware", "--max-source-file-bytes=4"])
        .arg(&old)
        .arg(&new)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("source file byte limit"));
}

#[test]
fn source_mode_bounds_structural_records_across_the_complete_tree() {
    let (_temporary, old, new) = roots();
    let declarations = (0..25_001)
        .map(|index| format!("fn item_{index}() {{}}\n"))
        .collect::<String>();
    fs::write(new.join("first.rs"), &declarations).unwrap();
    fs::write(new.join("second.rs"), declarations).unwrap();

    let output = run_source_compare(&old, &new);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("source record limit exceeded"));
}

#[test]
fn source_mode_bounds_copied_facts_across_files_with_long_qualified_names() {
    let (_temporary, old, new) = roots();
    let scope = "a".repeat(2_048);
    let mut declarations = String::new();
    for index in 0..4_100 {
        declarations.push_str(&format!("fn item_{index}() {{}}\n"));
    }
    let source = format!("mod {scope} {{\n{declarations}}}\n");
    fs::write(new.join("lib_a.rs"), &source).unwrap();
    fs::write(new.join("lib_b.rs"), source).unwrap();

    let output = run_source_compare(&old, &new);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("source fact byte limit exceeded"));
}

#[test]
fn source_mode_preserves_repeated_import_occurrences() {
    let (_temporary, old, new) = roots();
    fs::write(old.join("main.c"), "#include <stdio.h>\n").unwrap();
    fs::write(
        new.join("main.c"),
        "#include <stdio.h>\n#include <stdio.h>\n",
    )
    .unwrap();

    let output = run_source_compare(&old, &new);

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let structural_changes = report["source_changes"][0]["structural_changes"]
        .as_array()
        .unwrap();
    assert_eq!(structural_changes.len(), 1);
    assert_eq!(structural_changes[0]["action"], "added");
    assert_eq!(structural_changes[0]["kind"], "import");
}
