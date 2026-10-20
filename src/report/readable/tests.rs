use crate::{
    model::Diff,
    path::RelPath,
    readable::select_semantic_tree,
    semantic_tree::SemanticTreeDiff,
    source::{
        SourceAnalysisStatus, SourceFileChange, SourceLanguage, StructuralAction, StructuralChange,
        StructuralKind, StructuralStatus,
    },
};

fn packet(name: &str, path: &[u8]) -> crate::readable::EvidencePacket {
    select_semantic_tree(&SemanticTreeDiff {
        filesystem: Diff::default(),
        source_changes: vec![SourceFileChange {
            path: RelPath::new(path.to_vec()).unwrap(),
            analysis_status: SourceAnalysisStatus::Compared,
            language: Some(SourceLanguage::Rust),
            lines_added: Some(4),
            lines_removed: Some(2),
            hunk_count: Some(1),
            structural_status: StructuralStatus::Complete,
            structural_changes: vec![
                StructuralChange {
                    action: StructuralAction::Removed,
                    kind: StructuralKind::Function,
                    name: "legacy_auth".to_owned(),
                    before_signature: Some("legacy_auth(token)".to_owned()),
                    after_signature: None,
                },
                StructuralChange {
                    action: StructuralAction::Added,
                    kind: StructuralKind::Function,
                    name: name.to_owned(),
                    before_signature: None,
                    after_signature: Some(format!("{name}(token)")),
                },
            ],
        }],
        binary_changes: Vec::new(),
    })
    .unwrap()
}

#[test]
fn text_summary_is_compact_and_deterministic() {
    let packet = packet("validate_token", b"src/auth.rs");
    let mut first = Vec::new();
    let mut second = Vec::new();

    super::write_text(&packet, &mut first).unwrap();
    super::write_text(&packet, &mut second).unwrap();

    assert_eq!(first, second);
    assert_eq!(
        String::from_utf8(first).unwrap(),
        "Readable summary\nSource analysis: 1 changed file, 2 structural changes.\nNotable changes:\n- `src/auth.rs`\n  - E0001: function \"validate_token\" added.\n  - E0002: function \"legacy_auth\" removed.\n  - E0003: text changed (+4 lines, -2 lines across 1 hunk).\n"
    );
}

#[test]
fn markdown_summary_escapes_untrusted_identifiers_and_uses_encoded_paths() {
    let packet = packet("check|token", b"src/\xffauth.rs");
    let mut output = Vec::new();

    super::write_markdown_in_language(&packet, crate::readable::Language::English, &mut output)
        .unwrap();

    let rendered = String::from_utf8(output).unwrap();
    assert!(rendered.starts_with("## Readable summary\n\nSource analysis:"));
    assert!(rendered.contains("`src/%FFauth.rs`"));
    assert!(rendered.contains("function \"check\\|token\" added."));
}

#[test]
fn html_summary_escapes_markup_and_control_characters() {
    let packet = packet("<script>\u{0007}", b"src/\xffauth.rs");
    let mut output = Vec::new();

    super::write_html_languages(&packet, &[crate::readable::Language::English], &mut output)
        .unwrap();

    let rendered = String::from_utf8(output).unwrap();
    assert!(rendered.contains("src/%FFauth.rs"));
    assert!(rendered.contains("&lt;script&gt;\\u{7}"));
    assert!(!rendered.contains("<script>"));
}

#[test]
fn summaries_escape_bidi_formatting_characters_in_identifiers() {
    let packet = packet("safe\u{202E}name", b"src/auth.rs");
    let mut text = Vec::new();
    let mut markdown = Vec::new();
    let mut html = Vec::new();

    super::write_text(&packet, &mut text).unwrap();
    super::write_markdown_in_language(&packet, crate::readable::Language::English, &mut markdown)
        .unwrap();
    super::write_html_languages(&packet, &[crate::readable::Language::English], &mut html).unwrap();

    for output in [text, markdown, html] {
        let rendered = String::from_utf8(output).unwrap();
        assert!(rendered.contains("safe"));
        assert!(rendered.contains("202E"));
        assert!(rendered.contains("name"));
        assert!(!rendered.contains('\u{202E}'));
    }
}

#[test]
fn empty_summary_and_omitted_count_are_explicit() {
    let empty = crate::readable::select_filesystem(&Diff::default()).unwrap();
    let mut output = Vec::new();
    super::write_text(&empty, &mut output).unwrap();
    assert_eq!(
        String::from_utf8(output).unwrap(),
        "Readable summary\nNo changes were found.\n"
    );

    let source_changes = (0..9)
        .map(|index| SourceFileChange {
            path: RelPath::new(format!("src/file_{index}.rs").into_bytes()).unwrap(),
            analysis_status: SourceAnalysisStatus::Compared,
            language: Some(SourceLanguage::Rust),
            lines_added: None,
            lines_removed: None,
            hunk_count: None,
            structural_status: StructuralStatus::Complete,
            structural_changes: vec![StructuralChange {
                action: StructuralAction::Added,
                kind: StructuralKind::Function,
                name: format!("function_{index}"),
                before_signature: None,
                after_signature: Some(format!("function_{index}()")),
            }],
        })
        .collect();
    let packet = select_semantic_tree(&SemanticTreeDiff {
        filesystem: Diff::default(),
        source_changes,
        binary_changes: Vec::new(),
    })
    .unwrap();
    let mut output = Vec::new();
    super::write_text(&packet, &mut output).unwrap();
    assert!(
        String::from_utf8(output)
            .unwrap()
            .contains("1 evidence record is not shown; see technical details.")
    );
}

#[test]
fn localized_empty_summaries_keep_the_default_language_explicit() {
    let packet = crate::readable::select_filesystem(&Diff::default()).unwrap();
    let expected = [
        (
            crate::readable::Language::English,
            "Readable summary\nNo changes were found.\n",
        ),
        (
            crate::readable::Language::French,
            "Résumé lisible\nAucun changement détecté.\n",
        ),
        (
            crate::readable::Language::Spanish,
            "Resumen legible\nNo se encontraron cambios.\n",
        ),
        (
            crate::readable::Language::SimplifiedChinese,
            "可读摘要\n未发现变更。\n",
        ),
    ];

    for (language, expected) in expected {
        let mut output = Vec::new();
        super::write_text_in_language(&packet, language, &mut output).unwrap();
        assert_eq!(String::from_utf8(output).unwrap(), expected);
    }
}

#[test]
fn localized_filesystem_templates_preserve_metadata_values() {
    use crate::readable::{EntryEvidence, EvidenceFact, Language};

    let before = EntryEvidence {
        kind: "symlink".to_owned(),
        size_bytes: None,
        mode: None,
        device_id: None,
        symlink_target: Some("old%20target".to_owned()),
    };
    let after = EntryEvidence {
        kind: "file".to_owned(),
        size_bytes: Some(42),
        mode: Some(0o755),
        device_id: Some(7),
        symlink_target: Some("new%20target".to_owned()),
    };
    let facts = [
        EvidenceFact::FilesystemChange {
            category: "added".to_owned(),
            changed_fields: Vec::new(),
            before: None,
            after: Some(after.clone()),
        },
        EvidenceFact::FilesystemChange {
            category: "removed".to_owned(),
            changed_fields: Vec::new(),
            before: Some(before.clone()),
            after: None,
        },
        EvidenceFact::FilesystemChange {
            category: "type_changed".to_owned(),
            changed_fields: vec!["type".to_owned()],
            before: Some(before.clone()),
            after: Some(after.clone()),
        },
        EvidenceFact::FilesystemChange {
            category: "modified".to_owned(),
            changed_fields: vec!["content".to_owned()],
            before: Some(before.clone()),
            after: Some(after.clone()),
        },
        EvidenceFact::FilesystemChange {
            category: "metadata_changed".to_owned(),
            changed_fields: vec![
                "content".to_owned(),
                "type".to_owned(),
                "mode".to_owned(),
                "device_id".to_owned(),
                "symlink_target".to_owned(),
            ],
            before: Some(before),
            after: Some(after),
        },
    ];
    let expected = [
        (
            Language::French,
            [
                "élément ajouté",
                "élément supprimé",
                "type changé",
                "contenu du fichier modifié",
                "0755",
                "7",
                "old%20target",
                "new%20target",
            ],
        ),
        (
            Language::Spanish,
            [
                "elemento añadido",
                "elemento eliminado",
                "tipo cambiado",
                "contenido del archivo modificado",
                "0755",
                "7",
                "old%20target",
                "new%20target",
            ],
        ),
        (
            Language::SimplifiedChinese,
            [
                "新增条目",
                "已移除条目",
                "类型从",
                "文件内容已更改",
                "0755",
                "7",
                "old%20target",
                "new%20target",
            ],
        ),
    ];

    for (language, phrases) in expected {
        let rendered = facts
            .iter()
            .map(|fact| super::language::describe(fact, language))
            .collect::<Vec<_>>()
            .join("\n");
        for phrase in phrases {
            assert!(
                rendered.contains(phrase),
                "{language:?}: {phrase}\n{rendered}"
            );
        }
    }
}

#[test]
fn localized_binary_templates_keep_format_facts_and_localize_unknown_values() {
    use crate::readable::{EvidenceFact, Language};

    let semantic = EvidenceFact::BinarySemanticChange {
        field: "machine".to_owned(),
        before: serde_json::json!("x86_64"),
        after: serde_json::json!("aarch64"),
    };
    let bytes = EvidenceFact::BinaryBytesChanged {
        old_kind: None,
        new_kind: Some("PE32+".to_owned()),
        old_size_bytes: Some(12),
        new_size_bytes: Some(24),
        byte_level_changed: Some(true),
        semantic_status: "unsupported".to_owned(),
    };
    let cases = [
        (
            Language::French,
            "champ binaire \"machine\"",
            "format inconnu",
            "PE32+",
            "12 octets",
            "non prise en charge",
        ),
        (
            Language::Spanish,
            "campo binario \"machine\"",
            "formato desconocido",
            "PE32+",
            "12 bytes",
            "no compatible",
        ),
        (
            Language::SimplifiedChinese,
            "二进制字段 \"machine\"",
            "未知格式",
            "PE32+",
            "12 字节",
            "不支持",
        ),
    ];

    for (language, semantic_phrase, unknown_format, known_format, size, status) in cases {
        let semantic_text = super::language::describe(&semantic, language);
        assert!(semantic_text.contains(semantic_phrase), "{semantic_text}");
        assert!(semantic_text.contains("x86_64"));
        assert!(semantic_text.contains("aarch64"));

        let bytes_text = super::language::describe(&bytes, language);
        for expected in [unknown_format, known_format, size, status] {
            assert!(
                bytes_text.contains(expected),
                "{language:?}: {expected}\n{bytes_text}"
            );
        }
    }
}

#[test]
fn localized_source_templates_cover_unknown_counts_and_content_kind_changes() {
    use crate::readable::{EvidenceFact, Language};

    let text = EvidenceFact::SourceTextChange {
        lines_added: None,
        lines_removed: Some(1),
        hunk_count: None,
    };
    let content_kind = EvidenceFact::SourceContentKindChanged;
    let cases = [
        (
            Language::French,
            "inconnu",
            "1 ligne",
            "type de contenu du fichier modifié",
        ),
        (
            Language::Spanish,
            "desconocido",
            "1 línea",
            "cambió el tipo de contenido del archivo",
        ),
        (
            Language::SimplifiedChinese,
            "未知",
            "-1 行",
            "文件内容类型已更改",
        ),
    ];

    for (language, unknown, singular, content_kind_phrase) in cases {
        let text = super::language::describe(&text, language);
        assert!(text.contains(unknown), "{language:?}: {text}");
        assert!(text.contains(singular), "{language:?}: {text}");
        assert!(
            text.contains("块")
                || text.contains("bloques")
                || text.contains("blocs")
                || language == Language::SimplifiedChinese
        );
        assert!(
            super::language::describe(&content_kind, language).contains(content_kind_phrase),
            "{language:?}"
        );
    }
}

#[test]
fn localized_overviews_cover_all_analysis_families_and_count_forms() {
    use crate::readable::{EvidenceTotals, Language};

    let totals = EvidenceTotals {
        filesystem: crate::readable::ChangeCounts {
            added: 2,
            metadata_changed: 1,
            ..EvidenceTotals::default().filesystem
        },
        filesystem_entries: 3,
        filesystem_changes: 3,
        source_files: 2,
        structural_changes: 3,
        file_comparison_inputs: 2,
        binary_files: 2,
        binary_semantic_changes: 3,
        ..EvidenceTotals::default()
    };

    let cases = [
        (
            Language::English,
            [
                "Filesystem: 3 changes across 3 entries (2 added, 1 metadata changed).",
                "Source analysis: 2 changed files, 3 structural changes.",
                "File comparison: 2 inputs, 3 semantic field changes.",
                "Binary analysis: 2 inputs, 3 semantic field changes.",
            ],
        ),
        (
            Language::French,
            [
                "Système de fichiers : 3 changements sur 3 éléments (2 éléments ajoutés, 1 changement de métadonnées).",
                "Analyse du code : 2 fichiers modifiés, 3 changements structurels.",
                "Comparaison de fichiers : 2 entrées, 3 changements de champs sémantiques.",
                "Analyse binaire : 2 entrées, 3 changements de champs sémantiques.",
            ],
        ),
        (
            Language::Spanish,
            [
                "Sistema de archivos: 3 cambios en 3 elementos (2 elementos añadidos, 1 cambio de metadatos).",
                "Análisis de código: 2 archivos modificados, 3 cambios estructurales.",
                "Comparación de archivos: 2 entradas, 3 cambios de campos semánticos.",
                "Análisis binario: 2 entradas, 3 cambios de campos semánticos.",
            ],
        ),
        (
            Language::SimplifiedChinese,
            [
                "文件系统：3 项变更，覆盖 3 个条目（新增项 2 项、元数据变更 1 项）。",
                "源码分析：2 个文件有变更，3 项结构变更。",
                "文件比较：2 个输入，3 项语义字段变更。",
                "二进制分析：2 个输入，3 项语义字段变更。",
            ],
        ),
    ];

    for (language, expected) in cases {
        let lines = super::language::overview_lines(&totals, language);
        assert_eq!(lines, expected, "{language:?}");
    }
}

#[test]
fn localized_summaries_keep_paths_encoded_and_escape_untrusted_identifiers() {
    use crate::readable::Language;

    let packet = packet("<script>\u{0007}", b"src/\xffauth.rs");
    for language in Language::ALL {
        let mut text = Vec::new();
        super::write_text_in_language(&packet, language, &mut text).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("`src/%FFauth.rs`"), "{language:?}: {text}");
        assert!(text.contains("\\u{7}"), "{language:?}: {text}");
        assert!(
            text.contains("<script>"),
            "text keeps printable identifiers literal"
        );

        let mut markdown = Vec::new();
        super::write_markdown_in_language(&packet, language, &mut markdown).unwrap();
        let markdown = String::from_utf8(markdown).unwrap();
        assert!(
            markdown.contains("`src/%FFauth.rs`"),
            "{language:?}: {markdown}"
        );
        assert!(
            markdown.contains("\\\\u\\{7\\}"),
            "{language:?}: {markdown}"
        );

        let mut html = Vec::new();
        super::write_html_languages(&packet, &[language], &mut html).unwrap();
        let html = String::from_utf8(html).unwrap();
        assert!(html.contains("src/%FFauth.rs"), "{language:?}: {html}");
        assert!(
            html.contains("&lt;script&gt;\\u{7}"),
            "{language:?}: {html}"
        );
        assert!(!html.contains("<script>alert"), "{language:?}: {html}");
    }
}

#[test]
fn omission_notes_localize_singular_and_plural_forms() {
    use crate::readable::Language;

    for language in Language::ALL {
        let singular = super::language::omission_note(language, 1);
        let plural = super::language::omission_note(language, 2);
        assert!(singular.contains('1'), "{language:?}: {singular}");
        assert!(plural.contains('2'), "{language:?}: {plural}");
        assert_ne!(singular, plural, "{language:?}");
    }
}

#[test]
fn localized_source_text_counts_use_each_languages_plural_form() {
    use crate::readable::{EvidenceFact, Language};

    let fact = EvidenceFact::SourceTextChange {
        lines_added: Some(2),
        lines_removed: Some(2),
        hunk_count: Some(2),
    };
    let cases = [
        (Language::English, "+2 lines", "-2 lines", "2 hunks"),
        (Language::French, "+2 lignes", "-2 lignes", "2 blocs"),
        (Language::Spanish, "+2 líneas", "-2 líneas", "2 bloques"),
        (Language::SimplifiedChinese, "+2 行", "-2 行", "2 个片段"),
    ];

    for (language, added, removed, hunks) in cases {
        let rendered = super::language::describe(&fact, language);
        for phrase in [added, removed, hunks] {
            assert!(rendered.contains(phrase), "{language:?}: {rendered}");
        }
    }
}

#[test]
fn localized_filesystem_overviews_cover_singular_counts() {
    use crate::readable::{EvidenceTotals, Language};

    let totals = EvidenceTotals {
        filesystem: crate::readable::ChangeCounts {
            added: 1,
            ..EvidenceTotals::default().filesystem
        },
        filesystem_entries: 1,
        filesystem_changes: 1,
        ..EvidenceTotals::default()
    };
    let cases = [
        (
            Language::English,
            "Filesystem: 1 change across 1 entry (1 added).",
        ),
        (
            Language::French,
            "Système de fichiers : 1 changement sur 1 élément (1 élément ajouté).",
        ),
        (
            Language::Spanish,
            "Sistema de archivos: 1 cambio en 1 elemento (1 elemento añadido).",
        ),
        (
            Language::SimplifiedChinese,
            "文件系统：1 项变更，覆盖 1 个条目（新增项 1 项）。",
        ),
    ];

    for (language, expected) in cases {
        assert_eq!(
            super::language::overview_lines(&totals, language),
            [expected]
        );
    }
}

#[test]
fn localized_binary_comparison_states_use_explicit_language_words() {
    use crate::readable::{EvidenceFact, Language};

    let cases = [
        (
            Language::French,
            ["effectuée", "formats différents", "non prise en charge"],
            ["différente", "identique", "non établie"],
        ),
        (
            Language::Spanish,
            ["realizada", "formatos distintos", "no compatible"],
            ["diferente", "igual", "no establecida"],
        ),
        (
            Language::SimplifiedChinese,
            ["已完成", "格式不同", "不支持"],
            ["已更改", "未更改", "未确定"],
        ),
    ];
    let statuses = ["compared", "format_mismatch", "unsupported"];
    let byte_changes = [Some(true), Some(false), None];

    for (language, semantic_words, byte_words) in cases {
        for (status, expected) in statuses.into_iter().zip(semantic_words) {
            let fact = EvidenceFact::BinaryBytesChanged {
                old_kind: Some("ELF".to_owned()),
                new_kind: Some("PE32+".to_owned()),
                old_size_bytes: Some(1),
                new_size_bytes: Some(2),
                byte_level_changed: Some(true),
                semantic_status: status.to_owned(),
            };
            assert!(
                super::language::describe(&fact, language).contains(expected),
                "{language:?}: {status}"
            );
        }
        for (changed, expected) in byte_changes.into_iter().zip(byte_words) {
            let fact = EvidenceFact::BinaryBytesChanged {
                old_kind: Some("ELF".to_owned()),
                new_kind: Some("PE32+".to_owned()),
                old_size_bytes: Some(1),
                new_size_bytes: Some(2),
                byte_level_changed: changed,
                semantic_status: "unsupported".to_owned(),
            };
            assert!(
                super::language::describe(&fact, language).contains(expected),
                "{language:?}: {changed:?}"
            );
        }
    }
}

#[test]
fn french_structural_summaries_use_grammatical_union_and_signature_articles() {
    use crate::readable::{EvidenceFact, Language};

    fn render(action: &str, kind: &str, before: Option<&str>, after: Option<&str>) -> String {
        super::language::describe(
            &EvidenceFact::SourceStructuralChange {
                action: action.to_owned(),
                symbol_kind: kind.to_owned(),
                name: "DeviceInfo".to_owned(),
                before_signature: before.map(str::to_owned),
                after_signature: after.map(str::to_owned),
            },
            Language::French,
        )
    }

    let union_added = render("added", "union", None, None);
    assert_eq!(union_added, "union \"DeviceInfo\" ajoutée");

    let union_signature = render(
        "signature_changed",
        "union",
        Some("DeviceInfo(old)"),
        Some("DeviceInfo(new)"),
    );
    assert_eq!(
        union_signature,
        "signature de l'union \"DeviceInfo\" modifiée de \"DeviceInfo(old)\" à \"DeviceInfo(new)\""
    );

    let type_signature = render(
        "signature_changed",
        "type",
        Some("DeviceInfo(old)"),
        Some("DeviceInfo(new)"),
    );
    assert_eq!(
        type_signature,
        "signature du type \"DeviceInfo\" modifiée de \"DeviceInfo(old)\" à \"DeviceInfo(new)\""
    );
}

#[test]
fn spanish_signature_summaries_use_grammatical_articles() {
    use crate::readable::{EvidenceFact, Language};

    fn render(kind: &str) -> String {
        super::language::describe(
            &EvidenceFact::SourceStructuralChange {
                action: "signature_changed".to_owned(),
                symbol_kind: kind.to_owned(),
                name: "login".to_owned(),
                before_signature: Some("login(old)".to_owned()),
                after_signature: Some("login(new)".to_owned()),
            },
            Language::Spanish,
        )
    }

    assert_eq!(
        render("method"),
        "firma del método \"login\" cambió de \"login(old)\" a \"login(new)\""
    );
    assert_eq!(
        render("function"),
        "firma de la función \"login\" cambió de \"login(old)\" a \"login(new)\""
    );
}
