use crate::readable::{EntryEvidence, EvidenceFact, EvidenceTotals, Language};

pub(super) fn heading(language: Language) -> &'static str {
    match language {
        Language::English => "Readable summary",
        Language::French => "Résumé lisible",
        Language::Spanish => "Resumen legible",
        Language::SimplifiedChinese => "可读摘要",
    }
}

pub(super) fn empty_message(language: Language) -> &'static str {
    match language {
        Language::English => "No changes were found.",
        Language::French => "Aucun changement détecté.",
        Language::Spanish => "No se encontraron cambios.",
        Language::SimplifiedChinese => "未发现变更。",
    }
}

pub(super) fn notable_changes(language: Language) -> &'static str {
    match language {
        Language::English => "Notable changes",
        Language::French => "Changements notables",
        Language::Spanish => "Cambios destacados",
        Language::SimplifiedChinese => "重要变更",
    }
}

pub(super) fn overview_lines(totals: &EvidenceTotals, language: Language) -> Vec<String> {
    if language == Language::English {
        return super::overview_lines(totals);
    }

    let mut lines = Vec::with_capacity(4);
    if totals.filesystem_entries > 0 {
        let changes = filesystem_counts(totals, language);
        let (label, entry_count, change_count) = match language {
            Language::French => (
                "Système de fichiers",
                phrase(totals.filesystem_entries, "élément", "éléments"),
                phrase(totals.filesystem_changes, "changement", "changements"),
            ),
            Language::Spanish => (
                "Sistema de archivos",
                phrase(totals.filesystem_entries, "elemento", "elementos"),
                phrase(totals.filesystem_changes, "cambio", "cambios"),
            ),
            Language::SimplifiedChinese => (
                "文件系统",
                format!("{} 个条目", totals.filesystem_entries),
                format!("{} 项变更", totals.filesystem_changes),
            ),
            Language::English => unreachable!(),
        };
        let separator = if language == Language::SimplifiedChinese {
            "、"
        } else {
            ", "
        };
        lines.push(match language {
            Language::French => format!(
                "{label} : {change_count} sur {entry_count} ({}).",
                changes.join(separator)
            ),
            Language::Spanish => format!(
                "{label}: {change_count} en {entry_count} ({}).",
                changes.join(separator)
            ),
            Language::SimplifiedChinese => {
                format!(
                    "{label}：{change_count}，覆盖 {entry_count}（{}）。",
                    changes.join(separator)
                )
            }
            Language::English => unreachable!(),
        });
    }
    if totals.source_files > 0 {
        lines.push(match language {
            Language::French => format!(
                "Analyse du code : {}, {}.",
                phrase(totals.source_files, "fichier modifié", "fichiers modifiés"),
                phrase(
                    totals.structural_changes,
                    "changement structurel",
                    "changements structurels"
                )
            ),
            Language::Spanish => format!(
                "Análisis de código: {}, {}.",
                phrase(
                    totals.source_files,
                    "archivo modificado",
                    "archivos modificados"
                ),
                phrase(
                    totals.structural_changes,
                    "cambio estructural",
                    "cambios estructurales"
                )
            ),
            Language::SimplifiedChinese => format!(
                "源码分析：{} 个文件有变更，{} 项结构变更。",
                totals.source_files, totals.structural_changes
            ),
            Language::English => unreachable!(),
        });
    }
    if totals.file_comparison_inputs > 0 {
        lines.push(match language {
            Language::French => format!(
                "Comparaison de fichiers : {}, {}.",
                phrase(totals.file_comparison_inputs, "entrée", "entrées"),
                phrase(
                    totals.binary_semantic_changes,
                    "changement de champ sémantique",
                    "changements de champs sémantiques"
                )
            ),
            Language::Spanish => format!(
                "Comparación de archivos: {}, {}.",
                phrase(totals.file_comparison_inputs, "entrada", "entradas"),
                phrase(
                    totals.binary_semantic_changes,
                    "cambio de campo semántico",
                    "cambios de campos semánticos"
                )
            ),
            Language::SimplifiedChinese => format!(
                "文件比较：{} 个输入，{} 项语义字段变更。",
                totals.file_comparison_inputs, totals.binary_semantic_changes
            ),
            Language::English => unreachable!(),
        });
    }
    if totals.binary_files > 0 {
        lines.push(match language {
            Language::French => format!(
                "Analyse binaire : {}, {}.",
                phrase(totals.binary_files, "entrée", "entrées"),
                phrase(
                    totals.binary_semantic_changes,
                    "changement de champ sémantique",
                    "changements de champs sémantiques"
                )
            ),
            Language::Spanish => format!(
                "Análisis binario: {}, {}.",
                phrase(totals.binary_files, "entrada", "entradas"),
                phrase(
                    totals.binary_semantic_changes,
                    "cambio de campo semántico",
                    "cambios de campos semánticos"
                )
            ),
            Language::SimplifiedChinese => format!(
                "二进制分析：{} 个输入，{} 项语义字段变更。",
                totals.binary_files, totals.binary_semantic_changes
            ),
            Language::English => unreachable!(),
        });
    }
    lines
}

pub(super) fn describe(fact: &EvidenceFact, language: Language) -> String {
    if language == Language::English {
        return super::describe(fact);
    }
    match fact {
        EvidenceFact::FilesystemChange {
            category,
            changed_fields,
            before,
            after,
        } => describe_filesystem(
            language,
            category,
            changed_fields,
            before.as_ref(),
            after.as_ref(),
        ),
        EvidenceFact::SourceStructuralChange {
            action,
            symbol_kind,
            name,
            before_signature,
            after_signature,
        } => localized_structural_change(
            language,
            action,
            symbol_kind,
            name,
            before_signature.as_deref(),
            after_signature.as_deref(),
        ),
        EvidenceFact::SourceTextChange {
            lines_added,
            lines_removed,
            hunk_count,
        } => describe_text(language, *lines_added, *lines_removed, *hunk_count),
        EvidenceFact::SourceContentKindChanged => match language {
            Language::French => "type de contenu du fichier modifié".to_owned(),
            Language::Spanish => "cambió el tipo de contenido del archivo".to_owned(),
            Language::SimplifiedChinese => "文件内容类型已更改".to_owned(),
            Language::English => unreachable!(),
        },
        EvidenceFact::BinarySemanticChange {
            field,
            before,
            after,
        } => {
            let field = super::display_safe(field);
            let before = super::display_safe(&before.to_string());
            let after = super::display_safe(&after.to_string());
            match language {
                Language::French => {
                    format!("champ binaire \"{field}\" modifié de {before} à {after}")
                }
                Language::Spanish => {
                    format!("campo binario \"{field}\" cambió de {before} a {after}")
                }
                Language::SimplifiedChinese => {
                    format!("二进制字段 \"{field}\" 从 {before} 变为 {after}")
                }
                Language::English => unreachable!(),
            }
        }
        EvidenceFact::BinaryBytesChanged {
            old_kind,
            new_kind,
            old_size_bytes,
            new_size_bytes,
            byte_level_changed,
            semantic_status,
        } => describe_binary_bytes(
            language,
            old_kind
                .as_deref()
                .unwrap_or_else(|| unknown_format(language)),
            new_kind
                .as_deref()
                .unwrap_or_else(|| unknown_format(language)),
            *old_size_bytes,
            *new_size_bytes,
            *byte_level_changed,
            semantic_status,
        ),
    }
}

pub(super) fn omission_note(language: Language, omitted: u64) -> String {
    match language {
        Language::English => format!(
            "{omitted} evidence {} not shown; see technical details.",
            if omitted == 1 {
                "record is"
            } else {
                "records are"
            }
        ),
        Language::French => format!(
            "{omitted} {} de preuve non affiché{} ; voir les détails techniques.",
            if omitted == 1 {
                "élément"
            } else {
                "éléments"
            },
            if omitted == 1 { "" } else { "s" }
        ),
        Language::Spanish => format!(
            "No se muestran {omitted} {} de evidencia; consulta los detalles técnicos.",
            if omitted == 1 {
                "registro"
            } else {
                "registros"
            }
        ),
        Language::SimplifiedChinese => {
            format!("有 {omitted} 项证据未显示；请查看技术详情。")
        }
    }
}

pub(super) fn explanation_labels(language: Language) -> (&'static str, &'static str, &'static str) {
    match language {
        Language::English => ("Evidence", "Path", "Fact"),
        Language::French => ("Preuve", "Chemin", "Fait"),
        Language::Spanish => ("Evidencia", "Ruta", "Hecho"),
        Language::SimplifiedChinese => ("证据", "路径", "事实"),
    }
}

pub(super) fn file_comparison_path(language: Language) -> &'static str {
    match language {
        Language::English => "file comparison",
        Language::French => "comparaison de fichiers",
        Language::Spanish => "comparación de archivos",
        Language::SimplifiedChinese => "文件比较",
    }
}

fn filesystem_counts(totals: &EvidenceTotals, language: Language) -> Vec<String> {
    let counts = [
        totals.filesystem.added,
        totals.filesystem.removed,
        totals.filesystem.modified,
        totals.filesystem.type_changed,
        totals.filesystem.metadata_changed,
        totals.filesystem.unchanged,
    ];
    let labels = match language {
        Language::French => [
            ("élément ajouté", "éléments ajoutés"),
            ("élément supprimé", "éléments supprimés"),
            ("élément modifié", "éléments modifiés"),
            ("changement de type", "changements de type"),
            ("changement de métadonnées", "changements de métadonnées"),
            ("élément inchangé", "éléments inchangés"),
        ],
        Language::Spanish => [
            ("elemento añadido", "elementos añadidos"),
            ("elemento eliminado", "elementos eliminados"),
            ("elemento modificado", "elementos modificados"),
            ("cambio de tipo", "cambios de tipo"),
            ("cambio de metadatos", "cambios de metadatos"),
            ("elemento sin cambios", "elementos sin cambios"),
        ],
        Language::SimplifiedChinese => [
            ("新增项", "新增项"),
            ("删除项", "删除项"),
            ("修改项", "修改项"),
            ("类型变更", "类型变更"),
            ("元数据变更", "元数据变更"),
            ("未变更项", "未变更项"),
        ],
        Language::English => [
            ("added", "added"),
            ("removed", "removed"),
            ("modified", "modified"),
            ("type changed", "type changed"),
            ("metadata changed", "metadata changed"),
            ("unchanged", "unchanged"),
        ],
    };
    counts
        .into_iter()
        .zip(labels)
        .filter(|(count, _)| *count > 0)
        .map(|(count, (singular, plural))| match language {
            Language::SimplifiedChinese => format!("{singular} {count} 项"),
            _ => phrase(count, singular, plural),
        })
        .collect()
}

fn phrase(count: u64, singular: &str, plural: &str) -> String {
    format!("{count} {}", if count == 1 { singular } else { plural })
}

fn describe_filesystem(
    language: Language,
    category: &str,
    changed_fields: &[String],
    before: Option<&EntryEvidence>,
    after: Option<&EntryEvidence>,
) -> String {
    match category {
        "added" => match language {
            Language::French => format!("élément ajouté : {}", describe_entry(language, after)),
            Language::Spanish => format!("elemento añadido: {}", describe_entry(language, after)),
            Language::SimplifiedChinese => {
                format!("新增条目：{}", describe_entry(language, after))
            }
            Language::English => unreachable!(),
        },
        "removed" => match language {
            Language::French => format!("élément supprimé : {}", describe_entry(language, before)),
            Language::Spanish => {
                format!("elemento eliminado: {}", describe_entry(language, before))
            }
            Language::SimplifiedChinese => {
                format!("已移除条目：{}", describe_entry(language, before))
            }
            Language::English => unreachable!(),
        },
        "type_changed" => match language {
            Language::French => format!(
                "type changé de {} à {}",
                before.map_or("type inconnu", |entry| entry_kind(language, &entry.kind)),
                after.map_or("type inconnu", |entry| entry_kind(language, &entry.kind))
            ),
            Language::Spanish => format!(
                "tipo cambiado de {} a {}",
                before.map_or("tipo desconocido", |entry| entry_kind(
                    language,
                    &entry.kind
                )),
                after.map_or("tipo desconocido", |entry| entry_kind(
                    language,
                    &entry.kind
                ))
            ),
            Language::SimplifiedChinese => format!(
                "类型从 {} 变为 {}",
                before.map_or("未知类型", |entry| entry_kind(language, &entry.kind)),
                after.map_or("未知类型", |entry| entry_kind(language, &entry.kind))
            ),
            Language::English => unreachable!(),
        },
        "modified" | "metadata_changed" => {
            let details = changed_fields
                .iter()
                .filter_map(|field| describe_field(language, field, before, after))
                .collect::<Vec<_>>();
            if details.is_empty() {
                match language {
                    Language::French => "métadonnées du système de fichiers modifiées".to_owned(),
                    Language::Spanish => {
                        "cambiaron los metadatos del sistema de archivos".to_owned()
                    }
                    Language::SimplifiedChinese => "文件系统元数据已更改".to_owned(),
                    Language::English => unreachable!(),
                }
            } else {
                details.join(match language {
                    Language::SimplifiedChinese => "；",
                    _ => ", ",
                })
            }
        }
        _ => match language {
            Language::French => "entrée du système de fichiers modifiée".to_owned(),
            Language::Spanish => "cambió una entrada del sistema de archivos".to_owned(),
            Language::SimplifiedChinese => "文件系统条目已更改".to_owned(),
            Language::English => unreachable!(),
        },
    }
}

fn describe_entry(language: Language, entry: Option<&EntryEvidence>) -> String {
    let Some(entry) = entry else {
        return match language {
            Language::French => "entrée aux métadonnées indisponibles".to_owned(),
            Language::Spanish => "entrada con metadatos no disponibles".to_owned(),
            Language::SimplifiedChinese => "元数据不可用的条目".to_owned(),
            Language::English => unreachable!(),
        };
    };
    let mut details = vec![entry_kind(language, &entry.kind).to_owned()];
    if let Some(size) = entry.size_bytes {
        details.push(match language {
            Language::French => format!("{size} octets"),
            Language::Spanish => format!("{size} bytes"),
            Language::SimplifiedChinese => format!("{size} 字节"),
            Language::English => unreachable!(),
        });
    }
    if let Some(mode) = entry.mode {
        details.push(match language {
            Language::French => format!("mode {mode:04o}"),
            Language::Spanish => format!("modo {mode:04o}"),
            Language::SimplifiedChinese => format!("权限 {mode:04o}"),
            Language::English => unreachable!(),
        });
    }
    if let Some(device_id) = entry.device_id {
        details.push(match language {
            Language::French => format!("identifiant de périphérique {device_id}"),
            Language::Spanish => format!("ID de dispositivo {device_id}"),
            Language::SimplifiedChinese => format!("设备 ID {device_id}"),
            Language::English => unreachable!(),
        });
    }
    if let Some(target) = &entry.symlink_target {
        details.push(match language {
            Language::French => format!("cible {target}"),
            Language::Spanish => format!("destino {target}"),
            Language::SimplifiedChinese => format!("目标 {target}"),
            Language::English => unreachable!(),
        });
    }
    details.join("; ")
}

fn entry_kind(language: Language, kind: &str) -> &str {
    match (language, kind) {
        (Language::French, "file") => "fichier",
        (Language::French, "directory") => "répertoire",
        (Language::French, "symlink") => "lien symbolique",
        (Language::French, "fifo") => "tube nommé",
        (Language::French, "socket") => "socket",
        (Language::French, "char_device") => "périphérique caractère",
        (Language::French, "block_device") => "périphérique bloc",
        (Language::Spanish, "file") => "archivo",
        (Language::Spanish, "directory") => "directorio",
        (Language::Spanish, "symlink") => "enlace simbólico",
        (Language::Spanish, "fifo") => "FIFO",
        (Language::Spanish, "socket") => "socket",
        (Language::Spanish, "char_device") => "dispositivo de caracteres",
        (Language::Spanish, "block_device") => "dispositivo de bloques",
        (Language::SimplifiedChinese, "file") => "文件",
        (Language::SimplifiedChinese, "directory") => "目录",
        (Language::SimplifiedChinese, "symlink") => "符号链接",
        (Language::SimplifiedChinese, "fifo") => "FIFO",
        (Language::SimplifiedChinese, "socket") => "套接字",
        (Language::SimplifiedChinese, "char_device") => "字符设备",
        (Language::SimplifiedChinese, "block_device") => "块设备",
        (_, _) => kind,
    }
}

fn describe_field(
    language: Language,
    field: &str,
    before: Option<&EntryEvidence>,
    after: Option<&EntryEvidence>,
) -> Option<String> {
    let value = |entry: Option<&EntryEvidence>, field: fn(&EntryEvidence) -> Option<String>| {
        entry.and_then(field).unwrap_or_else(|| match language {
            Language::French => "inconnu".to_owned(),
            Language::Spanish => "desconocido".to_owned(),
            Language::SimplifiedChinese => "未知".to_owned(),
            Language::English => unreachable!(),
        })
    };
    match field {
        "content" => Some(match language {
            Language::French => "contenu du fichier modifié".to_owned(),
            Language::Spanish => "contenido del archivo modificado".to_owned(),
            Language::SimplifiedChinese => "文件内容已更改".to_owned(),
            Language::English => unreachable!(),
        }),
        "type" => Some(match language {
            Language::French => format!(
                "type de {} à {}",
                before.map_or("inconnu", |entry| entry_kind(language, &entry.kind)),
                after.map_or("inconnu", |entry| entry_kind(language, &entry.kind))
            ),
            Language::Spanish => format!(
                "tipo de {} a {}",
                before.map_or("desconocido", |entry| entry_kind(language, &entry.kind)),
                after.map_or("desconocido", |entry| entry_kind(language, &entry.kind))
            ),
            Language::SimplifiedChinese => format!(
                "类型从 {} 变为 {}",
                before.map_or("未知", |entry| entry_kind(language, &entry.kind)),
                after.map_or("未知", |entry| entry_kind(language, &entry.kind))
            ),
            Language::English => unreachable!(),
        }),
        "mode" => Some(match language {
            Language::French => format!(
                "mode {} à {}",
                value(before, |entry| entry.mode.map(|mode| format!("{mode:04o}"))),
                value(after, |entry| entry.mode.map(|mode| format!("{mode:04o}")))
            ),
            Language::Spanish => format!(
                "modo {} a {}",
                value(before, |entry| entry.mode.map(|mode| format!("{mode:04o}"))),
                value(after, |entry| entry.mode.map(|mode| format!("{mode:04o}")))
            ),
            Language::SimplifiedChinese => format!(
                "权限从 {} 变为 {}",
                value(before, |entry| entry.mode.map(|mode| format!("{mode:04o}"))),
                value(after, |entry| entry.mode.map(|mode| format!("{mode:04o}")))
            ),
            Language::English => unreachable!(),
        }),
        "device_id" => Some(match language {
            Language::French => format!(
                "identifiant de périphérique de {} à {}",
                value(before, |entry| entry.device_id.map(|id| id.to_string())),
                value(after, |entry| entry.device_id.map(|id| id.to_string()))
            ),
            Language::Spanish => format!(
                "ID de dispositivo de {} a {}",
                value(before, |entry| entry.device_id.map(|id| id.to_string())),
                value(after, |entry| entry.device_id.map(|id| id.to_string()))
            ),
            Language::SimplifiedChinese => format!(
                "设备 ID 从 {} 变为 {}",
                value(before, |entry| entry.device_id.map(|id| id.to_string())),
                value(after, |entry| entry.device_id.map(|id| id.to_string()))
            ),
            Language::English => unreachable!(),
        }),
        "symlink_target" => Some(match language {
            Language::French => format!(
                "cible du lien symbolique de {} à {}",
                value(before, |entry| entry.symlink_target.clone()),
                value(after, |entry| entry.symlink_target.clone())
            ),
            Language::Spanish => format!(
                "destino del enlace simbólico de {} a {}",
                value(before, |entry| entry.symlink_target.clone()),
                value(after, |entry| entry.symlink_target.clone())
            ),
            Language::SimplifiedChinese => format!(
                "符号链接目标从 {} 变为 {}",
                value(before, |entry| entry.symlink_target.clone()),
                value(after, |entry| entry.symlink_target.clone())
            ),
            Language::English => unreachable!(),
        }),
        _ => None,
    }
}

fn structural_kind(language: Language, kind: &str) -> &str {
    match (language, kind) {
        (Language::French, "function") => "fonction",
        (Language::French, "method") => "méthode",
        (Language::French, "struct") => "structure",
        (Language::French, "union") => "union",
        (Language::French, "enum") => "énumération",
        (Language::French, "class") => "classe",
        (Language::French, "interface") => "interface",
        (Language::French, "type") => "type",
        (Language::French, "constant") => "constante",
        (Language::French, "module") => "module",
        (Language::French, "macro") => "macro",
        (Language::French, "import") => "importation",
        (Language::Spanish, "function") => "función",
        (Language::Spanish, "method") => "método",
        (Language::Spanish, "struct") => "estructura",
        (Language::Spanish, "union") => "unión",
        (Language::Spanish, "enum") => "enumeración",
        (Language::Spanish, "class") => "clase",
        (Language::Spanish, "interface") => "interfaz",
        (Language::Spanish, "type") => "tipo",
        (Language::Spanish, "constant") => "constante",
        (Language::Spanish, "module") => "módulo",
        (Language::Spanish, "macro") => "macro",
        (Language::Spanish, "import") => "importación",
        (Language::SimplifiedChinese, "function") => "函数",
        (Language::SimplifiedChinese, "method") => "方法",
        (Language::SimplifiedChinese, "struct") => "结构体",
        (Language::SimplifiedChinese, "union") => "联合体",
        (Language::SimplifiedChinese, "enum") => "枚举",
        (Language::SimplifiedChinese, "class") => "类",
        (Language::SimplifiedChinese, "interface") => "接口",
        (Language::SimplifiedChinese, "type") => "类型",
        (Language::SimplifiedChinese, "constant") => "常量",
        (Language::SimplifiedChinese, "module") => "模块",
        (Language::SimplifiedChinese, "macro") => "宏",
        (Language::SimplifiedChinese, "import") => "导入",
        (_, _) => kind,
    }
}

fn localized_structural_change(
    language: Language,
    action: &str,
    kind: &str,
    name: &str,
    before_signature: Option<&str>,
    after_signature: Option<&str>,
) -> String {
    let kind = structural_kind(language, kind);
    let name = super::display_safe(name);
    match (language, action) {
        (Language::French, "added") => match french_feminine_kind(kind) {
            Some(true) => format!("{kind} \"{name}\" ajoutée"),
            Some(false) => format!("{kind} \"{name}\" ajouté"),
            None => format!("ajout de {kind} \"{name}\""),
        },
        (Language::French, "removed") => match french_feminine_kind(kind) {
            Some(true) => format!("{kind} \"{name}\" supprimée"),
            Some(false) => format!("{kind} \"{name}\" supprimé"),
            None => format!("suppression de {kind} \"{name}\""),
        },
        (Language::French, "signature_changed") => {
            let subject = french_signature_subject(kind);
            format!(
                "signature {subject} \"{name}\" modifiée de {} à {}",
                quoted(language, before_signature),
                quoted(language, after_signature)
            )
        }
        (Language::French, _) => format!("modification de {kind} \"{name}\""),
        (Language::Spanish, "added") => match spanish_feminine_kind(kind) {
            Some(true) => format!("{kind} \"{name}\" añadida"),
            Some(false) => format!("{kind} \"{name}\" añadido"),
            None => format!("adición de {kind} \"{name}\""),
        },
        (Language::Spanish, "removed") => match spanish_feminine_kind(kind) {
            Some(true) => format!("{kind} \"{name}\" eliminada"),
            Some(false) => format!("{kind} \"{name}\" eliminado"),
            None => format!("eliminación de {kind} \"{name}\""),
        },
        (Language::Spanish, "signature_changed") => {
            let preposition = match spanish_feminine_kind(kind) {
                Some(true) => "de la ",
                Some(false) => "del ",
                None => "de ",
            };
            format!(
                "firma {preposition}{kind} \"{name}\" cambió de {} a {}",
                quoted(language, before_signature),
                quoted(language, after_signature)
            )
        }
        (Language::Spanish, _) => format!("cambio de {kind} \"{name}\""),
        (Language::SimplifiedChinese, "added") => format!("{kind} \"{name}\" 已添加"),
        (Language::SimplifiedChinese, "removed") => format!("{kind} \"{name}\" 已移除"),
        (Language::SimplifiedChinese, "signature_changed") => format!(
            "{kind} \"{name}\" 的签名从 {} 变为 {}",
            quoted(language, before_signature),
            quoted(language, after_signature)
        ),
        (Language::SimplifiedChinese, _) => format!("{kind} \"{name}\" 已更改"),
        (Language::English, "added") => format!("{kind} \"{name}\" added"),
        (Language::English, "removed") => format!("{kind} \"{name}\" removed"),
        (Language::English, "signature_changed") => format!(
            "{kind} \"{name}\" signature changed from {} to {}",
            quoted(language, before_signature),
            quoted(language, after_signature)
        ),
        (Language::English, _) => format!("{kind} \"{name}\" changed"),
    }
}

fn french_feminine_kind(kind: &str) -> Option<bool> {
    match kind {
        "fonction" | "méthode" | "structure" | "énumération" | "classe" | "interface"
        | "constante" | "macro" | "importation" | "union" => Some(true),
        "type" | "module" => Some(false),
        _ => None,
    }
}

fn french_signature_subject(kind: &str) -> String {
    match french_feminine_kind(kind) {
        Some(true) if begins_with_french_vowel(kind) => format!("de l'{kind}"),
        Some(true) => format!("de la {kind}"),
        Some(false) => format!("du {kind}"),
        None => format!("de {kind}"),
    }
}

fn begins_with_french_vowel(value: &str) -> bool {
    value.chars().next().is_some_and(|character| {
        matches!(
            character,
            'a' | 'à'
                | 'â'
                | 'ä'
                | 'e'
                | 'é'
                | 'è'
                | 'ê'
                | 'ë'
                | 'i'
                | 'î'
                | 'ï'
                | 'o'
                | 'ô'
                | 'ö'
                | 'u'
                | 'ù'
                | 'û'
                | 'ü'
                | 'y'
                | 'ÿ'
        )
    })
}

fn spanish_feminine_kind(kind: &str) -> Option<bool> {
    match kind {
        "función" | "estructura" | "unión" | "enumeración" | "clase" | "interfaz" | "constante"
        | "macro" | "importación" => Some(true),
        "método" | "tipo" | "módulo" => Some(false),
        _ => None,
    }
}

fn unknown_format(language: Language) -> &'static str {
    match language {
        Language::English => "unknown format",
        Language::French => "format inconnu",
        Language::Spanish => "formato desconocido",
        Language::SimplifiedChinese => "未知格式",
    }
}

fn describe_text(
    language: Language,
    lines_added: Option<u64>,
    lines_removed: Option<u64>,
    hunk_count: Option<u64>,
) -> String {
    let added = lines_added.map_or_else(|| unknown(language).to_owned(), |count| count.to_string());
    let removed =
        lines_removed.map_or_else(|| unknown(language).to_owned(), |count| count.to_string());
    match language {
        Language::French => format!(
            "texte modifié (+{} {}, -{} {} sur {})",
            added,
            plural_word(lines_added, "ligne", "lignes"),
            removed,
            plural_word(lines_removed, "ligne", "lignes"),
            hunk_count.map_or_else(
                || "un nombre inconnu de blocs".to_owned(),
                |count| phrase(count, "bloc", "blocs")
            )
        ),
        Language::Spanish => format!(
            "texto modificado (+{} {}, -{} {} en {})",
            added,
            plural_word(lines_added, "línea", "líneas"),
            removed,
            plural_word(lines_removed, "línea", "líneas"),
            hunk_count.map_or_else(
                || "un número desconocido de bloques".to_owned(),
                |count| phrase(count, "bloque", "bloques")
            )
        ),
        Language::SimplifiedChinese => format!(
            "文本已更改（+{} 行，-{} 行，分为 {}）",
            added,
            removed,
            hunk_count.map_or_else(
                || "未知数量的片段".to_owned(),
                |count| format!("{count} 个片段")
            )
        ),
        Language::English => super::describe(&EvidenceFact::SourceTextChange {
            lines_added,
            lines_removed,
            hunk_count,
        }),
    }
}

fn describe_binary_bytes(
    language: Language,
    old_kind: &str,
    new_kind: &str,
    old_size: Option<u64>,
    new_size: Option<u64>,
    byte_changed: Option<bool>,
    semantic_status: &str,
) -> String {
    let old_kind = super::display_safe(old_kind);
    let new_kind = super::display_safe(new_kind);
    let old_size = old_size.map_or_else(
        || unknown_size(language).to_owned(),
        |size| size.to_string(),
    );
    let new_size = new_size.map_or_else(
        || unknown_size(language).to_owned(),
        |size| size.to_string(),
    );
    match language {
        Language::French => format!(
            "comparaison octet par octet {} ; {} ({old_size} octets) vers {} ({new_size} octets) ; comparaison sémantique : {}",
            byte_change(language, byte_changed),
            old_kind,
            new_kind,
            semantic_status_fr(semantic_status)
        ),
        Language::Spanish => format!(
            "comparación byte a byte {}; {} ({old_size} bytes) a {} ({new_size} bytes); comparación semántica: {}",
            byte_change(language, byte_changed),
            old_kind,
            new_kind,
            semantic_status_es(semantic_status)
        ),
        Language::SimplifiedChinese => format!(
            "逐字节比较：{}；{}（{old_size} 字节）变为 {}（{new_size} 字节）；语义比较：{}",
            byte_change(language, byte_changed),
            old_kind,
            new_kind,
            semantic_status_zh(semantic_status)
        ),
        Language::English => unreachable!(),
    }
}

fn byte_change(language: Language, changed: Option<bool>) -> &'static str {
    match (language, changed) {
        (Language::French, Some(true)) => "différente",
        (Language::French, Some(false)) => "identique",
        (Language::French, None) => "non établie",
        (Language::Spanish, Some(true)) => "diferente",
        (Language::Spanish, Some(false)) => "igual",
        (Language::Spanish, None) => "no establecida",
        (Language::SimplifiedChinese, Some(true)) => "已更改",
        (Language::SimplifiedChinese, Some(false)) => "未更改",
        (Language::SimplifiedChinese, None) => "未确定",
        (Language::English, Some(true)) => "changed",
        (Language::English, Some(false)) => "unchanged",
        (Language::English, None) => "not established",
    }
}

fn semantic_status_fr(status: &str) -> &str {
    match status {
        "compared" => "effectuée",
        "format_mismatch" => "formats différents",
        "unsupported" => "non prise en charge",
        _ => status,
    }
}

fn semantic_status_es(status: &str) -> &str {
    match status {
        "compared" => "realizada",
        "format_mismatch" => "formatos distintos",
        "unsupported" => "no compatible",
        _ => status,
    }
}

fn semantic_status_zh(status: &str) -> &str {
    match status {
        "compared" => "已完成",
        "format_mismatch" => "格式不同",
        "unsupported" => "不支持",
        _ => status,
    }
}

fn quoted(language: Language, value: Option<&str>) -> String {
    value.map_or_else(
        || match language {
            Language::French => "signature indisponible".to_owned(),
            Language::Spanish => "firma no disponible".to_owned(),
            Language::SimplifiedChinese => "签名不可用".to_owned(),
            Language::English => unreachable!(),
        },
        |value| format!("\"{}\"", super::display_safe(value)),
    )
}

fn plural_word<'a>(count: Option<u64>, singular: &'a str, plural: &'a str) -> &'a str {
    if count == Some(1) { singular } else { plural }
}

fn unknown(language: Language) -> &'static str {
    match language {
        Language::French => "inconnu",
        Language::Spanish => "desconocido",
        Language::SimplifiedChinese => "未知",
        Language::English => "unknown",
    }
}

fn unknown_size(language: Language) -> &'static str {
    match language {
        Language::French => "taille inconnue",
        Language::Spanish => "tamaño desconocido",
        Language::SimplifiedChinese => "大小未知",
        Language::English => "unknown size",
    }
}
