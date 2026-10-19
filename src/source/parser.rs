use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    ops::ControlFlow,
    os::unix::ffi::OsStrExt,
    path::Path,
};

use tree_sitter::{
    Language, Node, ParseOptions, ParseState, Parser, Query, QueryCursor, QueryCursorOptions,
    QueryCursorState, StreamingIterator,
};

use super::{
    MAX_SOURCE_FACT_BYTES, MAX_SOURCE_RECORDS, SourceLanguage, StructuralAction, StructuralChange,
    StructuralKind, StructuralStatus,
};
use crate::{
    error::{DiffError, Resource},
    path::RelPath,
};

const MAX_SOURCE_NODES: usize = 500_000;
const MAX_SOURCE_PARSE_CALLBACKS: u64 = 100_000;
const MAX_SOURCE_QUERY_CALLBACKS: u64 = 10_000;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Fact {
    kind: StructuralKind,
    name: String,
    signature: Option<String>,
}

pub(super) fn language_for_path(path: &Path) -> Option<SourceLanguage> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    match extension.as_str() {
        "rs" => Some(SourceLanguage::Rust),
        "c" | "h" => Some(SourceLanguage::C),
        "cc" | "cpp" | "cxx" | "hh" | "hpp" | "hxx" => Some(SourceLanguage::Cpp),
        "py" => Some(SourceLanguage::Python),
        _ => None,
    }
}

pub(super) struct Analyzer {
    parsers: BTreeMap<SourceLanguage, Parser>,
    queries: BTreeMap<SourceLanguage, Query>,
    budget: AnalysisBudget,
}

struct AnalysisBudget {
    fact_bytes: u64,
    work_limits: WorkLimits,
    work: WorkCounters,
}

#[derive(Clone, Copy)]
struct WorkLimits {
    parse_callbacks: u64,
    query_callbacks: u64,
}

struct WorkCounters {
    parse_callbacks: u64,
    query_callbacks: u64,
}

impl Analyzer {
    pub(super) fn new() -> Self {
        Self {
            parsers: BTreeMap::new(),
            queries: BTreeMap::new(),
            budget: AnalysisBudget {
                fact_bytes: 0,
                work_limits: WorkLimits {
                    parse_callbacks: MAX_SOURCE_PARSE_CALLBACKS,
                    query_callbacks: MAX_SOURCE_QUERY_CALLBACKS,
                },
                work: WorkCounters {
                    parse_callbacks: 0,
                    query_callbacks: 0,
                },
            },
        }
    }

    pub(super) fn compare(
        &mut self,
        language: SourceLanguage,
        old: &str,
        new: &str,
        path: &RelPath,
    ) -> Result<(StructuralStatus, Vec<StructuralChange>), DiffError> {
        let display_path = Path::new(OsStr::from_bytes(path.as_bytes()));
        self.prepare(language, display_path)?;
        let (parsers, queries, budget) = (&mut self.parsers, &self.queries, &mut self.budget);
        let parser = parsers
            .get_mut(&language)
            .ok_or_else(|| source_error(display_path, "parser state is unavailable".to_owned()))?;
        let query = queries
            .get(&language)
            .ok_or_else(|| source_error(display_path, "parser query is unavailable".to_owned()))?;
        let (old_has_errors, old_facts) = parse(parser, query, language, old, path, budget)?;
        let (new_has_errors, new_facts) = parse(parser, query, language, new, path, budget)?;
        if old_has_errors || new_has_errors {
            return Ok((StructuralStatus::SyntaxErrors, Vec::new()));
        }
        Ok((
            StructuralStatus::Complete,
            compare_facts(old_facts, new_facts),
        ))
    }

    fn prepare(&mut self, language: SourceLanguage, path: &Path) -> Result<(), DiffError> {
        let (grammar, tags_query) = grammar(language);
        if let std::collections::btree_map::Entry::Vacant(entry) = self.parsers.entry(language) {
            let mut parser = Parser::new();
            parser
                .set_language(&grammar)
                .map_err(|error| source_error(path, error.to_string()))?;
            entry.insert(parser);
        }
        if let std::collections::btree_map::Entry::Vacant(entry) = self.queries.entry(language) {
            let query = Query::new(&grammar, tags_query)
                .map_err(|error| source_error(path, error.to_string()))?;
            entry.insert(query);
        }
        Ok(())
    }
}

fn parse(
    parser: &mut Parser,
    query: &Query,
    language: SourceLanguage,
    source: &str,
    path: &RelPath,
    budget: &mut AnalysisBudget,
) -> Result<(bool, BTreeMap<Fact, usize>), DiffError> {
    let display_path = Path::new(OsStr::from_bytes(path.as_bytes())).to_path_buf();
    let source_bytes = source.as_bytes();
    let parse_callback_limit = budget.work_limits.parse_callbacks;
    let mut parse_limit_exceeded = false;
    let mut progress = |_: &ParseState| {
        if budget.work.parse_callbacks >= parse_callback_limit {
            parse_limit_exceeded = true;
            ControlFlow::Break(())
        } else {
            budget.work.parse_callbacks += 1;
            ControlFlow::Continue(())
        }
    };
    let mut input = |offset: usize, _| &source_bytes[offset..];
    let tree = parser.parse_with_options(
        &mut input,
        None,
        Some(ParseOptions::new().progress_callback(&mut progress)),
    );
    drop(progress);
    if parse_limit_exceeded {
        return Err(DiffError::LimitExceeded {
            resource: Resource::SourceParseWork,
            limit: parse_callback_limit,
        });
    }
    let tree =
        tree.ok_or_else(|| source_error(&display_path, "parser did not complete".to_owned()))?;
    let root = tree.root_node();
    if root.has_error() {
        return Ok((true, BTreeMap::new()));
    }

    let mut facts = BTreeMap::new();
    let mut record_count = 0;
    collect_imports_and_unions(
        language,
        root,
        source,
        &mut facts,
        &mut record_count,
        &mut budget.fact_bytes,
    )?;
    let mut cursor = QueryCursor::new();
    let query_callback_limit = budget.work_limits.query_callbacks;
    let mut query_limit_exceeded = false;
    let mut progress = |_: &QueryCursorState| {
        if budget.work.query_callbacks >= query_callback_limit {
            query_limit_exceeded = true;
            ControlFlow::Break(())
        } else {
            budget.work.query_callbacks += 1;
            ControlFlow::Continue(())
        }
    };
    let mut matches = cursor.matches_with_options(
        query,
        root,
        source.as_bytes(),
        QueryCursorOptions::new().progress_callback(&mut progress),
    );
    let mut seen_definitions = BTreeSet::new();
    while let Some(query_match) = matches.next() {
        let mut name = None;
        let mut definition = None;
        let mut kind = None;
        for capture in query_match.captures() {
            let Some(capture_name) = query.capture_names().get(capture.index as usize) else {
                continue;
            };
            if *capture_name == "name" {
                name = Some(capture.node);
            } else if let Some(capture_kind) = capture_name.strip_prefix("definition.") {
                definition = Some(capture.node);
                kind = kind_from_tag(capture_kind);
            }
        }
        let (Some(name_node), Some(definition_node), Some(tag_kind)) = (name, definition, kind)
        else {
            continue;
        };
        let Some(mut kind) = kind_from_definition(tag_kind, definition_node, name_node) else {
            continue;
        };
        let member = is_member(language, definition_node);
        if language == SourceLanguage::Rust && kind == StructuralKind::Method && !member {
            continue;
        }
        let Some(name_text) = node_text(name_node, source) else {
            continue;
        };
        let (qualified_name, is_c_member) =
            qualified_name(name_text, definition_node, language, source);
        if language == SourceLanguage::C && is_c_member {
            continue;
        }
        if kind == StructuralKind::Function && member {
            kind = StructuralKind::Method;
        }
        if !seen_definitions.insert(name_node.id()) {
            continue;
        }
        insert_fact(
            &mut facts,
            &mut record_count,
            &mut budget.fact_bytes,
            Fact {
                kind,
                name: qualified_name,
                signature: (matches!(kind, StructuralKind::Function | StructuralKind::Method))
                    .then(|| signature(definition_node, source))
                    .flatten(),
            },
        )?;
    }
    drop(matches);
    drop(progress);
    if query_limit_exceeded {
        return Err(DiffError::LimitExceeded {
            resource: Resource::SourceQueryWork,
            limit: query_callback_limit,
        });
    }
    Ok((false, facts))
}

fn grammar(language: SourceLanguage) -> (Language, &'static str) {
    match language {
        SourceLanguage::C => (tree_sitter_c::LANGUAGE.into(), tree_sitter_c::TAGS_QUERY),
        SourceLanguage::Cpp => (
            tree_sitter_cpp::LANGUAGE.into(),
            tree_sitter_cpp::TAGS_QUERY,
        ),
        SourceLanguage::Python => (
            tree_sitter_python::LANGUAGE.into(),
            tree_sitter_python::TAGS_QUERY,
        ),
        SourceLanguage::Rust => (
            tree_sitter_rust::LANGUAGE.into(),
            tree_sitter_rust::TAGS_QUERY,
        ),
    }
}

fn kind_from_tag(tag: &str) -> Option<StructuralKind> {
    Some(match tag {
        "function" => StructuralKind::Function,
        "method" => StructuralKind::Method,
        "class" => StructuralKind::Class,
        "interface" => StructuralKind::Interface,
        "type" => StructuralKind::Type,
        "constant" => StructuralKind::Constant,
        "module" => StructuralKind::Module,
        "macro" => StructuralKind::Macro,
        _ => return None,
    })
}

fn kind_from_definition(
    tag_kind: StructuralKind,
    definition: Node<'_>,
    name: Node<'_>,
) -> Option<StructuralKind> {
    let mut node = Some(name);
    while let Some(current) = node {
        let kind = match current.kind() {
            "struct_item" | "struct_specifier" => Some(StructuralKind::Struct),
            "union_item" | "union_specifier" => Some(StructuralKind::Union),
            "enum_item" | "enum_specifier" => Some(StructuralKind::Enum),
            "type_item" | "type_definition" => Some(StructuralKind::Type),
            "trait_item" => Some(StructuralKind::Interface),
            "class_specifier" => Some(StructuralKind::Class),
            "mod_item" => Some(StructuralKind::Module),
            "macro_definition" => Some(StructuralKind::Macro),
            _ => None,
        };
        if kind.is_some() {
            return kind;
        }
        if current == definition {
            break;
        }
        node = current.parent();
    }
    Some(tag_kind)
}

fn node_text(node: Node<'_>, source: &str) -> Option<String> {
    source
        .get(node.start_byte()..node.end_byte())
        .map(str::to_owned)
}

fn qualified_name(
    name: String,
    definition: Node<'_>,
    language: SourceLanguage,
    source: &str,
) -> (String, bool) {
    let mut parent = definition.parent();
    let mut scopes = Vec::new();
    let mut c_member = false;
    while let Some(node) = parent {
        c_member |= language == SourceLanguage::C && node.kind() == "struct_specifier";
        let scope = match (language, node.kind()) {
            (SourceLanguage::Rust, "mod_item" | "struct_item" | "enum_item" | "trait_item")
            | (
                SourceLanguage::Cpp,
                "namespace_definition" | "class_specifier" | "struct_specifier",
            )
            | (SourceLanguage::Python, "class_definition")
            | (SourceLanguage::C, "struct_specifier") => node
                .child_by_field_name("name")
                .and_then(|scope_node| node_text(scope_node, source)),
            (SourceLanguage::Rust, "impl_item") => node
                .child_by_field_name("type")
                .and_then(|type_node| node_text(type_node, source))
                .map(|type_name| {
                    match node
                        .child_by_field_name("trait")
                        .and_then(|trait_node| node_text(trait_node, source))
                    {
                        Some(trait_name) => format!("<{type_name} as {trait_name}>"),
                        None => type_name,
                    }
                }),
            _ => None,
        };
        if let Some(scope) = scope {
            scopes.push(scope);
        }
        parent = node.parent();
    }

    scopes.reverse();
    scopes.push(name);
    (scopes.join("::"), c_member)
}

fn is_member(language: SourceLanguage, definition: Node<'_>) -> bool {
    if language == SourceLanguage::Rust {
        let mut node = Some(definition);
        while let Some(current) = node {
            if current.kind() == "declaration_list" {
                return current
                    .parent()
                    .is_some_and(|owner| matches!(owner.kind(), "impl_item" | "trait_item"));
            }
            node = current.parent();
        }
        return false;
    }

    let mut parent = definition.parent();
    while let Some(node) = parent {
        match (language, node.kind()) {
            (SourceLanguage::Cpp, "field_declaration_list" | "class_specifier")
            | (SourceLanguage::Python, "class_definition") => return true,
            _ => {}
        }
        parent = node.parent();
    }
    false
}

fn signature(node: Node<'_>, source: &str) -> Option<String> {
    let mut container = node;
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        if matches!(
            candidate.kind(),
            "function_item"
                | "function_signature_item"
                | "function_definition"
                | "declaration"
                | "function_declaration"
        ) {
            container = candidate;
            break;
        }
        if matches!(
            candidate.kind(),
            "source_file" | "translation_unit" | "module"
        ) {
            break;
        }
        parent = candidate.parent();
    }
    let end_byte = container
        .child_by_field_name("body")
        .map_or(container.end_byte(), |body| body.start_byte());
    normalized_tokens(container, source, end_byte)
}

fn normalized_tokens(node: Node<'_>, source: &str, end_byte: usize) -> Option<String> {
    let mut pending = vec![node];
    let mut tokens = Vec::new();
    while let Some(current) = pending.pop() {
        if current.start_byte() >= end_byte || current.kind() == "comment" {
            continue;
        }
        if current.child_count() == 0 {
            if let Some(token) = source.get(current.start_byte()..current.end_byte()) {
                tokens.push(token);
            }
            continue;
        }
        for index in (0..current.child_count()).rev() {
            if let Some(child) = current.child(index) {
                pending.push(child);
            }
        }
    }
    (!tokens.is_empty()).then(|| tokens.join(" "))
}

fn collect_imports_and_unions(
    language: SourceLanguage,
    root: Node<'_>,
    source: &str,
    facts: &mut BTreeMap<Fact, usize>,
    record_count: &mut usize,
    fact_bytes: &mut u64,
) -> Result<(), DiffError> {
    let mut pending = vec![root];
    let mut visited = 0_usize;
    while let Some(node) = pending.pop() {
        visited = visited
            .checked_add(1)
            .ok_or_else(|| limit_error(ResourceLimit::Nodes))?;
        if visited > MAX_SOURCE_NODES {
            return Err(limit_error(ResourceLimit::Nodes));
        }
        if is_import(language, node.kind()) {
            let import = normalized_tokens(node, source, node.end_byte())
                .unwrap_or_else(|| source[node.start_byte()..node.end_byte()].to_owned());
            insert_fact(
                facts,
                record_count,
                fact_bytes,
                Fact {
                    kind: StructuralKind::Import,
                    name: import,
                    signature: None,
                },
            )?;
        }
        if matches!(language, SourceLanguage::C | SourceLanguage::Cpp)
            && node.kind() == "union_specifier"
            && let Some(name) = node.child_by_field_name("name")
            && let Some(name) = node_text(name, source)
        {
            insert_fact(
                facts,
                record_count,
                fact_bytes,
                Fact {
                    kind: StructuralKind::Union,
                    name,
                    signature: None,
                },
            )?;
        }
        for index in (0..node.child_count()).rev() {
            if let Some(child) = node.child(index) {
                pending.push(child);
            }
        }
    }
    Ok(())
}

fn is_import(language: SourceLanguage, kind: &str) -> bool {
    match language {
        SourceLanguage::C | SourceLanguage::Cpp => kind == "preproc_include",
        SourceLanguage::Python => matches!(kind, "import_statement" | "import_from_statement"),
        SourceLanguage::Rust => kind == "use_declaration",
    }
}

fn compare_facts(old: BTreeMap<Fact, usize>, new: BTreeMap<Fact, usize>) -> Vec<StructuralChange> {
    let mut old_groups = group_facts(old);
    let mut new_groups = group_facts(new);
    let mut keys: BTreeSet<_> = old_groups.keys().cloned().collect();
    keys.extend(new_groups.keys().cloned());
    let mut changes = Vec::new();
    for key in keys {
        let old_signatures = old_groups.remove(&key).unwrap_or_default();
        let new_signatures = new_groups.remove(&key).unwrap_or_default();
        let (old_unmatched, new_unmatched) =
            subtract_sorted_multisets(old_signatures, new_signatures);
        let paired = old_unmatched.len().min(new_unmatched.len());
        for index in 0..paired {
            changes.push(StructuralChange {
                action: StructuralAction::SignatureChanged,
                kind: key.0,
                name: key.1.clone(),
                before_signature: old_unmatched[index].clone(),
                after_signature: new_unmatched[index].clone(),
            });
        }
        for signature in old_unmatched.into_iter().skip(paired) {
            changes.push(StructuralChange {
                action: StructuralAction::Removed,
                kind: key.0,
                name: key.1.clone(),
                before_signature: signature,
                after_signature: None,
            });
        }
        for signature in new_unmatched.into_iter().skip(paired) {
            changes.push(StructuralChange {
                action: StructuralAction::Added,
                kind: key.0,
                name: key.1.clone(),
                before_signature: None,
                after_signature: signature,
            });
        }
    }
    changes.sort_by(|left, right| {
        (
            left.kind,
            &left.name,
            left.action,
            &left.before_signature,
            &left.after_signature,
        )
            .cmp(&(
                right.kind,
                &right.name,
                right.action,
                &right.before_signature,
                &right.after_signature,
            ))
    });
    changes
}

fn subtract_sorted_multisets<T: Ord>(old: Vec<T>, new: Vec<T>) -> (Vec<T>, Vec<T>) {
    let mut old = old.into_iter().peekable();
    let mut new = new.into_iter().peekable();
    let mut old_only = Vec::new();
    let mut new_only = Vec::new();

    loop {
        match (old.peek(), new.peek()) {
            (Some(old_item), Some(new_item)) => match old_item.cmp(new_item) {
                Ordering::Less => {
                    if let Some(item) = old.next() {
                        old_only.push(item);
                    }
                }
                Ordering::Greater => {
                    if let Some(item) = new.next() {
                        new_only.push(item);
                    }
                }
                Ordering::Equal => {
                    old.next();
                    new.next();
                }
            },
            (Some(_), None) => {
                old_only.extend(old);
                break;
            }
            (None, Some(_)) => {
                new_only.extend(new);
                break;
            }
            (None, None) => break,
        }
    }

    (old_only, new_only)
}

fn group_facts(
    facts: BTreeMap<Fact, usize>,
) -> BTreeMap<(StructuralKind, String), Vec<Option<String>>> {
    let mut groups = BTreeMap::new();
    for (fact, count) in facts {
        let signatures = groups
            .entry((fact.kind, fact.name))
            .or_insert_with(Vec::new);
        for _ in 0..count {
            signatures.push(fact.signature.clone());
        }
    }
    for signatures in groups.values_mut() {
        signatures.sort();
    }
    groups
}

fn check_record_count(count: usize) -> Result<(), DiffError> {
    if count as u64 > MAX_SOURCE_RECORDS {
        return Err(limit_error(ResourceLimit::Records));
    }
    Ok(())
}

fn insert_fact(
    facts: &mut BTreeMap<Fact, usize>,
    record_count: &mut usize,
    fact_bytes: &mut u64,
    fact: Fact,
) -> Result<(), DiffError> {
    // Charge duplicate facts because comparison expands them into separate output rows.
    let signature_bytes = fact.signature.as_ref().map_or(0, String::len);
    let byte_count = fact
        .name
        .len()
        .checked_add(signature_bytes)
        .and_then(|count| u64::try_from(count).ok())
        .ok_or_else(|| limit_error(ResourceLimit::FactBytes))?;
    let next_fact_bytes = fact_bytes
        .checked_add(byte_count)
        .filter(|bytes| *bytes <= MAX_SOURCE_FACT_BYTES)
        .ok_or_else(|| limit_error(ResourceLimit::FactBytes))?;
    let next_record_count = record_count
        .checked_add(1)
        .ok_or_else(|| limit_error(ResourceLimit::Records))?;
    check_record_count(next_record_count)?;

    let count = facts.entry(fact).or_default();
    *count = count
        .checked_add(1)
        .ok_or_else(|| limit_error(ResourceLimit::Records))?;
    *record_count = next_record_count;
    *fact_bytes = next_fact_bytes;
    Ok(())
}

enum ResourceLimit {
    Nodes,
    Records,
    FactBytes,
}

fn limit_error(resource: ResourceLimit) -> DiffError {
    let (resource, limit) = match resource {
        ResourceLimit::Nodes => (crate::error::Resource::SourceNodes, MAX_SOURCE_NODES as u64),
        ResourceLimit::Records => (crate::error::Resource::SourceRecords, MAX_SOURCE_RECORDS),
        ResourceLimit::FactBytes => (
            crate::error::Resource::SourceFactBytes,
            MAX_SOURCE_FACT_BYTES,
        ),
    };
    DiffError::LimitExceeded { resource, limit }
}

fn source_error(path: &std::path::Path, message: String) -> DiffError {
    DiffError::SourceAnalysis {
        path: path.to_path_buf(),
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, cmp::Ordering, rc::Rc};

    #[test]
    fn file_extensions_only_select_a_parser_hint() {
        assert_eq!(
            language_for_path(Path::new("firmware.C")),
            Some(SourceLanguage::C)
        );
        assert_eq!(
            language_for_path(Path::new("firmware.hpp")),
            Some(SourceLanguage::Cpp)
        );
        assert_eq!(
            language_for_path(Path::new("main.py")),
            Some(SourceLanguage::Python)
        );
        assert_eq!(language_for_path(Path::new("README")), None);
    }

    #[test]
    fn syntax_errors_do_not_produce_structural_changes() {
        let path = RelPath::new(b"bad.rs".to_vec()).unwrap();
        let mut analyzer = Analyzer::new();

        let (status, changes) = analyzer
            .compare(SourceLanguage::Rust, "fn valid() {}", "fn broken( {", &path)
            .unwrap();

        assert_eq!(status, StructuralStatus::SyntaxErrors);
        assert!(changes.is_empty());
    }

    #[test]
    fn trait_implementation_methods_keep_trait_identity() {
        let path = RelPath::new(b"src/lib.rs".to_vec()).unwrap();
        let mut analyzer = Analyzer::new();

        let (status, changes) = analyzer
            .compare(
                SourceLanguage::Rust,
                "trait First { fn run(&self); }\nstruct Item;\nimpl First for Item { fn run(&self) {} }",
                "trait Second { fn run(&self); }\nstruct Item;\nimpl Second for Item { fn run(&self) {} }",
                &path,
            )
            .unwrap();

        assert_eq!(status, StructuralStatus::Complete);
        assert!(changes.iter().any(|change| {
            change.action == StructuralAction::Removed
                && change.name == "<Item as First>::run"
                && change.before_signature.is_some()
        }));
        assert!(changes.iter().any(|change| {
            change.action == StructuralAction::Added
                && change.name == "<Item as Second>::run"
                && change.after_signature.is_some()
        }));
    }

    #[test]
    fn duplicate_signature_matching_uses_linear_order_comparisons() {
        const RECORDS: usize = 25_000;
        let comparisons = Rc::new(ComparisonCounts::default());
        let signatures = || {
            (0..RECORDS)
                .map(|_| CountedOrder {
                    value: 0,
                    comparisons: Rc::clone(&comparisons),
                })
                .collect()
        };

        let (old_only, new_only) = subtract_sorted_multisets(signatures(), signatures());

        assert!(old_only.is_empty());
        assert!(new_only.is_empty());
        assert_eq!(comparisons.order.get(), RECORDS);
        assert_eq!(comparisons.equality.get(), 0);
    }

    #[test]
    fn disjoint_signature_matching_does_not_rescan_the_new_group() {
        const RECORDS: usize = 10_000;
        let comparisons = Rc::new(ComparisonCounts::default());
        let signatures = |range: std::ops::Range<usize>| {
            range
                .map(|value| CountedOrder {
                    value,
                    comparisons: Rc::clone(&comparisons),
                })
                .collect()
        };

        let (old_only, new_only) =
            subtract_sorted_multisets(signatures(0..RECORDS), signatures(RECORDS..RECORDS * 2));

        assert_eq!(old_only.len(), RECORDS);
        assert_eq!(new_only.len(), RECORDS);
        assert!(
            old_only
                .iter()
                .enumerate()
                .all(|(value, item)| item.value == value)
        );
        assert!(
            new_only
                .iter()
                .enumerate()
                .all(|(value, item)| item.value == RECORDS + value)
        );
        assert_eq!(comparisons.order.get(), RECORDS);
        assert_eq!(comparisons.equality.get(), 0);
    }

    #[test]
    fn duplicate_facts_keep_their_occurrence_counts_when_compared() {
        let fact = |signature: &str| Fact {
            kind: StructuralKind::Function,
            name: "run".to_owned(),
            signature: Some(signature.to_owned()),
        };
        let old = BTreeMap::from([(fact("run(a)"), 2), (fact("run(b)"), 1)]);
        let new = BTreeMap::from([(fact("run(a)"), 1), (fact("run(c)"), 2)]);

        let changes = compare_facts(old, new);

        assert_eq!(changes.len(), 2);
        for (change, before) in changes.iter().zip(["run(a)", "run(b)"]) {
            assert_eq!(change.action, StructuralAction::SignatureChanged);
            assert_eq!(change.before_signature.as_deref(), Some(before));
            assert_eq!(change.after_signature.as_deref(), Some("run(c)"));
        }
    }

    #[derive(Default)]
    struct ComparisonCounts {
        equality: Cell<usize>,
        order: Cell<usize>,
    }

    struct CountedOrder {
        value: usize,
        comparisons: Rc<ComparisonCounts>,
    }

    impl PartialEq for CountedOrder {
        fn eq(&self, other: &Self) -> bool {
            self.comparisons
                .equality
                .set(self.comparisons.equality.get() + 1);
            self.value == other.value
        }
    }

    impl Eq for CountedOrder {}

    impl PartialOrd for CountedOrder {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for CountedOrder {
        fn cmp(&self, other: &Self) -> Ordering {
            self.comparisons.order.set(self.comparisons.order.get() + 1);
            self.value.cmp(&other.value)
        }
    }

    #[test]
    fn fact_extraction_stops_at_the_syntax_node_limit() {
        let path = RelPath::new(b"large.rs".to_vec()).unwrap();
        let source = "fn item() {}\n".repeat(MAX_SOURCE_NODES / 4);
        let mut analyzer = Analyzer::new();

        let error = analyzer
            .compare(SourceLanguage::Rust, "", &source, &path)
            .unwrap_err();

        assert!(matches!(
            error,
            DiffError::LimitExceeded {
                resource: crate::error::Resource::SourceNodes,
                limit,
            }
                if limit == MAX_SOURCE_NODES as u64
        ));
    }

    #[test]
    fn parsing_stops_at_its_work_limit_before_fact_extraction() {
        let path = RelPath::new(b"large.rs".to_vec()).unwrap();
        let source = "fn item() {}\n".repeat(1_000);
        let mut analyzer = Analyzer::new();
        analyzer.budget.work_limits.parse_callbacks = 0;

        let error = analyzer
            .compare(SourceLanguage::Rust, "", &source, &path)
            .unwrap_err();

        assert!(matches!(
            error,
            DiffError::LimitExceeded {
                resource: crate::error::Resource::SourceParseWork,
                limit: 0,
            }
        ));
    }

    #[test]
    fn querying_stops_at_its_work_limit_without_returning_partial_facts() {
        let path = RelPath::new(b"large.rs".to_vec()).unwrap();
        let source = "fn item() {}\n".repeat(1_000);
        let mut analyzer = Analyzer::new();
        analyzer.budget.work_limits.query_callbacks = 0;

        let result = analyzer.compare(SourceLanguage::Rust, "", &source, &path);

        let Err(error) = result else {
            panic!("query work limit should fail the analysis");
        };
        assert!(matches!(
            error,
            DiffError::LimitExceeded {
                resource: crate::error::Resource::SourceQueryWork,
                limit: 0,
            }
        ));
    }
}
