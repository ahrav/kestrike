//! Listed enums and the construction sites of their variants.
//!
//! A listed enum has a name ending in one of [`ENDINGS`] and a declaring
//! file under one of [`FAMILIES`]. A construction site is an expression that
//! names a variant; each site has a [`Form`].

use std::collections::BTreeMap;

use proc_macro2::{LineColumn, TokenStream, TokenTree};
use syn::ext::IdentExt;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};

use crate::cfg::{gated, sets_path};

pub const FAMILIES: [&str; 3] = ["storage", "net", "failover"];

pub const ENDINGS: [&str; 6] = [
    "Error",
    "Refusal",
    "Refused",
    "Rejection",
    "Reason",
    "Failure",
];

/// The methods that evaluate their arguments on every call. A site in an
/// argument of one of them has [`Form::Eager`].
const EAGER: [&str; 7] = [
    "ok_or",
    "unwrap_or",
    "map_or",
    "then_some",
    "or",
    "and",
    "xor",
];

/// `x.ok_or(E::V)?` and `x.map_err(E::V)?` return through their `?` exactly
/// when the argument became the error, so that `?` counts the argument's
/// error returns. The `?` after any other call gives its arguments no
/// chain. The rule reads the method's name alone and assumes the semantics
/// of `Option::ok_or` and `Result::map_err`.
const CHAINED: [&str; 2] = ["ok_or", "map_err"];

/// These methods run their closure exactly when they return an error, so a
/// trailing `?` counts closure executions when it propagates errors. The
/// rule reads the method's name alone and assumes the semantics of
/// `Result::map_err` and `Option::ok_or_else`.
const ERROR_PATH: [&str; 2] = ["map_err", "ok_or_else"];

const COMPARING: [&str; 4] = [
    "assert_eq",
    "assert_ne",
    "debug_assert_eq",
    "debug_assert_ne",
];

/// These macros match their first argument against a pattern in the second.
const MATCHING: [&str; 3] = ["matches", "assert_matches", "debug_assert_matches"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    Unit,
    Tuple,
    Struct,
}

#[derive(Debug)]
pub struct Variant {
    pub name: String,
    pub shape: Shape,
}

#[derive(Debug)]
pub struct Enum {
    /// The module path from the crate root, then the name, joined by `::`.
    pub path: String,
    pub name: String,
    pub module: Vec<String>,
    /// The declaring file, relative to the source root.
    pub file: String,
    pub variants: Vec<Variant>,
}

impl Enum {
    /// The family directory of a listed enum, or `None` for an enum outside
    /// the list.
    pub fn family(&self) -> Option<&'static str> {
        let directory = self.file.split('/').next()?;
        let family = FAMILIES.into_iter().find(|family| *family == directory)?;
        ENDINGS
            .iter()
            .any(|ending| self.name.ends_with(ending))
            .then_some(family)
    }
}

/// `Form` classifies variant references by syntax or use context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Form {
    Path,
    Call,
    Struct,
    /// A tuple variant passed as a function value, as in `.map_err(E::V)`.
    Value,
    /// An argument of an [`EAGER`] method.
    Eager,
    /// A site inside an operand of `==` or `!=` or one of the first two
    /// arguments of a [`COMPARING`] macro, call arguments and method
    /// receivers within the operand included. The arguments of a
    /// [`CHAINED`] or [`ERROR_PATH`] call that a `?` ends supply the error
    /// that leaves through the `?`, so they keep their own form.
    Compare,
    /// An initializer of a `const` or `static` item.
    Table,
}

impl Form {
    pub fn constructs(self) -> bool {
        !matches!(self, Self::Compare | Self::Table)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Call => "call",
            Self::Struct => "struct",
            Self::Value => "value",
            Self::Eager => "eager",
            Self::Compare => "compare",
            Self::Table => "table",
        }
    }
}

/// A line and a 1-based column, as the coverage export counts them.
pub type At = (usize, usize);

#[derive(Clone, Debug)]
pub struct Site {
    /// The index of the site's enum in [`Source::enums`].
    pub owner: usize,
    pub variant: String,
    pub file: String,
    /// The enclosing function as `Type::name` or `name`, or the `const` or
    /// `static` item's name.
    pub function: String,
    pub form: Form,
    pub at: At,
    /// The `?` whose operand is the [`CHAINED`] method call that takes the
    /// site as an argument. A block, `if` or match arm inside the argument
    /// keeps that `?`. A closure, another call, another `?`, a `return` and
    /// a `break` that leaves the argument start no chain.
    pub chain: Option<At>,
    /// True when the site inherits an eager argument's `?` through a block,
    /// `if` or match arm. The shared `?` count can include errors from
    /// another branch.
    pub branch: bool,
    /// The `?` whose operand is an [`ERROR_PATH`] call that takes a closure
    /// containing the site. A zero count at that `?` means the closure never
    /// ran.
    pub outer: Option<At>,
}

#[derive(Debug, Default)]
pub struct Source {
    pub enums: Vec<Enum>,
    pub sites: Vec<Site>,
    /// Paths for which variant resolution leaves two or more candidate
    /// enums.
    pub ambiguous: Vec<String>,
}

impl Source {
    /// Returns indices into [`Source::enums`] for `family`, ordered by enum
    /// path.
    pub fn listed(&self, family: &str) -> Vec<usize> {
        let mut found: Vec<usize> = (0..self.enums.len())
            .filter(|&index| self.enums[index].family() == Some(family))
            .collect();
        found.sort_by(|&a, &b| self.enums[a].path.cmp(&self.enums[b].path));
        found
    }

    pub fn sites_of<'a>(
        &'a self,
        owner: usize,
        variant: &'a str,
    ) -> impl Iterator<Item = &'a Site> {
        self.sites
            .iter()
            .filter(move |site| site.owner == owner && site.variant == variant)
    }
}

struct Parsed {
    rel: String,
    module: Vec<String>,
    text: String,
    ast: syn::File,
}

/// `Read` maps a path relative to the source root to its text, `Ok(None)`
/// for an absent file, or an error for a file that exists and cannot be
/// read as text.
pub type Read<'a> = dyn Fn(&str) -> Result<Option<String>, String> + 'a;

/// `parse` starts at `mod.rs` and follows `mod` declarations for which
/// `gated(&declaration.attrs)` returns `false`.
///
/// # Errors
///
/// `parse` returns `Err` when it cannot read or parse a file the walk
/// needs or when module file resolution fails.
pub fn parse(read: &Read) -> Result<Source, String> {
    let mut parsed = Vec::new();
    let root = read("mod.rs")?.ok_or("mod.rs: absent")?;
    walk(read, "mod.rs", root, &[], &mut Vec::new(), &mut parsed)?;
    parsed.sort_by(|a, b| a.rel.cmp(&b.rel));
    let mut source = Source::default();
    for file in &parsed {
        let mut declarations = Declarations {
            file: &file.rel,
            module: file.module.clone(),
            out: &mut source.enums,
            problems: Vec::new(),
        };
        declarations.visit_file(&file.ast);
        if let Some(problem) = declarations.problems.first() {
            return Err(problem.clone());
        }
    }
    let mut paths: BTreeMap<&str, &str> = BTreeMap::new();
    for declared in source.enums.iter().filter(|e| e.family().is_some()) {
        if let Some(first) = paths.insert(&declared.path, &declared.file) {
            return Err(format!(
                "{} is declared twice ({first}, {}); rename one enum or keep one declaration",
                declared.path, declared.file
            ));
        }
    }
    for file in &parsed {
        let mut sites = Sites::new(&source.enums, file);
        sites.visit_file(&file.ast);
        source.sites.append(&mut sites.out);
        source.ambiguous.append(&mut sites.ambiguous);
    }
    Ok(source)
}

fn walk(
    read: &Read,
    rel: &str,
    text: String,
    module: &[String],
    active: &mut Vec<String>,
    parsed: &mut Vec<Parsed>,
) -> Result<(), String> {
    if active.iter().any(|file| file == rel) {
        return Err(format!(
            "{rel}: a `#[path]` declaration re-enters this file"
        ));
    }
    if parsed.iter().any(|file| file.rel == rel) {
        return Ok(());
    }
    let ast = syn::parse_file(&text).map_err(|error| format!("{rel}: {error}"))?;
    if gated(&ast.attrs) {
        return Ok(());
    }
    let directory = parent(rel);
    let stem = rel
        .rsplit('/')
        .next()
        .unwrap_or(rel)
        .trim_end_matches(".rs");
    let children = if stem == "mod" {
        directory.clone()
    } else {
        join(&directory, stem)
    };
    active.push(rel.to_owned());
    let base = Base {
        directory: &directory,
        children: &children,
        inline: false,
    };
    let walked = declared(read, &ast.items, &base, module, active, parsed);
    active.pop();
    walked?;
    parsed.push(Parsed {
        rel: rel.to_owned(),
        module: module.to_vec(),
        text,
        ast,
    });
    Ok(())
}

struct Base<'a> {
    directory: &'a str,
    children: &'a str,
    inline: bool,
}

fn declared(
    read: &Read,
    items: &[syn::Item],
    base: &Base,
    module: &[String],
    active: &mut Vec<String>,
    parsed: &mut Vec<Parsed>,
) -> Result<(), String> {
    for item in items {
        let syn::Item::Mod(declaration) = item else {
            continue;
        };
        if gated(&declaration.attrs) {
            continue;
        }
        let name = declaration.ident.unraw().to_string();
        let mut path = module.to_vec();
        path.push(name.clone());
        let inner = join(base.children, &name);
        if let Some((_, items)) = &declaration.content {
            let nested = Base {
                directory: base.directory,
                children: &inner,
                inline: true,
            };
            declared(read, items, &nested, &path, active, parsed)?;
            continue;
        }
        let at = join(base.directory, "");
        if sets_path(&declaration.attrs) {
            return Err(format!(
                "{at}: `mod {name}` takes its file from a `cfg_attr` the build model cannot rule out"
            ));
        }
        let (rel, text) = match path_attribute(&declaration.attrs) {
            Some(_) if base.inline => {
                return Err(format!(
                    "{at}: `mod {name}` names its file by `#[path]` inside an inline module"
                ));
            }
            Some(target) => {
                let rel = resolve_path(base.directory, &target).ok_or_else(|| {
                    format!("{at}: `mod {name}` names {target:?} outside the source root")
                })?;
                let text = read(&rel)?.ok_or_else(|| format!("{rel}: absent"))?;
                (rel, text)
            }
            None => {
                let mut found = Vec::new();
                for candidate in [format!("{inner}.rs"), join(&inner, "mod.rs")] {
                    if let Some(text) = read(&candidate)? {
                        found.push((candidate, text));
                    }
                }
                match <[_; 1]>::try_from(found) {
                    Ok([file]) => file,
                    Err(found) if found.is_empty() => {
                        return Err(format!("{at}: no file for `mod {name}`"));
                    }
                    Err(_) => return Err(format!("{at}: two files for `mod {name}`")),
                }
            }
        };
        walk(read, &rel, text, &path, active, parsed)?;
    }
    Ok(())
}

fn path_attribute(attributes: &[syn::Attribute]) -> Option<String> {
    attributes.iter().find_map(|attribute| {
        let syn::Meta::NameValue(pair) = &attribute.meta else {
            return None;
        };
        let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(text),
            ..
        }) = &pair.value
        else {
            return None;
        };
        pair.path.is_ident("path").then(|| text.value())
    })
}

fn parent(rel: &str) -> String {
    rel.rsplit_once('/')
        .map_or(String::new(), |(directory, _)| directory.to_owned())
}

fn join(directory: &str, name: &str) -> String {
    if directory.is_empty() {
        name.to_owned()
    } else {
        format!("{directory}/{name}")
    }
}

fn resolve_path(directory: &str, target: &str) -> Option<String> {
    if target.starts_with('/') || target.starts_with('\\') || target.contains(':') {
        return None;
    }
    let mut parts: Vec<&str> = directory
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            part => parts.push(part),
        }
    }
    Some(parts.join("/"))
}

fn item_attributes(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::ExternCrate(item) => &item.attrs,
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::ForeignMod(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::TraitAlias(item) => &item.attrs,
        syn::Item::Type(item) => &item.attrs,
        syn::Item::Union(item) => &item.attrs,
        syn::Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

fn impl_item_attributes(item: &syn::ImplItem) -> &[syn::Attribute] {
    match item {
        syn::ImplItem::Const(item) => &item.attrs,
        syn::ImplItem::Fn(item) => &item.attrs,
        syn::ImplItem::Type(item) => &item.attrs,
        syn::ImplItem::Macro(item) => &item.attrs,
        _ => &[],
    }
}

fn trait_item_attributes(item: &syn::TraitItem) -> &[syn::Attribute] {
    match item {
        syn::TraitItem::Const(item) => &item.attrs,
        syn::TraitItem::Fn(item) => &item.attrs,
        syn::TraitItem::Type(item) => &item.attrs,
        syn::TraitItem::Macro(item) => &item.attrs,
        _ => &[],
    }
}

struct Declarations<'a> {
    file: &'a str,
    module: Vec<String>,
    out: &'a mut Vec<Enum>,
    problems: Vec<String>,
}

impl<'ast> Visit<'ast> for Declarations<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if !gated(item_attributes(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if let Some((_, items)) = &item.content {
            self.module.push(item.ident.unraw().to_string());
            for item in items {
                self.visit_item(item);
            }
            self.module.pop();
        }
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        let name = item.ident.unraw().to_string();
        let mut path = self.module.clone();
        path.push(name.clone());
        let path = path.join("::");
        let mut variants: Vec<Variant> = Vec::new();
        for variant in item
            .variants
            .iter()
            .filter(|variant| !gated(&variant.attrs))
        {
            let shape = match variant.fields {
                syn::Fields::Unit => Shape::Unit,
                syn::Fields::Unnamed(_) => Shape::Tuple,
                syn::Fields::Named(_) => Shape::Struct,
            };
            let name = variant.ident.unraw().to_string();
            match variants.iter().find(|known| known.name == name) {
                Some(known) if known.shape != shape => self.problems.push(format!(
                    "{}: {path}::{name} is declared with two shapes",
                    self.file
                )),
                Some(_) => {}
                None => variants.push(Variant { name, shape }),
            }
        }
        self.out.push(Enum {
            path,
            name,
            module: self.module.clone(),
            file: self.file.to_owned(),
            variants,
        });
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        if !gated(impl_item_attributes(item)) {
            visit::visit_impl_item(self, item);
        }
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        if !gated(trait_item_attributes(item)) {
            visit::visit_trait_item(self, item);
        }
    }

    fn visit_stmt(&mut self, statement: &'ast syn::Stmt) {
        if !statement_gated(statement) {
            visit::visit_stmt(self, statement);
        }
    }

    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        if !gated(&arm.attrs) {
            visit::visit_arm(self, arm);
        }
    }

    fn visit_field_value(&mut self, field: &'ast syn::FieldValue) {
        if !gated(&field.attrs) {
            visit::visit_field_value(self, field);
        }
    }
}

fn statement_gated(statement: &syn::Stmt) -> bool {
    match statement {
        syn::Stmt::Local(local) => gated(&local.attrs),
        syn::Stmt::Macro(statement) => gated(&statement.attrs),
        syn::Stmt::Expr(expression, _) => gated(expression_attributes(expression)),
        syn::Stmt::Item(_) => false,
    }
}

fn expression_attributes(expression: &syn::Expr) -> &[syn::Attribute] {
    match expression {
        syn::Expr::Array(expression) => &expression.attrs,
        syn::Expr::Assign(expression) => &expression.attrs,
        syn::Expr::Async(expression) => &expression.attrs,
        syn::Expr::Await(expression) => &expression.attrs,
        syn::Expr::Binary(expression) => &expression.attrs,
        syn::Expr::Block(expression) => &expression.attrs,
        syn::Expr::Break(expression) => &expression.attrs,
        syn::Expr::Call(expression) => &expression.attrs,
        syn::Expr::Cast(expression) => &expression.attrs,
        syn::Expr::Closure(expression) => &expression.attrs,
        syn::Expr::Const(expression) => &expression.attrs,
        syn::Expr::Continue(expression) => &expression.attrs,
        syn::Expr::Field(expression) => &expression.attrs,
        syn::Expr::ForLoop(expression) => &expression.attrs,
        syn::Expr::Group(expression) => &expression.attrs,
        syn::Expr::If(expression) => &expression.attrs,
        syn::Expr::Index(expression) => &expression.attrs,
        syn::Expr::Let(expression) => &expression.attrs,
        syn::Expr::Lit(expression) => &expression.attrs,
        syn::Expr::Loop(expression) => &expression.attrs,
        syn::Expr::Macro(expression) => &expression.attrs,
        syn::Expr::Match(expression) => &expression.attrs,
        syn::Expr::MethodCall(expression) => &expression.attrs,
        syn::Expr::Paren(expression) => &expression.attrs,
        syn::Expr::Path(expression) => &expression.attrs,
        syn::Expr::Range(expression) => &expression.attrs,
        syn::Expr::Reference(expression) => &expression.attrs,
        syn::Expr::Repeat(expression) => &expression.attrs,
        syn::Expr::Return(expression) => &expression.attrs,
        syn::Expr::Struct(expression) => &expression.attrs,
        syn::Expr::Try(expression) => &expression.attrs,
        syn::Expr::TryBlock(expression) => &expression.attrs,
        syn::Expr::Tuple(expression) => &expression.attrs,
        syn::Expr::Unary(expression) => &expression.attrs,
        syn::Expr::Unsafe(expression) => &expression.attrs,
        syn::Expr::While(expression) => &expression.attrs,
        syn::Expr::Yield(expression) => &expression.attrs,
        _ => &[],
    }
}

/// `Frame` maps the local names of one scope's ungated `use` items to their
/// source paths and lists the paths the scope imports by glob. A module
/// frame sets `inherits` exactly when an ungated `use` imports `super::*`.
#[derive(Default)]
struct Frame {
    named: BTreeMap<String, Vec<Vec<String>>>,
    globs: Vec<Vec<String>>,
    module: bool,
    inherits: bool,
}

impl Frame {
    fn of<'a>(items: impl Iterator<Item = &'a syn::Item>, module: bool) -> Self {
        let mut frame = Self {
            module,
            ..Self::default()
        };
        for item in items {
            if let syn::Item::Use(item) = item
                && !gated(&item.attrs)
            {
                frame.add(&item.tree, &mut Vec::new());
            }
        }
        frame.inherits = module && frame.globs.iter().any(|glob| glob == &["super"]);
        frame
    }

    fn add(&mut self, tree: &syn::UseTree, prefix: &mut Vec<String>) {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.unraw().to_string());
                self.add(&path.tree, prefix);
                prefix.pop();
            }
            syn::UseTree::Name(name) => self.name(prefix, &name.ident, None),
            syn::UseTree::Rename(rename) => self.name(prefix, &rename.ident, Some(&rename.rename)),
            syn::UseTree::Glob(_) => self.globs.push(prefix.clone()),
            syn::UseTree::Group(group) => {
                for tree in &group.items {
                    self.add(tree, prefix);
                }
            }
        }
    }

    fn name(&mut self, prefix: &[String], ident: &syn::Ident, rename: Option<&syn::Ident>) {
        let mut path = prefix.to_vec();
        if ident != "self" {
            path.push(ident.unraw().to_string());
        }
        let Some(last) = path.last() else {
            return;
        };
        let local = rename.map_or_else(|| last.clone(), |rename| rename.unraw().to_string());
        let paths = self.named.entry(local).or_default();
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Path,
    Call,
    Struct,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    Block,
    Closure,
}

/// What a call's arguments take from the `?` that follows the call.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ends {
    /// No `?` follows the call.
    Open,
    /// A `?` follows a call whose arguments do not supply its error.
    Opaque,
    /// The `?` at this position follows a [`CHAINED`] method call.
    Chain(At),
}

/// A loop, or a labeled block, entered since the current argument began.
struct Target {
    label: Option<String>,
    looping: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ItemKind {
    Function,
    Table,
}

struct Sites<'a> {
    enums: &'a [Enum],
    file: &'a str,
    frames: Vec<Frame>,
    module: Vec<String>,
    self_types: Vec<Option<String>>,
    owners: Vec<String>,
    functions: Vec<String>,
    compare: u32,
    eager: u32,
    table: u32,
    branch: u32,
    chain: Vec<Option<At>>,
    outer: Vec<Option<At>>,
    targets: Vec<Target>,
    lines: Vec<&'a str>,
    out: Vec<Site>,
    ambiguous: Vec<String>,
}

impl<'a> Sites<'a> {
    fn new(enums: &'a [Enum], file: &'a Parsed) -> Self {
        Self {
            enums,
            file: &file.rel,
            frames: Vec::new(),
            module: file.module.clone(),
            self_types: Vec::new(),
            owners: Vec::new(),
            functions: Vec::new(),
            compare: 0,
            eager: 0,
            table: 0,
            branch: 0,
            chain: Vec::new(),
            outer: Vec::new(),
            targets: Vec::new(),
            lines: file.text.lines().collect(),
            out: Vec::new(),
            ambiguous: Vec::new(),
        }
    }

    fn framed(&mut self, frame: Frame, body: impl FnOnce(&mut Self)) {
        self.frames.push(frame);
        body(self);
        self.frames.pop();
    }

    /// `lookup` returns all source paths for `local` from the innermost
    /// visible frame that binds `local`.
    fn lookup(&self, local: &str) -> Option<&[Vec<String>]> {
        for frame in self.frames.iter().rev() {
            if let Some(paths) = frame.named.get(local) {
                return Some(paths);
            }
            if frame.module && !frame.inherits {
                break;
            }
        }
        None
    }

    fn globs(&self) -> Vec<&[String]> {
        let mut globs = Vec::new();
        for frame in self.frames.iter().rev() {
            globs.extend(frame.globs.iter().map(Vec::as_slice));
            if frame.module && !frame.inherits {
                break;
            }
        }
        globs
    }

    fn at(&self, start: LineColumn) -> At {
        let line = self
            .lines
            .get(start.line.wrapping_sub(1))
            .copied()
            .unwrap_or_default();
        let byte = line
            .char_indices()
            .nth(start.column)
            .map_or(line.len(), |(offset, _)| offset);
        (start.line, byte + 1)
    }

    /// The module a qualifier starting with `crate`, `self` or `super`
    /// names, relative to the current module.
    fn absolute(&self, qualifier: &[String]) -> Option<Vec<String>> {
        let (first, rest) = qualifier.split_first()?;
        let mut module = match first.as_str() {
            "crate" => Vec::new(),
            "self" => self.module.clone(),
            "super" => self.module[..self.module.len().saturating_sub(1)].to_vec(),
            _ => return None,
        };
        for segment in rest {
            if segment == "super" {
                module.pop();
            } else {
                module.push(segment.clone());
            }
        }
        Some(module)
    }

    /// The enum named `name` that holds `variant`, chosen among equals by
    /// the qualifier's module, then the same file, then the longest shared
    /// module prefix. `Err(())` signals unresolved ambiguity.
    fn resolve(
        &self,
        name: &str,
        qualifier: &[String],
        variant: &str,
    ) -> Result<Option<usize>, ()> {
        let candidates: Vec<usize> = (0..self.enums.len())
            .filter(|&index| {
                let candidate = &self.enums[index];
                candidate.name == name && candidate.variants.iter().any(|v| v.name == variant)
            })
            .collect();
        if candidates.len() < 2 {
            return Ok(candidates.first().copied());
        }
        let unique = |filter: &dyn Fn(&Enum) -> bool| {
            let kept: Vec<usize> = candidates
                .iter()
                .copied()
                .filter(|&index| filter(&self.enums[index]))
                .collect();
            (kept.len() == 1).then(|| kept[0])
        };
        let by_module = match self.absolute(qualifier) {
            Some(module) => {
                return unique(&|candidate| candidate.module == module)
                    .or_else(|| unique(&|candidate| candidate.module.starts_with(&module)))
                    .map(Some)
                    .ok_or(());
            }
            None => qualifier
                .last()
                .and_then(|hint| unique(&|candidate| candidate.module.last() == Some(hint))),
        };
        if let Some(found) = by_module.or_else(|| unique(&|candidate| candidate.file == self.file))
        {
            return Ok(Some(found));
        }
        let shared = |candidate: &Enum| {
            candidate
                .module
                .iter()
                .zip(&self.module)
                .take_while(|(a, b)| a == b)
                .count()
        };
        let best = candidates
            .iter()
            .map(|&index| shared(&self.enums[index]))
            .max();
        match best {
            Some(best) if best > 0 => unique(&|candidate| shared(candidate) == best)
                .ok_or(())
                .map(Some),
            _ => Err(()),
        }
    }

    /// The enum name, qualifier and variant a path names, through the file's
    /// imports where the path starts with an imported name.
    fn named(&self, segments: &[String]) -> Vec<(String, Vec<String>, String)> {
        let (variant, head) = match segments.split_last() {
            Some(split) => split,
            None => return Vec::new(),
        };
        if let Some((ty, qualifier)) = head.split_last() {
            if ty == "Self" && qualifier.is_empty() {
                return match self.self_types.last().cloned().flatten() {
                    Some(ty) => vec![(ty, Vec::new(), variant.clone())],
                    None => Vec::new(),
                };
            }
            if qualifier.is_empty()
                && let Some(paths) = self.lookup(ty)
            {
                return paths
                    .iter()
                    .filter_map(|path| path.split_last())
                    .map(|(imported, qualifier)| {
                        (imported.clone(), qualifier.to_vec(), variant.clone())
                    })
                    .collect();
            }
            return vec![(ty.clone(), qualifier.to_vec(), variant.clone())];
        }
        if let Some(paths) = self.lookup(variant) {
            return paths
                .iter()
                .filter_map(|path| match path.as_slice() {
                    [qualifier @ .., ty, original] => {
                        Some((ty.clone(), qualifier.to_vec(), original.clone()))
                    }
                    _ => None,
                })
                .collect();
        }
        self.globs()
            .into_iter()
            .filter_map(|glob| glob.split_last())
            .map(|(ty, qualifier)| (ty.clone(), qualifier.to_vec(), variant.clone()))
            .collect()
    }

    fn listed_candidate(&self, name: &str, variant: &str) -> bool {
        self.enums.iter().any(|candidate| {
            candidate.name == name
                && candidate.family().is_some()
                && candidate.variants.iter().any(|v| v.name == variant)
        })
    }

    fn record(&mut self, path: &syn::Path, kind: Kind) {
        let segments: Vec<String> = path
            .segments
            .iter()
            .map(|segment| segment.ident.unraw().to_string())
            .collect();
        let Some(first) = path.segments.first() else {
            return;
        };
        let mut owners: Vec<(usize, String)> = Vec::new();
        let mut tied = false;
        for (ty, qualifier, variant) in self.named(&segments) {
            match self.resolve(&ty, &qualifier, &variant) {
                Ok(Some(owner)) => {
                    if !owners
                        .iter()
                        .any(|known| known.0 == owner && known.1 == variant)
                    {
                        owners.push((owner, variant));
                    }
                }
                Ok(None) => {}
                Err(()) => tied |= self.listed_candidate(&ty, &variant),
            }
        }
        let listed = owners
            .iter()
            .any(|(owner, _)| self.enums[*owner].family().is_some());
        if tied || (owners.len() > 1 && listed) {
            let start = first.ident.span().start();
            self.ambiguous.push(format!(
                "{}:{}: {}",
                self.file,
                start.line,
                segments.join("::")
            ));
            return;
        }
        let Some((owner, variant)) = owners.into_iter().next() else {
            return;
        };
        if self.enums[owner].family().is_none() {
            return;
        }
        let shape = self.enums[owner]
            .variants
            .iter()
            .find(|candidate| candidate.name == variant)
            .map_or(Shape::Unit, |candidate| candidate.shape);
        let form = match (kind, shape) {
            _ if self.compare > 0 => Form::Compare,
            _ if self.table > 0 => Form::Table,
            (Kind::Path, Shape::Tuple) => Form::Value,
            (Kind::Path, Shape::Struct) => return,
            _ if self.eager > 0 => Form::Eager,
            (Kind::Path, Shape::Unit) => Form::Path,
            (Kind::Call, _) => Form::Call,
            (Kind::Struct, _) => Form::Struct,
        };
        self.out.push(Site {
            owner,
            variant,
            file: self.file.to_owned(),
            function: self.functions.last().cloned().unwrap_or_default(),
            form,
            at: self.at(first.ident.span().start()),
            chain: self.chain.last().copied().flatten(),
            branch: self.branch > 0,
            outer: self.outer.last().copied().flatten(),
        });
    }

    /// `tokens` submits each maximal `::`-separated identifier chain of two
    /// or more segments to `record` as `Kind::Path`.
    fn tokens(&mut self, stream: TokenStream) {
        let trees: Vec<TokenTree> = stream.into_iter().collect();
        let mut i = 0;
        while i < trees.len() {
            if let TokenTree::Group(group) = &trees[i] {
                self.tokens(group.stream());
            }
            let mut path: Punctuated<syn::PathSegment, syn::Token![::]> = Punctuated::new();
            let mut j = i;
            while let Some(TokenTree::Ident(ident)) = trees.get(j) {
                path.push(syn::PathSegment::from(ident.clone()));
                let colons = matches!(
                    (trees.get(j + 1), trees.get(j + 2), trees.get(j + 3)),
                    (Some(TokenTree::Punct(a)), Some(TokenTree::Punct(b)), Some(TokenTree::Ident(_)))
                        if a.as_char() == ':' && b.as_char() == ':'
                );
                if !colons {
                    break;
                }
                j += 3;
            }
            if path.len() >= 2 {
                let path = syn::Path {
                    leading_colon: None,
                    segments: path,
                };
                self.record(&path, Kind::Path);
                i = j;
            }
            i += 1;
        }
    }

    /// A closure body ([`Scope::Closure`]) starts a scope with no chain, no
    /// comparison and no table, since it runs as code. A block or match arm
    /// ([`Scope::Block`]) keeps the comparison and table marks, since its
    /// value flows into the operand or the initializer. Inside an eager
    /// argument, a block or match arm keeps the argument's chain and marks
    /// its sites as branches; elsewhere it starts no chain.
    fn scoped(&mut self, scope: Scope, body: impl FnOnce(&mut Self)) {
        if scope == Scope::Block && self.eager > 0 {
            self.branch += 1;
            body(self);
            self.branch -= 1;
            return;
        }
        let compare = match scope {
            Scope::Block => self.compare,
            Scope::Closure => 0,
        };
        let table = match scope {
            Scope::Block => self.table,
            Scope::Closure => 0,
        };
        let saved = (
            self.eager,
            self.compare,
            self.branch,
            self.table,
            std::mem::take(&mut self.targets),
        );
        (self.eager, self.compare, self.branch, self.table) = (0, compare, 0, table);
        self.chain.push(None);
        body(self);
        self.chain.pop();
        (
            self.eager,
            self.compare,
            self.branch,
            self.table,
            self.targets,
        ) = saved;
    }

    /// With [`Ends::Chain`], the arguments take that `?` as their chain;
    /// with [`Ends::Opaque`], they take none. Either starts a new argument
    /// scope outside any eager argument. With [`Ends::Open`], the arguments
    /// take no chain and stay inside an enclosing eager argument.
    fn arguments(&mut self, ends: Ends, body: impl FnOnce(&mut Self)) {
        let question = match ends {
            Ends::Open => {
                self.chain.push(None);
                body(self);
                self.chain.pop();
                return;
            }
            Ends::Opaque => None,
            Ends::Chain(question) => Some(question),
        };
        let saved = (self.eager, self.branch, std::mem::take(&mut self.targets));
        (self.eager, self.branch) = (0, 0);
        self.chain.push(question);
        body(self);
        self.chain.pop();
        (self.eager, self.branch, self.targets) = saved;
    }

    /// `leave` visits a value that leaves the enclosing argument and
    /// comparison, the operand of a `return` or of a `break` to a target
    /// outside the argument, with no chain, outside any eager argument and
    /// comparison.
    fn leave(&mut self, value: &syn::Expr) {
        let compare = std::mem::take(&mut self.compare);
        self.arguments(Ends::Opaque, |sites| sites.visit_expr(value));
        self.compare = compare;
    }

    /// `target` visits a loop or a labeled block as a target of `break`.
    fn target(&mut self, label: Option<&syn::Label>, looping: bool, body: impl FnOnce(&mut Self)) {
        self.targets.push(Target {
            label: label.map(|label| label.name.ident.unraw().to_string()),
            looping,
        });
        body(self);
        self.targets.pop();
    }

    /// A `const` or `static` item starts table context and a function ends
    /// it, so a function nested in an initializer counts as code.
    fn named_item(&mut self, name: String, kind: ItemKind, body: impl FnOnce(&mut Self)) {
        let table = u32::from(kind == ItemKind::Table);
        self.functions.push(name);
        let saved = (
            self.eager,
            self.compare,
            self.branch,
            std::mem::take(&mut self.targets),
        );
        let saved_table = std::mem::replace(&mut self.table, table);
        (self.eager, self.compare, self.branch) = (0, 0, 0);
        self.chain.push(None);
        self.outer.push(None);
        body(self);
        self.outer.pop();
        self.chain.pop();
        self.table = saved_table;
        (self.eager, self.compare, self.branch, self.targets) = saved;
        self.functions.pop();
    }

    /// `question` holds the `?` whose operand is `call`, with any
    /// parentheses between them removed.
    /// The arguments of a [`CHAINED`] or [`ERROR_PATH`] call that a `?`
    /// ends leave the comparison mark, since they supply the error.
    fn method_call(&mut self, call: &syn::ExprMethodCall, question: Option<At>) {
        self.visit_expr(&call.receiver);
        let method = call.method.unraw().to_string();
        let method = method.as_str();
        let eager = u32::from(EAGER.contains(&method));
        let error = question.filter(|_| ERROR_PATH.contains(&method));
        let ends = match question {
            None => Ends::Open,
            Some(question) if CHAINED.contains(&method) => Ends::Chain(question),
            Some(_) => Ends::Opaque,
        };
        let residual = ends != Ends::Open && (CHAINED.contains(&method) || error.is_some());
        let compare = self.compare;
        if residual {
            self.compare = 0;
        }
        self.arguments(ends, |sites| {
            sites.eager += eager;
            for argument in &call.args {
                let closure = error.filter(|_| matches!(argument, syn::Expr::Closure(_)));
                if closure.is_some() {
                    sites.outer.push(closure);
                }
                sites.visit_expr(argument);
                if closure.is_some() {
                    sites.outer.pop();
                }
            }
            sites.eager -= eager;
        });
        self.compare = compare;
    }

    /// `question` holds the `?` whose operand is `call`, with any
    /// parentheses between them removed.
    fn call(&mut self, call: &syn::ExprCall, question: Option<At>) {
        match &*call.func {
            syn::Expr::Path(function) => self.record(&function.path, Kind::Call),
            function => self.visit_expr(function),
        }
        let ends = if question.is_some() {
            Ends::Opaque
        } else {
            Ends::Open
        };
        self.arguments(ends, |sites| {
            for argument in &call.args {
                sites.visit_expr(argument);
            }
        });
    }
}

fn last_segment(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.unraw().to_string()),
        _ => None,
    }
}

struct Matching(syn::Expr);

impl syn::parse::Parse for Matching {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let expression = input.parse()?;
        input.parse::<TokenStream>()?;
        Ok(Self(expression))
    }
}

impl<'ast> Visit<'ast> for Sites<'_> {
    fn visit_file(&mut self, file: &'ast syn::File) {
        self.framed(Frame::of(file.items.iter(), true), |sites| {
            visit::visit_file(sites, file);
        });
    }

    fn visit_item(&mut self, item: &'ast syn::Item) {
        if !gated(item_attributes(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if let Some((_, items)) = &item.content {
            self.module.push(item.ident.unraw().to_string());
            self.framed(Frame::of(items.iter(), true), |sites| {
                for item in items {
                    sites.visit_item(item);
                }
            });
            self.module.pop();
        }
    }

    fn visit_variant(&mut self, variant: &'ast syn::Variant) {
        if !gated(&variant.attrs) {
            visit::visit_variant(self, variant);
        }
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let ty = last_segment(&item.self_ty);
        self.owners.push(ty.clone().unwrap_or_default());
        self.self_types.push(ty);
        visit::visit_item_impl(self, item);
        self.self_types.pop();
        self.owners.pop();
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        self.owners.push(item.ident.unraw().to_string());
        self.self_types.push(None);
        visit::visit_item_trait(self, item);
        self.self_types.pop();
        self.owners.pop();
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.named_item(
            item.sig.ident.unraw().to_string(),
            ItemKind::Function,
            |sites| {
                visit::visit_item_fn(sites, item);
            },
        );
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        if !gated(impl_item_attributes(item)) {
            visit::visit_impl_item(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        let owner = self.owners.last().cloned().unwrap_or_default();
        let name = format!("{owner}::{}", item.sig.ident.unraw());
        self.named_item(name, ItemKind::Function, |sites| {
            visit::visit_impl_item_fn(sites, item)
        });
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        let owner = self.owners.last().cloned().unwrap_or_default();
        let name = format!("{owner}::{}", item.sig.ident.unraw());
        self.named_item(name, ItemKind::Function, |sites| {
            visit::visit_trait_item_fn(sites, item);
        });
    }

    fn visit_trait_item_const(&mut self, item: &'ast syn::TraitItemConst) {
        self.named_item(item.ident.unraw().to_string(), ItemKind::Table, |sites| {
            visit::visit_trait_item_const(sites, item);
        });
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        if !gated(trait_item_attributes(item)) {
            visit::visit_trait_item(self, item);
        }
    }

    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        self.named_item(item.ident.unraw().to_string(), ItemKind::Table, |sites| {
            visit::visit_item_const(sites, item);
        });
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        self.named_item(item.ident.unraw().to_string(), ItemKind::Table, |sites| {
            visit::visit_item_static(sites, item);
        });
    }

    fn visit_impl_item_const(&mut self, item: &'ast syn::ImplItemConst) {
        self.named_item(item.ident.unraw().to_string(), ItemKind::Table, |sites| {
            visit::visit_impl_item_const(sites, item);
        });
    }

    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        if !item.mac.path.is_ident("macro_rules") {
            self.visit_macro(&item.mac);
        }
    }

    fn visit_stmt(&mut self, statement: &'ast syn::Stmt) {
        if !statement_gated(statement) {
            visit::visit_stmt(self, statement);
        }
    }

    fn visit_pat(&mut self, _: &'ast syn::Pat) {}

    fn visit_block(&mut self, block: &'ast syn::Block) {
        let items = block.stmts.iter().filter_map(|statement| match statement {
            syn::Stmt::Item(item) => Some(item),
            _ => None,
        });
        self.framed(Frame::of(items, false), |sites| {
            sites.scoped(Scope::Block, |sites| visit::visit_block(sites, block));
        });
    }

    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        if gated(&arm.attrs) {
            return;
        }
        self.scoped(Scope::Block, |sites| {
            if let Some((_, guard)) = &arm.guard {
                sites.visit_expr(guard);
            }
            sites.visit_expr(&arm.body);
        });
    }

    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        self.scoped(Scope::Closure, |sites| sites.visit_expr(&closure.body));
    }

    fn visit_expr_try(&mut self, expression: &'ast syn::ExprTry) {
        let question = Some(self.at(expression.question_token.span.start()));
        let mut operand = &*expression.expr;
        while let syn::Expr::Paren(inner) = operand {
            operand = &inner.expr;
        }
        match operand {
            syn::Expr::MethodCall(call) => self.method_call(call, question),
            syn::Expr::Call(call) => self.call(call, question),
            _ => self.arguments(Ends::Opaque, |sites| sites.visit_expr(&expression.expr)),
        }
    }

    fn visit_expr_return(&mut self, expression: &'ast syn::ExprReturn) {
        if let Some(value) = &expression.expr {
            self.leave(value);
        }
    }

    /// A `break` whose target lies outside the current argument takes its
    /// value out of the argument.
    fn visit_expr_break(&mut self, expression: &'ast syn::ExprBreak) {
        let Some(value) = &expression.expr else {
            return;
        };
        let label = expression
            .label
            .as_ref()
            .map(|label| label.ident.unraw().to_string());
        let caught = self.targets.iter().any(|target| match &label {
            Some(label) => target.label.as_ref() == Some(label),
            None => target.looping,
        });
        if caught {
            self.visit_expr(value);
        } else {
            self.leave(value);
        }
    }

    fn visit_expr_loop(&mut self, expression: &'ast syn::ExprLoop) {
        self.target(expression.label.as_ref(), true, |sites| {
            sites.visit_block(&expression.body);
        });
    }

    fn visit_expr_while(&mut self, expression: &'ast syn::ExprWhile) {
        self.target(expression.label.as_ref(), true, |sites| {
            sites.visit_expr(&expression.cond);
            sites.visit_block(&expression.body);
        });
    }

    fn visit_expr_for_loop(&mut self, expression: &'ast syn::ExprForLoop) {
        self.visit_expr(&expression.expr);
        self.target(expression.label.as_ref(), true, |sites| {
            sites.visit_block(&expression.body);
        });
    }

    fn visit_expr_block(&mut self, expression: &'ast syn::ExprBlock) {
        match &expression.label {
            Some(label) => self.target(Some(label), false, |sites| {
                sites.visit_block(&expression.block);
            }),
            None => self.visit_block(&expression.block),
        }
    }

    fn visit_expr_binary(&mut self, expression: &'ast syn::ExprBinary) {
        let comparing = matches!(expression.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_));
        self.compare += u32::from(comparing);
        self.visit_expr(&expression.left);
        self.visit_expr(&expression.right);
        self.compare -= u32::from(comparing);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.method_call(call, None);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        self.call(call, None);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.record(&path.path, Kind::Path);
    }

    fn visit_expr_struct(&mut self, literal: &'ast syn::ExprStruct) {
        self.record(&literal.path, Kind::Struct);
        for field in &literal.fields {
            if !gated(&field.attrs) {
                self.visit_expr(&field.expr);
            }
        }
        if let Some(rest) = &literal.rest {
            self.visit_expr(rest);
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let name = mac
            .path
            .segments
            .last()
            .map(|segment| segment.ident.unraw().to_string())
            .unwrap_or_default();
        if MATCHING.contains(&name.as_str()) {
            if let Ok(Matching(expression)) = mac.parse_body::<Matching>() {
                self.visit_expr(&expression);
            }
            return;
        }
        let comparing = COMPARING.contains(&name.as_str());
        if let Ok(arguments) =
            mac.parse_body_with(Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated)
        {
            for (index, argument) in arguments.iter().enumerate() {
                let compared = comparing && index < 2;
                self.compare += u32::from(compared);
                self.visit_expr(argument);
                self.compare -= u32::from(compared);
            }
            return;
        }
        self.compare += u32::from(comparing);
        if let Ok(statements) = mac.parse_body_with(syn::Block::parse_within) {
            for statement in &statements {
                self.visit_stmt(statement);
            }
        } else {
            self.tokens(mac.tokens.clone());
        }
        self.compare -= u32::from(comparing);
    }
}
