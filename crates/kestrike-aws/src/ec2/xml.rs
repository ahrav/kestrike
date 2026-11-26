//! `parse` builds the element tree of an EC2 Query XML reply: each element's
//! name, its text with character references resolved, and its child
//! elements in document order.
//!
//! The reader decodes the body as UTF-8. It accepts an optional XML
//! declaration at the first byte that declares `version` `1.0`, then
//! optionally an `encoding` of UTF-8 in any letter case, then optionally
//! `standalone` `yes` or `no`, then one root element holding elements and
//! text. Element names are unprefixed; a start tag's attributes are
//! checked for their form and then skipped. Whitespace is the XML
//! whitespace set: space, tab, carriage return and line feed, and text
//! keeps its line ends as written. Each of these makes `parse` return
//! `None`: a comment, a CDATA section, a document type, a processing
//! instruction, a declaration elsewhere, one that declares another version
//! or encoding, one with another pseudo-attribute or another order of
//! them, a prefixed element name, an attribute without whitespace before
//! it, a quoted value or `=`, a repeated attribute name, a reference to an
//! entity other than the five predefined XML entities, a character or
//! numeric reference outside the XML character set, a literal `]]>` in
//! element text, a mismatched end tag, a second root, non-whitespace text
//! outside the root, a body that ends inside an element or a tag, nesting
//! past `DEPTH`, more than `ELEMENTS` elements and bytes that are not
//! UTF-8.
//!
//! An element that holds both child elements and text other than
//! whitespace reads as having no children: `child`, `elements` and `items`
//! return `None` for it.

use std::collections::BTreeSet;

/// The deepest element nesting `parse` accepts, with the root at level one.
const DEPTH: usize = 32;

/// The most elements `parse` accepts in one document, counting the root.
/// The limit bounds per-element overhead across the tree. At the 4 MiB EC2
/// body cap, the limit allows one element per 16 body bytes on average.
const ELEMENTS: usize = 1 << 18;

/// One element: its unprefixed name, the concatenation of its text pieces,
/// and its child elements in document order.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Element {
    pub(crate) name: String,
    pub(crate) text: String,
    pub(crate) children: Vec<Element>,
}

impl Element {
    /// The one child named `name`, `None` when it has none or several or
    /// when this element holds text other than whitespace.
    pub(crate) fn child(&self, name: &str) -> Option<&Element> {
        let mut named = self.elements()?.iter().filter(|child| child.name == name);
        let first = named.next()?;
        named.next().is_none().then_some(first)
    }

    /// The element's children, `None` when it holds text other than
    /// whitespace.
    pub(crate) fn elements(&self) -> Option<&[Element]> {
        self.text
            .chars()
            .all(is_space)
            .then_some(self.children.as_slice())
    }

    /// The text of the one child named `name`, `None` when that child holds
    /// elements.
    pub(crate) fn text_of(&self, name: &str) -> Option<&str> {
        self.child(name)?.leaf_text()
    }

    /// The element's text, `None` when it holds elements.
    pub(crate) fn leaf_text(&self) -> Option<&str> {
        self.children.is_empty().then_some(self.text.as_str())
    }

    /// The members of the one set child named `name`, `None` when the set is
    /// absent or repeated, holds a child other than `item`, or holds text
    /// other than whitespace.
    pub(crate) fn items(&self, name: &str) -> Option<&[Element]> {
        let items = self.child(name)?.elements()?;
        items
            .iter()
            .all(|item| item.name == "item")
            .then_some(items)
    }
}

pub(crate) fn parse(body: &[u8]) -> Option<Element> {
    let mut rest = std::str::from_utf8(body).ok()?;
    if !rest.chars().all(is_char) {
        return None;
    }
    if let Some(declaration) = rest.strip_prefix("<?xml") {
        let (pseudo, after) = declaration.split_once("?>")?;
        if !declares_utf8(&attributes(pseudo)?) {
            return None;
        }
        rest = after;
    }
    let mut open: Vec<Element> = Vec::new();
    let mut elements = 0;
    loop {
        let at = rest.find('<')?;
        let (text, tag) = rest.split_at(at);
        match open.last_mut() {
            Some(_) if text.contains("]]>") => return None,
            Some(element) => unescape(text, &mut element.text)?,
            None if !text.chars().all(is_space) => return None,
            None => {}
        }
        let end = tag_end(tag)?;
        let inner = &tag[1..end];
        rest = &tag[end + 1..];
        let closed = if let Some(name) = inner.strip_prefix('/') {
            let element = open.pop()?;
            (element.name == name.trim_end_matches(is_space)).then_some(element)?
        } else {
            let (inner, empty) = match inner.strip_suffix('/') {
                Some(inner) => (inner, true),
                None => (inner, false),
            };
            let (name, rest) = inner.split_at(inner.find(is_space).unwrap_or(inner.len()));
            if !is_name(name) || attributes(rest).is_none() {
                return None;
            }
            let element = Element {
                name: name.to_owned(),
                text: String::new(),
                children: Vec::new(),
            };
            if open.len() >= DEPTH || elements == ELEMENTS {
                return None;
            }
            elements += 1;
            if !empty {
                open.push(element);
                continue;
            }
            element
        };
        match open.last_mut() {
            Some(parent) => parent.children.push(closed),
            None => return rest.chars().all(is_space).then_some(closed),
        }
    }
}

/// The offset of the `>` that ends the tag `tag` opens, past any quoted
/// attribute value.
fn tag_end(tag: &str) -> Option<usize> {
    let mut quote = None;
    for (at, byte) in tag.bytes().enumerate() {
        match (quote, byte) {
            (None, b'"' | b'\'') => quote = Some(byte),
            (Some(open), _) if byte == open => quote = None,
            (None, b'>') => return Some(at),
            _ => {}
        }
    }
    None
}

/// Whether `pseudo`, the pseudo-attributes of an XML declaration, declares
/// a document `parse` decodes as written: `version` `1.0`, then optionally
/// `encoding` naming UTF-8 in any letter case, then optionally `standalone`
/// `yes` or `no`. A document that declares another encoding holds other
/// text than its bytes read as UTF-8.
fn declares_utf8(pseudo: &[(&str, &str)]) -> bool {
    let [("version", "1.0"), rest @ ..] = pseudo else {
        return false;
    };
    let rest = match rest {
        [("encoding", name), rest @ ..] if name.eq_ignore_ascii_case("UTF-8") => rest,
        rest => rest,
    };
    matches!(rest, [] | [("standalone", "yes" | "no")])
}

/// The name and the quoted value, as written, of each attribute in `rest`,
/// the part of a start tag or a declaration after its name, in order. Each
/// attribute is whitespace, a name with at most one `:` between two names,
/// `=` with optional whitespace around it, and a value in matching quotes
/// that holds no `<` and only references `unescape` resolves; optional
/// whitespace follows the last one. `attributes` returns `None` for any
/// other form and for a repeated name.
fn attributes(mut rest: &str) -> Option<Vec<(&str, &str)>> {
    let mut attributes: Vec<(&str, &str)> = Vec::new();
    let mut seen = BTreeSet::new();
    loop {
        let attribute = rest.trim_start_matches(is_space);
        if attribute.is_empty() {
            return Some(attributes);
        }
        if attribute.len() == rest.len() {
            return None;
        }
        let (name, value) = attribute.split_once('=')?;
        let name = name.trim_end_matches(is_space);
        let qualified = match name.split_once(':') {
            Some((prefix, local)) => is_name(prefix) && is_name(local),
            None => is_name(name),
        };
        if !qualified || !seen.insert(name) {
            return None;
        }
        let value = value.trim_start_matches(is_space);
        let quote = value
            .chars()
            .next()
            .filter(|quote| matches!(quote, '"' | '\''))?;
        let (quoted, after) = value[1..].split_once(quote)?;
        if quoted.contains('<') {
            return None;
        }
        unescape(quoted, &mut String::new())?;
        attributes.push((name, quoted));
        rest = after;
    }
}

/// Whether `name` starts with an ASCII letter or `_` and holds only ASCII
/// letters, digits, `_`, `-` and `.`.
fn is_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// Whether `c` is XML whitespace: space, tab, carriage return or line feed.
fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

/// Whether `c` is in the XML 1.0 character set: tab, line feed, carriage
/// return, and every scalar value from U+0020 on except U+FFFE and U+FFFF.
fn is_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r') || (c >= ' ' && !matches!(c, '\u{FFFE}' | '\u{FFFF}'))
}

/// Appends `text` to `out` with its character references resolved. It
/// returns `None` for a reference to an entity other than the five
/// predefined XML entities and for a numeric reference that names no
/// character `is_char` accepts.
fn unescape(text: &str, out: &mut String) -> Option<()> {
    let mut pieces = text.split('&');
    out.push_str(pieces.next().unwrap_or_default());
    for piece in pieces {
        let (reference, after) = piece.split_once(';')?;
        let resolved = match reference {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let (digits, radix) = match reference.strip_prefix("#x") {
                    Some(hex) => (hex, 16),
                    None => (reference.strip_prefix('#')?, 10),
                };
                if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
                    return None;
                }
                char::from_u32(u32::from_str_radix(digits, radix).ok()?).filter(|c| is_char(*c))?
            }
        };
        out.push(resolved);
        out.push_str(after);
    }
    Some(())
}

#[cfg(test)]
#[path = "xml_tests.rs"]
mod tests;
