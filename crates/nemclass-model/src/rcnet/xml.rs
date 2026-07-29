//! A minimal XML element tree, built on `quick-xml`'s event reader.
//!
//! `Data.xml` inside a `.rcnet` is small and deeply nested, and the mapping code
//! reads much better against a tree than against a stream of start/end events —
//! a `<node>` needs its attributes *and* its children before it can be turned
//! into a node, which a straight event walk would have to hand-stack anyway.

use std::collections::BTreeMap;

use quick_xml::escape::escape;
use quick_xml::events::Event;

use crate::error::{ModelError, Result};

/// Nesting past this is refused. `.rcnet` files nest one level per wrapped
/// node; a hundred is far past anything a person builds and stops a crafted
/// file from recursing the mapper into a stack overflow.
const MAX_DEPTH: usize = 100;

#[derive(Debug, Clone, Default)]
pub struct Element {
    pub name: String,
    pub attrs: BTreeMap<String, String>,
    /// The element's own character data, unescaped.
    ///
    /// `.rcnet` puts every value in an attribute and never uses this; Cheat
    /// Engine's `.CT` puts every value here and uses almost no attributes, so
    /// the same reader has to carry both.
    pub text: String,
    pub children: Vec<Element>,
}

impl Element {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            attrs: BTreeMap::new(),
            text: String::new(),
            children: Vec::new(),
        }
    }

    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attrs.get(key).map(String::as_str)
    }

    /// An attribute, or `""` when absent — matching how the ReClass.NET reader
    /// treats every optional string attribute.
    pub fn attr_or_empty(&self, key: &str) -> &str {
        self.attr(key).unwrap_or("")
    }

    pub fn attr_bool(&self, key: &str) -> bool {
        matches!(self.attr(key), Some(v) if v.eq_ignore_ascii_case("true"))
    }

    pub fn attr_i64(&self, key: &str) -> Option<i64> {
        self.attr(key).and_then(|v| v.trim().parse::<i64>().ok())
    }

    pub fn set(&mut self, key: &str, value: impl Into<String>) -> &mut Self {
        self.attrs.insert(key.to_string(), value.into());
        self
    }

    pub fn push(&mut self, child: Element) -> &mut Self {
        self.children.push(child);
        self
    }

    /// Direct children with the given tag name.
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.children.iter().filter(move |c| c.name == name)
    }

    pub fn child<'a>(&'a self, name: &'a str) -> Option<&'a Element> {
        self.children_named(name).next()
    }

    /// Serialize as indented XML with an `<?xml?>` declaration.
    pub fn to_document(&self) -> String {
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        self.write_into(&mut out, 0);
        out
    }

    fn write_into(&self, out: &mut String, depth: usize) {
        let pad = "  ".repeat(depth);
        out.push_str(&pad);
        out.push('<');
        out.push_str(&self.name);
        for (key, value) in &self.attrs {
            out.push(' ');
            out.push_str(key);
            out.push_str("=\"");
            out.push_str(&escape(value.as_str()));
            out.push('"');
        }
        if self.children.is_empty() && self.text.is_empty() {
            out.push_str(" />\n");
            return;
        }
        if self.children.is_empty() {
            out.push('>');
            out.push_str(&escape(self.text.as_str()));
            out.push_str("</");
            out.push_str(&self.name);
            out.push_str(">\n");
            return;
        }
        out.push_str(">\n");
        for child in &self.children {
            child.write_into(out, depth + 1);
        }
        out.push_str(&pad);
        out.push_str("</");
        out.push_str(&self.name);
        out.push_str(">\n");
    }
}

/// Parse a document into its root element.
pub fn parse(xml: &str) -> Result<Element> {
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    let mut buf = Vec::new();

    let bad = |e: String| ModelError::DeserializeError(format!("malformed XML: {e}"));

    loop {
        let event = reader.read_event_into(&mut buf).map_err(|e| bad(e.to_string()))?;
        match event {
            Event::Start(ref start) | Event::Empty(ref start) => {
                let is_empty = matches!(event, Event::Empty(_));
                if stack.len() >= MAX_DEPTH {
                    return Err(bad(format!("nesting deeper than {MAX_DEPTH} elements")));
                }
                let name = String::from_utf8_lossy(start.name().as_ref()).into_owned();
                let mut element = Element::new(name);
                for attr in start.attributes() {
                    let attr = attr.map_err(|e| bad(e.to_string()))?;
                    let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
                    // XML 1.0: `.rcnet` documents always declare 1.0, and the
                    // version only affects which control characters normalize.
                    let value = attr
                        .decoded_and_normalized_value(quick_xml::XmlVersion::Explicit1_0, reader.decoder())
                        .map_err(|e| bad(e.to_string()))?
                        .into_owned();
                    element.attrs.insert(key, value);
                }
                if is_empty {
                    match stack.last_mut() {
                        Some(parent) => parent.children.push(element),
                        None => root = Some(element),
                    }
                } else {
                    stack.push(element);
                }
            }
            Event::End(_) => {
                let Some(done) = stack.pop() else {
                    return Err(bad("closing tag with no matching open".to_string()));
                };
                match stack.last_mut() {
                    Some(parent) => parent.children.push(done),
                    None => root = Some(done),
                }
            }
            Event::Text(ref t) => {
                if let Some(current) = stack.last_mut()
                    && let Ok(decoded) = t.decode()
                {
                    current.text.push_str(decoded.as_ref());
                }
            }
            Event::CData(ref t) => {
                if let Some(current) = stack.last_mut()
                    && let Ok(text) = std::str::from_utf8(t.as_ref())
                {
                    current.text.push_str(text);
                }
            }
            Event::Eof => break,
            // Comments and processing instructions carry nothing either format
            // uses.
            _ => {}
        }
        buf.clear();
    }

    if !stack.is_empty() {
        return Err(bad("unclosed element at end of document".to_string()));
    }
    root.ok_or_else(|| bad("document has no root element".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_elements_and_attributes_round_trip() {
        let mut root = Element::new("reclass");
        root.set("version", "65537");
        let mut classes = Element::new("classes");
        let mut class = Element::new("class");
        class.set("name", "Player & \"friends\"");
        class.push(Element::new("node"));
        classes.push(class);
        root.push(classes);

        let doc = root.to_document();
        let parsed = parse(&doc).unwrap();
        assert_eq!(parsed.name, "reclass");
        assert_eq!(parsed.attr("version"), Some("65537"));
        let class = parsed.child("classes").unwrap().child("class").unwrap();
        // The ampersand and quotes survive escaping and unescaping.
        assert_eq!(class.attr("name"), Some("Player & \"friends\""));
        assert_eq!(class.children.len(), 1);
    }

    #[test]
    fn a_truncated_document_is_an_error() {
        assert!(parse("<reclass><classes>").is_err());
    }
}
