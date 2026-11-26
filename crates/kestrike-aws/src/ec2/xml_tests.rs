use super::{DEPTH, ELEMENTS, Element, parse};

fn leaf(name: &str, text: &str) -> Element {
    Element {
        name: name.to_owned(),
        text: text.to_owned(),
        children: Vec::new(),
    }
}

#[test]
fn a_document_parses_into_names_text_and_ordered_children() {
    let document = parse(
        br#"<?xml version="1.0" encoding="UTF-8"?>
<Root xmlns="http://ec2.amazonaws.com/doc/2016-11-15/" note='a>b'>
  <first>one &amp; &lt;two&gt; &quot;&apos; &#65;&#x42;</first>
  <empty/>
  <empty />
  <set><item>x</item><item>y</item></set>
</Root>
"#,
    )
    .unwrap();
    assert_eq!(document.name, "Root");
    assert_eq!(
        document.children[..3],
        [
            leaf("first", "one & <two> \"' AB"),
            leaf("empty", ""),
            leaf("empty", "")
        ]
    );
    assert_eq!(document.text_of("first"), Some("one & <two> \"' AB"));
    assert_eq!(document.child("empty"), None);
    let items = document.items("set").unwrap();
    assert_eq!(items, [leaf("item", "x"), leaf("item", "y")]);
    assert_eq!(document.items("first"), None);
    assert_eq!(document.items("absent"), None);
}

/// A set holding only whitespace and items lists them; a set holding other
/// text lists nothing, and an element holding elements has no text.
#[test]
fn only_leaf_elements_have_text_and_only_whitespace_separates_items() {
    let document =
        parse(b"<R>\r\n\t<set>\n  <item>x</item>\n</set><empty/><nested>a<b/></nested></R>")
            .unwrap();
    assert_eq!(document.items("set"), Some(&[leaf("item", "x")][..]));
    assert_eq!(document.items("empty"), Some(&[][..]));
    assert_eq!(document.text_of("nested"), None);
    assert_eq!(document.text_of("empty"), Some(""));
    for text in [
        "<set>x</set>",
        "<set>x<item/></set>",
        "<set><item/>\u{a0}</set>",
    ] {
        let document = parse(format!("<R>{text}</R>").as_bytes()).unwrap();
        assert_eq!(document.items("set"), None, "{text}");
    }
}

/// Attributes of the accepted form are skipped, and the text keeps legal
/// characters that are not XML whitespace, such as a nonbreaking space.
#[test]
fn well_formed_attributes_and_legal_characters_are_accepted() {
    let document = parse(
        "<?xml version='1.0'?><R xmlns:p=\"urn:x\" a = \"&amp;\" b='>'><c d=\"\"/>a\u{a0}b&#9;&#10;&#13;\u{1F600}</R>".as_bytes(),
    )
    .unwrap();
    assert_eq!(document.text, "a\u{a0}b\t\n\r\u{1F600}");
    assert_eq!(document.children, [leaf("c", "")]);
}

#[test]
fn a_set_holding_a_child_other_than_item_has_no_items() {
    let document = parse(b"<R><set><item/><other/></set></R>").unwrap();
    assert_eq!(document.items("set"), None);
}

/// An element or attribute name starts with an ASCII letter or `_` and
/// may hold digits, `_`, `-` and `.` after it.
#[test]
fn a_name_may_hold_digits_underscores_hyphens_and_dots() {
    let document =
        parse(b"<_r a-b.c_d1=\"x\" _e='y'><a-b>1</a-b><c.d>2</c.d><e_f9>3</e_f9><_g/></_r>")
            .unwrap();
    assert_eq!(document.name, "_r");
    assert_eq!(
        document.children,
        [
            leaf("a-b", "1"),
            leaf("c.d", "2"),
            leaf("e_f9", "3"),
            leaf("_g", "")
        ]
    );
}

/// Names match in their exact letter case: a child or a set member whose
/// name differs from the asked one only in case is another element.
#[test]
fn a_name_in_another_letter_case_is_another_element() {
    let document =
        parse(b"<R><Volume>v</Volume><set><Item>x</Item></set><list><item>y</item></list></R>")
            .unwrap();
    assert_eq!(document.text_of("Volume"), Some("v"));
    assert_eq!(document.text_of("volume"), None);
    assert_eq!(document.child("VOLUME"), None);
    assert_eq!(document.items("set"), None);
    assert_eq!(document.items("List"), None);
    assert_eq!(document.items("list"), Some(&[leaf("item", "y")][..]));
}

/// A declaration of version 1.0 reads with or without an encoding of
/// UTF-8, in any letter case, and with or without `standalone`.
#[test]
fn a_declaration_of_version_one_and_utf8_reads() {
    for declaration in [
        "<?xml version=\"1.0\"?>",
        "<?xml version='1.0' ?>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        "<?xml version=\"1.0\" encoding='utf-8'?>",
        "<?xml version=\"1.0\" standalone=\"yes\"?>",
        "<?xml version=\"1.0\"\n encoding=\"Utf-8\"\tstandalone=\"no\" ?>",
    ] {
        let document = parse(format!("{declaration}\n<a>x</a>").as_bytes());
        assert_eq!(document, Some(leaf("a", "x")), "{declaration}");
    }
}

/// Text keeps the whitespace written in it: a tab, a carriage return and
/// a line feed read as themselves, at the ends of the text and inside it.
#[test]
fn whitespace_written_in_text_reads_as_written() {
    let document = parse(b"<R><a>\tx\ty \r\n z\n</a><b> </b></R>").unwrap();
    assert_eq!(document.text_of("a"), Some("\tx\ty \r\n z\n"));
    assert_eq!(document.text_of("b"), Some(" "));
}

/// A numeric reference reads with hexadecimal digits in either letter
/// case and with leading zeros.
#[test]
fn a_numeric_reference_reads_in_either_hex_case_and_with_leading_zeros() {
    let document = parse(b"<R>&#x7f;&#x7F;&#xe9;&#xE9;&#0065;&#x0041;&#x00000041;</R>").unwrap();
    assert_eq!(document.text, "\u{7f}\u{7f}\u{e9}\u{e9}AAA");
}

/// A reference resolves once: the text a reference yields is text, even
/// where it spells another reference.
#[test]
fn the_text_a_reference_yields_is_not_resolved_again() {
    let document =
        parse(b"<R a=\"&amp;lt;\">&amp;lt; &#38;amp; &amp;#65; &#x26;#x41;</R>").unwrap();
    assert_eq!(document.text, "&lt; &amp; &#65; &#x41;");
}

/// XML whitespace inside a tag changes nothing: an end tag may hold it
/// before its `>`, and a start tag's name ends at a space, a tab, a
/// carriage return or a line feed.
#[test]
fn whitespace_inside_a_tag_reads_as_the_same_document() {
    let plain = parse(b"<R><a b=\"c\">x</a><e/></R>").unwrap();
    assert_eq!(plain.children, [leaf("a", "x"), leaf("e", "")]);
    for spaced in [
        "<R><a b=\"c\">x</a ><e/></R >",
        "<R><a\nb=\"c\">x</a\n><e\n/></R\r\n>",
        "<R><a\tb=\"c\"\t>x</a\t><e\t/></R>",
        "<R\r><a\rb=\"c\">x</a><e /></R>",
    ] {
        assert_eq!(
            parse(spaced.as_bytes()).as_ref(),
            Some(&plain),
            "{spaced:?}"
        );
    }
}

/// The characters at the edges of the XML character set read in text,
/// written literally and as numeric references: U+007F, the last
/// character below the surrogates, the first above them, U+FFFD and the
/// last scalar value.
#[test]
fn the_edges_of_the_xml_character_set_read_in_text() {
    let text = "\u{7f}\u{85}\u{d7ff}\u{e000}\u{fffd}\u{10000}\u{10ffff}";
    let document = parse(format!("<R>{text}</R>").as_bytes()).unwrap();
    assert_eq!(document.text, text);
    let referenced =
        parse(b"<R>&#127;&#x85;&#xD7FF;&#xE000;&#xFFFD;&#x10000;&#x10FFFF;</R>").unwrap();
    assert_eq!(referenced.text, text);
}

#[test]
fn every_construct_outside_the_accepted_form_is_unreadable() {
    assert_eq!(DEPTH, 32);
    let deep = format!("{}{}", "<a>".repeat(DEPTH + 1), "</a>".repeat(DEPTH + 1));
    let deepest = format!("{}{}", "<a>".repeat(DEPTH), "</a>".repeat(DEPTH));
    assert!(parse(deepest.as_bytes()).is_some());
    let cases: [&[u8]; 75] = [
        b"",
        b"<a>]]></a>",
        b"<a><b/>]]></a>",
        b"</a>",
        b"<a",
        b"<a></a",
        b"<?xml version=\"1.0\"",
        b"<?xml?><a/>",
        b"<?xml encoding=\"UTF-8\"?><a/>",
        b"<?xml version=\"1.1\"?><a/>",
        b"<?xml version=\"1.0 \"?><a/>",
        b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a/>",
        b"<?xml version=\"1.0\" encoding=\"UTF-16\"?><a/>",
        b"<?xml version=\"1.0\" encoding=\"UTF8\"?><a/>",
        b"<?xml version=\"1.0\" encoding=\"\"?><a/>",
        b"<?xml version=\"1.0\" charset=\"UTF-8\"?><a/>",
        b"<?xml version=\"1.0\" standalone=\"maybe\"?><a/>",
        b"<?xml version=\"1.0\" standalone=\"yes\" encoding=\"UTF-8\"?><a/>",
        b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\" more=\"x\"?><a/>",
        b"<?xml encoding=\"UTF-8\" version=\"1.0\"?><a/>",
        b"<?xml-stylesheet href=\"x\"?><a/>",
        b" <?xml version=\"1.0\"?><a/>",
        b"<a>&#4294967296;</a>",
        b"<a>&#;</a>",
        b"<a>&#x;</a>",
        b"<a>&#0;</a>",
        b"<a>&#1;</a>",
        b"<a>&#xFFFE;</a>",
        b"<a>\x01</a>",
        b"<a>\xef\xbf\xbe</a>",
        b"<a></a>\xc2\xa0",
        b"\x0c<a></a>",
        b"<a\x0cb=\"c\"/>",
        b"<a bare/>",
        b"<a b=c/>",
        b"<a b=\"1\"c=\"2\"/>",
        b"<a b=\"1\" b=\"2\"/>",
        b"<a b=\"<\"/>",
        b"<a b=\"&nbsp;\"/>",
        b"<a b=\"1'/>",
        b"<a:b/>",
        b"text",
        b"<a>",
        b"<a></b>",
        b"<a></ab>",
        b"<ab></a>",
        b"<a></A>",
        b"<a></>",
        b"<a></ >",
        b"<a></a b=\"c\">",
        b"<a></a b>",
        b"<a//>",
        b"<a :b=\"1\"/>",
        b"<a b:=\"1\"/>",
        b"<a b:1c=\"1\"/>",
        b"<a>\xef\xbf\xbf</a>",
        b"<a>&#xFFFF;</a>",
        b"<a>&#x110000;</a>",
        b"<a></a><b></b>",
        b"<a></a>trailing",
        b"lead<a></a>",
        b"<a><!-- comment --></a>",
        b"<a><![CDATA[x]]></a>",
        b"<!DOCTYPE a><a></a>",
        b"<a><?pi x?></a>",
        b"<a>&nbsp;</a>",
        b"<a>&#xD800;</a>",
        b"<a>&#+65;</a>",
        b"<a>&#X41;</a>",
        b"\xef\xbb\xbf<a></a>",
        b"<a>& </a>",
        b"<1a></1a>",
        b"<-a/>",
        b"<.a/>",
        b"<a>\xff</a>",
    ];
    for case in cases {
        assert_eq!(parse(case), None, "{}", String::from_utf8_lossy(case));
    }
    assert_eq!(parse(deep.as_bytes()), None);
    let self_closing = format!("{}<a/>{}", "<a>".repeat(DEPTH), "</a>".repeat(DEPTH));
    assert_eq!(parse(self_closing.as_bytes()), None);
}

/// An element that holds text beside its children reads as having none,
/// and a literal `]]>` is refused in element text but read in its escaped
/// form and inside a quoted attribute value.
#[test]
fn stray_text_hides_children_and_only_an_escaped_cdata_end_reads() {
    let document = parse(b"<R>x<a/><set><item/></set></R>").unwrap();
    assert_eq!(document.child("a"), None);
    assert_eq!(document.elements(), None);
    assert_eq!(document.items("set"), None);
    let document = parse(b"<R>\n <a b=\"]]>\">]]&gt;</a></R>").unwrap();
    assert_eq!(document.elements().map(<[Element]>::len), Some(1));
    assert_eq!(document.text_of("a"), Some("]]>"));
}

/// A start tag with many distinct attributes reads, and one whose last
/// attribute repeats the first is refused.
#[test]
fn a_wide_start_tag_reads_and_a_repeated_name_at_its_end_is_refused() {
    let attributes: String = (0..20_000).map(|at| format!(" a{at}='v'")).collect();
    let wide = format!("<R{attributes}/>");
    assert!(parse(wide.as_bytes()).is_some());
    let repeated = format!("<R{attributes} a0='v'/>");
    assert_eq!(parse(repeated.as_bytes()), None);
}

/// A document of `ELEMENTS` elements reads, its root counted, and a
/// document of one more is unreadable whether the elements are empty, hold
/// text or nest.
#[test]
fn a_document_past_the_element_bound_is_unreadable() {
    assert_eq!(ELEMENTS, 262_144);
    let rows = |row: &str, count: usize| format!("<r>{}</r>", row.repeat(count));
    let full = parse(rows("<a/>", ELEMENTS - 1).as_bytes()).unwrap();
    assert_eq!(full.children.len(), ELEMENTS - 1);
    for past in [
        rows("<a/>", ELEMENTS),
        rows("<a>x</a>", ELEMENTS),
        rows("<a><b/></a>", ELEMENTS / 2),
    ] {
        assert_eq!(parse(past.as_bytes()).map(|root| root.children.len()), None);
    }
}
