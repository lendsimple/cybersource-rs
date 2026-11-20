//! Turning spec descriptions into short, safe rustdoc.
//!
//! Descriptions are long, contain HTML and indented text (which rustdoc
//! would compile as doctests). We keep the first paragraph, capped, with
//! markup neutralised.

const MAX_CHARS: usize = 500;

/// Rustdoc text for a description, or `None` if nothing useful remains.
pub fn summary(description: &str) -> Option<String> {
    let text = strip_html(description);
    let paragraph = text
        .split("\n\n")
        .map(|p| {
            p.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .find(|p| !p.is_empty())?;
    Some(escape_markdown(&truncate(&paragraph, MAX_CHARS)))
}

/// Replaces line-break tags with newlines and drops all other tags.
fn strip_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('<') {
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        match after.find('>') {
            Some(end) if looks_like_tag(&after[1..end]) => {
                let tag = after[1..end].trim().to_ascii_lowercase();
                if tag.starts_with("br") || tag == "p" || tag == "/p" || tag.starts_with("li") {
                    out.push('\n');
                    if tag != "li" && !tag.starts_with("br") {
                        out.push('\n');
                    }
                }
                rest = &after[end + 1..];
            }
            _ => {
                out.push('<');
                rest = &after[1..];
            }
        }
    }
    out.push_str(rest);
    out.replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// HTML elements that appear in Cybersource descriptions. Anything else in
/// angle brackets (e.g. `<none>`, `<merchant id>`) is text.
const HTML_TAGS: &[&str] = &[
    "a", "b", "br", "code", "div", "em", "font", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i",
    "img", "li", "ol", "p", "pre", "span", "strong", "sub", "sup", "table", "tbody", "td", "th",
    "thead", "tr", "u", "ul",
];

fn looks_like_tag(inner: &str) -> bool {
    let name: String = inner
        .trim_start_matches('/')
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    HTML_TAGS.contains(&name.as_str()) && !inner.contains('<')
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let cut: String = s.chars().take(max).collect();
    let at_word = cut.rfind(' ').map_or(cut.as_str(), |i| &cut[..i]);
    format!("{}…", at_word.trim_end_matches([',', ';', ':', ' ']))
}

/// Escapes characters rustdoc would treat as links, HTML or emphasis.
fn escape_markdown(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '[' | ']' | '*' | '_' | '`' | '\\' | '#' => {
                out.push('\\');
                out.push(c);
            }
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_first_paragraph_only() {
        assert_eq!(
            summary("First line\ncontinues.\n\nSecond paragraph.").as_deref(),
            Some("First line continues.")
        );
    }

    #[test]
    fn indented_text_cannot_become_a_doctest() {
        let doc = summary("Example:\n    let x = 1;").unwrap();
        assert!(!doc.contains("    "), "{doc:?}");
    }

    #[test]
    fn html_breaks_become_paragraphs_and_tags_are_dropped() {
        assert_eq!(
            summary("Use <b>this</b> value.<br><br>More detail.").as_deref(),
            Some("Use this value.")
        );
    }

    #[test]
    fn markup_is_escaped() {
        assert_eq!(
            summary("Values [A, B] or <none>, see field_name.").as_deref(),
            Some(r"Values \[A, B\] or &lt;none&gt;, see field\_name.")
        );
    }

    #[test]
    fn long_text_is_cut_at_a_word() {
        let doc = summary(&"word ".repeat(200)).unwrap();
        assert!(doc.ends_with("word…"));
        assert!(doc.chars().count() <= MAX_CHARS + 1);
    }

    #[test]
    fn empty_descriptions_give_none() {
        assert_eq!(summary("  \n <br> "), None);
    }
}
