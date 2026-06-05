//! Generic RFC-4180-ish CSV serializer.
//!
//! A small, pure, reusable helper: it takes a header row and a list of string
//! rows and produces a CSV string. Quoting follows RFC 4180: a field is quoted
//! iff it contains a comma, a double-quote, a carriage return, or a line feed;
//! an embedded double-quote is escaped by doubling it (`"` -> `""`). Rows are
//! joined with `\n`, the header row comes first, and the output ends with a
//! trailing newline (shell-pipeline safety, matching the JSON convention).
//!
//! This round it is wired into `report` only; `trustdb` / `auditd` CSV are
//! deferred.

/// Serialize a table to an RFC-4180-ish CSV string with a trailing newline.
///
/// `headers` is the header row; `rows` is the body, each a vector of fields in
/// column order. Callers are responsible for supplying rows whose length
/// matches `headers` - this function does not pad or validate column counts.
#[must_use]
pub fn to_csv(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut out = String::new();
    write_record(&mut out, headers.iter().map(|h| escape_field(h)));
    for row in rows {
        out.push('\n');
        write_record(&mut out, row.iter().map(|f| escape_field(f)));
    }
    out.push('\n');
    out
}

/// Append one CSV record (the already-escaped fields, comma-joined) to `out`.
fn write_record(out: &mut String, mut fields: impl Iterator<Item = String>) {
    if let Some(first) = fields.next() {
        out.push_str(&first);
        for field in fields {
            out.push(',');
            out.push_str(&field);
        }
    }
}

/// Quote+escape a single field per RFC 4180.
///
/// Quote iff the field contains `,`, `"`, CR, or LF; escape an embedded `"` by
/// doubling it. A field needing no quoting is returned unchanged.
fn escape_field(field: &str) -> String {
    let needs_quoting = field.contains([',', '"', '\r', '\n']);
    if !needs_quoting {
        return field.to_owned();
    }
    let mut quoted = String::with_capacity(field.len() + 2);
    quoted.push('"');
    for ch in field.chars() {
        if ch == '"' {
            quoted.push('"');
        }
        quoted.push(ch);
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(fields: &[&str]) -> Vec<String> {
        fields.iter().map(|s| (*s).to_owned()).collect()
    }

    /// Plain fields (no special characters) are emitted unquoted, comma-joined,
    /// header first, with a trailing newline.
    #[test]
    fn plain_fields_unquoted() {
        let csv = to_csv(&["a", "b"], &[row(&["1", "2"]), row(&["3", "4"])]);
        assert_eq!(csv, "a,b\n1,2\n3,4\n");
    }

    /// A field containing a comma must be wrapped in double quotes.
    #[test]
    fn comma_field_is_quoted() {
        let csv = to_csv(&["x"], &[row(&["a,b"])]);
        assert_eq!(csv, "x\n\"a,b\"\n");
    }

    /// A field containing a double-quote is quoted and the inner quote doubled.
    #[test]
    fn quote_field_is_escaped_by_doubling() {
        let csv = to_csv(&["x"], &[row(&["a\"b"])]);
        assert_eq!(csv, "x\n\"a\"\"b\"\n");
    }

    /// A field containing a newline (LF) must be quoted.
    #[test]
    fn newline_field_is_quoted() {
        let csv = to_csv(&["x"], &[row(&["a\nb"])]);
        assert_eq!(csv, "x\n\"a\nb\"\n");
    }

    /// A field containing a carriage return (CR) must be quoted.
    #[test]
    fn carriage_return_field_is_quoted() {
        let csv = to_csv(&["x"], &[row(&["a\rb"])]);
        assert_eq!(csv, "x\n\"a\rb\"\n");
    }

    /// Headers only (no rows) emit just the header row plus a trailing newline.
    #[test]
    fn headers_only_no_rows() {
        let csv = to_csv(&["a", "b", "c"], &[]);
        assert_eq!(csv, "a,b,c\n");
    }

    /// Every output ends with exactly one trailing newline.
    #[test]
    fn output_ends_with_trailing_newline() {
        assert!(to_csv(&["a"], &[]).ends_with('\n'));
        assert!(to_csv(&["a"], &[row(&["1"])]).ends_with('\n'));
    }

    /// A header field with special characters is also quoted (escaping applies
    /// to the header row, not just the body).
    #[test]
    fn header_field_is_escaped() {
        let csv = to_csv(&["a,b"], &[]);
        assert_eq!(csv, "\"a,b\"\n");
    }

    /// An empty field round-trips as an empty (unquoted) cell.
    #[test]
    fn empty_field_is_empty_cell() {
        let csv = to_csv(&["a", "b"], &[row(&["", "x"])]);
        assert_eq!(csv, "a,b\n,x\n");
    }
}
