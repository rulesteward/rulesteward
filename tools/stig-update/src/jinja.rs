//! A bounded evaluator for the per-product Jinja conditionals ComplianceAsCode
//! sysctl rules use. NOT a general Jinja engine: it handles exactly the
//! `{% if/elif/else/endif %}` statements (and the doubled `{{% %}}` form CaC source
//! uses) over the grammar the sysctl rules exercise - `product == 'X'`,
//! `product (not) in [..]`, `'tok' in product` (substring), `'tok' in families`
//! (list membership), combined with `and` / `or` and parentheses - so a rule.yml
//! can be collapsed to plain YAML for a given target product before parsing.

/// Product identity facts the conditionals test against.
pub struct ProductFacts {
    /// The product string, e.g. `rhel9`. `'tok' in product` is a substring test.
    pub product: String,
    /// The product's family tokens, e.g. `["rhel"]`. `'tok' in families` is a
    /// membership test.
    pub families: Vec<String>,
}

impl ProductFacts {
    /// Facts for a RHEL product string (`rhel8` / `rhel9` / `rhel10`): the EL family
    /// token the sysctl rules test for is `rhel` (the `'ol' in families` branch is
    /// Oracle Linux, which we do not target).
    #[must_use]
    pub fn rhel(product: &str) -> Self {
        ProductFacts {
            product: product.to_string(),
            families: vec!["rhel".to_string()],
        }
    }
}

/// Evaluate one conditional expression for `facts`.
pub fn eval_condition(expr: &str, facts: &ProductFacts) -> Result<bool, String> {
    let toks = tokenize(expr)?;
    let mut p = Parser { toks, pos: 0 };
    let value = p.or_expr(facts)?;
    if p.pos != p.toks.len() {
        return Err(format!(
            "trailing tokens in condition {expr:?} (parsed {} of {})",
            p.pos,
            p.toks.len()
        ));
    }
    Ok(value)
}

/// Collapse `{% if/elif/else/endif %}` (and the doubled `{{% %}}` form) in `text`,
/// keeping only the branch live for `facts`; non-conditional lines are preserved
/// verbatim (indentation + newlines). The result is plain YAML.
pub fn resolve_for_product(text: &str, facts: &ProductFacts) -> Result<String, String> {
    // CaC source doubles the delimiters (`{{% ... %}}`); normalize to single so the
    // line scanner sees `{% ... %}`. Expression delimiters `{{ }}` / `{{{ }}}` are
    // left untouched (they only appear inside quoted/block YAML scalars).
    let normalized = text.replace("{{%", "{%").replace("%}}", "%}");

    struct Frame {
        /// Some branch in this if-chain has already been taken (suppresses later arms).
        taken: bool,
        /// This branch's body should be emitted (gated by all enclosing frames).
        emit: bool,
    }
    let mut stack: Vec<Frame> = Vec::new();
    let mut out = String::new();

    for line in normalized.split_inclusive('\n') {
        let Some(inner) = directive_inner(line.trim()) else {
            // Content line: emit iff every enclosing branch is live.
            if stack.iter().all(|f| f.emit) {
                out.push_str(line);
            }
            continue;
        };
        // Tolerate whitespace-control markers `{%- ... -%}`.
        let inner = inner.trim().trim_matches('-').trim();
        let mut parts = inner.splitn(2, char::is_whitespace);
        let keyword = parts.next().unwrap_or("");
        let cond = parts.next().unwrap_or("").trim();
        match keyword {
            "if" => {
                let parent_emit = stack.iter().all(|f| f.emit);
                let c = eval_condition(cond, facts)?;
                stack.push(Frame {
                    taken: c,
                    emit: parent_emit && c,
                });
            }
            "elif" => {
                let parent_emit = stack[..stack.len().saturating_sub(1)]
                    .iter()
                    .all(|f| f.emit);
                if stack.last().ok_or("elif without if")?.taken {
                    stack.last_mut().unwrap().emit = false;
                } else {
                    let c = eval_condition(cond, facts)?;
                    let top = stack.last_mut().unwrap();
                    top.taken = c;
                    top.emit = parent_emit && c;
                }
            }
            "else" => {
                let parent_emit = stack[..stack.len().saturating_sub(1)]
                    .iter()
                    .all(|f| f.emit);
                let top = stack.last_mut().ok_or("else without if")?;
                if top.taken {
                    top.emit = false;
                } else {
                    top.emit = parent_emit;
                    top.taken = true;
                }
            }
            "endif" => {
                stack.pop().ok_or("endif without if")?;
            }
            other => return Err(format!("unsupported jinja directive {other:?} in {line:?}")),
        }
    }
    if !stack.is_empty() {
        return Err("unclosed jinja `if` block".to_string());
    }
    Ok(out)
}

/// The inner text of a `{% ... %}` directive line, or `None` for a content line.
fn directive_inner(trimmed: &str) -> Option<&str> {
    trimmed.strip_prefix("{%")?.strip_suffix("%}")
}

// --- condition tokenizer + recursive-descent evaluator -----------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    And,
    Or,
    Not,
    In,
    Eq,
    Ne,
    Ident(String),
    Str(String),
}

fn tokenize(s: &str) -> Result<Vec<Tok>, String> {
    let b = s.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match c {
            b' ' | b'\t' | b'\n' | b'\r' => i += 1,
            b'(' => {
                toks.push(Tok::LParen);
                i += 1;
            }
            b')' => {
                toks.push(Tok::RParen);
                i += 1;
            }
            b'[' => {
                toks.push(Tok::LBracket);
                i += 1;
            }
            b']' => {
                toks.push(Tok::RBracket);
                i += 1;
            }
            b',' => {
                toks.push(Tok::Comma);
                i += 1;
            }
            b'=' if i + 1 < b.len() && b[i + 1] == b'=' => {
                toks.push(Tok::Eq);
                i += 2;
            }
            b'!' if i + 1 < b.len() && b[i + 1] == b'=' => {
                toks.push(Tok::Ne);
                i += 2;
            }
            b'\'' | b'"' => {
                let start = i + 1;
                let mut j = start;
                while j < b.len() && b[j] != c {
                    j += 1;
                }
                if j >= b.len() {
                    return Err(format!("unterminated string in condition {s:?}"));
                }
                toks.push(Tok::Str(s[start..j].to_string()));
                i = j + 1;
            }
            _ if c.is_ascii_alphanumeric() || c == b'_' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                toks.push(match &s[start..i] {
                    "and" => Tok::And,
                    "or" => Tok::Or,
                    "not" => Tok::Not,
                    "in" => Tok::In,
                    word => Tok::Ident(word.to_string()),
                });
            }
            _ => {
                return Err(format!(
                    "unexpected char {:?} in condition {s:?}",
                    c as char
                ));
            }
        }
    }
    Ok(toks)
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == Some(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, t: &Tok) -> Result<(), String> {
        if self.eat(t) {
            Ok(())
        } else {
            Err(format!("expected {t:?}, found {:?}", self.peek()))
        }
    }

    fn take_str(&mut self) -> Result<String, String> {
        match self.peek().cloned() {
            Some(Tok::Str(s)) => {
                self.pos += 1;
                Ok(s)
            }
            other => Err(format!("expected string, found {other:?}")),
        }
    }

    fn or_expr(&mut self, f: &ProductFacts) -> Result<bool, String> {
        let mut v = self.and_expr(f)?;
        while self.eat(&Tok::Or) {
            v = self.and_expr(f)? || v;
        }
        Ok(v)
    }

    fn and_expr(&mut self, f: &ProductFacts) -> Result<bool, String> {
        let mut v = self.atom(f)?;
        while self.eat(&Tok::And) {
            v = self.atom(f)? && v;
        }
        Ok(v)
    }

    fn atom(&mut self, f: &ProductFacts) -> Result<bool, String> {
        if self.eat(&Tok::LParen) {
            let v = self.or_expr(f)?;
            self.expect(&Tok::RParen)?;
            return Ok(v);
        }
        self.comparison(f)
    }

    fn comparison(&mut self, f: &ProductFacts) -> Result<bool, String> {
        match self.peek().cloned() {
            // `'str' [not] in (product|families)`
            Some(Tok::Str(s)) => {
                self.pos += 1;
                let neg = self.eat(&Tok::Not);
                self.expect(&Tok::In)?;
                let target = match self.peek().cloned() {
                    Some(Tok::Ident(id)) => {
                        self.pos += 1;
                        id
                    }
                    other => {
                        return Err(format!("expected identifier after `in`, found {other:?}"));
                    }
                };
                let present = match target.as_str() {
                    "product" => f.product.contains(&s),
                    "families" => f.families.contains(&s),
                    other => return Err(format!("unknown `in` target {other:?}")),
                };
                Ok(present ^ neg)
            }
            // `product (== | != | [not] in) ...`
            Some(Tok::Ident(id)) if id == "product" => {
                self.pos += 1;
                if self.eat(&Tok::Eq) {
                    Ok(f.product == self.take_str()?)
                } else if self.eat(&Tok::Ne) {
                    Ok(f.product != self.take_str()?)
                } else if self.eat(&Tok::In) {
                    Ok(self.list()?.contains(&f.product))
                } else if self.eat(&Tok::Not) {
                    self.expect(&Tok::In)?;
                    Ok(!self.list()?.contains(&f.product))
                } else {
                    Err(format!(
                        "unexpected token after `product`: {:?}",
                        self.peek()
                    ))
                }
            }
            other => Err(format!("unexpected operand {other:?} in condition")),
        }
    }

    fn list(&mut self) -> Result<Vec<String>, String> {
        self.expect(&Tok::LBracket)?;
        let mut items = Vec::new();
        if self.peek() != Some(&Tok::RBracket) {
            loop {
                items.push(self.take_str()?);
                if !self.eat(&Tok::Comma) {
                    break;
                }
            }
        }
        self.expect(&Tok::RBracket)?;
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::{ProductFacts, eval_condition, resolve_for_product};

    fn ok(expr: &str, product: &str) -> bool {
        eval_condition(expr, &ProductFacts::rhel(product)).expect("valid condition")
    }

    #[test]
    fn equality() {
        assert!(ok("product == 'rhel8'", "rhel8"));
        assert!(!ok("product == 'rhel8'", "rhel9"));
        assert!(ok("product != 'rhel8'", "rhel9"));
    }

    #[test]
    fn substring_in_product() {
        // `'rhel' in product` is a substring test, true for every rhelN.
        assert!(ok("'rhel' in product", "rhel9"));
        assert!(ok("'rhel' in product", "rhel10"));
    }

    #[test]
    fn membership_in_families() {
        // families = ["rhel"] for our targets, so 'ol' (Oracle) is absent.
        assert!(!ok("'ol' in families", "rhel9"));
        assert!(ok("'rhel' in families", "rhel9"));
    }

    #[test]
    fn product_in_list() {
        assert!(!ok("product in ['ubuntu2404']", "rhel8"));
        assert!(ok("product not in ['ol9','rhel9']", "rhel8"));
        assert!(!ok("product not in ['ol9','rhel9']", "rhel9"));
        assert!(ok("product not in ['ol9','rhel9']", "rhel10"));
    }

    #[test]
    fn the_rp_filter_compound_condition() {
        // The sharpest real case: rhel8/rhel10 -> true (accept {1,2}); rhel9 -> false.
        let e = "('ol' in families or 'rhel' in product) and product not in ['ol9','rhel9']";
        assert!(ok(e, "rhel8"));
        assert!(!ok(e, "rhel9"));
        assert!(ok(e, "rhel10"));
    }

    #[test]
    fn malformed_condition_errors() {
        assert!(eval_condition("product = 'rhel8'", &ProductFacts::rhel("rhel8")).is_err());
        assert!(eval_condition("product == ", &ProductFacts::rhel("rhel8")).is_err());
    }

    #[test]
    fn resolve_keeps_the_live_branch_kptr_restrict() {
        // The real kptr_restrict block (doubled `{{% %}}` delimiters): rhel8 keeps
        // the scalar `1`, rhel9 keeps the `[1,2]` list.
        let block = "\
sysctlvar: kernel.kptr_restrict
{{% if product == 'rhel8' %}}
sysctlval: '1'
{{% elif 'ol' in families or 'rhel' in product %}}
sysctlval:
- '1'
- '2'
{{% endif %}}
datatype: int
";
        let r8 = resolve_for_product(block, &ProductFacts::rhel("rhel8")).unwrap();
        assert!(
            r8.contains("sysctlval: '1'"),
            "rhel8 keeps the scalar: {r8:?}"
        );
        assert!(!r8.contains("- '2'"), "rhel8 drops the [1,2] list: {r8:?}");
        // The directive lines themselves must be gone.
        assert!(
            !r8.contains("{%") && !r8.contains("%}"),
            "directives stripped: {r8:?}"
        );

        let r9 = resolve_for_product(block, &ProductFacts::rhel("rhel9")).unwrap();
        assert!(r9.contains("- '2'"), "rhel9 keeps the [1,2] list: {r9:?}");
        assert!(
            !r9.contains("sysctlval: '1'"),
            "rhel9 drops the scalar branch: {r9:?}"
        );
    }

    #[test]
    fn resolve_keeps_the_else_branch_ptrace_scope() {
        // ptrace_scope: only ubuntu2404 gets [1,2,3]; everything else (rhelN) the else.
        let block = "\
{{% if product in ['ubuntu2404'] %}}
sysctlval:
  - '1'
  - '2'
  - '3'
{{% else %}}
sysctlval: '1'
{{% endif %}}
";
        let r9 = resolve_for_product(block, &ProductFacts::rhel("rhel9")).unwrap();
        assert!(
            r9.contains("sysctlval: '1'"),
            "rhel9 takes the else: {r9:?}"
        );
        assert!(!r9.contains("- '3'"), "rhel9 drops the ubuntu list: {r9:?}");
    }
}
