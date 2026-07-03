//! Body of `rulesteward fapolicyd explain`; filled by pipeline P1 (issue #74).

use rulesteward_fapolicyd::{
    Entry, SetTable, explain_event, parse_audit_event, parse_rules_file, render_human,
};

use crate::cli::{ExplainArgs, HumanJsonFormat};
use crate::exit_code::{EXIT_CLEAN, EXIT_ERRORS, EXIT_TOOL_FAILURE};
use crate::output::json::render_envelope;

/// Schema version for the `explain` kind.
///
/// Bumps only on a breaking change to the explain payload (field removal,
/// rename, or retype). Adding new optional fields is free.
const EXPLAIN_SCHEMA_VERSION: u32 = 1;

// ExplainArgs is passed by value from the match arm in fapolicyd.rs; the
// caller owns the value and clippy's by-ref suggestion would require changing
// the call site which is outside this file's scope.
#[allow(clippy::needless_pass_by_value)]
pub fn run(args: ExplainArgs) -> anyhow::Result<i32> {
    // --- Read the record file ---
    let record_input = match std::fs::read_to_string(&args.record) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: reading record file {}: {e}", args.record.display());
            return Ok(EXIT_TOOL_FAILURE);
        }
    };

    // --- Parse the audit event ---
    let event = match parse_audit_event(&record_input) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: parsing FANOTIFY record: {e}");
            // Exit 2 (EXIT_ERRORS) per f1 §4.2: an unparseable denial RECORD. NOT
            // EXIT_RULE_PARSE_ERROR (5), which spec §12.4 reserves for an unparseable
            // RULES file -- a denial record is not a rule. `auditd cost` parses a
            // rules file and returns 5; the divergence is intentional (#114).
            return Ok(EXIT_ERRORS);
        }
    };

    // --- Load the ruleset from the rules.d/ directory ---
    let ruleset_path = &args.ruleset;
    if !ruleset_path.is_dir() {
        eprintln!(
            "error: ruleset path {} is not a directory",
            ruleset_path.display()
        );
        return Ok(EXIT_TOOL_FAILURE);
    }

    let mut rule_files: Vec<std::path::PathBuf> = match std::fs::read_dir(ruleset_path) {
        Ok(rd) => rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("rules"))
            .collect(),
        Err(e) => {
            eprintln!(
                "error: reading ruleset directory {}: {e}",
                ruleset_path.display()
            );
            return Ok(EXIT_TOOL_FAILURE);
        }
    };
    rule_files.sort_by(|a, b| rulesteward_fapolicyd::fagenrules_cmp(a, b));

    let mut all_entries: Vec<Entry> = Vec::new();
    for path in &rule_files {
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: reading rule file {}: {e}", path.display());
                return Ok(EXIT_TOOL_FAILURE);
            }
        };
        match parse_rules_file(&source, path) {
            Ok(entries) => all_entries.extend(entries),
            Err(_diags) => {
                eprintln!("error: parsing rule file {}", path.display());
                return Ok(EXIT_TOOL_FAILURE);
            }
        }
    }

    // Build the Rule slice and SetTable from the parsed entries.
    let rules: Vec<&rulesteward_fapolicyd::Rule> = all_entries
        .iter()
        .filter_map(|e| {
            if let Entry::Rule(r) = e {
                Some(r)
            } else {
                None
            }
        })
        .collect();

    let sets = SetTable::from_entries(&all_entries);

    // --- Explain ---
    let result = match explain_event(&event, &rules, &sets) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            // Exit 2 per f1 §4.2: record references a rule number the ruleset lacks,
            // or replay found no deny match.
            return Ok(EXIT_ERRORS);
        }
    };

    // --- Render output ---
    match args.format {
        HumanJsonFormat::Human => {
            println!("{}", render_human(&result));
        }
        HumanJsonFormat::Json => {
            print!(
                "{}",
                render_envelope("explain", EXPLAIN_SCHEMA_VERSION, &result)
            );
        }
    }

    Ok(EXIT_CLEAN)
}
