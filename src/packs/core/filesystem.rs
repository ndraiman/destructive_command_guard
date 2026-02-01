//! Core filesystem patterns - protections against destructive rm commands.
//!
//! This includes patterns for:
//! - rm -rf outside temp directories (blocked)
//! - rm -rf in /tmp, /var/tmp, $TMPDIR (allowed)

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, Platform, SafePattern, Severity};
use crate::{destructive_pattern, safe_pattern};

// ============================================================================
// Suggestion constants (must be 'static for the pattern struct)
// ============================================================================

/// Suggestions for `rm -rf` on root/home paths pattern.
const RM_RF_ROOT_HOME_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "find {path} -type f | head -20",
        "Preview what files would be deleted before running",
    ),
    PatternSuggestion::new(
        "ls -la {path}",
        "List directory contents to verify the path",
    ),
    PatternSuggestion::new(
        "rm -rf /path/to/specific/subdirectory",
        "Use explicit, specific paths instead of root or home",
    ),
];

/// Suggestions for general `rm -rf` pattern.
const RM_RF_GENERAL_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "rm -ri {path}",
        "Interactive mode: confirms each file before deletion",
    ),
    PatternSuggestion::with_platform(
        "trash-put {path}",
        "Move to trash instead of permanent deletion (requires trash-cli)",
        Platform::Linux,
    ),
    PatternSuggestion::with_platform(
        "gio trash {path}",
        "Move to trash via GNOME (requires gio)",
        Platform::Linux,
    ),
    PatternSuggestion::new(
        "mv {path} /tmp/delete-me-{timestamp}",
        "Move to a temp holding area instead of deleting immediately",
    ),
    PatternSuggestion::new(
        "rm -rf /tmp/{subdir}",
        "Safe temp directory deletion (allowed without confirmation)",
    ),
    PatternSuggestion::new(
        "find {path} -type f | wc -l",
        "Count files that would be deleted before proceeding",
    ),
    PatternSuggestion::new(
        "ls -la {path}",
        "List directory contents to verify the path",
    ),
];

/// Suggestions for `rm -r -f` (separate flags) pattern.
const RM_R_F_SEPARATE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "rm -ri {path}",
        "Interactive mode: confirms each file before deletion",
    ),
    PatternSuggestion::new(
        "rm -r -f /tmp/{subdir}",
        "Safe temp directory deletion (allowed without confirmation)",
    ),
    PatternSuggestion::new(
        "rm -r -f $TMPDIR/{subdir}",
        "Use system temp directory (allowed without confirmation)",
    ),
    PatternSuggestion::new(
        "find {path} -type f | head -20",
        "Preview files before deletion",
    ),
];

/// Suggestions for `rm --recursive --force` (long flags) pattern.
const RM_RECURSIVE_FORCE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "rm --interactive --recursive {path}",
        "Interactive mode: confirms each file before deletion",
    ),
    PatternSuggestion::new(
        "find {path} --maxdepth 2 -ls | head -30",
        "Preview directory structure before deletion",
    ),
    PatternSuggestion::new(
        "rm --recursive --force /tmp/{subdir}",
        "Safe temp directory deletion (allowed without confirmation)",
    ),
];
use crate::{normalize::NormalizeTokenKind, normalize::tokenize_for_normalization};
use std::ops::Range;

const RM_RF_ROOT_HOME_NAME: &str = "rm-rf-root-home";
const RM_RF_ROOT_HOME_REASON: &str = "rm -rf on root or home paths is EXTREMELY DANGEROUS. This command will NOT be executed. Ask the user to run it manually if truly needed.";
const RM_RF_GENERAL_NAME: &str = "rm-rf-general";
const RM_RF_GENERAL_REASON: &str = "rm -rf is destructive and requires human approval. Explain what you want to delete and why, then ask the user to run the command manually.";
const RM_R_F_SEPARATE_NAME: &str = "rm-r-f-separate";
const RM_R_F_SEPARATE_REASON: &str =
    "rm with separate -r -f flags is destructive and requires human approval.";
const RM_RECURSIVE_FORCE_NAME: &str = "rm-recursive-force-long";
const RM_RECURSIVE_FORCE_REASON: &str =
    "rm --recursive --force is destructive and requires human approval.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteKind {
    None,
    Single,
    Double,
}

#[derive(Debug, Clone)]
pub(crate) struct RmParseMatch {
    pub(crate) pattern_name: &'static str,
    pub(crate) reason: &'static str,
    pub(crate) severity: Severity,
    /// Byte span of the flags for highlighting.
    pub(crate) span: Option<Range<usize>>,
    /// Byte span of "rm" and its flags for text replacement (e.g., "rm -rf").
    pub(crate) rm_span: Range<usize>,
}

#[derive(Debug, Clone)]
pub(crate) enum RmParseDecision {
    Allow,
    Deny(RmParseMatch),
    /// Rewrite the rm command to use trash instead of permanent deletion.
    Rewrite(RmRewriteInfo),
    NoMatch,
}

/// Information needed to rewrite an rm command to trash.
#[derive(Debug, Clone)]
pub(crate) struct RmRewriteInfo {
    /// Byte span of "rm" and its flags (e.g., "rm -rf") for text replacement.
    pub(crate) rm_span: Range<usize>,
    /// The paths to be moved to trash (for display purposes, may be empty).
    pub(crate) paths: Vec<String>,
    /// Whether the original command had a sudo prefix.
    pub(crate) has_sudo: bool,
    /// The severity of the original match (used for logging).
    pub(crate) severity: Severity,
    /// Byte span of the match for highlighting.
    pub(crate) span: Option<Range<usize>>,
}

#[derive(Debug)]
struct PathToken<'a> {
    unquoted: &'a str,
    quote: QuoteKind,
    range: Range<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RmFlagStyle {
    Combined,
    Separate,
    Long,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RmFlagState {
    style: RmFlagStyle,
    span: Option<Range<usize>>,
    /// End byte position of the last flag (for computing rm_span).
    flags_end: usize,
    saw_terminator: bool,
}

#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
struct RmFlagTracker {
    combined_span: Option<Range<usize>>,
    seen_r: bool,
    r_span: Option<Range<usize>>,
    seen_f: bool,
    f_span: Option<Range<usize>>,
    seen_long_recursive: bool,
    recursive_span: Option<Range<usize>>,
    seen_long_force: bool,
    force_span: Option<Range<usize>>,
    saw_terminator: bool,
}

impl RmFlagTracker {
    /// Compute the end position of the last flag from all tracked spans.
    fn flags_end(&self) -> usize {
        [
            &self.combined_span,
            &self.r_span,
            &self.f_span,
            &self.recursive_span,
            &self.force_span,
        ]
        .iter()
        .filter_map(|s| s.as_ref().map(|r| r.end))
        .max()
        .unwrap_or(0)
    }

    fn resolve(self) -> Option<RmFlagState> {
        let flags_end = self.flags_end();

        if let Some(span) = self.combined_span {
            return Some(RmFlagState {
                style: RmFlagStyle::Combined,
                span: Some(span),
                flags_end,
                saw_terminator: self.saw_terminator,
            });
        }

        if self.seen_r && self.seen_f {
            return Some(RmFlagState {
                style: RmFlagStyle::Separate,
                span: self.r_span.or(self.f_span),
                flags_end,
                saw_terminator: self.saw_terminator,
            });
        }

        if self.seen_long_recursive && self.seen_long_force {
            return Some(RmFlagState {
                style: RmFlagStyle::Long,
                span: self.recursive_span.or(self.force_span),
                flags_end,
                saw_terminator: self.saw_terminator,
            });
        }

        None
    }
}

/// Parse an rm command and optionally convert Deny to Rewrite for trash-eligible commands.
///
/// This wraps `parse_rm_command` and transforms the result based on trash configuration:
/// - Critical severity (rm -rf /, rm -rf ~) → always Deny
/// - Other rm -rf commands → Rewrite when trash is enabled (uses text replacement)
///
/// # Arguments
/// * `command` - The normalized command (for pattern matching)
/// * `original_command` - The original command (for sudo prefix detection)
/// * `trash_enabled` - Whether trash rewriting is enabled
pub(crate) fn parse_rm_command_with_trash(
    command: &str,
    original_command: &str,
    trash_enabled: bool,
) -> RmParseDecision {
    let result = parse_rm_command(command);

    // If trash rewriting is disabled, return the original result
    if !trash_enabled {
        return result;
    }

    // Only transform Deny decisions
    let RmParseDecision::Deny(ref match_info) = result else {
        return result;
    };

    // Never rewrite Critical severity (rm -rf /, rm -rf ~)
    if match_info.severity == Severity::Critical {
        return result;
    }

    // Extract paths for display (may be empty for complex commands like loops)
    // Check sudo on original_command since normalization strips it
    let has_sudo = crate::trash::has_sudo_prefix(original_command);
    let paths = extract_rm_paths(command);

    RmParseDecision::Rewrite(RmRewriteInfo {
        rm_span: match_info.rm_span.clone(),
        paths,
        has_sudo,
        severity: match_info.severity,
        span: match_info.span.clone(),
    })
}

/// Extract path arguments from an rm command.
fn extract_rm_paths(command: &str) -> Vec<String> {
    use crate::normalize::{NormalizeTokenKind, tokenize_for_normalization};

    let tokens = tokenize_for_normalization(command);
    let mut paths = Vec::new();
    let mut in_rm = false;
    let mut options_ended = false;

    for token in &tokens {
        if token.kind == NormalizeTokenKind::Separator {
            // Reset state at command boundaries
            if in_rm && !paths.is_empty() {
                break;
            }
            in_rm = false;
            options_ended = false;
            continue;
        }

        let Some(text) = token.text(command) else {
            continue;
        };

        // Skip sudo and env var assignments at the start; detect rm
        if !in_rm {
            if text == "rm" {
                in_rm = true;
            }
            // Skip sudo, env vars, and any token before rm
            continue;
        }

        // Skip options
        if !options_ended {
            if text == "--" {
                options_ended = true;
                continue;
            }
            if text.starts_with('-') && text != "-" {
                continue;
            }
        }

        // This is a path argument
        options_ended = true;
        let unquoted = text.trim_matches('"').trim_matches('\'');
        paths.push(unquoted.to_string());
    }

    paths
}

pub(crate) fn parse_rm_command(command: &str) -> RmParseDecision {
    let tokens = tokenize_for_normalization(command);
    if tokens.is_empty() {
        return RmParseDecision::NoMatch;
    }

    let mut i = 0;
    while i < tokens.len() {
        let current = &tokens[i];
        if current.kind == NormalizeTokenKind::Separator {
            i += 1;
            continue;
        }

        let Some(text) = current.text(command) else {
            i += 1;
            continue;
        };

        if text == "rm" {
            return parse_rm_segment(command, &tokens, i + 1, current.byte_range.start);
        }

        // Shell control keywords and commands that start new command contexts.
        // After these, the next word could be a command like "rm".
        if matches!(
            text,
            "do" | "then" | "else" | "elif" | "{" | "!" | "xargs" | "-exec" | "-execdir"
        ) {
            i += 1;
            continue;
        }

        // Skip to the next separator or control keyword before scanning for another command word.
        i += 1;
        while i < tokens.len() && tokens[i].kind != NormalizeTokenKind::Separator {
            // Check if this token is a control keyword - if so, break to continue outer loop
            if let Some(skip_text) = tokens[i].text(command) {
                if matches!(
                    skip_text,
                    "do" | "then" | "else" | "elif" | "{" | "!" | "xargs" | "-exec" | "-execdir"
                ) {
                    break;
                }
            }
            i += 1;
        }
    }

    RmParseDecision::NoMatch
}

#[allow(clippy::too_many_lines)]
fn parse_rm_segment(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
    start_idx: usize,
    rm_start: usize,
) -> RmParseDecision {
    let mut options_ended = false;
    let mut flags = RmFlagTracker::default();

    let mut paths: Vec<PathToken<'_>> = Vec::new();

    for token in tokens.iter().skip(start_idx) {
        if token.kind == NormalizeTokenKind::Separator {
            break;
        }

        let Some(text) = token.text(command) else {
            continue;
        };

        if !options_ended {
            if text == "--" {
                options_ended = true;
                flags.saw_terminator = true;
                continue;
            }

            if text.starts_with('-') && text != "-" {
                if text.starts_with("--") {
                    if text.starts_with("--recursive") {
                        flags.seen_long_recursive = true;
                        if flags.recursive_span.is_none() {
                            flags.recursive_span = Some(token.byte_range.clone());
                        }
                    }
                    if text.starts_with("--force") {
                        flags.seen_long_force = true;
                        if flags.force_span.is_none() {
                            flags.force_span = Some(token.byte_range.clone());
                        }
                    }
                } else {
                    let flag_text = text.trim_start_matches('-');
                    if !flag_text.is_empty() {
                        let has_r = flag_text.chars().any(|c| c == 'r' || c == 'R');
                        let has_f = flag_text.chars().any(|c| c == 'f');
                        if has_r && has_f {
                            if flags.combined_span.is_none() {
                                flags.combined_span = Some(token.byte_range.clone());
                            }
                        } else {
                            if has_r && !flags.seen_r {
                                flags.seen_r = true;
                                flags.r_span = Some(token.byte_range.clone());
                            }
                            if has_f && !flags.seen_f {
                                flags.seen_f = true;
                                flags.f_span = Some(token.byte_range.clone());
                            }
                        }
                    }
                }

                continue;
            }
        }

        options_ended = true;
        let (quote, unquoted) = strip_outer_quotes(text);
        paths.push(PathToken {
            unquoted,
            quote,
            range: token.byte_range.clone(),
        });
    }

    let flag_state = flags.resolve();
    let Some(flag_state) = flag_state else {
        return RmParseDecision::NoMatch;
    };

    let safe_paths = !paths.is_empty()
        && !flag_state.saw_terminator
        && paths
            .iter()
            .all(|path| path_is_safe_for_style(path, flag_state.style));

    if safe_paths {
        return RmParseDecision::Allow;
    }

    let first_path = paths.first();
    let is_critical = flag_state.style == RmFlagStyle::Combined
        && !flag_state.saw_terminator
        && first_path.is_some_and(path_is_root_home);

    let (pattern_name, reason, severity) = if is_critical {
        (
            RM_RF_ROOT_HOME_NAME,
            RM_RF_ROOT_HOME_REASON,
            Severity::Critical,
        )
    } else {
        match flag_state.style {
            RmFlagStyle::Combined => (RM_RF_GENERAL_NAME, RM_RF_GENERAL_REASON, Severity::High),
            RmFlagStyle::Separate => (RM_R_F_SEPARATE_NAME, RM_R_F_SEPARATE_REASON, Severity::High),
            RmFlagStyle::Long => (
                RM_RECURSIVE_FORCE_NAME,
                RM_RECURSIVE_FORCE_REASON,
                Severity::High,
            ),
        }
    };

    let span = flag_state
        .span
        .or_else(|| paths.first().map(|path| path.range.clone()));

    RmParseDecision::Deny(RmParseMatch {
        pattern_name,
        reason,
        severity,
        span,
        rm_span: rm_start..flag_state.flags_end,
    })
}

fn strip_outer_quotes(token: &str) -> (QuoteKind, &str) {
    if token.len() >= 2 {
        if token.starts_with('"') && token.ends_with('"') {
            return (QuoteKind::Double, &token[1..token.len() - 1]);
        }
        if token.starts_with('\'') && token.ends_with('\'') {
            return (QuoteKind::Single, &token[1..token.len() - 1]);
        }
    }
    (QuoteKind::None, token)
}

fn path_is_safe_for_style(path: &PathToken<'_>, style: RmFlagStyle) -> bool {
    if path.quote == QuoteKind::Double && style != RmFlagStyle::Combined {
        return false;
    }

    match path.quote {
        QuoteKind::None => path_is_safe_unquoted(path.unquoted),
        QuoteKind::Double => path_is_safe_double_quoted(path.unquoted),
        QuoteKind::Single => false,
    }
}

fn path_is_safe_unquoted(path: &str) -> bool {
    if let Some(rest) = path.strip_prefix("/tmp/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("/var/tmp/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("$TMPDIR/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("${TMPDIR}/") {
        return !has_dotdot_segment(rest);
    }
    // Handle shell default value syntax: ${TMPDIR:-/tmp} and ${TMPDIR:-/var/tmp}
    // These always expand to a safe temp directory.
    if let Some(rest) = path.strip_prefix("${TMPDIR:-/tmp}/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("${TMPDIR:-/var/tmp}/") {
        return !has_dotdot_segment(rest);
    }
    false
}

fn path_is_safe_double_quoted(path: &str) -> bool {
    if let Some(rest) = path.strip_prefix("$TMPDIR/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("${TMPDIR}/") {
        return !has_dotdot_segment(rest);
    }
    // Handle shell default value syntax: ${TMPDIR:-/tmp} and ${TMPDIR:-/var/tmp}
    // These always expand to a safe temp directory.
    if let Some(rest) = path.strip_prefix("${TMPDIR:-/tmp}/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("${TMPDIR:-/var/tmp}/") {
        return !has_dotdot_segment(rest);
    }
    false
}

fn has_dotdot_segment(path: &str) -> bool {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .any(|segment| segment == "..")
}

fn path_is_root_home(path: &PathToken<'_>) -> bool {
    // Check if the path is root or home, ignoring quotes for absolute paths.
    // Tilde expansion only happens if UNQUOTED, but / is absolute regardless.

    let text = path.unquoted;

    // Absolute paths starting with / are dangerous regardless of quotes
    // e.g. rm -rf "/" is just as deadly as rm -rf /
    if text.starts_with('/') {
        return true;
    }

    // Tilde expansion (~/) only happens if unquoted
    if path.quote == QuoteKind::None && text.starts_with('~') {
        return true;
    }

    false
}

/// Create the core filesystem pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "core.filesystem".to_string(),
        name: "Core Filesystem",
        description: "Protects against dangerous rm -rf commands outside temp directories",
        keywords: &["rm"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

#[allow(clippy::too_many_lines)]
fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // rm -rf in /tmp (combined flags)
        safe_pattern!(
            "rm-rf-tmp",
            r"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-fr-tmp",
            r"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -rf in /var/tmp (combined flags)
        safe_pattern!(
            "rm-rf-var-tmp",
            r"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-fr-var-tmp",
            r"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -rf with $TMPDIR (combined flags)
        safe_pattern!(
            "rm-rf-tmpdir",
            r"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-fr-tmpdir",
            r"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -rf with ${TMPDIR} (braced form)
        safe_pattern!(
            "rm-rf-tmpdir-brace",
            r"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-fr-tmpdir-brace",
            r"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -rf with quoted $TMPDIR
        safe_pattern!(
            "rm-rf-tmpdir-quoted",
            r#"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:"\$TMPDIR/(?!(?:[^"]*/)?\.\.(?:/|"))[^"]*"(?:\s+|$))+$"#
        ),
        safe_pattern!(
            "rm-fr-tmpdir-quoted",
            r#"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:"\$TMPDIR/(?!(?:[^"]*/)?\.\.(?:/|"))[^"]*"(?:\s+|$))+$"#
        ),
        // rm -rf with quoted ${TMPDIR}
        safe_pattern!(
            "rm-rf-tmpdir-brace-quoted",
            r#"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:"\$\{TMPDIR\}/(?!(?:[^"]*/)?\.\.(?:/|"))[^"]*"(?:\s+|$))+$"#
        ),
        safe_pattern!(
            "rm-fr-tmpdir-brace-quoted",
            r#"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:"\$\{TMPDIR\}/(?!(?:[^"]*/)?\.\.(?:/|"))[^"]*"(?:\s+|$))+$"#
        ),
        // rm -r -f (separate flags) in /tmp
        safe_pattern!(
            "rm-r-f-tmp",
            r"^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-f-r-tmp",
            r"^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -r -f (separate flags) in /var/tmp
        safe_pattern!(
            "rm-r-f-var-tmp",
            r"^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-f-r-var-tmp",
            r"^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -r -f (separate flags) with $TMPDIR
        safe_pattern!(
            "rm-r-f-tmpdir",
            r"^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-f-r-tmpdir",
            r"^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -r -f (separate flags) with ${TMPDIR}
        safe_pattern!(
            "rm-r-f-tmpdir-brace",
            r"^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-f-r-tmpdir-brace",
            r"^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm --recursive --force (long flags) in /tmp
        safe_pattern!(
            "rm-recursive-force-tmp",
            r"^rm\s+.*--recursive.*--force\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-force-recursive-tmp",
            r"^rm\s+.*--force.*--recursive\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm --recursive --force (long flags) in /var/tmp
        safe_pattern!(
            "rm-recursive-force-var-tmp",
            r"^rm\s+.*--recursive.*--force\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-force-recursive-var-tmp",
            r"^rm\s+.*--force.*--recursive\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm --recursive --force (long flags) with $TMPDIR
        safe_pattern!(
            "rm-recursive-force-tmpdir",
            r"^rm\s+.*--recursive.*--force\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-force-recursive-tmpdir",
            r"^rm\s+.*--force.*--recursive\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm --recursive --force (long flags) with ${TMPDIR}
        safe_pattern!(
            "rm-recursive-force-tmpdir-brace",
            r"^rm\s+.*--recursive.*--force\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-force-recursive-tmpdir-brace",
            r"^rm\s+.*--force.*--recursive\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    // Severity levels:
    // - Critical: Most dangerous, irreversible, high-confidence detections
    // - High: Dangerous but more context-dependent (default)
    // - Medium: Warn by default
    // - Low: Log only

    vec![
        // rm -rf on root or home paths (CRITICAL - catastrophic, never allow)
        destructive_pattern!(
            "rm-rf-root-home",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+[/~]|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+[/~]",
            "rm -rf on root or home paths is EXTREMELY DANGEROUS. This command will NOT be executed. Ask the user to run it manually if truly needed.",
            Critical,
            "This command would recursively delete files starting from the root filesystem (/) \
             or home directory (~). This is catastrophic and will destroy:\n\n\
             - Your entire operating system\n\
             - All installed applications and libraries\n\
             - All user data, documents, and configurations\n\
             - Boot files, making the system unbootable\n\n\
             There is NO recovery without backups. Even with backups, full restoration \
             takes hours to days.\n\n\
             If you need to delete specific files, use explicit paths:\n  \
             rm -rf /path/to/specific/directory\n\n\
             Always preview what would be deleted first:\n  \
             find /path/to/directory -type f | head -20",
            RM_RF_ROOT_HOME_SUGGESTIONS
        ),
        // General rm -rf (caught after safe patterns) - High because temp paths are allowed
        destructive_pattern!(
            "rm-rf-general",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR]",
            "rm -rf is destructive and requires human approval. Explain what you want to delete and why, then ask the user to run the command manually.",
            High,
            "rm -rf recursively removes files and directories without confirmation prompts. \
             The -f (force) flag suppresses all warnings, making accidental deletions \
             silent and immediate.\n\n\
             Why this is dangerous:\n\
             - Deleted files bypass the trash - they're gone immediately\n\
             - Typos in paths can delete unintended directories\n\
             - Wildcards can expand to match more than expected\n\
             - No undo mechanism exists\n\n\
             Safe alternatives:\n\
             - rm -ri: Interactive mode, confirms each file\n\
             - trash-cli: Moves files to trash instead of deleting\n\
             - rm -rf in /tmp, /var/tmp, $TMPDIR: Allowed (safe temp directories)\n\n\
             Preview what would be deleted:\n  \
             find /path/to/delete -type f | wc -l  # Count files\n  \
             ls -la /path/to/delete               # List contents",
            RM_RF_GENERAL_SUGGESTIONS
        ),
        // rm -r -f (separate flags)
        destructive_pattern!(
            "rm-r-f-separate",
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f|rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]",
            "rm with separate -r -f flags is destructive and requires human approval.",
            High,
            "rm with separate -r and -f flags has the same effect as rm -rf: recursive \
             forced deletion without confirmation.\n\n\
             Common variations that are all equivalent:\n\
             - rm -r -f path\n\
             - rm -f -r path\n\
             - rm -r -f -v path (verbose but still forced)\n\n\
             All carry the same risks as rm -rf: immediate, silent, irreversible deletion.\n\n\
             Safer approach for temporary directories:\n\
             - rm -r -f /tmp/mydir    # Allowed - temp directories are safe\n\
             - rm -r -f $TMPDIR/mydir # Allowed - uses system temp dir\n\n\
             For other paths, prefer:\n  \
             rm -ri /path  # Interactive confirmation",
            RM_R_F_SEPARATE_SUGGESTIONS
        ),
        // rm --recursive --force (long flags)
        destructive_pattern!(
            "rm-recursive-force-long",
            r"rm\s+.*--recursive.*--force|rm\s+.*--force.*--recursive",
            "rm --recursive --force is destructive and requires human approval.",
            High,
            "rm --recursive --force is the long-form equivalent of rm -rf. While more \
             readable, it carries identical risks: silent, recursive, irreversible deletion.\n\n\
             The long flags may appear in:\n\
             - Scripts aiming for clarity\n\
             - Generated code from build tools\n\
             - Cross-platform compatibility scenarios\n\n\
             All standard rm -rf precautions apply:\n\
             - Verify the path before running\n\
             - Use absolute paths to avoid ambiguity\n\
             - Consider using trash-cli for recoverable deletion\n\n\
             Preview command:\n  \
             find /path --maxdepth 2 -ls | head -30",
            RM_RECURSIVE_FORCE_SUGGESTIONS
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "core.filesystem");
        assert_eq!(pack.name, "Core Filesystem");
        assert!(pack.keywords.contains(&"rm"));
    }

    #[test]
    fn test_rm_rf_root_critical() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "rm -rf /", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf /etc", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf /home", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf ~/", Severity::Critical);
        assert_blocks_with_pattern(&pack, "rm -rf /", "rm-rf-root-home");
    }

    #[test]
    fn test_rm_rf_general_high() {
        let pack = create_pack();
        // Outside safe dirs, general rule catches it
        assert_blocks_with_severity(&pack, "rm -rf ./build", Severity::High);
        assert_blocks_with_pattern(&pack, "rm -rf ./build", "rm-rf-general");
    }

    #[test]
    fn test_rm_flags_ordering() {
        let pack = create_pack();
        assert_blocks(&pack, "rm -r -f ./build", "separate -r -f flags");
        assert_blocks(&pack, "rm -f -r ./build", "separate -r -f flags");
        assert_blocks(
            &pack,
            "rm --recursive --force ./build",
            "rm --recursive --force is destructive",
        );
        assert_blocks(
            &pack,
            "rm --force --recursive ./build",
            "rm --recursive --force is destructive",
        );
    }

    #[test]
    fn test_safe_rm_tmp() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "rm -rf /tmp/test");
        assert_safe_pattern_matches(&pack, "rm -rf /var/tmp/stuff");
        assert_safe_pattern_matches(&pack, "rm -rf $TMPDIR/junk");
        assert_safe_pattern_matches(&pack, "rm -rf ${TMPDIR}/junk");
    }

    #[test]
    fn test_tmpdir_brace_requires_exact_var_name() {
        let pack = create_pack();
        assert!(!pack.matches_safe("rm -rf ${TMPDIR_NOT}/junk"));
        assert_rm_parser_denies(
            "rm -rf ${TMPDIR_NOT}/junk",
            RM_RF_GENERAL_NAME,
            Severity::High,
        );
    }

    #[test]
    fn test_safe_rm_variants() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "rm -fr /tmp/test");
        assert_safe_pattern_matches(&pack, "rm -r -f /tmp/test");
        assert_safe_pattern_matches(&pack, "rm --recursive --force /tmp/test");
    }

    #[test]
    fn test_path_traversal_blocked() {
        let pack = create_pack();
        // Should NOT match safe patterns (so it falls through to destructive)
        assert!(!pack.matches_safe("rm -rf /tmp/../etc"));
        assert!(!pack.matches_safe("rm -rf /var/tmp/../etc"));

        // And should be blocked by destructive rules
        assert_blocks(&pack, "rm -rf /tmp/../etc", "rm -rf on root or home paths");
    }

    fn assert_rm_parser_allows(command: &str) {
        let decision = parse_rm_command(command);
        assert!(
            matches!(decision, RmParseDecision::Allow),
            "Expected rm parser to allow '{command}', got {decision:?}",
        );
    }

    fn assert_rm_parser_denies(command: &str, expected_rule: &str, expected_severity: Severity) {
        match parse_rm_command(command) {
            RmParseDecision::Deny(hit) => {
                assert_eq!(
                    hit.pattern_name, expected_rule,
                    "Unexpected rule for '{command}'"
                );
                assert_eq!(
                    hit.severity, expected_severity,
                    "Unexpected severity for '{command}'"
                );
            }
            other => unreachable!("Expected rm parser to deny '{command}', got {other:?}"),
        }
    }

    fn assert_rm_parser_no_match(command: &str) {
        match parse_rm_command(command) {
            RmParseDecision::NoMatch => {}
            other => {
                unreachable!("Expected rm parser to return NoMatch for '{command}', got {other:?}")
            }
        }
    }

    #[test]
    fn test_rm_parser_allows_tmpdir_quotes() {
        assert_rm_parser_allows(r#"rm -rf "$TMPDIR/foo""#);
        assert_rm_parser_allows(r#"rm -rf "${TMPDIR}/foo""#);
        assert_rm_parser_denies(r"rm -rf '$TMPDIR/foo'", RM_RF_GENERAL_NAME, Severity::High);
        assert_rm_parser_denies(
            r#"rm -r -f "$TMPDIR/foo""#,
            RM_R_F_SEPARATE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm -r -f "${TMPDIR}/foo""#,
            RM_R_F_SEPARATE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm --recursive --force "$TMPDIR/foo""#,
            RM_RECURSIVE_FORCE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm --recursive --force "${TMPDIR}/foo""#,
            RM_RECURSIVE_FORCE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm --force --recursive "$TMPDIR/foo""#,
            RM_RECURSIVE_FORCE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm --force --recursive "${TMPDIR}/foo""#,
            RM_RECURSIVE_FORCE_NAME,
            Severity::High,
        );
    }

    #[test]
    fn test_rm_parser_traversal_blocked() {
        assert_rm_parser_denies(
            "rm -rf /tmp/../etc",
            RM_RF_ROOT_HOME_NAME,
            Severity::Critical,
        );
    }

    #[test]
    fn test_rm_parser_option_terminator() {
        assert_rm_parser_no_match("rm -- -rf /tmp/safe");
    }

    #[test]
    fn test_rm_parser_for_loop_finds_rm() {
        // For loop with rm -rf should be detected
        let command = "for d in */; do rm -rf \"$d\"; done";
        let result = parse_rm_command(command);
        match result {
            RmParseDecision::Deny(hit) => {
                assert_eq!(hit.pattern_name, RM_RF_GENERAL_NAME);
                // Verify rm_span covers "rm -rf"
                let rm_text = &command[hit.rm_span.clone()];
                assert_eq!(rm_text, "rm -rf", "rm_span should cover 'rm -rf', got '{}'", rm_text);
            }
            other => panic!("Expected Deny for for loop rm, got {:?}", other),
        }
    }

    #[test]
    fn test_rm_rewrite_for_loop() {
        // Test the full rewrite flow for a for loop
        let command = "for d in */; do rm -rf \"$d\"; done";
        let result = parse_rm_command_with_trash(command, command, true);
        match result {
            RmParseDecision::Rewrite(info) => {
                // Verify rm_span covers "rm -rf"
                let rm_text = &command[info.rm_span.clone()];
                assert_eq!(rm_text, "rm -rf", "rm_span should cover 'rm -rf', got '{}'", rm_text);
            }
            other => panic!("Expected Rewrite for for loop rm with trash enabled, got {:?}", other),
        }
    }

    #[test]
    fn test_rm_parser_find_exec() {
        // find -exec rm should be detected
        let command = "find . -name \"*.tmp\" -exec rm -rf {} \\;";
        let result = parse_rm_command(command);
        match result {
            RmParseDecision::Deny(hit) => {
                assert_eq!(hit.pattern_name, RM_RF_GENERAL_NAME);
                let rm_text = &command[hit.rm_span.clone()];
                assert_eq!(rm_text, "rm -rf", "rm_span should cover 'rm -rf', got '{}'", rm_text);
            }
            other => panic!("Expected Deny for find -exec rm, got {:?}", other),
        }
    }

    #[test]
    fn test_rm_parser_xargs() {
        // xargs rm should be detected
        let command = "ls | xargs rm -rf";
        let result = parse_rm_command(command);
        match result {
            RmParseDecision::Deny(hit) => {
                assert_eq!(hit.pattern_name, RM_RF_GENERAL_NAME);
                let rm_text = &command[hit.rm_span.clone()];
                assert_eq!(rm_text, "rm -rf", "rm_span should cover 'rm -rf', got '{}'", rm_text);
            }
            other => panic!("Expected Deny for xargs rm, got {:?}", other),
        }
    }

    #[test]
    fn test_rm_rewrite_find_exec() {
        let command = "find . -exec rm -rf {} \\;";
        let result = parse_rm_command_with_trash(command, command, true);
        match result {
            RmParseDecision::Rewrite(info) => {
                let rm_text = &command[info.rm_span.clone()];
                assert_eq!(rm_text, "rm -rf", "rm_span should cover 'rm -rf', got '{}'", rm_text);
            }
            other => panic!("Expected Rewrite for find -exec rm, got {:?}", other),
        }
    }

    #[test]
    fn test_rm_rewrite_xargs() {
        let command = "ls | xargs rm -rf";
        let result = parse_rm_command_with_trash(command, command, true);
        match result {
            RmParseDecision::Rewrite(info) => {
                let rm_text = &command[info.rm_span.clone()];
                assert_eq!(rm_text, "rm -rf", "rm_span should cover 'rm -rf', got '{}'", rm_text);
            }
            other => panic!("Expected Rewrite for xargs rm, got {:?}", other),
        }
    }
}
