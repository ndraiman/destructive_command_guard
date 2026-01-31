//! Trash binary detection and rm-to-trash rewriting.
//!
//! This module provides platform-specific trash binary detection and command
//! rewriting functionality to safely redirect destructive `rm` commands to
//! move files to the system trash instead of permanently deleting them.
//!
//! # Platform Detection
//!
//! The module automatically detects available trash binaries:
//! - macOS: `/usr/bin/trash` (from Homebrew's `trash` package)
//! - Linux: `gio trash` (GNOME), `trash-put` (trash-cli), `kioclient5 move` (KDE)
//!
//! # Environment Override
//!
//! The `DCG_TRASH_COMMAND` environment variable overrides platform detection:
//! ```bash
//! export DCG_TRASH_COMMAND="custom-trash"
//! ```

use std::env;
use std::process::Command;

/// Environment variable for custom trash command override.
pub const ENV_TRASH_COMMAND: &str = "DCG_TRASH_COMMAND";

/// Trash rewrite mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrashMode {
    /// Rewrite rm commands to use trash binary.
    #[default]
    Rewrite,
    /// Deny rm commands (default dcg behavior).
    Deny,
}

/// Detected trash binary information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashBinary {
    /// The command to invoke (e.g., "trash", "gio", "trash-put").
    pub command: String,
    /// Additional arguments before the paths (e.g., ["trash"] for "gio trash").
    pub args: Vec<String>,
    /// Human-readable description of the trash binary.
    pub description: &'static str,
    /// How the binary was detected.
    pub source: TrashSource,
}

/// How the trash binary was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrashSource {
    /// From DCG_TRASH_COMMAND environment variable.
    EnvVar,
    /// From config custom_command setting.
    Config,
    /// Auto-detected based on platform.
    PlatformDetection,
}

impl TrashBinary {
    /// Format a trash command for the given paths.
    #[must_use]
    pub fn format_command(&self, paths: &[&str]) -> String {
        let mut parts = vec![self.command.clone()];
        parts.extend(self.args.iter().cloned());
        parts.extend(paths.iter().map(|s| (*s).to_string()));
        parts.join(" ")
    }

    /// Format a trash command preserving sudo prefix if present.
    #[must_use]
    pub fn format_command_with_sudo(&self, paths: &[&str], has_sudo: bool) -> String {
        let trash_cmd = self.format_command(paths);
        if has_sudo {
            format!("sudo {trash_cmd}")
        } else {
            trash_cmd
        }
    }
}

/// Result of trash binary detection.
#[derive(Debug, Clone)]
pub enum TrashDetectionResult {
    /// Trash binary found and available.
    Found(TrashBinary),
    /// No trash binary available.
    NotFound {
        /// Binaries that were checked.
        checked: Vec<String>,
        /// Platform-specific installation hint.
        install_hint: &'static str,
    },
}

impl TrashDetectionResult {
    /// Returns the trash binary if found.
    #[must_use]
    pub fn binary(&self) -> Option<&TrashBinary> {
        match self {
            Self::Found(bin) => Some(bin),
            Self::NotFound { .. } => None,
        }
    }

    /// Returns true if a trash binary was found.
    #[must_use]
    pub fn is_found(&self) -> bool {
        matches!(self, Self::Found(_))
    }
}

/// Detect the available trash binary for the current platform.
///
/// Detection order:
/// 1. `DCG_TRASH_COMMAND` environment variable (if set)
/// 2. Config `custom_command` (if provided)
/// 3. Platform-specific detection
#[must_use]
pub fn detect_trash_binary(custom_command: Option<&str>) -> TrashDetectionResult {
    // 1. Check environment variable override
    if let Some(binary) = parse_custom_command(env::var(ENV_TRASH_COMMAND).ok(), TrashSource::EnvVar) {
        return TrashDetectionResult::Found(binary);
    }

    // 2. Check config custom_command
    if let Some(binary) = parse_custom_command(custom_command.map(str::to_string), TrashSource::Config) {
        return TrashDetectionResult::Found(binary);
    }

    // 3. Platform-specific detection
    detect_platform_trash_binary()
}

/// Parse a custom command string into a TrashBinary.
fn parse_custom_command(cmd: Option<String>, source: TrashSource) -> Option<TrashBinary> {
    let cmd = cmd?;
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    let first = parts.first()?;

    let description = match source {
        TrashSource::EnvVar => "Custom trash command from DCG_TRASH_COMMAND",
        TrashSource::Config => "Custom trash command from config",
        TrashSource::PlatformDetection => "Custom trash command",
    };

    Some(TrashBinary {
        command: (*first).to_string(),
        args: parts[1..].iter().map(|s| (*s).to_string()).collect(),
        description,
        source,
    })
}

/// Detect platform-specific trash binary.
fn detect_platform_trash_binary() -> TrashDetectionResult {
    let mut checked = Vec::new();

    #[cfg(target_os = "macos")]
    {
        // macOS: check for Homebrew's trash utility
        checked.push("trash".to_string());
        if command_exists("trash") {
            return TrashDetectionResult::Found(TrashBinary {
                command: "trash".to_string(),
                args: vec![],
                description: "macOS trash utility (Homebrew)",
                source: TrashSource::PlatformDetection,
            });
        }

        // Also check for trash-cli on macOS
        checked.push("trash-put".to_string());
        if command_exists("trash-put") {
            return TrashDetectionResult::Found(TrashBinary {
                command: "trash-put".to_string(),
                args: vec![],
                description: "trash-cli (cross-platform)",
                source: TrashSource::PlatformDetection,
            });
        }

        return TrashDetectionResult::NotFound {
            checked,
            install_hint: "Install with: brew install trash",
        };
    }

    #[cfg(target_os = "linux")]
    {
        // Linux: check for gio trash (GNOME), trash-put (trash-cli), kioclient5 (KDE)

        // gio trash is most common on modern Linux desktops
        checked.push("gio".to_string());
        if command_exists("gio") {
            return TrashDetectionResult::Found(TrashBinary {
                command: "gio".to_string(),
                args: vec!["trash".to_string()],
                description: "GNOME gio trash",
                source: TrashSource::PlatformDetection,
            });
        }

        // trash-cli is the most portable option
        checked.push("trash-put".to_string());
        if command_exists("trash-put") {
            return TrashDetectionResult::Found(TrashBinary {
                command: "trash-put".to_string(),
                args: vec![],
                description: "trash-cli",
                source: TrashSource::PlatformDetection,
            });
        }

        // KDE's kioclient5
        checked.push("kioclient5".to_string());
        if command_exists("kioclient5") {
            return TrashDetectionResult::Found(TrashBinary {
                command: "kioclient5".to_string(),
                args: vec!["move".to_string()],
                description: "KDE kioclient5",
                source: TrashSource::PlatformDetection,
            });
        }

        return TrashDetectionResult::NotFound {
            checked,
            install_hint: "Install with: sudo apt install trash-cli  # or: sudo dnf install trash-cli",
        };
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        // Other platforms: try trash-cli as it's cross-platform
        checked.push("trash-put".to_string());
        if command_exists("trash-put") {
            return TrashDetectionResult::Found(TrashBinary {
                command: "trash-put".to_string(),
                args: vec![],
                description: "trash-cli (cross-platform)",
                source: TrashSource::PlatformDetection,
            });
        }

        TrashDetectionResult::NotFound {
            checked,
            install_hint: "Install trash-cli: pip install trash-cli",
        }
    }
}

/// Check if a command exists in PATH.
fn command_exists(cmd: &str) -> bool {
    // Use `which` on Unix-like systems
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Information about a rewritten command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteInfo {
    /// The original rm command.
    pub original: String,
    /// The rewritten trash command.
    pub rewritten: String,
    /// Paths being moved to trash.
    pub paths: Vec<String>,
    /// The trash binary used for rewriting.
    pub trash_binary: TrashBinary,
}

/// Rewrite an rm command to use trash.
///
/// Returns `None` if the command cannot be safely rewritten (e.g., piped input,
/// find -exec, xargs).
///
/// # Arguments
///
/// * `command` - The original rm command
/// * `paths` - The paths extracted from the rm command
/// * `trash_binary` - The trash binary to use for rewriting
/// * `has_sudo` - Whether the original command has a sudo prefix
#[must_use]
pub fn rewrite_rm_to_trash(
    command: &str,
    paths: &[String],
    trash_binary: &TrashBinary,
    has_sudo: bool,
) -> Option<RewriteInfo> {
    // Check for unsafe patterns that can't be safely rewritten
    if !can_safely_rewrite(command) {
        return None;
    }

    // Convert paths to references for format_command
    let path_refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    let rewritten = trash_binary.format_command_with_sudo(&path_refs, has_sudo);

    Some(RewriteInfo {
        original: command.to_string(),
        rewritten,
        paths: paths.to_vec(),
        trash_binary: trash_binary.clone(),
    })
}

/// Check if an rm command can be safely rewritten to trash.
///
/// Commands that cannot be safely rewritten:
/// - xargs rm
/// - find -exec rm
/// - Commands with shell expansion that can't be traced
#[must_use]
pub fn can_safely_rewrite(command: &str) -> bool {
    let lower = command.to_lowercase();

    // xargs patterns - paths come from stdin, can't safely rewrite
    if lower.contains("xargs") && lower.contains("rm") {
        return false;
    }

    // find -exec patterns - paths are dynamically determined
    if lower.contains("find") && lower.contains("-exec") && lower.contains("rm") {
        return false;
    }

    // Subshell expansion with rm
    if (lower.contains("$(") || lower.contains("`")) && lower.contains("rm") {
        return false;
    }

    // Glob in variable that might expand unexpectedly
    // This is conservative - we allow simple variable expansion like $TMPDIR
    // but reject patterns that might expand to multiple items in unsafe ways
    if lower.contains("${") && lower.contains("*") {
        return false;
    }

    true
}

/// Check if command has sudo prefix.
#[must_use]
pub fn has_sudo_prefix(command: &str) -> bool {
    let trimmed = command.trim_start();
    trimmed.starts_with("sudo ") || trimmed.starts_with("sudo\t")
}

/// Extract the command part after common prefixes (sudo, env vars, etc.).
#[must_use]
pub fn strip_command_prefix(command: &str) -> &str {
    let mut rest = command.trim_start();

    // Strip sudo
    if let Some(after_sudo) = rest.strip_prefix("sudo") {
        rest = after_sudo.trim_start();
    }

    // Strip env var assignments (VAR=value command)
    while let Some(eq_pos) = rest.find('=') {
        // Check if there's whitespace before the = (not an env assignment)
        let before_eq = &rest[..eq_pos];
        if before_eq.contains(char::is_whitespace) {
            break;
        }
        // Skip past the value
        let after_eq = &rest[eq_pos + 1..];
        if let Some(space_pos) = after_eq.find(char::is_whitespace) {
            rest = after_eq[space_pos..].trim_start();
        } else {
            break;
        }
    }

    rest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_safely_rewrite() {
        // Safe patterns
        assert!(can_safely_rewrite("rm -rf /path/to/dir"));
        assert!(can_safely_rewrite("sudo rm -rf /path/to/dir"));
        assert!(can_safely_rewrite("rm -rf $TMPDIR/foo"));
        assert!(can_safely_rewrite("rm -rf dir1 dir2 dir3"));

        // Unsafe patterns
        assert!(!can_safely_rewrite("find . -name '*.tmp' -exec rm {} \\;"));
        assert!(!can_safely_rewrite("xargs rm -rf"));
        assert!(!can_safely_rewrite("ls | xargs rm"));
        assert!(!can_safely_rewrite("rm -rf $(find . -name '*.tmp')"));
        assert!(!can_safely_rewrite("rm -rf `find . -name '*.tmp'`"));
    }

    #[test]
    fn test_has_sudo_prefix() {
        assert!(has_sudo_prefix("sudo rm -rf /"));
        assert!(has_sudo_prefix("  sudo rm -rf /"));
        assert!(!has_sudo_prefix("rm -rf /"));
        assert!(!has_sudo_prefix("sudorm -rf /"));
    }

    #[test]
    fn test_trash_binary_format() {
        let bin = TrashBinary {
            command: "trash".to_string(),
            args: vec![],
            description: "test",
            source: TrashSource::PlatformDetection,
        };
        assert_eq!(bin.format_command(&["/path/a", "/path/b"]), "trash /path/a /path/b");
        assert_eq!(
            bin.format_command_with_sudo(&["/path/a"], true),
            "sudo trash /path/a"
        );

        let gio = TrashBinary {
            command: "gio".to_string(),
            args: vec!["trash".to_string()],
            description: "test",
            source: TrashSource::PlatformDetection,
        };
        assert_eq!(gio.format_command(&["/path/a"]), "gio trash /path/a");
    }

    #[test]
    fn test_strip_command_prefix() {
        assert_eq!(strip_command_prefix("rm -rf /"), "rm -rf /");
        assert_eq!(strip_command_prefix("sudo rm -rf /"), "rm -rf /");
        assert_eq!(strip_command_prefix("  sudo rm -rf /"), "rm -rf /");
        assert_eq!(strip_command_prefix("VAR=val rm -rf /"), "rm -rf /");
        assert_eq!(strip_command_prefix("sudo VAR=val rm -rf /"), "rm -rf /");
    }

    #[test]
    fn test_rewrite_rm_to_trash() {
        let bin = TrashBinary {
            command: "trash".to_string(),
            args: vec![],
            description: "test",
            source: TrashSource::PlatformDetection,
        };

        // Basic rewrite
        let info = rewrite_rm_to_trash(
            "rm -rf /path/to/dir",
            &["/path/to/dir".to_string()],
            &bin,
            false,
        )
        .unwrap();
        assert_eq!(info.rewritten, "trash /path/to/dir");

        // With sudo
        let info = rewrite_rm_to_trash(
            "sudo rm -rf /path/to/dir",
            &["/path/to/dir".to_string()],
            &bin,
            true,
        )
        .unwrap();
        assert_eq!(info.rewritten, "sudo trash /path/to/dir");

        // Multiple paths
        let info = rewrite_rm_to_trash(
            "rm -rf a b c",
            &["a".to_string(), "b".to_string(), "c".to_string()],
            &bin,
            false,
        )
        .unwrap();
        assert_eq!(info.rewritten, "trash a b c");

        // Unsafe pattern - should return None
        let info = rewrite_rm_to_trash(
            "find . -exec rm {} \\;",
            &["{}".to_string()],
            &bin,
            false,
        );
        assert!(info.is_none());
    }
}
