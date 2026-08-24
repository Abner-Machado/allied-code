use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Shell {
    Posix,
    Powershell,
}

impl fmt::Display for Shell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Shell::Posix => write!(f, "posix"),
            Shell::Powershell => write!(f, "powershell"),
        }
    }
}

impl Shell {
    /// Read a shell name. Anything unrecognised is POSIX, which splits more
    /// eagerly — the safe direction to be wrong in.
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "powershell" | "ps" | "pwsh" => Shell::Powershell,
            _ => Shell::Posix,
        }
    }

    pub fn auto_detect(input: &str) -> Self {
        if input.contains("iex ")
            || input.contains("Invoke-Expression")
            || input.contains("$env:")
            || input.contains("Get-ChildItem")
            || input.contains("Remove-Item")
            || input.contains("Stop-Process")
            || input.contains("Set-ExecutionPolicy")
        {
            Shell::Powershell
        } else {
            Shell::Posix
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SegmentKind {
    Exec,
    Quoted,
    Substitution,
}

impl fmt::Display for SegmentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SegmentKind::Exec => write!(f, "Exec"),
            SegmentKind::Quoted => write!(f, "Quoted"),
            SegmentKind::Substitution => write!(f, "Substitution"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    pub kind: SegmentKind,
    pub text: String,
    pub byte_range: (usize, usize),
    pub shell: Shell,
}

impl Segment {
    pub fn new(kind: SegmentKind, text: String, byte_range: (usize, usize), shell: Shell) -> Self {
        Self {
            kind,
            text,
            byte_range,
            shell,
        }
    }
}

/// Characters that end one command and begin another.
///
/// `&&` and `||` need no special case: the first character already ends the
/// segment and the second is swallowed with the rest of the separator run.
fn is_separator(c: char) -> bool {
    matches!(c, ';' | '|' | '&' | '\n' | '\r')
}

/// Push `input[start..end]`, trimmed, as a segment — dropping it if there is
/// nothing left after trimming.
///
/// The byte range reported is the range of the *trimmed* text in the original
/// input, so a caller highlighting the evidence underlines the command and not
/// the whitespace around it.
fn push_trimmed(
    out: &mut Vec<Segment>,
    input: &str,
    start: usize,
    end: usize,
    kind: SegmentKind,
    shell: Shell,
) {
    if start >= end || end > input.len() {
        return;
    }
    let slice = &input[start..end];
    let trimmed = slice.trim();
    if trimmed.is_empty() {
        return;
    }
    let offset = slice.find(trimmed).unwrap_or(0);
    let s = start + offset;
    let e = s + trimmed.len();
    out.push(Segment::new(kind, trimmed.to_string(), (s, e), shell));
}

/// Split a command line into the pieces that actually run, and the pieces that
/// only look like they do.
///
/// This is the reason the crate exists. A guard that searches the whole line for
/// `rm -rf` cannot tell `rm -rf /tmp/x` from `echo "rm -rf /tmp/x"`, and a guard
/// that cries wolf on the second one gets switched off — which is a worse
/// outcome than not having it. So the line is split first, and only `Exec`
/// segments are ever matched against a hazard pattern.
///
/// Three kinds come out:
///
/// - `Exec` — text that the shell will run.
/// - `Quoted` — a quoted run or a here-string. Literal text; never classified.
/// - `Substitution` — `$(…)`, a backtick run, `@(…)`, or a PowerShell variable
///   reference. It *does* run, or feeds something that runs, but its content is
///   not knowable here — which is itself a signal, and `shell.indirect-construction`
///   is the class that carries it.
pub fn segments(input: &str, shell: Shell) -> Vec<Segment> {
    let chars: Vec<(usize, char)> = input.char_indices().collect();
    let n = chars.len();
    let end_byte = |k: usize| -> usize {
        if k < n {
            chars[k].0
        } else {
            input.len()
        }
    };

    let mut out: Vec<Segment> = Vec::new();
    let mut exec_start = 0usize;
    let mut i = 0usize;

    while i < n {
        let (pos, c) = chars[i];
        let next = chars.get(i + 1).map(|(_, ch)| *ch);

        // --- PowerShell here-string: @'…'@ or @"…"@ -------------------------
        // Checked before anything else: a here-string can contain quotes,
        // separators and newlines, and none of them mean what they usually mean.
        if shell == Shell::Powershell && c == '@' && matches!(next, Some('\'') | Some('"')) {
            let quote = next.unwrap();
            push_trimmed(&mut out, input, exec_start, pos, SegmentKind::Exec, shell);
            let mut j = i + 2;
            let mut stop = input.len();
            while j < n {
                if chars[j].1 == quote && chars.get(j + 1).map(|(_, ch)| *ch) == Some('@') {
                    stop = end_byte(j + 2);
                    j += 2;
                    break;
                }
                j += 1;
            }
            push_trimmed(&mut out, input, pos, stop, SegmentKind::Quoted, shell);
            i = j;
            exec_start = stop;
            continue;
        }

        // --- Substitution with balanced parentheses: $( … ) and @( … ) ------
        if (c == '$' || (shell == Shell::Powershell && c == '@')) && next == Some('(') {
            push_trimmed(&mut out, input, exec_start, pos, SegmentKind::Exec, shell);
            let mut depth = 0usize;
            let mut j = i + 1;
            let mut stop = input.len();
            while j < n {
                match chars[j].1 {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            stop = end_byte(j + 1);
                            j += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            push_trimmed(&mut out, input, pos, stop, SegmentKind::Substitution, shell);
            i = j;
            exec_start = stop;
            continue;
        }

        // --- PowerShell variable reference: $name, $env:name ----------------
        // Its value is decided at run time, so the guard cannot read it. Marking
        // it as its own segment is what lets `iex $env:payload` be seen for what
        // it is: a call whose argument the guard is blind to.
        if shell == Shell::Powershell && c == '$' {
            let mut j = i + 1;
            while j < n {
                let ch = chars[j].1;
                if ch.is_alphanumeric() || ch == '_' || ch == ':' {
                    j += 1;
                } else {
                    break;
                }
            }
            if j > i + 1 {
                push_trimmed(&mut out, input, exec_start, pos, SegmentKind::Exec, shell);
                let stop = end_byte(j);
                push_trimmed(&mut out, input, pos, stop, SegmentKind::Substitution, shell);
                i = j;
                exec_start = stop;
                continue;
            }
        }

        // --- POSIX backtick substitution ------------------------------------
        // Only POSIX: in PowerShell the backtick is the escape character.
        if shell == Shell::Posix && c == '`' {
            push_trimmed(&mut out, input, exec_start, pos, SegmentKind::Exec, shell);
            let mut j = i + 1;
            let mut stop = input.len();
            while j < n {
                if chars[j].1 == '\\' {
                    j += 2;
                    continue;
                }
                if chars[j].1 == '`' {
                    stop = end_byte(j + 1);
                    j += 1;
                    break;
                }
                j += 1;
            }
            push_trimmed(&mut out, input, pos, stop, SegmentKind::Substitution, shell);
            i = j;
            exec_start = stop;
            continue;
        }

        // --- Quoted runs -----------------------------------------------------
        if c == '\'' || c == '"' {
            push_trimmed(&mut out, input, exec_start, pos, SegmentKind::Exec, shell);
            let escape = if shell == Shell::Posix { '\\' } else { '`' };
            let mut j = i + 1;
            let mut stop = input.len();
            while j < n {
                let ch = chars[j].1;
                // A single-quoted run takes no escapes in either shell.
                if c == '"' && ch == escape {
                    j += 2;
                    continue;
                }
                if ch == c {
                    stop = end_byte(j + 1);
                    j += 1;
                    break;
                }
                j += 1;
            }
            push_trimmed(&mut out, input, pos, stop, SegmentKind::Quoted, shell);
            i = j;
            exec_start = stop;
            continue;
        }

        // --- Escape outside quotes -------------------------------------------
        if (shell == Shell::Posix && c == '\\') || (shell == Shell::Powershell && c == '`') {
            i += 2;
            continue;
        }

        // --- Separators -------------------------------------------------------
        if is_separator(c) {
            push_trimmed(&mut out, input, exec_start, pos, SegmentKind::Exec, shell);
            let mut j = i;
            while j < n && (is_separator(chars[j].1) || chars[j].1.is_whitespace()) {
                j += 1;
            }
            exec_start = end_byte(j);
            i = j;
            continue;
        }

        i += 1;
    }

    push_trimmed(
        &mut out,
        input,
        exec_start,
        input.len(),
        SegmentKind::Exec,
        shell,
    );
    out
}

/// The command line with every literal run blanked out, rebuilt from segments.
///
/// Some hazards are properties of the *pipeline*, not of any single command:
/// `curl … | sh` is dangerous precisely because of the pipe. Those patterns are
/// matched against this reconstruction, which keeps the flow between commands
/// while still leaving quoted text out — so a pipeline is still readable, and
/// `echo "curl x | sh"` still is not a pipeline.
pub fn executable_flow(segments: &[Segment]) -> String {
    segments
        .iter()
        .filter(|s| s.kind != SegmentKind::Quoted)
        .map(|s| s.text.as_str())
        .collect::<Vec<_>>()
        .join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_posix_simple() {
        let segs = segments("echo hello; ls -la", Shell::Posix);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].kind, SegmentKind::Exec);
        assert_eq!(segs[0].text, "echo hello");
        assert_eq!(segs[1].text, "ls -la");
    }

    #[test]
    fn test_posix_pipeline() {
        let segs = segments("cmd1 && cmd2 | cmd3", Shell::Posix);
        assert_eq!(segs.len(), 3);
        assert_eq!(segs[0].text, "cmd1");
        assert_eq!(segs[1].text, "cmd2");
        assert_eq!(segs[2].text, "cmd3");
    }

    #[test]
    fn test_posix_quoted_single() {
        let segs = segments("echo 'rm -rf /'", Shell::Posix);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].kind, SegmentKind::Exec);
        assert_eq!(segs[0].text, "echo");
        assert_eq!(segs[1].kind, SegmentKind::Quoted);
        assert_eq!(segs[1].text, "'rm -rf /'");
    }

    #[test]
    fn test_posix_quoted_double() {
        let segs = segments("echo \"rm -rf /\"", Shell::Posix);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[1].kind, SegmentKind::Quoted);
        assert_eq!(segs[1].text, "\"rm -rf /\"");
    }

    #[test]
    fn test_posix_substitution() {
        let segs = segments("echo $(ls -la)", Shell::Posix);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].text, "echo");
        assert_eq!(segs[1].kind, SegmentKind::Substitution);
        assert_eq!(segs[1].text, "$(ls -la)");
    }

    #[test]
    fn test_posix_backtick_substitution() {
        let segs = segments("echo `ls -la`", Shell::Posix);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[1].kind, SegmentKind::Substitution);
        assert_eq!(segs[1].text, "`ls -la`");
    }

    #[test]
    fn test_posix_escaped_quote() {
        let segs = segments("echo \"it\\'s done\"", Shell::Posix);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[1].kind, SegmentKind::Quoted);
    }

    #[test]
    fn test_powershell_simple() {
        let segs = segments("echo hello; ls", Shell::Powershell);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].kind, SegmentKind::Exec);
        assert_eq!(segs[1].text, "ls");
    }

    #[test]
    fn test_powershell_quoted_single() {
        let segs = segments("echo 'rm -rf /'", Shell::Powershell);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[1].kind, SegmentKind::Quoted);
        assert_eq!(segs[1].text, "'rm -rf /'");
    }

    #[test]
    fn test_powershell_quoted_double() {
        let segs = segments("echo \"rm -rf /\"", Shell::Powershell);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[1].kind, SegmentKind::Quoted);
    }

    #[test]
    fn test_powershell_here_string_single() {
        let segs = segments("@'\nhello\nworld\n'@", Shell::Powershell);
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].kind, SegmentKind::Quoted);
    }

    #[test]
    fn test_powershell_here_string_double() {
        let segs = segments("@\"\nhello\nworld\n\"@", Shell::Powershell);
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].kind, SegmentKind::Quoted);
    }

    #[test]
    fn test_powershell_substitution() {
        let segs = segments("echo $(Get-ChildItem)", Shell::Powershell);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[1].kind, SegmentKind::Substitution);
        assert_eq!(segs[1].text, "$(Get-ChildItem)");
    }

    #[test]
    fn test_powershell_array_substitution() {
        let segs = segments("echo @(1,2,3)", Shell::Powershell);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[1].kind, SegmentKind::Substitution);
    }

    #[test]
    fn test_powershell_iex() {
        let segs = segments("iex $env:payload", Shell::Powershell);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].text, "iex");
        assert_eq!(segs[1].text, "$env:payload");
    }

    #[test]
    fn test_powershell_variable() {
        let segs = segments("$env:X='rm'; & $env:X -rf .", Shell::Powershell);
        assert!(segs.len() >= 2);
    }

    #[test]
    fn test_auto_detect_posix() {
        assert_eq!(Shell::auto_detect("ls -la"), Shell::Posix);
        assert_eq!(Shell::auto_detect("echo hello"), Shell::Posix);
    }

    #[test]
    fn test_auto_detect_powershell() {
        assert_eq!(Shell::auto_detect("iex $env:payload"), Shell::Powershell);
        assert_eq!(Shell::auto_detect("$env:X='rm'"), Shell::Powershell);
        assert_eq!(Shell::auto_detect("Invoke-Expression"), Shell::Powershell);
    }

    #[test]
    fn test_byte_ranges() {
        // The range is the half-open span of the trimmed text in the original
        // input, so `&input[start..end]` gives back exactly `segment.text`.
        let input = "echo hello; ls";
        let segs = segments(input, Shell::Posix);
        assert_eq!(segs[0].byte_range, (0, 10));
        assert_eq!(
            &input[segs[0].byte_range.0..segs[0].byte_range.1],
            "echo hello"
        );
        assert_eq!(segs[1].byte_range, (12, 14));
        assert_eq!(&input[segs[1].byte_range.0..segs[1].byte_range.1], "ls");
    }

    #[test]
    fn test_empty_segments_filtered() {
        let segs = segments(";;echo hello;;", Shell::Posix);
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].text, "echo hello");
    }
}
