//! Hot-path classification core for the allied-code guard.
//!
//! This crate answers one question — "what kind of action is this?" — and never
//! "should it run?". The decision stays in Python, where it is weighed against
//! the incidents recorded in the corpus. Keeping the two apart is what makes the
//! guard auditable: a class can be wrong without a rule being wrong.
//!
//! The Rust side exists for two reasons, in this order:
//!
//! 1. **Correctness.** A command line is not a string to be searched; it is a
//!    sequence of segments, some of which never execute. `lexer` splits it, and
//!    only `Exec` segments are classified. That is what stops `echo "rm -rf /"`
//!    from being read as a deletion.
//! 2. **Cost.** Classification runs on every single tool call, so it is the one
//!    place where microseconds are worth buying.

pub mod lexer;
pub mod rules;

pub use lexer::{segments, Segment, SegmentKind, Shell};
pub use rules::{classify_mcp, classify_write, escalate, worst, Hazard};

/// Classify a raw command line.
///
/// `shell_hint` accepts `"posix"`, `"powershell"` (also `"ps"`/`"pwsh"`), or
/// `"auto"` to guess from the text. Guessing is deliberately biased towards
/// PowerShell only on unambiguous markers — a wrong guess changes which
/// separators and quoting rules apply, and the safe direction is to fall back
/// to POSIX, which splits more eagerly.
pub fn classify_command_line(command: &str, shell_hint: &str) -> Vec<Hazard> {
    let shell = if shell_hint.eq_ignore_ascii_case("auto") {
        Shell::auto_detect(command)
    } else {
        Shell::parse(shell_hint)
    };
    let segs = lexer::segments(command, shell);
    rules::classify_command(&segs)
}

/// Split a command line into segments without classifying anything.
///
/// Exposed on its own because "why did the guard not see this?" is answered by
/// looking at the segmentation, not at the patterns.
pub fn segment_command_line(command: &str, shell_hint: &str) -> Vec<Segment> {
    let shell = if shell_hint.eq_ignore_ascii_case("auto") {
        Shell::auto_detect(command)
    } else {
        Shell::parse(shell_hint)
    };
    lexer::segments(command, shell)
}

#[cfg(feature = "python")]
mod python_bindings {
    use super::*;
    use pyo3::prelude::*;
    use pyo3::types::{PyDict, PyList};

    /// A hazard crosses into Python as a plain dict with exactly the keys the
    /// Python `Hazard` dataclass takes, so the caller can rebuild it with
    /// `Hazard(**d)` and nothing else has to know a backend changed.
    fn hazard_to_dict<'py>(py: Python<'py>, h: &Hazard) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new_bound(py);
        d.set_item("id", &h.id)?;
        d.set_item("severity", &h.severity)?;
        d.set_item("summary", &h.summary)?;
        d.set_item("tags", PyList::new_bound(py, &h.tags))?;
        d.set_item("evidence", &h.evidence)?;
        Ok(d)
    }

    fn hazards_to_list<'py>(py: Python<'py>, hs: &[Hazard]) -> PyResult<Bound<'py, PyList>> {
        let items: PyResult<Vec<_>> = hs.iter().map(|h| hazard_to_dict(py, h)).collect();
        Ok(PyList::new_bound(py, items?))
    }

    #[pyfunction]
    #[pyo3(signature = (command, shell = "auto"))]
    fn classify_command<'py>(
        py: Python<'py>,
        command: &str,
        shell: &str,
    ) -> PyResult<Bound<'py, PyList>> {
        let hazards = classify_command_line(command, shell);
        hazards_to_list(py, &hazards)
    }

    #[pyfunction]
    #[pyo3(name = "classify_mcp", signature = (tool_name, tool_input))]
    fn classify_mcp_py<'py>(
        py: Python<'py>,
        tool_name: &str,
        tool_input: &Bound<'py, PyDict>,
    ) -> PyResult<Bound<'py, PyList>> {
        // Convert the dict to JSON via its repr-free path: only string keys and
        // scalar-ish values matter for classification, and anything exotic is
        // stringified rather than rejected — a classifier that throws on an odd
        // argument would fail open on exactly the calls worth inspecting.
        let mut map = serde_json::Map::new();
        for (k, v) in tool_input.iter() {
            let key = k.str()?.to_string_lossy().into_owned();
            let val = if let Ok(s) = v.extract::<String>() {
                serde_json::Value::String(s)
            } else if let Ok(b) = v.extract::<bool>() {
                serde_json::Value::Bool(b)
            } else if let Ok(i) = v.extract::<i64>() {
                serde_json::Value::Number(i.into())
            } else {
                serde_json::Value::String(v.str()?.to_string_lossy().into_owned())
            };
            map.insert(key, val);
        }
        let value = serde_json::Value::Object(map);
        let hazards = rules::classify_mcp(tool_name, &value);
        hazards_to_list(py, &hazards)
    }

    #[pyfunction]
    #[pyo3(name = "classify_write", signature = (path, protected))]
    fn classify_write_py<'py>(
        py: Python<'py>,
        path: &str,
        protected: Vec<String>,
    ) -> PyResult<Bound<'py, PyList>> {
        let hazards = rules::classify_write(path, &protected);
        hazards_to_list(py, &hazards)
    }

    #[pyfunction]
    #[pyo3(name = "segments", signature = (command, shell = "auto"))]
    fn segments_py<'py>(
        py: Python<'py>,
        command: &str,
        shell: &str,
    ) -> PyResult<Bound<'py, PyList>> {
        let segs = segment_command_line(command, shell);
        let items: PyResult<Vec<_>> = segs
            .iter()
            .map(|s| {
                let d = PyDict::new_bound(py);
                d.set_item("kind", s.kind.to_string())?;
                d.set_item("text", &s.text)?;
                d.set_item("start", s.byte_range.0)?;
                d.set_item("end", s.byte_range.1)?;
                d.set_item("shell", s.shell.to_string())?;
                Ok(d)
            })
            .collect();
        Ok(PyList::new_bound(py, items?))
    }

    #[pymodule]
    fn alliedcore(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add("__version__", env!("CARGO_PKG_VERSION"))?;
        m.add_function(wrap_pyfunction!(classify_command, m)?)?;
        m.add_function(wrap_pyfunction!(classify_mcp_py, m)?)?;
        m.add_function(wrap_pyfunction!(classify_write_py, m)?)?;
        m.add_function(wrap_pyfunction!(segments_py, m)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defect this whole crate exists to fix: a dangerous command inside
    /// quotes is text, not an action.
    #[test]
    fn quoted_command_is_not_classified() {
        let hazards = classify_command_line("echo \"rm -rf /\"", "posix");
        assert!(
            hazards.is_empty(),
            "echo of a quoted string must not classify as a deletion, got {hazards:?}"
        );
    }

    #[test]
    fn unquoted_recursive_delete_is_classified() {
        let hazards = classify_command_line("rm -rf /tmp/build", "posix");
        assert!(
            hazards.iter().any(|h| h.id == "fs.recursive-delete"),
            "expected fs.recursive-delete, got {hazards:?}"
        );
    }

    #[test]
    fn a_pipeline_classifies_each_stage_on_its_own() {
        let hazards = classify_command_line("ls -la | grep foo && rm -rf build", "posix");
        assert!(hazards.iter().any(|h| h.id == "fs.recursive-delete"));
    }

    #[test]
    fn force_with_lease_is_not_a_history_rewrite() {
        let hazards = classify_command_line("git push --force-with-lease origin main", "posix");
        assert!(
            !hazards.iter().any(|h| h.id == "git.history-rewrite"),
            "--force-with-lease is the safe form, got {hazards:?}"
        );
    }
}
