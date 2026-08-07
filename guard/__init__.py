"""A pre-execution guard for coding agents.

The guard answers one question before a tool call runs: *has this kind of action
hurt us before?* It answers it from a corpus of recorded incidents, not from a
static blocklist, and it writes a receipt for every decision it makes.
"""

__version__ = "0.1.0"
