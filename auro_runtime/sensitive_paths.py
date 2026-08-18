r"""
Sensitive-resource classification: one inventory, one canonicaliser, two subjects.

Until 2026-08-18 the knowledge of "which paths name a credential" lived in three
places -- `guards._SENSITIVE_PATH_PATTERNS` (11 regexes), the tool read path's
`_READ_BLOCKLIST_FILES` (3 literals), and the staged-file check's
`_SENSITIVE_FILES` (the identical 3) -- and nothing kept them in agreement. A
family added to one was missed by the other two, and each copy reported
agreement with itself. This module is the single definition all three consume.

Categories, not just patterns
-----------------------------
Every entry carries a category because "which class of secret was this" is what
an operator needs from an audit record. "Which regex matched" is an
implementation detail that changes when the inventory is restructured.

Two subjects, deliberately
--------------------------
There are two ways to ask this module a question, and the difference is the
whole point of the control:

    classify_text(s)                 -- judges a caller-supplied string
    classify_resolved(resolved, base) -- judges the path the filesystem will use

The policy guard runs before the tool and can only see the string the model
sent. The tool runs after resolution and sees the real target. Those disagree
whenever resolution does any work: `read_file("directives/x.md")` is the string
`directives/x.md` but the file `auro_runtime/resources/directives/x.md`, and
`restore_file`'s destination can come from the archive manifest with no caller
argument contributing to it at all.

What the two layers share is this inventory and `canonicalize_path`. What they
must NOT share is how they obtain their subject. That is not an oversight to be
tidied away later -- it is the reason the pair composes. 2026-08-16 established
the rule the hard way: both enforcement layers compared a raw model-supplied
string against a name list, so one trailing space opened both simultaneously.
Two checks sharing a root cause are one check with a redundant implementation,
and the redundancy is worse than nothing because it reads as depth on review.
Layers compose only when they fail independently, which here means: same
inventory, same normalisation, different subject.

Scope
-----
Confidentiality only. This module answers "does this path name a secret". The
hygiene filters (`__pycache__`, `.pyc`) and the integrity protections
(`_PROTECTED_PATTERNS`, guarding the runtime's own source from writes) are
different control families answering different questions, and they stay where
they are rather than being folded in here. Merging them would produce one list
nobody can reason about and would mislabel a noise filter as a security control.
"""

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

# Categories. Strings rather than an enum so they cross the audit boundary
# unchanged -- an audit record is read by operators and by jq, not by Python.
ENV_FILE = "env_file"
SSH_KEY = "ssh_key"
CLOUD_CREDENTIAL = "cloud_credential"
GPG_KEYRING = "gpg_keyring"
AURO_SECRET = "auro_secret"
WEB_AUTH = "web_auth"
GENERIC_CREDENTIAL = "generic_credential"

# Assigned when a caller hands this module a path that is not under the base it
# claimed. Not a secret category -- a caller-contract violation. See
# classify_resolved for why that answers "refuse" rather than "approve".
UNCONTAINED = "uncontained"


@dataclass(frozen=True)
class SensitiveMatch:
    """Why a path was classified sensitive. Carried into the audit record."""

    category: str
    pattern: str
    subject: str


# Directory patterns end with ([\\/]|$), not [\\/].
#
# Requiring a trailing separator meant these matched a file *inside* the
# directory but not the directory itself, and `canonicalize_path` normalises
# through PurePosixPath, which strips a trailing separator the caller did
# supply. So `.ssh/id_rsa` was blocked while `.ssh/`, `.ssh` and `.aws/` were
# all allowed, and `list_dir` would happily enumerate them. Alternating with
# `$` covers the bare form without loosening anything else: `.sshrc` still has
# to fail, because a name merely starting with `.ssh` is not the directory.
#
# IGNORECASE is retained even though canonicalize_path already lowercases. The
# two mechanisms are independent on purpose: a caller reaching for a pattern
# without going through the canonicaliser still gets case-insensitive matching
# rather than a silent miss.
_SENSITIVE_RESOURCES: tuple[tuple[str, re.Pattern], ...] = (
    (ENV_FILE, re.compile(r"(^|[\\/])\.env(\..*)?$", re.IGNORECASE)),
    (SSH_KEY, re.compile(r"(^|[\\/])\.ssh([\\/]|$)", re.IGNORECASE)),
    (SSH_KEY, re.compile(r"(^|[\\/])id_rsa", re.IGNORECASE)),
    (SSH_KEY, re.compile(r"(^|[\\/])id_ed25519", re.IGNORECASE)),
    (GENERIC_CREDENTIAL, re.compile(r"(^|[\\/])\.credentials", re.IGNORECASE)),
    (AURO_SECRET, re.compile(r"(^|[\\/])auro_secrets\.yaml$", re.IGNORECASE)),
    (AURO_SECRET, re.compile(r"(^|[\\/])\.auro_secrets\.yaml$", re.IGNORECASE)),
    (GPG_KEYRING, re.compile(r"(^|[\\/])\.gnupg([\\/]|$)", re.IGNORECASE)),
    (CLOUD_CREDENTIAL, re.compile(r"(^|[\\/])\.aws([\\/]|$)", re.IGNORECASE)),
    (GENERIC_CREDENTIAL, re.compile(r"(^|[\\/])credentials\.json$", re.IGNORECASE)),
    (WEB_AUTH, re.compile(r"(^|[\\/])\.htpasswd$", re.IGNORECASE)),
)


def canonicalize_path(p: str) -> str:
    r"""
    Normalize a path string for security comparison.

    Trailing dots and spaces are stripped from every component, because Windows
    strips them when it opens the file and this guard compares strings. Without
    it, `output/.env ` did not match the `\.env(\..*)?$` pattern -- `$` cannot
    follow a trailing space -- so the guard allowed the call and the filesystem
    then opened the real `output/.env`. Confirmed live 2026-08-16: the read
    returned the file's contents through this guard AND the tool's own
    blocklist, which shared the same root cause. `.env.` behaved identically.

    Applied on every platform, not only Windows. On Linux `.env ` and `.env` are
    genuinely different files, so this over-classifies there by a hair: a file
    deliberately named with a trailing space is refused as if it were the real
    one. That is the fail-closed direction (D-038), it costs nothing real, and
    the alternative is a classifier whose answer depends on the host OS -- the
    same mistake as letting a resolver decide whether an SSRF destination is
    refused.

    Lowercasing is unconditional as of 2026-08-18. It was previously applied
    only under `os.name == "nt"`, which is the very host-dependence the
    paragraph above rejects, while the tool-layer copy of this normalisation
    lowercased always -- so the two layers disagreed about case semantics on
    Linux. Unifying on the tool layer's behaviour is the fail-closed direction
    and makes this function's output a property of the input alone.
    """
    p = p.replace("\\", "/")
    p = re.sub(r"%2[eE]", ".", p)
    try:
        p = str(PurePosixPath(p))
    except Exception:
        pass
    p = "/".join(part.rstrip(" .") or part for part in p.split("/"))
    return p.lower()


def _match(p: str) -> SensitiveMatch | None:
    """Run the inventory over one path string. Not public: callers pick an
    entry point below, and the entry point they pick records what they are
    judging. That record is the control's whole value."""
    if not p:
        return None
    canonical = canonicalize_path(p)
    for category, pattern in _SENSITIVE_RESOURCES:
        if pattern.search(canonical):
            return SensitiveMatch(category=category, pattern=pattern.pattern, subject=canonical)
    return None


def classify_text(p: str) -> SensitiveMatch | None:
    """
    Classify a caller-supplied path string. Used by the pre-execution guard.

    The weaker entry point by construction: it judges what the model asked for,
    which is not necessarily what the filesystem will open. Worth running
    anyway because it refuses before any resolution work happens, and because a
    refusal here can name the offending argument, which a resolved-path refusal
    cannot.
    """
    return _match(p)


def classify_workspace_relative(rel: Path | str) -> SensitiveMatch | None:
    """
    Classify a path already resolved and relativised against its base.

    For callers that resolved and contained the target themselves and hold the
    relative remainder -- `_is_read_blocked` is the pattern. Takes the relative
    form rather than re-deriving it so a hot path such as recursive `list_dir`
    does not pay a second `resolve()` syscall per entry.
    """
    return _match(rel.as_posix() if isinstance(rel, Path) else rel)


def classify_resolved(resolved: Path, base: Path) -> SensitiveMatch | None:
    """
    Classify the resource the filesystem will actually act on.

    `resolved` is judged relative to `base`, and that is load-bearing rather
    than cosmetic: the absolute form runs through the operator's own home
    directory, so a workspace nested under a `.ssh-backup` folder would match
    the ssh pattern on its ancestry and refuse every file underneath it. Only
    the portion inside the workspace is the tool's subject.

    A path that does not sit under `base` is a caller-contract violation --
    every caller here contains before classifying -- and the fail-closed answer
    to a caller bug in a security control is to refuse, not to approve. It
    returns a match with the UNCONTAINED category rather than None so the
    refusal carries a reason an operator can read.
    """
    try:
        rel = resolved.resolve().relative_to(base)
    except ValueError:
        return SensitiveMatch(
            category=UNCONTAINED,
            pattern="<not under base>",
            subject=str(resolved),
        )
    return classify_workspace_relative(rel)
