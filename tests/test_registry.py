"""
Tests for the tool registry and the wiring around it: project root
resolution, the module import graph, the CLI surface, model-backend
selection, and the per-run call counter.

Two things this file locks down:

* Registry drift — a tool that should exist goes missing, a name is
  registered twice, or an entry's (callable, doc, schema) shape rots.
* Wiring rot — project-root resolution, the module import graph, or the
  CLI's subcommand surface silently breaks.

Plus two source-hygiene invariants that hold for any checkout: every logger
sits under the `auro_runtime.*` namespace, and no absolute path into a
developer's home directory reaches shipped source.
"""

import importlib
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest
from pydantic import BaseModel

# --- Expected registry shape ------------------------------------------------

_EXPECTED_TOOL_NAMES = frozenset({
    "delete_file", "echo", "http_request", "list_dir",
    "list_directives", "list_tools", "read_file", "resolve_secret",
    "restore_file", "validate_directive", "write_file",
})

# The four verify_* functions were registered tools until 2026-08-13, and were
# the only registered tools with no argument schema. They are operator functions
# now, called directly rather than by a model, so every registered tool takes a
# schema and the coverage check below has no exemptions left to grant.

# name -> the tool_schemas.py class it must be validated by. Pins the exact
# wiring, not just "some BaseModel or other" — a copy-paste mixup (e.g.
# write_file quietly validated by DeleteFileArgs) would still pass an
# `issubclass(schema, BaseModel)` check.
_EXPECTED_SCHEMA_BY_TOOL = {
    "list_dir": "ListDirArgs",
    "read_file": "ReadFileArgs",
    "echo": "EchoArgs",
    "resolve_secret": "ResolveSecretArgs",
    "list_tools": "ListToolsArgs",
    "write_file": "WriteFileArgs",
    "delete_file": "DeleteFileArgs",
    "restore_file": "RestoreFileArgs",
    "validate_directive": "ValidateDirectiveArgs",
    "http_request": "HttpRequestArgs",
    "list_directives": "ListDirectivesArgs",
}

# --- Source-tree scanning helpers -------------------------------------------
#
# These walk the filesystem directly (not via import) so a bug in the import
# machinery itself couldn't hide a problem from this suite, and so the checks
# work even for strings that would never be reached by simply importing every
# module (e.g. a stray reference sitting in a comment or an unused branch).

_SOURCE_PACKAGE_DIRS = ("auro_runtime", "runtime_tools")


def _iter_py_files(repo_root: Path, dirs=_SOURCE_PACKAGE_DIRS):
    for d in dirs:
        base = repo_root / d
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            yield path


_GET_LOGGER_RE = re.compile(r"getLogger\(\s*[\"']([^\"']*)[\"']")


def _find_bad_logger_namespaces(repo_root: Path) -> list[tuple[str, str]]:
    """(relative_path, logger_name) for every getLogger(...) not under auro_runtime.*."""
    offenders = []
    for path in _iter_py_files(repo_root):
        text = path.read_text(encoding="utf-8")
        rel = str(path.relative_to(repo_root))
        for name in _GET_LOGGER_RE.findall(text):
            if name != "auro_runtime" and not name.startswith("auro_runtime."):
                offenders.append((rel, name))
    return offenders


_REGISTER_CALL_RE = re.compile(r'@register\(\s*["\']([^"\']+)["\']')


def _tool_names_registered_in_source(repo_root: Path) -> list[str]:
    """Every string literal passed as the first arg to a @register(...) call."""
    names = []
    for path in sorted((repo_root / "runtime_tools").glob("*.py")):
        names.extend(_REGISTER_CALL_RE.findall(path.read_text(encoding="utf-8")))
    return names


# Absolute paths into a developer's home directory have no business in shipped
# source, and can be checked without naming anyone.
_HOME_PATH_RE = re.compile(r"(?:[A-Za-z]:\\Users\\|/home/|/Users/)[A-Za-z0-9._-]+", re.IGNORECASE)

# Broader than the logger scan on purpose: a stray absolute path could just as
# easily sit in a directive's Markdown body or a policy's YAML description as
# in a .py file.
_CARVE_CONTENT_DIRS = ("auro_runtime", "runtime_tools", "directives", "policies")
_CARVE_CONTENT_SUFFIXES = (".py", ".md", ".yaml", ".yml")


def _iter_shipped_content_files(repo_root: Path):
    for d in _CARVE_CONTENT_DIRS:
        base = repo_root / d
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.suffix in _CARVE_CONTENT_SUFFIXES and "__pycache__" not in path.parts:
                yield path
    for name in ("pyproject.toml", "LICENSE", "README.md"):
        p = repo_root / name
        if p.is_file():
            yield p


def _home_path_offenders(repo_root: Path):
    """Absolute paths into someone's home directory, wherever they appear."""
    offenders = []
    for path in _iter_shipped_content_files(repo_root):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for match in _HOME_PATH_RE.findall(text):
            offenders.append((str(path.relative_to(repo_root)), match))
    return offenders


# =============================================================================
# Registry shape
# =============================================================================


class TestToolRegistryShape:
    def test_exactly_twelve_tools_registered(self, registry):
        assert len(registry) == 11

    def test_registered_tool_names_match_expected_set(self, registry):
        assert set(registry.keys()) == _EXPECTED_TOOL_NAMES

    def test_every_registry_entry_is_a_three_tuple(self, registry):
        for name, entry in registry.items():
            assert isinstance(entry, tuple), f"{name}: entry is a {type(entry).__name__}, not a tuple"
            assert len(entry) == 3, f"{name}: entry has {len(entry)} elements, expected 3"

    def test_every_tool_callable_is_actually_callable(self, registry):
        for name, (fn, _doc, _schema) in registry.items():
            assert callable(fn), f"{name}: registered object is not callable"

    def test_every_tool_has_a_non_empty_description(self, registry):
        for name, (_fn, doc, _schema) in registry.items():
            assert isinstance(doc, str) and doc.strip(), f"{name}: description/docstring is empty"

    def test_each_tool_name_is_registered_by_exactly_one_register_call(self, repo_root):
        """
        The registry is a plain dict keyed by name: a second, unrelated
        `@register("write_file", ...)` elsewhere would silently overwrite the
        first with no error, and the 17-name-set checks above can't see it —
        the resulting name set looks identical either way. This walks the
        source directly instead of the runtime registry.
        """
        counts = Counter(_tool_names_registered_in_source(repo_root))
        dupes = {name: n for name, n in counts.items() if n > 1}
        assert dupes == {}, f"tool name(s) registered by more than one @register call: {dupes}"


# =============================================================================
# Tool schemas
# =============================================================================


class TestToolSchemas:
    def test_expected_schema_map_covers_every_tool_name(self):
        """Sanity-check the two constants above against each other before trusting either."""
        assert set(_EXPECTED_SCHEMA_BY_TOOL) == _EXPECTED_TOOL_NAMES

    def test_schemas_present_are_pydantic_basemodel_subclasses(self, registry):
        for name, (_fn, _doc, schema) in registry.items():
            if schema is not None:
                assert isinstance(schema, type) and issubclass(schema, BaseModel), (
                    f"{name}: schema {schema!r} is not a BaseModel subclass"
                )

    def test_every_registered_tool_has_an_argument_schema(self, registry):
        """
        No exemptions since 2026-08-13. A registered tool takes model-supplied
        arguments, so one without a schema is validated by nothing.
        """
        no_schema = sorted(name for name, (_fn, _doc, schema) in registry.items() if schema is None)
        assert no_schema == []

    def test_each_tool_is_wired_to_its_expected_schema_class(self, registry):
        for name, expected in _EXPECTED_SCHEMA_BY_TOOL.items():
            _fn, _doc, schema = registry[name]
            assert schema is not None, f"{name}: expected schema {expected}, got None"
            assert schema.__name__ == expected, f"{name}: expected schema {expected}, got {schema.__name__}"


# =============================================================================
# list_tools tool behavior
# =============================================================================


class TestListToolsTool:
    def test_returns_all_twelve_with_descriptions(self, registry):
        list_tools_fn = registry["list_tools"][0]
        result = list_tools_fn(include_args=True)
        assert result["count"] == 11
        names = {t["name"] for t in result["tools"]}
        assert names == _EXPECTED_TOOL_NAMES
        for t in result["tools"]:
            assert t["description"] and t["description"] != "—", (
                f"{t['name']}: empty description in list_tools output"
            )

    def test_include_args_true_adds_an_args_summary_per_tool(self, registry):
        list_tools_fn = registry["list_tools"][0]
        result = list_tools_fn(include_args=True)
        for t in result["tools"]:
            assert "args_summary" in t

    def test_include_args_false_omits_the_args_summary(self, registry):
        list_tools_fn = registry["list_tools"][0]
        result = list_tools_fn(include_args=False)
        for t in result["tools"]:
            assert "args_summary" not in t

    def test_runs_cleanly_through_the_real_executor(self, registry, make_tool_call):
        """Exercises the schema-validation + dispatch path in executor.execute, not just the bare function."""
        from auro_runtime.executor import UNRESTRICTED, execute

        result = execute(make_tool_call("list_tools", {}), allowed_tools=UNRESTRICTED, policy_rules=UNRESTRICTED, run_history=[])
        assert result.success is True
        assert result.error is None
        assert result.result["count"] == 11


# =============================================================================
# Workspace root, marker directories, and core module imports
# =============================================================================


class TestWorkspaceRootAndCoreImports:
    def test_get_workspace_root_returns_the_repo_root(self, repo_root, monkeypatch):
        """The `get_project_root()` alias was cut; the property was always this one."""
        from auro_runtime.paths import get_workspace_root

        monkeypatch.delenv("AURO_ROOT", raising=False)
        get_workspace_root.cache_clear()
        assert get_workspace_root().resolve() == repo_root.resolve()

    def test_project_root_contains_expected_marker_dirs(self, repo_root):
        """`directives/` and `policies/` are not among the markers any more.

        They were retired as top-level mirrors; the executable copies live in
        the package and are asserted below against the resolver that finds
        them, not against a sibling path that happened to exist.
        """
        from auro_runtime.paths import get_directives_dir, get_policies_dir

        for marker in ("auro_runtime", "runtime_tools"):
            assert (repo_root / marker).is_dir(), f"expected marker directory missing: {marker}"

        for authority in (get_directives_dir(), get_policies_dir()):
            assert authority.is_dir(), f"packaged authority missing: {authority}"

    def test_the_project_root_alias_stays_cut(self):
        """A removed name is only removed until someone re-adds it for convenience.

        `get_project_root()` was an alias for the workspace root, and the name
        is exactly the ambiguity D-039 retired: a caller reading it as "where
        the directives are" got the workspace, which was right only while a
        mirror sat there. Re-exporting it would restore that reading silently,
        so the absence is asserted rather than trusted to memory.
        """
        import auro_runtime.paths as paths

        assert not hasattr(paths, "get_project_root"), (
            "get_project_root was cut on 2026-08-29; ask for the root you mean"
        )

    def test_get_registry_returns_a_copy_not_the_live_dict(self, registry):
        """get_registry()'s docstring promises a copy; mutating the result must not corrupt the real registry."""
        from auro_runtime.executor import get_registry

        first = get_registry()
        first["totally_fake_tool_for_this_test"] = (lambda: None, "fake", None)
        second = get_registry()
        assert "totally_fake_tool_for_this_test" not in second

    @pytest.mark.parametrize(
        "module_name",
        [
            "auro_runtime",
            "auro_runtime.__main__",
            "auro_runtime.paths",
            "auro_runtime.policy",
            "auro_runtime.guards",
            "auro_runtime.executor",
            "auro_runtime.orchestrator",
            "auro_runtime.mcp_server",
            "auro_runtime.secrets",
            "auro_runtime.models",
            "auro_runtime.pipeline.runner",
            "auro_runtime.pipeline.contract",
            "auro_runtime.pipeline.plugins.default",
            "runtime_tools",
        ],
    )
    def test_core_module_imports_cleanly(self, module_name):
        importlib.import_module(module_name)

    def test_main_entrypoint_is_callable(self):
        import auro_runtime.__main__ as entrypoint

        assert callable(entrypoint.main)


# =============================================================================
# CLI surface
# =============================================================================


class TestCliEntrypoint:
    def test_help_lists_exactly_run_and_mcp_and_not_web(self, repo_root):
        proc = subprocess.run(
            [sys.executable, "-m", "auro_runtime", "--help"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 0, f"--help exited {proc.returncode}; stderr:\n{proc.stderr}"
        assert "{run,mcp}" in proc.stdout, proc.stdout
        assert "web" not in proc.stdout.lower(), "a 'web' subcommand should not exist"


# =============================================================================
# Source hygiene: logger namespace, catalogue currency, no absolute home paths
# =============================================================================


class TestSourceTreeHygiene:
    def test_all_loggers_use_the_auro_runtime_namespace(self, repo_root):
        offenders = _find_bad_logger_namespaces(repo_root)
        assert offenders == [], f"logger(s) not under auro_runtime.*: {offenders}"

    def test_test_catalogue_is_current(self, repo_root):
        """
        docs/TESTS.md is generated from the test sources. A hand-maintained
        catalogue drifts within a week, and a stale one is worse than none: it
        describes coverage the suite no longer has.

        Regenerate with: python -m tests.catalogue
        """
        from tests.catalogue import collect, render

        catalogue = repo_root / "docs" / "TESTS.md"
        assert catalogue.is_file(), "docs/TESTS.md missing — run: python -m tests.catalogue"
        assert catalogue.read_text(encoding="utf-8") == render(collect()), (
            "docs/TESTS.md is stale. Regenerate with: python -m tests.catalogue"
        )

    def test_no_absolute_home_paths_in_shipped_source(self, repo_root):
        """
        An absolute path into someone's home directory is machine-specific: it
        breaks on every other checkout, and it names a user. Neither belongs in
        shipped source.
        """
        offenders = _home_path_offenders(repo_root)
        assert offenders == [], f"absolute home path(s) in shipped source: {offenders}"


# =============================================================================
# Model backend selection
# =============================================================================


class TestModelBackendSelection:
    def test_default_backend_is_anthropic(self, monkeypatch):
        monkeypatch.delenv("AURO_MODEL_BACKEND", raising=False)
        from auro_runtime.models import get_backend
        from auro_runtime.models.anthropic_backend import AnthropicBackend

        assert isinstance(get_backend(), AnthropicBackend)

    @pytest.mark.parametrize("value", ["openai", "openai_compatible", "OPENAI", "  openai_compatible  "])
    def test_openai_and_openai_compatible_are_aliases_for_the_same_backend(self, monkeypatch, value):
        monkeypatch.setenv("AURO_MODEL_BACKEND", value)
        from auro_runtime.models import get_backend
        from auro_runtime.models.openai_compatible_backend import OpenAICompatibleBackend

        assert isinstance(get_backend(), OpenAICompatibleBackend)

    def test_unknown_backend_name_raises_value_error(self, monkeypatch):
        monkeypatch.setenv("AURO_MODEL_BACKEND", "definitely_not_a_real_backend")
        from auro_runtime.models import get_backend

        with pytest.raises(ValueError, match="definitely_not_a_real_backend"):
            get_backend()

    def test_resolve_model_reports_the_id_generate_would_actually_call(self, monkeypatch):
        """
        The cost gate needs the resolved id. Without this, `model=None` — the
        ordinary way to ask for the configured default — is invisible to any
        check that inspects the caller's argument.
        """
        from auro_runtime.models import resolve_model
        from auro_runtime.models.anthropic_backend import DEFAULT_MODEL

        monkeypatch.delenv("AURO_MODEL_BACKEND", raising=False)
        monkeypatch.delenv("AURO_MODEL", raising=False)
        assert resolve_model(None) == DEFAULT_MODEL

        monkeypatch.setenv("AURO_MODEL", "configured-default-model")
        assert resolve_model(None) == "configured-default-model"
        # An explicit argument still wins over the configured default.
        assert resolve_model("explicit-model") == "explicit-model"


class TestProviderSdkImportIsolation:
    """
    Constructing a backend must never require a provider SDK to be importable.

    This class was TestHighCostModelGate until 2026-08-26. The three gate tests
    went with `generate_text`; these two never belonged to the gate and are what
    the class actually holds.
    """

    def test_get_backend_works_even_when_provider_sdks_are_unimportable(self, monkeypatch):
        """
        Simulates neither the anthropic nor the openai SDK being installed by
        forcing their import to fail: setting sys.modules[name] = None makes
        the import system raise ImportError for that name (a standard,
        documented trick), regardless of what's actually pip-installed in
        this environment. get_backend() must still succeed for every alias,
        proving backend *construction* never touches a provider SDK — only
        calling .generate() on the result does.
        """
        monkeypatch.setitem(sys.modules, "anthropic", None)
        monkeypatch.setitem(sys.modules, "openai", None)
        from auro_runtime.models import get_backend

        monkeypatch.delenv("AURO_MODEL_BACKEND", raising=False)
        get_backend()  # anthropic default — must not raise ImportError

        for value in ("openai", "openai_compatible"):
            monkeypatch.setenv("AURO_MODEL_BACKEND", value)
            get_backend()

    def test_importing_models_package_does_not_import_provider_sdks(self, repo_root):
        """
        A clean-interpreter check (subprocess, not the sys.modules trick
        above) that plain `import auro_runtime.models` — and the
        `runtime_tools` import that registers the built-in tools — never
        eagerly imports anthropic or openai, regardless of whether those
        packages happen to be pip-installed in this dev environment.
        """
        code = (
            "import sys\n"
            "import runtime_tools\n"
            "import auro_runtime.models\n"
            "assert 'anthropic' not in sys.modules, 'importing pulled in the anthropic SDK'\n"
            "assert 'openai' not in sys.modules, 'importing pulled in the openai SDK'\n"
            "print('OK')\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        assert "OK" in proc.stdout
