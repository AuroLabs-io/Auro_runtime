"""
Distribution-boundary verification for both published artifacts.

These tests deliberately do not import the project under test in their child
processes from this checkout.  They build one exact wheel and one exact source
distribution from a writable temporary source copy, install each of them and
all of their dependencies into a clean virtual environment, and run the
installed interpreter with ``-I`` from a hostile unrelated working directory.

Every installed-surface probe is parametrised over both lineages -- the wheel
itself, and a wheel rebuilt from the source distribution -- because a release
that publishes two files and probes one has evidence for one.  The selection
between them is proved in both directions rather than assumed -- a broken
source distribution must fail the sdist leg and only the sdist leg, and a
healthy one must reach it intact and only it.  See the two controls named
``..._installs_the_sdist_and_not_the_supplied_wheel`` and
``..._reaches_the_install_intact_and_only_the_sdist_leg``.

The test is opt-in because populating the temporary wheelhouse may require
package-index access.  Run it with::

    AURO_RUN_DISTRIBUTION_TESTS=1 pytest -m distribution
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import venv
import zipfile
from dataclasses import dataclass
from pathlib import Path

import pytest


pytestmark = [
    pytest.mark.slow,
    pytest.mark.distribution,
    pytest.mark.skipif(
        os.environ.get("AURO_RUN_DISTRIBUTION_TESTS") != "1",
        reason="set AURO_RUN_DISTRIBUTION_TESTS=1 to build and probe an isolated wheel install",
    ),
]

_PROJECT_WHEEL_PREFIX = "auro_runtime-"
_AUDIT_FILENAME = "auro_audit.jsonl"
_SENSITIVE_SENTINEL = "distribution-test-sensitive-sentinel"
_SDIST_MUTATION_SENTINEL = (
    "SDIST_INSTALL_PROBE: this source artifact is unusable when installed"
)
_SDIST_POSITIVE_MARKER = "SDIST_INSTALL_PROBE: this source artifact reached the install"

_LIBRARY_PROBE = r"""
import json
import sys
from pathlib import Path

import auro_runtime
import runtime_tools
from auro_runtime import run
from auro_runtime.paths import get_authority_root, get_workspace_root

result = run("tool_catalog", "attempt the requested sensitive-path read")
print(json.dumps({
    "auro_runtime_file": auro_runtime.__file__,
    "runtime_tools_file": runtime_tools.__file__,
    "authority_root": str(get_authority_root()),
    "workspace_root": str(get_workspace_root()),
    "sys_path": sys.path,
    "result": result,
}, default=str))
"""

_PROVENANCE_PROBE = r"""
import json
import sys

import auro_runtime
import runtime_tools
from auro_runtime.paths import get_authority_root, get_workspace_root

print(json.dumps({
    "auro_runtime_file": auro_runtime.__file__,
    "runtime_tools_file": runtime_tools.__file__,
    "authority_root": str(get_authority_root()),
    "workspace_root": str(get_workspace_root()),
    "sys_path": sys.path,
}))
"""

_IMMUTABILITY_PROBE = r"""
import json
import sys
from pathlib import Path

import auro_runtime
import runtime_tools
from auro_runtime.paths import get_authority_root, get_workspace_root
from runtime_tools.file_tools import delete_file, restore_file, write_file

authority_target = get_authority_root() / "directives" / "tool_catalog.md"
relative_write = write_file(
    "directives/tool_catalog.md",
    "must not replace executable authority",
)
absolute_write = write_file(
    str(authority_target),
    "must not replace installed authority",
)
absolute_delete = delete_file(str(authority_target))

workspace_write = write_file(
    "output/distribution-positive.txt",
    "workspace-positive-control",
)
workspace_delete = delete_file("output/distribution-positive.txt")
blocked_restore = restore_file(
    workspace_delete["archive_path"],
    restore_to=str(authority_target),
)
workspace_restore = restore_file(workspace_delete["archive_path"])

print(json.dumps({
    "auro_runtime_file": auro_runtime.__file__,
    "runtime_tools_file": runtime_tools.__file__,
    "authority_root": str(get_authority_root()),
    "workspace_root": str(get_workspace_root()),
    "sys_path": sys.path,
    "relative_write": relative_write,
    "absolute_write": absolute_write,
    "absolute_delete": absolute_delete,
    "workspace_write": workspace_write,
    "workspace_delete": workspace_delete,
    "blocked_restore": blocked_restore,
    "workspace_restore": workspace_restore,
}))
"""


_ARTIFACT_LINEAGES = ("wheel", "sdist")


@dataclass(frozen=True)
class BuiltDistribution:
    wheel: Path
    sdist: Path
    sdist_wheel: Path
    wheelhouse: Path
    sha256: str
    sdist_sha256: str
    source_copy: Path
    source_root: Path

    def installable(self, lineage: str) -> Path:
        """The file an install of ``lineage`` must actually consume.

        The two lineages are different files by construction.  ``wheel`` is the
        candidate wheel; ``sdist`` is a wheel rebuilt from the candidate source
        distribution, sharing none of its bytes.  Both installs are routed
        through this one lookup on purpose: collapsing the sdist leg back onto
        the supplied wheel is then a one-line change, which is exactly what
        ``test_the_sdist_leg_installs_the_sdist_and_not_the_supplied_wheel``
        exists to fail on.  Law 1c -- a selection proved only by its passes is
        not proved.
        """
        if lineage == "wheel":
            return self.wheel
        if lineage == "sdist":
            return self.sdist_wheel
        raise AssertionError(f"unknown artifact lineage: {lineage!r}")


@dataclass(frozen=True)
class InstalledDistribution:
    built: BuiltDistribution
    lineage: str
    installable: Path
    root: Path
    python: Path
    site_packages: Path
    hostile_cwd: Path
    authority_root: Path

    def clean_env(
        self,
        workspace: Path,
        extra: dict[str, str] | None = None,
    ) -> dict[str, str]:
        env = os.environ.copy()
        for key in (
            "PYTHONPATH",
            "PYTHONHOME",
            "AURO_ROOT",
            "AURO_AUTHORITY_ROOT",
            "AURO_AUDIT_LOG",
            "AURO_ALLOW_NO_POLICIES",
            "AURO_POLICY_PROFILE",
            "AURO_MCP_ALLOWED_DIRECTIVE_IDS",
            "AURO_DISTRIBUTION_DIR",
        ):
            env.pop(key, None)
        env["PYTHONNOUSERSITE"] = "1"
        env["AURO_WORKSPACE_ROOT"] = str(workspace.resolve())
        if extra:
            env.update(extra)
        return env

    def run_isolated(
        self,
        code: str,
        *,
        workspace: Path,
        extra_env: dict[str, str] | None = None,
        timeout: int = 120,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.python), "-I", "-B", "-c", code],
            cwd=self.hostile_cwd,
            env=self.clean_env(workspace, extra_env),
            text=True,
            capture_output=True,
            timeout=timeout,
        )


def _python_in(venv_root: Path) -> Path:
    if os.name == "nt":
        return venv_root / "Scripts" / "python.exe"
    return venv_root / "bin" / "python"


def _console_script_in(venv_root: Path) -> Path:
    """The entry point setuptools generates from ``[project.scripts]``.

    This is a different artifact from the module CLI: pip writes it at install
    time from ``entry_points.txt``, so it can be absent or broken while
    ``python -m auro_runtime`` works perfectly.
    """
    if os.name == "nt":
        return venv_root / "Scripts" / "auro-runtime.exe"
    return venv_root / "bin" / "auro-runtime"


def _normalise_prog(text: str) -> str:
    """Erase the program name argparse derives from ``argv[0]``.

    ``python -m auro_runtime`` reports itself as ``__main__.py`` and the console
    script as ``auro-runtime``.  That difference is correct -- each names the
    command the reader actually typed -- so it must not count as a divergence
    when the two invocations are compared.
    """
    return text.replace("__main__.py", "PROG").replace("auro-runtime", "PROG")


def _last_json_line(stdout: str) -> dict:
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        pass
    else:
        if isinstance(value, dict):
            return value
    for line in reversed(stdout.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise AssertionError(f"subprocess emitted no JSON object:\n{stdout}")


def _is_under(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _assert_installed_provenance(
    payload: dict,
    install: InstalledDistribution,
    workspace: Path,
) -> None:
    auro_file = Path(payload["auro_runtime_file"]).resolve()
    tools_file = Path(payload["runtime_tools_file"]).resolve()
    authority = Path(payload["authority_root"]).resolve()
    resolved_workspace = Path(payload["workspace_root"]).resolve()

    assert _is_under(auro_file, install.site_packages), (
        f"auro_runtime imported outside the installed venv: {auro_file}"
    )
    assert _is_under(tools_file, install.site_packages), (
        f"runtime_tools imported outside the installed venv: {tools_file}"
    )
    assert authority == install.authority_root
    assert resolved_workspace == workspace.resolve()
    assert authority != resolved_workspace

    forbidden = (install.built.source_root, install.built.source_copy, install.hostile_cwd)
    for entry in payload["sys_path"]:
        if not entry:
            continue
        entry_path = Path(entry).resolve()
        assert not any(_is_under(entry_path, root) for root in forbidden), (
            f"isolated child sys.path leaked a forbidden source: {entry_path}"
        )


def _tree_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _read_audit(workspace: Path) -> list[dict]:
    audit = workspace / _AUDIT_FILENAME
    assert audit.is_file(), f"default audit was not written to {audit}"
    return [
        json.loads(line)
        for line in audit.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _prepare_workspace(base: Path, name: str) -> Path:
    workspace = base / name
    (workspace / ".aws").mkdir(parents=True)
    (workspace / ".aws" / "credentials").write_text(
        _SENSITIVE_SENTINEL,
        encoding="utf-8",
    )
    return workspace


def _assert_sensitive_path_refusal(result: dict) -> None:
    assert result["legacy_steps"], result
    step = result["legacy_steps"][0]
    assert step["tool"] == "read_file"
    assert step["success"] is False
    assert "Policy violation [sensitive_paths]" in step["error"]
    assert _SENSITIVE_SENTINEL not in json.dumps(result)


def _build_sdist(source: Path, outdir: Path) -> Path:
    built = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "build",
            "--sdist",
            "--no-isolation",
            "--outdir",
            str(outdir),
        ],
        cwd=source,
        text=True,
        capture_output=True,
        timeout=300,
    )
    assert built.returncode == 0, built.stdout + built.stderr
    sdists = sorted(outdir.glob("auro_runtime-*.tar.gz"))
    assert len(sdists) == 1, sdists
    return sdists[0]


def _wheel_from_sdist(sdist: Path, outdir: Path, *, cwd: Path) -> Path:
    rebuilt = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "pip",
            "wheel",
            str(sdist),
            "--wheel-dir",
            str(outdir),
            "--no-build-isolation",
            "--no-deps",
        ],
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=300,
    )
    assert rebuilt.returncode == 0, rebuilt.stdout + rebuilt.stderr
    wheels = sorted(outdir.glob("auro_runtime-*.whl"))
    assert len(wheels) == 1, wheels
    return wheels[0]


def _install_into_clean_venv(
    venv_root: Path,
    *,
    installable: Path,
    wheelhouse: Path,
    cwd: Path,
) -> subprocess.CompletedProcess[str]:
    """Install exactly ``installable`` into a fresh venv, dependencies local.

    Returns the completed ``pip install`` rather than asserting on it, because
    one caller is a negative control that requires the install-or-import to
    fail.  A helper that asserted success could not be reused to prove failure.
    """
    venv.EnvBuilder(with_pip=True, clear=True).create(venv_root)
    return subprocess.run(
        [
            str(_python_in(venv_root)),
            "-I",
            "-B",
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(wheelhouse),
            str(installable),
        ],
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=300,
    )


def _probe_each_lineage_against_a_mutated_sdist(
    built: BuiltDistribution,
    tmp_path: Path,
    *,
    init_source: str,
    probe: str,
) -> dict[str, subprocess.CompletedProcess[str]]:
    """Install both lineages when only the sdist has been altered, and probe each.

    The wheel handed to the sdist-lineage install is rebuilt from a source
    distribution whose ``auro_runtime/__init__.py`` is ``init_source``; the
    wheel lineage gets the untouched candidate.  Only the source distribution
    differs between the two, so any difference the probe observes is caused by
    which artifact was installed and by nothing else.

    Returns both completed probes rather than asserting, because the two
    controls that call this require opposite outcomes -- one needs the sdist
    leg to fail, the other needs it to succeed and carry a marker.
    """
    mutant_source = tmp_path / "mutant-source"
    shutil.copytree(
        built.source_copy,
        mutant_source,
        ignore=shutil.ignore_patterns(
            ".pytest_cache", "__pycache__", "*.pyc", "*.egg-info", "build", "dist"
        ),
    )
    (mutant_source / "auro_runtime" / "__init__.py").write_text(
        init_source, encoding="utf-8"
    )

    sdist_dir = tmp_path / "mutant-sdist"
    wheel_dir = tmp_path / "mutant-sdist-wheel"
    sdist_dir.mkdir()
    wheel_dir.mkdir()
    mutant_sdist = _build_sdist(mutant_source, sdist_dir)
    mutant = BuiltDistribution(
        # The wheel is the real one, untouched. Only the sdist is altered, so a
        # collapse onto the wheel is the single thing that can erase the
        # difference the callers below are looking for.
        wheel=built.wheel,
        sdist=mutant_sdist,
        sdist_wheel=_wheel_from_sdist(mutant_sdist, wheel_dir, cwd=tmp_path),
        wheelhouse=built.wheelhouse,
        sha256=built.sha256,
        sdist_sha256=hashlib.sha256(mutant_sdist.read_bytes()).hexdigest(),
        source_copy=mutant_source,
        source_root=built.source_root,
    )
    assert mutant.installable("sdist") != mutant.installable("wheel")

    observed: dict[str, subprocess.CompletedProcess[str]] = {}
    for lineage in _ARTIFACT_LINEAGES:
        venv_root = tmp_path / f"venv-{lineage}"
        install = _install_into_clean_venv(
            venv_root,
            installable=mutant.installable(lineage),
            wheelhouse=mutant.wheelhouse,
            cwd=tmp_path,
        )
        assert install.returncode == 0, (
            f"the {lineage} lineage failed to install at all, so this control "
            f"cannot say which artifact was chosen\n{install.stdout}\n{install.stderr}"
        )
        observed[lineage] = subprocess.run(
            [str(_python_in(venv_root)), "-I", "-B", "-c", probe],
            cwd=tmp_path,
            text=True,
            capture_output=True,
            timeout=120,
        )
    return observed


def _assert_refusal_audit(workspace: Path) -> None:
    events = _read_audit(workspace)
    matching = [
        event
        for event in events
        if event.get("event") == "policy_guard_check"
        and event.get("rule_id") == "sensitive_paths"
    ]
    assert matching
    assert matching[-1]["allowed"] is False
    assert _SENSITIVE_SENTINEL not in json.dumps(events)


@pytest.fixture(scope="session")
def built_distribution(
    tmp_path_factory: pytest.TempPathFactory,
    repo_root: Path,
) -> BuiltDistribution:
    scratch = tmp_path_factory.mktemp("auro-wheel-build")
    source_copy = scratch / "source"
    wheelhouse = scratch / "wheelhouse"
    wheelhouse.mkdir()

    shutil.copytree(
        repo_root,
        source_copy,
        ignore=shutil.ignore_patterns(
            ".git",
            ".pytest_cache",
            "__pycache__",
            "*.pyc",
            "*.egg-info",
            "build",
            "dist",
            ".auro_archive",
            "output",
            _AUDIT_FILENAME,
        ),
    )
    assert not (source_copy / _AUDIT_FILENAME).exists()

    supplied_dir_raw = os.environ.get("AURO_DISTRIBUTION_DIR")
    supplied_wheel = None
    supplied_sdist = None
    if supplied_dir_raw:
        supplied_dir = Path(supplied_dir_raw).resolve()
        supplied_wheels = sorted(supplied_dir.glob("auro_runtime-*.whl"))
        supplied_sdists = sorted(supplied_dir.glob("auro_runtime-*.tar.gz"))
        assert len(supplied_wheels) == 1, supplied_wheels
        assert len(supplied_sdists) == 1, supplied_sdists
        supplied_wheel = supplied_wheels[0]
        supplied_sdist = supplied_sdists[0]

    proc = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "pip",
            "wheel",
            ".",
            "--wheel-dir",
            str(wheelhouse),
            "--no-build-isolation",
        ],
        cwd=source_copy,
        text=True,
        capture_output=True,
        timeout=300,
    )
    assert proc.returncode == 0, (
        "failed to build the isolated wheelhouse\n"
        f"stdout:\n{proc.stdout}\n"
        f"stderr:\n{proc.stderr}"
    )

    project_wheels = sorted(
        path
        for path in wheelhouse.glob("*.whl")
        if path.name.lower().startswith(_PROJECT_WHEEL_PREFIX)
    )
    assert len(project_wheels) == 1, (
        f"expected one exact auro-runtime wheel, found: {project_wheels}"
    )
    wheel = project_wheels[0]
    if supplied_wheel is not None:
        # Keep the dependency wheelhouse produced above, but replace the locally
        # built project wheel with the exact publication candidate. Every install
        # and probe below therefore exercises the candidate named by the evidence
        # record, while remaining independent of package-index access.
        shutil.copy2(supplied_wheel, wheel)
        assert hashlib.sha256(wheel.read_bytes()).digest() == hashlib.sha256(
            supplied_wheel.read_bytes()
        ).digest()

    if supplied_sdist is None:
        sdist_dir = scratch / "sdist"
        sdist_dir.mkdir()
        sdist = _build_sdist(source_copy, sdist_dir)
    else:
        sdist = supplied_sdist

    # Rebuild a wheel from the source distribution once, session-wide. This is
    # the artifact an adopter gets from `pip install --no-binary`, or from any
    # index resolution where no compatible wheel is offered, and until this
    # existed no probe in this module had ever run against it -- the sdist was
    # opened, inspected and rebuilt, and then every installed-surface assertion
    # went back to the wheel fixture.
    sdist_wheel_dir = scratch / "sdist-wheel"
    sdist_wheel_dir.mkdir()
    sdist_wheel = _wheel_from_sdist(sdist, sdist_wheel_dir, cwd=scratch)

    return BuiltDistribution(
        wheel=wheel,
        sdist=sdist,
        sdist_wheel=sdist_wheel,
        wheelhouse=wheelhouse,
        sha256=hashlib.sha256(wheel.read_bytes()).hexdigest(),
        sdist_sha256=hashlib.sha256(sdist.read_bytes()).hexdigest(),
        source_copy=source_copy,
        source_root=repo_root.resolve(),
    )


@pytest.fixture(params=_ARTIFACT_LINEAGES)
def installed_distribution(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    built_distribution: BuiltDistribution,
) -> InstalledDistribution:
    """One clean install per artifact lineage, so every probe runs twice.

    Clause 5 of the release gate says *both* artifacts install and pass their
    applicable public-surface probes.  Until this fixture was parametrised the
    suite proved that for the wheel and asserted it for the pair: the sdist was
    inspected and rebuilt, never installed, and no probe below had ever
    imported anything derived from it.  Law 16c -- a control's stated scope
    must be falsifiable against its actual reach.
    """
    lineage = request.param
    installable = built_distribution.installable(lineage)
    venv_root = tmp_path / "venv"
    python = _python_in(venv_root)

    proc = _install_into_clean_venv(
        venv_root,
        installable=installable,
        wheelhouse=built_distribution.wheelhouse,
        cwd=tmp_path,
    )
    assert proc.returncode == 0, (
        f"failed to install the exact {lineage}-derived artifact into the clean venv\n"
        f"artifact={installable}\n"
        f"wheel_sha256={built_distribution.sha256}\n"
        f"sdist_sha256={built_distribution.sdist_sha256}\n"
        f"stdout:\n{proc.stdout}\n"
        f"stderr:\n{proc.stderr}"
    )

    check = subprocess.run(
        [str(python), "-I", "-B", "-m", "pip", "check"],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert check.returncode == 0, check.stdout + check.stderr

    site_proc = subprocess.run(
        [
            str(python),
            "-I",
            "-B",
            "-c",
            "import json,site; print(json.dumps(site.getsitepackages()))",
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert site_proc.returncode == 0, site_proc.stderr
    candidates = [Path(path).resolve() for path in json.loads(site_proc.stdout)]
    site_packages = next(
        path for path in candidates if (path / "auro_runtime").is_dir()
    )

    hostile = tmp_path / "hostile-cwd"
    (hostile / "auro_runtime").mkdir(parents=True)
    (hostile / "auro_runtime" / "__init__.py").write_text(
        "raise RuntimeError('hostile auro_runtime imported')\n",
        encoding="utf-8",
    )
    (hostile / "runtime_tools").mkdir()
    (hostile / "runtime_tools" / "__init__.py").write_text(
        "raise RuntimeError('hostile runtime_tools imported')\n",
        encoding="utf-8",
    )
    (hostile / "directives").mkdir()
    (hostile / "directives" / "tool_catalog.md").write_text(
        "---\nid: tool_catalog\ntools: [resolve_secret, delete_file]\n---\nHostile.\n",
        encoding="utf-8",
    )
    (hostile / "policies").mkdir()
    (hostile / "policies" / "default.yaml").write_text(
        "id: default\nrules: []\n",
        encoding="utf-8",
    )

    authority = site_packages / "auro_runtime" / "resources"
    assert authority.is_dir()
    return InstalledDistribution(
        built=built_distribution,
        lineage=lineage,
        installable=installable,
        root=venv_root,
        python=python,
        site_packages=site_packages,
        hostile_cwd=hostile,
        authority_root=authority.resolve(),
    )


def test_wheel_contains_reviewed_authority_assets_and_record(
    built_distribution: BuiltDistribution,
) -> None:
    expected = {
        *(
            f"auro_runtime/resources/directives/{path.name}"
            for path in (
                built_distribution.source_copy
                / "auro_runtime" / "resources" / "directives"
            ).glob("*.md")
        ),
        *(
            f"auro_runtime/resources/policies/{path.name}"
            for path in (
                built_distribution.source_copy
                / "auro_runtime" / "resources" / "policies"
            ).glob("*.yaml")
        ),
    }
    assert expected

    with zipfile.ZipFile(built_distribution.wheel) as archive:
        names = set(archive.namelist())
        authority_members = {
            name
            for name in names
            if name.startswith("auro_runtime/resources/") and not name.endswith("/")
        }
        assert authority_members == expected
        assert not any(name.startswith(("directives/", "policies/", "tests/")) for name in names)
        assert not any(
            name.endswith((_AUDIT_FILENAME, ".env", "auro_secrets.yaml"))
            for name in names
        )

        records = [name for name in names if name.endswith(".dist-info/RECORD")]
        assert len(records) == 1
        recorded_paths = {
            line.split(",", 1)[0]
            for line in archive.read(records[0]).decode("utf-8").splitlines()
        }
        assert expected <= recorded_paths


def test_sdist_excludes_tests_and_builds_the_same_authority_set(
    built_distribution: BuiltDistribution,
) -> None:
    sdist = built_distribution.sdist

    with tarfile.open(sdist, "r:gz") as archive:
        members = {
            "/".join(Path(name).parts[1:])
            for name in archive.getnames()
            if len(Path(name).parts) > 1
        }
    assert {
        "MANIFEST.in",
        "README.md",
        "SECURITY.md",
        "docs/API.md",
        "docs/AUDIT_EVENTS.md",
        "docs/CREDENTIALS.md",
        "docs/DIRECTIVES.md",
        "docs/FAQ.md",
        "docs/TESTS.md",
        "docs/auro-runtime-boundary.svg",
    } <= members
    # docs/TESTS.md is the generated catalogue of the suite. The README links to
    # it, and the link should resolve inside the sdist as well as on GitHub.
    #
    # docs/DIRECTIVES.md is the same arrangement for directives, and shipping it
    # matters more: it is the only enumeration of what tool authority each
    # shipped directive grants. Its generator lives in tests/ and is pruned
    # below, so the sdist must carry the output or the README links nowhere.
    #
    # docs/AUDIT_EVENTS.md is the third generated catalogue. API.md calls `event`
    # the grouping key, so the set of names is part of the integration contract
    # and has to travel with the doc that references it.
    #
    # docs/auro-runtime-boundary.svg is the first non-markdown file the README
    # references. MANIFEST.in shipped only *.md out of docs/ until it was added,
    # so the sdist would have carried a README with a broken image while every
    # other check here passed -- visible to anyone installing from source rather
    # than reading GitHub. Asserted here so the manifest line is a control
    # rather than something that happens to be true.
    #
    # SECURITY.md and docs/FAQ.md were added to this set on 2026-08-16, for the
    # same reason as DIRECTIVES.md rather than as a formality. SECURITY.md is
    # where a reporter is told which channel is private and, just as usefully,
    # which findings are already-documented boundaries rather than defects; it
    # cites docs/FAQ.md for several of them, so shipping one without the other
    # leaves the security policy pointing nowhere from inside the sdist. Neither
    # is generated, so nothing else would notice them dropping out of MANIFEST.in.
    #
    # docs/API.md is hand-written rather than generated, so nothing regenerates
    # it if it goes missing. It is the only description of the executor contract
    # for an embedder driving execute() directly, and of the matched_fields
    # obligation a third-party guard has to meet. Asserting it here is the only
    # thing standing between "the doc was dropped from the sdist" and a release
    # that ships an unusable extension surface.
    assert not any(
        member == "tests" or member.startswith("tests/")
        for member in members
    ), "test implementation must not ship in the source distribution"

    # The rebuild is the session fixture's, not a second one: the wheel whose
    # authority set is compared here is the same file the sdist leg of
    # installed_distribution installs, so this assertion describes the artifact
    # actually probed rather than a rebuild that happens to resemble it.
    expected_authority = {
        f"auro_runtime/resources/{directory}/{path.name}"
        for directory, pattern in (("directives", "*.md"), ("policies", "*.yaml"))
        for path in (
            built_distribution.source_copy / "auro_runtime" / "resources" / directory
        ).glob(pattern)
    }
    with zipfile.ZipFile(built_distribution.sdist_wheel) as archive:
        rebuilt_authority = {
            name
            for name in archive.namelist()
            if name.startswith("auro_runtime/resources/")
        }
    assert expected_authority
    assert rebuilt_authority == expected_authority


def test_the_sdist_leg_installs_the_sdist_and_not_the_supplied_wheel(
    built_distribution: BuiltDistribution,
    tmp_path: Path,
) -> None:
    """Negative control for the artifact selection itself.

    Every probe below is parametrised over two lineages, and the whole value of
    that parametrisation rests on one unproved assumption: that the sdist leg
    installs something derived from the source distribution rather than the
    wheel sitting beside it.  Nothing in a passing run distinguishes those.  A
    fixture that returned ``self.wheel`` for both lineages would produce two
    green legs, a doubled test count, and exactly the evidence the suite had
    before this file was changed -- which is how the previous version of this
    module came to state a reach over both artifacts while probing one.

    So the selection is mutated rather than asserted.  A source distribution is
    built whose installed package raises on import, paired with the untouched
    good wheel, and both lineages are installed:

      * the sdist lineage must carry the injected failure -- if it does not,
        the selection has collapsed onto the wheel and every sdist-leg pass
        elsewhere in this module is vacuous;
      * the wheel lineage must be unaffected -- if it is not, the mutation was
        not localised to the sdist and proves nothing about which artifact was
        chosen.

    Law 1c asks for both directions, and this is the shape it takes here: one
    mutation, two observations that must disagree.  Law 1b -- the harness is
    subject to every law, and the fixture that picks the artifact is harness.

    Proved by mutation on 2026-08-30, at both layers a collapse can occur:

      * ``installable()`` returning ``self.wheel`` for the sdist lineage is
        killed by the inequality guard below, before any venv is built;
      * ``_install_into_clean_venv`` resolving ``auro_runtime`` by name from the
        wheelhouse instead of installing the file it was handed -- the pip
        resolution the guard cannot see -- is killed by the sdist import
        assertion, which is the failure this docstring describes.

    This is only the refusal half.  The permit half -- that a healthy source
    distribution installs, imports, and arrives with its own content -- is
    ``test_a_healthy_sdist_reaches_the_install_intact_and_only_the_sdist_leg``,
    and neither control is sufficient alone: this one would be satisfied by a
    leg that refused every sdist, and that one by a leg that never refused any.

    Known bound, recorded rather than left implicit.  The ``returncode == 0``
    wheel assertion below is a localisation guard and is *not* mutation-proved:
    every mutation that breaks the wheel leg while leaving the two paths
    distinct turned out to be a mutation of this test rather than of its
    subject, and a test's own assertion is not the subject.  The wheel leg's
    *content* is separately discriminated by the permit control, which fails if
    the wheel ever carries what only the sdist was given; what stays unproved
    is narrower than it looks, and is recorded here rather than assumed away.
    """
    observed = _probe_each_lineage_against_a_mutated_sdist(
        built_distribution,
        tmp_path,
        init_source=f'raise RuntimeError("{_SDIST_MUTATION_SENTINEL}")\n',
        probe="import auro_runtime",
    )

    assert observed["sdist"].returncode != 0, (
        "the sdist lineage imported cleanly from a source distribution built to "
        "raise on import, so installed_distribution is not installing the sdist "
        "-- the two artifact paths have collapsed onto the supplied wheel"
    )
    assert _SDIST_MUTATION_SENTINEL in observed["sdist"].stderr, (
        "the sdist lineage failed for some reason other than the injected one:\n"
        f"{observed['sdist'].stdout}\n{observed['sdist'].stderr}"
    )
    assert observed["wheel"].returncode == 0, (
        "the wheel lineage broke under an sdist-only mutation, so the failure "
        f"above does not identify the chosen artifact:\n{observed['wheel'].stderr}"
    )
    assert _SDIST_MUTATION_SENTINEL not in observed["wheel"].stderr


def test_a_healthy_sdist_reaches_the_install_intact_and_only_the_sdist_leg(
    built_distribution: BuiltDistribution,
    tmp_path: Path,
) -> None:
    """Permit direction of the same control, and the half law 1c asks for.

    The negative control above proves the sdist leg can go red.  That is not
    the same as proving its green is caused by anything: a leg that refused
    every source distribution, or that observed only *that* a rebuild happened
    rather than what it contained, would satisfy every assertion up there.
    Both are refusal-shaped evidence, and a control proven only by its refusals
    is not proven.

    So the sdist is mutated again, benignly this time.  A marker attribute is
    appended to the packaged ``__init__``, and the requirement inverts: both
    lineages must install, both must import cleanly, and the marker must be
    visible through the sdist leg and absent from the wheel leg.

    That is a stronger statement than the negative control's, and it is the one
    the twelve parametrised sdist-leg probes below actually rest on:

      * the sdist leg permits a healthy source distribution rather than merely
        being capable of failing;
      * what it installs carries the *content* of that source distribution, not
        just a path that differs from the wheel's -- a selection that returned
        some other correctly-built wheel would pass the negative control and
        fail here;
      * the wheel leg is untouched by an sdist-only change, so the marker
        discriminates the artifact rather than the environment.

    The mutation is of the subject, not of this test: what changes is the
    source distribution being installed.
    """
    packaged_init = (
        built_distribution.source_copy / "auro_runtime" / "__init__.py"
    ).read_text(encoding="utf-8")
    observed = _probe_each_lineage_against_a_mutated_sdist(
        built_distribution,
        tmp_path,
        init_source=(
            f'{packaged_init}\n__sdist_probe__ = "{_SDIST_POSITIVE_MARKER}"\n'
        ),
        probe=(
            "import auro_runtime\n"
            "print(getattr(auro_runtime, '__sdist_probe__', '<absent>'))\n"
        ),
    )

    for lineage in _ARTIFACT_LINEAGES:
        assert observed[lineage].returncode == 0, (
            f"the {lineage} lineage failed to import a healthy package, so this "
            f"control cannot speak to the permit direction:\n"
            f"{observed[lineage].stdout}\n{observed[lineage].stderr}"
        )

    assert observed["sdist"].stdout.strip() == _SDIST_POSITIVE_MARKER, (
        "the sdist lineage imported cleanly but without the marker written into "
        "the source distribution it was built from, so what it installed is not "
        "that source distribution's content"
    )
    assert observed["wheel"].stdout.strip() == "<absent>", (
        "the wheel lineage carried a marker that exists only in the mutated "
        "source distribution, so the two lineages are not separated by artifact"
    )


def test_installed_library_and_cli_use_packaged_authority_and_workspace_audit(
    installed_distribution: InstalledDistribution,
    tmp_path: Path,
    stub_backend,
) -> None:
    install = installed_distribution
    authority_before = _tree_hashes(install.authority_root)
    source_audit = install.built.source_root / _AUDIT_FILENAME
    source_audit_before = (
        hashlib.sha256(source_audit.read_bytes()).hexdigest()
        if source_audit.is_file()
        else None
    )

    provenance_workspace = _prepare_workspace(tmp_path, "provenance-workspace")
    provenance = install.run_isolated(
        _PROVENANCE_PROBE,
        workspace=provenance_workspace,
    )
    assert provenance.returncode == 0, provenance.stdout + provenance.stderr
    provenance_payload = _last_json_line(provenance.stdout)
    _assert_installed_provenance(provenance_payload, install, provenance_workspace)

    immutability_workspace = _prepare_workspace(tmp_path, "immutability-workspace")
    immutability = install.run_isolated(
        _IMMUTABILITY_PROBE,
        workspace=immutability_workspace,
    )
    assert immutability.returncode == 0, immutability.stdout + immutability.stderr
    immutability_payload = _last_json_line(immutability.stdout)
    _assert_installed_provenance(
        immutability_payload,
        install,
        immutability_workspace,
    )
    assert immutability_payload["relative_write"]["written"] is False
    assert "protected" in immutability_payload["relative_write"]["error"].lower()
    assert immutability_payload["absolute_write"]["written"] is False
    assert "outside" in immutability_payload["absolute_write"]["error"].lower()
    assert immutability_payload["absolute_delete"]["deleted"] is False
    assert "outside" in immutability_payload["absolute_delete"]["error"].lower()
    assert immutability_payload["workspace_write"]["written"] is True
    assert immutability_payload["workspace_delete"]["deleted"] is True
    assert immutability_payload["blocked_restore"]["restored"] is False
    assert "outside" in immutability_payload["blocked_restore"]["error"].lower()
    assert immutability_payload["workspace_restore"]["restored"] is True
    assert (
        immutability_workspace / "output" / "distribution-positive.txt"
    ).read_text(encoding="utf-8") == "workspace-positive-control"
    assert _tree_hashes(install.authority_root) == authority_before

    script = [
        {
            "tool": "read_file",
            "args": {"path": ".aws/credentials"},
            "reason": "distribution refusal probe",
        },
        {"done": True, "summary": "refusal observed"},
    ]

    library_workspace = _prepare_workspace(tmp_path, "library-workspace")
    stub_backend.set_script(script)
    library = install.run_isolated(
        _LIBRARY_PROBE,
        workspace=library_workspace,
        extra_env=stub_backend.env(),
    )
    assert library.returncode == 0, library.stdout + library.stderr
    library_payload = _last_json_line(library.stdout)
    _assert_installed_provenance(library_payload, install, library_workspace)
    _assert_sensitive_path_refusal(library_payload["result"])
    _assert_refusal_audit(library_workspace)
    assert len(stub_backend.received) == 2

    cli_workspace = _prepare_workspace(tmp_path, "cli-workspace")
    stub_backend.set_script(script)
    cli = subprocess.run(
        [
            str(install.python),
            "-I",
            "-B",
            "-m",
            "auro_runtime",
            "run",
            "--directive",
            "tool_catalog",
            "attempt the requested sensitive-path read",
            "--json",
        ],
        cwd=install.hostile_cwd,
        env=install.clean_env(cli_workspace, stub_backend.env()),
        text=True,
        capture_output=True,
        timeout=120,
    )
    assert cli.returncode == 0, cli.stdout + cli.stderr
    _assert_sensitive_path_refusal(_last_json_line(cli.stdout))
    _assert_refusal_audit(cli_workspace)
    assert len(stub_backend.received) == 2

    assert _tree_hashes(install.authority_root) == authority_before
    assert not (install.hostile_cwd / _AUDIT_FILENAME).exists()
    assert not (install.built.source_copy / _AUDIT_FILENAME).exists()
    source_audit_after = (
        hashlib.sha256(source_audit.read_bytes()).hexdigest()
        if source_audit.is_file()
        else None
    )
    assert source_audit_after == source_audit_before


def _unwrap_tool_result(result) -> object:
    if result.structuredContent is not None:
        payload = result.structuredContent
        return payload.get("result", payload)
    assert result.content
    text = getattr(result.content[0], "text", None)
    assert text is not None
    return json.loads(text)


def test_installed_mcp_stdio_discovers_packaged_directive_and_refuses_sensitive_path(
    installed_distribution: InstalledDistribution,
    tmp_path: Path,
    stub_backend,
) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    install = installed_distribution
    workspace = _prepare_workspace(tmp_path, "mcp-workspace")
    stub_backend.set_script([
        {
            "tool": "read_file",
            "args": {"path": ".aws/credentials"},
            "reason": "MCP distribution refusal probe",
        },
        {"done": True, "summary": "refusal observed"},
    ])
    env = install.clean_env(
        workspace,
        {
            **stub_backend.env(),
            "AURO_MCP_ALLOWED_DIRECTIVE_IDS": "tool_catalog",
        },
    )
    server = StdioServerParameters(
        command=str(install.python),
        args=["-I", "-B", "-m", "auro_runtime", "mcp", "--transport", "stdio"],
        env=env,
        cwd=install.hostile_cwd,
    )

    async def probe() -> tuple[set[str], object, object]:
        # Windows subprocess creation requires a real OS file handle for
        # stderr; StringIO has no fileno().
        with (tmp_path / "mcp-stderr.log").open(
            "w+", encoding="utf-8"
        ) as errlog:
            async with stdio_client(server, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    listed_tools = await session.list_tools()
                    directives = await session.call_tool("list_directives", {})
                    run_result = await session.call_tool(
                        "run_directive",
                        {
                            "directive_id": "tool_catalog",
                            "request": "attempt the requested sensitive-path read",
                        },
                    )
                    return (
                        {tool.name for tool in listed_tools.tools},
                        _unwrap_tool_result(directives),
                        _unwrap_tool_result(run_result),
                    )

    tool_names, directives, run_result = asyncio.run(probe())
    assert tool_names == {"run_directive", "list_directives", "list_tools"}
    assert isinstance(directives, list)
    assert [item["id"] for item in directives] == ["tool_catalog"]
    assert isinstance(run_result, dict)
    _assert_sensitive_path_refusal(run_result)
    _assert_refusal_audit(workspace)
    assert len(stub_backend.received) == 2
    assert not (install.hostile_cwd / _AUDIT_FILENAME).exists()


def test_missing_installed_policy_fails_without_source_fallback(
    installed_distribution: InstalledDistribution,
    tmp_path: Path,
    repo_root: Path,
    stub_backend,
) -> None:
    install = installed_distribution
    installed_policy = install.authority_root / "policies" / "default.yaml"
    assert installed_policy.is_file()
    assert (repo_root / "auro_runtime" / "resources" / "policies" / "default.yaml").is_file()
    assert (
        install.built.source_copy
        / "auro_runtime"
        / "resources"
        / "policies"
        / "default.yaml"
    ).is_file()
    installed_policy.unlink()

    workspace = _prepare_workspace(tmp_path, "missing-policy-workspace")
    stub_backend.set_script([{"done": True, "summary": "must not be reached"}])
    proc = install.run_isolated(
        _LIBRARY_PROBE,
        workspace=workspace,
        extra_env=stub_backend.env(),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = _last_json_line(proc.stdout)
    _assert_installed_provenance(payload, install, workspace)
    result = payload["result"]
    assert result["success"] is False
    assert result["meta"]["event"] == "incomplete_policy_profile"
    assert "Missing bindings=['default']" in result["error"]
    assert stub_backend.received == []
    assert any(
        event.get("event") == "incomplete_policy_profile"
        for event in _read_audit(workspace)
    )


def test_missing_installed_directive_fails_without_source_fallback(
    installed_distribution: InstalledDistribution,
    tmp_path: Path,
    repo_root: Path,
    stub_backend,
) -> None:
    install = installed_distribution
    installed_directive = install.authority_root / "directives" / "tool_catalog.md"
    assert installed_directive.is_file()
    assert (
        repo_root
        / "auro_runtime"
        / "resources"
        / "directives"
        / "tool_catalog.md"
    ).is_file()
    assert (
        install.built.source_copy
        / "auro_runtime"
        / "resources"
        / "directives"
        / "tool_catalog.md"
    ).is_file()
    installed_directive.unlink()

    workspace = _prepare_workspace(tmp_path, "missing-directive-workspace")
    stub_backend.set_script([{"done": True, "summary": "must not be reached"}])
    proc = install.run_isolated(
        _LIBRARY_PROBE,
        workspace=workspace,
        extra_env=stub_backend.env(),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = _last_json_line(proc.stdout)
    _assert_installed_provenance(payload, install, workspace)
    result = payload["result"]
    assert result["success"] is False
    assert result["meta"]["event"] == "directive_load_failed"
    assert "Directive not found: tool_catalog" in result["error"]
    assert stub_backend.received == []
    assert any(
        event.get("event") == "directive_load_failed"
        for event in _read_audit(workspace)
    )


def test_nonisolated_source_contamination_trips_provenance_check(
    installed_distribution: InstalledDistribution,
    tmp_path: Path,
) -> None:
    """Negative control: the same check rejects a child contaminated by PYTHONPATH."""
    install = installed_distribution
    workspace = _prepare_workspace(tmp_path, "contaminated-workspace")
    env = install.clean_env(workspace)
    env["PYTHONPATH"] = str(install.built.source_root)
    proc = subprocess.run(
        [str(install.python), "-B", "-c", _PROVENANCE_PROBE],
        # Use a neutral cwd so this negative control isolates PYTHONPATH
        # contamination specifically; the main probes use the hostile cwd.
        cwd=workspace,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = _last_json_line(proc.stdout)
    assert _is_under(
        Path(payload["auro_runtime_file"]),
        install.built.source_root,
    ), payload
    with pytest.raises(AssertionError, match="outside the installed venv"):
        _assert_installed_provenance(payload, install, workspace)


# The README states, at the head of its usage section: "Installing puts an
# `auro-runtime` command on your path. Every `python -m auro_runtime ...`
# example below works as `auro-runtime ...` on an installed copy."
#
# That is a claim quantified over every CLI example in the document, and until
# 2026-08-28 nothing executed the console script at all -- the whole suite drove
# `python -m`. These two cases put a runner behind the claim.
_README_INVOCATIONS = [
    pytest.param(["--help"], id="help"),
    pytest.param(
        ["run", "--directive", "tool_catalog", "list the available tools"],
        id="run-tool-catalog",
    ),
    pytest.param(
        ["mcp", "--transport", "streamable-http", "--host", "127.0.0.1", "--port", "8971"],
        id="mcp-streamable-http",
    ),
]


@pytest.mark.parametrize("argv", _README_INVOCATIONS)
def test_the_console_script_dispatches_exactly_like_the_module_cli(
    installed_distribution: InstalledDistribution,
    tmp_path: Path,
    argv: list[str],
) -> None:
    """The README's `auro-runtime ...` promise, run rather than read.

    Law 4 -- a claim is not a result.  The README's promise is a claim, and it
    stood unexecuted from the day the entry point was declared: the whole suite
    drove `python -m` and nothing invoked the generated script, so "the console
    script works" was an inference from `entry_points.txt` being present.

    Law 16f -- a document that shows a result is a test that has not been run.
    This is the runner that law asks for, attached to the one README sentence
    that quantifies over every CLI example in the document.

    Parity is the assertion, not success: several of these invocations are
    expected to fail, and they must fail *identically* whichever way they were
    started.  A console script that dispatched somewhere else would show up here
    as a differing exit code even though both commands "ran".

    The non-vacuity anchor is the existence check below rather than the
    comparison (law 1): two commands that both failed to start at all would
    agree on everything and prove nothing, so the script must be shown to exist
    before its behaviour is compared to anything.
    """
    install = installed_distribution
    script = _console_script_in(install.root)
    assert script.exists(), (
        f"pip installed no console script at {script}; the README tells every "
        "adopter this command is on their path"
    )

    workspace = tmp_path / "ws"
    workspace.mkdir()
    # No model backend is configured, so the `run` case fails at the backend --
    # which is fine and is itself part of the parity being asserted.
    env = install.clean_env(workspace)

    def invoke(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            # A neutral cwd, deliberately not the hostile one the provenance
            # probes use. The two invocations are genuinely asymmetric about the
            # working directory: `python -m` puts cwd on sys.path and the
            # generated console script does not, so running this from the
            # hostile cwd compares a booby-trapped import against a clean one
            # and reports a dispatch difference that is really a sys.path
            # difference. Cwd shadowing is a real property with its own tests
            # above; this one is about dispatch.
            cwd=workspace,
            env=env,
            text=True,
            capture_output=True,
            timeout=120,
        )

    as_module = invoke([str(install.python), "-B", "-m", "auro_runtime", *argv])
    as_script = invoke([str(script), *argv])

    assert as_module.returncode == as_script.returncode, (
        f"`python -m auro_runtime {' '.join(argv)}` exited "
        f"{as_module.returncode} but `auro-runtime {' '.join(argv)}` exited "
        f"{as_script.returncode}; the README promises they are interchangeable\n"
        f"module stderr:\n{as_module.stderr}\nscript stderr:\n{as_script.stderr}"
    )
    assert _normalise_prog(as_module.stdout) == _normalise_prog(as_script.stdout), (
        "the two invocations printed different stdout once the argparse program "
        "name is normalised"
    )
    assert _normalise_prog(as_module.stderr) == _normalise_prog(as_script.stderr), (
        "the two invocations printed different stderr once the argparse program "
        "name is normalised"
    )


# Each entry is (extra environment, argv tail, the substring the README promises).
# The README's remote-transport section states that AURO_MCP_API_KEY is mandatory
# on streamable-http and must be ASCII, and that binding a non-loopback host
# additionally requires --public-url. Those exits were verified against the
# source checkout on 2026-08-27; this pins them to the installed wheel, which is
# the artifact an adopter actually runs.
_DOCUMENTED_TRANSPORT_REFUSALS = [
    pytest.param({}, ["--host", "127.0.0.1", "--port", "8981"],
                 "AURO_MCP_API_KEY must be set", id="missing-key"),
    pytest.param({"AURO_MCP_API_KEY": "k\u00e9y-with-accent"},
                 ["--host", "127.0.0.1", "--port", "8982"],
                 "must be ASCII", id="non-ascii-key"),
    pytest.param({"AURO_MCP_API_KEY": "ascii-key-123"},
                 ["--host", "0.0.0.0", "--port", "8983"],
                 "--public-url is required", id="non-loopback-without-public-url"),
]


@pytest.mark.parametrize("extra_env,argv_tail,expected", _DOCUMENTED_TRANSPORT_REFUSALS)
def test_the_installed_artifact_refuses_every_documented_unsafe_transport(
    installed_distribution: InstalledDistribution,
    tmp_path: Path,
    extra_env: dict[str, str],
    argv_tail: list[str],
    expected: str,
) -> None:
    """Three documented refusals, against each artifact rather than the checkout.

    These exits were verified against the source checkout on 2026-08-27.  Law 4
    again: that established the claim for a tree, not for the artifact an
    adopter installs, and those are different objects -- the whole reason this
    module exists.

    Law 3 -- fail closed by default.  Each case is a configuration the runtime
    must refuse to start rather than serve, and the refusal is the safe
    direction: an unauthenticated listener is the failure being prevented.

    Law 7b -- enumerate the input shapes, not only the call sites.  One call
    site, three shapes: key absent, key present but unusable, and host/flag
    combination unsafe.  Testing the transport once would have covered the call
    site and none of the shapes.

    Non-vacuity is structural here (law 1): every one of these configurations
    would otherwise start a listening server and block until the timeout, so a
    guard that stopped refusing fails this test by hanging rather than by
    passing quietly.

    Known bound, recorded rather than left implicit -- law 1c asks for both
    directions and this file automates only the refusals.  The permit direction
    was verified by hand on 2026-08-28 and deliberately not automated: an ASCII
    key on a loopback host starts a listener and blocks, which is the correct
    behaviour and is also why it is a poor fit for this matrix -- asserting it
    means binding a port and tearing down a live server on every run.

    That hand check is what makes the non-vacuity argument above concrete
    rather than assumed.  Permitting means blocking on a listener, so a guard
    that stopped refusing would block too, and these cases would fail on the
    timeout rather than pass quietly.  The claim was checked before being
    relied on -- law 4, and law 16f, which is the law this file was extended to
    serve.
    """
    install = installed_distribution
    workspace = tmp_path / "ws"
    workspace.mkdir()

    proc = subprocess.run(
        [
            str(_console_script_in(install.root)),
            "mcp", "--transport", "streamable-http", *argv_tail,
        ],
        cwd=install.hostile_cwd,
        env=install.clean_env(workspace, extra_env),
        text=True,
        capture_output=True,
        timeout=120,
    )

    assert proc.returncode != 0, (
        "the installed runtime started a streamable-http listener for a "
        f"configuration the README says it refuses: {argv_tail} {extra_env}"
    )
    combined = proc.stdout + proc.stderr
    assert expected in combined, (
        f"expected the documented refusal {expected!r}, got:\n{combined}"
    )
