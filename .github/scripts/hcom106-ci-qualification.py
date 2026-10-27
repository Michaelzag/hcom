"""Scratch-only GitHub-hosted Linux qualification for hcom issue 106.

Use case: checked-out SHA + diagnostic/owner20/ancestor50 -> retained raw logs,
counts and native execution evidence; never retry a failed sample, touch a real
HOME, widen a test budget, or signal a process without owned-child identity.
Only the three requested campaigns vary. No third-party Python dependencies.

ancestor50 uses the approved pinned-executable fallback: Cargo prebuilds ALL
--all-targets test harnesses, then each unit/integration harness runs once,
unfiltered, with its default concurrency. Cargo's compile-only artifact slots
are never offered as evidence of runtime load. Cfg-empty/all-ignored targets
still execute and remain explicitly distinct from functional coverage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO, cast


QUIET_TEST = "buzz::serve::tests::a_healthy_but_quiet_session_never_trips_the_watchdog"
ANCESTOR_TEST = "sys::kill_tree_linux::tests::an_ancestor_carrying_the_id_is_never_signaled"
RUST_TOOLCHAIN = "+1.97.1"
OUTPUT_LOCK = threading.Lock()
SUMMARY_RE = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; "
    r"(\d+) ignored; (\d+) measured; (\d+) filtered out; finished in .+$",
    re.MULTILINE,
)
LIST_SUMMARY_RE = re.compile(r"^(\d+) tests?, (\d+) benchmarks?$", re.MULTILINE)


class QualificationError(RuntimeError):
    """The observed run does not satisfy this qualification's contract."""


class Mode(StrEnum):
    DIAGNOSTIC = "diagnostic"
    OWNER = "owner20"
    ANCESTOR = "ancestor50"


@dataclass(frozen=True, slots=True)
class Summary:
    outcome: str
    passed: int
    failed: int
    ignored: int
    measured: int
    filtered: int


@dataclass(frozen=True, slots=True)
class TestListing:
    tests: frozenset[str]
    benchmarks: frozenset[str]


@dataclass(frozen=True, slots=True)
class Executable:
    name: str
    kind: tuple[str, ...]
    path: Path
    fd: int
    device: int
    inode: int
    sha256: str

    def record(self) -> dict[str, object]:
        return {
            "name": self.name, "kind": self.kind, "path": str(self.path),
            "device": self.device, "inode": self.inode, "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class Harness:
    executable: Executable
    all_tests: TestListing
    ignored: TestListing

    @property
    def runnable(self) -> int:
        return len(self.all_tests.tests - self.ignored.tests)


@dataclass(frozen=True, slots=True)
class Run:
    label: str
    command: tuple[str, ...]
    raw_path: Path
    invocation: Path
    started: str
    finished: str
    started_monotonic_ns: int
    finished_monotonic_ns: int
    exit_code: int
    execution: dict[str, object]

    def record(self) -> dict[str, object]:
        return {
            "label": self.label, "command": self.command,
            "raw_path": str(self.raw_path), "invocation": str(self.invocation),
            "started": self.started, "finished": self.finished,
            "started_monotonic_ns": self.started_monotonic_ns,
            "finished_monotonic_ns": self.finished_monotonic_ns,
            "exit_code": self.exit_code, "execution": self.execution,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def object_value(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise QualificationError("Expected a JSON object with string keys")
    return cast(dict[str, object], value)


def array_value(value: object) -> list[object]:
    if not isinstance(value, list):
        raise QualificationError("Expected a JSON array")
    return cast(list[object], value)


def string_value(value: object) -> str:
    if not isinstance(value, str):
        raise QualificationError("Expected a JSON string")
    return value


def parse_summary(text: str) -> Summary:
    matches = list(SUMMARY_RE.finditer(text))
    if len(matches) != 1 or len(re.findall(r"^test result:", text, re.MULTILINE)) != 1:
        raise QualificationError(f"Expected one libtest summary, observed {len(matches)}")
    match = matches[0]
    return Summary(match[1], *(int(match[index]) for index in range(2, 7)))


def require_passing(summary: Summary, *, exact: int | None = None) -> None:
    if summary.outcome != "ok" or summary.failed != 0 or summary.measured != 0:
        raise QualificationError(f"Not a passing test summary: {summary}")
    if summary.passed <= 0 or (exact is not None and summary.passed != exact):
        raise QualificationError(f"Unexpected passing test count: {summary.passed}, exact={exact}")


def parse_listing(text: str) -> TestListing:
    matches = list(LIST_SUMMARY_RE.finditer(text))
    if len(matches) != 1:
        raise QualificationError("Missing or ambiguous libtest listing summary")
    tests: set[str] = set()
    benchmarks: set[str] = set()
    for line in text.splitlines():
        for suffix, names in ((": test", tests), (": benchmark", benchmarks)):
            if line.endswith(suffix):
                name = line.removesuffix(suffix)
                if not name or name in names:
                    raise QualificationError("Empty or duplicate test name in listing")
                names.add(name)
    if (len(tests), len(benchmarks)) != tuple(int(group) for group in matches[0].groups()):
        raise QualificationError("Listing names disagree with the listing's own counts")
    return TestListing(frozenset(tests), frozenset(benchmarks))


def harness_coverage(harness: Harness, summary: Summary) -> str:
    if not harness.ignored.tests <= harness.all_tests.tests:
        raise QualificationError("Ignored listing is not a subset of the full listing")
    if harness.all_tests.benchmarks or harness.ignored.benchmarks:
        raise QualificationError("Unexpected benchmark harness; refusing to omit a target")
    if (
        summary.outcome != "ok" or summary.failed != 0 or summary.filtered != 0
        or summary.measured != 0 or summary.passed != harness.runnable
        or summary.ignored != len(harness.ignored.tests)
    ):
        raise QualificationError("Full target summary disagrees with its unfiltered listing")
    if not harness.all_tests.tests:
        return "cfg-empty; no functional coverage"
    if harness.runnable == 0:
        return "all-ignored; no functional coverage"
    return "functional"


def proc_identity(pid: int) -> dict[str, object]:
    # The closing parenthesis, not whitespace in comm, delimits Linux stat fields.
    text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    fields = text[text.rindex(")") + 2:].split()
    if len(fields) < 20:
        raise QualificationError("Incomplete owned-child /proc stat")
    return {
        "pid": pid, "state": fields[0], "parent_pid": int(fields[1]),
        "pgrp": int(fields[2]), "session": int(fields[3]),
        "birth_ticks": int(fields[19]),
    }


def pin_executable(path: Path, name: str, kind: tuple[str, ...], stack: ExitStack) -> Executable:
    path = path.resolve(strict=True)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    stack.callback(os.close, fd)
    stat = os.fstat(fd)
    with os.fdopen(os.dup(fd), "rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    return Executable(name, kind, path, fd, stat.st_dev, stat.st_ino, digest)


class Evidence:
    """Retain independent command records even if a later command fails."""

    def __init__(self, root: Path) -> None:
        root.mkdir(parents=True, exist_ok=False)
        (root / "raw").mkdir()
        (root / "invocations").mkdir()
        self.root = root
        self.lock = threading.Lock()
        self.completed: list[dict[str, object]] = []
        self.samples: list[dict[str, object]] = []
        self.context: dict[str, object] = {}

    def write_json(self, name: str, value: object) -> None:
        temporary = self.root / f".{name}.tmp"
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(self.root / name)

    def event(self, event: str, **fields: object) -> None:
        row = {"event": event, "timestamp": utc_now(), "monotonic_ns": time.monotonic_ns(), **fields}
        with self.lock, (self.root / "events.jsonl").open("a", encoding="utf-8") as target:
            target.write(json.dumps(row, sort_keys=True) + "\n")

    def complete(self, row: dict[str, object]) -> None:
        with self.lock:
            self.completed.append(row)
            self.write_json("commands.json", self.completed)

    def sample(self, row: dict[str, object]) -> None:
        with self.lock:
            self.samples.append(row)
            self.write_json("samples.json", self.samples)

    def outcome(self, mode: Mode, status: str, reason: str | None = None) -> None:
        self.write_json("result.json", {
            "status": status, "mode": mode, "reason": reason,
            "checked_out_sha": self.context.get("checked_out_sha"),
            "requested_samples": {Mode.DIAGNOSTIC: 21, Mode.OWNER: 20, Mode.ANCESTOR: 50}[mode],
            "attempted_samples": len(self.samples),
            "passed_samples": sum(row["status"] == "PASS" for row in self.samples),
            "failed_samples": sum(row["status"] == "FAIL" for row in self.samples),
            "commands_completed": len(self.completed), "finished": utc_now(),
        })


@dataclass(frozen=True, slots=True)
class Context:
    mode: Mode
    repo: Path
    cargo: str
    git: str
    targets: Path
    base_env: Mapping[str, str]
    evidence: Evidence

    def environment(self, label: str) -> tuple[dict[str, str], Path]:
        invocation = Path(tempfile.mkdtemp(prefix=f"{label}-", dir=self.evidence.root / "invocations"))
        folders = {
            "HOME": "home", "HCOM_DIR": "hcom", "TMPDIR": "tmp", "TMP": "tmp",
            "TEMP": "tmp", "XDG_CONFIG_HOME": "xdg/config", "XDG_CACHE_HOME": "xdg/cache",
            "XDG_DATA_HOME": "xdg/data", "XDG_STATE_HOME": "xdg/state",
            "XDG_RUNTIME_DIR": "xdg/runtime", "CODEX_HOME": "codex",
            "CLAUDE_CONFIG_DIR": "claude", "BUN_INSTALL": "bun",
        }
        env = dict(self.base_env)
        for key, suffix in folders.items():
            folder = invocation / suffix
            folder.mkdir(parents=True, exist_ok=True, mode=0o700)
            env[key] = str(folder)
        # Relay fields are file-only on load. HCOM_RELAY is a URL, NOT a boolean.
        (invocation / "hcom" / "config.toml").write_text("[relay]\nenabled = false\n", encoding="utf-8")
        return env, invocation

    def cargo_command(self, *args: str, target: str) -> tuple[str, ...]:
        return (self.cargo, RUST_TOOLCHAIN, "test", "--locked", "--target-dir",
                str(self.targets / target), *args)


class OwnedChild:
    """Own one unreaped child, its pidfd, fresh group and raw output lifecycle."""

    def __init__(
        self, context: Context, label: str, command: tuple[str, ...],
        executable: Executable | None = None,
    ) -> None:
        self.context = context
        self.label = label
        self.command = command
        self.env, self.invocation = context.environment(label)
        self.raw_path = context.evidence.root / "raw" / f"{label}.log"
        self.started = utc_now()
        self.started_ns = time.monotonic_ns()
        self.lock = threading.RLock()
        self.pump_error: OSError | None = None
        self.executable = executable
        self.pidfd: int | None = None
        self.reaped = False
        self.finished_run: Run | None = None
        self.execution: dict[str, object] = {}
        self.raw: BinaryIO = self.raw_path.open("xb")
        try:
            self.child = subprocess.Popen(
                command, cwd=context.repo, env=self.env, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, start_new_session=True,
                executable=f"/proc/self/fd/{executable.fd}" if executable else None,
                pass_fds=(executable.fd,) if executable else (),
            )
        except OSError:
            self.raw.close()
            raise
        # Popen's exec-error handshake has completed. Never call poll(): it reaps.
        self.birth = proc_identity(self.child.pid)
        if self.birth["parent_pid"] != os.getpid() or self.birth["pgrp"] != self.child.pid or self.birth["session"] != self.child.pid:
            raise QualificationError("Popen did not create the expected directly owned fresh session")
        self.pidfd = os.pidfd_open(self.child.pid)
        self.pump = threading.Thread(target=self._stream, name=f"raw-{label}")
        self.pump.start()
        self.execution = {
            "birth": self.birth, "exec_handshake_completed": utc_now(),
            "pinned_executable": executable.record() if executable else None,
        }

    def _stream(self) -> None:
        pipe = self.child.stdout
        if pipe is None:
            self.pump_error = OSError("Missing owned child's stdout pipe")
            self.raw.close()
            return
        try:
            with pipe, self.raw:
                while chunk := os.read(pipe.fileno(), 65536):
                    self.raw.write(chunk)
                    self.raw.flush()
                    with OUTPUT_LOCK:
                        sys.stdout.buffer.write(chunk)
                        sys.stdout.buffer.flush()
        except OSError as error:
            self.pump_error = error

    def _owned_identity(self) -> tuple[dict[str, object], bool] | None:
        if self.reaped or self.child.returncode is not None:
            return None
        exited = os.waitid(os.P_PID, self.child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        identity = proc_identity(self.child.pid)
        if identity["birth_ticks"] != self.birth["birth_ticks"] or identity["parent_pid"] != os.getpid():
            raise QualificationError("Owned unreaped child identity changed")
        return identity, exited is not None

    def execution_proof(self) -> dict[str, object] | None:
        with self.lock:
            owned = self._owned_identity()
            if owned is None or owned[1]:
                return None
            identity = owned[0]
            executable = self.executable
            if executable is None:
                raise QualificationError("Only a pinned test executable can prove actual suite load")
            try:
                native = os.stat(f"/proc/{self.child.pid}/exe")
            except FileNotFoundError:
                # A child can exit between WNOWAIT and exe lookup. This is not
                # live execution evidence, and it must not turn into a PID search.
                exited = os.waitid(os.P_PID, self.child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if exited is not None:
                    return None
                raise
            if (native.st_dev, native.st_ino) != (executable.device, executable.inode):
                raise QualificationError("Native child executable does not match the pinned Cargo artifact")
            proof = {
                **identity, "timestamp": utc_now(), "monotonic_ns": time.monotonic_ns(),
                "executable": executable.record(), "proof": "direct-Popen+WNOWAIT+proc-exe+pidfd",
            }
            self.execution = proof
            return proof

    def cancel(self) -> None:
        # The owner lock excludes finish/reap; a live or zombie owned leader pins
        # its PID until this immediate group check and signal. Never kill a PID
        # copied from a report, and never fall back from a failed identity check.
        with self.lock:
            owned = self._owned_identity()
            if owned is None:
                return
            identity = owned[0]
            if identity["pgrp"] != self.child.pid or identity["session"] != self.child.pid or os.getpgid(self.child.pid) != self.child.pid:
                raise QualificationError("Refusing cleanup: fresh owned group proof changed")
            try:
                os.killpg(self.child.pid, signal.SIGKILL)
            except ProcessLookupError:
                # A leader exit can empty its group. No numeric-PID fallback.
                pass
            self.context.evidence.event("owned-group-cleanup", label=self.label, identity=identity, signal="SIGKILL")

    def finish(self) -> Run:
        if self.pidfd is None:
            raise QualificationError("Missing owned-child pidfd")
        select.select([self.pidfd], [], [])
        with self.lock:
            if self.finished_run is not None:
                return self.finished_run
            # Keep the exited leader unreaped while cleaning only its proven
            # fresh group, so inherited output pipes cannot outlive this run.
            self.cancel()
            exit_code = self.child.wait()
            self.reaped = True
            os.close(self.pidfd)
            self.pidfd = None
        self.pump.join()
        run = Run(
            self.label, self.command, self.raw_path, self.invocation, self.started,
            utc_now(), self.started_ns, time.monotonic_ns(), exit_code, self.execution,
        )
        self.finished_run = run
        self.context.evidence.complete(run.record())
        if self.pump_error is not None:
            raise QualificationError(f"Raw log streaming failed for {self.label}") from self.pump_error
        return run


def run_command(
    context: Context, label: str, command: tuple[str, ...],
    executable: Executable | None = None,
    on_exec: Callable[[OwnedChild], None] | None = None,
) -> Run:
    child = OwnedChild(context, label, command, executable)
    try:
        context.evidence.event(
            "command-start", label=label, command=command, raw_path=str(child.raw_path),
            invocation=str(child.invocation), birth=child.birth,
        )
        if executable is not None:
            child.execution_proof()
        if on_exec is not None:
            on_exec(child)
        return child.finish()
    finally:
        if not child.reaped:
            child.cancel()
            child.finish()


def require_exit(run: Run) -> None:
    if run.exit_code != 0:
        raise QualificationError(f"{run.label} exited {run.exit_code}; raw log: {run.raw_path}")


def checked_test(
    context: Context, run: Run, *, iteration: int, exact: int | None = None,
    expected_filtered: int | None = None,
) -> Summary:
    row: dict[str, object] = {**run.record(), "iteration": iteration, "status": "FAIL", "summary": None}
    try:
        summary = parse_summary(run.raw_path.read_text(encoding="utf-8", errors="replace"))
        row["summary"] = asdict(summary)
        require_exit(run)
        require_passing(summary, exact=exact)
        if expected_filtered is not None and summary.filtered != expected_filtered:
            raise QualificationError("Unexpected filtered tests in a full-target campaign")
        row["status"] = "PASS"
    except QualificationError as error:
        row["reason"] = str(error)
        raise
    finally:
        context.evidence.sample(row)
    return summary


def repeat_campaign(context: Context) -> None:
    if context.mode == Mode.DIAGNOSTIC:
        command = context.cargo_command(
            "--bin", "hcom", QUIET_TEST, "--", "--exact", "--nocapture", "--test-threads=1", target="diagnostic",
        )
        count, exact = 21, 1  # First diagnostic; only a pass permits 20 further samples.
    else:
        command = context.cargo_command(
            "--test", "kill_owner", "--", "--nocapture", "--test-threads=1", target="owner20",
        )
        count, exact = 20, None
    for iteration in range(1, count + 1):
        context.evidence.event("iteration-start", iteration=iteration, requested=count)
        run = run_command(context, f"{context.mode}-{iteration:02d}", command)
        summary = checked_test(
            context, run, iteration=iteration, exact=exact,
            expected_filtered=0 if context.mode == Mode.OWNER else None,
        )
        context.evidence.event("iteration-pass", iteration=iteration, summary=asdict(summary), raw_path=str(run.raw_path))


def json_lines(run: Run) -> list[dict[str, object]]:
    require_exit(run)
    rows = []
    for line in run.raw_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("{"):
            rows.append(object_value(json.loads(line)))
    if not rows:
        raise QualificationError(f"No JSON records in {run.label}")
    return rows


def cargo_artifacts(run: Run, target: Path, stack: ExitStack) -> tuple[Executable, ...]:
    executables: list[Executable] = []
    identities: set[tuple[str, tuple[str, ...]]] = set()
    finished = 0
    for row in json_lines(run):
        if row.get("reason") == "build-finished":
            finished += 1
            if row.get("success") is not True:
                raise QualificationError("Cargo JSON reports an unsuccessful build")
        if row.get("reason") != "compiler-artifact":
            continue
        profile = object_value(row.get("profile"))
        if profile.get("test") is not True or row.get("executable") is None:
            continue
        description = object_value(row.get("target"))
        name = string_value(description.get("name"))
        kind = tuple(string_value(value) for value in array_value(description.get("kind")))
        if not set(kind) <= {"bin", "test", "lib"}:
            raise QualificationError(f"Unexpected executable target kind {kind}; refusing omissions")
        identity = (name, kind)
        if identity in identities:
            raise QualificationError(f"Duplicate test-profile artifact for {identity}")
        identities.add(identity)
        path = Path(string_value(row.get("executable"))).resolve(strict=True)
        if not path.is_relative_to(target.resolve()):
            raise QualificationError("Cargo executable escaped its dedicated target directory")
        executables.append(pin_executable(path, name, kind, stack))
    if finished != 1 or not executables:
        raise QualificationError("Missing successful build-finished record or no test executables")
    return tuple(sorted(executables, key=lambda item: (item.kind != ("bin",), item.name, item.kind)))


def metadata_targets(context: Context) -> set[tuple[str, tuple[str, ...]]]:
    run = run_command(
        context, "metadata", (context.cargo, RUST_TOOLCHAIN, "metadata", "--locked", "--format-version=1", "--no-deps"),
    )
    rows = json_lines(run)
    if len(rows) != 1:
        raise QualificationError("Expected one Cargo metadata object")
    packages = [object_value(value) for value in array_value(rows[0].get("packages"))]
    package = [item for item in packages if Path(string_value(item.get("manifest_path"))).resolve() == context.repo / "Cargo.toml"]
    if len(package) != 1:
        raise QualificationError("Cargo metadata does not identify exactly one checked-out hcom package")
    expected: set[tuple[str, tuple[str, ...]]] = set()
    for value in array_value(package[0].get("targets")):
        target = object_value(value)
        kind = tuple(string_value(item) for item in array_value(target.get("kind")))
        if set(kind) & {"example", "bench"}:
            raise QualificationError("New example/bench target requires a Cargo-equivalent execution policy")
        if target.get("test") is True:
            expected.add((string_value(target.get("name")), kind))
    if not expected:
        raise QualificationError("Cargo metadata contains no enabled test targets")
    return expected


def list_harness(context: Context, executable: Executable, index: int) -> Harness:
    listings: list[TestListing] = []
    for label, args in (("all", ("--list",)), ("ignored", ("--list", "--ignored"))):
        run = run_command(context, f"list-{index:02d}-{label}", (str(executable.path), *args), executable)
        require_exit(run)
        listings.append(parse_listing(run.raw_path.read_text(encoding="utf-8")))
    harness = Harness(executable, listings[0], listings[1])
    if not harness.ignored.tests <= harness.all_tests.tests:
        raise QualificationError("Ignored test names are absent from the full test listing")
    context.evidence.event(
        "target-listing", executable=executable.record(), tests=sorted(harness.all_tests.tests),
        ignored=sorted(harness.ignored.tests), benchmarks=sorted(harness.all_tests.benchmarks), runnable=harness.runnable,
    )
    return harness


class FullSuite:
    """Run every pinned Cargo harness once; expose only a directly owned child."""

    def __init__(self, context: Context, harnesses: tuple[Harness, ...]) -> None:
        self.context = context
        self.harnesses = harnesses
        self.functional_files = frozenset(
            (harness.executable.device, harness.executable.inode)
            for harness in harnesses if harness.runnable > 0
        )
        self.lock = threading.Lock()
        self.ready = threading.Event()
        self.stop_requested = threading.Event()
        self.active: OwnedChild | None = None
        self.failure: BaseException | None = None
        self.targets: list[dict[str, object]] = [
            {"target": harness.executable.record(), "status": "NOT RUN", "coverage": "not executed"}
            for harness in harnesses
        ]
        context.evidence.write_json("suite-targets.json", self.targets)
        self.thread = threading.Thread(target=self._run, name="full-unfiltered-suite")

    def _publish(self, child: OwnedChild) -> None:
        with self.lock:
            self.active = child
        if self.stop_requested.is_set():
            child.cancel()
            return
        proof = child.execution_proof()
        if proof is not None:
            self.context.evidence.event("suite-test-exec", label=child.label, execution=proof)
            executable = child.executable
            if executable is not None and (executable.device, executable.inode) in self.functional_files:
                self.ready.set()

    def _run(self) -> None:
        try:
            for index, harness in enumerate(self.harnesses, 1):
                if self.stop_requested.is_set():
                    raise QualificationError("Suite cancelled after first campaign failure")
                executable = harness.executable
                label = f"suite-{index:02d}-{executable.name}"
                row = self.targets[index - 1]
                row.update({"label": label, "command": [str(executable.path)], "status": "FAIL"})
                try:
                    run = run_command(self.context, label, (str(executable.path),), executable, self._publish)
                    row.update(run.record())
                    summary = parse_summary(run.raw_path.read_text(encoding="utf-8", errors="replace"))
                    row["summary"] = asdict(summary)
                    require_exit(run)
                    row["coverage"] = harness_coverage(harness, summary)
                    row["status"] = "PASS"
                except (QualificationError, OSError, ValueError) as error:
                    row["reason"] = str(error)
                    raise
                finally:
                    with self.lock:
                        self.active = None
                        self.context.evidence.write_json("suite-targets.json", self.targets)
                if self.stop_requested.is_set():
                    raise QualificationError("Suite cancelled after first campaign failure")
            passed = sum(cast(int, object_value(row["summary"])["passed"]) for row in self.targets)
            if passed <= 0 or any(row["status"] != "PASS" for row in self.targets):
                raise QualificationError("Full suite lacks nonzero functional coverage or omitted a target")
        except BaseException as error:
            # A worker exception must cross the thread boundary as failure,
            # including exceptions outside the expected command/parser errors.
            with self.lock:
                self.failure = error
            self.context.evidence.event(
                "suite-worker-failed", error_type=type(error).__name__, reason=str(error),
            )
        finally:
            with self.lock:
                self.active = None
            self.ready.set()

    def proof(self) -> dict[str, object]:
        with self.lock:
            if self.failure is not None:
                raise QualificationError("Full suite failed") from self.failure
            if self.active is None:
                raise QualificationError("No actual full-suite test executable is active")
            executable = self.active.executable
            if executable is None or (executable.device, executable.inode) not in self.functional_files:
                raise QualificationError("An empty/ignored harness is not functional suite load")
            proof = self.active.execution_proof()
        if proof is None:
            raise QualificationError("Full-suite test executable has already exited")
        return proof

    def require_healthy(self) -> None:
        with self.lock:
            if self.failure is not None:
                raise QualificationError("Full suite failed during ancestor qualification") from self.failure

    def cancel(self) -> None:
        self.stop_requested.set()
        with self.lock:
            child = self.active
        if child is not None:
            child.cancel()


def ancestor_campaign(context: Context, stack: ExitStack) -> None:
    expected = metadata_targets(context)
    suite_target = context.targets / "suite"
    suite_build = run_command(
        context, "prebuild-suite", context.cargo_command("--all-targets", "--no-run", "--message-format=json", target="suite"),
    )
    suite_executables = cargo_artifacts(suite_build, suite_target, stack)
    if {(item.name, item.kind) for item in suite_executables} != expected:
        raise QualificationError("Pinned executable set differs from ALL enabled Cargo unit/integration targets")
    ancestor_target = context.targets / "ancestor"
    ancestor_build = run_command(
        context, "prebuild-ancestor", context.cargo_command("--bin", "hcom", "--no-run", "--message-format=json", target="ancestor"),
    )
    ancestor_executables = cargo_artifacts(ancestor_build, ancestor_target, stack)
    units = [item for item in ancestor_executables if item.name == "hcom" and item.kind == ("bin",)]
    if len(ancestor_executables) != 1 or len(units) != 1:
        raise QualificationError("Separate ancestor target must pin exactly one hcom bin test-profile executable")
    context.evidence.write_json("pinned-executables.json", {
        "suite": [item.record() for item in suite_executables], "ancestor": units[0].record(),
        "suite_policy": "ALL Cargo-selected unit/integration harnesses; direct pinned exec; default concurrency; no filters or --ignored",
    })
    # BOTH builds are complete before even listing a harness, let alone runtime.
    harnesses = tuple(list_harness(context, item, index) for index, item in enumerate(suite_executables, 1))
    unit_harness = list_harness(context, units[0], len(harnesses) + 1)
    if ANCESTOR_TEST not in unit_harness.all_tests.tests - unit_harness.ignored.tests:
        raise QualificationError("Exact ancestor test is absent or ignored in the separate pinned unit binary")
    suite = FullSuite(context, harnesses)
    suite.thread.start()
    try:
        suite.ready.wait()
        proof = suite.proof()
        context.evidence.event("stress-start-after-real-test-exec", execution=proof)
        for iteration in range(1, 51):
            suite.require_healthy()
            run = run_command(
                context, f"ancestor-{iteration:02d}",
                (str(units[0].path), ANCESTOR_TEST, "--exact", "--nocapture", "--test-threads=1"), units[0],
            )
            summary = checked_test(context, run, iteration=iteration, exact=1)
            context.evidence.event("iteration-pass", iteration=iteration, requested=50, summary=asdict(summary), raw_path=str(run.raw_path))
            suite.require_healthy()
        # No sleep, padding, artificial load or re-launch: failure is final if
        # real suite test execution no longer overlaps the completion of all 50.
        context.evidence.event("all-50-finished-suite-still-executing", execution=suite.proof())
        suite.thread.join()
        suite.require_healthy()
        if any(row["status"] != "PASS" for row in suite.targets):
            raise QualificationError("Full suite did not record PASS for every target")
        context.evidence.event("all-targets-suite-pass", targets=len(suite.targets))
    finally:
        if suite.thread.is_alive():
            try:
                suite.cancel()
            finally:
                suite.thread.join()


def find_tool(name: str, path: str) -> str:
    found = shutil.which(name, path=path)
    if found is None:
        raise QualificationError(f"Workflow did not provision required tool: {name}")
    # Keep the shim's basename: resolving cargo's symlink to rustup changes its CLI.
    return os.path.abspath(found)


def configure(mode: Mode, inherited: Mapping[str, str]) -> Context:
    if inherited.get("GITHUB_ACTIONS") != "true" or inherited.get("RUNNER_ENVIRONMENT") != "github-hosted" or inherited.get("RUNNER_OS") != "Linux":
        raise QualificationError("Qualification is restricted to throwaway GitHub-hosted Linux runners")
    repo = Path(inherited["GITHUB_WORKSPACE"]).resolve(strict=True)
    runner_temp = Path(inherited["RUNNER_TEMP"]).resolve(strict=True)
    if not Path(inherited["GITHUB_WORKSPACE"]).is_absolute() or not Path(inherited["RUNNER_TEMP"]).is_absolute():
        raise QualificationError("GitHub workspace and runner temporary directory must be absolute")
    original_home = Path(inherited["HOME"])
    path = inherited["PATH"]
    tools = {name: find_tool(name, path) for name in ("cargo", "git", "node", "bun", "python3")}
    cargo_home = Path(inherited.get("CARGO_HOME", str(original_home / ".cargo"))).resolve(strict=True)
    rustup_home = Path(inherited.get("RUSTUP_HOME", str(original_home / ".rustup"))).resolve(strict=True)
    evidence = Evidence(runner_temp / "hcom106-qualification" / mode)
    targets = runner_temp / "hcom106-qualification-targets" / mode
    targets.mkdir(parents=True, exist_ok=False)
    # An allowlist also drops inherited HCOM_*, credentials, Cargo runners,
    # test filters/thread overrides, target dirs and operator tool configuration.
    base_env = {
        "PATH": path, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "dumb",
        "NO_COLOR": "1", "CI": "true", "GITHUB_ACTIONS": "true",
        "RUNNER_TEMP": str(runner_temp), "CARGO_HOME": str(cargo_home),
        "RUSTUP_HOME": str(rustup_home), "RUSTUP_TOOLCHAIN": RUST_TOOLCHAIN.removeprefix("+"),
        "CARGO_TERM_COLOR": "never", "RUST_BACKTRACE": "1",
    }
    evidence.context = {
        "mode": mode, "workspace": str(repo), "runner_temp": str(runner_temp),
        "target_root": str(targets),
        "github": {key: inherited.get(key) for key in (
            "GITHUB_SHA", "GITHUB_REF", "GITHUB_REPOSITORY", "GITHUB_RUN_ID",
            "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "RUNNER_OS", "RUNNER_ARCH", "RUNNER_ENVIRONMENT",
        )},
        "tools": tools, "rust_toolchain": RUST_TOOLCHAIN, "cargo_home": str(cargo_home),
        "rustup_home": str(rustup_home), "helper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "rust_diagnostics": str(runner_temp / "hcom106-watchdog-diagnostics"),
        "isolation": "fresh HOME/HCOM_DIR/TMPDIR/XDG per command; only HCOM_DIR added; private relay config disabled",
    }
    evidence.write_json("context.json", evidence.context)
    return Context(mode, repo, tools["cargo"], tools["git"], targets, base_env, evidence)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=[mode.value for mode in Mode])
    args = parser.parse_args()
    context: Context | None = None
    try:
        context = configure(Mode(args.mode), os.environ)
        sha_run = run_command(context, "checkout-sha", (context.git, "rev-parse", "--verify", "HEAD"))
        require_exit(sha_run)
        sha = sha_run.raw_path.read_text(encoding="ascii").strip()
        if re.fullmatch(r"[0-9a-f]{40}", sha) is None or sha != os.environ.get("GITHUB_SHA"):
            raise QualificationError("Actual checked-out commit differs from the GitHub event SHA")
        context.evidence.context["checked_out_sha"] = sha
        context.evidence.write_json("context.json", context.evidence.context)
        with ExitStack() as stack:
            if context.mode == Mode.ANCESTOR:
                ancestor_campaign(context, stack)
            else:
                repeat_campaign(context)
        context.evidence.outcome(context.mode, "PASS")
        return 0
    except (QualificationError, OSError, ValueError, KeyError, ChildProcessError) as error:
        if context is not None:
            context.evidence.event("qualification-failed", reason=str(error), error_type=type(error).__name__)
            context.evidence.outcome(context.mode, "FAIL", str(error))
        print(f"hcom106 qualification FAILED: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
