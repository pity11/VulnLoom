"""Fail-closed Docker CLI adapter for ephemeral, network-disabled Workers."""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from .environment import build_worker_environment
from .models import (
    CleanupReport,
    MountKind,
    NetworkMode,
    SandboxOutput,
    SandboxRunRequest,
    SandboxRunResult,
    SandboxRunStatus,
    SandboxUsage,
    invocation_digest,
    run_request_digest,
    sandbox_profile_digest,
)
from .output import RunnerOutputCaptureFailed, RunnerOutputStore
from .preflight import RunnerIdempotencyConflict, RunnerRejected, validate_run_request


class DockerBackendError(RuntimeError):
    """The trusted Docker control adapter failed."""


class DockerOutputLimitError(DockerBackendError):
    """Attached Worker output exceeded its trusted capture budget."""


class RunnerCleanupFailed(RuntimeError):
    """A container could not be proven absent after a terminal run."""


@dataclass(frozen=True)
class DockerEnginePolicy:
    """Host requirements. Production keeps ``require_rootless`` enabled."""

    require_rootless: bool = True
    require_seccomp: bool = True
    require_cgroup_v2: bool = True
    require_resource_controls: bool = True


@dataclass(frozen=True)
class DockerTool:
    """A trusted in-image executable prefix; untrusted arguments are appended verbatim."""

    tool_id: str
    argv_prefix: tuple[str, ...]
    successful_exit_codes: frozenset[int] = frozenset({0})

    def __post_init__(self) -> None:
        if not self.argv_prefix or not self.argv_prefix[0].startswith("/"):
            raise ValueError("Docker tool entrypoint must be an absolute in-image path")
        if any(not item or "\x00" in item for item in self.argv_prefix):
            raise ValueError("Docker tool entrypoint contains an empty or invalid argument")
        if (
            not self.successful_exit_codes
            or any(code < 0 or code > 255 for code in self.successful_exit_codes)
        ):
            raise ValueError("Docker tool successful exit codes must be bounded")


class DockerBackend(Protocol):
    def engine_info(self) -> Mapping[str, Any]: ...

    def inspect_image(self, image: str) -> Mapping[str, Any]: ...

    def create(self, arguments: Sequence[str]) -> str: ...

    def inspect_container(self, container: str) -> Mapping[str, Any]: ...

    def start(self, container: str, timeout: float) -> int: ...

    def start_capture(
        self,
        container: str,
        timeout: float,
        destination: Path,
        max_bytes: int,
    ) -> int: ...

    def kill(self, container: str) -> None: ...

    def remove(self, container: str) -> None: ...

    def exists(self, container: str) -> bool: ...


class DockerCliBackend:
    """Docker CLI transport using argument arrays and a minimal trusted environment."""

    def __init__(self, *, executable: str = "docker", environment: Mapping[str, str] | None = None):
        resolved = shutil.which(executable)
        if resolved is None:
            raise DockerBackendError("Docker CLI is not installed")
        self.executable = resolved
        self.environment = dict(environment or _docker_control_environment())

    def engine_info(self) -> Mapping[str, Any]:
        return self._json(("info", "--format", "{{json .}}"))

    def inspect_image(self, image: str) -> Mapping[str, Any]:
        values = self._json(("image", "inspect", image))
        if not isinstance(values, list) or len(values) != 1:
            raise DockerBackendError("Docker returned an invalid image inspection")
        return values[0]

    def create(self, arguments: Sequence[str]) -> str:
        result = self._run(("create", *arguments))
        container_id = result.stdout.strip()
        if not container_id:
            raise DockerBackendError("Docker create returned no container id")
        return container_id

    def inspect_container(self, container: str) -> Mapping[str, Any]:
        values = self._json(("inspect", container))
        if not isinstance(values, list) or len(values) != 1:
            raise DockerBackendError("Docker returned an invalid container inspection")
        return values[0]

    def network_gateway_ips(self) -> frozenset[str]:
        """Return every daemon-managed network gateway for Broker denylisting."""
        networks = self._run(("network", "ls", "--quiet", "--no-trunc")).stdout.split()
        if not networks:
            raise DockerBackendError("Docker returned no networks to inspect")
        values = self._json(("network", "inspect", *networks))
        if not isinstance(values, list):
            raise DockerBackendError("Docker returned an invalid network inspection")
        gateways = _network_gateway_ips(values)
        if not gateways:
            raise DockerBackendError("Docker reported no network gateway addresses")
        return gateways

    def start(self, container: str, timeout: float) -> int:
        try:
            result = subprocess.run(
                (self.executable, "start", "--attach", container),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
                timeout=timeout,
                env=self.environment,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("Docker Worker exceeded its wall-clock limit") from exc
        return result.returncode

    def kill(self, container: str) -> None:
        self._run(("kill", container), check=False)

    def start_capture(
        self,
        container: str,
        timeout: float,
        destination: Path,
        max_bytes: int,
    ) -> int:
        if destination.exists() or max_bytes <= 0:
            raise DockerBackendError("Docker output capture target is invalid")
        process = subprocess.Popen(
            (self.executable, "start", "--attach", container),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=self.environment,
        )
        exceeded = threading.Event()
        reader_error: list[BaseException] = []

        def copy_bounded() -> None:
            assert process.stdout is not None
            total = 0
            try:
                with destination.open("xb") as output:
                    while chunk := process.stdout.read(64 * 1024):
                        if total + len(chunk) > max_bytes:
                            exceeded.set()
                            process.kill()
                            return
                        output.write(chunk)
                        total += len(chunk)
            except BaseException as exc:
                reader_error.append(exc)
                process.kill()

        reader = threading.Thread(target=copy_bounded, name="docker-output-capture", daemon=True)
        reader.start()
        try:
            return_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait(timeout=5)
            reader.join(timeout=5)
            raise TimeoutError("Docker Worker exceeded its wall-clock limit") from exc
        reader.join(timeout=5)
        if reader.is_alive():
            process.kill()
            raise DockerBackendError("Docker output reader did not terminate")
        if reader_error:
            raise DockerBackendError("Docker output capture failed") from reader_error[0]
        if exceeded.is_set():
            raise DockerOutputLimitError("Docker Worker output exceeded its size limit")
        return return_code

    def remove(self, container: str) -> None:
        self._run(("rm", "--force", "--volumes", container))

    def exists(self, container: str) -> bool:
        result = self._run(("inspect", container), check=False)
        if result.returncode == 0:
            return True
        if "no such object" in result.stderr.lower():
            return False
        raise DockerBackendError("Docker could not verify container absence")

    def _json(self, arguments: Sequence[str]) -> Any:
        result = self._run(arguments)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise DockerBackendError("Docker returned malformed JSON") from exc

    def _run(
        self, arguments: Sequence[str], *, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            (self.executable, *arguments),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env=self.environment,
        )
        if check and result.returncode != 0:
            message = result.stderr.strip()[:500]
            raise DockerBackendError(f"Docker command failed: {message}")
        return result


class RegisteredObjectStore:
    """Trusted mapping from content digests to directories under one storage root."""

    def __init__(self, root: Path, objects: Mapping[str, Path]):
        self.root = root.resolve(strict=True)
        self._objects = {key: value.resolve(strict=True) for key, value in objects.items()}
        for path in self._objects.values():
            if "," in str(path) or not path.is_dir() or not path.is_relative_to(self.root):
                raise ValueError("registered sandbox object escapes its storage root")

    def resolve(self, object_id: str) -> Path:
        try:
            path = self._objects[object_id]
        except KeyError as exc:
            raise RunnerRejected("sandbox content object is not registered") from exc
        try:
            current = path.resolve(strict=True)
        except OSError as exc:
            raise RunnerRejected("sandbox content object is no longer available") from exc
        if current != path or not current.is_dir() or not current.is_relative_to(self.root):
            raise RunnerRejected("sandbox content object is no longer safe")
        return current


class DockerSandboxRunner:
    """Run one registered tool in an ephemeral hardened Docker container."""

    def __init__(
        self,
        backend: DockerBackend,
        object_store: RegisteredObjectStore,
        tools: Sequence[DockerTool],
        *,
        engine_policy: DockerEnginePolicy | None = None,
        output_store: RunnerOutputStore | None = None,
        captured_output_tools: frozenset[str] = frozenset(),
    ):
        self.backend = backend
        self.object_store = object_store
        self.engine_policy = engine_policy or DockerEnginePolicy()
        self._tools = {tool.tool_id: tool for tool in tools}
        if len(self._tools) != len(tools):
            raise ValueError("Docker tool ids must be unique")
        if captured_output_tools - frozenset(self._tools) or bool(captured_output_tools) != bool(
            output_store
        ):
            raise ValueError("captured output tools require one registered output store")
        self.output_store = output_store
        self.captured_output_tools = captured_output_tools
        self._results: dict[str, tuple[str, SandboxRunResult]] = {}
        self.last_inspection: Mapping[str, Any] | None = None
        self.last_terminal_inspection: Mapping[str, Any] | None = None

    def execute(self, request: SandboxRunRequest, *, now: datetime) -> SandboxRunResult:
        request = validate_run_request(request, frozenset(self._tools))
        digest = run_request_digest(request)
        existing = self._results.get(request.idempotency_key)
        if existing is not None:
            if existing[0] != digest:
                raise RunnerIdempotencyConflict(
                    "run idempotency key was reused with a different request"
                )
            return existing[1]

        wall_limit = min(request.task.budget.wall_seconds, request.profile.limits.wall_seconds)
        if now >= request.task.deadline:
            result = self._result(
                request, SandboxRunStatus.TIMED_OUT, 0.0, ("wall_time_budget_exceeded",), 0
            )
            self._results[request.idempotency_key] = (digest, result)
            return result

        self._validate_engine()
        if request.profile.network_mode is not NetworkMode.NONE:
            raise RunnerRejected(
                "Docker Runner cannot enforce target-only egress; use the typed Tool Broker"
            )
        image = self.backend.inspect_image(request.profile.image_digest)
        if image.get("Id") != request.profile.image_digest:
            raise RunnerRejected("Docker image id does not match the bound image digest")

        create_args = self._create_arguments(request)
        container: str | None = None
        started = time.monotonic()
        status = SandboxRunStatus.FAILED
        errors: tuple[str, ...] = ("worker_failed",)
        outputs: tuple[SandboxOutput, ...] = ()
        tool_calls = 1
        try:
            container = self.backend.create(create_args)
            inspection = self.backend.inspect_container(container)
            self._validate_created_container(request, inspection)
            self.last_inspection = inspection
            try:
                if request.invocation.tool_id in self.captured_output_tools:
                    assert self.output_store is not None
                    exit_code, output = self.output_store.capture_attached(
                        self.backend,
                        container,
                        timeout=wall_limit,
                    )
                    outputs = (output,)
                else:
                    exit_code = self.backend.start(container, wall_limit)
            except TimeoutError:
                status = SandboxRunStatus.TIMED_OUT
                errors = ("wall_time_budget_exceeded",)
                self.backend.kill(container)
            except RunnerOutputCaptureFailed:
                errors = ("output_capture_failed",)
                self.backend.kill(container)
            else:
                stopped = self.backend.inspect_container(container)
                self.last_terminal_inspection = stopped
                if stopped.get("State", {}).get("OOMKilled"):
                    errors = ("memory_limit_exceeded",)
                elif (
                    exit_code in self._tools[request.invocation.tool_id].successful_exit_codes
                    and stopped.get("State", {}).get("ExitCode")
                    in self._tools[request.invocation.tool_id].successful_exit_codes
                ):
                    status = SandboxRunStatus.COMPLETED
                    errors = ()
                if status is not SandboxRunStatus.COMPLETED:
                    # A failed Worker may have emitted partial or misleading bytes. Keep
                    # the immutable object quarantined, but never publish its reference.
                    outputs = ()
        finally:
            if container is not None:
                try:
                    self.backend.remove(container)
                    still_exists = self.backend.exists(container)
                except Exception as exc:
                    raise RunnerCleanupFailed("Docker cleanup could not be verified") from exc
                if still_exists:
                    raise RunnerCleanupFailed("Docker container still exists after cleanup")

        wall_seconds = time.monotonic() - started
        result = self._result(request, status, wall_seconds, errors, tool_calls, outputs)
        self._results[request.idempotency_key] = (digest, result)
        return result

    def _validate_engine(self) -> None:
        info = self.backend.engine_info()
        security = info.get("SecurityOptions", [])
        normalized = {str(item).lower() for item in security}
        if self.engine_policy.require_rootless and not any(
            "rootless" in item for item in normalized
        ):
            raise RunnerRejected("Docker engine is not running in rootless mode")
        if self.engine_policy.require_seccomp and not any("seccomp" in item for item in normalized):
            raise RunnerRejected("Docker engine does not report seccomp enforcement")
        if self.engine_policy.require_cgroup_v2 and str(info.get("CgroupVersion")) != "2":
            raise RunnerRejected("Docker engine does not report cgroup v2 enforcement")
        if self.engine_policy.require_resource_controls and not all(
            info.get(field) is True for field in ("MemoryLimit", "CpuCfsQuota", "PidsLimit")
        ):
            raise RunnerRejected("Docker engine cannot enforce required resource controls")

    def _create_arguments(self, request: SandboxRunRequest) -> tuple[str, ...]:
        profile = request.profile
        environment = _docker_worker_environment(request.environment)
        name = f"vulnloom-{request.run_id.hex}"
        args: list[str] = [
            "--name",
            name,
            "--pull",
            "never",
            "--read-only",
            "--user",
            f"{profile.run_as_uid}:{profile.run_as_gid}",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--network",
            "none",
            "--pids-limit",
            str(profile.limits.pids),
            "--memory",
            str(profile.limits.memory_bytes),
            "--memory-swap",
            str(profile.limits.memory_bytes),
            "--cpus",
            _cpu_limit(profile.limits.cpu_millis, profile.limits.wall_seconds),
            "--ulimit",
            f"nofile={profile.limits.open_files}:{profile.limits.open_files}",
            "--tmpfs",
            _tmpfs("/tmp", profile.limits.tmp_bytes, profile.run_as_uid, profile.run_as_gid),
            "--tmpfs",
            _tmpfs(
                "/workspace/output",
                profile.limits.file_bytes,
                profile.run_as_uid,
                profile.run_as_gid,
            ),
            "--init",
            "--log-driver",
            "none",
            "--restart",
            "no",
            "--workdir",
            {
                "source": "/workspace/source",
                "output": "/workspace/output",
                "temp": "/tmp",
            }[request.invocation.working_directory.value],
        ]
        for name, value in sorted(environment.items()):
            args.extend(("--env", f"{name}={value}"))
        for mount in profile.mounts:
            if mount.object_id is None:
                continue
            source = self.object_store.resolve(mount.object_id)
            args.extend(
                (
                    "--mount",
                    f"type=bind,src={source},dst={mount.destination},readonly,bind-propagation=rprivate",
                )
            )
        tool = self._tools[request.invocation.tool_id]
        args.extend(("--entrypoint", tool.argv_prefix[0]))
        args.append(profile.image_digest)
        args.extend(tool.argv_prefix[1:])
        args.extend(request.invocation.arguments)
        return tuple(args)

    def _validate_created_container(
        self, request: SandboxRunRequest, inspection: Mapping[str, Any]
    ) -> None:
        profile = request.profile
        config = inspection.get("Config", {})
        host = inspection.get("HostConfig", {})
        expected_env = _docker_worker_environment(request.environment)
        actual_env = dict(item.split("=", 1) for item in config.get("Env", []) if "=" in item)
        expected_tmpfs = {
            "/tmp": _tmpfs_options(
                profile.limits.tmp_bytes, profile.run_as_uid, profile.run_as_gid
            ),
            "/workspace/output": _tmpfs_options(
                profile.limits.file_bytes, profile.run_as_uid, profile.run_as_gid
            ),
        }
        nofile = next(
            (item for item in host.get("Ulimits") or () if item.get("Name") == "nofile"), None
        )
        checks = (
            config.get("User") == f"{profile.run_as_uid}:{profile.run_as_gid}",
            actual_env == expected_env,
            config.get("Entrypoint") == [self._tools[request.invocation.tool_id].argv_prefix[0]],
            host.get("ReadonlyRootfs") is True,
            set(host.get("CapDrop") or ()) == {"ALL"},
            any("no-new-privileges" in item for item in host.get("SecurityOpt") or ()),
            host.get("NetworkMode") == "none",
            host.get("Privileged") is False,
            host.get("PidMode") != "host",
            host.get("IpcMode") != "host",
            host.get("UTSMode") != "host",
            host.get("PidsLimit") == profile.limits.pids,
            host.get("Memory") == profile.limits.memory_bytes,
            host.get("MemorySwap") == profile.limits.memory_bytes,
            host.get("NanoCpus")
            == int(float(_cpu_limit(profile.limits.cpu_millis, profile.limits.wall_seconds)) * 1e9),
            host.get("Tmpfs") == expected_tmpfs,
            nofile is not None
            and nofile.get("Soft") == profile.limits.open_files
            and nofile.get("Hard") == profile.limits.open_files,
            host.get("Init") is True,
            host.get("LogConfig", {}).get("Type") == "none",
            host.get("RestartPolicy", {}).get("Name") == "no",
        )
        if not all(checks):
            raise RunnerRejected("created Docker container failed hardening verification")
        expected_mounts = {
            (mount.destination, str(self.object_store.resolve(mount.object_id)))
            for mount in profile.mounts
            if mount.kind in {MountKind.SNAPSHOT, MountKind.ANALYZER_DATA, MountKind.EVIDENCE}
        }
        actual_mounts = {
            (mount.get("Destination"), mount.get("Source"))
            for mount in inspection.get("Mounts", [])
            if mount.get("RW") is False
        }
        if expected_mounts != actual_mounts:
            raise RunnerRejected("created Docker container is missing a read-only content mount")

    @staticmethod
    def _result(
        request: SandboxRunRequest,
        status: SandboxRunStatus,
        wall_seconds: float,
        errors: tuple[str, ...],
        tool_calls: int,
        outputs: tuple[SandboxOutput, ...] = (),
    ) -> SandboxRunResult:
        from vulnloom.domain.protocol import TaskBudget

        return SandboxRunResult(
            run_id=request.run_id,
            task_id=request.task.task_id,
            status=status,
            sandbox_profile_digest=sandbox_profile_digest(request.profile),
            invocation_digest=invocation_digest(request.invocation),
            budget_used=TaskBudget(
                wall_seconds=max(1, min(int(wall_seconds), request.task.budget.wall_seconds)),
                model_tokens=0,
                tool_calls=tool_calls,
            ),
            usage=SandboxUsage(
                wall_seconds=wall_seconds,
                cpu_millis=0,
                peak_memory_bytes=0,
                pids_peak=0,
                open_files_peak=0,
                output_bytes=sum(item.size for item in outputs),
                temporary_bytes=0,
            ),
            error_codes=errors,
            outputs=outputs,
            cleanup=CleanupReport(
                processes_terminated=True,
                network_released=True,
                writable_layer_removed=True,
                temporary_mounts_removed=True,
            ),
        )


def _tmpfs(destination: str, size: int, uid: int, gid: int) -> str:
    return f"{destination}:{_tmpfs_options(size, uid, gid)}"


def _tmpfs_options(size: int, uid: int, gid: int) -> str:
    return f"rw,noexec,nosuid,nodev,size={size},uid={uid},gid={gid},mode=0700"


def _cpu_limit(cpu_millis: int, wall_seconds: int) -> str:
    average_cores = cpu_millis / (wall_seconds * 1000)
    return f"{max(0.01, min(1.0, average_cores)):.3f}"


def _docker_control_environment() -> dict[str, str]:
    environment = {"PATH": os.defpath}
    for name in ("HOME", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_HOST"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _docker_worker_environment(explicit: Mapping[str, str]) -> dict[str, str]:
    environment = build_worker_environment(explicit)
    # Override image-provided PATH with a fixed non-host-derived value.
    environment["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    return environment


def _network_gateway_ips(inspections: Sequence[Mapping[str, Any]]) -> frozenset[str]:
    gateways: set[str] = set()
    try:
        for network in inspections:
            configurations = network.get("IPAM", {}).get("Config") or ()
            for configuration in configurations:
                gateway = configuration.get("Gateway")
                if gateway:
                    gateways.add(str(ipaddress.ip_address(gateway)))
    except (AttributeError, TypeError, ValueError) as exc:
        raise DockerBackendError("Docker network gateway inspection is malformed") from exc
    return frozenset(gateways)
