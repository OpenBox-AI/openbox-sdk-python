from __future__ import annotations

import asyncio
import json
import os
import stat
import tempfile
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

try:
    import fcntl
except ImportError:  # pragma: no cover - fail-closed portability boundary
    fcntl = None  # type: ignore[assignment]


@dataclass(frozen=True, slots=True)
class TelemetryEvent:
    event: str
    workflow_id: str
    run_id: str
    activity_id: str
    attempt: int = 1
    governance_event_id: str | None = None
    verdict: str | None = None
    action: str | None = None
    disposition: str | None = None
    directive: str | None = None
    sandbox_id: str | None = None
    lifecycle_phase: str | None = None
    timeout_seconds: int | None = None
    timeout_status: str | None = None
    exit_code: int | None = None
    stdout_bytes: int | None = None
    stderr_bytes: int | None = None
    duration_ms: int | None = None
    error_code: str | None = None
    cleanup_status: str | None = None
    runtime_contract_version: int | None = None
    policy_id: str | None = None
    policy_version: int | None = None
    template_digest: str | None = None
    profile_bundle_version: str | None = None

    def to_wire(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in {
                field.name: getattr(self, field.name)
                for field in self.__dataclass_fields__.values()
            }.items()
            if value is not None
        }


class TelemetrySink(Protocol):
    async def emit(self, event: TelemetryEvent) -> None: ...


class NullTelemetrySink:
    async def emit(self, event: TelemetryEvent) -> None:
        del event


@dataclass(slots=True)
class InMemoryTelemetrySink:
    events: list[TelemetryEvent] = field(default_factory=list)

    async def emit(self, event: TelemetryEvent) -> None:
        self.events.append(event)


@dataclass(frozen=True, slots=True, repr=False)
class CleanupBacklog:
    directory: Path
    compatibility_id: str

    def __repr__(self) -> str:
        return f"CleanupBacklog(directory=<redacted>, compatibility_id={self.compatibility_id!r})"

    async def record(self, request_id: str, state: str, recorded_at: str) -> None:
        await asyncio.to_thread(self._record, request_id, state, recorded_at)

    async def remove(self, request_id: str) -> None:
        await asyncio.to_thread(self._remove, request_id)

    async def request_ids(self) -> tuple[str, ...]:
        return await asyncio.to_thread(self._request_ids)

    @asynccontextmanager
    async def reconciliation_lock(self) -> AsyncIterator[None]:
        """Serialize the complete cleanup transaction across local replicas."""
        if fcntl is None:
            raise OSError("cleanup reconciliation locking unsupported")
        descriptor = self._open_lock()
        acquired = False
        try:
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except BlockingIOError:
                    await asyncio.sleep(0.05)
            yield
        finally:
            if acquired:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
            os.close(descriptor)

    def _open_lock(self) -> int:
        self._secure_directory()
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if nofollow:
            flags |= nofollow
        path = self.directory / ".reconcile.lock"
        try:
            if not nofollow:
                try:
                    if stat.S_ISLNK(os.lstat(path).st_mode):
                        raise OSError("cleanup reconciliation lock rejected")
                except FileNotFoundError:
                    pass
            descriptor = os.open(path, flags, 0o600)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077
            ):
                raise OSError("cleanup reconciliation lock rejected")
            os.fchmod(descriptor, 0o600)
            return descriptor
        except BaseException:
            if "descriptor" in locals():
                os.close(descriptor)
            raise

    def _secure_directory(self) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = os.lstat(self.directory)
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
        ):
            raise OSError("cleanup backlog path rejected")
        os.chmod(self.directory, 0o700)

    def _path(self, request_id: str) -> Path:
        if not request_id.startswith("sbx-") or len(request_id) != 40:
            raise OSError("cleanup identifier rejected")
        try:
            parsed = uuid.UUID(request_id[4:])
        except ValueError as error:
            raise OSError("cleanup identifier rejected") from error
        if parsed.version != 4 or str(parsed) != request_id[4:]:
            raise OSError("cleanup identifier rejected")
        return self.directory / f"{request_id}.json"

    def _record(self, request_id: str, state: str, recorded_at: str) -> None:
        self._secure_directory()
        path = self._path(request_id)
        if path.exists() and stat.S_ISLNK(os.lstat(path).st_mode):
            raise OSError("cleanup record path rejected")
        payload = json.dumps(
            {
                "schema_version": 1,
                "request_id": request_id,
                "state": state,
                "recorded_at": recorded_at,
                "compatibility_id": self.compatibility_id,
            },
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        descriptor, temporary = tempfile.mkstemp(prefix=".cleanup-", dir=self.directory)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            os.chmod(path, 0o600)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def _remove(self, request_id: str) -> None:
        self._secure_directory()
        path = self._path(request_id)
        try:
            if stat.S_ISLNK(os.lstat(path).st_mode):
                raise OSError("cleanup record path rejected")
        except FileNotFoundError:
            return
        path.unlink()

    def _request_ids(self) -> tuple[str, ...]:
        self._secure_directory()
        result: list[str] = []
        for path in self.directory.glob("sbx-*.json"):
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise OSError("cleanup record path rejected")
            value = json.loads(path.read_bytes())
            if (
                not isinstance(value, dict)
                or set(value)
                != {
                    "schema_version",
                    "request_id",
                    "state",
                    "recorded_at",
                    "compatibility_id",
                }
                or value["schema_version"] != 1
                or value["compatibility_id"] != self.compatibility_id
                or value["request_id"] != path.stem
            ):
                raise OSError("cleanup record rejected")
            result.append(value["request_id"])
        return tuple(sorted(result))
