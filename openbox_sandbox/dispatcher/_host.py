from __future__ import annotations

import asyncio
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .errors import DispatchErrorCode
from .result import TimeoutStatus


@dataclass(frozen=True, slots=True, repr=False)
class _HostConfig:
    workdir: Path
    stdout_bytes: int = 1024 * 1024
    stderr_bytes: int = 1024 * 1024
    combined_bytes: int = 2 * 1024 * 1024
    environment: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if (
            not self.workdir.is_absolute()
            or not isinstance(self.environment, Mapping)
            or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in self.environment.items()
            )
            or min(self.stdout_bytes, self.stderr_bytes, self.combined_bytes) <= 0
            or self.stdout_bytes > self.combined_bytes
            or self.stderr_bytes > self.combined_bytes
            or self.combined_bytes > 16 * 1024 * 1024
        ):
            raise ValueError("host execution configuration rejected")

    def __repr__(self) -> str:
        return (
            "_HostConfig(workdir=<trusted>, "
            f"stdout_bytes={self.stdout_bytes}, stderr_bytes={self.stderr_bytes}, "
            f"combined_bytes={self.combined_bytes})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class _HostOutcome:
    exit_code: int
    stdout: bytes
    stderr: bytes
    timeout_status: TimeoutStatus


class _HostFailure(Exception):
    def __init__(self, code: DispatchErrorCode) -> None:
        super().__init__("host execution failed")
        self.code = code


class _OutputOverflow(Exception):
    pass


class _HostExecutor:
    def __init__(self, config: _HostConfig) -> None:
        self._config = config

    async def execute(self, argv: tuple[str, ...], timeout_seconds: int) -> _HostOutcome:
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                cwd=self._config.workdir,
                env=dict(self._config.environment),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
        except (OSError, ValueError) as error:
            raise _HostFailure(DispatchErrorCode.HOST_EXEC_INDETERMINATE) from error
        assert process.stdout is not None and process.stderr is not None
        total = [0]

        async def read_stream(reader: asyncio.StreamReader, limit: int) -> bytes:
            result = bytearray()
            while True:
                chunk = await reader.read(64 * 1024)
                if not chunk:
                    return bytes(result)
                total[0] += len(chunk)
                if len(result) + len(chunk) > limit or total[0] > self._config.combined_bytes:
                    raise _OutputOverflow()
                result.extend(chunk)

        stdout_task = asyncio.create_task(read_stream(process.stdout, self._config.stdout_bytes))
        stderr_task = asyncio.create_task(read_stream(process.stderr, self._config.stderr_bytes))
        wait_task = asyncio.create_task(process.wait())
        group = asyncio.gather(wait_task, stdout_task, stderr_task)
        try:
            async with asyncio.timeout(timeout_seconds):
                exit_code, stdout, stderr = await asyncio.shield(group)
            return _HostOutcome(exit_code, stdout, stderr, TimeoutStatus.NOT_OBSERVED)
        except TimeoutError:
            await _terminate(process)
            try:
                async with asyncio.timeout(1):
                    _, stdout, stderr = await group
            except _OutputOverflow as error:
                await _cancel_tasks(stdout_task, stderr_task, wait_task)
                _close_transport(process)
                raise _HostFailure(DispatchErrorCode.HOST_OUTPUT_LIMIT) from error
            except TimeoutError as error:
                await _cancel_tasks(stdout_task, stderr_task, wait_task)
                _close_transport(process)
                raise _HostFailure(DispatchErrorCode.HOST_EXEC_INDETERMINATE) from error
            _close_transport(process)
            # Let asyncio deliver the final pipe/transport close callbacks before
            # the process wrapper becomes unreachable.
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            return _HostOutcome(
                process.returncode if process.returncode is not None else -9,
                stdout,
                stderr,
                TimeoutStatus.CONFIRMED_TIMEOUT,
            )
        except _OutputOverflow as error:
            await _terminate(process)
            await _cancel_tasks(stdout_task, stderr_task, wait_task)
            _close_transport(process)
            raise _HostFailure(DispatchErrorCode.HOST_OUTPUT_LIMIT) from error
        except asyncio.CancelledError:
            await _terminate(process)
            await _cancel_tasks(stdout_task, stderr_task, wait_task)
            _close_transport(process)
            raise
        except (OSError, RuntimeError) as error:
            await _terminate(process)
            await _cancel_tasks(stdout_task, stderr_task, wait_task)
            _close_transport(process)
            raise _HostFailure(DispatchErrorCode.HOST_EXEC_INDETERMINATE) from error


async def _terminate(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    try:
        os.killpg(process.pid, 15)
    except (ProcessLookupError, PermissionError):
        try:
            process.terminate()
        except ProcessLookupError:
            pass
    try:
        async with asyncio.timeout(1):
            await process.wait()
    except TimeoutError:
        try:
            os.killpg(process.pid, 9)
        except (ProcessLookupError, PermissionError):
            try:
                process.kill()
            except ProcessLookupError:
                pass
        await process.wait()


def _close_transport(process: asyncio.subprocess.Process) -> None:
    # asyncio exposes no public subprocess close method. Closing its transport is
    # necessary after forced termination so pipe descriptors cannot survive until
    # garbage collection (CPython issue 103847).
    process._transport.close()  # type: ignore[attr-defined]


async def _cancel_tasks(*tasks: asyncio.Task[object]) -> None:
    for task in tasks:
        if not task.done():
            task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
