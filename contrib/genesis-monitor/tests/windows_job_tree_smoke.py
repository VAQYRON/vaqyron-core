"""Windows-only smoke test for bounded-runner Job Object cleanup."""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
from ctypes import wintypes
from pathlib import Path
from typing import Any


TIMEOUT_SECONDS = 3
METADATA_WAIT_SECONDS = 2
RUNNER_JOIN_SECONDS = 10
SYNCHRONIZE = 0x00100000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x00000102
WAIT_FAILED = 0xFFFFFFFF
ERROR_INVALID_PARAMETER = 87
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class _FileTime(ctypes.Structure):
    _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]


def _filetime_value(value: _FileTime) -> int:
    return (value.high << 32) | value.low


def _write_synthetic_parent(path: Path) -> None:
    path.write_text(
        """
import json
import os
import subprocess
import sys
import time
import ctypes
from ctypes import wintypes
from pathlib import Path

class FileTime(ctypes.Structure):
    _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.GetProcessTimes.argtypes = (
    wintypes.HANDLE,
    ctypes.POINTER(FileTime),
    ctypes.POINTER(FileTime),
    ctypes.POINTER(FileTime),
    ctypes.POINTER(FileTime),
)
kernel32.GetProcessTimes.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
kernel32.CloseHandle.restype = wintypes.BOOL

def creation_time(handle):
    creation = FileTime()
    exit_time = FileTime()
    kernel_time = FileTime()
    user_time = FileTime()
    if not kernel32.GetProcessTimes(
        handle,
        ctypes.byref(creation),
        ctypes.byref(exit_time),
        ctypes.byref(kernel_time),
        ctypes.byref(user_time),
    ):
        raise OSError(ctypes.get_last_error(), "GetProcessTimes failed")
    return (creation.high << 32) | creation.low

metadata = Path(sys.argv[1])
marker = sys.argv[2]
if not marker.startswith("vaqyron-job-tree-"):
    raise SystemExit("invalid synthetic ownership marker")

child_code = (
    "import sys, time; "
    "assert sys.argv[1].startswith('vaqyron-job-tree-'); "
    "time.sleep(600)"
)
child = subprocess.Popen(
    [sys.executable, "-c", child_code, marker],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    shell=False,
)
child_handle = kernel32.OpenProcess(
    0x1000 | 0x00100000,
    False,
    child.pid,
)
if not child_handle:
    raise OSError(ctypes.get_last_error(), "cannot inspect synthetic child")
try:
    child_creation_time = creation_time(child_handle)
finally:
    if not kernel32.CloseHandle(child_handle):
        raise OSError(ctypes.get_last_error(), "cannot close synthetic child handle")
temporary = metadata.with_suffix(".tmp")
temporary.write_text(
    json.dumps({
        "parent_pid": os.getpid(),
        "parent_creation_time": creation_time(kernel32.GetCurrentProcess()),
        "child_pid": child.pid,
        "child_creation_time": child_creation_time,
        "marker": marker,
    }),
    encoding="utf-8",
)
temporary.replace(metadata)
while True:
    time.sleep(1)
""".lstrip(),
        encoding="utf-8",
    )


def _process_has_exited(pid: int, expected_creation_time: int) -> bool:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = (
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    )
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetProcessTimes.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_FileTime),
        ctypes.POINTER(_FileTime),
        ctypes.POINTER(_FileTime),
        ctypes.POINTER(_FileTime),
    )
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL

    handle = kernel32.OpenProcess(
        SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        pid,
    )
    if not handle:
        error_code = ctypes.get_last_error()
        if error_code == ERROR_INVALID_PARAMETER:
            return True
        raise OSError(error_code, f"OpenProcess failed for captured PID {pid}")

    try:
        creation_time = _FileTime()
        exit_time = _FileTime()
        kernel_time = _FileTime()
        user_time = _FileTime()
        if not kernel32.GetProcessTimes(
            handle,
            ctypes.byref(creation_time),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            error_code = ctypes.get_last_error()
            raise OSError(error_code, f"GetProcessTimes failed for captured PID {pid}")
        if _filetime_value(creation_time) != expected_creation_time:
            raise RuntimeError(f"captured PID {pid} has been reused by a different process")

        result = kernel32.WaitForSingleObject(handle, 0)
        if result == WAIT_OBJECT_0:
            return True
        if result == WAIT_TIMEOUT:
            return False
        if result == WAIT_FAILED:
            error_code = ctypes.get_last_error()
            raise OSError(error_code, f"WaitForSingleObject failed for PID {pid}")
        raise OSError(f"unexpected wait result {result:#x} for captured PID {pid}")
    finally:
        if not kernel32.CloseHandle(handle):
            error_code = ctypes.get_last_error()
            raise OSError(error_code, f"CloseHandle failed for captured PID {pid}")


def _run_test(evidence_dir: Path) -> dict[str, Any]:
    from genesis_monitor.verification import _run_bounded_process

    marker = f"vaqyron-job-tree-{uuid.uuid4().hex}"
    metadata = evidence_dir / "processes.json"
    parent_script = evidence_dir / "synthetic_parent.py"
    _write_synthetic_parent(parent_script)

    outcome: dict[str, Any] = {}

    def run_bounded_parent() -> None:
        try:
            outcome["result"] = _run_bounded_process(
                [sys.executable, str(parent_script), str(metadata), marker],
                timeout_seconds=TIMEOUT_SECONDS,
            )
        except BaseException as error:
            outcome["error"] = error

    runner = threading.Thread(target=run_bounded_parent, daemon=True)
    runner.start()

    deadline = time.monotonic() + METADATA_WAIT_SECONDS
    while time.monotonic() < deadline and not metadata.exists():
        if not runner.is_alive():
            break
        time.sleep(0.05)

    if not metadata.exists():
        runner.join(RUNNER_JOIN_SECONDS)
        raise RuntimeError(
            "synthetic parent did not record its PIDs before the bounded timeout; "
            f"runner_error={outcome.get('error')!r}"
        )

    process_data = json.loads(metadata.read_text(encoding="utf-8"))
    if process_data.get("marker") != marker:
        runner.join(RUNNER_JOIN_SECONDS)
        raise RuntimeError("synthetic process ownership marker did not match")

    for field in ("parent_pid", "child_pid"):
        pid = process_data.get(field)
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            runner.join(RUNNER_JOIN_SECONDS)
            raise RuntimeError(f"invalid captured {field}: {pid!r}")
        creation_field = field.replace("_pid", "_creation_time")
        creation_time = process_data.get(creation_field)
        if isinstance(creation_time, bool) or not isinstance(creation_time, int) or creation_time <= 0:
            runner.join(RUNNER_JOIN_SECONDS)
            raise RuntimeError(f"invalid captured {creation_field}: {creation_time!r}")
    if process_data["parent_pid"] == process_data["child_pid"]:
        runner.join(RUNNER_JOIN_SECONDS)
        raise RuntimeError("synthetic parent and child unexpectedly share a PID")

    runner.join(RUNNER_JOIN_SECONDS)
    if runner.is_alive():
        raise RuntimeError("bounded runner did not return after its timeout")

    error = outcome.get("error")
    if not isinstance(error, subprocess.TimeoutExpired):
        raise RuntimeError(f"expected TimeoutExpired from bounded runner, got {error!r}")

    for field in ("parent_pid", "child_pid"):
        pid = process_data[field]
        creation_time = process_data[field.replace("_pid", "_creation_time")]
        if not _process_has_exited(pid, creation_time):
            raise RuntimeError(f"captured synthetic {field} {pid} is still running")

    return process_data


def main() -> int:
    evidence_dir: Path | None = None
    if os.name != "nt":
        print("WINDOWS_JOB_TREE_CLEANUP=FAIL: this smoke test requires Windows", file=sys.stderr)
        return 1

    try:
        evidence_dir = Path(tempfile.mkdtemp(prefix="vaqyron-job-tree-"))
        process_data = _run_test(evidence_dir)
        shutil.rmtree(evidence_dir)
        print(
            "WINDOWS_JOB_TREE_CLEANUP=PASS "
            f"parent_pid={process_data['parent_pid']} "
            f"child_pid={process_data['child_pid']} "
            f"timeout_seconds={TIMEOUT_SECONDS}"
        )
        return 0
    except BaseException as error:
        print(f"WINDOWS_JOB_TREE_CLEANUP=FAIL: {error}", file=sys.stderr)
        traceback.print_exc()
        if evidence_dir is not None:
            print(f"Evidence preserved at: {evidence_dir}", file=sys.stderr)
            metadata = evidence_dir / "processes.json"
            if metadata.is_file():
                try:
                    print(
                        f"Captured process metadata: "
                        f"{metadata.read_text(encoding='utf-8')}",
                        file=sys.stderr,
                    )
                except OSError as read_error:
                    print(f"Could not read process metadata: {read_error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
