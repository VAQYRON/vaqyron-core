"""Offline orchestration of independent FOUND-claim verification."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .store import CentralStore


MAX_STDOUT_BYTES = 64 * 1024
MAX_STDERR_BYTES = 8 * 1024
MAX_VERIFICATION_ATTEMPTS = 3
SUPPORTED_CONSENSUS = {
    "time": 1791363600,
    "nbits": 0x1D00FFFF,
    "block_version": 1,
    "pow_limit": "00000000" + "ff" * 28,
}
AUTHORIZED_NONCE_START = 541696


class VerificationError(RuntimeError):
    """The verifier could not provide a trustworthy outcome."""


def _platform_is_windows() -> bool:
    return sys.platform == "win32"


def _run_bounded_process(
    command: list[str],
    *,
    timeout_seconds: float,
) -> subprocess.CompletedProcess[bytes]:
    limits = (MAX_STDOUT_BYTES, MAX_STDERR_BYTES)
    creation_flags = 0
    if _platform_is_windows():
        creation_flags = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "CREATE_SUSPENDED", 0)
        )
    process = subprocess.Popen(
        command,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creation_flags,
    )
    job = _attach_windows_job(process) if _platform_is_windows() else None
    if job is not None:
        _resume_windows_process(process, job)
    pipes = (process.stdout, process.stderr)
    if any(pipe is None for pipe in pipes):
        if job is not None:
            job.terminate()
            job.close()
        else:
            process.kill()
        process.wait()
        raise VerificationError("verifier output pipes could not be created")

    captured = [bytearray(), bytearray()]
    oversized = [False, False]
    read_errors: list[OSError] = []

    def drain(index: int) -> None:
        pipe = pipes[index]
        try:
            while True:
                chunk = pipe.read(4096)
                if not chunk:
                    return
                if len(captured[index]) + len(chunk) > limits[index]:
                    oversized[index] = True
                remaining = limits[index] + 1 - len(captured[index])
                if remaining > 0:
                    captured[index].extend(chunk[:remaining])
        except OSError as error:
            read_errors.append(error)

    readers = [
        threading.Thread(target=drain, args=(index,), daemon=True)
        for index in range(2)
    ]
    for reader in readers:
        reader.start()
    try:
        returncode = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        if job is not None:
            job.terminate()
            job.close()
            job = None
        else:
            process.kill()
        process.wait()
        for reader in readers:
            reader.join()
        raise
    except BaseException:
        if job is not None:
            job.terminate()
            job.close()
            job = None
        else:
            process.kill()
        process.wait()
        for reader in readers:
            reader.join()
        raise
    finally:
        if job is not None:
            job.close()
    for reader in readers:
        reader.join()
    if read_errors:
        raise VerificationError(f"cannot capture independent verifier output: {read_errors[0]}")
    if any(oversized):
        raise VerificationError("independent verifier output exceeded its size limit")
    return subprocess.CompletedProcess(
        command,
        returncode,
        stdout=bytes(captured[0]),
        stderr=bytes(captured[1]),
    )


def _attach_windows_job(process: subprocess.Popen[bytes]) -> Any:
    """Place verifier and descendants in a kill-on-close Windows Job Object."""
    import ctypes
    from ctypes import wintypes

    class BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
        )]

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimitInformation),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = (
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD
    )
    kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    job_handle = kernel32.CreateJobObjectW(None, None)
    if not job_handle:
        process.kill()
        process.wait()
        raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")

    info = ExtendedLimitInformation()
    info.BasicLimitInformation.LimitFlags = 0x00002000
    configured = kernel32.SetInformationJobObject(
        job_handle, 9, ctypes.byref(info), ctypes.sizeof(info)
    )
    assigned = configured and kernel32.AssignProcessToJobObject(
        job_handle, wintypes.HANDLE(process._handle)
    )
    if not assigned:
        error_code = ctypes.get_last_error()
        kernel32.TerminateJobObject(job_handle, 1)
        kernel32.CloseHandle(job_handle)
        process.kill()
        process.wait()
        raise OSError(error_code, "cannot assign verifier to a kill-on-close Job Object")

    class Job:
        def terminate(self) -> None:
            kernel32.TerminateJobObject(job_handle, 1)

        def close(self) -> None:
            if job_handle:
                kernel32.CloseHandle(job_handle)

    return Job()


def _resume_windows_process(process: subprocess.Popen[bytes], job: Any) -> None:
    """Resume only after assigning the suspended verifier to its kill-on-close job."""
    import ctypes
    from ctypes import wintypes

    try:
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        resume = ntdll.NtResumeProcess
        resume.argtypes = (wintypes.HANDLE,)
        resume.restype = wintypes.LONG
        status = resume(wintypes.HANDLE(process._handle))
        if status < 0:
            raise OSError(status, "NtResumeProcess failed for isolated verifier")
    except BaseException:
        job.terminate()
        job.close()
        process.wait()
        raise


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class FoundVerifier:
    """Persist and independently verify FOUND claims from stored telemetry."""

    def __init__(
        self,
        store: CentralStore,
        *,
        verifier_script: str | Path | None = None,
        yespower_cli: str | Path | None = None,
        timeout_seconds: float = 15,
    ) -> None:
        base = Path(__file__).resolve().parents[2]
        verification_dir = base / "genesis-verification"
        self.store = store
        self.verifier_script = Path(verifier_script) if verifier_script is not None else verification_dir / "verify_candidate.py"
        self.yespower_cli = Path(yespower_cli) if yespower_cli is not None else verification_dir / "yespower-ref-cli.exe"
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds <= 60:
            raise ValueError("timeout_seconds must be greater than 0 and at most 60")
        self.timeout_seconds = float(timeout_seconds)

    def verify_event(
        self,
        machine_id: str,
        event_id: str,
        *,
        now: str | None = None,
    ) -> list[dict[str, Any]]:
        event = self.store.event_for_verification(machine_id, event_id)
        event_now = now or _utc_now()
        payload = event["payload"]
        claims: list[tuple[str, dict[str, Any] | None]] = []
        log = payload["log"]
        if log["result"] == "FOUND":
            claims.append(("log", log["found_candidate"]))
        checkpoint = payload["checkpoint"]
        if checkpoint["found"] is not None:
            claims.append(("checkpoint", checkpoint["found"]))
        return [
            self._verify_claim(
                machine_id=machine_id,
                event_id=event_id,
                source=source,
                candidate=candidate,
                event=event,
                now=event_now,
            )
            for source, candidate in claims
        ]

    def _verify_claim(
        self,
        *,
        machine_id: str,
        event_id: str,
        source: str,
        candidate: dict[str, Any] | None,
        event: dict[str, Any],
        now: str,
    ) -> dict[str, Any]:
        if candidate is None:
            claim = {"malformed": True, "source": source}
        elif source == "log":
            claim = {
                "nonce": candidate["nonce"],
                "block_hash": candidate["block_hash"],
                "pow_digest_raw": candidate["pow_digest_raw"],
                "timestamp": candidate["timestamp"],
            }
        else:
            claim = {
                "nonce": candidate["nonce"],
                "block_hash": candidate["header_hash"],
                "pow_digest_raw": candidate["pow_digest_raw"],
                "timestamp": None,
            }
        record = self.store.create_verification(
            machine_id=machine_id, event_id=event_id, source=source, claim=claim, now=now
        )
        if record["status"] != "PENDING":
            return record
        record = self.store.begin_verification_attempt(
            record["verification_id"],
            max_attempts=MAX_VERIFICATION_ATTEMPTS,
            lease_seconds=self.timeout_seconds + 30,
            now=now,
        )
        if record["status"] != "PENDING" or not record["attempt_claimed"]:
            return record

        rejection = self._validate_claim(machine_id, source, claim, event)
        if rejection is not None:
            return self.store.finish_verification(
                record["verification_id"],
                status="REJECTED",
                detail=rejection,
                verifier_result=None,
                now=now,
            )

        try:
            verifier_result, exit_code = self._run_verifier(claim["nonce"])
        except VerificationError as error:
            return self.store.finish_verification(
                record["verification_id"],
                status="ERROR",
                detail=str(error),
                verifier_result=None,
                now=now,
            )

        result_matches = (
            verifier_result["nonce"] == claim["nonce"]
            and verifier_result["time"] == SUPPORTED_CONSENSUS["time"]
            and verifier_result["version"] == SUPPORTED_CONSENSUS["block_version"]
            and verifier_result["bits"].lower() == f'{SUPPORTED_CONSENSUS["nbits"]:08x}'
        )
        hashes_match = (
            verifier_result["block_id"].lower() == claim["block_hash"]
            and verifier_result["pow_digest_raw"].lower() == claim["pow_digest_raw"]
        )
        valid = (
            verifier_result["candidate_valid"] is True
            and verifier_result["pow_valid"] is True
            and verifier_result["target_valid"] is True
            and verifier_result["result"] == "PASS"
        )
        if exit_code == 0 and result_matches and hashes_match and valid:
            status, detail = "VERIFIED", "independent reconstruction and proof-of-work checks passed"
        elif exit_code == 1 or (not hashes_match and result_matches) or not valid:
            status, detail = "REJECTED", "candidate did not match the independent verifier result"
        else:
            status, detail = "ERROR", "verifier output did not satisfy the expected contract"
        return self.store.finish_verification(
            record["verification_id"],
            status=status,
            detail=detail,
            verifier_result=verifier_result,
            now=now,
        )

    def _validate_claim(
        self,
        machine_id: str,
        source: str,
        claim: dict[str, Any],
        event: dict[str, Any],
    ) -> str | None:
        if "nonce" not in claim:
            return "FOUND claim is malformed or missing candidate fields"
        configuration = self.store.search_configuration(machine_id)
        if configuration is None:
            return "machine has no registered search configuration"
        if any(configuration[field] != value for field, value in SUPPORTED_CONSENSUS.items()):
            return "registered search consensus configuration is incompatible with this verifier"
        if configuration["start_nonce"] < AUTHORIZED_NONCE_START:
            return "registered search range begins below the verifier's authorized nonce range"
        nonce = claim["nonce"]
        if not configuration["start_nonce"] <= nonce <= configuration["end_nonce"]:
            return "candidate nonce is outside the registered search range"

        if source == "checkpoint":
            checkpoint = event["payload"]["checkpoint"]
            if checkpoint["status"] != "valid" or checkpoint["configuration"] != configuration:
                return "checkpoint configuration does not match the registered search configuration"
            workers = checkpoint["workers"]
            if not any(worker["start_nonce"] <= nonce <= worker["end_nonce"] for worker in workers):
                return "candidate nonce is outside checkpoint worker ranges"
        else:
            log = event["payload"]["log"]
            if (
                log["status"] != "available"
                or log["worker_ranges_status"] != "valid"
                or log["search_time"] != configuration["time"]
                or log["range_start"] != configuration["start_nonce"]
                or log["range_end"] != configuration["end_nonce"]
            ):
                return "log search configuration does not match the registered search configuration"
            actual_workers = min(
                configuration["end_nonce"] - configuration["start_nonce"] + 1,
                configuration["requested_worker_count"],
            )
            if log["worker_count"] != actual_workers:
                return "log worker count does not match the registered search configuration"
            if not any(
                worker["range_start"] is not None
                and worker["range_start"] <= nonce <= worker["range_end"]
                for worker in log["workers"]
            ):
                return "candidate nonce is outside observed worker ranges"
        return None

    def _run_verifier(self, nonce: int) -> tuple[dict[str, Any], int]:
        if not self.verifier_script.is_file():
            raise VerificationError("independent verifier script is unavailable")
        if not self.yespower_cli.is_file():
            raise VerificationError("reference yespower helper is unavailable")
        command = [
            sys.executable,
            str(self.verifier_script.resolve()),
            "--nonce",
            str(nonce),
            "--yespower-cli",
            str(self.yespower_cli.resolve()),
        ]
        try:
            completed = _run_bounded_process(
                command,
                timeout_seconds=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            raise VerificationError("independent verifier timed out") from error
        except OSError as error:
            raise VerificationError(f"cannot start independent verifier: {error}") from error
        stdout = completed.stdout.decode("utf-8", errors="replace")
        stderr = completed.stderr.decode("utf-8", errors="replace")
        try:
            result = json.loads(stdout)
        except json.JSONDecodeError as error:
            detail = stderr.strip() or "verifier returned malformed JSON"
            if completed.returncode == 2:
                raise VerificationError(detail[:2048]) from error
            raise VerificationError("independent verifier returned malformed JSON") from error
        if not isinstance(result, dict):
            raise VerificationError("independent verifier returned a non-object result")
        required = {
            "nonce", "time", "version", "bits", "block_id", "pow_digest_raw",
            "candidate_valid", "pow_valid", "target_valid", "result",
        }
        if not required.issubset(result):
            raise VerificationError("independent verifier result is missing required fields")
        if (
            isinstance(result["nonce"], bool) or not isinstance(result["nonce"], int)
            or isinstance(result["time"], bool) or not isinstance(result["time"], int)
            or isinstance(result["version"], bool) or not isinstance(result["version"], int)
            or not isinstance(result["bits"], str) or len(result["bits"]) != 8
            or any(char not in "0123456789abcdefABCDEF" for char in result["bits"])
            or not isinstance(result["block_id"], str) or len(result["block_id"]) != 64
            or any(char not in "0123456789abcdefABCDEF" for char in result["block_id"])
            or not isinstance(result["pow_digest_raw"], str) or len(result["pow_digest_raw"]) != 64
            or any(char not in "0123456789abcdefABCDEF" for char in result["pow_digest_raw"])
            or not all(isinstance(result[name], bool) for name in ("candidate_valid", "pow_valid", "target_valid"))
            or not isinstance(result["result"], str)
        ):
            raise VerificationError("independent verifier result fields have invalid types")
        if completed.returncode not in (0, 1):
            detail = stderr.strip() or f"verifier exited with {completed.returncode}"
            raise VerificationError(detail[:2048])
        return result, completed.returncode
