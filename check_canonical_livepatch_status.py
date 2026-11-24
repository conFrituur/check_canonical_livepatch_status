#!/usr/bin/env python3

import argparse
import json
import logging
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar, NoReturn


class LivepatchError(RuntimeError):
    """Raised when the Livepatch status cannot be obtained or evaluated."""


class CheckCanonicalLivepatchStatus:
    COMMAND = "canonical-livepatch"
    COMMAND_TIMEOUT = 15
    DEFAULT_STATE_FILE = "/tmp/check_canonical_livepatch_status.state"
    # The client checks in hourly by default (check-interval, minimum 60 minutes).
    DEFAULT_WARNING_SECONDS = 3 * 3600
    DEFAULT_CRITICAL_SECONDS = 6 * 3600
    DEFAULT_PATCHING_WARNING_SECONDS = 2 * 3600
    DEFAULT_PENDING_WARNING_SECONDS = 2 * 3600
    SEVERITY: ClassVar[dict[str, int]] = {"OK": 0, "UNKNOWN": 1, "WARNING": 2, "CRITICAL": 3}
    SYMBOLS = "✓✗⧗"

    # (pattern, level) for the documented "kernel state" values.
    KERNEL_RULES: ClassVar[list[tuple[str, str]]] = [
        (r"kernel series .+ is covered by Livepatch", "OK"),
        (r"kernel .+ is covered by Livepatch until ", "WARNING"),
        (r"kernel is not covered by Livepatch", "CRITICAL"),
        (r"kernel is no longer covered by Livepatch", "CRITICAL"),
        (r"Livepatch coverage has ended", "CRITICAL"),
        (r"Livepatch coverage ended ", "CRITICAL"),
        (r"unable to determine kernel support status", "UNKNOWN"),
    ]

    # (pattern, level, in-progress stage) for the documented "patch state" values.
    # An in-progress stage is OK until it has lasted longer than its limit.
    PATCH_RULES: ClassVar[list[tuple[str, str, str | None]]] = [
        (r"all applicable .*applied", "OK", None),
        (r"no live(?: kernel )?patch(?:es)? available for kernel ", "OK", None),
        (r"kernel upgraded after a reboot", "OK", None),
        (r"patching the kernel", "OK", "patching"),
        (r"live(?: kernel )?patch(?:es)? are downloaded, but the kernel module", "OK", "pending"),
        (r"kernel .+ contains a vulnerability that cannot be remediated", "WARNING", None),
        (r"Livepatch kernel module inserted but kernel bug detected", "CRITICAL", None),
        (r"detected a crash last time", "CRITICAL", None),
        (r"unknown error occurred", "CRITICAL", None),
        (r"failed to verify the signature", "CRITICAL", None),
        (r"failed to extract information", "CRITICAL", None),
        (r"failed to load certificate", "CRITICAL", None),
        (r"failed to confirm that the Livepatch kernel module", "CRITICAL", None),
    ]

    UNIT_SECONDS: ClassVar[dict[str, int]] = {
        "second": 1,
        "minute": 60,
        "hour": 3600,
        "day": 86400,
        "week": 7 * 86400,
        "month": 30 * 86400,
        "year": 365 * 86400,
    }

    def __init__(
        self,
        warning_seconds: int | None = None,
        critical_seconds: int | None = None,
        state_file: str = DEFAULT_STATE_FILE,
        patching_warning_seconds: int = DEFAULT_PATCHING_WARNING_SECONDS,
        pending_warning_seconds: int = DEFAULT_PENDING_WARNING_SECONDS,
        verbose: bool = False,
    ) -> None:
        self.warning_seconds = warning_seconds
        self.critical_seconds = critical_seconds
        self.state_file = Path(state_file)
        self.stall_limits = {
            "patching": patching_warning_seconds,
            "pending": pending_warning_seconds,
        }
        self.validate_thresholds()

        self.log = logging.getLogger(__name__)
        if not self.log.handlers:
            self.log.addHandler(logging.StreamHandler())
        self.log.setLevel(logging.DEBUG if verbose else logging.CRITICAL)

    def validate_thresholds(self) -> None:
        for name, value in (
            ("warning-seconds", self.warning_seconds),
            ("critical-seconds", self.critical_seconds),
            ("patching-warning-seconds", self.stall_limits["patching"]),
            ("pending-warning-seconds", self.stall_limits["pending"]),
        ):
            if value is not None and value <= 0:
                raise ValueError(f"{name} must be greater than zero")
        if (
            self.warning_seconds is not None
            and self.critical_seconds is not None
            and self.warning_seconds >= self.critical_seconds
        ):
            raise ValueError("warning-seconds must be lower than critical-seconds")

    def check_status(self) -> None:
        try:
            status = self.parse_status(self.run_status())
            results = self.evaluate(status)
        except LivepatchError as error:
            self.nagios_exit("UNKNOWN", str(error))

        worst = max(results, key=lambda result: self.SEVERITY[result[0]])[0]
        if worst == "OK":
            self.nagios_exit("OK", self.ok_summary(status, results))
        affected = [message for level, message in results if level == worst]
        self.nagios_exit(worst, "; ".join(affected))

    def run_status(self) -> str:
        """Run `canonical-livepatch status` once and return its output."""
        self.log.debug("Running: %s status --format humane", self.COMMAND)
        try:
            result = subprocess.run(
                [self.COMMAND, "status", "--format", "humane"],
                capture_output=True,
                text=True,
                timeout=self.COMMAND_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise LivepatchError(f"could not run {self.COMMAND}: {error}") from error

        self.log.debug(
            "Exit code %d, stdout=%r stderr=%r",
            result.returncode,
            result.stdout,
            result.stderr,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip() or "no output"
            raise LivepatchError(
                f"{self.COMMAND} exited with {result.returncode}: {detail}"
            )
        return result.stdout

    def parse_status(self, output: str) -> dict[str, str]:
        status: dict[str, str] = {}
        for line in output.splitlines():
            key, separator, value = line.partition(":")
            if separator and key.strip() and not key[0].isspace():
                status[key.strip().lower()] = value.strip().lstrip(self.SYMBOLS).strip()
        if "kernel state" not in status and "patch state" not in status:
            raise LivepatchError(
                f"could not find any Livepatch state in output: {output.strip()[:200]!r}"
            )
        return status

    def evaluate(self, status: dict[str, str]) -> list[tuple[str, str]]:
        results = [
            self.evaluate_kernel_state(status.get("kernel state")),
            self.evaluate_patch_state(status.get("patch state")),
            self.evaluate_check_in(status.get("server check-in")),
        ]
        last_check = self.evaluate_last_check(status.get("last check"))
        if last_check is not None:
            results.append(last_check)
        return results

    def evaluate_kernel_state(self, text: str | None) -> tuple[str, str]:
        if text is None:
            return "UNKNOWN", "kernel state is missing from the status output"
        for pattern, level in self.KERNEL_RULES:
            if re.match(pattern, text):
                return level, text
        return "UNKNOWN", f"unknown kernel state {text!r}"

    def evaluate_patch_state(self, text: str | None) -> tuple[str, str]:
        if text is None:
            self.reset_progress()
            return "UNKNOWN", "patch state is missing from the status output"
        for pattern, level, stage in self.PATCH_RULES:
            if re.match(pattern, text):
                if stage is None:
                    self.reset_progress()
                    return level, text
                return self.evaluate_progress(stage, text)
        self.reset_progress()
        return "UNKNOWN", f"unknown patch state {text!r}"

    @staticmethod
    def evaluate_check_in(text: str | None) -> tuple[str, str]:
        if text is None:
            return "UNKNOWN", "server check-in is missing from the status output"
        if text == "succeeded":
            return "OK", "server check-in succeeded"
        return "CRITICAL", f"server check-in {text}"

    def evaluate_last_check(self, text: str | None) -> tuple[str, str] | None:
        if self.warning_seconds is None and self.critical_seconds is None:
            return None
        age = self.parse_age(text)
        if age is None:
            return "UNKNOWN", f"could not parse last check {text!r}"
        detail = f"last check {self.duration(age)} ago"
        if self.critical_seconds is not None and age > self.critical_seconds:
            return "CRITICAL", detail
        if self.warning_seconds is not None and age > self.warning_seconds:
            return "WARNING", detail
        return "OK", detail

    def parse_age(self, text: str | None) -> int | None:
        """Convert text like '52 seconds ago' or 'an hour ago' to seconds."""
        if text is None:
            return None
        match = re.match(
            r"(?:less than )?(\d+|an?|one) (second|minute|hour|day|week|month|year)s?"
            r"(?: ago)?$",
            text.strip(),
        )
        if not match:
            return None
        count = int(match.group(1)) if match.group(1).isdigit() else 1
        return count * self.UNIT_SECONDS[match.group(2)]

    def evaluate_progress(self, stage: str, text: str) -> tuple[str, str]:
        """In-progress states are OK, unless they last longer than the stage limit.

        The client does not report how long a state has lasted, so the first
        time it was seen is kept in the state file between check runs.
        """
        now = int(self.get_current_time().timestamp())
        since = self.load_progress_since(stage)
        if since is None:
            since = now
            self.save_progress(stage, since)
        age = max(0, now - since)
        limit = self.stall_limits[stage]
        detail = f"{text} for {self.duration(age)}"
        self.log.debug("Stage %s since %d age=%d limit=%d", stage, since, age, limit)
        if age > limit:
            return "WARNING", f"{detail} (limit {self.duration(limit)}), check manually"
        return "OK", detail

    def load_progress_since(self, stage: str) -> int | None:
        try:
            data = json.loads(self.state_file.read_text())
            if data["stage"] == stage and isinstance(data["since"], int):
                return data["since"]
        except (OSError, ValueError, KeyError, TypeError):
            self.log.debug("No usable state file %s", self.state_file)
        return None

    def save_progress(self, stage: str, since: int) -> None:
        try:
            self.state_file.write_text(json.dumps({"stage": stage, "since": since}))
        except OSError as error:
            raise LivepatchError(
                f"could not write state file {self.state_file}: {error}"
            ) from error

    def reset_progress(self) -> None:
        try:
            self.state_file.unlink(missing_ok=True)
        except OSError as error:
            self.log.debug("Could not remove state file: %s", error)

    @staticmethod
    def ok_summary(status: dict[str, str], results: list[tuple[str, str]]) -> str:
        summary = f"kernel {status.get('kernel', 'unknown')}: " + "; ".join(
            message for _, message in results[:2]
        )
        if "patch version" in status:
            summary += f" (patch version {status['patch version']})"
        return summary

    @staticmethod
    def get_current_time() -> datetime:
        return datetime.now(UTC)

    @staticmethod
    def duration(seconds: int) -> str:
        if seconds < 60:
            return f"{seconds} secs"
        if seconds < 3600:
            return f"{seconds // 60} mins"
        if seconds < 86400:
            return f"{seconds // 3600} hours"
        return f"{seconds // 86400} days"

    @staticmethod
    def nagios_exit(status: str, message: str) -> NoReturn:
        codes = {"OK": 0, "WARNING": 1, "CRITICAL": 2, "UNKNOWN": 3}
        print(f"{status} - {message}")
        raise SystemExit(codes[status])


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check the Canonical Livepatch client status"
    )
    parser.add_argument(
        "--warning-seconds",
        "-w",
        type=int,
        default=CheckCanonicalLivepatchStatus.DEFAULT_WARNING_SECONDS,
        help="warn when the last check with the Livepatch server is older than this "
        "(default: %(default)s)",
    )
    parser.add_argument(
        "--critical-seconds",
        "-c",
        type=int,
        default=CheckCanonicalLivepatchStatus.DEFAULT_CRITICAL_SECONDS,
        help="fail when the last check with the Livepatch server is older than this "
        "(default: %(default)s)",
    )
    parser.add_argument(
        "--patching-warning-seconds",
        type=int,
        default=CheckCanonicalLivepatchStatus.DEFAULT_PATCHING_WARNING_SECONDS,
        help="warn when 'patching the kernel' lasts longer than this "
        "(default: %(default)s)",
    )
    parser.add_argument(
        "--pending-warning-seconds",
        type=int,
        default=CheckCanonicalLivepatchStatus.DEFAULT_PENDING_WARNING_SECONDS,
        help="warn when patches are downloaded but the module is not inserted "
        "for longer than this (default: %(default)s)",
    )
    parser.add_argument(
        "--state-file",
        default=CheckCanonicalLivepatchStatus.DEFAULT_STATE_FILE,
        help="file remembering since when a patch is in progress "
        "(default: %(default)s)",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    try:
        check = CheckCanonicalLivepatchStatus(
            args.warning_seconds,
            args.critical_seconds,
            args.state_file,
            args.patching_warning_seconds,
            args.pending_warning_seconds,
            args.verbose,
        )
    except ValueError as error:
        parser.error(str(error))
    check.check_status()


if __name__ == "__main__":  # pragma: no cover
    main()
