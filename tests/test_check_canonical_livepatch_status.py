import subprocess
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from check_canonical_livepatch_status import (
    CheckCanonicalLivepatchStatus,
    LivepatchError,
    main,
)

NOW = datetime(2026, 10, 25, 15, 15, tzinfo=UTC)
OUTPUTS = Path(__file__).parent / "Outputs"
OK_KERNEL = "✓ kernel series 5.4 is covered by Livepatch"
OK_PATCH = "✓ all applicable live kernel patch modules applied"


def status_output(
    kernel_state: str | None = OK_KERNEL,
    patch_state: str | None = OK_PATCH,
    check_in: str | None = "succeeded",
    last_check: str | None = "52 seconds ago",
) -> str:
    lines = {
        "last check": last_check,
        "kernel": "5.4.0-216.236-generic",
        "server check-in": check_in,
        "kernel state": kernel_state,
        "patch state": patch_state,
        "patch version": "113.1",
        "tier": "updates (Free usage; This machine beta tests new patches.)",
        "machine id": "abc123",
    }
    return "\n".join(f"{key}: {value}" for key, value in lines.items() if value) + "\n"


@pytest.fixture
def state_file(tmp_path: Path) -> Path:
    return tmp_path / "livepatch.state"


def make_check(state_file: Path, **kwargs) -> CheckCanonicalLivepatchStatus:
    check = CheckCanonicalLivepatchStatus(
        state_file=str(state_file), verbose=True, **kwargs
    )
    check.get_current_time = MagicMock(return_value=NOW)
    return check


def run_check(check: CheckCanonicalLivepatchStatus, output: str, capsys):
    check.run_status = MagicMock(return_value=output)
    with pytest.raises(SystemExit) as exit_info:
        check.check_status()
    return exit_info.value.code, capsys.readouterr().out.strip()


def completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_main_constructs_and_runs_checker() -> None:
    args = [
        "check_canonical_livepatch_status.py",
        "--warning-seconds",
        "3600",
        "--critical-seconds",
        "7200",
        "--patching-warning-seconds",
        "600",
        "--pending-warning-seconds",
        "1200",
        "--state-file",
        "/tmp/x.state",
        "--verbose",
    ]
    with (
        patch("sys.argv", args),
        patch("check_canonical_livepatch_status.CheckCanonicalLivepatchStatus") as cls,
    ):
        main()
    cls.assert_called_once_with(
        3600, 7200, "/tmp/x.state", 600, 1200, True
    )
    cls.return_value.check_status.assert_called_once_with()


def test_main_rejects_invalid_thresholds() -> None:
    args = ["check_canonical_livepatch_status.py", "-w", "10", "-c", "5"]
    with patch("sys.argv", args), pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 2


@pytest.mark.parametrize(
    "kwargs",
    [
        {"warning_seconds": 0},
        {"critical_seconds": -1},
        {"warning_seconds": 60, "critical_seconds": 60},
        {"warning_seconds": 120, "critical_seconds": 60},
        {"patching_warning_seconds": 0},
        {"pending_warning_seconds": 0},
    ],
)
def test_invalid_thresholds(kwargs) -> None:
    with pytest.raises(ValueError):
        CheckCanonicalLivepatchStatus(**kwargs)


def test_verbatim_documented_output_is_ok(state_file, capsys) -> None:
    check = make_check(state_file)
    code, out = run_check(check, (OUTPUTS / "ok.txt").read_text(), capsys)
    assert code == 0
    assert out == (
        "OK - kernel 5.4.0-216.236-generic: kernel series 5.4 is covered by "
        "Livepatch; all applicable live kernel patch modules applied "
        "(patch version 113.1)"
    )


def test_ok_without_patch_version(state_file, capsys) -> None:
    check = make_check(state_file)
    output = status_output().replace("patch version: 113.1\n", "")
    code, out = run_check(check, output, capsys)
    assert code == 0
    assert "patch version" not in out


@pytest.mark.parametrize(
    ("kernel_state", "code"),
    [
        ("✓ kernel series 5.4 is covered by Livepatch", 0),
        (
            ("✓ kernel 5.4.0-216 is covered by Livepatch until 2026-12-01, "
            "please install available kernel updates and reboot before then"),
            1,
        ),
        ("✗ kernel is not covered by Livepatch", 2),
        ("✗ kernel is no longer covered by Livepatch", 2),
        ("✗ Livepatch coverage has ended; please upgrade the kernel and reboot", 2),
        (
            ("✗ Livepatch coverage ended 2026-01-01; please upgrade the kernel "
            "and reboot"),
            2,
        ),
        (
            ("✗ unable to determine kernel support status; please contact "
            "Canonical support"),
            3,
        ),
        ("✗ something brand new", 3),
    ],
)
def test_kernel_states(kernel_state, code, state_file, capsys) -> None:
    check = make_check(state_file)
    result, out = run_check(check, status_output(kernel_state=kernel_state), capsys)
    assert result == code
    if code:
        assert kernel_state.lstrip("✓✗ ") in out or "unknown kernel state" in out


@pytest.mark.parametrize(
    ("patch_state", "code"),
    [
        ("✓ all applicable live kernel patch modules applied", 0),
        ("✓ no live kernel patches available for kernel 5.4.0-216-generic", 0),
        ("✓ kernel upgraded after a reboot", 0),
        (
            ("✗ kernel 5.4.0-216-generic contains a vulnerability that cannot be "
            "remediated with live kernel patching, please upgrade and reboot"),
            1,
        ),
        ("✗ Livepatch kernel module inserted but kernel bug detected", 2),
        (
            ("✗ detected a crash last time the Livepatch kernel module was applied, "
            "check system logs with journalctl -f -u "
            "snap.canonical-livepatch.canonical-livepatchd"),
            2,
        ),
        (
            ("✗ unknown error occurred, please check system logs with journalctl "
            "-f -u snap.canonical-livepatch.canonical-livepatchd"),
            2,
        ),
        ("✗ failed to verify the signature of the Livepatch kernel module", 2),
        ("✗ failed to extract information about the Livepatch kernel module", 2),
        (
            ("✗ failed to load certificate used to verify the signature of the "
            "Livepatch kernel module"),
            2,
        ),
        (
            ("✗ failed to confirm that the Livepatch kernel module was applied "
            "successfully"),
            2,
        ),
        ("✗ something brand new", 3),
    ],
)
def test_patch_states(patch_state, code, state_file, capsys) -> None:
    check = make_check(state_file)
    result, out = run_check(check, status_output(patch_state=patch_state), capsys)
    assert result == code
    assert out.startswith(("OK", "WARNING", "CRITICAL", "UNKNOWN"))


def test_non_progress_state_removes_state_file(state_file, capsys) -> None:
    state_file.write_text("{}")
    check = make_check(state_file)
    run_check(check, status_output(), capsys)
    assert not state_file.exists()


def test_reset_survives_unremovable_state_file(state_file, capsys) -> None:
    check = make_check(state_file)
    with patch.object(Path, "unlink", side_effect=PermissionError("denied")):
        code, _ = run_check(check, status_output(), capsys)
    assert code == 0


def test_worst_state_wins_and_only_affected_are_listed(state_file, capsys) -> None:
    check = make_check(state_file)
    output = status_output(
        kernel_state="✗ kernel is no longer covered by Livepatch",
        patch_state="✗ failed to verify the signature of the Livepatch kernel module",
        check_in="failed",
    )
    code, out = run_check(check, output, capsys)
    assert code == 2
    assert out == (
        "CRITICAL - kernel is no longer covered by Livepatch; "
        "failed to verify the signature of the Livepatch kernel module; "
        "server check-in failed"
    )


def test_critical_beats_warning_and_unknown(state_file, capsys) -> None:
    check = make_check(state_file)
    output = status_output(
        kernel_state="✓ kernel 5.4 is covered by Livepatch until 2026-12-01, reboot",
        patch_state="✗ something brand new",
        check_in="failed",
    )
    code, out = run_check(check, output, capsys)
    assert code == 2
    assert out == "CRITICAL - server check-in failed"


def test_missing_states_are_unknown(state_file, capsys) -> None:
    check = make_check(state_file)
    code, out = run_check(check, status_output(patch_state=None), capsys)
    assert code == 3
    assert "patch state is missing" in out
    code, out = run_check(check, status_output(kernel_state=None), capsys)
    assert code == 3
    assert "kernel state is missing" in out


def test_missing_check_in_is_unknown(state_file, capsys) -> None:
    check = make_check(state_file)
    code, out = run_check(check, status_output(check_in=None), capsys)
    assert code == 3
    assert "server check-in is missing" in out


def test_output_without_any_state_is_unknown(state_file, capsys) -> None:
    check = make_check(state_file)
    code, out = run_check(check, "Machine is not enabled\n", capsys)
    assert code == 3
    assert "could not find any Livepatch state" in out


def test_parse_status_ignores_indented_and_empty_keys(state_file) -> None:
    check = make_check(state_file)
    output = "  indented: x\n: nokey\nkernel state: ✓ fine\nplain line\n"
    assert check.parse_status(output) == {"kernel state": "fine"}


# --- in-progress states -----------------------------------------------------

PATCHING = "⧗ patching the kernel"
PENDING = "⧗ live kernel patches are downloaded, but the kernel module is not yet inserted"


@pytest.mark.parametrize("patch_state", [PATCHING, PENDING])
def test_in_progress_first_seen_is_ok_and_recorded(
    patch_state, state_file, capsys
) -> None:
    check = make_check(state_file)
    code, out = run_check(check, status_output(patch_state=patch_state), capsys)
    assert code == 0
    assert "for 0 secs" in out
    assert state_file.exists()


@pytest.mark.parametrize(
    ("patch_state", "stage", "age", "code"),
    [
        (PATCHING, "patching", 7200, 0),
        (PATCHING, "patching", 7201, 1),
        (PENDING, "pending", 7200, 0),
        (PENDING, "pending", 7201, 1),
    ],
)
def test_in_progress_stall_detection(
    patch_state, stage, age, code, state_file, capsys
) -> None:
    since = int(NOW.timestamp()) - age
    state_file.write_text(f'{{"stage": "{stage}", "since": {since}}}')
    check = make_check(state_file)
    result, out = run_check(check, status_output(patch_state=patch_state), capsys)
    assert result == code
    if code:
        assert "check manually" in out and "limit" in out


def test_in_progress_custom_limit(state_file, capsys) -> None:
    since = int(NOW.timestamp()) - 700
    state_file.write_text(f'{{"stage": "patching", "since": {since}}}')
    check = make_check(state_file, patching_warning_seconds=600)
    code, _ = run_check(check, status_output(patch_state=PATCHING), capsys)
    assert code == 1


def test_stage_change_restarts_timer(state_file, capsys) -> None:
    since = int(NOW.timestamp()) - 100000
    state_file.write_text(f'{{"stage": "pending", "since": {since}}}')
    check = make_check(state_file)
    code, out = run_check(check, status_output(patch_state=PATCHING), capsys)
    assert code == 0
    assert "for 0 secs" in out


@pytest.mark.parametrize(
    "content", ["not json", "[]", "{}", '{"stage": "patching", "since": "x"}']
)
def test_corrupt_state_file_is_treated_as_first_seen(
    content, state_file, capsys
) -> None:
    state_file.write_text(content)
    check = make_check(state_file)
    code, out = run_check(check, status_output(patch_state=PATCHING), capsys)
    assert code == 0
    assert "for 0 secs" in out


def test_unwritable_state_file_is_unknown(tmp_path, capsys) -> None:
    check = make_check(tmp_path / "missing-dir" / "livepatch.state")
    code, out = run_check(check, status_output(patch_state=PATCHING), capsys)
    assert code == 3
    assert "could not write state file" in out


def test_in_progress_leaving_progress_clears_timer(state_file, capsys) -> None:
    check = make_check(state_file)
    run_check(check, status_output(patch_state=PATCHING), capsys)
    run_check(check, status_output(), capsys)
    assert not state_file.exists()


# --- last check -------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "seconds"),
    [
        ("52 seconds ago", 52),
        ("1 minute ago", 60),
        ("3 minutes ago", 180),
        ("an hour ago", 3600),
        ("2 hours ago", 7200),
        ("5 days ago", 432000),
        ("1 week ago", 604800),
        ("a month ago", 2592000),
        ("a year ago", 31536000),
        ("less than 1 second ago", 1),
        ("garbage", None),
        (None, None),
    ],
)
def test_parse_age(text, seconds, state_file) -> None:
    assert make_check(state_file).parse_age(text) == seconds


@pytest.mark.parametrize(
    ("last_check", "code"),
    [
        ("30 minutes ago", 0),
        ("3 hours ago", 1),
        ("2 days ago", 2),
        ("garbage", 3),
        (None, 3),
    ],
)
def test_last_check_thresholds(last_check, code, state_file, capsys) -> None:
    check = make_check(state_file, warning_seconds=7200, critical_seconds=86400)
    result, _ = run_check(check, status_output(last_check=last_check), capsys)
    assert result == code


def test_last_check_warning_only(state_file, capsys) -> None:
    check = make_check(state_file, warning_seconds=60)
    code, out = run_check(check, status_output(last_check="2 hours ago"), capsys)
    assert code == 1
    assert out == "WARNING - last check 2 hours ago"


def test_last_check_ignored_without_thresholds(state_file, capsys) -> None:
    check = make_check(state_file)
    code, _ = run_check(check, status_output(last_check="5 days ago"), capsys)
    assert code == 0


# --- running the command ----------------------------------------------------


def test_run_status_returns_stdout(state_file) -> None:
    check = make_check(state_file)
    with patch("subprocess.run", return_value=completed("hello")) as run:
        assert check.run_status() == "hello"
    assert run.call_args.args[0] == ["canonical-livepatch", "status"]


@pytest.mark.parametrize(
    "error",
    [FileNotFoundError("not found"), subprocess.TimeoutExpired("cmd", 15)],
)
def test_run_status_command_failure(error, state_file) -> None:
    check = make_check(state_file)
    with patch("subprocess.run", side_effect=error), pytest.raises(LivepatchError):
        check.run_status()


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (completed(stderr="Machine is not enabled", returncode=1), "not enabled"),
        (completed(stdout="stdout text", returncode=2), "stdout text"),
        (completed(returncode=1), "no output"),
    ],
)
def test_run_status_non_zero_exit(result, expected, state_file, capsys) -> None:
    check = make_check(state_file)
    with patch("subprocess.run", return_value=result):
        code = None
        with pytest.raises(SystemExit) as exit_info:
            check.check_status()
        code = exit_info.value.code
    out = capsys.readouterr().out
    assert code == 3
    assert expected in out


def test_run_status_failure_exits_unknown(state_file, capsys) -> None:
    check = make_check(state_file)
    with (
        patch("subprocess.run", side_effect=FileNotFoundError("nope")),
        pytest.raises(SystemExit) as exit_info,
    ):
        check.check_status()
    assert exit_info.value.code == 3
    assert "UNKNOWN - could not run canonical-livepatch" in capsys.readouterr().out


def test_end_to_end_through_subprocess(state_file, capsys) -> None:
    check = make_check(state_file)
    with (
        patch("subprocess.run", return_value=completed(status_output())),
        pytest.raises(SystemExit) as exit_info,
    ):
        check.check_status()
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.startswith("OK - kernel 5.4.0-216.236-generic")


@pytest.mark.parametrize(
    ("seconds", "text"),
    [(5, "5 secs"), (120, "2 mins"), (7200, "2 hours"), (172800, "2 days")],
)
def test_duration(seconds, text) -> None:
    assert CheckCanonicalLivepatchStatus.duration(seconds) == text


def test_get_current_time_is_timezone_aware() -> None:
    assert CheckCanonicalLivepatchStatus.get_current_time().tzinfo is not None


def test_nagios_exit_codes(capsys) -> None:
    for status, code in (("OK", 0), ("WARNING", 1), ("CRITICAL", 2), ("UNKNOWN", 3)):
        with pytest.raises(SystemExit) as exit_info:
            CheckCanonicalLivepatchStatus.nagios_exit(status, "msg")
        assert exit_info.value.code == code
        assert capsys.readouterr().out == f"{status} - msg\n"
