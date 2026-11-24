# Check_Canonical_Livepatch_Status
[![Build](https://github.com/conFrituur/check_canonical_livepatch_status/actions/workflows/build.yml/badge.svg)](https://github.com/conFrituur/check_canonical_livepatch_status/actions/workflows/build.yml)
[![Coverage](https://raw.githubusercontent.com/conFrituur/check_canonical_livepatch_status/refs/heads/coverage-badge/coverage.svg)](https://github.com/conFrituur/check_canonical_livepatch_status/actions/workflows/build.yml)
[![uv](https://img.shields.io/python/required-version-toml?tomlFilePath=https%3A%2F%2Fraw.githubusercontent.com%2FconFrituur%2Fcheck_canonical_livepatch_status%2Frefs%2Fheads%2Fmain%2Fpyproject.toml&style=flat&logo=python&logoColor=lightgrey
)](https://www.python.org)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)

Icinga/Nagios plugin that checks the Canonical Livepatch client (`canonical-livepatch status`) [official status documentation](https://ubuntu.com/security/livepatch/docs/client/how-to-guides/operations/check-client-status/).

It complements [check_pro_security_status](https://github.com/conFrituur/check_pro_security_status): this looks at pending security updates for the installed packages, the Ubuntu Pro and ESM status and whether a reboot is required.

>**AI NOTICE:** This code was derived from my other check plugins and altered with AI to fit this command.

## Usage

```console
foo@bar:~$ uv run check_canonical_livepatch_status.py --help
usage: check_canonical_livepatch_status.py [-h] [--warning-seconds WARNING_SECONDS]
                                           [--critical-seconds CRITICAL_SECONDS]
                                           [--patching-warning-seconds PATCHING_WARNING_SECONDS]
                                           [--pending-warning-seconds PENDING_WARNING_SECONDS]
                                           [--state-file STATE_FILE] [--verbose]

Check the Canonical Livepatch client status

options:
  -h, --help            show this help message and exit
  --warning-seconds, -w WARNING_SECONDS
                        warn when the last check with the Livepatch server is older than this
                        (default: 10800)
  --critical-seconds, -c CRITICAL_SECONDS
                        fail when the last check with the Livepatch server is older than this
                        (default: 21600)
  --patching-warning-seconds PATCHING_WARNING_SECONDS
                        warn when 'patching the kernel' lasts longer than this (default: 7200)
  --pending-warning-seconds PENDING_WARNING_SECONDS
                        warn when patches are downloaded but the module is not inserted for longer
                        than this (default: 7200)
  --state-file STATE_FILE
                        file remembering since when a patch is in progress (default:
                        /tmp/check_canonical_livepatch_status.state)
  --verbose, -v
```

The plugin always runs `canonical-livepatch status --format humane` directly (the format is forced because the client switches to YAML when its output is not a terminal) (it does not call sudo), so it must run as a user that is allowed to execute the client.

The client checks in every hour by default (`check-interval`, minimum 60 minutes), so `last check` defaults to WARNING after 3 hours (`-w 10800`) and CRITICAL after 6 hours (`-c 21600`).

## States

| Level | Output |
|---|---|
| OK | kernel series covered; all patches applied; no patches available; kernel upgraded after a reboot; patching in progress or downloaded-not-inserted (within limits) |
| WARNING | kernel covered only until a date (reboot needed); unpatchable vulnerability (upgrade and reboot); patching stalled; patches downloaded but not inserted for too long; `last check` older than `-w` |
| CRITICAL | kernel not covered / no longer covered / coverage ended; kernel bug detected; crash; unknown error; signature, certificate, extraction or confirmation failures; server check-in not `succeeded`; `last check` older than `-c` |
| UNKNOWN | client cannot be run or exits non-zero (for example "Machine is not enabled"); unrecognized or missing state; state file not writable |

The client does not report how long a state has lasted, so stalls are detected with a small state file written by the check. Run the check periodically (the Icinga check interval is enough). Any non-progress state removes the file.

Example output:

```
OK - kernel 5.4.0-216.236-generic: kernel series 5.4 is covered by Livepatch; all applicable live kernel patch modules applied (patch version 113.1)
WARNING - patching the kernel for 3 hours (limit 2 hours), check manually
CRITICAL - kernel is no longer covered by Livepatch
```

## Icinga CheckCommand

```icinga2
object CheckCommand "canonical-livepatch-status" {
    import "plugin-check-command"
    command = [ PluginDir + "/check_canonical_livepatch_status" ]
    timeout = 1m
    arguments += {
        "--patching-warning-seconds" = {
            description = "warn when 'patching the kernel' lasts longer than this (default: 7200)"
            repeat_key = false
            required = false
            value = "$livepatch_patching_warning_seconds$"
        }
        "--pending-warning-seconds" = {
            description = "warn when patches are downloaded but the module is not inserted for longer than this (default: 7200)"
            repeat_key = false
            required = false
            value = "$livepatch_pending_warning_seconds$"
        }
        "--state-file" = {
            description = "file remembering since when a patch is in progress (default: /tmp/check_canonical_livepatch_status.state)"
            repeat_key = false
            required = false
            value = "$livepatch_state_file$"
        }
        "-c" = {
            description = "fail when the last check with the Livepatch server is older than this (default: 21600)"
            repeat_key = false
            required = false
            value = "$livepatch_critical_seconds$"
        }
        "-w" = {
            description = "warn when the last check with the Livepatch server is older than this (default: 10800)"
            repeat_key = false
            required = false
            value = "$livepatch_warning_seconds$"
        }
    }
}
```