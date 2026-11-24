# Repository Guidelines

- Code: `check_canonical_livepatch_status.py` (CLI in `main()`, logic in `CheckCanonicalLivepatchStatus`). Tests: `tests/test_check_canonical_livepatch_status.py`, sample client output in `tests/Outputs/`. Python >=3.12, no runtime dependencies.
- Setup: `uv sync --locked --all-extras --dev`
- Lint: `uv run ruff check`
- Test (as in CI): `uv run pytest --cov=check_canonical_livepatch_status`
- Style: standard Python, type annotations kept, tests named `test_<behavior>`.
- Tests mock `subprocess.run`, time and `nagios_exit`; they stay offline and deterministic.
- Every documented `kernel state` and `patch state` string needs a test. Unrecognized output must be UNKNOWN, never OK.
- Commits: short, imperative summaries.
