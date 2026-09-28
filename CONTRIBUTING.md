# Contributing

1. Fork, then `python -m venv .venv && . .venv/bin/activate` (Windows: `.venv\Scripts\activate`)
2. `pip install -r requirements-dev.txt && pip install -e .`
3. Run `ruff check .` and `pytest` before every PR.
4. Keep business logic out of `paashaa/gui/` so it stays unit-testable.
5. Any change touching crypto, OTP or auth needs tests and a note in the PR description.

Use conventional commit messages (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
