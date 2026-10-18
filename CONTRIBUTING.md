# Contributing

Thank you for helping improve `oidc-audit`.

## Ground rules

- Audit only configurations you own or are authorized to assess.
- Never commit real realm exports, client secrets, tokens, private keys,
  personal data, or production URLs.
- Every rule needs a focused fixture, a clean false-positive test, remediation,
  and a precise primary reference.
- Open an issue before making a large behavioral or schema change.

## Local workflow

1. Create a virtual environment and run `python -m pip install -e '.[dev]'`.
2. Add or update offline tests.
3. Run `ruff check .`, `ruff format --check .`, `mypy src`, and `pytest`.
4. Update the README and rule catalogue when behavior changes.

Use short, imperative commit subjects. Pull requests should explain the
security use case, test coverage, citation, and compatibility impact.

