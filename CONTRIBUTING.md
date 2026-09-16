# Contributing

## Setup

```bash
python -m venv .venv
source .venv/bin/activate  # .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

## Workflow

```bash
ruff check .          # lint
ruff format --check . # formatting
mypy src              # type check
pytest                # tests
python -m build        # build the sdist/wheel
```

All four must pass before a pull request is merged; CI runs the same checks.

## Ground rules

- This SDK is a typed API client, not a risk-scoring engine. Do not add client-side logic that
  recomputes, derives, or overrides `risk.index`, `risk.band`, or any detection flag -- those values
  come from the server only.
- Preserve tri-state semantics (`True` / `False` / `None`) on every detection flag. Never coerce
  `None` to `False`, and never coerce a missing/`null` `risk.index` to `0`.
- Unknown fields returned by the API must be ignored, not raise -- this keeps older SDK versions
  working against a server that has added new fields.
- Do not read `process.env`-style configuration beyond what's documented (`NETRISKSCAN_API_KEY`).

## Releasing

Version is set in `pyproject.toml` (`[project].version`) and mirrored in `src/netriskscan/version.py`.
To release: bump both, update `CHANGELOG.md`, commit, then push a `vX.Y.Z` tag -- `.github/workflows/publish.yml`
builds and publishes to PyPI via Trusted Publishing (OIDC), no stored token required. Before the very
first release, a maintainer must register this repository as a pending trusted publisher for the
`netriskscan` project at https://pypi.org/manage/account/publishing/ (one-time manual step, since the
project does not exist on PyPI yet).

## Reporting bugs / requesting features

Open a [GitHub issue](https://github.com/TeamQQ/netriskscan-sdk-python/issues).

## Security issues

See [SECURITY.md](SECURITY.md) -- do not open a public issue.
