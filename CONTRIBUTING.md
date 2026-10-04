# Contributing

Read the [development guide](docs/development.md) for setup and verification.
Each application owns its dependencies, tests, and build configuration.

## Code conventions

- Use descriptive names that explain the domain or operation. Preserve public
  API fields, encrypted payload formats, database identifiers, and native
  project identifiers unless a change includes an explicit migration.
- Keep comments focused on invariants, security boundaries, surprising behavior,
  and compatibility constraints. Put audit chronology and task status in the
  relevant report or plan.
- Remove code only after checking imports, dynamic entry points, build scripts,
  native wiring, and regression coverage. Shared vectors and historical
  migrations are maintained compatibility assets.
- Follow each component's existing style. Python code uses Ruff and mypy;
  TypeScript application code uses strict compiler checks. Fix errors instead
  of disabling checks for an entire source file.
- Keep regression tests that explain a failure mode. Add behavioral coverage
  when changing a contract; avoid assertions that merely duplicate source text.

## Dependencies and generated files

Use `npm ci` for JavaScript packages and the hash-checked Python requirement
locks for development and CI. When changing a dependency, update the owning
manifest and lockfiles together. Backend direct requirements, package metadata,
and the uv lock must remain consistent. Review native dependency patches and
lockfiles as part of mobile dependency changes.

Do not commit runtime databases, recordings, credentials, build output, caches,
or screenshots containing journal content. The [ignore rules](.gitignore)
cover local artifacts. Published synthetic validation evidence in `reports/`
is intentionally retained with its source and provenance.

Generated shared fixtures and catalogs have producers under `backend/scripts/`
and client `tools/` directories. Regenerate them through those tools and run
the corresponding cross-platform checks.

## Verification and review

Run the checks for every component affected by a change, including consumers
of shared fixtures or API contracts. Run repository tooling tests when changing
backup, release, mutation, or evidence tooling. CI adds PostgreSQL integration,
native builds, dependency audits, and deployment checks.

Keep documentation links valid with `python tools/check-docs.py`. Update the
[API reference](docs/api.md) when changing error codes; that command checks the
reference against the backend's emitted codes. Keep current guidance in `docs/`
and dated findings in `docs/archive/` or `reports/`.

Describe the behavior changed, its reason, and the checks run in each change
summary. Identify any verification that could not run locally.
