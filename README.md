# Fathom

Fathom is an encrypted journaling application that helps people recognize
patterns in their mental state. It combines a patient web client, a native
mobile app, a therapist portal, and a FastAPI service.

After 30 distinct active journaling days, the deterministic analysis engine
can surface patterns with supporting evidence and a reflective question.
The product provides observations, not diagnosis, treatment, or advice.

The code, package names, native project names, and `MINDPATTERN_*` environment
variables retain the original **MindPattern** identifier for compatibility.

## Repository layout

| Directory | Purpose |
| --- | --- |
| [backend/](backend/) | Python API, analysis engine, migrations, and regression tests |
| [web/](web/) | React patient client using browser cryptography |
| [mobile/](mobile/) | React Native app and native iOS/Android projects |
| [portal/](portal/) | React therapist portal for consented access and private notes |
| [shared/](shared/) | Cross-platform cryptographic fixtures, analysis vectors, and language catalogs |
| [deploy/](deploy/) | Production deployment, monitoring, and offsite backup configuration |
| [backup/](backup/) | Authenticated database backup tooling |
| [tools/](tools/) | Repository validation and migration checks |
| [redteam/](redteam/) | Security harnesses and mutation-testing campaigns |
| [e2e_gui/](e2e_gui/) | Synthetic accounts for manual browser drills |
| [docs/](docs/README.md) | Architecture, development, operations, research, and plans |
| [reports/](reports/README.md) | Dated validation evidence and reproducible simulations |

## Local development

Use Python 3.12 or newer and the Node.js version in [.nvmrc](.nvmrc).
Run the API and each client in separate terminals, starting at the repository
root. Production configuration fails closed; local commands explicitly select
development mode.

```sh
cd backend
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.dev.lock.txt
MINDPATTERN_ENV=development uvicorn app.main:app --reload
```

The API listens on `http://localhost:8000`; development API documentation is
available at `http://localhost:8000/docs`.

```sh
cd web
npm ci
npm run dev
```

The patient client proxies `/api` to the local API. The therapist portal uses
the same commands from `portal/`. For native prerequisites and platform
commands, see [mobile/README.md](mobile/README.md).

The [development guide](docs/development.md) covers Docker, synthetic demo
accounts, database migrations, and validation commands.

## Validation

Run checks from the relevant component directory:

| Component | Checks |
| --- | --- |
| Backend | `ruff check .`, `ruff format --check .`, `python -m mypy`, `python -m pytest` |
| Patient web and therapist portal | `npm run typecheck`, `npm test`, `npm run build` |
| Mobile | `npm run typecheck`, `npm test`, `npm run verify:vectors`, `npm run verify:native-release` |
| Repository tooling (from root) | `python -m unittest discover -s tools/tests -v`, `python tools/check-docs.py` |

[CI](.github/workflows/ci.yml) also validates PostgreSQL, native builds,
deployment contracts, dependency security, and shared vectors. Install the
configured [pre-commit hooks](.pre-commit-config.yaml) with `pre-commit install`.
See [CONTRIBUTING.md](CONTRIBUTING.md) for maintenance conventions.

## Security and release status

Clients encrypt journal content before storage or sync. An explicitly
requested server analysis temporarily receives the data key in a single-use
processing session; the service can read journal content during that request.
This is not a hardware enclave or an unconditional zero-knowledge guarantee.

Therapist access requires explicit patient consent. Keys, session custody,
revocation limits, and the supported single-process deployment are described
in the [architecture guide](docs/architecture.md). Deployment and retention
requirements are documented in the [operator pack](docs/OPERATOR_PACK.md) and
[configuration reference](docs/configuration.md).

Current implementation status and remaining release gates are tracked in
[remediation status](docs/remediation-status.md) and the
[quality roadmap](docs/plans/quality-roadmap.md). Historical test reports are
scoped evidence; they do not establish clinical benefit or release readiness.
The [documentation index](docs/README.md) links research, API contracts,
operational runbooks, and the audit archive.

## License

[MIT](LICENSE).
