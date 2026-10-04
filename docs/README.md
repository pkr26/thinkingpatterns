# Documentation

Start with the [repository overview](../README.md) or the guide relevant to your task.

## Development and design

| Guide | Contents |
| --- | --- |
| [Development](development.md) | Local setup, demo data, migrations, and validation |
| [Contributing](../CONTRIBUTING.md) | Code, dependency, testing, and documentation conventions |
| [Architecture](architecture.md) | Encryption, session custody, sharing, and supported deployment model |
| [API contract](api.md) | Route versions, pagination, authentication, and error codes |
| [Analysis](analysis.md) | Pattern kinds, evidence, thresholds, and on-device analysis |
| [Configuration](configuration.md) | Environment variables and deletion/retention behavior |
| [Research](research.md) | Scientific sources and detector design rationale |
| [Web threat model](WEB_THREAT_MODEL.md) | Browser-specific trust boundaries and protections |
| [TEE design](TEE_ATTESTATION_DESIGN.md) | Proposed attestation boundary and implementation constraints |

## Operations and release validation

- [Production deployment](../deploy/README.md), [monitoring](../deploy/monitoring/README.md), and [backups](../backup/README.md)
- [Operator pack](OPERATOR_PACK.md): privacy, retention, subprocessors, and compliance templates
- [Security policy](SECURITY_POLICY.md), [incident response](INCIDENT_RUNBOOK.md), and [documented residual risks](SECURITY_RESIDUALS.md)
- [Current remediation status](remediation-status.md) and [quality roadmap](plans/quality-roadmap.md)
- [Independent validation](VALIDATION_TO_90.md), [audit issues](INDEPENDENT_AUDIT_ISSUES.md), and [study protocol](IRB_STUDY_PROTOCOL.md)
- [Validation evidence](../reports/README.md) and [audit archive](archive/README.md)

## Planning history

The [original build plan](plans/build-plan.md), [web plan](plans/web-plan.md),
and [voice plan](plans/voice-plan.md) preserve design decisions and implementation
history. They may describe superseded behavior; use the current component
guides and remediation status when implementing changes.
