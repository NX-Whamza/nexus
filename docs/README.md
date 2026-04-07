# NEXUS Documentation

This directory is the canonical documentation set for the repository.

## Start Here

| Document | Purpose | Audience |
|----------|---------|----------|
| [../README.md](../README.md) | Project overview and main setup paths | Everyone |
| [QUICK_START_EXE.md](QUICK_START_EXE.md) | EXE/package usage | End users |
| [UAT_VM_DEPLOYMENT_RUNBOOK.md](UAT_VM_DEPLOYMENT_RUNBOOK.md) | UAT/dev deployment on the VM | IT/devs |
| [../vm_deployment/DOMAIN_SETUP.md](../vm_deployment/DOMAIN_SETUP.md) | Production domain and nginx setup | IT/devs |

## Core Guides

| Document | Purpose |
|----------|---------|
| [COMPLETE_DOCUMENTATION.md](COMPLETE_DOCUMENTATION.md) | Full system documentation |
| [SECURITY_SETUP.md](SECURITY_SETUP.md) | Secrets, auth, and security setup |
| [DISTRIBUTION_GUIDE.md](DISTRIBUTION_GUIDE.md) | Packaging and distribution notes |
| [NOC_CONFIG_SUITE_SOP.md](NOC_CONFIG_SUITE_SOP.md) | Operational SOP |
| [API_REFERENCE.md](API_REFERENCE.md) | API reference overview |
| [API_V2.md](API_V2.md) | API v2 contract notes |

## Project References

| Document | Purpose |
|----------|---------|
| [../CHANGELOG.md](../CHANGELOG.md) | Version history |
| [../PRODUCTION_READY_SUMMARY.md](../PRODUCTION_READY_SUMMARY.md) | Production deployment summary |
| [../ENV_TEMPLATE.txt](../ENV_TEMPLATE.txt) | Environment template |
| [MIKROTIK_BACKEND_MIGRATION_PLAN.md](MIKROTIK_BACKEND_MIGRATION_PLAN.md) | Backend migration notes |
| [OMNI_HANDOFF.md](OMNI_HANDOFF.md) | OMNI integration handoff |
| [UI_API_PARITY.md](UI_API_PARITY.md) | UI/API parity tracking |

## Configuration Policies

Located in `../config_policies/`:
- [POLICY_INDEX.md](../config_policies/POLICY_INDEX.md)
- [router-interface-policy.md](../config_policies/nextlink/router-interface-policy.md)

## Notes

- Production deployment is Docker-based.
- Host nginx should proxy to the Docker frontend on port `8000`.
- The duplicated `vm_deployment/docs/` tree has been removed; maintain docs only in `docs/`.
