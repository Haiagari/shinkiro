# Skill Registry - OzyRecon

**Generated**: Sun Apr 26 2026
**Project**: OzyRecon
**Stack**: Python 3.10+, pytest

## Available Skills

### SDD Workflow (Spec-Driven Development)
| Skill | Purpose | Trigger |
|-------|---------|---------|
| sdd-explore | Explore ideas before committing to change | Investigate feature, investigate codebase |
| sdd-propose | Create change proposal with intent/scope/approach | Create/update proposal |
| sdd-spec | Write specs with requirements/scenarios | Write/update specs |
| sdd-design | Technical design document | Write/update design |
| sdd-tasks | Implementation task checklist | Create/update tasks |
| sdd-apply | Implement tasks from change | Implement code |
| sdd-verify | Validate implementation matches specs | Verify change |
| sdd-archive | Sync to main specs, archive change | Archive completed change |
| sdd-init | Initialize SDD context | "sdd init", "iniciar sdd" |
| sdd-onboard | Guided SDD walkthrough | Full SDD cycle |

### Code Quality
| Skill | Purpose | Trigger |
|-------|---------|---------|
| verification-loop | Build, type-check, lint, test, security | Before PRs |
| tdd-workflow | Test-driven development, 80%+ coverage | Writing features, fixing bugs |
| coding-standards | Node.js/TS best practices (Naming, DRY, YAGNI) | Writing code |

### Git & GitHub
| Skill | Purpose | Trigger |
|-------|---------|---------|
| github-pr | Create PRs with conventional commits | Create PRs |
| branch-pr | PR workflow (issue-first enforcement) | Opening PR, preparing changes |
| git-workflow | Branching, commits, merge vs rebase | Git operations |
| issue-creation | Issue workflow (issue-first) | Creating issues |

### Security
| Skill | Purpose | Trigger |
|-------|---------|---------|
| security-review | OWASP Top 10, XSS, CSRF, input validation | Auth, user input, API endpoints |
| security-engineer | DevSecOps, CI/CD security, vulnerability mgmt | Infrastructure security |
| security-auditor | Code and Dockerfile audit | Security audits |
| cyber-mentor-pro | eJPT, OSCP, DevSecOps mentoring | Security certifications |

### Testing
| Skill | Purpose | Trigger |
|-------|---------|---------|
| e2e-testing | Playwright E2E, POM, CI/CD integration | E2E tests |

### Docker & Deployment
| Skill | Purpose | Trigger |
|-------|---------|---------|
| docker-patterns | Docker, Compose, container security | Docker operations |
| deployment-patterns | CI/CD, health checks, rollback | Deployment |

### Knowledge
| Skill | Purpose | Trigger |
|-------|---------|---------|
| wiki | Obsidian vault management | "wiki setup", "set up vault" |
| wiki-query | Query wiki vault | "wiki query", "what do you know" |
| wiki-save | Save to wiki | "save this", "/save" |
| wiki-ingest | Ingest sources to wiki | "ingest", "add to wiki" |

### Project Conventions

#### Project Files (None found)
- No AGENTS.md, CLAUDE.md, or .cursorrules found

#### SDD Structure
```
openspec/
├── config.yaml
├── specs/
└── changes/
    └── archive/
```

## Notes
- SDD initialized in HYBRID mode (openspec + engram)
- Strict TDD Mode: ENABLED
- Test runner: pytest 9.0.3
- Linter: ruff available (not in project venv but in pyproject.toml)