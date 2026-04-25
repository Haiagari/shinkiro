# Contributing to OzyRecon

First off, thank you for considering contributing to OzyRecon! It's people like you that make OzyRecon a powerful tool for the community.

### 📜 Our Standards
We follow **Clean Architecture** and **Strict TypeScript/Python patterns**. Before you start:
1. Ensure your code follows the [Architecture Guide](docs/architecture.md).
2. All new features **must** include tests.
3. No sensitive data (domains, keys, IPs) should be hardcoded.

### 🚀 Getting Started
1. Fork the repository.
2. Create a new branch: `git checkout -b feature/my-amazing-feature`.
3. Install dev dependencies: `pip install -r requirements-dev.txt`.
4. Make your changes.

### 🧪 Testing
We take testing seriously. We have 43+ integration and unit tests that must pass.
```bash
pytest tests/
```

### 📝 Commit Messages
We follow [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` for new features.
- `fix:` for bug fixes.
- `docs:` for documentation changes.
- `refactor:` for code changes that neither fix a bug nor add a feature.

### 📬 Pull Request Process
1. Update the `README.md` if your change adds functionality.
2. Update the `CHANGELOG.md` under the `[Unreleased]` section.
3. The PR will be reviewed by at least one maintainer.
4. Once approved, it will be merged into `main`.

---
**Questions?** Open an issue or join our community discussions.
