# Contributing to Upstream Healer

## Overview
This document provides guidelines for contributing to the Upstream Healer project. We welcome contributions from the community to help improve and extend this tool.

## How to Contribute

### Reporting Issues
If you find a bug or have a feature request:
1. Check existing issues to avoid duplicates
2. Create a new issue with detailed description
3. Include steps to reproduce (for bugs)
4. Add relevant labels and assignees when possible

### Submitting Pull Requests
1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes following the coding standards
4. Add or update tests as needed
5. Document any API changes
6. Submit a pull request with clear description

## Development Workflow

### Setting Up Development Environment
```bash
# Clone the repository
git clone https://192.168.86.38:32768/monster/upstream_healer.git
cd upstream-healer

# Install development dependencies
pip install -r requirements.txt -r requirements-dev.txt

# Run tests to verify setup
python3 -m pytest tests/ -v
python3 -m ruff check app/ scripts/ tests/
```

### Code Style and Standards
- Follow PEP 8 coding standards
- Use ruff for code formatting (E+F rules with long lines allowed)
- Maintain 70%+ test coverage
- Write clear, descriptive commit messages

### Testing Guidelines
1. All new features must include unit tests
2. E2E tests should cover critical workflows
3. Tests should be isolated and deterministic
4. Update test coverage when adding new functionality

## Documentation Standards

### API Documentation
When adding or modifying API endpoints:
1. Update the API reference documentation
2. Add appropriate docstrings to functions
3. Include example usage in documentation

### Process Documentation
When updating processes:
1. Reference the pipeline and testing process documents
2. Keep information current with implementation changes
3. Update any relevant workflow diagrams or process descriptions

## Code Review Process

1. All pull requests require review by maintainers
2. Code must pass all tests (linting, unit, E2E)
3. Documentation must be updated for API changes
4. Coverage requirements must be maintained or improved
5. Security considerations should be reviewed

## Branching Strategy

### Main Branch
- Contains stable, production-ready code
- Only updated through pull requests from feature branches

### Feature Branches
- Created for new features or bug fixes
- Should be named descriptively (e.g., `feature/add-notification-types`)
- Should be kept up-to-date with main branch

### Release Branches
- Created for release preparation
- Used to make final adjustments before release

## Versioning

This project follows semantic versioning:
- Major versions: Breaking changes
- Minor versions: New features and enhancements
- Patch versions: Bug fixes and documentation updates

## License

By contributing to this project, you agree that your contributions will be licensed under the same license as the project (see LICENSE file).

## Community Guidelines

1. Be respectful and constructive in all interactions
2. Follow the code of conduct
3. Help others with questions and issues
4. Share knowledge and best practices
5. Keep discussions focused on improving the project

## Contact

For questions about contributing, please:
- Open an issue on GitLab
- Contact the maintainers directly
- Join discussions in the project's communication channels (if available)