# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-01-XX

### Added
- Multi-cloud compliance scanning for AWS, Azure, and GCP
- AWS S3 bucket compliance checking with GDPR rules
- Azure Blob Storage container compliance checking
- GCP Cloud Storage bucket compliance checking
- AI-driven risk assessment with heuristic scoring
- Beautiful CLI interface using Rich library
- Comprehensive test suite with mocking support
- Professional documentation and setup guides
- Plugin architecture for extensibility
- GitHub Actions CI/CD workflows
- Issue and PR templates
- Code of Conduct
- Development Makefile for common tasks

### Features
- **Multi-Cloud Support**: Scan AWS S3, Azure Blob, and GCP Storage resources
- **GDPR Compliance**: Comprehensive compliance rules for data protection
- **Risk Assessment**: AI-driven risk scoring (0-100 scale)
- **Rich CLI**: Beautiful terminal output with tables, progress bars, and colors
- **Plugin System**: Extensible architecture for new cloud providers and compliance frameworks
- **Testing**: Full test coverage with mocked AWS services using moto
- **CI/CD**: Automated testing and release workflows on GitHub Actions

### Technical Details
- Python 3.9+ support
- Pydantic models for data validation
- Click CLI framework
- Rich for terminal UI
- pytest for testing
- moto for AWS mocking
- Pre-commit hooks for code quality

## [0.0.1] - 2024-12-XX

### Added
- Initial project structure
- Basic CLI framework
- Pydantic models for compliance reports
- Foundation for multi-cloud support

[Unreleased]: https://github.com/wipenode/secomp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/wipenode/secomp/releases/tag/v0.1.0
[0.0.1]: https://github.com/wipenode/secomp/releases/tag/v0.0.1
