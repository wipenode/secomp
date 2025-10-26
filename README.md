# Secomp

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://img.shields.io/pypi/v/secomp.svg)](https://pypi.org/project/secomp/)

> **Revolutionary CLI for compliance and risk assessment in multi-cloud environments**

Secomp is a cutting-edge, open-source CLI tool designed to revolutionize cybersecurity compliance and risk assessment. In a world drowning in "tool sprawl" with an average of 45 tools per organization, Secomp emerges as the game-changer that every CISO, pentester, and DevOps engineer will download from GitHub in the first week after launch.

## 🌟 Why Secomp?

- **🚀 One Command Compliance**: `secomp scan --cloud aws --compliance gdpr --output report.json`
- **🧠 AI-Driven Risk Scoring**: Intelligent risk assessment with contextual recommendations
- **🎨 Beautiful Terminal UI**: Colorful, interactive output with progress bars and tables
- **🔌 Plugin Architecture**: Extensible system for new cloud providers and compliance frameworks
- **⚡ Zero Configuration**: Works out-of-the-box with AWS credentials
- **📊 Comprehensive Reporting**: JSON reports with remediation steps and risk analysis

## 🎯 Breaking the Status Quo

Traditional tools like Checkov, Trivy, and Nmap are excellent in their niches, but none solve compliance holistically. Secomp thinks differently:

- **Runtime + Infrastructure**: Scans both configuration and runtime compliance
- **Risk-First Approach**: Prioritizes findings by actual business risk
- **Developer Experience**: As intuitive as `docker run`, as powerful as ZAP in pentesting
- **Community-Driven**: Open-source with plugin system ready for community contributions

## 📦 Installation

### Option 1: PyPI (Recommended)

#### AWS Setup
```bash
# Method 1: Environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key

# Method 2: AWS CLI (recommended)
aws configure

# Method 3: IAM roles (for EC2/ECS)
# No configuration needed - uses instance metadata
```

#### Azure Setup
```bash
# Method 1: Service Principal (recommended)
export AZURE_CLIENT_ID=your_client_id
export AZURE_CLIENT_SECRET=your_client_secret
export AZURE_TENANT_ID=your_tenant_id

# Method 2: Azure CLI
az login
az account set --subscription "your-subscription-id"

# Method 3: Managed Identity (for Azure VMs)
# No configuration needed - uses managed identity
```

#### GCP Setup
```bash
# Method 1: Service Account Key (recommended)
export GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account.json

# Method 2: Application Default Credentials
gcloud auth application-default login

# Method 3: Compute Engine default service account
# No configuration needed - uses metadata service
```

### 2. Run Your First Scan
```bash
# AWS GDPR compliance scan
secomp scan --cloud aws --compliance gdpr --output report.json

# Azure GDPR compliance scan
secomp scan --cloud azure --compliance gdpr --region my-resource-group

# GCP GDPR compliance scan
secomp scan --cloud gcp --compliance gdpr --region my-project-id

# With debug mode for detailed insights
secomp scan --cloud aws --compliance gdpr --debug

# Custom region and format
secomp scan --cloud azure --compliance gdpr --region production-rg --format json
```

### 3. Review Results
```bash
# View beautiful table output
secomp scan --cloud aws --compliance gdpr

# Save detailed JSON report
secomp scan --cloud aws --compliance gdpr --output compliance-report.json

# Interactive debug mode
secomp scan --cloud aws --compliance gdpr --debug
```

## 📋 Command Reference

### `secomp scan`
Scan cloud resources for compliance violations and security risks.

```bash
secomp scan [OPTIONS]

Options:
  --cloud [aws|azure|gcp]    Cloud provider to scan (required)
  --compliance [gdpr|nis2|soc2]  Compliance framework (required)
  --region TEXT              AWS region (default: us-east-1)
  --output PATH              Output file for JSON report
  --format [table|json]      Output format (default: table)
  --debug                    Enable debug mode
  --help                     Show help message
```

### `secomp plugins`
List available plugins and their status.

```bash
secomp plugins
```

## 🎨 Sample Output

### Table Format
```
📊 Scan Results
╭─────────────────────────────────────────────────────────╮
│        Secomp Compliance Report                         │
│  Cloud: AWS | Framework: GDPR | Risk Score: 45/100      │
╰─────────────────────────────────────────────────────────╯

📈 Summary
┌─────────────┬───────┐
│ Metric      │ Value │
├─────────────┼───────┤
│ Total       │ 3     │
│ ✅ Compliant│ 2     │
│ ❌ Non-Comp │ 1     │
│ 🔍 Risk     │ 45/100│
└─────────────┴───────┘

🔍 Resource Findings
┌─────────────────┬──────────────┬───────────┬────────────┬─────────────────┐
│ Resource        │ Status       │ Risk Score│ Risk Level │ Issues          │
├─────────────────┼──────────────┼───────────┼────────────┼─────────────────┤
│ my-public-bucket│ ❌ Non-Comp  │ 80/100    │ CRITICAL   │ Public Access   │
│ secure-bucket   │ ✅ Compliant │ 0/100     │ LOW        │ None            │
└─────────────────┴──────────────┴───────────┴────────────┴─────────────────┘
```

## 🔧 Configuration

### AWS Configuration
Secomp uses standard AWS credentials in order of precedence:
1. **Environment Variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
2. **AWS CLI Configuration**: `aws configure`
3. **IAM Roles**: For EC2/ECS instances
4. **AWS Credentials File**: `~/.aws/credentials`

#### Supported Regions
- **AWS**: All AWS regions (us-east-1, eu-west-1, ap-southeast-1, etc.)
- **Azure**: All Azure regions (East US, West Europe, Southeast Asia, etc.)
- **GCP**: All GCP regions (us-central1, europe-west1, asia-southeast1, etc.)

## 🏗️ Architecture

```
secomp/
├── secomp/
│   ├── __init__.py          # Package initialization
│   ├── cli.py              # Multi-cloud CLI interface
│   ├── scanner.py          # AWS, Azure, GCP resource scanning
│   ├── compliance.py       # Multi-cloud compliance rules
│   ├── models.py           # Pydantic data models
│   └── plugins/            # Plugin system
│       └── __init__.py
├── tests/
│   ├── test_scanner.py     # Multi-cloud tests with mocking
│   └── test_cli.py         # CLI tests
├── .github/
│   ├── workflows/
│   │   ├── ci.yml          # Continuous integration
│   │   └── release.yml     # Automated releases
│   ├── ISSUE_TEMPLATE/     # GitHub issue templates
│   └── dependabot.yml      # Automated dependency updates
├── docs/                   # Documentation (future)
├── Makefile               # Development automation
├── pyproject.toml         # Modern Python configuration
├── setup.py              # Package configuration
├── requirements.txt       # Dependencies
├── README.md             # This file
├── CHANGELOG.md          # Version history
└── CODE_OF_CONDUCT.md    # Community guidelines
```
## 🔄 CI/CD & Development Workflow

Secomp uses modern development practices with automated testing and quality checks:

### Automated Workflows
- **🧪 Testing**: Multi-Python version testing (3.9, 3.10, 3.11)
- **🔍 Code Quality**: Linting with flake8, formatting with black, type checking with mypy
- **🔒 Security**: Automated security scanning with safety and bandit
- **📦 Releases**: Automated PyPI releases when tags are pushed
- **🔄 Dependencies**: Weekly dependency updates via Dependabot

### Development Workflow
```bash
# 1. Fork and clone
git clone https://github.com/wipenode/secomp.git
cd secomp

# 2. Set up development environment
make install-dev

# 3. Create feature branch
git checkout -b feature/your-feature-name

# 4. Make changes and run tests
make pre-commit

# 5. Commit and push
git add .
git commit -m "Add your feature description"
git push origin feature/your-feature-name

# 6. Create Pull Request
```

### Running Tests
```bash
# Install test dependencies
pip install -r requirements.txt

# Run all tests
pytest

# Run with coverage
pytest --cov=secomp --cov-report=html

# Run tests with mocked AWS (recommended)
pytest tests/test_scanner.py -v

# Run CLI tests
pytest tests/test_cli.py -v
```

### Testing with Real Clouds

#### AWS Testing
1. Configure AWS credentials
2. Create a test S3 bucket: `aws s3 mb s3://secomp-test-bucket`
3. Run scan: `secomp scan --cloud aws --compliance gdpr`
4. Clean up: `aws s3 rb s3://secomp-test-bucket --force`

#### Azure Testing
1. Configure Azure credentials (see Configuration section)
2. Create a test storage account: `az storage account create -n secomptest -g test-rg`
3. Run scan: `secomp scan --cloud azure --compliance gdpr --region test-rg`
4. Clean up: `az storage account delete -n secomptest -g test-rg`

#### GCP Testing
1. Configure GCP credentials (see Configuration section)
2. Create a test bucket: `gsutil mb gs://secomp-test-bucket`
3. Run scan: `secomp scan --cloud gcp --compliance gdpr --region your-project-id`
4. Clean up: `gsutil rm -r gs://secomp-test-bucket`

### Testing with Mock Services
```bash
# Install all cloud SDKs for full testing
pip install boto3 azure-storage-blob google-cloud-storage moto

# Run all multi-cloud tests
pytest tests/test_scanner.py -v

# Run specific cloud tests
pytest tests/test_scanner.py::TestAzureScanner -v
pytest tests/test_scanner.py::TestGCPScanner -v
pytest tests/test_scanner.py::TestMultiCloudCompliance -v
```

## 🔌 Plugin Development

Secomp is designed for extensibility. Create plugins for new cloud providers or compliance frameworks:

### Example Plugin Structure
```python
# secomp/plugins/azure_scanner.py
from secomp.plugins import CloudScannerPlugin

class AzureScanner(CloudScannerPlugin):
    def get_name(self) -> str:
        return "Azure Blob Scanner"

    def scan_resources(self, config):
        # Implementation here
        pass
```

### Registering Plugins
```python
# In your plugin's __init__.py
from secomp.plugins import plugin_manager

plugin_manager.register_cloud_plugin('azure', AzureScanner)
```

## 🗺️ Roadmap

### Q1 2025 (MVP - Current)
- ✅ AWS S3 compliance scanning
- ✅ Azure Blob Storage compliance scanning
- ✅ GCP Cloud Storage compliance scanning
- ✅ GDPR compliance rules
- ✅ AI-driven risk scoring
- ✅ Beautiful CLI interface
- ✅ Comprehensive testing

### Q2 2025
- 🔄 NIS2 compliance framework
- 🔄 SOC2 compliance framework
- 🔄 Open Policy Agent (OPA) integration
- 🔄 Real-time monitoring mode

### Q3 2025
- 🔄 GitHub Actions integration
- 🔄 Terraform provider
- 🔄 Kubernetes operator
- 🔄 Advanced AI/ML risk models

### Q4 2025
- 🔄 Multi-cloud orchestration
- 🔄 Enterprise dashboard
- 🔄 Compliance automation workflows
- 🔄 Industry-specific compliance templates

## 🤝 Contributing

We welcome contributions! Here's how to get involved:

### Development Setup
```bash
# Clone the repository
git clone https://github.com/wipenode/secomp.git
cd secomp

# Set up virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
make install-dev

# Run tests
make test

# Run all pre-commit checks
make pre-commit
```

### Development Commands
```bash
# Install the package
make install

# Run tests with coverage
make test-cov

# Format code
make format

# Lint code
make lint

# Run security checks
make security

# Clean build artifacts
make clean

# Build package
make build

# See all available commands
make help
```

### Contribution Guidelines
1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Test** your changes: `pytest tests/ -v`
4. **Commit** with clear messages: `git commit -m "Add amazing feature"`
5. **Push** and create a Pull Request

### Code Style
- Follow PEP 8
- Write comprehensive tests (minimum 80% coverage)
- Add type hints
- Document public APIs

### Pull Request Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows project style
- [ ] Tests pass
- [ ] Documentation updated
- [ ] Changelog entry added
```

## 📄 License

Secomp is open-source software licensed under the MIT License. See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- Built with [Rich](https://github.com/Textualize/rich) for beautiful terminal output
- AWS integration powered by [boto3](https://github.com/boto/boto3)
- Azure integration powered by [azure-storage-blob](https://github.com/Azure/azure-sdk-for-python)
- GCP integration powered by [google-cloud-storage](https://github.com/googleapis/python-storage)
- Testing with [moto](https://github.com/getmoto/moto)
- CLI framework using [Click](https://github.com/pallets/click)

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/wipenode/secomp/issues)
- **Security**: [Security Policy](https://github.com/wipenode/secomp/security)
- **Discussions**: [GitHub Discussions](https://github.com/wipenode/secomp/discussions)
- **Email**: team@secomp.dev

## 🎯 Vision

Secomp isn't just another security tool—it's the standard for compliance in multi-cloud environments. By 2026, every CISO will show Secomp scans in their board presentations, saying "This changed how we work."

Join us in building the future of cybersecurity compliance! 🚀
