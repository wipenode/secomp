# Secomp

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

Terminal-first compliance scanner for cloud storage. Secomp connects to AWS, Azure,
and GCP, inspects storage resources against compliance rules, and produces risk-scored
reports as terminal tables or JSON.

It is built for people who live in a terminal and want a single lightweight client
for talking to multiple clouds -- no browser consoles, no agents deployed into the
target environment, no server component. One binary-sized Python package, your
existing cloud credentials, and read-only API calls.

## Current state

Secomp is an early-stage project (0.1.x). What works today:

| Area | Status |
|---|---|
| AWS S3 scanning | ACL grants, bucket policy heuristics, server-side encryption config |
| Azure Blob Storage scanning | Container public-access level; encryption reported as always-on (Azure SSE cannot be disabled) |
| GCP Cloud Storage scanning | IAM policy check for `allUsers` / `allAuthenticatedUsers`, KMS key detection, versioning, uniform bucket-level access |
| GDPR storage rules | 3 rules: public access, encryption at rest, access logging (logging currently reported as `unknown` -- not yet checked) |
| Risk scoring | Weighted heuristic, 0-100 per resource, aggregated per scan |
| Output | Rich terminal tables or JSON (stdout / file) |
| Frameworks | GDPR only. `nis2` and `soc2` are accepted by the CLI but exit with an error until implemented |

What it deliberately is not: an agent-based platform, a SaaS, or a remediation tool.
Secomp only reads configuration and reports on it.

## Installation

```bash
# from source (recommended for now)
git clone https://github.com/wipenode/secomp.git
cd secomp
pip install -e .

# with optional providers and test tooling
pip install -e .[all]        # azure + gcp + test deps
pip install -e .[azure]      # just Azure SDK
pip install -e .[gcp]        # just GCP SDK
```

AWS support (boto3) is always installed. Azure and GCP SDKs are optional extras;
without them the respective scanners report that the SDK is missing and return
no findings.

Requires Python 3.9+. Works on Linux, macOS, and Windows (including legacy
`cmd.exe` consoles).

## Usage

```bash
# AWS: scan all S3 buckets in the account
secomp scan --cloud aws --compliance gdpr --region us-east-1

# Azure: scan blob containers in a storage account
secomp scan --cloud azure --compliance gdpr --region my-resource-group

# GCP: scan storage buckets in a project
secomp scan --cloud gcp --compliance gdpr --region my-project-id

# machine-readable output
secomp scan --cloud aws --compliance gdpr --format json
secomp scan --cloud aws --compliance gdpr --output report.json

# verbose diagnostics
secomp scan --cloud aws --compliance gdpr --debug
```

The `--region` flag is overloaded per provider: AWS region, Azure resource group,
or GCP project ID. This will be split into explicit flags in a future release.

Exit codes: `0` scan completed, `1` runtime error (credentials, network, API),
`2` requested framework not implemented.

### Credentials

Secomp uses each provider's standard credential chain and never stores secrets itself.

```bash
# AWS - any standard mechanism: env vars, ~/.aws/credentials, IAM roles
aws configure

# Azure - data-plane access to a storage account
export AZURE_STORAGE_ACCOUNT_URL=https://youraccount.blob.core.windows.net
az login   # DefaultAzureCredential picks up CLI login, managed identity, or SP env vars
# or:
export AZURE_STORAGE_CONNECTION_STRING=...

# GCP - Application Default Credentials
gcloud auth application-default login
# or:
export GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account.json
```

Required permissions are read-only: `s3:ListAllMyBuckets`, `s3:GetBucket*` for AWS;
list/read on containers for Azure; `storage.buckets.get`, `storage.buckets.getIamPolicy`
for GCP.

## How scanning works

Each scanner walks the provider's storage resources and builds a normalized details
model (Pydantic). The rules engine evaluates every resource against the active
framework's rules; each rule returns `compliant`, `non_compliant`, or `unknown`
together with remediation guidance.

Risk scoring is a transparent weighted heuristic, not a model:

| Rule | Weight |
|---|---|
| GDPR-STORAGE-001 public access | 50 |
| GDPR-STORAGE-002 encryption at rest | 30 |
| GDPR-STORAGE-003 access logging (unknown counts as risk) | 20 |
| Penalty per violation when multiple rules fail | +15 |

Scores are capped at 100 and mapped to levels: `<30` low, `30-59` medium,
`60-79` high, `>=80` critical. When a resource cannot be verified (for example
an S3 ACL read fails), Secomp fails closed and flags it rather than assuming
compliance.

The JSON report contains the full detail chain: per-resource findings, every rule
result with remediation text, timestamps, and scan metadata -- suitable for diffing
between runs or feeding into other tooling.

## Roadmap: interactive terminal client

The long-term direction is an interactive TUI, in the spirit of htop or k9s:
a persistent terminal client that holds authenticated sessions to multiple clouds
simultaneously and lets you run scans, browse findings, and drill into resources
without leaving the keyboard. Think of it loosely as a C2-style client for your own
cloud accounts -- one pane of glass, many targets, read-only.

Planned progression:

**0.2 -- scanning depth (CLI)**
- S3 Public Access Block and account-level settings, not just ACL/policy heuristics
- Access-logging checks (CloudTrail / Azure Monitor / Cloud Logging) so
  GDPR-STORAGE-003 stops returning `unknown`
- Pagination for large accounts; explicit `--region` / `--resource-group` / `--project` flags
- Scan exit code reflecting findings (usable as a CI gate)
- Report diffing: `secomp diff old.json new.json`

**0.3 -- sessions and profiles**
- Named connection profiles (`secomp connect aws-prod`, `secomp connect gcp-dev`)
  wrapping provider credential chains
- Concurrent scans across multiple connected clouds in one invocation
- Local scan history with timestamped JSON reports

**0.4 -- interactive TUI**
- Full-screen terminal UI (Textual is the current candidate; it is already
  cross-platform on Linux/macOS/Windows and shares the Rich rendering stack
  Secomp uses today)
- Connection manager pane: attach/detach cloud sessions at runtime
- Live scan view with per-resource status, sortable findings table,
  detail pane with rule results and remediation
- Keyboard-driven: filter, rescan single resource, export selection to JSON

**Later**
- NIS2 / SOC2 rule sets behind the same rules-engine interface
- Resource types beyond storage (IAM, networking) where read-only checks make sense
- Plugin loading via Python entry points so third-party scanners and frameworks
  can register without forking the codebase

No dates are promised. Items ship when they are correct.

## Architecture

```
secomp/
├── secomp/                 # Python package
│   ├── cli.py              # Click commands, Rich rendering
│   ├── scanner.py          # AWSScanner, AzureScanner, GCPScanner
│   ├── compliance.py       # rules engine + risk scoring
│   ├── models.py           # Pydantic models (findings, reports, configs)
│   └── plugins/            # plugin interfaces (not yet wired into the CLI)
├── tests/                  # pytest suite, AWS mocked with moto
├── .github/workflows/      # CI (tests, lint, security, build) and release
├── pyproject.toml          # packaging, deps, tool config
└── Makefile                # dev shortcuts
```

Design notes:

- Scanners are independent classes with a common finding format; adding a provider
  means implementing list + describe + mapping to a details model.
- Rules operate on the normalized models via duck typing, so one rule set covers
  all providers.
- Findings are never fabricated: if a resource cannot be inspected, the scanner
  raises and the resource is skipped with a logged error, or the check fails closed.

## Development

```bash
pip install -e .[all]
pytest tests/ -v            # unit tests (AWS mocked via moto, no credentials needed)
python test_mock.py         # quick smoke test
python test_multicloud.py   # multi-provider smoke test

make lint                   # flake8 + black + isort
make format
make security               # safety + bandit
```

CI runs the test matrix on Python 3.9-3.12, linting, security scans, and a build
check on every push and pull request.

Contributions are welcome -- particularly new rule implementations, provider depth
(the checks marked as heuristic or unknown above), and groundwork for the TUI.
Fork, branch, add tests, open a PR.

## License

MIT. See [LICENSE](LICENSE).
