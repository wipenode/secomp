.PHONY: help install test lint format clean build release docs

help:  ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install:  ## Install the package in development mode
	pip install -r requirements.txt
	pip install -e .

test:  ## Run tests
	pytest tests/ -v

test-cov:  ## Run tests with coverage
	pytest tests/ -v --cov=secomp --cov-report=html --cov-report=term-missing

lint:  ## Run linting
	flake8 secomp/ tests/ --count --select=E9,F63,F7,F82 --show-source --statistics
	flake8 secomp/ tests/ --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
	black --check --diff secomp/ tests/
	isort --check-only --diff secomp/ tests/

format:  ## Format code
	black secomp/ tests/
	isort secomp/ tests/

type-check:  ## Run type checking
	mypy secomp/

security:  ## Run security checks
	safety check
	bandit -r secomp/ -f json -o bandit-report.json || true

clean:  ## Clean up build artifacts
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .coverage
	rm -rf .pytest_cache/
	rm -rf __pycache__/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

build:  ## Build the package
	python -m build

release:  ## Release to PyPI (requires credentials)
	python -m build
	twine upload dist/*

docs:  ## Build documentation
	mkdocs build

docs-serve:  ## Serve documentation locally
	mkdocs serve

pre-commit: test lint type-check security  ## Run all pre-commit checks

ci: test lint security  ## Run CI checks locally

install-dev:  ## Install development dependencies
	pip install -r requirements.txt
	pip install black isort flake8 mypy bandit safety twine build mkdocs mkdocs-material

install-all:  ## Install all dependencies including optional ones
	pip install -r requirements.txt
	pip install azure-storage-blob google-cloud-storage
	pip install black isort flake8 mypy bandit safety twine build mkdocs mkdocs-material
	pip install -e .
