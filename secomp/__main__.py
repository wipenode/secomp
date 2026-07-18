"""
Secomp CLI entry point when running as module.

This allows users to run: python -m secomp
"""

from .cli import cli

if __name__ == "__main__":
    cli()
