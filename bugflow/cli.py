#!/usr/bin/env python3
"""
BugFlow CLI Entry Point
========================
Main command-line interface for the BugFlow pipeline.

Usage:
    bugflow --target shopify.com
    bugflow --target api.target.com --phase 4
    bugflow --list-phases
    bugflow --check-tools
"""

import sys
from pathlib import Path

# Ensure the package root is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from bugflow.orchestrator import main

if __name__ == "__main__":
    main()
