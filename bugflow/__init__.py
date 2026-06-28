"""
BugFlow — Multi-Agent Bug Bounty Automation Engine
====================================================

A 5-phase automated bug bounty pipeline that handles everything from
target selection to professional report writing.

Phases:
    1. Target Selection — Pick high-value programs (Haddix-style)
    2. Reconnaissance — Multi-source subdomain/endpoint discovery
    3. Vulnerability Scanning — Nuclei + custom checks
    4. API Testing — BOLA/IDOR/Auth/Mass Assignment (InsiderPhD-style)
    5. Report Writing — Professional reports with CVSS scoring

Usage:
    >>> from bugflow import BugFlowOrchestrator
    >>> orchestrator = BugFlowOrchestrator(config)
    >>> results = orchestrator.run_all("example.com")

CLI:
    $ bugflow --target shopify.com
    $ bugflow --target api.target.com --phase 4
    $ bugflow --list-phases
"""

__version__ = "1.0.0"
__author__ = "Enish Shah"
__license__ = "MIT"

from bugflow.bugflow import BugFlowOrchestrator

__all__ = ["BugFlowOrchestrator", "__version__"]
