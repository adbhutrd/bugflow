"""
BugFlow - Phase 1: Target Selection
=====================================
Haddix-style: Research and select high-value bug bounty targets.
Analyzes programs, scope, payouts to pick the best targets.
"""

import json
import logging
import random
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# Allow standalone execution
if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).parent.parent))

from core.humanize import random_delay, get_random_headers, get_session
from core.utils import save_results, load_config, get_output_dir, check_tool

logger = logging.getLogger("bugflow.phase1_targets")


class TargetSelector:
    """Select and analyze bug bounty targets (Haddix-style)."""

    def __init__(self, config: dict):
        self.config = config
        ts_config = config.get("target_selection", {})
        self.max_scope = ts_config.get("max_scope_domains", 50)
        self.min_payouts = ts_config.get("min_payouts", 5)
        self.platforms = ts_config.get("platforms", [])
        self.session = get_session()
        self.output_dir = Path(config.get("general", {}).get("output_dir", "output"))
        
        # Known high-paying programs (curated list to start)
        self.known_programs = [
            {"name": "Shopify", "platform": "hackerone", "scope": ["*.shopify.com", "*.shopify.dev"], "payout_range": "$500 - $10,000"},
            {"name": "GitHub", "platform": "hackerone", "scope": ["*.github.com", "api.github.com"], "payout_range": "$500 - $20,000"},
            {"name": "PayPal", "platform": "bugcrowd", "scope": ["*.paypal.com", "*.paypalobjects.com"], "payout_range": "$500 - $10,000"},
            {"name": "Atlassian", "platform": "bugcrowd", "scope": ["*.atlassian.com", "*.jira.com"], "payout_range": "$500 - $5,000"},
            {"name": "Mozilla", "platform": "hackerone", "scope": ["*.mozilla.org", "*.firefox.com"], "payout_range": "$500 - $10,000"},
            {"name": "Slack", "platform": "hackerone", "scope": ["*.slack.com", "*.slack-edge.com"], "payout_range": "$500 - $5,000"},
            {"name": "Discord", "platform": "bugcrowd", "scope": ["*.discord.com", "*.discordapp.com"], "payout_range": "$500 - $10,000"},
            {"name": "Dropbox", "platform": "hackerone", "scope": ["*.dropbox.com", "*.dropboxapi.com"], "payout_range": "$500 - $10,000"},
            {"name": "Twitter", "platform": "hackerone", "scope": ["*.twitter.com", "*.x.com"], "payout_range": "$500 - $5,000"},
            {"name": "Cloudflare", "platform": "hackerone", "scope": ["*.cloudflare.com", "api.cloudflare.com"], "payout_range": "$500 - $5,000"},
            {"name": "WordPress", "platform": "hackerone", "scope": ["*.wordpress.com", "*.wp.com"], "payout_range": "$500 - $3,000"},
            {"name": "Ubisoft", "platform": "hackerone", "scope": ["*.ubisoft.com", "*.ubi.com"], "payout_range": "$500 - $5,000"},
        ]

    def run(self, target_hint: str = "") -> list[dict]:
        """Run target selection phase.
        
        If target_hint is provided, analyze just that target.
        Otherwise, select from known high-value programs.
        """
        logger.info("=" * 50)
        logger.info("PHASE 1: Target Selection (Haddix-style)")
        logger.info("=" * 50)

        if target_hint:
            targets = self._analyze_single_target(target_hint)
        else:
            targets = self._select_targets()
        
        # Save results
        out_dir = get_output_dir("targets", "phase1_targets", str(self.output_dir))
        save_results(targets, out_dir / "selected_targets.json", fmt="json")
        save_results([t["name"] for t in targets], out_dir / "targets.txt")
        
        logger.info(f"Phase 1 complete: {len(targets)} target(s) selected")
        return targets

    def _analyze_single_target(self, target: str) -> list[dict]:
        """Analyze a single target program."""
        target = target.lower().strip()
        logger.info(f"Analyzing target: {target}")
        
        # Check if it's in our known programs
        for prog in self.known_programs:
            if target in prog["name"].lower() or target in str(prog["scope"]).lower():
                logger.info(f"Found known program: {prog['name']} on {prog['platform']}")
                logger.info(f"  Scope: {', '.join(prog['scope'])}")
                logger.info(f"  Payout: {prog['payout_range']}")
                return [prog]
        
        # Unknown target - return basic info
        result = {
            "name": target,
            "platform": "unknown",
            "scope": [f"*.{target}", f"*.{target}.com"],
            "payout_range": "unknown - check program page",
            "status": "needs_review"
        }
        logger.info(f"Unknown program: {target} - check manually")
        return [result]

    def _select_targets(self) -> list[dict]:
        """Select the best targets from known programs."""
        logger.info("Selecting from known high-value programs...")
        random_delay(1, 3)
        
        selected = []
        for program in self.known_programs:
            selected.append(program)
        
        logger.info(f"\nSelected {len(selected)} top programs:")
        for i, prog in enumerate(selected[:5], 1):
            logger.info(f"  {i}. {prog['name']} - {prog['payout_range']}")
        
        if len(selected) > 5:
            logger.info(f"  ... and {len(selected) - 5} more")
        
        return selected

    def print_report(self, targets: list[dict]) -> None:
        """Print a human-readable target report."""
        print("\n" + "=" * 60)
        print("TARGET SELECTION REPORT")
        print("=" * 60)
        for i, t in enumerate(targets, 1):
            print(f"\n{i}. {t['name']}")
            print(f"   Platform: {t.get('platform', 'N/A')}")
            print(f"   Scope: {', '.join(t.get('scope', []))}")
            print(f"   Payout: {t.get('payout_range', 'N/A')}")


# ==============================================================================
# Sub-agents for parallel target research
# ==============================================================================

class ProgramResearcher:
    """Sub-agent: Research a single bug bounty program in detail."""
    
    def __init__(self, program: dict):
        self.program = program
    
    def research(self) -> dict:
        """Gather intelligence on this program."""
        name = self.program["name"]
        logger.info(f"  [SUB-AGENT] Researching {name}...")
        random_delay(1, 3)
        
        # Simulate researching the program
        info = {
            **self.program,
            "status": "ready",
            "tips": self._get_hunting_tips(name),
        }
        return info
    
    def _get_hunting_tips(self, name: str) -> list:
        """Get program-specific hunting tips."""
        tips_map = {
            "Shopify": [
                "Focus on custom apps and themes - they often have unique vulns",
                "Check for privilege escalation in store admin panels",
                "API rate limiting bypass can lead to data harvesting",
            ],
            "GitHub": [
                "OAuth misconfigurations are common and high-paying",
                "Check for SSRF in webhook integrations",
                "Repository access control bypasses",
            ],
            "PayPal": [
                "Payment flow logic flaws are the highest paying",
                "2FA bypasses are common",
                "Check for IDOR in transaction APIs",
            ],
        }
        return tips_map.get(name, [
            "Explore API endpoints thoroughly",
            "Check for IDOR in all authenticated requests",
            "Test business logic flows end-to-end",
        ])


if __name__ == "__main__":
    # Standalone run
    from core.utils import setup_logging, print_banner
    setup_logging()
    print_banner()
    
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    config = load_config()
    
    selector = TargetSelector(config)
    targets = selector.run(target)
    selector.print_report(targets)
