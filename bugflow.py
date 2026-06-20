#!/usr/bin/env python3
"""
BugFlow - Multi-Agent Bug Bounty Pipeline
===========================================
Master orchestrator that runs all 5 phases in sequence.
Each phase spawns its own sub-agents for parallel work.

Workflow: Haddix-style Recon → Scanning → InsiderPhD-style API Testing → Report

Usage:
    python3 bugflow.py --target shopify.com --program Shopify
    python3 bugflow.py --target shopify.com --phase 2    (run only phase 2)
    python3 bugflow.py --list-phases
"""

import sys
import json
import logging
import argparse
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.utils import load_config, get_output_dir, print_banner, setup_logging, available_tools, check_tool
from core.humanize import random_delay

logger = logging.getLogger("bugflow")


class BugFlowOrchestrator:
    """Main orchestrator that runs all 5 phases.
    
    Each phase is an independent agent that spawns its own sub-agents.
    Results flow from one phase to the next.
    """

    def __init__(self, config: dict):
        self.config = config
        self.target_info = {}
        self.results = {
            "targets": [],
            "recon": {},
            "scanning": [],
            "api_findings": [],
            "reports": [],
        }

    def run_all(self, target: str, program: str = "") -> dict:
        """Run all 5 phases in sequence."""
        print_banner()
        
        target = target.lower().strip()
        program = program or target.split(".")[0].capitalize()
        
        logger.info(f"🎯 Target: {target}")
        logger.info(f"📋 Program: {program}")
        logger.info(f"Starting full BugFlow pipeline...\n")
        
        # Check available tools
        tools = available_tools()
        available = [t for t, v in tools.items() if v]
        missing = [t for t, v in tools.items() if not v]
        logger.info(f"✅ Available tools: {', '.join(available)}")
        if missing:
            logger.info(f"⚠️  Missing tools: {', '.join(missing)}")
        print()

        # Phase 1: Target Selection
        if self.config.get("target_selection", {}).get("enabled", True):
            from phases.phase1_targets import TargetSelector
            logger.info("\n" + "=" * 60)
            logger.info("PHASE 1/5: Target Selection (Haddix-style)")
            logger.info("=" * 60)
            
            selector = TargetSelector(self.config)
            self.results["targets"] = selector.run(target)
            self.target_info = {"name": program, "domain": target}
            
            # Spawn sub-agents for each target
            if len(self.results["targets"]) > 1:
                from phases.phase1_targets import ProgramResearcher
                logger.info(f"\n  Spawning target research sub-agents...")
                for t in self.results["targets"][:3]:
                    researcher = ProgramResearcher(t)
                    info = researcher.research()
                    if info.get("tips"):
                        logger.info(f"  💡 Tips for {t['name']}: {info['tips'][0]}")
            
            random_delay(2, 4)
        
        # Phase 2: Reconnaissance
        if self.config.get("recon", {}).get("enabled", True):
            from phases.phase2_recon import ReconEngine
            logger.info("\n" + "=" * 60)
            logger.info("PHASE 2/5: Reconnaissance (Haddix-style)")
            logger.info("=" * 60)
            
            engine = ReconEngine(self.config)
            targets = [t["name"] for t in self.results["targets"]] if self.results["targets"] else [target]
            
            logger.info(f"  Spawning {len(targets)} recon pipelines (each with 4 sub-agents)...")
            self.results["recon"] = engine.run(targets)
            
            random_delay(2, 4)
        
        # Phase 3: Vulnerability Scanning
        if self.config.get("scanning", {}).get("enabled", True):
            from phases.phase3_scanning import ScanningEngine
            logger.info("\n" + "=" * 60)
            logger.info("PHASE 3/5: Vulnerability Scanning")
            logger.info("=" * 60)
            
            engine = ScanningEngine(self.config)
            live_hosts = self.results["recon"].get("live_hosts_list", [])
            subdomains = self.results["recon"].get("subdomains", [])
            
            logger.info(f"  Spawning scanning sub-agents (nuclei + httpx + custom)...")
            self.results["scanning"] = engine.run([target], subdomains, live_hosts)
            
            random_delay(2, 4)
        
        # Phase 4: API Testing (InsiderPhD-style)
        if self.config.get("api_testing", {}).get("enabled", True):
            from phases.phase4_api_testing import APITestingEngine
            logger.info("\n" + "=" * 60)
            logger.info("PHASE 4/5: API Testing (InsiderPhD-style)")
            logger.info("=" * 60)
            
            engine = APITestingEngine(self.config)
            live_hosts = self.results["recon"].get("live_hosts_list", [])
            urls = self.results["recon"].get("urls", [])
            
            logger.info(f"  Spawning API test sub-agents (BOLA + Auth + Mass Assignment)...")
            self.results["api_findings"] = engine.run(live_hosts, urls)
            
            random_delay(2, 4)
        
        # Phase 5: Report Writing
        if self.config.get("reporting", {}).get("enabled", True):
            from phases.phase5_report import ReportWriter
            logger.info("\n" + "=" * 60)
            logger.info("PHASE 5/5: Report Writing (Hermes-powered)")
            logger.info("=" * 60)
            
            writer = ReportWriter(self.config)
            all_findings = self.results["scanning"] + self.results["api_findings"]
            
            if all_findings:
                logger.info(f"  Spawning report sub-agents for {len(all_findings)} findings...")
                self.results["reports"] = writer.run(all_findings, self.target_info)
            else:
                logger.info("  No findings to report on")
        
        # Summary
        self._print_summary(target)
        
        # Save full results
        output_dir = get_output_dir(target, "full_pipeline", 
                                     str(self.config.get("general", {}).get("output_dir", "output")))
        with open(output_dir / "full_results.json", "w") as f:
            # Convert sets to lists for JSON serialization
            serializable = self._make_serializable(self.results)
            json.dump(serializable, f, indent=2)
        
        logger.info(f"\n💾 Full results saved to: {output_dir}")
        
        return self.results

    def run_phase(self, phase_num: int, target: str) -> dict:
        """Run a single phase."""
        from phases.phase1_targets import TargetSelector
        from phases.phase2_recon import ReconEngine
        from phases.phase3_scanning import ScanningEngine
        from phases.phase4_api_testing import APITestingEngine
        from phases.phase5_report import ReportWriter

        phases = {
            1: ("Target Selection", lambda: TargetSelector(self.config).run(target)),
            2: ("Reconnaissance", lambda: ReconEngine(self.config).run([target])),
            3: ("Scanning", lambda: ScanningEngine(self.config).run([target], [], [target])),
            4: ("API Testing", lambda: APITestingEngine(self.config).run([target], [target])),
            5: ("Report Writing", lambda: ReportWriter(self.config).run(
                [{"type": "test", "severity": "medium", "endpoint": target}], 
                {"name": target})),
        }

        if phase_num not in phases:
            logger.error(f"Invalid phase: {phase_num}. Use 1-5.")
            return {}

        name, fn = phases[phase_num]
        logger.info(f"Running Phase {phase_num}: {name}")
        return fn()

    def _print_summary(self, target: str) -> None:
        """Print a beautiful summary of results."""
        try:
            from colorama import Fore, Style
            GREEN = Fore.GREEN
            CYAN = Fore.CYAN
            YELLOW = Fore.YELLOW
            RESET = Style.RESET_ALL
        except ImportError:
            GREEN = CYAN = YELLOW = RESET = ""
        
        print("\n" + "=" * 60)
        print(f"{GREEN}BUGFLOW PIPELINE COMPLETE{RESET}")
        print("=" * 60)
        print(f"\n{CYAN}Target:{RESET} {target}")
        print(f"{CYAN}Pipeline:{RESET} 5 phases complete\n")
        
        r = self.results
        print(f"{YELLOW}Phase 1 - Targets:{RESET} {len(r['targets'])} selected")
        print(f"{YELLOW}Phase 2 - Recon:{RESET} {r['recon'].get('total_subdomains', 0)} subdomains, "
              f"{r['recon'].get('live_hosts', 0)} live")
        print(f"{YELLOW}Phase 3 - Scanning:{RESET} {len(r['scanning'])} findings")
        print(f"{YELLOW}Phase 4 - API:{RESET} {len(r['api_findings'])} API issues")
        print(f"{YELLOW}Phase 5 - Reports:{RESET} {len(r['reports'])} reports generated")
        
        total_findings = len(r['scanning']) + len(r['api_findings'])
        if total_findings > 0:
            print(f"\n{GREEN}💰 Ready to submit: {total_findings} potential bugs{RESET}")
            print(f"   Reports are saved in the output directory.")
        print()

    def _make_serializable(self, obj):
        """Convert sets and non-serializable types for JSON output."""
        if isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(v) for v in obj]
        return obj


def main():
    parser = argparse.ArgumentParser(
        description="BugFlow - Multi-Agent Bug Bounty Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  bugflow.py --target shopify.com                   Full pipeline
  bugflow.py --target api.target.com --phase 4       Just API testing
  bugflow.py --target shopify.com --verbose          Full pipeline with debug
        """
    )
    parser.add_argument("--target", "-t", help="Target domain or program name")
    parser.add_argument("--program", "-p", help="Program name (for reports)")
    parser.add_argument("--phase", type=int, choices=range(1, 6),
                        help="Run a single phase (1-5)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--list-phases", action="store_true",
                        help="List available phases")
    parser.add_argument("--check-tools", action="store_true",
                        help="Check which tools are installed")
    parser.add_argument("--config", default="config.yaml",
                        help="Path to config file (default: config.yaml)")

    args = parser.parse_args()

    # Setup
    setup_logging(args.verbose)
    
    # Load config
    config = load_config(args.config)
    
    # List phases
    if args.list_phases:
        print("\nBugFlow Phases:")
        print("  1: Target Selection  - Pick high-value programs (Haddix-style)")
        print("  2: Reconnaissance    - Multi-source subdomain/endpoint discovery")
        print("  3: Vulnerability Scanning - Nuclei + custom checks")
        print("  4: API Testing       - BOLA/IDOR/Auth/Mass Assignment (InsiderPhD-style)")
        print("  5: Report Writing    - Hermes-powered professional reports")
        print("\nEach phase spawns its own sub-agents for parallel work.")
        return

    # Check tools
    if args.check_tools:
        tools = available_tools()
        print("\nInstalled Tools:")
        for tool, installed in tools.items():
            status = "✅" if installed else "❌"
            print(f"  {status} {tool}")
        return

    # Run pipeline
    if not args.target:
        parser.print_help()
        print("\nError: --target is required unless using --list-phases or --check-tools")
        return

    orchestrator = BugFlowOrchestrator(config)

    if args.phase:
        orchestrator.run_phase(args.phase, args.target)
    else:
        orchestrator.run_all(args.target, args.program)


if __name__ == "__main__":
    main()
