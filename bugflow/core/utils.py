"""
BugFlow - Shared Utilities
===========================
Helpers for file I/O, target parsing, output formatting.
"""

import os
import sys
import json
import yaml
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger("bugflow.utils")


def load_config(path: str = "config.yaml") -> dict:
    """Load configuration from YAML file."""
    config_path = Path(path)
    if not config_path.exists():
        logger.error(f"Config file not found: {path}")
        return {}
    
    with open(config_path) as f:
        config = yaml.safe_load(f)
    
    logger.info(f"Loaded config from {path}")
    return config


def get_output_dir(program: str, phase: str, base_dir: str = "output") -> Path:
    """Get timestamped output directory for a phase."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(base_dir) / f"{program}_{timestamp}" / phase
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def save_results(results: list, filepath: Path, fmt: str = "txt") -> None:
    """Save results to file in the specified format."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    
    if fmt == "json":
        with open(filepath, "w") as f:
            json.dump(results, f, indent=2)
    elif fmt == "txt":
        with open(filepath, "w") as f:
            for item in results:
                f.write(f"{item}\n")
    
    logger.info(f"Saved {len(results)} results to {filepath}")


def load_targets(target_arg: str) -> list:
    """Load targets from a file or return as a single-item list."""
    target_path = Path(target_arg)
    if target_path.exists():
        with open(target_path) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        logger.info(f"Loaded {len(targets)} targets from {target_arg}")
        return targets
    return [target_arg]


def parse_nuclei_output(raw: str) -> list[dict]:
    """Parse nuclei JSON output into structured findings."""
    findings = []
    for line in raw.strip().split("\n"):
        if not line.strip():
            continue
        try:
            finding = json.loads(line)
            findings.append(finding)
        except json.JSONDecodeError:
            continue
    return findings


def check_tool(tool_name: str) -> bool:
    """Check if a system tool is available."""
    import subprocess
    try:
        result = subprocess.run(
            ["which", tool_name], 
            capture_output=True, 
            text=True, 
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def available_tools() -> dict:
    """Check which bug bounty tools are installed."""
    tools = [
        "subfinder", "amass", "httpx", "nuclei", "nmap",
        "gau", "waybackurls", "ffuf", "gf", "dnsx",
        "naabu", "chaos", "shuffledns", "puredns", "httpx"
    ]
    result = {}
    for tool in tools:
        result[tool] = check_tool(tool)
    return result


def print_banner() -> None:
    """Print the BugFlow banner."""
    try:
        from colorama import Fore, Style, init
        init()
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════╗
║         {Fore.YELLOW}BUGFLOW v1.0{Fore.CYAN}                ║
║   {Fore.GREEN}Multi-Agent Bug Bounty Pipeline{Fore.CYAN}     ║
║   {Fore.MAGENTA}Haddix → Recon → Scan → API → Report{Fore.CYAN}  ║
╚══════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    except ImportError:
        print("=== BUGFLOW v1.0 ===")
        print("Multi-Agent Bug Bounty Pipeline")
        print("Haddix → Recon → Scan → API → Report")
        print()


def setup_logging(verbose: bool = False) -> None:
    """Set up logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
