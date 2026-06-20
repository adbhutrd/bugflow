"""
BugFlow - Phase 3: Vulnerability Scanning
==========================================
Haddix-style: Intelligent vulnerability scanning with human-like behavior.
Spawns sub-agents for different scan types running in parallel.
"""

import json
import logging
import random
import subprocess
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).parent.parent))

from core.humanize import random_delay, get_session, RequestTracker
from core.utils import save_results, load_config, get_output_dir, check_tool, parse_nuclei_output

logger = logging.getLogger("bugflow.phase3_scanning")


class ScanningEngine:
    """Nuclei + custom scanning engine with human delays."""

    def __init__(self, config: dict):
        self.config = config
        sc_config = config.get("scanning", {})
        self.min_severity = sc_config.get("min_severity", "medium")
        self.custom_templates = sc_config.get("custom_templates", [])
        self.tracker = RequestTracker()
        self.session = get_session()
        self.output_dir = Path(config.get("general", {}).get("output_dir", "output"))

    def run(self, targets: list[str], subdomains: list[str], live_hosts: list[str]) -> list[dict]:
        """Run scanning phase on discovered assets.
        
        Spawns parallel sub-agents for different scan types.
        """
        logger.info("=" * 50)
        logger.info("PHASE 3: Vulnerability Scanning")
        logger.info("=" * 50)
        
        all_findings = []
        scan_targets = live_hosts if live_hosts else targets[:10]
        
        logger.info(f"  Scanning {len(scan_targets)} targets...")
        
        # Spawn parallel scanning sub-agents
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}
            
            # Sub-agent 1: Nuclei scan
            if check_tool("nuclei"):
                futures[executor.submit(self._nuclei_scan, scan_targets)] = "nuclei"
            
            # Sub-agent 2: HTTP probing (technology detection)
            if check_tool("httpx"):
                futures[executor.submit(self._httpx_probe, scan_targets)] = "httpx"
            
            # Sub-agent 3: Custom template scan (your 250+ templates)
            futures[executor.submit(self._custom_template_scan, scan_targets)] = "custom"
            
            for future in as_completed(futures):
                name = futures[future]
                try:
                    findings = future.result()
                    if findings:
                        all_findings.extend(findings)
                        logger.info(f"  [SUB-AGENT {name}] Found {len(findings)} findings")
                except Exception as e:
                    logger.warning(f"  [SUB-AGENT {name}] Failed: {e}")
        
        # Save findings
        out_dir = get_output_dir("scanning", "phase3_scanning", str(self.output_dir))
        save_results(all_findings, out_dir / "findings.json", fmt="json")
        save_results([f"{f.get('severity','?').upper()} | {f.get('name','?')} | {f.get('host','?')}" 
                      for f in all_findings], out_dir / "findings_summary.txt")
        
        result = sorted(all_findings, key=lambda x: self._severity_score(x.get("severity", "low")), reverse=True)
        logger.info(f"Phase 3 complete: {len(result)} findings (critical={self._count_by_sev(result, 'critical')}, "
                    f"high={self._count_by_sev(result, 'high')}, medium={self._count_by_sev(result, 'medium')})")
        return result

    def _nuclei_scan(self, targets: list[str]) -> list[dict]:
        """Sub-agent: Run nuclei with human-like delays between targets."""
        logger.info(f"    └─ sub-agent: nuclei scan ({len(targets)} targets)")
        
        targets_file = f"/tmp/bugflow_nuclei_targets_{random.randint(1000,9999)}.txt"
        with open(targets_file, "w") as f:
            for t in targets[:20]:  # Limit to 20 for speed
                f.write(f"{t}\n")
        
        try:
            templates = self.custom_templates[0] if self.custom_templates else "~/nuclei-templates/"
            result = subprocess.run(
                ["nuclei", "-l", targets_file, "-t", templates,
                 "-json", "-silent", "-rl", "30",  # Rate limit: 30 req/sec
                 "-o", "/dev/stdout"],
                capture_output=True, text=True, timeout=180
            )
            
            findings = parse_nuclei_output(result.stdout)
            logger.info(f"  Nuclei found {len(findings)} findings")
            return findings
        except Exception as e:
            logger.debug(f"Nuclei scan failed: {e}")
            return []
        finally:
            Path(targets_file).unlink(missing_ok=True)

    def _httpx_probe(self, targets: list[str]) -> list[dict]:
        """Sub-agent: Probe targets for technology detection."""
        logger.info(f"    └─ sub-agent: httpx probe ({len(targets)} targets)")
        
        targets_file = f"/tmp/bugflow_httpx_{random.randint(1000,9999)}.txt"
        with open(targets_file, "w") as f:
            for t in targets[:20]:
                f.write(f"{t}\n")
        
        try:
            result = subprocess.run(
                ["httpx", "-l", targets_file, "-td", "-status-code",
                 "-title", "-silent", "-json", "-o", "/dev/stdout"],
                capture_output=True, text=True, timeout=120
            )
            
            findings = []
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    findings.append({
                        "type": "technology",
                        "name": f"Tech: {data.get('url', '?')}",
                        "host": data.get("host", ""),
                        "severity": "info",
                        "details": data,
                    })
                except json.JSONDecodeError:
                    continue
            
            return findings
        except Exception as e:
            logger.debug(f"httpx probe failed: {e}")
            return []
        finally:
            Path(targets_file).unlink(missing_ok=True)

    def _custom_template_scan(self, targets: list[str]) -> list[dict]:
        """Sub-agent: Quick checks using common vulnerability patterns."""
        logger.info(f"    └─ sub-agent: custom checks ({len(targets)} targets)")
        
        findings = []
        
        for target in targets[:10]:
            self.tracker.wait()
            
            # Check for common endpoints
            common_paths = [
                "/.env", "/.git/config", "/admin", "/api/docs",
                "/graphql", "/swagger.json", "/.well-known/security.txt",
                "/robots.txt", "/sitemap.xml", "/backup/",
            ]
            
            for path in common_paths:
                self.tracker.wait()
                try:
                    resp = self.session.get(
                        f"https://{target}{path}",
                        timeout=10,
                        allow_redirects=False,
                    )
                    if resp.status_code == 200 and resp.status_code != 404:
                        findings.append({
                            "type": "exposed_endpoint",
                            "name": f"Exposed: {path}",
                            "host": target,
                            "severity": "medium",
                            "url": f"https://{target}{path}",
                            "status_code": resp.status_code,
                        })
                except Exception:
                    pass
        
        return findings

    def _severity_score(self, severity: str) -> int:
        scores = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
        return scores.get(severity.lower(), 0)

    def _count_by_sev(self, findings: list, severity: str) -> int:
        return sum(1 for f in findings if f.get("severity", "").lower() == severity)


# ==============================================================================
# Standalone scanning sub-agent
# ==============================================================================

class FindingSubAgent:
    """Standalone sub-agent: Scan a single target."""
    
    def __init__(self, target: str, scan_type: str):
        self.target = target
        self.scan_type = scan_type
    
    def run(self) -> list[dict]:
        logger.info(f"  [SUB-AGENT] {self.scan_type} scan on {self.target}")
        engine = ScanningEngine(load_config())
        return engine._custom_template_scan([self.target])


if __name__ == "__main__":
    from core.utils import setup_logging, print_banner, load_config
    setup_logging()
    print_banner()
    
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    if not target:
        print("Usage: python3 phase3_scanning.py <target.com>")
        sys.exit(1)
    
    config = load_config()
    engine = ScanningEngine(config)
    findings = engine.run([target], [], [target])
    
    print(f"\nFound {len(findings)} findings:")
    for f in findings[:10]:
        sev = f.get('severity', '?').upper()
        name = f.get('name', '?')
        host = f.get('host', '?')
        print(f"  [{sev}] {name} @ {host}")
