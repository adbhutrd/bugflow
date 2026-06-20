"""
BugFlow - Phase 2: Reconnaissance
=====================================
Haddix-style: Multi-source recon with human-like behavior.
Spawns sub-agents for each recon source to run in parallel.
"""

import json
import logging
import random
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).parent.parent))

from core.humanize import random_delay, get_random_headers, get_session, RequestTracker
from core.utils import save_results, load_config, get_output_dir, check_tool

logger = logging.getLogger("bugflow.phase2_recon")


class ReconEngine:
    """Multi-source reconnaissance engine (Haddix-style).
    
    Spawns sub-agents for each recon source in parallel.
    """

    def __init__(self, config: dict):
        self.config = config
        rc_config = config.get("recon", {})
        self.sources = rc_config.get("sources", ["crt.sh", "subfinder", "wayback"])
        self.max_subdomains = rc_config.get("max_subdomains", 500)
        self.filter_cdn = rc_config.get("filter_cdn", True)
        self.tracker = RequestTracker()
        self.session = get_session()
        self.output_dir = Path(config.get("general", {}).get("output_dir", "output"))

    def run(self, targets: list[str]) -> dict:
        """Run full recon on all targets.
        
        Spawns parallel sub-agents for different recon sources.
        """
        logger.info("=" * 50)
        logger.info("PHASE 2: Reconnaissance (Haddix-style)")
        logger.info("=" * 50)
        
        all_subdomains = set()
        all_urls = set()
        all_tech = {}
        
        for target in targets:
            logger.info(f"\n[RECON] Target: {target}")
            
            # Spawn sub-agents for each source in parallel
            results = self._parallel_recon(target)
            
            # Merge results
            all_subdomains.update(results.get("subdomains", []))
            all_urls.update(results.get("urls", []))
            all_tech.update(results.get("technology", {}))
            
            random_delay(3, 8)  # Human pause between targets
        
        # Probe and filter
        live_hosts = self._probe_hosts(list(all_subdomains))
        
        # Save results
        out_dir = get_output_dir("recon", "phase2_recon", str(self.output_dir))
        save_results(sorted(all_subdomains), out_dir / "all_subdomains.txt")
        save_results(live_hosts, out_dir / "live_hosts.txt")
        save_results(sorted(all_urls), out_dir / "all_urls.txt")
        
        result = {
            "total_subdomains": len(all_subdomains),
            "live_hosts": len(live_hosts),
            "total_urls": len(all_urls),
            "technologies": all_tech,
            "subdomains": list(all_subdomains)[:self.max_subdomains],
            "live_hosts_list": live_hosts,
            "urls": list(all_urls)[:200],
        }
        
        logger.info(f"Phase 2 complete: {result['total_subdomains']} subdomains, "
                    f"{result['live_hosts']} live")
        return result

    def _parallel_recon(self, target: str) -> dict:
        """Run multiple recon sources in parallel via sub-agents."""
        results = {"subdomains": set(), "urls": set(), "technology": {}}
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {}
            
            # Sub-agent 1: crt.sh
            if "crt.sh" in self.sources:
                futures[executor.submit(self._crt_sh_source, target)] = "crt.sh"
            
            # Sub-agent 2: subfinder (if installed)
            if "subfinder" in self.sources and check_tool("subfinder"):
                futures[executor.submit(self._subfinder_source, target)] = "subfinder"
            
            # Sub-agent 3: Wayback Machine
            if "wayback" in self.sources:
                futures[executor.submit(self._wayback_source, target)] = "wayback"
            
            # Sub-agent 4: DNS (common subdomain wordlist)
            if "dnsdumpster" in self.sources:
                futures[executor.submit(self._dns_common_source, target)] = "dns"
            
            logger.info(f"  Spawned {len(futures)} recon sub-agents for {target}")
            
            for future in as_completed(futures):
                source_name = futures[future]
                try:
                    data = future.result()
                    if data:
                        results["subdomains"].update(data.get("subdomains", []))
                        results["urls"].update(data.get("urls", []))
                        logger.info(f"  [SUB-AGENT {source_name}] Found "
                                  f"{len(data.get('subdomains', []))} subdomains, "
                                  f"{len(data.get('urls', []))} URLs")
                except Exception as e:
                    logger.warning(f"  [SUB-AGENT {source_name}] Failed: {e}")
        
        return results

    # ========================
    # Sub-agent: crt.sh source
    # ========================
    def _crt_sh_source(self, domain: str) -> dict:
        """Query Certificate Transparency logs (crt.sh)."""
        logger.info(f"    └─ sub-agent: crt.sh for {domain}")
        random_delay(1, 3)
        
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", "30",
                 f"https://crt.sh/?q=%25.{domain}&output=json"],
                capture_output=True, text=True, timeout=35
            )
            if result.returncode != 0 or not result.stdout:
                return {"subdomains": set(), "urls": set()}
            
            data = json.loads(result.stdout)
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                if name:
                    for sub in name.split("\n"):
                        sub = sub.strip()
                        if sub.endswith(domain):
                            subdomains.add(sub)
            
            return {"subdomains": subdomains, "urls": set()}
        except Exception as e:
            logger.debug(f"crt.sh failed: {e}")
            return {"subdomains": set(), "urls": set()}

    # =============================
    # Sub-agent: subfinder (Haddix favorite)
    # =============================
    def _subfinder_source(self, domain: str) -> dict:
        """Run subfinder for passive subdomain enumeration."""
        logger.info(f"    └─ sub-agent: subfinder for {domain}")
        random_delay(2, 5)
        
        try:
            result = subprocess.run(
                ["subfinder", "-d", domain, "-silent", "-o", "/dev/stdout"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode != 0:
                return {"subdomains": set(), "urls": set()}
            
            subdomains = set()
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if line and line.endswith(domain):
                    subdomains.add(line)
            
            return {"subdomains": subdomains, "urls": set()}
        except Exception as e:
            logger.debug(f"subfinder failed: {e}")
            return {"subdomains": set(), "urls": set()}

    # ============================
    # Sub-agent: Wayback Machine
    # ============================
    def _wayback_source(self, domain: str) -> dict:
        """Query Wayback Machine for historical URLs and subdomains."""
        logger.info(f"    └─ sub-agent: wayback for {domain}")
        random_delay(2, 4)
        
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", "30",
                 f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
                 f"&output=text&fl=original&collapse=urlkey"],
                capture_output=True, text=True, timeout=35
            )
            if result.returncode != 0 or not result.stdout:
                return {"subdomains": set(), "urls": set()}
            
            urls = set()
            subdomains = set()
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if line:
                    urls.add(line)
                    # Extract subdomain from URL
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(line)
                        host = parsed.hostname or ""
                        if host.endswith(domain):
                            subdomains.add(host)
                    except Exception:
                        pass
            
            return {"subdomains": subdomains, "urls": urls}
        except Exception as e:
            logger.debug(f"wayback failed: {e}")
            return {"subdomains": set(), "urls": set()}

    # ==================================
    # Sub-agent: Common DNS wordlist
    # ==================================
    def _dns_common_source(self, domain: str) -> dict:
        """Check common subdomains via DNS resolution."""
        logger.info(f"    └─ sub-agent: dns-common for {domain}")
        
        common_subs = [
            "www", "api", "admin", "dev", "staging", "test", "beta",
            "app", "portal", "mail", "remote", "blog", "cdn", "shop",
            "secure", "vpn", "webmail", "dashboard", "docs", "help",
            "support", "status", "graphql", "rest", "graph", "auth",
        ]
        
        subdomains = set()
        for sub in common_subs:
            random_delay(0.2, 0.8)
            try:
                import socket
                hostname = f"{sub}.{domain}"
                socket.getaddrinfo(hostname, 80, socket.AF_INET)
                subdomains.add(hostname)
            except (socket.gaierror, Exception):
                pass
        
        return {"subdomains": subdomains, "urls": set()}

    # =======================
    # Probe live hosts
    # =======================
    def _probe_hosts(self, hosts: list[str]) -> list[str]:
        """Check which hosts are actually live."""
        logger.info(f"  Probing {len(hosts)} hosts for liveness...")
        live = []
        
        for host in hosts[:self.max_subdomains]:
            self.tracker.wait()
            try:
                resp = self.session.get(
                    f"https://{host}",
                    timeout=10,
                    allow_redirects=True,
                )
                if resp.status_code and resp.status_code < 500:
                    live.append(host)
                    if len(live) <= 5:
                        logger.info(f"    LIVE: {host} ({resp.status_code})")
            except Exception:
                pass
        
        logger.info(f"  Found {len(live)} live hosts out of {min(len(hosts), self.max_subdomains)} probed")
        return live


# ==============================================================================
# Standalone sub-agent for parallel target research
# ==============================================================================

class SubdomainSubAgent:
    """Standalone sub-agent: Run a single recon source on one target."""
    
    def __init__(self, target: str, source: str):
        self.target = target
        self.source = source
    
    def run(self) -> dict:
        """Run the recon source and return results."""
        logger.info(f"  [SUB-AGENT] Recon: {self.source} on {self.target}")
        
        # Each sub-agent uses the engine to run its source
        engine = ReconEngine(load_config())
        
        if self.source == "crt.sh":
            return engine._crt_sh_source(self.target)
        elif self.source == "subfinder":
            return engine._subfinder_source(self.target)
        elif self.source == "wayback":
            return engine._wayback_source(self.target)
        else:
            return {"subdomains": set(), "urls": set()}


if __name__ == "__main__":
    from core.utils import setup_logging, print_banner, load_config
    setup_logging()
    print_banner()
    
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    if not target:
        print("Usage: python3 phase2_recon.py <target.com>")
        sys.exit(1)
    
    config = load_config()
    engine = ReconEngine(config)
    results = engine.run([target])
    
    print(f"\nRecon complete for {target}:")
    print(f"  Subdomains: {results['total_subdomains']}")
    print(f"  Live hosts: {results['live_hosts']}")
    print(f"  URLs: {results['total_urls']}")
