"""
BugFlow - Phase 2: Reconnaissance
=====================================
Haddix-style: Multi-source recon with human-like behavior.
Spawns sub-agents for each recon source to run in parallel.
Now with 8 additional sources for deeper coverage.
"""

import json
import logging
import random
import subprocess
import sys
import socket
import shlex
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
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
        self.sources_dict = rc_config
        self.sources = rc_config.get("sources", ["crt.sh", "gau", "dns_common"])
        self.max_subdomains = rc_config.get("max_subdomains", 500)
        self.filter_cdn = rc_config.get("filter_cdn", True)
        self.api_keys = rc_config.get("api_keys", {})
        self.tracker = RequestTracker()
        self.session = get_session()
        self.output_dir = Path(config.get("general", {}).get("output_dir", "output"))

    def run(self, targets: list[str]) -> dict:
        """Run full recon on all targets.
        
        Spawns parallel sub-agents for different recon sources.
        """
        logger.info("=" * 50)
        logger.info("PHASE 2: Reconnaissance (Haddix-style)")
        logger.info(f"  Sources enabled: {', '.join(self.sources)}")
        logger.info("=" * 50)
        
        all_subdomains = set()
        all_urls = set()
        all_tech = {}
        source_stats = {}
        
        for target in targets:
            logger.info(f"\n[RECON] Target: {target}")
            
            # Spawn sub-agents for each source in parallel
            results, stats = self._parallel_recon(target)
            
            # Merge results
            all_subdomains.update(results.get("subdomains", []))
            all_urls.update(results.get("urls", []))
            all_tech.update(results.get("technology", {}))
            for k, v in stats.items():
                source_stats[k] = source_stats.get(k, 0) + v
            
            random_delay(3, 8)  # Human pause between targets
        
        # Probe and filter using httpx
        live_hosts = self._probe_hosts(list(all_subdomains))
        
        # Save results
        out_dir = get_output_dir("recon", "phase2_recon", str(self.output_dir))
        save_results(sorted(all_subdomains), out_dir / "all_subdomains.txt")
        save_results(live_hosts, out_dir / "live_hosts.txt")
        save_results(sorted(all_urls), out_dir / "all_urls.txt")
        save_results([f"{k}: {v} found" for k, v in sorted(source_stats.items())], 
                     out_dir / "source_breakdown.txt")
        
        result = {
            "total_subdomains": len(all_subdomains),
            "live_hosts": len(live_hosts),
            "total_urls": len(all_urls),
            "technologies": all_tech,
            "source_breakdown": source_stats,
            "subdomains": list(all_subdomains)[:self.max_subdomains],
            "live_hosts_list": live_hosts,
            "urls": list(all_urls)[:500],
        }
        
        logger.info(f"Phase 2 complete: {result['total_subdomains']} subdomains, "
                    f"{result['live_hosts']} live, {result['total_urls']} URLs")
        for src, count in sorted(source_stats.items()):
            logger.info(f"  └─ {src}: {count}")
        return result

    def _parallel_recon(self, target: str) -> tuple[dict, dict]:
        """Run multiple recon sources in parallel via sub-agents."""
        results = {"subdomains": set(), "urls": set(), "technology": {}}
        source_stats = {}
        
        source_map = {
                "crt.sh": self._crt_sh_source,
                "amass": self._amass_source,
                "gau": self._gau_source,
                "alienvault": self._alienvault_source,
                "urlscan": self._urlscan_source,
                "hackertarget": self._hackertarget_source,
                "github": self._github_source,
                "chaos": self._chaos_source,
                "securitytrails": self._securitytrails_source,
                "dns_common": self._dns_common_source,
            }
            
        num_sources = len([s for s in self.sources if s in source_map])
        num_workers = min(max(num_sources, 1), self.config.get("general", {}).get("max_workers", 3) * 3)
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = {}
            for source_name in self.sources:
                source_fn = source_map.get(source_name)
                if source_fn:
                    futures[executor.submit(source_fn, target)] = source_name
            
            logger.info(f"  Spawned {len(futures)} recon sub-agents for {target}")
            
            for future in as_completed(futures):
                source_name = futures[future]
                try:
                    data = future.result()
                    if data:
                        subs = data.get("subdomains", [])
                        urls = data.get("urls", [])
                        results["subdomains"].update(subs)
                        results["urls"].update(urls)
                        source_stats[source_name] = len(subs) + len(urls)
                        logger.info(f"  [SUB-AGENT {source_name}] "
                                  f"{len(subs)} subdomains, {len(urls)} URLs")
                except Exception as e:
                    logger.warning(f"  [SUB-AGENT {source_name}] Failed: {e}")
                    source_stats[source_name] = 0
        
        return results, source_stats

    # ============================
    # Sub-agent 1: crt.sh (CT logs)
    # ============================
    def _crt_sh_source(self, domain: str) -> dict:
        """Query Certificate Transparency logs (crt.sh). Free, no API key needed."""
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
            
            # Handle non-JSON responses (e.g. 502 Bad Gateway)
            if not result.stdout.strip().startswith("["):
                logger.warning(f"      crt.sh returned non-JSON response: {result.stdout[:100]}...")
                return {"subdomains": set(), "urls": set()}
            
            data = json.loads(result.stdout)
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                if name:
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and "*" not in sub:
                            subdomains.add(sub)
            
            return {"subdomains": subdomains, "urls": set()}
        except Exception as e:
            logger.debug(f"crt.sh failed: {e}")
            return {"subdomains": set(), "urls": set()}

    # ============================
    # Sub-agent 2: Amass (installed)
    # ============================
    def _amass_source(self, domain: str) -> dict:
        """Run OWASP Amass for passive subdomain enumeration. Installed on system."""
        if not check_tool("amass"):
            logger.debug("amass not installed, skipping")
            return {"subdomains": set(), "urls": set()}
        
        logger.info(f"    └─ sub-agent: amass (intel mode) for {domain}")
        random_delay(2, 5)
        
        try:
            # Amass intel mode - passive, WHOIS-based discovery (no traffic to target)
            result = subprocess.run(
                ["amass", "intel", "-d", domain, "-whois", "-max-dns-queries", "200",
                 "-timeout", "60", "-o", "/dev/stdout"],
                capture_output=True, text=True, timeout=90
            )
            subdomains = set()
            if result.stdout:
                for line in result.stdout.strip().split("\n"):
                    line = line.strip().lower()
                    if line and line.endswith(domain):
                        subdomains.add(line)
            
            return {"subdomains": subdomains, "urls": set()}
        except subprocess.TimeoutExpired:
            logger.debug(f"amass timed out for {domain}")
            return {"subdomains": set(), "urls": set()}
        except Exception as e:
            logger.debug(f"amass failed: {e}")
            return {"subdomains": set(), "urls": set()}

    # ============================
    # Sub-agent 3: GAU (GetAllUrls, installed)
    # ============================
    def _gau_source(self, domain: str) -> dict:
        """Run GAU to fetch URLs from Wayback, OTX, CommonCrawl. Installed on system."""
        if not check_tool("gau"):
            logger.debug("gau not installed, falling back to wayback source")
            return self._wayback_fallback(domain)
        
        logger.info(f"    └─ sub-agent: gau for {domain}")
        random_delay(2, 4)
        
        try:
            # Use all providers for maximum coverage
            result = subprocess.run(
                ["gau", "--subs", "--providers", "wayback,otx,commoncrawl", domain],
                capture_output=True, text=True, timeout=90
            )
            if result.stderr:
                logger.debug(f"      gau stderr: {result.stderr.strip()}")
            if not result.stdout:
                logger.debug(f"      gau returned no output, falling back")
                return self._wayback_fallback(domain)
            
            urls = set()
            subdomains = set()
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if line:
                    urls.add(line)
                    try:
                        parsed = urlparse(line)
                        host = (parsed.hostname or "").lower()
                        if host.endswith(domain):
                            subdomains.add(host)
                    except Exception:
                        pass
            
            logger.info(f"      gau found {len(urls)} URLs, {len(subdomains)} subdomains")
            return {"subdomains": subdomains, "urls": urls}
        except subprocess.TimeoutExpired:
            logger.debug(f"gau timed out, falling back to wayback")
            return self._wayback_fallback(domain)
        except Exception as e:
            logger.debug(f"gau failed: {e}, falling back to wayback")
            return self._wayback_fallback(domain)

    def _wayback_fallback(self, domain: str) -> dict:
        """Fallback: direct Wayback CDX API if GAU is not available."""
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", "30",
                 f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
                 f"&output=text&fl=original&collapse=urlkey"],
                capture_output=True, text=True, timeout=35
            )
            if not result.stdout:
                return {"subdomains": set(), "urls": set()}
            
            urls = set()
            subdomains = set()
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if line:
                    urls.add(line)
                    try:
                        parsed = urlparse(line)
                        host = (parsed.hostname or "").lower()
                        if host.endswith(domain):
                            subdomains.add(host)
                    except Exception:
                        pass
            return {"subdomains": subdomains, "urls": urls}
        except Exception as e:
            logger.debug(f"wayback fallback failed: {e}")
            return {"subdomains": set(), "urls": set()}

    # ============================
    # Sub-agent 4: AlienVault OTX
    # ============================
    def _alienvault_source(self, domain: str) -> dict:
        """Query AlienVault OTX API. Free, no API key needed for basic queries."""
        logger.info(f"    └─ sub-agent: alienvault OTX for {domain}")
        random_delay(1, 3)
        
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            result = subprocess.run(
                ["curl", "-s", "--max-time", "20",
                 "-H", get_random_headers().get("User-Agent", "Mozilla/5.0"),
                 url],
                capture_output=True, text=True, timeout=25
            )
            if not result.stdout:
                return {"subdomains": set(), "urls": set()}
            
            data = json.loads(result.stdout)
            subdomains = set()
            for entry in data.get("passive_dns", []):
                hostname = (entry.get("hostname", "") or "").strip().lower()
                if hostname and hostname.endswith(domain):
                    subdomains.add(hostname)
            
            # Also try the URL list endpoint
            random_delay(1, 2)
            url2 = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
            result2 = subprocess.run(
                ["curl", "-s", "--max-time", "15",
                 "-H", get_random_headers().get("User-Agent", "Mozilla/5.0"),
                 url2],
                capture_output=True, text=True, timeout=20
            )
            if result2.stdout:
                try:
                    data2 = json.loads(result2.stdout)
                    urls = set()
                    for entry in data2.get("url_list", []):
                        u = (entry.get("url", "") or "").strip()
                        if u:
                            urls.add(u)
                    return {"subdomains": subdomains, "urls": urls}
                except (json.JSONDecodeError, KeyError):
                    pass
            
            return {"subdomains": subdomains, "urls": set()}
        except Exception as e:
            logger.debug(f"alienvault failed: {e}")
            return {"subdomains": set(), "urls": set()}

    # ============================
    # Sub-agent 5: URLScan.io
    # ============================
    def _urlscan_source(self, domain: str) -> dict:
        """Query URLScan.io for subdomains and URLs. Free tier, no key needed for basic."""
        logger.info(f"    └─ sub-agent: urlscan.io for {domain}")
        random_delay(3, 6)
        
        api_key = self.api_keys.get("urlscan", "")
        
        try:
            cmd = ["curl", "-s", "--max-time", "20"]
            if api_key:
                cmd.extend(["-H", f"API-Key: {api_key}"])
            url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100" if api_key else f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=20"
            cmd.append(url)
            
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=25
            )
            if not result.stdout:
                return {"subdomains": set(), "urls": set()}
            
            data = json.loads(result.stdout)
            subdomains = set()
            urls = set()
            
            for entry in data.get("results", []):
                page = entry.get("page", {})
                dom = (page.get("domain", "") or "").lower()
                url = (page.get("url", "") or "").lower()
                if dom and dom.endswith(domain):
                    subdomains.add(dom)
                if url:
                    urls.add(url)
            
            return {"subdomains": subdomains, "urls": urls}
        except Exception as e:
            logger.debug(f"urlscan failed: {e}")
            return {"subdomains": set(), "urls": set()}

    # ============================
    # Sub-agent 6: HackerTarget
    # ============================
    def _hackertarget_source(self, domain: str) -> dict:
        """Query HackerTarget API. Free, no API key needed (rate limited to ~5 req/day)."""
        logger.info(f"    └─ sub-agent: hackertarget for {domain}")
        random_delay(2, 5)
        
        try:
            # Hostname lookup
            result = subprocess.run(
                ["curl", "-s", "--max-time", "20",
                 f"https://api.hackertarget.com/hostsearch/?q={domain}"],
                capture_output=True, text=True, timeout=25
            )
            if not result.stdout:
                return {"subdomains": set(), "urls": set()}
            
            output = result.stdout.strip()
            if "error" in output.lower() or "rate limit" in output.lower():
                logger.debug(f"      hackertarget: {output[:100]}")
                return {"subdomains": set(), "urls": set()}
            
            subdomains = set()
            for line in output.split("\n"):
                if "," in line:
                    parts = line.split(",")
                    host = parts[0].strip().lower()
                    if host and host.endswith(domain):
                        subdomains.add(host)
            
            return {"subdomains": subdomains, "urls": set()}
        except Exception as e:
            logger.debug(f"hackertarget failed: {e}")
            return {"subdomains": set(), "urls": set()}

    # ============================
    # Sub-agent 7: GitHub Dorking
    # ============================
    def _github_source(self, domain: str) -> dict:
        """Search GitHub for domain references. Helps find leaked configs, API keys, endpoints."""
        logger.info(f"    └─ sub-agent: github dorking for {domain}")
        random_delay(3, 7)
        
        token = self.api_keys.get("github_token", "")
        subdomains = set()
        urls = set()
        
        try:
            if not token:
                logger.info("      (no github_token in config — sparse results, 60 unauthenticated req/hr)")
            
            # Search for domain references in code
            queries = [domain, f"api.{domain}", f"https://{domain}"]
            
            for query in queries:
                random_delay(2, 4)
                cmd = ["curl", "-s", "--max-time", "15"]
                if token:
                    cmd.extend(["-H", f"Authorization: token {token}"])
                cmd.append(f"https://api.github.com/search/code?q={shlex.quote(query)}&per_page=10")
                
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=20
                )
                if not result.stdout:
                    continue
                
                try:
                    data = json.loads(result.stdout)
                    for item in data.get("items", []):
                        repo = item.get("repository", {}).get("full_name", "")
                        if repo:
                            urls.add(f"https://github.com/{repo}")
                except (json.JSONDecodeError, KeyError):
                    pass
            
            return {"subdomains": subdomains, "urls": urls}
        except Exception as e:
            logger.debug(f"github dorking failed: {e}")
            return {"subdomains": set(), "urls": set()}

    # ============================
    # Sub-agent 8: Chaos (ProjectDiscovery)
    # ============================
    def _chaos_source(self, domain: str) -> dict:
        """Query ProjectDiscovery Chaos dataset. Free tier available."""
        logger.info(f"    └─ sub-agent: chaos dataset for {domain}")
        random_delay(2, 5)
        
        token = self.api_keys.get("chaos_token", "")
        
        try:
            cmd = ["curl", "-s", "--max-time", "20"]
            if token:
                cmd.extend(["-H", f"Authorization: {token}"])
            cmd.append(f"https://dns.projectdiscovery.io/dns/{domain}.json")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
            
            if not result.stdout:
                return {"subdomains": set(), "urls": set()}
            
            output = result.stdout.strip()
            
            # Handle unauthorized / not found
            if output.startswith("{") and ('"unauthorized"' in output or '"error"' in output.lower()):
                logger.debug(f"      chaos API: {output[:100]} (set chaos_token in config if needed)")
                return {"subdomains": set(), "urls": set()}
            
            subdomains = set()
            try:
                data = json.loads(output)
                if isinstance(data, list):
                    for entry in data:
                        host = (entry.get("host", "") or "").strip().lower()
                        if host and host.endswith(domain):
                            subdomains.add(host)
                elif isinstance(data, dict):
                    for key, entry in data.items():
                        host = (entry.get("host", "") or "").strip().lower() if isinstance(entry, dict) else ""
                        if host and host.endswith(domain):
                            subdomains.add(host)
            except json.JSONDecodeError:
                pass
            
            return {"subdomains": subdomains, "urls": set()}
        except Exception as e:
            logger.debug(f"chaos failed: {e}")
            return {"subdomains": set(), "urls": set()}

    # ============================
    # Sub-agent 9: SecurityTrails
    # ============================
    def _securitytrails_source(self, domain: str) -> dict:
        """Query SecurityTrails DNS API. Needs free API key from securitytrails.com."""
        api_key = self.api_keys.get("securitytrails", "")
        if not api_key:
            logger.debug("securitytrails: no API key configured, skipping")
            return {"subdomains": set(), "urls": set()}
        
        logger.info(f"    └─ sub-agent: securitytrails for {domain}")
        random_delay(2, 4)
        
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", "20",
                 "-H", f"APIKEY: {api_key}",
                 f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"],
                capture_output=True, text=True, timeout=25
            )
            if not result.stdout:
                return {"subdomains": set(), "urls": set()}
            
            data = json.loads(result.stdout)
            subdomains = set()
            for sub in data.get("subdomains", []):
                full = f"{sub}.{domain}".lower()
                subdomains.add(full)
            
            return {"subdomains": subdomains, "urls": set()}
        except Exception as e:
            logger.debug(f"securitytrails failed: {e}")
            return {"subdomains": set(), "urls": set()}

    # ============================
    # Sub-agent 10: DNS Common wordlist
    # ============================
    def _dns_common_source(self, domain: str) -> dict:
        """Check common subdomains via DNS resolution. No external deps."""
        logger.info(f"    └─ sub-agent: dns-common wordlist for {domain}")
        
        common_subs = [
            "www", "api", "admin", "dev", "staging", "test", "beta",
            "app", "portal", "mail", "remote", "blog", "cdn", "shop",
            "secure", "vpn", "webmail", "dashboard", "docs", "help",
            "support", "status", "graphql", "rest", "graph", "auth",
            "jenkins", "jira", "gitlab", "confluence", "wiki", "swagger",
            "sso", "oauth", "login", "register", "signup", "console",
            "monitor", "metrics", "logs", "analytics", "tracking",
            "static", "assets", "img", "media", "files", "uploads",
            "download", "api-docs", "developer", "partners", "partners-api",
            "sandbox", "demo", "training", "corp", "internal", "intranet",
            "backup", "db", "database", "redis", "mysql", "mongo",
            "stage", "prod", "production", "uat", "qa", "ci",
            "alpha", "edge", "cdn", "static", "resolver",
        ]
        
        subdomains = set()
        for sub in common_subs:
            random_delay(0.1, 0.3)
            try:
                hostname = f"{sub}.{domain}"
                socket.getaddrinfo(hostname, 80, socket.AF_INET)
                subdomains.add(hostname)
            except (socket.gaierror, Exception):
                pass
        
        return {"subdomains": subdomains, "urls": set()}

    # ============================
    # Probe live hosts
    # ============================
    def _probe_hosts(self, hosts: list[str]) -> list[str]:
        """Check which hosts are actually live using httpx (if installed) or direct HTTP probe.
        
        Note: The 'httpx' tool on this system is the Python HTTPX CLI, NOT the ProjectDiscovery
        httpx tool. We skip the PD httpx check and always use the built-in HTTP probe.
        """
        logger.info(f"  Probing {len(hosts)} hosts for liveness...")
        
        if not hosts:
            return []
        
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
            except Exception:
                try:
                    resp = self.session.get(
                        f"http://{host}",
                        timeout=8,
                        allow_redirects=True,
                    )
                    if resp.status_code and resp.status_code < 500:
                        live.append(host)
                except Exception:
                    pass
        
        logger.info(f"  Found {len(live)} live hosts out of {min(len(hosts), self.max_subdomains)}")
        return live


# ==============================================================================
# Standalone sub-agent for parallel execution
# ==============================================================================

class SubdomainSubAgent:
    """Standalone sub-agent: Run a single recon source on one target."""
    
    def __init__(self, target: str, source: str):
        self.target = target
        self.source = source
    
    def run(self) -> dict:
        """Run the recon source and return results."""
        logger.info(f"  [SUB-AGENT] Recon: {self.source} on {self.target}")
        
        engine = ReconEngine(load_config())
        source_methods = {
            "crt.sh": engine._crt_sh_source,
            "amass": engine._amass_source,
            "gau": engine._gau_source,
            "alienvault": engine._alienvault_source,
            "urlscan": engine._urlscan_source,
            "hackertarget": engine._hackertarget_source,
            "github": engine._github_source,
            "chaos": engine._chaos_source,
            "securitytrails": engine._securitytrails_source,
            "dns_common": engine._dns_common_source,
        }
        
        method = source_methods.get(self.source)
        if method:
            return method(self.target)
        return {"subdomains": set(), "urls": set()}


if __name__ == "__main__":
    from core.utils import setup_logging, print_banner, load_config
    setup_logging()
    print_banner()
    
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    if not target:
        print("Usage: python3 phase2_recon.py <target.com>")
        print("       python3 phase2_recon.py targets.txt")
        sys.exit(1)
    
    config = load_config()
    engine = ReconEngine(config)
    
    from pathlib import Path
    if Path(target).exists():
        with open(target) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    else:
        targets = [target]
    
    results = engine.run(targets)
    
    print(f"\n{'='*50}")
    print(f"RECON COMPLETE")
    print(f"{'='*50}")
    print(f"  Targets scanned: {len(targets)}")
    print(f"  Subdomains found: {results['total_subdomains']}")
    print(f"  Live hosts: {results['live_hosts']}")
    print(f"  URLs discovered: {results['total_urls']}")
    print(f"\nSource breakdown:")
    for src, count in sorted(results.get("source_breakdown", {}).items()):
        print(f"  └─ {src}: {count}")
