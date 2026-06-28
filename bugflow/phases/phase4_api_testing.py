"""
BugFlow - Phase 4: API Testing
================================
InsiderPhD-style: API discovery and vulnerability testing.
Spawns sub-agents for different API test types (BOLA, Auth, Mass Assignment).
"""

import json
import logging
import random
import sys
from pathlib import Path
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).parent.parent))

from core.humanize import random_delay, get_random_headers, get_session, RequestTracker
from core.utils import save_results, load_config, get_output_dir

logger = logging.getLogger("bugflow.phase4_api_testing")


class APITestingEngine:
    """API security testing engine (InsiderPhD-style).
    
    Phase 4 focuses on the OWASP API Top 10 vulnerabilities,
    especially BOLA (Broken Object Level Authorization) and
    Broken Authentication.
    """

    def __init__(self, config: dict):
        self.config = config
        api_config = config.get("api_testing", {})
        self.test_idor = api_config.get("test_idor", True)
        self.test_auth = api_config.get("test_auth", True)
        self.test_mass = api_config.get("test_mass_assignment", True)
        self.tracker = RequestTracker()
        self.session = get_session()
        self.output_dir = Path(config.get("general", {}).get("output_dir", "output"))
        self.findings = []

    def run(self, live_hosts: list[str], urls: list[str]) -> list[dict]:
        """Run API testing phase.
        
        Spawns sub-agents for different vulnerability types in parallel.
        """
        logger.info("=" * 50)
        logger.info("PHASE 4: API Testing (InsiderPhD-style)")
        logger.info("=" * 50)

        # Step 1: Discover API endpoints
        api_endpoints = self._discover_apis(urls, live_hosts)
        logger.info(f"  Discovered {len(api_endpoints)} API endpoints")

        # Step 2: Run parallel API test sub-agents
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}
            
            if self.test_idor and api_endpoints:
                futures[executor.submit(self._test_bola, api_endpoints)] = "BOLA/IDOR"
            
            if self.test_auth and api_endpoints:
                futures[executor.submit(self._test_auth, api_endpoints)] = "Broken Auth"
            
            if self.test_mass and api_endpoints:
                futures[executor.submit(self._test_mass_assignment, api_endpoints)] = "Mass Assignment"
            
            # Also test rate limiting
            futures[executor.submit(self._test_rate_limits, api_endpoints[:3])] = "Rate Limits"

            for future in as_completed(futures):
                name = futures[future]
                try:
                    f = future.result()
                    if f:
                        self.findings.extend(f)
                        logger.info(f"  [SUB-AGENT {name}] Found {len(f)} issues")
                except Exception as e:
                    logger.warning(f"  [SUB-AGENT {name}] Failed: {e}")

        # Step 3: Save results
        out_dir = get_output_dir("api_testing", "phase4_api", str(self.output_dir))
        save_results(self.findings, out_dir / "api_findings.json", fmt="json")
        save_results([f"{f.get('severity','?').upper()} | {f.get('type','?')} | {f.get('endpoint','?')}" 
                      for f in self.findings], out_dir / "api_findings_summary.txt")

        logger.info(f"Phase 4 complete: {len(self.findings)} API findings")
        return self.findings

    def _discover_apis(self, urls: list[str], hosts: list[str]) -> list[str]:
        """Discover API endpoints from URLs and common patterns."""
        api_patterns = ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/",
                        "/swagger", "/openapi", "/docs", "/api-docs"]
        
        discovered = set()
        
        # Extract from collected URLs
        for url in urls:
            for pattern in api_patterns:
                if pattern in url.lower():
                    discovered.add(url)
        
        # Check common API paths on live hosts
        common_api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/graphql", "/swagger.json", "/openapi.json",
            "/.well-known/openid-configuration",
            "/api-docs", "/docs", "/swagger",
            "/api/health", "/api/status",
        ]
        
        for host in hosts[:10]:
            for path in common_api_paths:
                self.tracker.wait()
                try:
                    resp = self.session.get(
                        f"https://{host}{path}",
                        timeout=10,
                        allow_redirects=False,
                    )
                    if resp.status_code in [200, 201, 401, 403, 405]:
                        api_url = f"https://{host}{path}"
                        discovered.add(api_url)
                        logger.info(f"    Found API: {api_url} ({resp.status_code})")
                except Exception:
                    pass
        
        return list(discovered)

    def _test_bola(self, endpoints: list[str]) -> list[dict]:
        """Sub-agent: Test for BOLA/IDOR vulnerabilities.
        
        InsiderPhD's #1 recommended API vulnerability to hunt.
        Tries accessing other users' data by changing IDs.
        """
        logger.info(f"    └─ sub-agent: BOLA/IDOR testing")
        findings = []
        
        for endpoint in endpoints[:10]:
            self.tracker.wait()
            
            # Look for numeric IDs in the URL path
            parts = urlparse(endpoint)
            path_segments = parts.path.split("/")
            
            for i, segment in enumerate(path_segments):
                if segment.isdigit() and int(segment) > 0:
                    # Try IDOR: change the ID
                    original_id = segment
                    # Only test 2 IDs to avoid triggering WAFs
                    test_ids = [
                        str(int(original_id) + 1),
                        str(int(original_id) - 1) if int(original_id) > 1 else "1",
                    ]
                    
                    for test_id in test_ids:
                        self.tracker.wait()
                        test_path = path_segments.copy()
                        test_path[i] = test_id
                        test_url = f"{parts.scheme}://{parts.netloc}{'/'.join(test_path)}"
                        
                        try:
                            resp = self.session.get(
                                test_url,
                                timeout=10,
                                headers=get_random_headers(),
                            )
                            if resp.status_code == 200:
                                findings.append({
                                    "type": "potential_idor",
                                    "name": f"Potential IDOR in endpoint",
                                    "endpoint": test_url,
                                    "severity": "high",
                                    "original_id": original_id,
                                    "tested_id": test_id,
                                    "status_code": resp.status_code,
                                    "response_size": len(resp.text),
                                })
                        except Exception:
                            pass
        
        return findings

    def _test_auth(self, endpoints: list[str]) -> list[dict]:
        """Sub-agent: Test for broken authentication.
        
        Checks for:
        - Endpoints accessible without auth headers
        - Weak token formats
        - Missing authorization checks
        """
        logger.info(f"    └─ sub-agent: broken auth testing")
        findings = []

        for endpoint in endpoints[:10]:
            self.tracker.wait()
            
            # Test without auth header
            try:
                resp = self.session.get(
                    endpoint,
                    timeout=10,
                    headers={k: v for k, v in get_random_headers().items() 
                            if k.lower() != "authorization"},
                )
                if resp.status_code in [200, 201]:
                    findings.append({
                        "type": "missing_auth",
                        "name": "Endpoint accessible without authentication",
                        "endpoint": endpoint,
                        "severity": "critical",
                        "status_code": resp.status_code,
                    })
            except Exception:
                pass
            
            # Test with fake token
            self.tracker.wait()
            try:
                headers = get_random_headers()
                headers["Authorization"] = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake"
                resp = self.session.get(endpoint, timeout=10, headers=headers)
                if resp.status_code in [200, 201]:
                    findings.append({
                        "type": "weak_auth",
                        "name": "Server doesn't validate tokens properly",
                        "endpoint": endpoint,
                        "severity": "high",
                        "status_code": resp.status_code,
                    })
            except Exception:
                pass

        return findings

    def _test_mass_assignment(self, endpoints: list[str]) -> list[dict]:
        """Sub-agent: Test for mass assignment vulnerabilities.
        
        Inserts extra fields into API requests to see if they're accepted.
        """
        logger.info(f"    └─ sub-agent: mass assignment testing")
        findings = []

        extra_fields = [
            {"role": "admin", "is_admin": True},
            {"admin": True, "is_admin": True},
            {"is_active": True, "is_verified": True},
            {"balance": 999999, "credit": 999999},
        ]

        for endpoint in endpoints[:5]:
            self.tracker.wait()
            
            for fields in extra_fields:
                self.tracker.wait()
                try:
                    resp = self.session.post(
                        endpoint,
                        json=fields,
                        timeout=10,
                        headers=get_random_headers(),
                    )
                    if resp.status_code in [200, 201, 202]:
                        findings.append({
                            "type": "potential_mass_assignment",
                            "name": f"Server accepted extra fields: {list(fields.keys())}",
                            "endpoint": endpoint,
                            "severity": "high",
                            "fields_tested": list(fields.keys()),
                            "status_code": resp.status_code,
                        })
                except Exception:
                    pass

        return findings

    def _test_rate_limits(self, endpoints: list[str]) -> list[dict]:
        """Sub-agent: Test for missing rate limiting (human-like pace)."""
        logger.info(f"    └─ sub-agent: rate limit testing")
        findings = []

        for endpoint in endpoints[:2]:
            responses = []
            for i in range(10):  # Send 10 requests with human delays
                self.tracker.wait()
                try:
                    resp = self.session.get(endpoint, timeout=5)
                    responses.append(resp.status_code)
                except Exception:
                    responses.append(0)
            
            # If all requests succeeded without rate limiting
            if len(set(responses)) == 1 and responses[0] in [200, 201, 401, 403]:
                findings.append({
                    "type": "missing_rate_limit",
                    "name": "No rate limiting detected on endpoint",
                    "endpoint": endpoint,
                    "severity": "medium",
                    "requests_sent": 10,
                    "responses": responses[:5],
                })

        return findings


# ==============================================================================
# Standalone sub-agent for parallel target research
# ==============================================================================

class APISubAgent:
    """Standalone sub-agent: Run one type of API test on one endpoint."""
    
    def __init__(self, endpoint: str, test_type: str):
        self.endpoint = endpoint
        self.test_type = test_type
    
    def run(self) -> list[dict]:
        logger.info(f"  [SUB-AGENT] {self.test_type} on {self.endpoint}")
        engine = APITestingEngine(load_config())
        
        if self.test_type == "BOLA":
            return engine._test_bola([self.endpoint])
        elif self.test_type == "auth":
            return engine._test_auth([self.endpoint])
        elif self.test_type == "mass_assignment":
            return engine._test_mass_assignment([self.endpoint])
        return []


if __name__ == "__main__":
    from core.utils import setup_logging, print_banner, load_config
    setup_logging()
    print_banner()
    
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    if not target:
        print("Usage: python3 phase4_api_testing.py <api-endpoint-url>")
        sys.exit(1)
    
    config = load_config()
    engine = APITestingEngine(config)
    findings = engine.run([target], [target])
    
    print(f"\nAPI testing complete: {len(findings)} findings")
    for f in findings:
        print(f"  [{f.get('severity','?').upper()}] {f.get('name','?')} @ {f.get('endpoint','?')}")
