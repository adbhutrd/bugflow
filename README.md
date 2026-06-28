# 🐛 BugFlow — Multi-Agent Bug Bounty Automation Engine

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License MIT">
  <img src="https://img.shields.io/badge/status-production-green.svg" alt="Production Ready">
  <img src="https://github.com/adbhutrd/bugflow/actions/workflows/tests.yml/badge.svg" alt="Tests">
</p>

<p align="center">
  <b>The open-source bug bounty automation engine.</b><br>
  From target selection to professional report — all in one command.
</p>

---

## ⚡ What is BugFlow?

BugFlow automates the entire bug bounty workflow using a **5-phase pipeline** inspired by industry leaders like Jason Haddix and Katie Paxton-Fear (InsiderPhD). It handles reconnaissance, vulnerability scanning, API testing, and professional reporting — orchestrating sub-agents that run in parallel for maximum efficiency.

**The problem BugFlow solves:** Bug bounty hunters waste 60-70% of their time on manual reconnaissance and report writing. BugFlow automates the repetitive parts so you focus on finding actual bugs.

```
┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
│  PHASE 1    │───▶│   PHASE 2    │───▶│   PHASE 3    │───▶│   PHASE 4   │───▶│   PHASE 5    │
│  Targets    │    │  Recon       │    │  Scanning    │    │  API Test   │    │  Report      │
│  Selection  │    │  Multi-Src   │    │  Nuclei+     │    │  BOLA/IDOR  │    │  Professional│
│  Haddix-Style│   │  10 Sources  │    │  Custom      │    │  Auth+Rate  │    │  CVSS+Remed   │
└─────────────┘    └──────────────┘    └──────────────┘    └─────────────┘    └──────────────┘
```

## 🚀 Quick Start

```bash
# Install
pip install bugflow

# Run full pipeline on a target
bugflow --target shopify.com --program Shopify

# Run only recon phase
bugflow --target api.target.com --phase 2

# Check installed tools
bugflow --check-tools

# List all phases
bugflow --list-phases
```

## 📦 What's Inside

### Phase 1: Target Selection (Haddix-Style)
- Scans bug bounty platforms (HackerOne, Bugcrowd, Intigriti, YesWeHack)
- Analyzes minimum payout thresholds, scope size, and response times
- Spawns research sub-agents for each promising target
- Outputs prioritized target list

### Phase 2: Reconnaissance (10 Sources)
- **Certificate Transparency** — crt.sh
- **OWASP Amass** — Comprehensive subdomain enumeration
- **GetAllUrls (gau)** — Wayback Machine + AlienVault + CommonCrawl
- **AlienVault OTX** — Free threat intelligence API
- **URLScan.io** — URL discovery
- **HackerTarget** — Free API
- **GitHub Dorking** — Public repository scanning
- **ProjectDiscovery Chaos** — Chaos dataset
- **SecurityTrails** — DNS intelligence (free tier)
- **Common DNS** — Wordlist-based brute force

### Phase 3: Vulnerability Scanning
- Nuclei template engine with custom template support
- Configurable severity filters
- Live host verification before scanning
- Parallel scanning for speed

### Phase 4: API Testing (InsiderPhD-Style)
- BOLA (Broken Object Level Authorization)
- IDOR (Insecure Direct Object References)
- Broken Authentication flows
- Mass Assignment vulnerabilities
- Rate limiting bypasses

### Phase 5: Report Writing
- Professional markdown reports
- CVSS 3.1 severity scoring
- Step-by-step remediation instructions
- Executive summary + technical details
- Auto-save to organized output directory

## 🛠️ Configuration

BugFlow is fully configurable via `config.yaml`:

```yaml
general:
  max_workers: 3          # Parallel agents per phase
  output_dir: "output"    # Where results are saved

recon:
  enabled: true
  sources:                # Enable/disable recon sources
    - crt.sh
    - amass
    - gau
    - github
  max_subdomains: 500     # Subdomain limit

scanning:
  enabled: true
  nuclei_templates: "all"
  min_severity: "medium"  # low, medium, high, critical

api_testing:
  enabled: true
  test_idor: true
  test_auth: true
  test_mass_assignment: true
```

## 🧪 Running Tests

```bash
pip install -e ".[dev]"
pytest --cov=bugflow --cov-report=term-missing
```

## 📊 Example Run

```bash
$ bugflow --target example.com

╔══════════════════════════════════════════════════════╗
║              BUGFLOW v1.0.0                          ║
║     Multi-Agent Bug Bounty Pipeline                  ║
╚══════════════════════════════════════════════════════╝

🎯 Target: example.com
📋 Program: Example
Starting full BugFlow pipeline...

✅ Available tools: python3, crt.sh, amass, gau, httpx, nuclei

============================================================
PHASE 1/5: Target Selection (Haddix-style)
============================================================
  📊 Analyzing 4 bug bounty platforms...
  🎯 Selected 3 high-value targets
  💡 Tip: High response rate, prioritize this program

============================================================
PHASE 2/5: Reconnaissance (Haddix-style)
============================================================
  🔍 Subdomain discovery using 10 sources...
  ✅ Found 247 subdomains, 89 live hosts

============================================================
PHASE 3/5: Vulnerability Scanning
============================================================
  🔬 Running Nuclei + custom checks...
  ⚠️  Found 12 potential vulnerabilities

============================================================
PHASE 4/5: API Testing (InsiderPhD-style)
============================================================
  🔌 Testing API endpoints...
  🚨 Found 3 API vulnerabilities (1 critical BOLA)

============================================================
PHASE 5/5: Report Writing (Hermes-powered)
============================================================
  📝 Generating professional report...
  ✅ Report saved: output/example.com/report_2026-06-28.md

============================================================
BUGFLOW PIPELINE COMPLETE
============================================================

Target: example.com
Pipeline: 5 phases complete

Phase 1 - Targets: 3 selected
Phase 2 - Recon: 247 subdomains, 89 live
Phase 3 - Scanning: 12 findings
Phase 4 - API: 3 API issues
Phase 5 - Reports: 1 report generated

💰 Ready to submit: 15 potential bugs
```

## 🏆 Why BugFlow?

| Feature | BugFlow | Manual | Other Tools |
|---------|---------|--------|-------------|
| Multi-source recon | ✅ 10 sources | ❌ Hours of work | ⚠️ 1-3 sources |
| API testing | ✅ BOLA/IDOR/Auth | ❌ Manual only | ❌ None |
| Professional reports | ✅ Auto-generated | ❌ 2-4 hours | ⚠️ Templates only |
| Parallel execution | ✅ Multi-agent | ❌ Sequential | ⚠️ Limited |
| Configurable | ✅ Full YAML | ❌ N/A | ⚠️ Partial |
| Open source | ✅ MIT Licensed | N/A | ⚠️ Mixed |

## 🤝 Contributing

Contributions are welcome! BugFlow is built for the bug bounty community, by the community.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📚 Resources

- **Bug Bounty Platforms**: [HackerOne](https://hackerone.com), [Bugcrowd](https://bugcrowd.com), [Intigriti](https://intigriti.com)
- **Inspired by**: Jason Haddix's methodology, InsiderPhD's API testing approach, ProjectDiscovery's tools
- **Built with**: Python, YAML, colorama, requests

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- **Jason Haddix** — For pioneering the modern bug bounty reconnaissance methodology
- **Katie Paxton-Fear (InsiderPhD)** — For API security testing frameworks
- **ProjectDiscovery** — For open-source security tools (nuclei, subfinder, httpx)
- **OWASP** — For the Amass project and security standards

---

<p align="center">
  <b>Built with ❤️ by <a href="https://github.com/adbhutrd">Enish Shah</a></b><br>
  MSc Cyber Security (Distinction) · Bug Bounty Hunter · Tool Builder
</p>
