"""Tests for BugFlow phase modules."""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

BASE_CONFIG = {
    "general": {"max_workers": 1, "output_dir": "output"},
    "target_selection": {
        "enabled": True,
        "min_payouts": 5,
        "max_scope_domains": 50,
        "platforms": ["hackerone"],
    },
    "recon": {
        "enabled": True,
        "sources": ["crt.sh"],
        "api_keys": {},
        "max_subdomains": 100,
    },
    "scanning": {
        "enabled": True,
        "nuclei_templates": "all",
        "min_severity": "medium",
    },
    "api_testing": {
        "enabled": True,
        "discover": ["wayback_urls"],
    },
    "reporting": {
        "enabled": True,
        "format": "markdown",
    },
}


class TestPhase1TargetSelection:
    """Test target selection phase."""

    def test_target_selector_creation(self):
        """TargetSelector should initialize."""
        from bugflow.phases.phase1_targets import TargetSelector
        selector = TargetSelector(BASE_CONFIG)
        assert selector is not None

    @patch("bugflow.phases.phase1_targets.TargetSelector.run")
    def test_target_selector_run(self, mock_run):
        """TargetSelector.run should return a list."""
        mock_run.return_value = [{"name": "Shopify", "domain": "shopify.com", "payouts": 500}]
        from bugflow.phases.phase1_targets import TargetSelector
        selector = TargetSelector(BASE_CONFIG)
        result = selector.run("shopify.com")
        assert isinstance(result, list)
        assert len(result) > 0
        assert "name" in result[0]


class TestPhase2Recon:
    """Test reconnaissance phase."""

    def test_recon_engine_creation(self):
        """ReconEngine should initialize."""
        from bugflow.phases.phase2_recon import ReconEngine
        engine = ReconEngine(BASE_CONFIG)
        assert engine is not None

    @patch("bugflow.phases.phase2_recon.ReconEngine.run")
    def test_recon_engine_run(self, mock_run):
        """ReconEngine.run should return recon data."""
        mock_run.return_value = {
            "subdomains": ["api.example.com", "admin.example.com"],
            "total_subdomains": 2,
            "live_hosts": 1,
        }
        from bugflow.phases.phase2_recon import ReconEngine
        engine = ReconEngine(BASE_CONFIG)
        result = engine.run(["example.com"])
        assert "subdomains" in result
        assert result["total_subdomains"] == 2


class TestPhase3Scanning:
    """Test scanning phase."""

    def test_scanning_engine_creation(self):
        """ScanningEngine should initialize."""
        from bugflow.phases.phase3_scanning import ScanningEngine
        engine = ScanningEngine(BASE_CONFIG)
        assert engine is not None

    @patch("bugflow.phases.phase3_scanning.ScanningEngine.run")
    def test_scanning_engine_run(self, mock_run):
        """ScanningEngine.run should return findings."""
        mock_run.return_value = [
            {
                "type": "xss",
                "severity": "high",
                "endpoint": "https://example.com/search?q=test",
                "template": "xss-reflected",
            }
        ]
        from bugflow.phases.phase3_scanning import ScanningEngine
        engine = ScanningEngine(BASE_CONFIG)
        findings = engine.run(["example.com"], ["api.example.com"], ["https://example.com"])
        assert isinstance(findings, list)
        assert findings[0]["severity"] == "high"


class TestPhase4APITesting:
    """Test API testing phase."""

    def test_api_engine_creation(self):
        """APITestingEngine should initialize."""
        from bugflow.phases.phase4_api_testing import APITestingEngine
        engine = APITestingEngine(BASE_CONFIG)
        assert engine is not None

    @patch("bugflow.phases.phase4_api_testing.APITestingEngine.run")
    def test_api_engine_run(self, mock_run):
        """APITestingEngine.run should return API findings."""
        mock_run.return_value = [
            {"type": "bola", "severity": "critical", "endpoint": "/api/users/1"}
        ]
        from bugflow.phases.phase4_api_testing import APITestingEngine
        engine = APITestingEngine(BASE_CONFIG)
        findings = engine.run(["https://api.example.com"], ["https://api.example.com/v1"])
        assert isinstance(findings, list)
        assert findings[0]["type"] == "bola"


class TestPhase5Report:
    """Test reporting phase."""

    def test_report_writer_creation(self):
        """ReportWriter should initialize."""
        from bugflow.phases.phase5_report import ReportWriter
        writer = ReportWriter(BASE_CONFIG)
        assert writer is not None

    @patch("bugflow.phases.phase5_report.ReportWriter.run")
    def test_report_writer_run(self, mock_run):
        """ReportWriter.run should return reports."""
        mock_run.return_value = [{"format": "markdown", "file": "report.md"}]
        from bugflow.phases.phase5_report import ReportWriter
        writer = ReportWriter(BASE_CONFIG)
        findings = [{"type": "xss", "severity": "medium", "endpoint": "/test"}]
        reports = writer.run(findings, {"name": "Test", "domain": "example.com"})
        assert isinstance(reports, list)
        assert reports[0]["format"] == "markdown"
