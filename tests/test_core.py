"""PhishWatch test suite."""

import pytest
from phishwatch.core.domain_analyzer import DomainAnalyzer
from phishwatch.core.threat_classifier import ThreatClassifier
from phishwatch.core.ics_iot_detector import ICSIoTDetector, ICSCategory


# ── Domain Analyzer ───────────────────────────────────────────────────────

class TestDomainAnalyzer:
    def setup_method(self):
        self.analyzer = DomainAnalyzer()

    def test_known_brand_similarity(self):
        result = self.analyzer.analyze("paypal-login-secure.tk")
        assert result["similarity"]["target"] == "paypal"
        assert result["similarity"]["score"] > 50

    def test_no_similarity_for_clean_domain(self):
        result = self.analyzer.analyze("example.com")
        assert result["similarity"]["score"] == 0

    def test_suspicious_keywords_detected(self):
        result = self.analyzer.analyze("verify-account-update.xyz")
        factors = result["risk_factors"]
        assert any("verify" in f.lower() for f in factors)

    def test_suspicious_tld(self):
        result = self.analyzer.analyze("something.tk")
        factors = result["risk_factors"]
        assert any(".tk" in f for f in factors)

    def test_entropy_calculation(self):
        result = self.analyzer.analyze("a" * 30 + ".com")
        assert result["entropy"] == 0.0  # Single char = 0 entropy

        result2 = self.analyzer.analyze("xk3m9qz7p4.com")
        assert result2["entropy"] > 3.0

    def test_homograph_detection(self):
        # Using Cyrillic 'a' (U+0430)
        result = self.analyzer.analyze("\u0430pple-login.com")
        assert result["homograph"]["detected"] is True

    def test_typosquat_detection(self):
        # Use a domain that contains the brand name so similarity check triggers
        result = self.analyzer.analyze("google1-login.com")
        assert result["similarity"]["typosquat"] is True


# ── ICS/IoT/OT Detector ──────────────────────────────────────────────────

class TestICSDetector:
    def setup_method(self):
        self.detector = ICSIoTDetector()

    def test_vendor_detection(self):
        det = self.detector.analyze("siemens-update-portal.tk")
        assert det.is_ics_targeted is True
        assert "siemens" in det.matched_vendors
        assert det.risk_multiplier > 1.0

    def test_protocol_detection(self):
        det = self.detector.analyze("modbus-config-tool.xyz")
        assert det.is_ics_targeted is True
        assert "modbus" in det.matched_protocols

    def test_scada_terms(self):
        det = self.detector.analyze("scada-hmi-login.com")
        assert det.is_ics_targeted is True
        assert det.category == ICSCategory.SCADA

    def test_clean_domain_not_flagged(self):
        det = self.detector.analyze("example.com")
        assert det.is_ics_targeted is False

    def test_iot_terms(self):
        det = self.detector.analyze("mqtt-dashboard-login.com")
        assert det.is_ics_targeted is True

    def test_safety_system_high_multiplier(self):
        det = self.detector.analyze("triconex-safety-system-update.tk")
        assert det.is_ics_targeted is True
        assert det.risk_multiplier >= 1.3

    def test_bulk_analyze(self):
        domains = [
            "siemens-login.tk",
            "example.com",
            "schneider-update.xyz",
        ]
        results = self.detector.bulk_analyze(domains)
        assert len(results) == 2  # Only ICS-targeted

    def test_mitre_techniques_assigned(self):
        det = self.detector.analyze("honeywell-experion-portal.com")
        assert len(det.mitre_techniques) > 0


# ── Threat Classifier ────────────────────────────────────────────────────

class TestThreatClassifier:
    def setup_method(self):
        self.classifier = ThreatClassifier()

    def test_high_risk_domain(self):
        analysis = {
            "similarity": {"target": "paypal", "score": 85, "typosquat": True},
            "risk_factors": [
                "Suspicious keyword: login",
                "Suspicious keyword: verify",
                "Suspicious keyword: account",
                "Suspicious TLD: .tk",
                "Excessive hyphens",
            ],
            "entropy": 4.3,
            "homograph": {"detected": False},
            "technical": {"days_old": 3},
        }
        score = self.classifier.calculate_risk("paypal-verify-account-login.tk", analysis)
        assert score >= 60

    def test_ics_multiplier_raises_score(self):
        analysis = {
            "similarity": {"target": "siemens", "score": 60},
            "risk_factors": ["Suspicious keyword: login"],
            "entropy": 3.2,
            "homograph": {"detected": False},
            "technical": {},
        }
        detector = ICSIoTDetector()
        ics_det = detector.analyze("siemens-login-portal.tk")

        score_without = self.classifier.calculate_risk("siemens-login-portal.tk", analysis)
        score_with = self.classifier.calculate_risk("siemens-login-portal.tk", analysis, ics_det)
        assert score_with > score_without

    def test_classify_levels(self):
        assert self.classifier.classify(95) == "CRITICAL"
        assert self.classifier.classify(75) == "HIGH"
        assert self.classifier.classify(55) == "MEDIUM"
        assert self.classifier.classify(35) == "LOW"
        assert self.classifier.classify(15) == "MINIMAL"

    def test_report_includes_ics_context(self):
        analysis = {"similarity": {"target": "abb"}, "risk_factors": [], "entropy": 3.0, "homograph": {"detected": False}, "technical": {}}
        detector = ICSIoTDetector()
        ics_det = detector.analyze("abb-control-system.tk")
        score = self.classifier.calculate_risk("abb-control-system.tk", analysis, ics_det)
        report = self.classifier.report("abb-control-system.tk", analysis, score, ics_det)
        assert "ics_context" in report
        assert report["ics_context"]["sector"] is not None


# ── Integration ──────────────────────────────────────────────────────────

class TestIntegration:
    def test_full_pipeline(self):
        domain = "schneider-electric-firmware-update.tk"

        analyzer = DomainAnalyzer()
        classifier = ThreatClassifier()
        ics_detector = ICSIoTDetector()

        analysis = analyzer.analyze(domain)
        ics_det = ics_detector.analyze(domain)
        score = classifier.calculate_risk(domain, analysis, ics_det)
        report = classifier.report(domain, analysis, score, ics_det)

        assert report["risk_score"] > 0
        assert report["threat_level"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]
        assert "ics_context" in report
        assert "schneider" in report["ics_context"]["vendors"] or "schneider-electric" in report["ics_context"]["vendors"]
