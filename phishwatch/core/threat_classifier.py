"""
Threat Classifier v2
Multi-factor risk scoring with ICS/IoT/OT awareness.
Maps findings to MITRE ATT&CK for ICS framework.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional

from phishwatch.config import Config

logger = logging.getLogger(__name__)


class ThreatClassifier:
    """Risk scoring and classification engine."""

    WEIGHTS = {
        "similarity": 0.22,
        "registration": 0.15,
        "patterns": 0.15,
        "dns": 0.08,
        "geo": 0.08,
        "tld": 0.10,
        "entropy": 0.07,
        "homograph": 0.05,
        "ics_targeting": 0.10,  # NEW: ICS/OT targeting boost
    }

    HIGH_RISK_TLDS = [
        ".tk", ".ml", ".cf", ".ga", ".buzz", ".click", ".download",
        ".loan", ".cricket", ".science", ".work", ".party",
        ".top", ".xyz", ".icu", ".cam", ".rest",
    ]

    HIGH_RISK_COUNTRIES = ["RU", "CN", "KP", "IR"]

    def calculate_risk(
        self,
        domain: str,
        analysis: Dict,
        ics_detection: Optional[object] = None,
    ) -> int:
        """
        Calculate 0-100 risk score combining all factors.
        If ics_detection is provided and is_ics_targeted, applies multiplier.
        """
        components: Dict[str, float] = {}

        components["similarity"] = self._score_similarity(analysis)
        components["registration"] = self._score_registration(analysis)
        components["patterns"] = self._score_patterns(analysis)
        components["dns"] = self._score_dns(analysis)
        components["geo"] = self._score_geo(analysis)
        components["tld"] = self._score_tld(domain)
        components["entropy"] = self._score_entropy(analysis)
        components["homograph"] = self._score_homograph(analysis)
        components["ics_targeting"] = 0.0

        # Weighted base score
        base = sum(components[k] * self.WEIGHTS[k] for k in self.WEIGHTS)

        # ICS/OT multiplier
        multiplier = 1.0
        if ics_detection and getattr(ics_detection, "is_ics_targeted", False):
            multiplier = getattr(ics_detection, "risk_multiplier", 1.3)
            components["ics_targeting"] = 80.0
            base = sum(components[k] * self.WEIGHTS[k] for k in self.WEIGHTS)

        final = min(100, max(0, int(base * multiplier)))

        logger.debug("Risk for %s: components=%s base=%.1f mult=%.2f final=%d",
                      domain, components, base, multiplier, final)
        return final

    # ── Component scorers ─────────────────────────────────────────────────

    @staticmethod
    def _score_similarity(analysis: Dict) -> float:
        sim = analysis.get("similarity", {})
        s = sim.get("score", 0)
        if s > 80:
            return 95.0
        if s > 60:
            return 75.0
        if s > 40:
            return 50.0
        if s > 20:
            return 30.0
        return 10.0

    @staticmethod
    def _score_registration(analysis: Dict) -> float:
        days = analysis.get("technical", {}).get("days_old")
        if days is None:
            return 30.0
        if days < 1:
            return 95.0
        if days < 7:
            return 80.0
        if days < 30:
            return 60.0
        if days < 90:
            return 40.0
        return 15.0

    @staticmethod
    def _score_patterns(analysis: Dict) -> float:
        factors = analysis.get("risk_factors", [])
        kw = sum(1 for f in factors if "keyword" in f.lower())
        struct = sum(1 for f in factors if any(x in f.lower() for x in ["hyphen", "digit", "long"]))
        tld = sum(1 for f in factors if "tld" in f.lower())
        dga = sum(1 for f in factors if "entropy" in f.lower() or "dga" in f.lower())
        return min(100.0, kw * 20 + struct * 12 + tld * 18 + dga * 25)

    @staticmethod
    def _score_dns(analysis: Dict) -> float:
        tech = analysis.get("technical", {})
        risk = 0.0
        if tech.get("dns_resolved") is False:
            risk += 25
        return min(100.0, risk)

    def _score_geo(self, analysis: Dict) -> float:
        country = analysis.get("technical", {}).get("country", "").upper()
        if country in self.HIGH_RISK_COUNTRIES:
            return 80.0
        return 25.0

    def _score_tld(self, domain: str) -> float:
        dl = domain.lower()
        for tld in self.HIGH_RISK_TLDS:
            if dl.endswith(tld):
                return 85.0
        return 20.0

    @staticmethod
    def _score_entropy(analysis: Dict) -> float:
        ent = analysis.get("entropy", 0.0)
        if ent > 4.5:
            return 90.0
        if ent > 4.0:
            return 60.0
        if ent > 3.5:
            return 35.0
        return 10.0

    @staticmethod
    def _score_homograph(analysis: Dict) -> float:
        h = analysis.get("homograph", {})
        if h.get("detected"):
            return 95.0
        return 0.0

    # ── Classification helpers ────────────────────────────────────────────

    @staticmethod
    def classify(score: int) -> str:
        if score >= 90:
            return "CRITICAL"
        if score >= 70:
            return "HIGH"
        if score >= 50:
            return "MEDIUM"
        if score >= 30:
            return "LOW"
        return "MINIMAL"

    @staticmethod
    def color(score: int) -> str:
        level = ThreatClassifier.classify(score)
        return {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#22c55e",
            "MINIMAL": "#06b6d4",
        }.get(level, "#6b7280")

    def report(self, domain: str, analysis: Dict, score: int, ics_det=None) -> Dict:
        """Generate a structured threat report."""
        level = self.classify(score)
        rpt = {
            "domain": domain,
            "risk_score": score,
            "threat_level": level,
            "color": self.color(score),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "recommendations": self._recommendations(score, analysis),
            "summary": self._summary(domain, score, analysis),
        }
        if ics_det and getattr(ics_det, "is_ics_targeted", False):
            rpt["ics_context"] = {
                "category": ics_det.category.value if ics_det.category else None,
                "vendors": ics_det.matched_vendors,
                "protocols": ics_det.matched_protocols,
                "sector": ics_det.sector,
                "mitre_techniques": ics_det.mitre_techniques,
                "confidence": ics_det.confidence,
            }
        return rpt

    @staticmethod
    def _recommendations(score: int, analysis: Dict) -> List[str]:
        recs = []
        if score >= 90:
            recs.extend([
                "IMMEDIATE: Block domain across all network segments including OT",
                "Add to SIEM and firewall deny-lists",
                "Alert SOC and OT security teams",
                "Check for similar domains (typosquatting variants)",
            ])
        elif score >= 70:
            recs.extend([
                "Block domain in web proxy and DNS sinkhole",
                "Add to monitoring watchlist",
                "Notify affected asset owners",
            ])
        elif score >= 50:
            recs.extend([
                "Add to watchlist for continued monitoring",
                "Investigate if accessed from OT network segments",
            ])
        else:
            recs.append("Continue passive monitoring")

        if analysis.get("similarity", {}).get("typosquat"):
            recs.append("Investigate brand impersonation — consider takedown")
        if analysis.get("homograph", {}).get("detected"):
            recs.append("Homograph/IDN attack detected — high confidence phishing")

        return recs

    @staticmethod
    def _summary(domain: str, score: int, analysis: Dict) -> str:
        target = analysis.get("similarity", {}).get("target", "unknown")
        level = ThreatClassifier.classify(score)
        return f"{level} ({score}/100): {domain} — probable target: {target}"
