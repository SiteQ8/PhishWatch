"""
Domain Analyzer v2
Comprehensive domain analysis for phishing detection with
enhanced entropy calculation, homograph detection, and ICS awareness.
"""

import logging
import math
import re
import socket
from collections import Counter
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class DomainAnalyzer:
    """Comprehensive domain analysis engine."""

    KNOWN_BRANDS = [
        "paypal", "microsoft", "google", "amazon", "apple", "facebook",
        "netflix", "dropbox", "adobe", "zoom", "linkedin", "twitter",
        "instagram", "whatsapp", "spotify", "github", "stackoverflow",
        "slack", "salesforce", "okta", "atlassian", "cloudflare",
        # ICS Vendors
        "siemens", "schneider", "rockwell", "honeywell", "abb",
        "emerson", "yokogawa", "mitsubishi", "omron", "beckhoff",
        "aveva", "wonderware", "factorytalk", "ge-digital",
    ]

    SUSPICIOUS_KEYWORDS = [
        "login", "signin", "sign-in", "verify", "account", "update",
        "suspend", "confirm", "support", "billing", "payment",
        "secure", "auth", "credential", "password", "reset",
        "urgent", "alert", "notification", "activate",
        # ICS-specific
        "firmware", "patch", "license", "activation", "portal",
        "remote-access", "vpn", "gateway",
    ]

    HOMOGRAPH_MAP = {
        "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
        "\u0443": "y", "\u0445": "x", "\u0441": "c", "\u0456": "i",
        "\u03bf": "o", "\u03c1": "p", "\u03b1": "a",
        "\u0261": "g", "\u0131": "i",
    }

    def analyze(self, domain: str) -> Dict:
        """Full analysis pipeline for a domain."""
        result: Dict = {
            "domain": domain,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "risk_factors": [],
            "similarity": {},
            "entropy": 0.0,
            "technical": {},
        }

        try:
            result["similarity"] = self._similarity_analysis(domain)
            result["entropy"] = self._shannon_entropy(domain.split(".")[0])
            result["risk_factors"] = self._pattern_analysis(domain)
            result["technical"] = self._technical_analysis(domain)
            result["homograph"] = self._homograph_check(domain)
        except Exception as exc:
            logger.error("Analysis error for %s: %s", domain, exc)
            result["error"] = str(exc)

        return result

    # ── Similarity ────────────────────────────────────────────────────────

    def _similarity_analysis(self, domain: str) -> Dict:
        dl = domain.lower()
        best = {"target": "", "score": 0, "distance": 999, "typosquat": False}

        for brand in self.KNOWN_BRANDS:
            if brand not in dl:
                continue
            dist = self._levenshtein(brand, dl.split(".")[0])
            typo = self._is_typosquat(brand, dl)
            score = max(0, 100 - dist * 8)
            if typo:
                score = max(score, 92)
            if score > best["score"]:
                best = {"target": brand, "score": score, "distance": dist, "typosquat": typo}

        return best

    def _is_typosquat(self, brand: str, domain: str) -> bool:
        subs = {"o": "0", "i": "1", "l": "1", "e": "3", "a": "@", "g": "9", "s": "5"}
        for orig, rep in subs.items():
            if brand.replace(orig, rep) in domain:
                return True
        for i in range(len(brand)):
            omit = brand[:i] + brand[i + 1 :]
            if len(omit) > 2 and omit in domain:
                return True
        for add in ["-", "1", "s", "x", "z", "online", "login"]:
            if (brand + add) in domain or (add + brand) in domain:
                return True
        return False

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return DomainAnalyzer._levenshtein(s2, s1)
        if not s2:
            return len(s1)
        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
            prev = curr
        return prev[-1]

    # ── Entropy ───────────────────────────────────────────────────────────

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    # ── Pattern analysis ──────────────────────────────────────────────────

    def _pattern_analysis(self, domain: str) -> List[str]:
        factors = []
        dl = domain.lower()

        for kw in self.SUSPICIOUS_KEYWORDS:
            if kw in dl:
                factors.append(f"Suspicious keyword: {kw}")

        if dl.count("-") > 3:
            factors.append("Excessive hyphens")
        if len(re.findall(r"\d", dl)) > 4:
            factors.append("Excessive digits")

        sus_tlds = [".tk", ".ml", ".cf", ".ga", ".buzz", ".click", ".download",
                    ".top", ".xyz", ".icu", ".cam", ".rest"]
        for tld in sus_tlds:
            if dl.endswith(tld):
                factors.append(f"Suspicious TLD: {tld}")

        if len(domain) > 60:
            factors.append("Unusually long domain")

        entropy = self._shannon_entropy(dl.split(".")[0])
        if entropy > 4.2:
            factors.append(f"High entropy ({entropy:.2f}) — possible DGA")

        return factors

    # ── Technical ─────────────────────────────────────────────────────────

    def _technical_analysis(self, domain: str) -> Dict:
        tech: Dict = {}
        try:
            ip = socket.gethostbyname(domain)
            tech["ip_address"] = ip
        except socket.gaierror:
            tech["dns_resolved"] = False
        except Exception as exc:
            tech["error"] = str(exc)
        return tech

    # ── Homograph ─────────────────────────────────────────────────────────

    def _homograph_check(self, domain: str) -> Dict:
        found = {}
        for ch in domain:
            if ch in self.HOMOGRAPH_MAP:
                found[ch] = self.HOMOGRAPH_MAP[ch]
        return {"detected": bool(found), "chars": found}
