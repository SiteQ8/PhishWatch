"""
ICS / IoT / OT Phishing Detector
Specialized detection engine for phishing campaigns targeting
industrial control systems, IoT infrastructure, and operational technology.

Maps detections to MITRE ATT&CK for ICS where applicable.
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Tuple

from phishwatch.config import Config

logger = logging.getLogger(__name__)


class ICSCategory(str, Enum):
    SCADA = "SCADA/HMI"
    PLC = "PLC/RTU"
    DCS = "DCS"
    PROTOCOL = "Industrial Protocol"
    VENDOR = "ICS Vendor"
    IOT = "IoT/IIoT"
    SAFETY = "Safety System"
    ENERGY = "Energy/Utilities"
    BUILDING = "Building Automation"
    SUPPLY_CHAIN = "Supply Chain"
    FIRMWARE = "Firmware/Update"
    GENERIC_OT = "Generic OT"


@dataclass
class ICSDetection:
    """Result of ICS/IoT/OT analysis on a domain."""

    is_ics_targeted: bool = False
    category: Optional[ICSCategory] = None
    matched_terms: List[str] = field(default_factory=list)
    matched_vendors: List[str] = field(default_factory=list)
    matched_protocols: List[str] = field(default_factory=list)
    risk_multiplier: float = 1.0
    mitre_techniques: List[str] = field(default_factory=list)
    sector: str = "Unknown"
    description: str = ""
    confidence: float = 0.0


class ICSIoTDetector:
    """
    Detect phishing domains that specifically target ICS, IoT, or OT
    environments. This detector checks for vendor impersonation,
    protocol-themed lures, and sector-specific terminology.
    """

    def __init__(self, config: Optional[Config] = None):
        cfg = config or Config()
        self.vendors = [v.lower() for v in cfg.ICS_VENDORS]
        self.protocols = [p.lower() for p in cfg.ICS_PROTOCOLS]
        self.ics_terms = [t.lower() for t in cfg.ICS_TERMS]
        self.iot_terms = [t.lower() for t in cfg.IOT_TERMS]
        self.mitre = cfg.MITRE_ICS_TECHNIQUES

        # Vendor → sector mapping
        self._vendor_sector = {
            "siemens": "Energy / Manufacturing",
            "schneider": "Energy / Building Automation",
            "schneider-electric": "Energy / Building Automation",
            "rockwell": "Manufacturing",
            "allen-bradley": "Manufacturing",
            "honeywell": "Oil & Gas / Building",
            "abb": "Energy / Utilities",
            "emerson": "Oil & Gas / Chemical",
            "yokogawa": "Oil & Gas / Chemical",
            "ge-digital": "Energy / Utilities",
            "mitsubishi-electric": "Manufacturing",
            "omron": "Manufacturing / Automotive",
            "beckhoff": "Manufacturing / Motion",
            "moxa": "Network / Edge",
            "advantech": "IoT / Edge Computing",
            "wonderware": "SCADA / Manufacturing",
            "factorytalk": "Manufacturing",
            "aveva": "Engineering / SCADA",
        }

        # Category keywords
        self._category_map: Dict[ICSCategory, List[str]] = {
            ICSCategory.SCADA: ["scada", "hmi", "historian", "wincc", "wonderware", "factorytalk", "ifix", "genesis"],
            ICSCategory.PLC: ["plc", "rtu", "step7", "tia-portal", "codesys", "ladder", "structured-text"],
            ICSCategory.DCS: ["dcs", "deltav", "centum", "ovation", "experion", "foxboro", "prosafe"],
            ICSCategory.PROTOCOL: self.protocols,
            ICSCategory.VENDOR: self.vendors,
            ICSCategory.IOT: self.iot_terms,
            ICSCategory.SAFETY: ["sis", "safety-system", "triconex", "tristation", "esd", "fire-gas", "prosafe"],
            ICSCategory.ENERGY: ["smart-grid", "substation", "power-plant", "turbine", "generator"],
            ICSCategory.BUILDING: ["bms", "building-management", "hvac", "bacnet", "knx", "lonworks"],
            ICSCategory.SUPPLY_CHAIN: ["firmware-update", "patch", "license-server", "activation"],
            ICSCategory.FIRMWARE: ["firmware", "update-portal", "device-update", "ota-update"],
        }

        # Pre-compile patterns for speed
        self._patterns = {
            term: re.compile(re.escape(term.replace("-", r"[\-_.]?")), re.IGNORECASE)
            for group in [self.vendors, self.protocols, self.ics_terms, self.iot_terms]
            for term in group
        }

    # ── Public API ────────────────────────────────────────────────────────

    def analyze(self, domain: str) -> ICSDetection:
        """
        Analyse a single domain for ICS/IoT/OT targeting indicators.

        Returns an ICSDetection dataclass with findings.
        """
        domain_lower = domain.lower()
        # Normalise hyphens/underscores/dots for matching
        normalised = domain_lower.replace("_", "-").replace(".", "-")

        detection = ICSDetection()

        # 1. Vendor impersonation
        vendor_hits = self._match_group(normalised, self.vendors)
        if vendor_hits:
            detection.matched_vendors = vendor_hits
            detection.is_ics_targeted = True
            detection.sector = self._resolve_sector(vendor_hits)
            detection.mitre_techniques.append("T0817")  # Drive-by

        # 2. Protocol keywords
        proto_hits = self._match_group(normalised, self.protocols)
        if proto_hits:
            detection.matched_protocols = proto_hits
            detection.is_ics_targeted = True
            detection.mitre_techniques.append("T0869")  # Standard App Layer Protocol

        # 3. ICS / OT terms
        ics_hits = self._match_group(normalised, self.ics_terms)
        if ics_hits:
            detection.matched_terms.extend(ics_hits)
            detection.is_ics_targeted = True

        # 4. IoT terms
        iot_hits = self._match_group(normalised, self.iot_terms)
        if iot_hits:
            detection.matched_terms.extend(iot_hits)
            detection.is_ics_targeted = True

        if not detection.is_ics_targeted:
            return detection

        # Determine category
        detection.category = self._categorise(detection)

        # Risk multiplier – ICS-targeted phishing is always higher severity
        detection.risk_multiplier = self._calc_multiplier(detection)

        # Confidence
        total_hits = (
            len(detection.matched_vendors)
            + len(detection.matched_protocols)
            + len(detection.matched_terms)
        )
        detection.confidence = min(1.0, total_hits * 0.25)

        # Human-readable description
        detection.description = self._describe(domain, detection)

        # Deduplicate MITRE
        detection.mitre_techniques = list(set(detection.mitre_techniques))

        return detection

    def bulk_analyze(self, domains: List[str]) -> List[Tuple[str, ICSDetection]]:
        """Analyse many domains. Returns list of (domain, detection) pairs where is_ics_targeted is True."""
        results = []
        for d in domains:
            det = self.analyze(d)
            if det.is_ics_targeted:
                results.append((d, det))
        return results

    # ── Internals ─────────────────────────────────────────────────────────

    def _match_group(self, normalised: str, terms: List[str]) -> List[str]:
        hits = []
        for term in terms:
            clean = term.replace("-", "")
            if clean in normalised.replace("-", ""):
                hits.append(term)
        return hits

    def _categorise(self, det: ICSDetection) -> ICSCategory:
        all_hits = det.matched_vendors + det.matched_protocols + det.matched_terms
        best: Optional[ICSCategory] = None
        best_score = 0
        for cat, keywords in self._category_map.items():
            score = sum(1 for h in all_hits if h in keywords)
            if score > best_score:
                best_score = score
                best = cat
        return best or ICSCategory.GENERIC_OT

    def _calc_multiplier(self, det: ICSDetection) -> float:
        base = 1.3  # Any ICS targeting gets at least 1.3×
        if det.category in (ICSCategory.SAFETY, ICSCategory.ENERGY):
            base = 1.6  # Safety-critical
        if det.matched_vendors and det.matched_protocols:
            base += 0.2  # Combined vendor + protocol = highly targeted
        if len(det.matched_terms) > 2:
            base += 0.1
        return min(2.0, base)

    def _resolve_sector(self, vendors: List[str]) -> str:
        for v in vendors:
            s = self._vendor_sector.get(v)
            if s:
                return s
        return "Industrial / OT"

    def _describe(self, domain: str, det: ICSDetection) -> str:
        parts = []
        if det.matched_vendors:
            parts.append(f"impersonates ICS vendor(s): {', '.join(det.matched_vendors)}")
        if det.matched_protocols:
            parts.append(f"references protocol(s): {', '.join(det.matched_protocols)}")
        if det.matched_terms:
            parts.append(f"contains OT/IoT terms: {', '.join(det.matched_terms[:5])}")

        cat_label = det.category.value if det.category else "ICS/OT"
        return (
            f"[{cat_label}] Domain '{domain}' " + "; ".join(parts) + "."
            f" Sector: {det.sector}. Confidence: {det.confidence:.0%}."
        )
