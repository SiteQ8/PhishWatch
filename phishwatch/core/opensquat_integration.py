"""
OpenSquat Integration v2
Interface for domain-squatting detection via OpenSquat.
"""

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class OpenSquatIntegration:
    """Wrapper around OpenSquat for domain squatting detection."""

    def __init__(self, opensquat_path: Optional[str] = None, keywords: Optional[List[str]] = None):
        self.opensquat_path = opensquat_path or os.environ.get(
            "OPENSQUAT_PATH", "/opt/opensquat/opensquat.py"
        )
        self.keywords = keywords or []
        self._available = self._check_available()

    @property
    def available(self) -> bool:
        return self._available

    def _check_available(self) -> bool:
        return Path(self.opensquat_path).exists()

    def scan(self, keywords: Optional[List[str]] = None) -> List[Dict]:
        """
        Run OpenSquat scan against current NRD feed.
        Returns list of suspicious domain dicts.
        """
        kw_list = keywords or self.keywords
        if not kw_list:
            logger.warning("No keywords configured for OpenSquat scan")
            return []

        if not self._available:
            logger.warning("OpenSquat not found at %s — using fallback", self.opensquat_path)
            return self._fallback_scan(kw_list)

        results: List[Dict] = []

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as kf:
                kf.write("\n".join(kw_list))
                kf_path = kf.name

            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as of:
                of_path = of.name

            cmd = [
                "python3", self.opensquat_path,
                "-k", kf_path,
                "-o", of_path,
                "-t", "0",  # All confidence levels
                "--type", "json",
            ]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if proc.returncode == 0 and Path(of_path).exists():
                with open(of_path) as f:
                    raw = json.load(f)
                    for entry in raw:
                        results.append({
                            "domain": entry.get("domain", ""),
                            "keyword": entry.get("keyword", ""),
                            "similarity": entry.get("similarity", 0),
                            "source": "OpenSquat",
                        })
            else:
                logger.error("OpenSquat failed: %s", proc.stderr[:500])

            # Cleanup
            Path(kf_path).unlink(missing_ok=True)
            Path(of_path).unlink(missing_ok=True)

        except subprocess.TimeoutExpired:
            logger.error("OpenSquat scan timed out")
        except Exception as exc:
            logger.error("OpenSquat error: %s", exc)

        return results

    def _fallback_scan(self, keywords: List[str]) -> List[Dict]:
        """Lightweight fallback when OpenSquat binary isn't available."""
        # Returns empty — actual scanning requires the OpenSquat tool
        logger.info("Fallback mode: OpenSquat binary not available, skipping scan")
        return []
