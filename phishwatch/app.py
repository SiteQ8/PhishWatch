#!/usr/bin/env python3
"""
PhishWatch v2 — Real-time Phishing Detection Platform
Main Flask + SocketIO application.

Author: Ali AlEnezi (SiteQ8)
"""

import csv
import io
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

from flask import Flask, render_template, jsonify, request, Response
from flask_socketio import SocketIO, emit

from phishwatch import __version__
from phishwatch.config import Config
from phishwatch.core.domain_analyzer import DomainAnalyzer
from phishwatch.core.threat_classifier import ThreatClassifier
from phishwatch.core.ics_iot_detector import ICSIoTDetector
from phishwatch.core.certstream_monitor import CertStreamMonitor
from phishwatch.core.opensquat_integration import OpenSquatIntegration

logging.basicConfig(level=logging.INFO, format=Config.LOG_FORMAT)
logger = logging.getLogger(__name__)


class PhishWatch:
    """Core application orchestrator."""

    def __init__(self, config: Optional[Config] = None):
        self.cfg = config or Config()

        # Flask
        self.app = Flask(
            __name__,
            template_folder="templates",
            static_folder="static",
        )
        self.app.config.from_object(self.cfg)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*", async_mode="threading")

        # Engines
        self.analyzer = DomainAnalyzer()
        self.classifier = ThreatClassifier()
        self.ics_detector = ICSIoTDetector(self.cfg)
        self.certstream = CertStreamMonitor(
            url=self.cfg.CERTSTREAM_URL,
            keywords=list(self.cfg.DEFAULT_WATCHLIST),
        )
        self.opensquat = OpenSquatIntegration(keywords=list(self.cfg.DEFAULT_WATCHLIST))

        # State
        self.detections: List[Dict] = []
        self.monitoring = False
        self._opensquat_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Counters
        self.stats = {
            "total": 0,
            "critical": 0,
            "high": 0,
            "ics_targeted": 0,
            "avg_risk": 0.0,
            "monitoring": False,
        }

        self._register_routes()
        self._register_socket_events()

    # ── Routes ────────────────────────────────────────────────────────────

    def _register_routes(self):
        @self.app.route("/")
        def index():
            return render_template("dashboard.html", version=__version__, stats=self.stats)

        @self.app.route("/api/v2/status")
        def api_status():
            return jsonify({
                "app": self.cfg.APP_NAME,
                "version": __version__,
                "monitoring": self.monitoring,
                "stats": self._calc_stats(),
            })

        @self.app.route("/api/v2/detections")
        def api_detections():
            risk = request.args.get("risk", "all")
            source = request.args.get("source", "all")
            ics_only = request.args.get("ics_only", "false") == "true"
            limit = min(int(request.args.get("limit", 100)), 1000)

            filtered = self._filter(risk, source, ics_only)
            return jsonify({"detections": filtered[:limit], "total": len(filtered)})

        @self.app.route("/api/v2/start", methods=["POST"])
        def api_start():
            if not self.monitoring:
                self._start_monitoring()
            return jsonify({"status": "monitoring", "active": True})

        @self.app.route("/api/v2/stop", methods=["POST"])
        def api_stop():
            if self.monitoring:
                self._stop_monitoring()
            return jsonify({"status": "stopped", "active": False})

        @self.app.route("/api/v2/analyze", methods=["POST"])
        def api_analyze():
            data = request.get_json(silent=True) or {}
            domain = data.get("domain", "").strip()
            if not domain:
                return jsonify({"error": "domain required"}), 400
            analysis = self.analyzer.analyze(domain)
            ics_det = self.ics_detector.analyze(domain)
            score = self.classifier.calculate_risk(domain, analysis, ics_det)
            report = self.classifier.report(domain, analysis, score, ics_det)
            return jsonify(report)

        @self.app.route("/api/v2/keywords", methods=["GET", "POST", "DELETE"])
        def api_keywords():
            if request.method == "GET":
                return jsonify({"keywords": list(self.cfg.DEFAULT_WATCHLIST)})
            data = request.get_json(silent=True) or {}
            kw = data.get("keyword", "").strip().lower()
            if request.method == "POST" and kw:
                if kw not in self.cfg.DEFAULT_WATCHLIST:
                    self.cfg.DEFAULT_WATCHLIST.append(kw)
                    self.certstream.update_keywords(self.cfg.DEFAULT_WATCHLIST)
                return jsonify({"keywords": self.cfg.DEFAULT_WATCHLIST})
            if request.method == "DELETE" and kw:
                self.cfg.DEFAULT_WATCHLIST = [k for k in self.cfg.DEFAULT_WATCHLIST if k != kw]
                self.certstream.update_keywords(self.cfg.DEFAULT_WATCHLIST)
                return jsonify({"keywords": self.cfg.DEFAULT_WATCHLIST})
            return jsonify({"error": "keyword required"}), 400

        @self.app.route("/api/v2/export")
        def api_export():
            fmt = request.args.get("format", "csv")
            if fmt == "json":
                return Response(
                    json.dumps(self.detections, indent=2),
                    mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=phishwatch_export.json"},
                )
            # CSV
            buf = io.StringIO()
            fields = [
                "id", "domain", "risk_score", "threat_level", "source",
                "timestamp", "similarity_target", "ics_targeted", "ics_category",
                "ics_sector", "ip_address",
            ]
            w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            for d in self.detections:
                row = {
                    "id": d.get("id"),
                    "domain": d.get("domain"),
                    "risk_score": d.get("risk_score"),
                    "threat_level": d.get("threat_level"),
                    "source": d.get("source"),
                    "timestamp": d.get("timestamp"),
                    "similarity_target": d.get("similarity", {}).get("target", ""),
                    "ics_targeted": d.get("ics_targeted", False),
                    "ics_category": d.get("ics_category", ""),
                    "ics_sector": d.get("ics_sector", ""),
                    "ip_address": d.get("ip_address", ""),
                }
                w.writerow(row)
            return Response(
                buf.getvalue(),
                mimetype="text/csv",
                headers={"Content-Disposition": "attachment; filename=phishwatch_export.csv"},
            )

    # ── Socket events ─────────────────────────────────────────────────────

    def _register_socket_events(self):
        @self.socketio.on("connect")
        def on_connect():
            emit("stats_update", self._calc_stats())

        @self.socketio.on("request_detections")
        def on_request(data):
            filters = data.get("filters", {})
            result = self._filter(
                filters.get("risk", "all"),
                filters.get("source", "all"),
                filters.get("ics_only", False),
            )
            emit("detections_update", {"detections": result[:100]})

    # ── Monitoring ────────────────────────────────────────────────────────

    def _start_monitoring(self):
        self.monitoring = True
        self.stats["monitoring"] = True

        # CertStream
        self.certstream.start(self._on_domain_found)

        # OpenSquat
        self._opensquat_thread = threading.Thread(target=self._opensquat_loop, daemon=True)
        self._opensquat_thread.start()

        self.socketio.emit("stats_update", self._calc_stats())
        logger.info("Monitoring started")

    def _stop_monitoring(self):
        self.monitoring = False
        self.stats["monitoring"] = False
        self.certstream.stop()
        self.socketio.emit("stats_update", self._calc_stats())
        logger.info("Monitoring stopped")

    def _opensquat_loop(self):
        while self.monitoring:
            try:
                results = self.opensquat.scan()
                for r in results:
                    if self.monitoring:
                        self._on_domain_found(r["domain"], {"source": "OpenSquat"})
            except Exception as exc:
                logger.error("OpenSquat loop error: %s", exc)
            # Sleep in small increments so we can stop quickly
            for _ in range(self.cfg.OPENSQUAT_SCAN_INTERVAL):
                if not self.monitoring:
                    break
                time.sleep(1)

    def _on_domain_found(self, domain: str, metadata: Dict) -> None:
        """Callback when a suspicious domain is detected."""
        try:
            analysis = self.analyzer.analyze(domain)
            ics_det = self.ics_detector.analyze(domain)
            score = self.classifier.calculate_risk(domain, analysis, ics_det)

            if score < self.cfg.MEDIUM_THRESHOLD:
                return  # Skip low-risk

            level = self.classifier.classify(score)
            detection = {
                "id": len(self.detections) + 1,
                "domain": domain,
                "risk_score": score,
                "threat_level": level,
                "color": self.classifier.color(score),
                "source": metadata.get("source_name", metadata.get("source", "CertStream")),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "similarity": analysis.get("similarity", {}),
                "risk_factors": analysis.get("risk_factors", []),
                "entropy": analysis.get("entropy", 0.0),
                "homograph": analysis.get("homograph", {}),
                "ip_address": analysis.get("technical", {}).get("ip_address", ""),
                # ICS/OT context
                "ics_targeted": ics_det.is_ics_targeted,
                "ics_category": ics_det.category.value if ics_det.category else None,
                "ics_sector": ics_det.sector if ics_det.is_ics_targeted else None,
                "ics_vendors": ics_det.matched_vendors,
                "ics_protocols": ics_det.matched_protocols,
                "ics_terms": ics_det.matched_terms,
                "ics_mitre": ics_det.mitre_techniques,
                "ics_confidence": ics_det.confidence,
            }

            with self._lock:
                self.detections.insert(0, detection)
                if len(self.detections) > self.cfg.MAX_DETECTIONS:
                    self.detections = self.detections[: self.cfg.MAX_DETECTIONS]

            # Broadcast
            self.socketio.emit("new_detection", detection)
            self.socketio.emit("stats_update", self._calc_stats())

            logger.info("Detection: %s [%s] score=%d ics=%s",
                        domain, level, score, ics_det.is_ics_targeted)

        except Exception as exc:
            logger.error("Processing error for %s: %s", domain, exc)

    # ── Helpers ───────────────────────────────────────────────────────────

    def _filter(self, risk: str, source: str, ics_only: bool = False) -> List[Dict]:
        result = self.detections
        if risk != "all":
            thresholds = {
                "critical": (90, 101),
                "high": (70, 90),
                "medium": (50, 70),
                "low": (0, 50),
            }
            lo, hi = thresholds.get(risk, (0, 101))
            result = [d for d in result if lo <= d["risk_score"] < hi]
        if source != "all":
            result = [d for d in result if d["source"].lower() == source.lower()]
        if ics_only:
            result = [d for d in result if d.get("ics_targeted")]
        return result

    def _calc_stats(self) -> Dict:
        n = len(self.detections)
        crit = sum(1 for d in self.detections if d["risk_score"] >= 90)
        high = sum(1 for d in self.detections if 70 <= d["risk_score"] < 90)
        ics = sum(1 for d in self.detections if d.get("ics_targeted"))
        avg = sum(d["risk_score"] for d in self.detections) / n if n else 0.0
        return {
            "total": n,
            "critical": crit,
            "high": high,
            "ics_targeted": ics,
            "avg_risk": round(avg, 1),
            "monitoring": self.monitoring,
        }

    def run(self, host: str = "0.0.0.0", port: int = 5000, debug: bool = False):
        logger.info("PhishWatch v%s starting on %s:%d", __version__, host, port)
        self.socketio.run(self.app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)


# ── Module-level instances for Gunicorn ───────────────────────────────────

_pw = PhishWatch()
app = _pw.app
socketio = _pw.socketio


if __name__ == "__main__":
    # The Werkzeug debugger allows remote code execution; enable it only when explicitly requested.
    _pw.run(debug=os.environ.get("PHISHWATCH_DEBUG", "").lower() in ("1", "true", "yes"))
