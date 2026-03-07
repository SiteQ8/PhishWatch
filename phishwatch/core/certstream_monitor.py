"""
CertStream Monitor
Real-time SSL/TLS certificate transparency log monitoring.
"""

import logging
import threading
from datetime import datetime
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class CertStreamMonitor:
    """Monitor CertStream for suspicious certificate issuances."""

    def __init__(self, url: str = "wss://certstream.calidog.io/", keywords: Optional[List[str]] = None):
        self.url = url
        self.keywords = [k.lower() for k in (keywords or [])]
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callback: Optional[Callable] = None

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self, callback: Callable[[str, Dict], None]) -> None:
        """Start monitoring. callback(domain, metadata) is called for suspicious hits."""
        if self._running:
            return
        self._callback = callback
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="certstream")
        self._thread.start()
        logger.info("CertStream monitor started")

    def stop(self) -> None:
        self._running = False
        logger.info("CertStream monitor stopped")

    def update_keywords(self, keywords: List[str]) -> None:
        self.keywords = [k.lower() for k in keywords]

    def _run(self) -> None:
        try:
            import certstream  # type: ignore

            def handler(message, context):
                if not self._running:
                    raise StopIteration()
                if message.get("message_type") == "heartbeat":
                    return
                if message.get("message_type") == "certificate_update":
                    self._process(message)

            certstream.listen_for_events(handler, url=self.url)
        except StopIteration:
            pass
        except Exception as exc:
            logger.error("CertStream error: %s", exc)
        finally:
            self._running = False

    def _process(self, message: Dict) -> None:
        try:
            leaf = message["data"]["leaf_cert"]
            domains = leaf.get("all_domains", [])
            meta = {
                "source_name": message["data"]["source"]["name"],
                "issuer": leaf.get("issuer", {}).get("O", ""),
                "seen": datetime.utcfromtimestamp(message["data"]["seen"]).isoformat() + "Z",
            }

            for domain in domains:
                if self._is_interesting(domain):
                    if self._callback:
                        self._callback(domain, meta)
        except (KeyError, TypeError) as exc:
            logger.debug("Skipping malformed cert message: %s", exc)

    def _is_interesting(self, domain: str) -> bool:
        dl = domain.lower().strip("*.")
        for kw in self.keywords:
            if kw in dl and kw != dl:
                return True
        return False
