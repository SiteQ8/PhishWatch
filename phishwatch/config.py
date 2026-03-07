"""
PhishWatch Configuration
Central configuration management for all components.
"""

import os
from typing import List, Dict


class Config:
    """Base configuration"""

    # Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "phishwatch-dev-key-change-in-production")
    SOCKETIO_ASYNC_MODE = "threading"

    # App metadata
    APP_NAME = "PhishWatch"
    APP_VERSION = "2.0.0"
    APP_DESCRIPTION = "Real-time Phishing Detection Platform"

    # CertStream
    CERTSTREAM_URL = os.environ.get("CERTSTREAM_URL", "wss://certstream.calidog.io/")

    # OpenSquat
    OPENSQUAT_SCAN_INTERVAL = int(os.environ.get("OPENSQUAT_SCAN_INTERVAL", 1800))

    # Storage
    MAX_DETECTIONS = int(os.environ.get("MAX_DETECTIONS", 5000))
    DATABASE_URI = os.environ.get("DATABASE_URI", "sqlite:///phishwatch.db")

    # Thresholds
    CRITICAL_THRESHOLD = int(os.environ.get("CRITICAL_THRESHOLD", 90))
    HIGH_THRESHOLD = int(os.environ.get("HIGH_THRESHOLD", 70))
    MEDIUM_THRESHOLD = int(os.environ.get("MEDIUM_THRESHOLD", 50))

    # Logging
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    # Export
    EXPORT_FORMATS = ["csv", "json", "pdf", "stix"]
    MAX_EXPORT_RECORDS = 50000

    # Default Brand Watchlist
    DEFAULT_WATCHLIST: List[str] = [
        # Major tech / cloud
        "paypal", "microsoft", "google", "amazon", "apple",
        "facebook", "meta", "netflix", "dropbox", "adobe",
        "zoom", "linkedin", "twitter", "instagram", "whatsapp",
        "github", "slack", "salesforce", "okta", "atlassian",
        "cloudflare", "aws", "azure",
        # Financial
        "chase", "wellsfargo", "bankofamerica", "citibank",
        "amex", "visa", "mastercard", "coinbase", "binance",
        "stripe", "square", "venmo",
        # Productivity
        "office365", "outlook", "onedrive", "sharepoint",
        "gmail", "drive", "icloud",
        # Social / messaging
        "telegram", "signal", "discord", "tiktok", "snapchat",
        "reddit", "spotify", "twitch", "youtube",
        # E-commerce
        "ebay", "walmart", "target", "shopify", "alibaba",
        # Crypto / fintech
        "metamask", "ledger", "phantom", "opensea",
        # Shipping / logistics
        "fedex", "ups", "usps", "dhl",
    ]

    # Threat Intelligence
    SUSPICIOUS_TLDS: List[str] = [
        ".tk", ".ml", ".cf", ".ga", ".buzz", ".click", ".download",
        ".loan", ".cricket", ".science", ".work", ".party",
        ".top", ".xyz", ".icu", ".cam", ".rest",
    ]

    HIGH_RISK_COUNTRIES: List[str] = ["RU", "CN", "KP", "IR"]

    SUSPICIOUS_KEYWORDS: List[str] = [
        "login", "signin", "sign-in", "verify", "account", "update",
        "suspend", "confirm", "support", "billing", "payment",
        "secure", "auth", "credential", "password", "reset",
        "urgent", "alert", "notification", "activate", "unlock",
        "recover", "restore", "validate", "expire", "renew",
        "invoice", "receipt", "refund", "shipping", "delivery",
        "track", "claim", "reward", "prize", "winner",
    ]

    # ICS / IoT / OT Module (Advanced Feature)
    ICS_VENDORS: List[str] = [
        "siemens", "schneider", "schneider-electric", "rockwell",
        "allen-bradley", "honeywell", "abb", "emerson", "yokogawa",
        "ge-digital", "ge-fanuc", "mitsubishi-electric", "omron",
        "beckhoff", "phoenix-contact", "wago", "moxa", "advantech",
        "deltav", "triconex", "foxboro", "wonderware", "factorytalk",
        "wincc", "step7", "tia-portal", "codesys", "prosafe",
        "centum", "ovation", "experion", "tristation",
    ]

    ICS_PROTOCOLS: List[str] = [
        "modbus", "dnp3", "opcua", "opc-ua", "bacnet", "profinet",
        "ethercat", "ethernet-ip", "hart", "foundation-fieldbus",
        "iec61850", "iec104", "goose", "s7comm", "fins", "melsec",
        "cip", "pccc", "enip",
    ]

    ICS_TERMS: List[str] = [
        "scada", "hmi", "plc", "rtu", "dcs", "ics", "ot-network",
        "industrial", "control-system", "historian", "iiot",
        "smart-grid", "substation", "turbine", "pipeline",
    ]

    IOT_TERMS: List[str] = [
        "iot", "smart-home", "smart-device", "mqtt", "coap",
        "zigbee", "z-wave", "lorawan", "nbiot", "sigfox",
        "firmware-update", "device-management",
    ]

    MITRE_ICS_TECHNIQUES: Dict[str, str] = {
        "T0817": "Drive-by Compromise",
        "T0819": "Exploit Public-Facing Application",
        "T0862": "Supply Chain Compromise",
        "T0865": "Spearphishing Attachment",
        "T0869": "Standard Application Layer Protocol",
    }


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    SECRET_KEY = os.environ.get("SECRET_KEY", "CHANGE-THIS-IN-PRODUCTION")


class TestingConfig(Config):
    DEBUG = True
    TESTING = True


config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}
