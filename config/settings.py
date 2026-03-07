"""
Configuration Settings for PhishGuard
"""

import os

class Config:
    """Base configuration"""

    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'phishguard-development-key-change-in-production'

    # SocketIO settings
    SOCKETIO_ASYNC_MODE = 'threading'

    # Application settings
    APP_NAME = 'PhishGuard'
    APP_VERSION = '2.1.0'

    # Monitoring settings
    CERTSTREAM_URL = 'wss://certstream.calidog.io/'
    OPENSQUAT_SCAN_INTERVAL = 1800  # 30 minutes
    MAX_DETECTIONS_STORED = 1000

    # Risk scoring thresholds
    CRITICAL_RISK_THRESHOLD = 90
    HIGH_RISK_THRESHOLD = 70
    MEDIUM_RISK_THRESHOLD = 50

    # Keywords for monitoring (can be overridden)
    DEFAULT_KEYWORDS = [
        'paypal', 'microsoft', 'google', 'amazon', 'apple',
        'facebook', 'netflix', 'dropbox', 'adobe', 'zoom',
        'linkedin', 'twitter', 'instagram', 'whatsapp',
        'spotify', 'github', 'stackoverflow', 'reddit'
    ]

    # Logging settings
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')

    # Export settings
    EXPORT_FORMATS = ['csv', 'json', 'txt']
    MAX_EXPORT_RECORDS = 10000

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'change-this-in-production'

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    WTF_CSRF_ENABLED = False

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
