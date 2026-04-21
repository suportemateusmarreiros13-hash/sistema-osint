"""
OSINT Platform - Configuration Management
Centralizes all environment variables and application settings.
"""

from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "OSINT URL Investigation Platform"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # API
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8001

    # Security
    RATE_LIMIT_PER_MINUTE: int = 10
    MAX_URL_LENGTH: int = 2048
    ALLOWED_SCHEMES: List[str] = ["http", "https"]

    # Private IP ranges blocked for SSRF protection
    BLOCKED_IP_PREFIXES: List[str] = [
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
        "172.30.", "172.31.", "192.168.", "127.", "0.", "169.254.",
        "::1", "fc00::", "fe80::"
    ]

    # Database
    DATABASE_URL: str = "sqlite:///./osint_platform.db"

    # DNS resolver (use public resolvers)
    DNS_RESOLVERS: List[str] = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    DNS_TIMEOUT: float = 3.0

    # HTTP probe settings
    HTTP_TIMEOUT: int = 10
    HTTP_USER_AGENT: str = "OSINT-Platform/1.0 (Security Research)"

    # Risk scoring thresholds
    RISK_LOW_MAX: int = 30
    RISK_MEDIUM_MAX: int = 60
    RISK_HIGH_MAX: int = 85
    # Above 85 = CRITICAL

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "osint_platform.log"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
