"""
OmniSight-OSINT Configuration Module
====================================
Production-grade configuration management powered by Pydantic Settings.
Loads secrets, API keys, and operational parameters from system environment variables
or a .env file with strict validation and graceful fallbacks.
"""

from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings schema for OmniSight-OSINT.
    
    Attributes:
        IPINFO_API_KEY: Optional authentication token for IPinfo.io API.
        NUMVERIFY_API_KEY: Optional API access key for Numverify phone carrier validation.
        HIBP_API_KEY: Optional API key for Have I Been Pwned v3.
        DEHASHED_API_KEY: Optional API key for DeHashed breach intelligence.
        DEHASHED_EMAIL: Optional registered email for DeHashed credentials.
        LEAKLOOKUP_API_KEY: Optional API key for Leak-Lookup API.
        REQUEST_TIMEOUT: Max timeout (seconds) for external HTTP lookups.
        MAX_CONCURRENT_REQUESTS: Semaphore concurrency limit for asynchronous scrapers.
        DEFAULT_USER_AGENT: Custom User-Agent string simulating standard desktop browsers.
        MOCK_BREACH_DATA: Fallback simulation flag when live breach API credentials are unset.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False
    )

    # API Keys
    ipinfo_api_key: Optional[str] = Field(default=None, alias="IPINFO_API_KEY")
    numverify_api_key: Optional[str] = Field(default=None, alias="NUMVERIFY_API_KEY")
    truecaller_api_key: Optional[str] = Field(default=None, alias="TRUECALLER_API_KEY")
    cnam_api_key: Optional[str] = Field(default=None, alias="CNAM_API_KEY")
    hibp_api_key: Optional[str] = Field(default=None, alias="HIBP_API_KEY")
    dehashed_api_key: Optional[str] = Field(default=None, alias="DEHASHED_API_KEY")
    dehashed_email: Optional[str] = Field(default=None, alias="DEHASHED_EMAIL")
    leaklookup_api_key: Optional[str] = Field(default=None, alias="LEAKLOOKUP_API_KEY")

    # Operational Parameters
    request_timeout: int = Field(default=10, alias="REQUEST_TIMEOUT", ge=2, le=60)
    max_concurrent_requests: int = Field(default=15, alias="MAX_CONCURRENT_REQUESTS", ge=1, le=50)
    default_user_agent: str = Field(
        default=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36 OmniSight-OSINT/1.0"
        ),
        alias="DEFAULT_USER_AGENT"
    )
    mock_breach_data: bool = Field(default=False, alias="MOCK_BREACH_DATA")


# Singleton instance caching
_settings_instance: Optional[Settings] = None


def get_settings() -> Settings:
    """Return a cached singleton instance of the application Settings."""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = Settings()
    return _settings_instance
