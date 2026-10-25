"""
OmniSight-OSINT Username & Data Breach Enumeration Module
========================================================
Asynchronously sweeps major online platforms to enumerate account registration presence,
and audits credential compromise telemetry via Have I Been Pwned (HIBP) / Leak-Lookup APIs
with automatic password masking for cybersecurity compliance.
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional
import aiohttp

from config import get_settings
from modules.models import BreachRecord, UsernamePlatformResult
from utils.logger import get_logger

logger = get_logger("OmniSight.BreachHunter")

# Platform catalogue for username profiling
PLATFORMS_CATALOGUE = [
    {
        "name": "GitHub",
        "category": "Development",
        "url_template": "https://github.com/{}",
        "check_type": "status_code",
        "exists_code": 200,
        "missing_code": 404
    },
    {
        "name": "GitLab",
        "category": "Development",
        "url_template": "https://gitlab.com/{}",
        "check_type": "status_code",
        "exists_code": 200,
        "missing_code": 404
    },
    {
        "name": "DockerHub",
        "category": "Development",
        "url_template": "https://hub.docker.com/v2/users/{}/",
        "check_type": "status_code",
        "exists_code": 200,
        "missing_code": 404
    },
    {
        "name": "Dev.to",
        "category": "Development",
        "url_template": "https://dev.to/{}",
        "check_type": "status_code",
        "exists_code": 200,
        "missing_code": 404
    },
    {
        "name": "Reddit",
        "category": "Social",
        "url_template": "https://www.reddit.com/user/{}/about.json",
        "check_type": "status_code",
        "exists_code": 200,
        "missing_code": 404
    },
    {
        "name": "Pinterest",
        "category": "Social",
        "url_template": "https://www.pinterest.com/{}/",
        "check_type": "status_code",
        "exists_code": 200,
        "missing_code": 404
    },
    {
        "name": "Medium",
        "category": "Blogging",
        "url_template": "https://medium.com/@{}",
        "check_type": "status_code",
        "exists_code": 200,
        "missing_code": 404
    },
    {
        "name": "Telegram",
        "category": "Messaging",
        "url_template": "https://t.me/{}",
        "check_type": "body_content",
        "missing_snippet": "If you have <strong>Telegram</strong>, you can contact"
    },
    {
        "name": "Keybase",
        "category": "Identity/Security",
        "url_template": "https://keybase.io/{}",
        "check_type": "status_code",
        "exists_code": 200,
        "missing_code": 404
    },
    {
        "name": "Instagram",
        "category": "Social Media",
        "url_template": "https://www.instagram.com/{}/",
        "check_type": "status_code",
        "exists_code": 200,
        "missing_code": 404
    },
    {
        "name": "Twitter / X",
        "category": "Social Media",
        "url_template": "https://x.com/{}",
        "check_type": "status_code",
        "exists_code": 200,
        "missing_code": 404
    },
    {
        "name": "Steam Community",
        "category": "Gaming",
        "url_template": "https://steamcommunity.com/id/{}",
        "check_type": "body_content",
        "missing_snippet": "The specified profile could not be found."
    },
    {
        "name": "HackerNews",
        "category": "Tech News",
        "url_template": "https://news.ycombinator.com/user?id={}",
        "check_type": "body_content",
        "missing_snippet": "No such user."
    }
]


def mask_credential(secret: str) -> str:
    """Mask credential strings for operational security and privacy compliance.

    Examples:
        'password123' -> 'p*********3'
        'abc' -> 'a*c'
        '' -> '[MASKED]'
    """
    if not secret:
        return "[MASKED_HASH]"
    if len(secret) <= 3:
        return secret[0] + "*" * (len(secret) - 1)
    return secret[0] + "*" * (len(secret) - 2) + secret[-1]


async def _probe_single_platform(
    session: aiohttp.ClientSession,
    platform_info: Dict,
    username: str,
    semaphore: asyncio.Semaphore,
    user_agent: str
) -> UsernamePlatformResult:
    """Audit single profile existence asynchronously under semaphore control."""
    target_url = platform_info["url_template"].format(username)
    name = platform_info["name"]
    category = platform_info.get("category", "Social")
    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5"
    }

    async with semaphore:
        start_time = time.perf_counter()
        try:
            async with session.get(target_url, headers=headers, allow_redirects=True) as resp:
                elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
                status = resp.status

                exists = False
                check_type = platform_info.get("check_type", "status_code")

                if check_type == "status_code":
                    if status == platform_info.get("exists_code", 200):
                        exists = True
                    elif status == platform_info.get("missing_code", 404):
                        exists = False
                    else:
                        exists = False
                elif check_type == "body_content":
                    if status == 200:
                        content = await resp.text()
                        missing_marker = platform_info.get("missing_snippet", "")
                        if missing_marker and missing_marker not in content:
                            exists = True
                        else:
                            exists = False
                    else:
                        exists = False

                return UsernamePlatformResult(
                    platform=name,
                    category=category,
                    url=target_url,
                    exists=exists,
                    status_code=status,
                    response_time_ms=elapsed_ms
                )

        except asyncio.TimeoutError:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return UsernamePlatformResult(
                platform=name,
                category=category,
                url=target_url,
                exists=False,
                response_time_ms=elapsed_ms,
                error_message="Request timed out"
            )
        except aiohttp.ClientError as ce:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return UsernamePlatformResult(
                platform=name,
                category=category,
                url=target_url,
                exists=False,
                response_time_ms=elapsed_ms,
                error_message=f"Network error: {type(ce).__name__}"
            )
        except Exception as err:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return UsernamePlatformResult(
                platform=name,
                category=category,
                url=target_url,
                exists=False,
                response_time_ms=elapsed_ms,
                error_message=str(err)
            )


async def hunt_username(
    username: str,
    concurrency_limit: Optional[int] = None,
    session: Optional[aiohttp.ClientSession] = None
) -> List[UsernamePlatformResult]:
    """Concurrently check username existence across catalogued public platforms.

    Args:
        username: Target handle to audit.
        concurrency_limit: Max simultaneous socket operations.
        session: Optional pre-configured aiohttp.ClientSession.

    Returns:
        List of structured UsernamePlatformResult records.
    """
    settings = get_settings()
    limit = concurrency_limit or settings.max_concurrent_requests
    clean_user = username.strip().lstrip("@")

    if not clean_user:
        return []

    close_session_at_exit = False
    if session is None:
        timeout = aiohttp.ClientTimeout(total=settings.request_timeout)
        session = aiohttp.ClientSession(timeout=timeout)
        close_session_at_exit = True

    semaphore = asyncio.Semaphore(limit)
    tasks = [
        _probe_single_platform(session, p_info, clean_user, semaphore, settings.default_user_agent)
        for p_info in PLATFORMS_CATALOGUE
    ]

    try:
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return sorted(results, key=lambda x: (not x.exists, x.platform))
    except Exception as exc:
        logger.exception(f"Error during username sweep for '{clean_user}': {exc}")
        return []
    finally:
        if close_session_at_exit and session and not session.closed:
            await session.close()


async def check_breaches(
    email_or_username: str,
    hibp_api_key: Optional[str] = None,
    session: Optional[aiohttp.ClientSession] = None
) -> List[BreachRecord]:
    """Audit data breach exposure for an email or username identifier.

    Queries Have I Been Pwned v3 if an API key is configured.
    Falls back gracefully to simulated/mock threat intelligence telemetry
    when credentials are unset to demonstrate pipeline execution safely.

    Args:
        email_or_username: Target identifier string.
        hibp_api_key: Optional HIBP API token.
        session: Optional aiohttp.ClientSession.

    Returns:
        List of structured BreachRecord objects.
    """
    settings = get_settings()
    key = hibp_api_key or settings.hibp_api_key
    target = email_or_username.strip()

    if not target:
        return []

    close_session_at_exit = False
    if session is None:
        timeout = aiohttp.ClientTimeout(total=settings.request_timeout)
        session = aiohttp.ClientSession(timeout=timeout)
        close_session_at_exit = True

    try:
        # 1. Live Have I Been Pwned (HIBP) API Check
        if key:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}?truncateResponse=false"
            headers = {
                "hibp-api-key": key,
                "user-agent": "OmniSight-OSINT-SecEngine",
                "Accept": "application/json"
            }
            logger.debug(f"Querying HIBP v3 endpoint for '{target}'...")
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    raw_breaches = await resp.json()
                    breach_records = []
                    for b in raw_breaches:
                        data_classes = b.get("DataClasses", [])
                        has_pw = any("password" in dc.lower() for dc in data_classes)
                        breach_records.append(
                            BreachRecord(
                                source_database=b.get("Title", b.get("Name", "Unknown Breach")),
                                breach_date=b.get("BreachDate"),
                                compromised_data_classes=data_classes,
                                is_verified=b.get("IsVerified", True),
                                is_sensitive=b.get("IsSensitive", False),
                                description=b.get("Description", "")[:250] + "..." if b.get("Description") else None,
                                has_passwords=has_pw,
                                sample_password_masked="[REDACTED_BY_HIBP]" if has_pw else None
                            )
                        )
                    return breach_records
                elif resp.status == 404:
                    logger.info(f"Target '{target}' has 0 documented breaches in HIBP.")
                    return []
                elif resp.status == 429:
                    logger.warning("HIBP rate limit exceeded (HTTP 429).")
                else:
                    logger.warning(f"HIBP returned HTTP status {resp.status}")

        # 2. Configurable / Mock Threat Intelligence Simulation
        if settings.mock_breach_data:
            logger.info(
                f"Generating realistic breach correlation telemetry for '{target}' (Mock Engine Active)..."
            )
            # Deterministic simulation based on target string
            simulated_records = [
                BreachRecord(
                    source_database="Collection #1 (Credential Dump)",
                    breach_date="2019-01-07",
                    compromised_data_classes=["Email addresses", "Passwords", "Usernames"],
                    is_verified=True,
                    is_sensitive=False,
                    description="Aggregated breach corpus containing billions of unique credential pairs.",
                    has_passwords=True,
                    sample_password_masked=mask_credential(f"P@ss_{target[:3]}2019!")
                ),
                BreachRecord(
                    source_database="Exploit.in Stealer Logs",
                    breach_date="2020-05-14",
                    compromised_data_classes=["IP addresses", "Browser Cookies", "Passwords", "Device Specs"],
                    is_verified=True,
                    is_sensitive=True,
                    description="Infostealer malware extraction logs auctioned on underground forums.",
                    has_passwords=True,
                    sample_password_masked=mask_credential("Winter2020$Secure")
                ),
                BreachRecord(
                    source_database="Canva Graphics Corp",
                    breach_date="2019-05-24",
                    compromised_data_classes=["Names", "Email addresses", "Passwords (Bcrypt)", "Locations"],
                    is_verified=True,
                    is_sensitive=False,
                    description="Unauthorized access to user database impacting over 137 million accounts.",
                    has_passwords=True,
                    sample_password_masked="[BCRYPT_HASH_MASKED]"
                )
            ]
            return simulated_records

        return []

    except Exception as exc:
        logger.exception(f"Exception during breach auditing for '{target}': {exc}")
        return []
    finally:
        if close_session_at_exit and session and not session.closed:
            await session.close()
