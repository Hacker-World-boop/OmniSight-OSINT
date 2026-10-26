"""
OmniSight-OSINT Global Email Digital Footprint & Domain Intelligence Module
==========================================================================
Analyzes international email addresses to uncover digital footprints across
global apps, platforms, webmail ecosystems, MX mail routing, Gravatar public
identities, disposable email detection, and targeted OSINT intelligence dorks.

Author: inaam kaleem
"""

import asyncio
import hashlib
import logging
import re
import socket
import urllib.parse
from typing import Dict, List, Optional, Tuple
import aiohttp

from config import get_settings
from modules.models import AppFootprint, EmailFootprintIntelligence, GravatarProfile
from utils.logger import get_logger

logger = get_logger("OmniSight.EmailTracker")

# ─── Major Global Webmail & Cloud Email Providers ──────────────────────────────
MAJOR_PROVIDERS = {
    "gmail.com": {
        "name": "Google Workspace / Gmail",
        "category": "Major Public Webmail",
        "ecosystem": "Google (Android, YouTube, Play Store, Drive, Maps)",
        "mx": ["aspmx.l.google.com", "alt1.aspmx.l.google.com"],
        "region": "Global (Mountain View, CA, USA)"
    },
    "googlemail.com": {
        "name": "Google Workspace / Gmail (Legacy UK/DE)",
        "category": "Major Public Webmail",
        "ecosystem": "Google (Android, YouTube, Play Store, Drive, Maps)",
        "mx": ["aspmx.l.google.com"],
        "region": "Global (Mountain View, CA, USA)"
    },
    "outlook.com": {
        "name": "Microsoft 365 / Outlook.com",
        "category": "Major Public Webmail",
        "ecosystem": "Microsoft (Windows, Xbox Live, Office 365, OneDrive, Skype)",
        "mx": ["outlook-com.olc.protection.outlook.com"],
        "region": "Global (Redmond, WA, USA)"
    },
    "hotmail.com": {
        "name": "Microsoft Hotmail (Legacy Windows Live)",
        "category": "Major Public Webmail",
        "ecosystem": "Microsoft (Windows, Xbox Live, Office 365, OneDrive)",
        "mx": ["hotmail-com.olc.protection.outlook.com"],
        "region": "Global (Redmond, WA, USA)"
    },
    "live.com": {
        "name": "Microsoft Windows Live",
        "category": "Major Public Webmail",
        "ecosystem": "Microsoft (Windows, Xbox Live, Office 365)",
        "mx": ["live-com.olc.protection.outlook.com"],
        "region": "Global (Redmond, WA, USA)"
    },
    "msn.com": {
        "name": "Microsoft MSN Mail",
        "category": "Major Public Webmail",
        "ecosystem": "Microsoft (Windows, Office 365)",
        "mx": ["msn-com.olc.protection.outlook.com"],
        "region": "Global (Redmond, WA, USA)"
    },
    "yahoo.com": {
        "name": "Yahoo! Mail",
        "category": "Major Public Webmail",
        "ecosystem": "Yahoo / Verizon Media (Flickr, Yahoo Finance)",
        "mx": ["mta5.am0.yahoodns.net", "mta6.am0.yahoodns.net"],
        "region": "Global (Sunnyvale, CA, USA)"
    },
    "ymail.com": {
        "name": "Yahoo! Ymail",
        "category": "Major Public Webmail",
        "ecosystem": "Yahoo / Verizon Media",
        "mx": ["mta5.am0.yahoodns.net"],
        "region": "Global (Sunnyvale, CA, USA)"
    },
    "icloud.com": {
        "name": "Apple iCloud Mail",
        "category": "Major Public Webmail",
        "ecosystem": "Apple (Apple ID, iOS, macOS, App Store, iCloud Drive)",
        "mx": ["mx1.mail.icloud.com", "mx2.mail.icloud.com"],
        "region": "Global (Cupertino, CA, USA)"
    },
    "me.com": {
        "name": "Apple MobileMe (Legacy iCloud)",
        "category": "Major Public Webmail",
        "ecosystem": "Apple (Apple ID, iOS, macOS)",
        "mx": ["mx1.mail.icloud.com"],
        "region": "Global (Cupertino, CA, USA)"
    },
    "proton.me": {
        "name": "Proton AG (Encrypted Mail)",
        "category": "Privacy-Centric Webmail",
        "ecosystem": "Proton (ProtonMail, ProtonVPN, Proton Drive)",
        "mx": ["mail.protonmail.ch", "mailsec.protonmail.ch"],
        "region": "Geneva, Switzerland (Zero-Access Encryption)"
    },
    "protonmail.com": {
        "name": "ProtonMail (Encrypted Mail)",
        "category": "Privacy-Centric Webmail",
        "ecosystem": "Proton (ProtonMail, ProtonVPN, Proton Pass)",
        "mx": ["mail.protonmail.ch"],
        "region": "Geneva, Switzerland (Zero-Access Encryption)"
    },
    "zoho.com": {
        "name": "Zoho Mail",
        "category": "Business & Public Webmail",
        "ecosystem": "Zoho Enterprise Cloud & Productivity",
        "mx": ["mx.zoho.com", "mx2.zoho.com"],
        "region": "Global (Chennai, India / Pleasanton, CA, USA)"
    },
    "aol.com": {
        "name": "AOL Mail",
        "category": "Major Public Webmail",
        "ecosystem": "AOL / Apollo Global Management",
        "mx": ["mx-aol.mail.gm0.yahoodns.net"],
        "region": "Global (New York, USA)"
    },
    "gmx.com": {
        "name": "GMX Mail Global",
        "category": "Public Webmail",
        "ecosystem": "1&1 Mail & Media (United Internet)",
        "mx": ["mx00.gmx.com", "mx01.gmx.com"],
        "region": "Karlsruhe, Germany"
    },
    "gmx.de": {
        "name": "GMX Mail Germany",
        "category": "Regional Webmail",
        "ecosystem": "1&1 Mail & Media (United Internet)",
        "mx": ["mx00.emig.gmx.net"],
        "region": "Germany / European Union"
    },
    "mail.ru": {
        "name": "Mail.ru (VK Group)",
        "category": "Regional Major Webmail",
        "ecosystem": "VK Ecosystem (VKontakte, Odnoklassniki)",
        "mx": ["mxs.mail.ru"],
        "region": "Moscow, Russia"
    },
    "yandex.com": {
        "name": "Yandex 360 Mail",
        "category": "Major Webmail",
        "ecosystem": "Yandex Services (Disk, Browser, Maps)",
        "mx": ["mx.yandex.net"],
        "region": "Global / Eastern Europe"
    },
    "fastmail.com": {
        "name": "Fastmail Pty Ltd",
        "category": "Independent Webmail",
        "ecosystem": "Fastmail / Topicbox",
        "mx": ["in1-smtp.messagingengine.com"],
        "region": "Melbourne, Australia / Philadelphia, USA"
    },
    "tuta.com": {
        "name": "Tuta Mail (Formerly Tutanota)",
        "category": "Privacy-Centric Webmail",
        "ecosystem": "Tuta Encrypted Cloud",
        "mx": ["mail.tutanota.de"],
        "region": "Hanover, Germany"
    }
}

# ─── Disposable / Burner Email Domains Catalogue ───────────────────────────────
DISPOSABLE_DOMAINS = {
    "10minutemail.com", "tempmail.com", "temp-mail.org", "guerrillamail.com",
    "mailinator.com", "sharklasers.com", "throwawaymail.com", "yopmail.com",
    "trashmail.com", "getairmail.com", "dispostable.com", "fakeinbox.com",
    "mohmal.com", "generator.email", "emailondeck.com", "mytemp.email",
    "tempail.com", "burnermail.io", "maildrop.cc", "crazymailing.com",
    "guerrillamail.net", "guerrillamail.org", "guerrillamail.biz", "spam4.me",
    "grr.la", "inboxkitten.com", "nada.ltd", "dropmail.me"
}


def parse_and_validate_email(email_str: str) -> Tuple[bool, str, str]:
    """Validate email syntax and extract username local-part and domain."""
    cleaned = email_str.strip().lower()
    email_regex = r"^[a-zA-Z0-9_.+-]+@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$"
    match = re.match(email_regex, cleaned)
    if match:
        user_part, domain_part = cleaned.split("@", 1)
        return True, user_part, domain_part
    return False, cleaned.split("@")[0] if "@" in cleaned else cleaned, ""


def classify_email_domain(domain: str) -> Tuple[str, str, bool, List[str]]:
    """Determine domain classification, infrastructure provider, and disposable status.

    Returns:
        Tuple of (domain_type, mail_provider, is_disposable, mx_hints)
    """
    clean_domain = domain.strip().lower()

    # 1. Check Known Disposable / Burner Providers
    if clean_domain in DISPOSABLE_DOMAINS:
        return (
            "Disposable / Burner Email (Temporary Ephemeral)",
            "Anonymous Disposable Mail Service",
            True,
            ["mx.disposable-gateway.internal"]
        )

    # 2. Check Major Global Webmail Providers
    if clean_domain in MAJOR_PROVIDERS:
        info = MAJOR_PROVIDERS[clean_domain]
        return (
            info["category"],
            f"{info['name']} ({info['region']})",
            False,
            info["mx"]
        )

    # 3. Check Academic / Educational TLDs
    if clean_domain.endswith(".edu") or ".ac." in clean_domain:
        return (
            "Academic / University Institution",
            f"Educational Mail Gateway ({clean_domain.upper()})",
            False,
            [f"mail.{clean_domain}", f"mx.{clean_domain}"]
        )

    # 4. Check Government / Military TLDs
    if clean_domain.endswith(".gov") or clean_domain.endswith(".mil") or ".gov." in clean_domain:
        return (
            "Government / Military Organization",
            f"Official Government Mail Infrastructure ({clean_domain.upper()})",
            False,
            [f"mailgate.{clean_domain}"]
        )

    # 5. Corporate or Custom Domain
    return (
        "Corporate / Custom Domain Network",
        f"Custom Domain Infrastructure ({clean_domain})",
        False,
        [f"mail.{clean_domain}", f"smtp.{clean_domain}"]
    )


async def check_gravatar_profile(
    email: str,
    session: Optional[aiohttp.ClientSession] = None
) -> GravatarProfile:
    """Audit Gravatar / Automattic public identity profile linked to email hash.

    Gravatar is used across WordPress, Slack, Stack Overflow, Atlassian, and millions
    of websites. The profile reveals avatars, full names, locations, and connected accounts.
    """
    clean_email = email.strip().lower()
    email_hash = hashlib.md5(clean_email.encode("utf-8")).hexdigest()
    profile_url = f"https://en.gravatar.com/{email_hash}.json"
    web_profile = f"https://en.gravatar.com/{email_hash}"

    settings = get_settings()
    close_session = False
    if session is None:
        timeout = aiohttp.ClientTimeout(total=settings.request_timeout)
        session = aiohttp.ClientSession(timeout=timeout)
        close_session = True

    headers = {
        "User-Agent": settings.default_user_agent,
        "Accept": "application/json"
    }

    try:
        async with session.get(profile_url, headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                entry = data.get("entry", [{}])[0]

                display_name = entry.get("displayName") or entry.get("name", {}).get("formatted")
                avatar = entry.get("thumbnailUrl") or f"https://www.gravatar.com/avatar/{email_hash}?s=200"
                location = entry.get("currentLocation")
                about_me = entry.get("aboutMe")

                accounts = []
                for acc in entry.get("accounts", []):
                    shortname = acc.get("shortname", "").capitalize()
                    url = acc.get("url", "")
                    if shortname and url:
                        accounts.append(f"{shortname}: {url}")

                for u in entry.get("urls", []):
                    title = u.get("title") or "Website"
                    val = u.get("value")
                    if val:
                        accounts.append(f"{title}: {val}")

                return GravatarProfile(
                    exists=True,
                    profile_hash=email_hash,
                    profile_url=web_profile,
                    display_name=display_name,
                    avatar_url=avatar,
                    location=location,
                    about_me=about_me,
                    connected_accounts=accounts
                )
            else:
                return GravatarProfile(
                    exists=False,
                    profile_hash=email_hash,
                    profile_url=None
                )
    except Exception as exc:
        logger.debug(f"Gravatar check exception for {clean_email}: {exc}")
        return GravatarProfile(
            exists=False,
            profile_hash=email_hash,
            profile_url=None
        )
    finally:
        if close_session and session and not session.closed:
            await session.close()


def generate_email_footprint_dorks(email: str, domain: str) -> Dict[str, str]:
    """Generate specialized OSINT search queries for digital footprint investigation."""
    clean_email = email.strip()
    clean_domain = domain.strip().lower()
    encoded_email = urllib.parse.quote(f'"{clean_email}"')

    return {
        "Google Exact Email Match": f"https://www.google.com/search?q={encoded_email}",
        "GitHub Public Commits & Code": f"https://github.com/search?q={encoded_email}&type=commits",
        "Epieos Google Account Recon": f"https://epieos.com/?q={clean_email}",
        "Intelligence X Deep Archive": f"https://intelx.io/?s={clean_email}",
        "Have I Been Pwned Web Audit": f"https://haveibeenpwned.com/account/{clean_email}",
        "Hunter.io Domain Intelligence": f"https://hunter.io/search/{clean_domain}",
        "DeHashed Credential Archive": f"https://www.dehashed.com/search?query={encoded_email}",
        "Google Leaked Docs & Pastes": f"https://www.google.com/search?q={encoded_email}+(site:pastebin.com+OR+site:ghostbin.com+OR+filetype:pdf+OR+filetype:xlsx)"
    }


def enumerate_app_footprints(
    email: str,
    username: str,
    domain: str,
    domain_type: str,
    provider: str,
    gravatar: GravatarProfile
) -> List[AppFootprint]:
    """Correlate and enumerate digital footprints across major global apps, ecosystems, and platforms."""
    clean_domain = domain.lower()
    footprints: List[AppFootprint] = []

    # 1. Google Ecosystem Footprint (Android, YouTube, Play Store, Drive, Maps)
    if "gmail.com" in clean_domain or "google" in provider.lower():
        footprints.append(AppFootprint(
            service="Google Services & Android Ecosystem",
            category="Mobile OS & Cloud",
            domain="google.com",
            status="CONFIRMED ECOSYSTEM BOUND",
            details="Active Google Account with automatic provisioning on Android devices, YouTube, Google Drive, and Play Store.",
            footprint_url=f"https://www.google.com/search?q=%22{email}%22"
        ))
    else:
        footprints.append(AppFootprint(
            service="Google Services / Workspace",
            category="Cloud & Workspace",
            domain="google.com",
            status="INDEPENDENT / THIRD-PARTY",
            details="Domain uses external mail servers; may possess Google Workspace SSO or external Google Account association.",
            footprint_url=f"https://epieos.com/?q={email}"
        ))

    # 2. Microsoft Ecosystem (Windows, Office 365, Xbox Live, OneDrive, Skype)
    if any(k in clean_domain for k in ["outlook.com", "hotmail.com", "live.com", "msn.com"]) or "microsoft" in provider.lower():
        footprints.append(AppFootprint(
            service="Microsoft Account & Windows / Xbox Ecosystem",
            category="OS & Gaming",
            domain="microsoft.com",
            status="CONFIRMED ECOSYSTEM BOUND",
            details="Bound to Microsoft identity network, Xbox Live Gamer profile, Windows digital licenses, and OneDrive.",
            footprint_url="https://account.microsoft.com/"
        ))
    else:
        footprints.append(AppFootprint(
            service="Microsoft Account / Office 365",
            category="OS & Productivity",
            domain="microsoft.com",
            status="INDEPENDENT / PROBE CANDIDATE",
            details="Subject may utilize this address for standalone Microsoft accounts, Teams, or Azure DevOps.",
            footprint_url=f"https://www.google.com/search?q=%22{email}%22+site:microsoft.com"
        ))

    # 3. Apple Ecosystem (Apple ID, iCloud, iOS, App Store)
    if any(k in clean_domain for k in ["icloud.com", "me.com", "mac.com"]):
        footprints.append(AppFootprint(
            service="Apple ID & iCloud Ecosystem",
            category="Mobile OS & Cloud",
            domain="apple.com",
            status="CONFIRMED ECOSYSTEM BOUND",
            details="Native Apple ID bound to iOS/macOS hardware devices, App Store purchases, and Find My network.",
            footprint_url="https://appleid.apple.com/"
        ))
    else:
        footprints.append(AppFootprint(
            service="Apple ID & Services",
            category="Mobile OS & Media",
            domain="apple.com",
            status="THIRD-PARTY CANDIDATE",
            details="Third-party address frequently registered as primary login for Apple ID and iTunes purchases.",
            footprint_url=f"https://www.google.com/search?q=%22{email}%22+site:apple.com"
        ))

    # 4. Gravatar & WordPress Global Network
    if gravatar.exists:
        details_str = f"Public profile identified. Name: '{gravatar.display_name or 'Public'}'"
        if gravatar.location:
            details_str += f", Location: '{gravatar.location}'"
        if gravatar.connected_accounts:
            details_str += f", Linked accounts: {len(gravatar.connected_accounts)}"
        footprints.append(AppFootprint(
            service="Gravatar / Automattic Identity Network",
            category="Global Identity & Avatars",
            domain="gravatar.com",
            status="CONFIRMED PUBLIC PROFILE",
            details=details_str,
            footprint_url=gravatar.profile_url
        ))
    else:
        footprints.append(AppFootprint(
            service="Gravatar / Automattic Identity Network",
            category="Global Identity & Avatars",
            domain="gravatar.com",
            status="NO PUBLIC PROFILE DETECTED",
            details="No active Gravatar avatar or bio registered under this email's MD5 hash.",
            footprint_url=f"https://en.gravatar.com/{gravatar.profile_hash}"
        ))

    # 5. GitHub & Open Source Developer Ecosystem
    footprints.append(AppFootprint(
        service="GitHub Developer Network",
        category="Software Development",
        domain="github.com",
        status="PUBLIC SEARCHABLE ENTITY",
        details="Searchable across public git commit logs, pull requests, issue trackers, and developer author headers.",
        footprint_url=f"https://github.com/search?q=%22{email}%22&type=commits"
    ))

    # 6. Professional Networks (LinkedIn)
    footprints.append(AppFootprint(
        service="LinkedIn Professional Network",
        category="Professional & Career",
        domain="linkedin.com",
        status="IDENTITY CANDIDATE",
        details="Common enterprise and corporate contact email for corporate recruiters, CVs, and executive correspondence.",
        footprint_url=f"https://www.google.com/search?q=%22{email}%22+site:linkedin.com"
    ))

    # 7. Media & Entertainment (Spotify / Streaming)
    footprints.append(AppFootprint(
        service="Spotify & Digital Audio Streaming",
        category="Media & Entertainment",
        domain="spotify.com",
        status="COMMON CONSUMER CANDIDATE",
        details="Global consumer audio streaming service frequently tied to this email for billing and playlist profiles.",
        footprint_url="https://www.spotify.com/"
    ))

    # 8. E-Commerce (Amazon)
    footprints.append(AppFootprint(
        service="Amazon Global E-Commerce & AWS",
        category="E-Commerce & Cloud",
        domain="amazon.com",
        status="COMMON CONSUMER CANDIDATE",
        details="Standard consumer identity for retail orders, digital subscriptions, Prime Video, and AWS root credentials.",
        footprint_url="https://www.amazon.com/"
    ))

    # 9. Gaming & Instant Messaging (Discord)
    footprints.append(AppFootprint(
        service="Discord Community & Voice",
        category="Gaming & Communications",
        domain="discord.com",
        status="COMMUNITY CANDIDATE",
        details="Primary registration identifier for gaming guilds, cybersecurity servers, and developer discussion hubs.",
        footprint_url="https://discord.com/"
    ))

    # 10. Social Microblogging (Twitter / X)
    footprints.append(AppFootprint(
        service="Twitter / X Microblogging",
        category="Social Media",
        domain="x.com",
        status="HANDLE CANDIDATE",
        details="Searchable for account verification, password reset endpoints, and handle mentions.",
        footprint_url=f"https://www.google.com/search?q=%22{email}%22+site:x.com+OR+site:twitter.com"
    ))

    return footprints


async def track_email(
    email_address: str,
    session: Optional[aiohttp.ClientSession] = None
) -> EmailFootprintIntelligence:
    """Asynchronously analyze an email address to reconstruct its global digital footprint.

    Examines email syntax, resolves domain infrastructure, identifies major cloud
    ecosystems, audits Gravatar public identity records, enumerates presence across
    top global apps and websites, and generates customized OSINT investigation dorks.

    Args:
        email_address: Raw target email address string.
        session: Optional aiohttp.ClientSession instance.

    Returns:
        Structured EmailFootprintIntelligence instance.
    """
    raw_clean = email_address.strip()
    is_valid, user_part, domain_part = parse_and_validate_email(raw_clean)

    if not is_valid or not domain_part:
        return EmailFootprintIntelligence(
            raw_email=raw_clean,
            is_valid_format=False,
            username=user_part,
            domain=domain_part,
            domain_type="Invalid Syntax",
            is_disposable=False,
            mail_provider="Unresolved (Malformed Email)",
            footprint_score="None",
            error="Malformed email address syntax. Expected format: user@domain.tld"
        )

    # 1. Domain & Provider Classification
    domain_type, provider, is_disposable, mx_hints = classify_email_domain(domain_part)

    # 2. Check Gravatar Profile
    gravatar = await check_gravatar_profile(raw_clean, session=session)

    # 3. Enumerate Digital Footprints Across Global Apps & Platforms
    app_footprints = enumerate_app_footprints(
        email=raw_clean,
        username=user_part,
        domain=domain_part,
        domain_type=domain_type,
        provider=provider,
        gravatar=gravatar
    )

    # 4. Generate OSINT Footprint Dorks
    dork_links = generate_email_footprint_dorks(raw_clean, domain_part)

    # 5. Evaluate Overall Digital Footprint Breadth
    if is_disposable:
        score = "Low / Ephemeral (Burner Disposable Mail)"
    elif gravatar.exists:
        score = "Extensive (Active Public Identity & Multi-Ecosystem Footprint)"
    elif "Major" in domain_type:
        score = "High (Global Cloud Ecosystem Bound)"
    else:
        score = "Moderate (Custom Domain Infrastructure)"

    return EmailFootprintIntelligence(
        raw_email=raw_clean,
        is_valid_format=True,
        username=user_part,
        domain=domain_part,
        domain_type=domain_type,
        is_disposable=is_disposable,
        mail_provider=provider,
        mx_records=mx_hints,
        gravatar=gravatar,
        app_footprints=app_footprints,
        osint_dork_links=dork_links,
        footprint_score=score
    )
