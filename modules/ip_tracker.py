"""
OmniSight-OSINT Network & IP Intelligence Module
================================================
Queries IP geolocation, ASN, and network telemetry endpoints asynchronously.
Includes routing-radius confidence estimation and explicit non-street-level caveats.
"""

import asyncio
import ipaddress
import logging
import socket
from typing import Optional, Tuple
import aiohttp

from config import get_settings
from modules.models import IPIntelligence
from utils.logger import get_logger

logger = get_logger("OmniSight.IPTracker")


def profile_private_subnet(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> dict:
    """Analyze and profile an RFC 1918 / private / internal network address.

    Extracts subnet class, estimated gateway, CIDR boundary, and common hardware/vendor heuristics.

    Args:
        ip_obj: Valid IPv4Address or IPv6Address object.

    Returns:
        Dictionary with private network intelligence attributes.
    """
    clean_ip = str(ip_obj)

    # Default fallback
    intel = {
        "subnet_class": "RFC-1918 / Private Subnet",
        "scope": "Local Area Network (LAN)",
        "subnet_range": "N/A",
        "estimated_gateway": "N/A",
        "vendor_profile": "Standard Internal Network Device",
    }

    if isinstance(ip_obj, ipaddress.IPv4Address):
        octets = clean_ip.split(".")
        first_octet = int(octets[0])
        second_octet = int(octets[1])
        third_octet = int(octets[2])

        # Subnet boundary calculation assuming standard /24 local segment
        network_24 = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        gateway_1 = f"{octets[0]}.{octets[1]}.{octets[2]}.1"

        intel["subnet_range"] = network_24
        intel["estimated_gateway"] = f"{gateway_1} (Host index: .{octets[3]})"

        # Classification & Heuristics
        if first_octet == 10:
            intel["subnet_class"] = "RFC 1918 Class A (10.0.0.0/8)"
            intel["scope"] = "Enterprise Intranet / Large Corporate Subnet / VLAN"
            intel["vendor_profile"] = "Corporate Gateway, Kubernetes Pod CIDR, or Enterprise Core Switch"
        elif first_octet == 172 and 16 <= second_octet <= 31:
            intel["subnet_class"] = "RFC 1918 Class B (172.16.0.0/12)"
            intel["scope"] = "Mid-scale Organization / Virtualization / Docker / VPN"
            if second_octet == 17:
                intel["vendor_profile"] = "Docker Container Engine Default Bridge Network (172.17.0.0/16)"
            else:
                intel["vendor_profile"] = "VPN Virtual Adapter / Virtualized Infrastructure"
        elif first_octet == 192 and second_octet == 168:
            intel["subnet_class"] = "RFC 1918 Class C (192.168.0.0/16)"
            intel["scope"] = "SOHO / Home Broadband / GPON Telecom Access Node"

            # Specific Equipment & Telecom Heuristics
            if third_octet == 100:
                intel["vendor_profile"] = (
                    "GPON / EPON Optical Network Terminal (ONT / ONU), Fiber Modem, "
                    "Huawei EchoLife / ZTE / FiberHome default management subnet"
                )
            elif third_octet == 1:
                intel["vendor_profile"] = "Wireless Consumer Router (Linksys / Cisco / Netgear / TP-Link default)"
            elif third_octet == 0:
                intel["vendor_profile"] = "Home Broadband Wi-Fi Gateway (D-Link / TP-Link default subnet)"
            elif third_octet == 8:
                intel["vendor_profile"] = "4G/LTE Portable Wi-Fi Dongles & Mobile Hotspots (Huawei Mobile Broadband)"
            else:
                intel["vendor_profile"] = "Standard SOHO Private Subnet"
        elif first_octet == 100 and 64 <= second_octet <= 127:
            intel["subnet_class"] = "RFC 6598 Carrier-Grade NAT (CGNAT) (100.64.0.0/10)"
            intel["scope"] = "ISP Cellular / WAN Shared Address Space"
            intel["vendor_profile"] = "Mobile Network Operator (MNO) / ISP CGNAT Aggregator"
        elif first_octet == 169 and second_octet == 254:
            intel["subnet_class"] = "RFC 3927 Link-Local / APIPA (169.254.0.0/16)"
            intel["scope"] = "Link-Local Address (DHCP Server Unreachable)"
            intel["vendor_profile"] = "Operating System Self-Assigned Fallback Adapter"
        elif first_octet == 127:
            intel["subnet_class"] = "RFC 1122 Loopback (127.0.0.0/8)"
            intel["scope"] = "Local Host Inter-Process Communication"
            intel["vendor_profile"] = "Localhost Virtual Loopback Adapter"

    return intel


async def resolve_local_ptr(ip_str: str) -> Optional[str]:
    """Attempt non-blocking reverse DNS PTR lookup on local network."""
    try:
        host, _, _ = await asyncio.wait_for(
            asyncio.to_thread(socket.gethostbyaddr, ip_str),
            timeout=1.0
        )
        return host
    except Exception:
        return None


def calculate_radius_confidence(
    city: Optional[str],
    region: Optional[str],
    country: Optional[str],
    is_private: bool = False
) -> Tuple[float, str]:
    """Calculate approximate geolocation accuracy radius and generate an operational caveat.

    IP geolocations reflect carrier routing hops, BGP prefixes, and data center edge nodes,
    not consumer physical GPS locations.

    Args:
        city: Resolved city or POP name.
        region: Administrative region / province / state.
        country: Resolved country name.
        is_private: Flag indicating RFC 1918 / Loopback non-routable address.

    Returns:
        Tuple of (confidence_radius_km: float, warning_message: str).
    """
    if is_private:
        return (
            0.0,
            "RFC 1918 / Loopback IP: Non-routable on public Internet. Accuracy radius is inapplicable."
        )

    if city and region and country:
        radius_km = 35.0
        msg = (
            f"City-level resolution ({city}, {region}). Radius confidence: ~{radius_km} km. "
            "WARNING: Geolocation corresponds to the ISP Point of Presence (POP) / aggregation switch, "
            "not the physical device or street address."
        )
    elif region and country:
        radius_km = 150.0
        msg = (
            f"Region-level resolution ({region}, {country}). Radius confidence: ~{radius_km} km. "
            "WARNING: Coarse regional aggregation. Physical subscriber may reside anywhere in this region."
        )
    elif country:
        radius_km = 750.0
        msg = (
            f"Country-level resolution ({country}). Radius confidence: ~{radius_km} km. "
            "WARNING: Nationwide routing prefix only. No local precision obtainable via BGP/Whois."
        )
    else:
        radius_km = 2000.0
        msg = "Unresolved geolocation coordinates. Geolocation confidence cannot be determined."

    return radius_km, msg


async def track_ip(
    ip_address: str,
    api_key: Optional[str] = None,
    session: Optional[aiohttp.ClientSession] = None
) -> IPIntelligence:
    """Asynchronously track and geolocate an IP address via IPinfo or fallback endpoints.

    Handles rate-limits gracefully (HTTP 429) and provides structured empty/failure
    schemas on exception to prevent application crashes.

    Args:
        ip_address: Target IPv4 or IPv6 string.
        api_key: Optional IPinfo.io token (retrieved from settings if None).
        session: Optional shared aiohttp.ClientSession.

    Returns:
        Structured IPIntelligence instance.
    """
    settings = get_settings()
    token = api_key or settings.ipinfo_api_key

    # 1. Syntax & Subnet Validation
    clean_ip = ip_address.strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError as err:
        logger.warning(f"Invalid IP address format: '{clean_ip}' ({err})")
        return IPIntelligence(
            ip=clean_ip,
            is_valid=False,
            confidence_warning="Invalid IPv4/IPv6 address syntax.",
            error=f"Syntax error: {err}"
        )

    # 2. Check for private/bogon/loopback addresses
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
        radius, warning = calculate_radius_confidence(None, None, None, is_private=True)
        profile = profile_private_subnet(ip_obj)
        local_hostname = await resolve_local_ptr(clean_ip)

        hostname = local_hostname or ("localhost" if ip_obj.is_loopback else "local-device.lan")

        return IPIntelligence(
            ip=clean_ip,
            is_valid=True,
            is_private=True,
            hostname=hostname,
            country="Local / Internal Network",
            country_code="LOCAL",
            region=profile["scope"],
            city="Private Subnet Segment",
            isp="Local Network Operator / Gateway",
            asn=profile["subnet_class"].split(" ")[0],
            subnet_class=profile["subnet_class"],
            scope=profile["scope"],
            estimated_gateway=profile["estimated_gateway"],
            subnet_range=profile["subnet_range"],
            vendor_profile=profile["vendor_profile"],
            radius_confidence_km=radius,
            confidence_warning=(
                f"Private IP detected ({profile['subnet_class']}). Address is internal to the LAN and non-routable over the public WAN. "
                f"Hardware/Segment Heuristic: {profile['vendor_profile']}."
            ),
            raw_data={"classification": "Internal Private Subnet", **profile}
        )

    # 3. Construct HTTP Request
    endpoint = f"https://ipinfo.io/{clean_ip}/json"
    headers = {
        "User-Agent": settings.default_user_agent,
        "Accept": "application/json"
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    close_session_at_exit = False
    if session is None:
        timeout = aiohttp.ClientTimeout(total=settings.request_timeout)
        session = aiohttp.ClientSession(timeout=timeout)
        close_session_at_exit = True

    try:
        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                logger.debug(f"Querying IP intelligence for {clean_ip} (attempt {attempt + 1})...")
                async with session.get(endpoint, headers=headers) as response:
                    if response.status == 429:
                        # Rate limit reached
                        retry_after = response.headers.get("Retry-After", "2")
                        wait_sec = min(float(retry_after) if retry_after.isdigit() else 2.0, 5.0)
                        logger.warning(
                            f"Rate limited by IPinfo (HTTP 429). Waiting {wait_sec:.1f}s before retry..."
                        )
                        if attempt < max_retries:
                            await asyncio.sleep(wait_sec)
                            continue
                        else:
                            return IPIntelligence(
                                ip=clean_ip,
                                is_valid=True,
                                confidence_warning="API rate limit exceeded on upstream provider.",
                                error="HTTP 429 Too Many Requests (Rate limit reached)"
                            )

                    if response.status == 200:
                        data = await response.json()
                        loc = data.get("loc", "")
                        lat, lon = None, None
                        if loc and "," in loc:
                            try:
                                parts = loc.split(",")
                                lat, lon = float(parts[0].strip()), float(parts[1].strip())
                            except (ValueError, IndexError):
                                pass

                        org = data.get("org", "")
                        asn, isp = None, org
                        if org and org.startswith("AS"):
                            tokens = org.split(" ", 1)
                            asn = tokens[0]
                            isp = tokens[1] if len(tokens) > 1 else org

                        city = data.get("city")
                        region = data.get("region")
                        country = data.get("country")

                        radius, warning = calculate_radius_confidence(city, region, country)

                        return IPIntelligence(
                            ip=clean_ip,
                            is_valid=True,
                            hostname=data.get("hostname"),
                            country=country,
                            country_code=data.get("country"),
                            region=region,
                            city=city,
                            postal=data.get("postal"),
                            latitude=lat,
                            longitude=lon,
                            coordinates=loc if loc else None,
                            isp=isp,
                            asn=asn,
                            timezone=data.get("timezone"),
                            radius_confidence_km=radius,
                            confidence_warning=warning,
                            raw_data=data
                        )
                    else:
                        text_resp = await response.text()
                        logger.error(f"IPinfo returned HTTP {response.status}: {text_resp[:120]}")
                        return IPIntelligence(
                            ip=clean_ip,
                            is_valid=True,
                            confidence_warning="Upstream provider returned an error code.",
                            error=f"HTTP {response.status} from upstream IP resolver"
                        )

            except (aiohttp.ClientError, asyncio.TimeoutError) as req_err:
                if attempt < max_retries:
                    await asyncio.sleep(1.0)
                    continue
                logger.error(f"Network error querying IP intelligence for {clean_ip}: {req_err}")
                return IPIntelligence(
                    ip=clean_ip,
                    is_valid=True,
                    confidence_warning="Network error prevented IP resolution.",
                    error=f"Connection/Timeout failure: {req_err}"
                )

    except Exception as exc:
        logger.exception(f"Unexpected exception while resolving IP {clean_ip}: {exc}")
        return IPIntelligence(
            ip=clean_ip,
            is_valid=False,
            confidence_warning="Unexpected error during lookup execution.",
            error=str(exc)
        )
    finally:
        if close_session_at_exit and session and not session.closed:
            await session.close()
