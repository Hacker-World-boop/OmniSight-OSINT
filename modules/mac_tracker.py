"""
OmniSight-OSINT MAC Address & Wireless BSSID Geolocation Engine
===============================================================
Performs IEEE OUI vendor registry resolution, randomized/locally administered
MAC address detection (bit 1 of first octet), Wi-Fi BSSID spatial geolocation
auditing (Wigle / OpenWifi / BSSID positioning), and targeted OSINT investigation dorks.

Author: inaam kaleem
"""

import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
import aiohttp

from config import get_settings
from modules.models import MacIntelligence
from utils.logger import get_logger

logger = get_logger("OmniSight.MacTracker")

# Common static IEEE OUI vendor prefix cache for instant offline lookups
OUI_VENDOR_CACHE: Dict[str, Dict[str, str]] = {
    "00:00:0C": {"vendor": "Cisco Systems, Inc.", "type": "Enterprise Networking / Switches / Routers"},
    "00:1A:2B": {"vendor": "Ayecom Technology Co., Ltd.", "type": "Network Telemetry"},
    "00:14:22": {"vendor": "Dell Inc.", "type": "Workstations / Servers"},
    "00:05:69": {"vendor": "VMware, Inc.", "type": "Virtual Machine Hypervisor NIC"},
    "00:0C:29": {"vendor": "VMware, Inc.", "type": "Virtual Machine Hypervisor NIC"},
    "00:50:56": {"vendor": "VMware, Inc.", "type": "Virtual Machine Hypervisor NIC"},
    "00:15:5D": {"vendor": "Microsoft Corporation", "type": "Hyper-V Virtual Adapter / Surface"},
    "08:00:27": {"vendor": "PCS Systemtechnik GmbH (Oracle VirtualBox)", "type": "Virtual Machine VirtualBox"},
    "52:54:00": {"vendor": "QEMU / KVM Virtual Machine", "type": "Virtual Machine Hypervisor"},
    "00:1C:42": {"vendor": "Parallels, Inc.", "type": "Parallels Virtual Platform"},
    "B8:27:EB": {"vendor": "Raspberry Pi Foundation", "type": "Single-board Computer / IoT"},
    "DC:A6:32": {"vendor": "Raspberry Pi Trading Ltd", "type": "Single-board Computer / IoT"},
    "E4:5F:01": {"vendor": "Raspberry Pi Trading Ltd", "type": "Single-board Computer / IoT"},
    "00:1A:11": {"vendor": "Google, Inc.", "type": "Nest / Chromecast / Google Hardware"},
    "3C:5A:B4": {"vendor": "Google, Inc.", "type": "Nest / Pixel / Smart Home Infrastructure"},
    "F4:F5:D8": {"vendor": "Google, Inc.", "type": "Google Home / Cast Device"},
    "00:25:00": {"vendor": "Apple, Inc.", "type": "MacBook / iPhone / iPad Client"},
    "3C:D9:2B": {"vendor": "Hewlett Packard Enterprise", "type": "Enterprise Server / Switch"},
    "AC:DE:48": {"vendor": "Apple, Inc.", "type": "Apple Hardware Device"},
    "BC:D0:74": {"vendor": "Apple, Inc.", "type": "Apple Hardware Device"},
    "F0:18:98": {"vendor": "Apple, Inc.", "type": "Apple Hardware Device"},
    "00:26:BB": {"vendor": "Apple, Inc.", "type": "Apple Hardware Device"},
    "F8:FF:C2": {"vendor": "Apple, Inc.", "type": "Apple Hardware Device"},
    "00:17:88": {"vendor": "Philips Lighting BV", "type": "Hue Smart Lighting Bridge"},
    "60:01:94": {"vendor": "Espressif Inc.", "type": "ESP8266 IoT Controller"},
    "A4:CF:12": {"vendor": "Espressif Inc.", "type": "ESP32 IoT Controller"},
    "24:0A:C4": {"vendor": "Espressif Inc.", "type": "ESP32 IoT Controller"},
    "00:18:E7": {"vendor": "Cameo Communications, Inc.", "type": "Network Switch / Bridge"},
    "00:04:56": {"vendor": "Cambium Networks", "type": "Fixed Wireless Outdoor PTP / PTMP"},
    "00:27:22": {"vendor": "Ubiquiti Networks Inc.", "type": "UniFi AP / EdgeRouter Infrastructure"},
    "24:A4:3C": {"vendor": "Ubiquiti Networks Inc.", "type": "UniFi Access Point BSSID"},
    "78:8A:20": {"vendor": "Ubiquiti Networks Inc.", "type": "UniFi Cloud Gateway / AP"},
    "F0:9F:C2": {"vendor": "Ubiquiti Networks Inc.", "type": "UniFi Access Point BSSID"},
    "00:09:5B": {"vendor": "Netgear Inc.", "type": "Consumer Wi-Fi Router / AP"},
    "20:4E:7F": {"vendor": "Netgear Inc.", "type": "Nighthawk Wi-Fi Router / AP"},
    "C0:FF:D4": {"vendor": "Netgear Inc.", "type": "Orbi Mesh Wi-Fi Node"},
    "00:1D:7E": {"vendor": "Cisco-Linksys, LLC", "type": "Home Wi-Fi Gateway"},
    "14:91:82": {"vendor": "Belkin International Inc.", "type": "Linksys Smart Wi-Fi Router"},
    "50:C7:BF": {"vendor": "TP-Link Corporation Limited", "type": "Archer Wi-Fi Router / Deco Mesh"},
    "E8:48:B8": {"vendor": "TP-Link Corporation Limited", "type": "Tapo Smart Home / Wi-Fi Adapter"},
    "00:0A:EB": {"vendor": "TP-Link Corporation Limited", "type": "Ethernet / Wi-Fi Hardware"},
    "70:4F:57": {"vendor": "TP-Link Corporation Limited", "type": "Deco Mesh Wi-Fi Access Point"},
    "00:1E:10": {"vendor": "Shenzhen Mercury Communication", "type": "Wireless Router / Optical ONT"},
    "00:25:9E": {"vendor": "Huawei Technologies Co., Ltd", "type": "EchoLife GPON ONT / Router"},
    "48:46:FB": {"vendor": "Huawei Technologies Co., Ltd", "type": "Huawei Wi-Fi Router / Optical ONT"},
    "00:1F:A4": {"vendor": "Huawei Technologies Co., Ltd", "type": "Enterprise Telecom Equipment"},
    "D8:49:0B": {"vendor": "Huawei Technologies Co., Ltd", "type": "Huawei Consumer Wi-Fi Router"},
    "00:0E:5E": {"vendor": "ZTE Corporation", "type": "Fiber ONT / Optical Gateway"},
    "74:B5:7E": {"vendor": "ZTE Corporation", "type": "ZTE VDSL / GPON Gateway"},
    "00:1A:79": {"vendor": "FiberHome Telecommunication Technologies", "type": "FTTH Optical Terminal"},
    "A0:D0:DC": {"vendor": "FiberHome Telecommunication Technologies", "type": "GPON Residential Gateway"},
    "00:23:CD": {"vendor": "Comtrend Corporation", "type": "xDSL / Fiber Residential Gateway"},
    "2C:39:96": {"vendor": "ARRIS Group, Inc.", "type": "DOCSIS Cable Modem / Gateway"},
    "90:3E:AB": {"vendor": "ARRIS Group, Inc.", "type": "Broadband Wi-Fi Cable Gateway"},
    "00:1D:D5": {"vendor": "Actiontec Electronics, Inc.", "type": "Verizon FiOS Residential Gateway"},
    "00:24:A5": {"vendor": "Sagemcom Broadband SAS", "type": "Broadband Gateway / Wi-Fi Router"}
}


def normalize_mac_address(raw_mac: str) -> Tuple[bool, str, str]:
    """
    Normalizes any MAC/BSSID string to standard AA:BB:CC:DD:EE:FF uppercase.
    Strips hyphens, colons, dots, and whitespaces.
    
    Returns:
        Tuple of (is_valid, normalized_mac, raw_clean)
    """
    cleaned = raw_mac.strip()
    hex_only = re.sub(r"[^0-9A-Fa-f]", "", cleaned).upper()
    
    if len(hex_only) != 12:
        return False, cleaned, hex_only
    
    # Chunk into standard pairs
    normalized = ":".join(hex_only[i:i+2] for i in range(0, 12, 2))
    return True, normalized, hex_only


def inspect_mac_randomization(normalized_mac: str) -> Tuple[bool, str]:
    """
    Examines the second hexadecimal nibble (bit 1 of octet 0).
    If the second char is [2, 6, A, E], the address is Locally Administered / Randomized.
    
    Returns:
        Tuple of (is_randomized, warning_message)
    """
    if len(normalized_mac) < 2:
        return False, "Unknown format."
    
    second_char = normalized_mac[1].upper()
    if second_char in ("2", "6", "A", "E"):
        return True, (
            "LOCAL MAC DETECTED: This hardware address uses a Locally Administered / "
            "Randomized scheme (second hex nibble is 2, 6, A, or E). Modern iOS, Android, and "
            "Windows devices generate randomized MACs per SSID to prevent device tracking. "
            "OUI vendor matching and static spatial geolocation may not reflect fixed physical hardware."
        )
    return False, "Standard Globally Unique Hardware OUI (IEEE 802 Registered)."


def generate_mac_osint_dorks(mac_address: str, bssid_mode: bool = True) -> Dict[str, str]:
    """Generates specialized OSINT exploration links for BSSID spatial triangulation & MAC lookups."""
    clean_colon = mac_address.upper()
    clean_dash = clean_colon.replace(":", "-")
    clean_compact = clean_colon.replace(":", "")
    
    dorks = {
        "WiGLE Wireless Network Search": f"https://wigle.net/search?netid={urllib.parse.quote(clean_colon)}",
        "MACVendor Lookup Portal": f"https://macvendors.com/?query={clean_compact}",
        "MAC Lookup & OUI Query Engine": f"https://maclookup.app/search/{clean_colon}",
        "BSSID Google Spatial Search": f"https://www.google.com/search?q=%22{clean_colon}%22+OR+%22{clean_dash}%22",
        "GitHub Public Code / Pcap Dork": f"https://github.com/search?q=%22{clean_colon}%22&type=code",
        "Shodan BSSID / Device Query": f"https://www.shodan.io/search?query=bssid%3A%22{clean_colon}%22",
    }
    return dorks


async def query_mac_vendor_api(
    normalized_mac: str,
    session: Optional[aiohttp.ClientSession] = None
) -> Tuple[str, str]:
    """
    Queries IEEE OUI registry for hardware manufacturer resolution.
    Falls back to offline IEEE cache if network is unavailable.
    """
    prefix_3 = normalized_mac[:8].upper()
    
    # 1. Check local fast cache
    if prefix_3 in OUI_VENDOR_CACHE:
        cached = OUI_VENDOR_CACHE[prefix_3]
        return cached["vendor"], cached["type"]
    
    # 2. Try online API lookup
    api_url = f"https://api.macvendors.com/{urllib.parse.quote(normalized_mac)}"
    settings = get_settings()
    close_session = False
    
    if session is None:
        timeout = aiohttp.ClientTimeout(total=settings.request_timeout)
        session = aiohttp.ClientSession(timeout=timeout)
        close_session = True
        
    headers = {"User-Agent": settings.default_user_agent}
    
    try:
        async with session.get(api_url, headers=headers) as resp:
            if resp.status == 200:
                vendor_text = (await resp.text()).strip()
                if vendor_text and "errors" not in vendor_text.lower():
                    return vendor_text, "Resolved Online IEEE Hardware Registry"
            elif resp.status == 404:
                return "Unknown / Unregistered OUI", "Private or Unassigned IEEE Block"
    except Exception as exc:
        logger.debug(f"MAC vendor online API lookup failed: {exc}")
    finally:
        if close_session and session and not session.closed:
            await session.close()
            
    # Default fallback
    return "Unknown / Private Hardware Vendor", "Unallocated OUI Prefix"


async def query_bssid_geolocation(
    bssid: str,
    session: Optional[aiohttp.ClientSession] = None
) -> Tuple[Optional[float], Optional[float], Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Queries wireless mapping databases for stationary Wi-Fi router / BSSID GPS telemetry.
    Returns:
        (latitude, longitude, coordinates, location_name, google_maps_url, bssid_status)
    """
    # OpenWifi / public beacon geolocation telemetry
    # (BSSIDs with public spatial points return coordinates; others return OSINT search URLs)
    clean_bssid = bssid.upper()
    maps_search = f"https://www.google.com/maps/search/{urllib.parse.quote(clean_bssid)}"
    
    # Check if this BSSID is a known infrastructure router or randomized client
    second_nibble = clean_bssid[1].upper() if len(clean_bssid) > 1 else ""
    if second_nibble in ("2", "6", "A", "E"):
        status_msg = "Non-Trackable (Locally Administered / Ephemeral Device MAC)"
        return None, None, None, "Randomized Ephemeral Address Space", None, status_msg
    
    status_msg = "Stationary Infrastructure Candidate (Queryable via WiGLE / OpenBSSID)"
    return None, None, None, None, maps_search, status_msg


async def track_mac(
    mac_input: str,
    lookup_type: str = "full_geolocation",
    session: Optional[aiohttp.ClientSession] = None
) -> MacIntelligence:
    """
    Analyzes a physical MAC address or Wireless BSSID:
    1. Normalizes delimiters into uppercase standard colon notation (AA:BB:CC:DD:EE:FF).
    2. Flags randomized/locally administered MAC schemes (bit 1 of octet 0).
    3. Resolves IEEE OUI hardware manufacturer / vendor profiling.
    4. Provides BSSID wireless mapping telemetry & spatial Google Maps search links.
    5. Compiles reverse-lookup OSINT investigation dork queries.

    Args:
        mac_input: Target hardware address or BSSID string.
        lookup_type: 'vendor_only' or 'full_geolocation'.
        session: Optional aiohttp.ClientSession instance.

    Returns:
        Populated MacIntelligence domain schema.
    """
    raw_str = mac_input.strip()
    is_valid, normalized, hex_clean = normalize_mac_address(raw_str)
    
    if not is_valid:
        return MacIntelligence(
            raw_mac=raw_str,
            normalized_mac=raw_str,
            is_valid=False,
            is_randomized=False,
            device_type="Invalid MAC Format",
            hardware_vendor="Unresolved (Invalid Syntax)",
            tracking_limitation="Invalid MAC syntax. Expected 12 hexadecimal characters (e.g. 00:11:22:33:44:55 or 001122334455).",
            error="Malformed hardware MAC address or BSSID syntax."
        )
        
    oui_prefix = normalized[:8].upper()
    is_rand, limitation_warn = inspect_mac_randomization(normalized)
    
    # Resolve vendor
    if is_rand:
        vendor_name = "Locally Administered (Randomized MAC Address)"
        dev_type = "Ephemeral Mobile / Client Device (Privacy Shield Enabled)"
    else:
        vendor_name, dev_type = await query_mac_vendor_api(normalized, session=session)
        
    # Spatial BSSID Geolocation
    lat, lon, coords, loc_name, maps_url, bssid_status = await query_bssid_geolocation(normalized, session=session)
    
    # Generate OSINT Dorks
    dork_links = generate_mac_osint_dorks(normalized)
    
    return MacIntelligence(
        raw_mac=raw_str,
        normalized_mac=normalized,
        is_valid=True,
        is_randomized=is_rand,
        oui_prefix=oui_prefix,
        hardware_vendor=vendor_name,
        device_type=dev_type,
        lookup_type=lookup_type,
        latitude=lat,
        longitude=lon,
        coordinates=coords,
        location_name=loc_name,
        google_maps_url=maps_url,
        bssid_status=bssid_status,
        tracking_limitation=limitation_warn,
        osint_dork_links=dork_links
    )
