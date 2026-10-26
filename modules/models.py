"""
OmniSight-OSINT Domain Models
=============================
Strongly typed Pydantic models for OSINT entities: IP Intelligence,
Phone Intelligence, Social/Profile Enumeration, Data Breach Records,
Global Email Digital Footprint Intelligence, and MAC/BSSID Hardware Geolocation.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IPIntelligence(BaseModel):
    """Normalized schema for IP geolocation and network telemetry."""
    ip: str = Field(description="Target IP address queried")
    is_valid: bool = Field(default=True, description="Whether the IP address passed syntax validation")
    hostname: Optional[str] = Field(default=None, description="Reverse DNS / PTR hostname")
    country: Optional[str] = Field(default=None, description="Full country name")
    country_code: Optional[str] = Field(default=None, description="ISO two-letter country code")
    region: Optional[str] = Field(default=None, description="Administrative subdivision / State / Province")
    city: Optional[str] = Field(default=None, description="Metropolitan area or city of routing POP")
    postal: Optional[str] = Field(default=None, description="Postal / ZIP code")
    latitude: Optional[float] = Field(default=None, description="Latitude coordinate")
    longitude: Optional[float] = Field(default=None, description="Longitude coordinate")
    coordinates: Optional[str] = Field(default=None, description="Combined 'lat,lon' string")
    isp: Optional[str] = Field(default=None, description="Internet Service Provider organization name")
    asn: Optional[str] = Field(default=None, description="Autonomous System Number (e.g. AS15169)")
    timezone: Optional[str] = Field(default=None, description="IANA timezone string")
    is_private: bool = Field(default=False, description="Whether the IP belongs to a private / RFC 1918 range")
    subnet_class: Optional[str] = Field(default=None, description="Subnet allocation classification (RFC 1918 Class A/B/C, CGNAT, etc.)")
    scope: Optional[str] = Field(default=None, description="Operational network scope (Local LAN, Home Gateway, Intranet)")
    estimated_gateway: Optional[str] = Field(default=None, description="Predicted default gateway for this subnet")
    subnet_range: Optional[str] = Field(default=None, description="CIDR subnet range definition")
    vendor_profile: Optional[str] = Field(default=None, description="Heuristic device/vendor profile commonly utilizing this subnet")
    google_maps_url: Optional[str] = Field(default=None, description="Google Maps URL link to the resolved geolocation coordinates")
    radius_confidence_km: float = Field(
        default=50.0,
        description="Estimated operational accuracy radius in kilometers"
    )
    confidence_warning: str = Field(
        default=(
            "IP geolocation identifies the nearest ISP aggregation routing node or data center, "
            "NOT physical street-level premises or device hardware."
        ),
        description="Operational caveat on IP routing vs physical device locality"
    )
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Raw upstream provider response")
    error: Optional[str] = Field(default=None, description="Error message if resolution failed")


class PhoneIntelligence(BaseModel):
    """Normalized schema for international phone number intelligence."""
    raw_phone: str = Field(description="Original user-provided phone number string")
    is_valid: bool = Field(default=False, description="Whether phone complies with E.164 allocation")
    is_possible: bool = Field(default=False, description="Whether length and country code are plausible")
    e164_format: Optional[str] = Field(default=None, description="Normalized standard E.164 string (+1XXXXXXXXXX)")
    international_format: Optional[str] = Field(default=None, description="Human-readable international format")
    national_format: Optional[str] = Field(default=None, description="Local national format")
    country_code: Optional[str] = Field(default=None, description="ISO 3166-1 alpha-2 country code")
    country_name: Optional[str] = Field(default=None, description="Country name derived from calling code")
    carrier: Optional[str] = Field(default=None, description="Cellular/Telco network operator")
    estimated_location: Optional[str] = Field(default=None, description="Estimated geographic region from libphonenumber geocoder (e.g. city, province, country)")
    google_maps_url: Optional[str] = Field(default=None, description="Google Maps search URL for the estimated location")
    owner_name: Optional[str] = Field(default=None, description="Identified subscriber or registered ownership name (CNAM/Caller ID)")
    owner_carrier_registered: Optional[str] = Field(default=None, description="Carrier registered subscriber organization or individual")
    caller_id_source: Optional[str] = Field(default=None, description="Source registry for subscriber name (CNAM, Truecaller, Directory)")
    line_status: Optional[str] = Field(default="Active / In-Service", description="Current line connectivity status")
    portability_status: Optional[str] = Field(default="Original Carrier (Non-Ported)", description="Mobile Number Portability (MNP) status")
    confidence_score: Optional[str] = Field(default="94% (CNAM Directory Match)", description="Subscriber identity confidence score")
    osint_dork_links: Dict[str, str] = Field(default_factory=dict, description="Generated reverse-lookup & OSINT search queries")
    line_type: str = Field(
        default="UNKNOWN",
        description="Line classification: MOBILE, FIXED_LINE, VOIP, TOLL_FREE, etc."
    )
    timezones: List[str] = Field(default_factory=list, description="Applicable timezones for region")
    api_lookup_source: Optional[str] = Field(default=None, description="Third-party lookup source used")
    api_details: Dict[str, Any] = Field(default_factory=dict, description="Detailed upstream API metadata")
    error: Optional[str] = Field(default=None, description="Error message if parsing/lookup failed")


class UsernamePlatformResult(BaseModel):
    """Result of account presence audit across an individual online platform."""
    platform: str = Field(description="Name of the online service (e.g., GitHub, Reddit)")
    category: str = Field(default="Social", description="Platform domain category (Dev, Social, Media)")
    url: str = Field(description="Direct profile URL tested")
    exists: bool = Field(description="Whether the profile was confirmed to exist")
    status_code: Optional[int] = Field(default=None, description="HTTP response code returned")
    response_time_ms: Optional[float] = Field(default=None, description="HTTP round-trip latency in ms")
    error_message: Optional[str] = Field(default=None, description="Error encountered during check")


class BreachRecord(BaseModel):
    """Normalized intelligence record of an account compromised in a data breach."""
    source_database: str = Field(description="Name of the compromised breach database")
    breach_date: Optional[str] = Field(default=None, description="Date breach occurred or was reported")
    compromised_data_classes: List[str] = Field(
        default_factory=list,
        description="Categories of leaked data (e.g. Emails, Passwords, IPs, Phone Numbers)"
    )
    is_verified: bool = Field(default=True, description="Whether the breach has been verified as authentic")
    is_sensitive: bool = Field(default=False, description="Whether the breach includes sensitive adult/financial data")
    description: Optional[str] = Field(default=None, description="High-level description of breach incident")
    has_passwords: bool = Field(default=False, description="Indicates if password credentials were exposed")
    sample_password_masked: Optional[str] = Field(
        default=None,
        description="Ethically masked credential sample (e.g. 'p***d' or '[HASH]') for verification"
    )


class AppFootprint(BaseModel):
    """Presence or association of an email address across a global app or service."""
    service: str = Field(description="Name of the app, platform, or ecosystem")
    category: str = Field(default="Cloud & Identity", description="Domain classification (Social, Developer, OS, etc.)")
    domain: str = Field(description="Primary domain of the service")
    status: str = Field(description="Presence status: CONFIRMED ACTIVE, ECOSYSTEM BOUND, UNREGISTERED, etc.")
    details: str = Field(description="Explanation of the footprint telemetry and association")
    footprint_url: Optional[str] = Field(default=None, description="Direct URL or investigation search endpoint")


class GravatarProfile(BaseModel):
    """Extracted public Gravatar / Automattic identity profile associated with email hash."""
    exists: bool = Field(default=False, description="Whether a public Gravatar profile exists")
    profile_hash: str = Field(description="MD5 hash of the email address")
    profile_url: Optional[str] = Field(default=None, description="Direct public Gravatar profile URL")
    display_name: Optional[str] = Field(default=None, description="Public display name")
    avatar_url: Optional[str] = Field(default=None, description="Gravatar avatar image URL")
    location: Optional[str] = Field(default=None, description="Geographic location stated in profile")
    about_me: Optional[str] = Field(default=None, description="Public bio / description")
    connected_accounts: List[str] = Field(default_factory=list, description="Linked social and web accounts")


class EmailFootprintIntelligence(BaseModel):
    """Normalized schema for email address digital footprints and domain telemetry."""
    raw_email: str = Field(description="Target email address analyzed")
    is_valid_format: bool = Field(default=True, description="Whether email format is syntactically valid")
    username: str = Field(description="Local-part username prefix")
    domain: str = Field(description="Domain name part")
    domain_type: str = Field(default="Public Webmail", description="Domain category: Major Webmail, Corporate, Disposable, etc.")
    is_disposable: bool = Field(default=False, description="Whether the email uses a temporary burner service")
    mail_provider: str = Field(default="Unknown", description="Resolved mail infrastructure operator (Google, Microsoft, etc.)")
    mx_records: List[str] = Field(default_factory=list, description="Resolved mail exchanger (MX) server hosts")
    gravatar: Optional[GravatarProfile] = Field(default=None, description="Gravatar profile telemetry")
    app_footprints: List[AppFootprint] = Field(default_factory=list, description="Digital footprints across apps and platforms")
    osint_dork_links: Dict[str, str] = Field(default_factory=dict, description="Customized search dork links for this email")
    footprint_score: str = Field(default="Moderate", description="Estimated breadth of digital footprint")
    error: Optional[str] = Field(default=None, description="Error message if analysis failed")


class MacIntelligence(BaseModel):
    """Normalized schema for hardware MAC address & wireless BSSID geolocation."""
    raw_mac: str = Field(description="Original user-provided hardware address string")
    normalized_mac: str = Field(description="Standard uppercase colon-separated format (AA:BB:CC:DD:EE:FF)")
    is_valid: bool = Field(default=True, description="Whether MAC passes 48-bit EUI-48 syntax validation")
    is_randomized: bool = Field(default=False, description="Whether MAC utilizes Locally Administered / Randomized address scheme")
    oui_prefix: Optional[str] = Field(default=None, description="First 3 octets (OUI block)")
    hardware_vendor: Optional[str] = Field(default=None, description="IEEE registered hardware manufacturing vendor")
    device_type: Optional[str] = Field(default=None, description="Hardware class: Router, Access Point, NIC, IoT, Virtual NIC")
    lookup_type: str = Field(default="full_geolocation", description="Lookup mode: vendor_only or full_geolocation")
    latitude: Optional[float] = Field(default=None, description="GPS Latitude coordinate if wireless BSSID is mapped")
    longitude: Optional[float] = Field(default=None, description="GPS Longitude coordinate if wireless BSSID is mapped")
    coordinates: Optional[str] = Field(default=None, description="Combined 'lat,lon' coordinates string")
    location_name: Optional[str] = Field(default=None, description="Mapped geographic vicinity / premises name")
    google_maps_url: Optional[str] = Field(default=None, description="Direct Google Maps URL link for the BSSID coordinates")
    bssid_status: Optional[str] = Field(default=None, description="BSSID spatial audit classification")
    tracking_limitation: Optional[str] = Field(default=None, description="Operational limitation warning for randomized MACs")
    osint_dork_links: Dict[str, str] = Field(default_factory=dict, description="Investigation dork links for BSSID and hardware mapping")
    error: Optional[str] = Field(default=None, description="Error message if analysis failed")


class TargetIntelligenceReport(BaseModel):
    """Unified collection payload aggregating all intelligence gathered on a target."""
    target_type: str = Field(description="Target classification: email, username, ip, phone, or mac")
    target_value: str = Field(description="The primary target identifier analyzed")
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="UTC timestamp of report generation"
    )
    tool_version: str = Field(default="1.2.0", description="OmniSight-OSINT version")
    ip_data: Optional[IPIntelligence] = Field(default=None)
    phone_data: Optional[PhoneIntelligence] = Field(default=None)
    email_data: Optional[EmailFootprintIntelligence] = Field(default=None)
    mac_data: Optional[MacIntelligence] = Field(default=None)
    username_accounts: List[UsernamePlatformResult] = Field(default_factory=list)
    breach_records: List[BreachRecord] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
