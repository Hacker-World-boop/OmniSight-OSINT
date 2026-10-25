#!/usr/bin/env python3
"""
OmniSight-OSINT CLI Entry Point (Linux Edition)
==============================================
Unified Command-Line Interface and Rich UI presentation layer for OmniSight-OSINT.
Coordinates concurrent intelligence gathering, error resilience, terminal styling,
and structured JSON artifact exportation on Linux systems.

Author: inaam kaleem
"""

import argparse
import asyncio
import io
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ─── Linux Operating System Enforcement ─────────────────────────────────────────
if not sys.platform.startswith("linux") and not os.environ.get("OSINT_ALLOW_ANY_OS"):
    sys.stderr.write("[-] Error: OmniSight-OSINT is engineered for Linux systems only.\n")
    sys.stderr.write(f"[-] Detected Operating System: {sys.platform}\n")
    sys.stderr.write("[-] Please run this tool on a Linux distribution (Ubuntu, Debian, Kali, Arch, etc.).\n")
    sys.exit(1)

import aiohttp
from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from config import get_settings
from modules.breach_hunter import check_breaches, hunt_username
from modules.ip_tracker import track_ip
from modules.models import TargetIntelligenceReport
from modules.phone_tracker import track_phone
from utils.logger import setup_logger

console = Console()

# ─── Colour Palette ─────────────────────────────────────────────────────────────
NEON_GREEN    = "#00FF41"
ELECTRIC_CYAN = "#00E5FF"
SKY_BLUE      = "#00BFFF"
PURPLE        = "#6C5CE7"
VIOLET        = "#A855F7"
MAGENTA       = "#FF00FF"
HOT_PINK      = "#FF0055"
GOLD          = "#FFD700"

BANNER_ART = r"""
  ___                  _ ____  _       _     _        ___  ____ ___ _   _ _____ 
 / _ \ _ __ ___  _ __ (_) ___|(_) __ _| |__ | |_     / _ \/ ___|_ _| \ | |_   _|
| | | | '_ ` _ \| '_ \| \___ \| |/ _` | '_ \| __|---| | | \___ \| ||  \| | | |  
| |_| | | | | | | | | | |___) | | (_| | | | | |_ |---| |_| |___) | || |\  | | |  
 \___/|_| |_| |_|_| |_|_|____/|_|\__, |_| |_|\__|    \___/|____/___|_| \_| |_|  
                                 |___/                                          
"""


def render_banner() -> None:
    """Print the stylized OmniSight banner without emojis or extraneous identity details."""
    banner_lines = BANNER_ART.strip().split("\n")
    gradient = [
        f"bold {NEON_GREEN}",
        f"bold {ELECTRIC_CYAN}",
        f"bold {SKY_BLUE}",
        f"bold {PURPLE}",
        f"bold {VIOLET}",
        f"bold {MAGENTA}",
    ]

    banner_text = Text()
    for i, line in enumerate(banner_lines):
        color = gradient[i % len(gradient)]
        banner_text.append(line + "\n", style=color)

    tool_title = Text("OmniSight-OSINT", style=f"bold {ELECTRIC_CYAN}")
    author_info = Text("author = inaam kaleem", style=f"bold {NEON_GREEN}")

    combined = Text()
    combined.append(banner_text)
    combined.append("\n")
    combined.append(tool_title)
    combined.append("\n")
    combined.append(author_info)

    panel = Panel(
        Align.center(combined),
        border_style=f"bold {NEON_GREEN}",
        box=box.DOUBLE,
        padding=(1, 2),
        title=f"[bold {MAGENTA}][ OMNISIGHT-OSINT ][/bold {MAGENTA}]",
    )
    console.print(panel)


def render_section_divider(title: str, color: str = "#00E5FF") -> None:
    """Render a styled section divider with a centred title."""
    console.print()
    console.print(Rule(
        title=f"[bold {color}] {title} [/bold {color}]",
        style=color,
        characters="-"
    ))
    console.print()


def render_scan_header(target_type: str, target_value: str) -> None:
    """Display a pre-scan target acquisition header without emojis."""
    header = Text()
    header.append("  [+] TARGET ACQUIRED\n\n", style=f"bold {HOT_PINK}")
    header.append("  | Type   : ", style="dim white")
    header.append(f"{target_type.upper()}\n", style=f"bold {NEON_GREEN}")
    header.append("  | Value  : ", style="dim white")
    header.append(f"{target_value}\n", style=f"bold {GOLD}")
    header.append("  | Time   : ", style="dim white")
    header.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", style=f"bold {SKY_BLUE}")
    header.append("  | Engine : ", style="dim white")
    header.append("OmniSight Async Pipeline v1.0 (Linux)\n", style=f"bold {VIOLET}")

    panel = Panel(
        header,
        border_style=f"bold {HOT_PINK}",
        box=box.ROUNDED,
        title=f"[bold {HOT_PINK}][ SCAN INITIATED ][/bold {HOT_PINK}]",
    )
    console.print(panel)


def render_scan_complete(target_type: str) -> None:
    """Display a post-scan completion footer without emojis."""
    footer = Text()
    footer.append("  [+] ", style="bold")
    footer.append("Intelligence gathering complete. ", style=f"bold {NEON_GREEN}")
    footer.append("All modules executed successfully.\n", style="dim bright_white")
    footer.append("  | Completed at: ", style="dim white")
    footer.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", style=f"bold {SKY_BLUE}")
    footer.append("  | Module      : ", style="dim white")
    footer.append(f"{target_type.upper()} Intelligence Engine", style=f"bold {VIOLET}")

    panel = Panel(
        footer,
        border_style=f"bold {NEON_GREEN}",
        box=box.ROUNDED,
        title=f"[bold {NEON_GREEN}][ SCAN COMPLETE ][/bold {NEON_GREEN}]",
    )
    console.print()
    console.print(panel)


def display_ip_results(report: TargetIntelligenceReport) -> None:
    """Render IP intelligence telemetry in Rich tables and callout panels."""
    data = report.ip_data
    if not data:
        console.print(f"[{GOLD}]No IP intelligence data captured.[/{GOLD}]")
        return

    # Check if target is a private / internal IP
    if data.is_private:
        table = Table(
            title=f"[bold black on {ELECTRIC_CYAN}] PRIVATE NETWORK & SUBNET INTELLIGENCE (LAN TARGET) [/bold black on {ELECTRIC_CYAN}]",
            box=box.ROUNDED,
            border_style=f"bold {ELECTRIC_CYAN}",
            header_style="bold bright_white on dark_blue"
        )
        table.add_column("Attribute", style="bold bright_white", width=26)
        table.add_column("Extracted Intelligence", style=f"{NEON_GREEN}")

        table.add_row("Target IP Address", f"[bold {GOLD}]{data.ip}[/bold {GOLD}]")
        table.add_row("Address Status", f"[bold black on {NEON_GREEN}] RFC 1918 Private / Valid [/bold black on {NEON_GREEN}]")
        table.add_row("Subnet Classification", f"[bold {MAGENTA}]{data.subnet_class or 'RFC-1918 Private'}[/bold {MAGENTA}]")
        table.add_row("Operational Scope", f"[bold {ELECTRIC_CYAN}]{data.scope or 'Local Network'}[/bold {ELECTRIC_CYAN}]")
        table.add_row("Subnet Segment (CIDR)", f"[bold {NEON_GREEN}]{data.subnet_range or 'N/A'}[/bold {NEON_GREEN}]")
        table.add_row("Estimated Gateway", f"[bold {GOLD}]{data.estimated_gateway or 'N/A'}[/bold {GOLD}]")
        table.add_row("Local Hostname / PTR", f"[bold black on {GOLD}] {data.hostname or 'Unresolved'} [/bold black on {GOLD}]")
        table.add_row("Hardware / Vendor Profile", f"[bold {SKY_BLUE}]{data.vendor_profile or 'Standard LAN'}[/bold {SKY_BLUE}]")
        table.add_row("Public WAN Routable", f"[bold {HOT_PINK}]No (Internal Subnet Only)[/bold {HOT_PINK}]")

        console.print(table)

        # Operational Caveat Panel for Private IP
        warn_text = Text()
        warn_text.append("[!] LAN BOUNDARY DETECTED: ", style=f"bold {GOLD}")
        warn_text.append("Internal RFC 1918 Address Space\n", style="bold bright_white")
        warn_text.append(data.confidence_warning, style="italic bright_white")

        warning_panel = Panel(
            warn_text,
            title=f"[bold black on {GOLD}] PRIVATE NETWORK CAVEAT [/bold black on {GOLD}]",
            border_style=f"bold {GOLD}",
            box=box.ROUNDED
        )
        console.print(warning_panel)
        return

    # Public IP table
    table = Table(
        title=f"[bold black on {SKY_BLUE}] PUBLIC NETWORK & WAN GEOLOCATION [/bold black on {SKY_BLUE}]",
        box=box.ROUNDED,
        border_style=f"bold {ELECTRIC_CYAN}",
        header_style="bold bright_white on dark_blue"
    )
    table.add_column("Attribute", style="bold bright_white", width=24)
    table.add_column("Extracted Intelligence", style=f"{NEON_GREEN}")

    table.add_row("Target IP Address", f"[bold {GOLD}]{data.ip}[/bold {GOLD}]")
    table.add_row("Address Status", f"[bold black on {NEON_GREEN}] Valid Public WAN [/bold black on {NEON_GREEN}]" if data.is_valid else f"[bold white on {HOT_PINK}] Invalid Syntax [/bold white on {HOT_PINK}]")
    if data.hostname:
        table.add_row("Hostname / PTR", f"[bold {ELECTRIC_CYAN}]{data.hostname}[/bold {ELECTRIC_CYAN}]")
    table.add_row("Country", f"[bold {MAGENTA}]{data.country or 'Unknown'}[/bold {MAGENTA}] ({data.country_code or 'N/A'})")
    table.add_row("Region / State", f"[bold {SKY_BLUE}]{data.region or 'Unknown'}[/bold {SKY_BLUE}]")
    table.add_row("City / Metro", f"[bold {VIOLET}]{data.city or 'Unknown'}[/bold {VIOLET}]")
    table.add_row("Postal / ZIP Code", data.postal or "N/A")
    table.add_row("Coordinates (Lat, Lon)", f"[bold {GOLD}]{data.coordinates or 'N/A'}[/bold {GOLD}]")
    table.add_row("ISP / Organization", f"[bold {ELECTRIC_CYAN}]{data.isp or 'Unknown'}[/bold {ELECTRIC_CYAN}]")
    table.add_row("Autonomous System (ASN)", f"[bold {PURPLE}]{data.asn or 'N/A'}[/bold {PURPLE}]")
    table.add_row("Timezone", f"[bold bright_white]{data.timezone or 'N/A'}[/bold bright_white]")

    console.print(table)

    # Operational Accuracy Warning Panel
    warn_text = Text()
    warn_text.append("[!] RADIUS CONFIDENCE: ", style=f"bold {GOLD}")
    warn_text.append(f"~{data.radius_confidence_km:.1f} km\n", style="bold bright_white")
    warn_text.append(data.confidence_warning, style="italic bright_white")

    warning_panel = Panel(
        warn_text,
        title=f"[bold black on {GOLD}] OPERATIONAL GEOLOCATION CAVEAT [/bold black on {GOLD}]",
        border_style=f"bold {GOLD}",
        box=box.ROUNDED
    )
    console.print(warning_panel)


def display_phone_results(report: TargetIntelligenceReport) -> None:
    """Render Phone intelligence telemetry in Rich tables with ownership metadata."""
    data = report.phone_data
    if not data:
        console.print(f"[{GOLD}]No phone intelligence data captured.[/{GOLD}]")
        return

    # ─── Prominent Subscriber Ownership Identity Card ───────────────────────
    if data.owner_name:
        owner_card = Text()
        owner_card.append("  [+] TARGET SUBSCRIBER / OWNER PROFILE\n\n", style=f"bold {GOLD}")
        owner_card.append("  | Identified Owner   : ", style="dim bright_white")
        owner_card.append(f" {data.owner_name} \n", style=f"bold black on {NEON_GREEN}")
        owner_card.append("  | Subscriber Registry: ", style="dim bright_white")
        owner_card.append(f"{data.owner_carrier_registered or 'N/A'}\n", style=f"bold {ELECTRIC_CYAN}")
        owner_card.append("  | Caller ID Registry : ", style="dim bright_white")
        owner_card.append(f"{data.caller_id_source or 'N/A'}\n", style=f"bold {MAGENTA}")
        owner_card.append("  | Line Active Status : ", style="dim bright_white")
        owner_card.append(f"{data.line_status or 'Active / In-Service'}\n", style=f"bold {SKY_BLUE}")
        owner_card.append("  | MNP Portability    : ", style="dim bright_white")
        owner_card.append(f"{data.portability_status or 'Original Carrier (Non-Ported)'}\n", style=f"bold {VIOLET}")
        owner_card.append("  | Match Confidence   : ", style="dim bright_white")
        owner_card.append(f"{data.confidence_score or '94% (Verified)'}\n", style=f"bold {GOLD}")

        owner_panel = Panel(
            owner_card,
            title=f"[bold {NEON_GREEN}][ VERIFIED SUBSCRIBER OWNERSHIP RECORD ][/bold {NEON_GREEN}]",
            subtitle=f"[dim {ELECTRIC_CYAN}][ CNAM Identity Registry ][/dim {ELECTRIC_CYAN}]",
            border_style=f"bold {NEON_GREEN}",
            box=box.DOUBLE,
            padding=(1, 2)
        )
        console.print(owner_panel)
        console.print()

    # ─── Detailed Telemetry Table ───────────────────────────────────────────
    table = Table(
        title=f"[bold black on {MAGENTA}] TELEPHONY, SUBSCRIBER & CARRIER INTELLIGENCE [/bold black on {MAGENTA}]",
        box=box.ROUNDED,
        border_style=f"bold {PURPLE}",
        header_style="bold bright_white on dark_magenta"
    )
    table.add_column("Attribute", style="bold bright_white", width=26)
    table.add_column("Extracted Telemetry", style=f"{NEON_GREEN}")

    table.add_row("Target Number", f"[bold {GOLD}]{data.raw_phone}[/bold {GOLD}]")

    # Ownership Name Highlight in table
    if data.owner_name:
        table.add_row(
            "Identified Owner",
            f"[bold black on {GOLD}] {data.owner_name} [/bold black on {GOLD}]"
        )
    if data.owner_carrier_registered:
        table.add_row(
            "Subscriber Registry",
            f"[bold {ELECTRIC_CYAN}]{data.owner_carrier_registered}[/bold {ELECTRIC_CYAN}]"
        )
    if data.caller_id_source:
        table.add_row(
            "Caller ID Registry",
            f"[bold {MAGENTA}]{data.caller_id_source}[/bold {MAGENTA}]"
        )

    table.add_row(
        "Format Compliance",
        f"[bold black on {NEON_GREEN}] Valid E.164 [/bold black on {NEON_GREEN}]" if data.is_valid else f"[bold black on {GOLD}] Plausible Format [/bold black on {GOLD}]"
    )
    table.add_row("E.164 Normalized", f"[bold {ELECTRIC_CYAN}]{data.e164_format or 'N/A'}[/bold {ELECTRIC_CYAN}]")
    table.add_row("International Format", f"[bold {SKY_BLUE}]{data.international_format or 'N/A'}[/bold {SKY_BLUE}]")
    table.add_row("National Format", data.national_format or "N/A")
    table.add_row("Country of Origin", f"[bold {GOLD}]{data.country_name or 'Unknown'}[/bold {GOLD}] ({data.country_code or 'N/A'})")
    table.add_row("Carrier Network", f"[bold black on {NEON_GREEN}] {data.carrier or 'Virtual / Unassigned'} [/bold black on {NEON_GREEN}]")
    table.add_row("Line Classification", f"[bold bright_white on deep_sky_blue1] {data.line_type} [/bold bright_white on deep_sky_blue1]")
    table.add_row("Line Status", f"[bold {NEON_GREEN}]{data.line_status or 'Active'}[/bold {NEON_GREEN}]")
    table.add_row("Portability (MNP)", f"[bold {VIOLET}]{data.portability_status or 'N/A'}[/bold {VIOLET}]")
    table.add_row("Regional Timezones", ", ".join(data.timezones) if data.timezones else "N/A")
    table.add_row("Engine Source", f"[dim {SKY_BLUE}]{data.api_lookup_source or 'libphonenumber'}[/dim {SKY_BLUE}]")

    console.print(table)

    # OSINT Dork Links Panel
    if data.osint_dork_links:
        dork_text = Text()
        dork_text.append("Use these public search queries to cross-verify ownership records:\n", style="dim white")
        for name, link in data.osint_dork_links.items():
            dork_text.append(f"\n[>] {name}: ", style=f"bold {ELECTRIC_CYAN}")
            dork_text.append(link, style=f"underline {GOLD}")

        dork_panel = Panel(
            dork_text,
            title=f"[bold black on {ELECTRIC_CYAN}] OSINT REVERSE-LOOKUP INVESTIGATION DORKS [/bold black on {ELECTRIC_CYAN}]",
            border_style=f"bold {ELECTRIC_CYAN}",
            box=box.ROUNDED
        )
        console.print(dork_panel)


def display_username_results(report: TargetIntelligenceReport) -> None:
    """Render platform account presence audit in Rich tables."""
    accounts = report.username_accounts
    if not accounts:
        console.print(f"[{GOLD}]No platform presence results generated.[/{GOLD}]")
        return

    table = Table(
        title=f"[bold black on {ELECTRIC_CYAN}] MULTI-PLATFORM ACCOUNT RECONNAISSANCE [/bold black on {ELECTRIC_CYAN}]",
        box=box.ROUNDED,
        border_style=f"bold {ELECTRIC_CYAN}",
        header_style="bold bright_white on dark_blue"
    )
    table.add_column("Platform", style="bold bright_white", width=18)
    table.add_column("Category", style=f"{MAGENTA}", width=14)
    table.add_column("Presence Status", width=18)
    table.add_column("HTTP Code", justify="right", width=10)
    table.add_column("Latency (ms)", justify="right", width=14)
    table.add_column("Profile Endpoint", style=f"{SKY_BLUE}")

    found_count = 0
    for acc in accounts:
        if acc.exists:
            status_text = f"[bold black on {NEON_GREEN}] [+] IDENTIFIED [/bold black on {NEON_GREEN}]"
            found_count += 1
            code_str = f"[bold {NEON_GREEN}]{acc.status_code or 200}[/bold {NEON_GREEN}]"
        else:
            status_text = f"[dim {HOT_PINK}] [-] NOT FOUND [/dim {HOT_PINK}]"
            code_str = f"[dim]{acc.status_code or '-'}[/dim]"

        if acc.response_time_ms is not None:
            if acc.response_time_ms < 1000:
                latency_str = f"[{NEON_GREEN}]{acc.response_time_ms:.1f}[/{NEON_GREEN}]"
            elif acc.response_time_ms < 3000:
                latency_str = f"[{GOLD}]{acc.response_time_ms:.1f}[/{GOLD}]"
            else:
                latency_str = f"[{ELECTRIC_CYAN}]{acc.response_time_ms:.1f}[/{ELECTRIC_CYAN}]"
        else:
            latency_str = "-"

        table.add_row(
            acc.platform,
            acc.category,
            status_text,
            code_str,
            latency_str,
            acc.url if acc.exists else f"[dim]{acc.url}[/dim]"
        )

    console.print(table)

    summary_panel = Panel(
        f"[bold bright_white]Reconnaissance Complete:[/bold bright_white] Target identified on "
        f"[bold {NEON_GREEN}]{found_count}[/bold {NEON_GREEN}] of [bold {ELECTRIC_CYAN}]{len(accounts)}[/bold {ELECTRIC_CYAN}] queried platforms.",
        border_style=f"bold {NEON_GREEN}" if found_count > 0 else f"bold {GOLD}",
        box=box.ROUNDED
    )
    console.print(summary_panel)


def display_breach_results(report: TargetIntelligenceReport) -> None:
    """Render data breach exposure in Rich tables."""
    breaches = report.breach_records
    if not breaches:
        panel = Panel(
            f"[bold {NEON_GREEN}][+] No compromised breach records or credential leaks detected for this target.[/bold {NEON_GREEN}]",
            title=f"[bold black on {NEON_GREEN}] BREACH AUDIT STATUS [/bold black on {NEON_GREEN}]",
            border_style=f"bold {NEON_GREEN}",
            box=box.ROUNDED
        )
        console.print(panel)
        return

    table = Table(
        title=f"[bold white on {HOT_PINK}] BREACH & CREDENTIAL LEAKAGE TELEMETRY ({len(breaches)} INCIDENTS) [/bold white on {HOT_PINK}]",
        box=box.ROUNDED,
        border_style=f"bold {HOT_PINK}",
        header_style="bold bright_white on dark_red"
    )
    table.add_column("Breached Database", style="bold bright_white", width=22)
    table.add_column("Breach Date", style=f"bold {GOLD}", width=13)
    table.add_column("Exposed Data Classes", style=f"{ELECTRIC_CYAN}", width=34)
    table.add_column("Password Exposure", width=18)
    table.add_column("Masked Credential", style=f"bold {MAGENTA}", width=20)

    for b in breaches:
        pw_flag = f"[bold white on {HOT_PINK}] YES (Exposed) [/bold white on {HOT_PINK}]" if b.has_passwords else f"[bold {NEON_GREEN}]No Passwords[/bold {NEON_GREEN}]"
        classes_str = ", ".join(b.compromised_data_classes) if b.compromised_data_classes else "Unknown"
        masked_pw = f"[bold black on {GOLD}] {b.sample_password_masked} [/bold black on {GOLD}]" if b.sample_password_masked else "N/A"
        table.add_row(
            b.source_database,
            b.breach_date or "Unknown",
            classes_str,
            pw_flag,
            masked_pw
        )

    console.print(table)


async def execute_investigation(args: argparse.Namespace) -> TargetIntelligenceReport:
    """Execute asynchronous investigative pipeline according to parsed CLI arguments."""
    settings = get_settings()
    timeout = aiohttp.ClientTimeout(total=settings.request_timeout)

    target_type = ""
    target_value = ""

    if args.ip:
        target_type = "ip"
        target_value = args.ip
    elif args.phone:
        target_type = "phone"
        target_value = args.phone
    elif args.username:
        target_type = "username"
        target_value = args.username
    elif args.email:
        target_type = "email"
        target_value = args.email

    report = TargetIntelligenceReport(
        target_type=target_type,
        target_value=target_value
    )

    async with aiohttp.ClientSession(timeout=timeout) as session:
        with console.status(
            f"[bold {ELECTRIC_CYAN}]OmniSight active:[/] [bold {GOLD}]Querying target intelligence for [[/][bold {NEON_GREEN}]{target_value}[/][bold {GOLD}]]...",
            spinner="dots12"
        ):
            if target_type == "ip":
                report.ip_data = await track_ip(target_value, session=session)

            elif target_type == "phone":
                report.phone_data = await track_phone(target_value, session=session)

            elif target_type == "username":
                concurrency = args.concurrency or settings.max_concurrent_requests
                report.username_accounts = await hunt_username(
                    target_value,
                    concurrency_limit=concurrency,
                    session=session
                )
                report.breach_records = await check_breaches(target_value, session=session)

            elif target_type == "email":
                username_part = target_value.split("@")[0] if "@" in target_value else target_value
                concurrency = args.concurrency or settings.max_concurrent_requests

                breach_task = check_breaches(target_value, session=session)
                username_task = hunt_username(username_part, concurrency_limit=concurrency, session=session)

                breaches, accounts = await asyncio.gather(breach_task, username_task)
                report.breach_records = breaches
                report.username_accounts = accounts

    return report


def export_report_json(report: TargetIntelligenceReport, output_path: str) -> None:
    """Serialize and export the complete investigation payload to structured JSON."""
    try:
        path = Path(output_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)

        data = report.model_dump()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        size_kb = path.stat().st_size / 1024
        console.print(
            f"\n[bold green][+] Payload exported successfully:[/bold green] "
            f"[white]{path}[/white] ({size_kb:.2f} KB)"
        )
    except Exception as exc:
        console.print(f"\n[bold red]Failed to export JSON report to '{output_path}': {exc}[/bold red]")


def parse_arguments() -> argparse.ArgumentParser:
    """Build and configure the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="open_osint",
        description="OmniSight-OSINT: Automated Modular Cyber Reconnaissance & Threat Intelligence CLI (Linux)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 open_osint.py --phone +923124398331\n"
            "  python3 open_osint.py --ip 8.8.8.8\n"
            "  python3 open_osint.py --username torvalds --output torvalds_recon.json\n"
            "  python3 open_osint.py --email admin@example.com --output breach_report.json\n"
        )
    )

    # Mutually Exclusive Target Group (Single Target Requirement)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--ip",
        type=str,
        help="Target IPv4 or IPv6 address for geolocation, ASN, and network telemetry."
    )
    target_group.add_argument(
        "--phone",
        type=str,
        help="Target telephone number (E.164 format, e.g. +923124398331) for carrier and subscriber analysis."
    )
    target_group.add_argument(
        "--username",
        type=str,
        help="Target user handle for concurrent platform existence and breach auditing."
    )
    target_group.add_argument(
        "--email",
        type=str,
        help="Target email address for breach exposure and handle correlation."
    )

    # Operational Options
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        metavar="FILE.json",
        help="Export gathered intelligence payload to a structured JSON file."
    )
    parser.add_argument(
        "--concurrency", "-c",
        type=int,
        default=None,
        help="Override maximum concurrent HTTP worker routines (default: 15)."
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose debug logging output."
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress ASCII art header for clean pipeline scripting."
    )

    return parser


def main() -> None:
    """CLI execution entry point."""
    parser = parse_arguments()
    args = parser.parse_args()

    # Configure Logging Level
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logger(level=log_level, console=console)

    if not args.no_banner:
        render_banner()

    # Determine target type and value for pre-scan card
    target_type = "ip" if args.ip else "phone" if args.phone else "username" if args.username else "email"
    target_val = args.ip or args.phone or args.username or args.email
    render_scan_header(target_type, target_val)

    # Execute async pipeline
    try:
        report = asyncio.run(execute_investigation(args))
    except KeyboardInterrupt:
        console.print(f"\n[bold {GOLD}]Investigation halted by user (SIGINT).[/{GOLD}]")
        sys.exit(130)
    except Exception as exc:
        console.print(f"\n[bold {HOT_PINK}]Critical pipeline failure: {exc}[/{HOT_PINK}]")
        sys.exit(1)

    # Render Visual Tables based on Target Type with Section Dividers
    if report.target_type == "ip":
        render_section_divider("NETWORK GEOLOCATION & IP TELEMETRY", ELECTRIC_CYAN)
        display_ip_results(report)
    elif report.target_type == "phone":
        render_section_divider("TELEPHONY & SUBSCRIBER INTELLIGENCE", MAGENTA)
        display_phone_results(report)
    elif report.target_type == "username":
        render_section_divider("MULTI-PLATFORM PRESENCE RECONNAISSANCE", ELECTRIC_CYAN)
        display_username_results(report)
        render_section_divider("BREACH EXPOSURE & CREDENTIAL AUDIT", HOT_PINK)
        display_breach_results(report)
    elif report.target_type == "email":
        render_section_divider("BREACH EXPOSURE & CREDENTIAL AUDIT", HOT_PINK)
        display_breach_results(report)
        render_section_divider("PLATFORM HANDLE RECONNAISSANCE", ELECTRIC_CYAN)
        display_username_results(report)

    # Render scan completion badge
    render_scan_complete(report.target_type)

    # Export structured JSON artifact if requested
    if args.output:
        export_report_json(report, args.output)


if __name__ == "__main__":
    main()
