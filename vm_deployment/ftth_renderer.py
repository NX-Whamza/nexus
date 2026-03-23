from pathlib import Path
import ipaddress
import os
import re
import hashlib
from datetime import datetime

try:
    from engineering_compliance import load_compliance_text
except ImportError:
    from vm_deployment.engineering_compliance import load_compliance_text

TEMPLATE_PATH = Path(__file__).parent / "ftth_template.rsc"

# ---------------------------------------------------------------------------
# GitLab dynamic compliance loader (optional — falls back gracefully)
# ---------------------------------------------------------------------------
try:
    from gitlab_compliance import get_loader as _get_gitlab_loader
    _FTTH_HAS_GITLAB = True
except ImportError:
    try:
        from vm_deployment.gitlab_compliance import get_loader as _get_gitlab_loader
        _FTTH_HAS_GITLAB = True
    except ImportError:
        _FTTH_HAS_GITLAB = False
        _get_gitlab_loader = None  # type: ignore[assignment]

try:
    from nextlink_compliance_reference import get_all_compliance_blocks as _get_compliance_blocks
    _FTTH_HAS_COMPLIANCE_REF = True
except ImportError:
    try:
        from vm_deployment.nextlink_compliance_reference import get_all_compliance_blocks as _get_compliance_blocks
        _FTTH_HAS_COMPLIANCE_REF = True
    except ImportError:
        _FTTH_HAS_COMPLIANCE_REF = False
        _get_compliance_blocks = None  # type: ignore[assignment]

# All template placeholder keys used in render_ftth_config().
# Compiled once at module load for single-pass re.sub() substitution.
_FTTH_TEMPLATE_KEYS = (
    "{{BRIDGE_LINES}}",
    "{{VPLS_LINES}}",
    "{{UPLINK_ETHERNET_LINES}}",
    "{{OLT_ETHERNET_LINES}}",
    "{{UPLINK_PRIMARY_PORT}}",
    "{{UPLINK_PRIMARY_MTU}}",
    "{{OLT1_TAG}}",
    "{{OLT1_BONDING_LINE}}",
    "{{OLT1_VLAN_LINES}}",
    "{{OLT1_BRIDGE_PORTS}}",
    "{{OLT1_IP_LINE}}",
    "{{OLT1_OSPF_LINE}}",
    "{{OLT2_BONDING_LINE}}",
    "{{OLT2_VLAN_LINES}}",
    "{{OLT2_BRIDGE_PORTS}}",
    "{{OLT2_IP_LINE}}",
    "{{OLT2_OSPF_LINE}}",
    "{{CGNAT_POOL_START}}",
    "{{CGNAT_POOL_END}}",
    "{{CPE_POOL_START}}",
    "{{CPE_POOL_END}}",
    "{{UNAUTH_POOL_START}}",
    "{{UNAUTH_POOL_END}}",
    "{{ROUTER_ID}}",
    "{{OSPF_AREA_NAME}}",
    "{{OSPF_AREA_ID}}",
    "{{CPE_GATEWAY}}",
    "{{CPE_PREFIX}}",
    "{{CPE_NETWORK_BASE}}",
    "{{LOOPBACK_IP}}",
    "{{UNAUTH_GATEWAY}}",
    "{{UNAUTH_PREFIX}}",
    "{{UNAUTH_NETWORK_BASE}}",
    "{{CGNAT_GATEWAY}}",
    "{{CGNAT_PREFIX}}",
    "{{CGNAT_NETWORK_BASE}}",
    "{{OLT1_IP}}",
    "{{OLT1_PREFIX}}",
    "{{OLT1_NETWORK_BASE}}",
    "{{CGNAT_PUBLIC}}",
    "{{UPLINK_IP_LINES}}",
    "{{UPLINK_OSPF_LINES}}",
    "{{UPLINK_LDP_LINES}}",
    "{{MPLS_ACCEPT_FILTERS}}",
    "{{MPLS_ADVERTISE_FILTERS}}",
    "{{OLT1_NAME}}",
    "{{ROUTER_IDENTITY}}",
    "{{LOCATION}}",
    "{{SNMP_CONTACT}}",
    "{{GENERATED_AT}}",
    "{{BGP_INSTANCE_BLOCK}}",
    "{{BGP_TEMPLATE_LINE}}",
    "{{BGP_CONNECTION_LINES}}",
    "{{USER_ROOT_PASSWORD}}",
    "{{USER_DEPLOYMENT_PASSWORD}}",
    "{{USER_INFRA_PASSWORD}}",
    "{{USER_IDO_PASSWORD}}",
    "{{USER_STS_PASSWORD}}",
    "{{USER_ENG_PASSWORD}}",
    "{{USER_NOC_PASSWORD}}",
    "{{USER_COMENG_PASSWORD}}",
    "{{USER_DEVOPS_PASSWORD}}",
    "{{USER_ACQ_PASSWORD}}",
    "{{USER_ADMIN_PASSWORD}}",
)


def _append_ftth_speed_parts(parts: list[str], speed: str | None, auto_neg: bool = False) -> None:
    """Render FTTH ethernet speed settings consistently.

    Auto speed should not emit `auto-negotiation=no`. Forced speeds should.
    """
    speed_value = (speed or "").strip()
    if not speed_value or speed_value.lower() == "auto":
        parts.append("auto-negotiation=yes")
        return
    if auto_neg:
        parts.append("auto-negotiation=yes")
        return
    parts.append("auto-negotiation=no")
    parts.append(f"speed={speed_value}")
# All keys use {{UPPER_SNAKE_CASE}} — no regex metacharacters.
_FTTH_TEMPLATE_RE = re.compile("|".join(re.escape(k) for k in _FTTH_TEMPLATE_KEYS))

MPLS_ACCEPT_FILTERS = [
    "add accept=no disabled=no prefix=10.2.0.14/32",
    "add accept=no disabled=no prefix=10.2.0.21/32",
    "add accept=no disabled=no prefix=10.2.0.107/32",
    "add accept=no disabled=no prefix=10.2.0.108/32",
    "add accept=no disabled=no prefix=10.17.0.10/32",
    "add accept=no disabled=no prefix=10.17.0.11/32",
    "add accept=no disabled=no prefix=10.30.0.9/32",
    "add accept=no disabled=no prefix=10.240.0.3/32",
    "add accept=no disabled=no prefix=10.243.0.9/32",
    "add accept=no disabled=no prefix=10.248.0.220/32",
    "add accept=no disabled=no prefix=10.249.0.220/32",
    "add accept=no disabled=no prefix=10.0.0.87/32",
    "add accept=no disabled=no prefix=10.9.0.88/32",
    "add accept=no disabled=no prefix=10.254.247.9/32",
    "add accept=yes disabled=no prefix=10.2.0.10/32",
    "add accept=yes disabled=no prefix=10.0.0.0/24",
    "add accept=yes disabled=no prefix=10.0.1.0/24",
    "add accept=yes disabled=no prefix=10.1.0.0/24",
    "add accept=yes disabled=no prefix=10.2.0.0/24",
    "add accept=yes disabled=no prefix=10.3.0.0/24",
    "add accept=yes disabled=no prefix=10.4.0.0/24",
    "add accept=yes disabled=no prefix=10.4.3.0/24",
    "add accept=yes disabled=no prefix=10.5.0.0/24",
    "add accept=yes disabled=no prefix=10.6.0.0/24",
    "add accept=yes disabled=no prefix=10.7.0.0/24",
    "add accept=yes disabled=no prefix=10.7.250.0/24",
    "add accept=yes disabled=no prefix=10.7.254.0/24",
    "add accept=yes disabled=no prefix=10.8.0.0/24",
    "add accept=yes disabled=no prefix=10.9.0.0/24",
    "add accept=yes disabled=no prefix=10.9.1.0/24",
    "add accept=yes disabled=no prefix=10.9.2.0/24",
    "add accept=yes disabled=no prefix=10.10.0.0/24",
    "add accept=yes disabled=no prefix=10.11.0.0/24",
    "add accept=yes disabled=no prefix=10.12.0.0/24",
    "add accept=yes disabled=no prefix=10.2.0.0/24",
    "add accept=yes disabled=no prefix=10.13.0.0/24",
    "add accept=yes disabled=no prefix=10.14.0.0/24",
    "add accept=yes disabled=no prefix=10.15.0.0/24",
    "add accept=yes disabled=no prefix=10.16.0.0/24",
    "add accept=yes disabled=no prefix=10.17.0.0/24",
    "add accept=yes disabled=no prefix=10.17.16.0/24",
    "add accept=yes disabled=no prefix=10.17.18.0/24",
    "add accept=yes disabled=no prefix=10.17.31.0/24",
    "add accept=yes disabled=no prefix=10.17.48.0/24",
    "add accept=yes disabled=no prefix=10.18.0.0/24",
    "add accept=yes disabled=no prefix=10.18.2.0/24",
    "add accept=yes disabled=no prefix=10.19.0.0/24",
    "add accept=yes disabled=no prefix=10.21.0.0/24",
    "add accept=yes disabled=no prefix=10.22.0.0/24",
    "add accept=yes disabled=no prefix=10.25.0.0/24",
    "add accept=yes disabled=no prefix=10.26.0.0/24",
    "add accept=yes disabled=no prefix=10.27.0.0/24",
    "add accept=yes disabled=no prefix=10.30.0.0/24",
    "add accept=yes disabled=no prefix=10.3.0.0/24",
    "add accept=yes disabled=no prefix=10.32.0.0/24",
    "add accept=yes disabled=no prefix=10.33.0.0/24",
    "add accept=yes disabled=no prefix=10.34.0.0/24",
    "add accept=yes disabled=no prefix=10.35.0.0/24",
    "add accept=yes disabled=no prefix=10.36.0.0/24",
    "add accept=yes disabled=no prefix=10.37.0.0/24",
    "add accept=yes disabled=no prefix=10.39.0.0/24",
    "add accept=yes disabled=no prefix=10.45.252.0/24",
    "add accept=yes disabled=no prefix=10.47.0.0/24",
    "add accept=yes disabled=no prefix=10.53.252.0/22",
    "add accept=yes disabled=no prefix=10.254.243.0/24",
    "add accept=yes disabled=no prefix=10.243.0.0/24",
    "add accept=yes disabled=no prefix=10.54.0.0/22",
    "add accept=yes disabled=no prefix=10.250.0.0/24",
    "add accept=yes disabled=no prefix=10.250.40.0/22",
    "add accept=yes disabled=no prefix=10.241.0.0/24",
    "add accept=yes disabled=no prefix=10.241.64.0/22",
    "add accept=yes disabled=no prefix=10.254.42.0/24",
    "add accept=yes disabled=no prefix=10.254.245.0/24",
    "add accept=yes disabled=no prefix=10.42.0.0/24",
    "add accept=yes disabled=no prefix=10.42.12.0/24",
    "add accept=yes disabled=no prefix=10.42.192.0/22",
    "add accept=yes disabled=no prefix=10.254.249.0/24",
    "add accept=yes disabled=no prefix=10.249.0.0/24",
    "add accept=yes disabled=no prefix=10.249.7.0/24",
    "add accept=yes disabled=no prefix=10.249.180.0/22",
    "add accept=yes disabled=no prefix=10.254.247.0/24",
    "add accept=yes disabled=no prefix=10.247.0.0/24",
    "add accept=yes disabled=no prefix=10.247.13.0/24",
    "add accept=yes disabled=no prefix=10.247.72.0/24",
    "add accept=yes disabled=no prefix=10.247.147.0/24",
    "add accept=yes disabled=no prefix=10.247.187.0/24",
    "add accept=yes disabled=no prefix=10.247.64.0/22",
    "add accept=yes disabled=no prefix=10.254.248.0/24",
    "add accept=yes disabled=no prefix=10.248.0.0/24",
    "add accept=yes disabled=no prefix=10.248.32.0/24",
    "add accept=yes disabled=no prefix=10.248.36.0/24",
    "add accept=yes disabled=no prefix=10.248.86.0/24",
    "add accept=yes disabled=no prefix=10.248.208.0/22",
    "add accept=no disabled=no prefix=0.0.0.0/0",
]

# ---------------------------------------------------------------------------
# FTTH Compliance Integration — GitLab single source of truth
# ---------------------------------------------------------------------------

# Compliance block keys to include in the FTTH overlay.
# Keys from GitLab parser are listed; missing keys are silently skipped.
# Excluded:  user_aaa / user_profiles — FTTH uses use-radius=yes (compliance sets use-radius=no)
#            user_groups     — FTTH has specific groups (ENG, NOC, LTE, …)
#            firewall_mangle — compliance only removes; FTTH has its own QoS/TOS marking
#            dhcp_options    — FTTH has its own DHCP option 43
#            radius          — FTTH has its own RADIUS config (GitLab combines radius+ldp_filters)
#            vpls_edge       — FTTH manages its own bridge/VPLS ports
_FTTH_COMPLIANCE_BLOCKS = [
    "variables",
    "ip_services",
    "dns",
    "firewall_address_lists",
    "firewall_filter_input",
    "firewall_raw",
    "firewall_forward",
    "firewall_mangle",
    "firewall_nat",
    "sip_alg_off",
    "clock_ntp",
    "snmp",
    "user_aaa",
    "user_profiles",
    "users",
    "dhcp_options",
    "radius",
    "auto_upgrade",
    "system_settings",
    "web_proxy_off",
    "vpls_edge_ports",
    "logging",
    "ldp_filters",
    "watchdog_timer",
    "sys_note",
]

# RouterOS section headers to strip from the rendered config when GitLab
# compliance data replaces them.
_FTTH_COMPLIANCE_STRIP_SECTIONS = [
    "/snmp community",
    "/system logging action",
    "/ip firewall filter",
    "/ip firewall mangle",
    "/ip firewall nat",
    "/ip firewall raw",
    "/ip firewall service-port",
    "/ip service",
    "/user aaa",
    "/user group",
    "/user",
    "/radius",
    "/ip dhcp-server option",
    "/ip dhcp-server option sets",
    "/system note",
    "/system clock",
    "/system logging",
    "/system ntp client servers",
    "/system ntp client",
    "/system routerboard settings",
    "/ip dns",
    "/mpls ldp accept-filter",
    "/mpls ldp advertise-filter",
]

# Address-list names that are compliance-owned (will be replaced by GitLab data).
# FTTH-specific lists (NAT-EXEMPT-DST, NETFLIX, Voip-Servers, bgp-networks,
# WALLED-GARDEN) are kept.
_COMPLIANCE_ADDRESS_LIST_NAMES = {"EOIP-ALLOW", "managerIP", "BGP-ALLOW", "SNMP", "WALLED-GARDEN"}

# FTTH-specific forward chain rules to inject into the compliance forward block.
# These protect the FTTH BNG topology and must be ordered before the unauth
# drop / fasttrack rules.
_FTTH_EXTRA_FORWARD_RULES = [
    'add action=accept chain=forward comment="NTP Allow" dst-address=10.0.0.1 dst-port=123 in-interface=lan-bridge protocol=udp',
    'add action=drop chain=forward comment="Traceroute Drop" out-interface=lan-bridge protocol=icmp src-address=10.0.0.0/8',
    'add action=drop chain=forward comment="Private Space Protect" dst-address=10.0.0.0/8 in-interface=lan-bridge',
]


def _fetch_compliance_blocks(loopback_ip: str) -> dict | None:
    """Fetch compliance blocks from GitLab (single source of truth).

    Returns a dict keyed by COMPLIANCE_ORDER names, or None if unavailable.
    No hardcoded fallback — GitLab is the only source.
    """
    # 1. GitLab dynamic compliance (preferred — direct loader)
    if _FTTH_HAS_GITLAB and _get_gitlab_loader is not None:
        try:
            loader = _get_gitlab_loader()
            if loader.is_configured():
                blocks = loader.get_compliance_blocks_from_script(loopback_ip=loopback_ip)
                if blocks:
                    print(f"[FTTH-COMPLIANCE] Loaded {len(blocks)} blocks from GitLab")
                    return blocks
        except Exception as exc:
            print(f"[FTTH-COMPLIANCE] GitLab loader error: {exc}")

    # 2. Via get_all_compliance_blocks (also GitLab-only, no hardcoded fallback)
    if _FTTH_HAS_COMPLIANCE_REF and _get_compliance_blocks is not None:
        try:
            blocks = _get_compliance_blocks(loopback_ip)
            if blocks:
                print(f"[FTTH-COMPLIANCE] Loaded {len(blocks)} blocks via compliance reference (GitLab)")
                return blocks
        except Exception as exc:
            print(f"[FTTH-COMPLIANCE] Compliance reference error: {exc}")

    print("[FTTH-COMPLIANCE] WARNING: No compliance source available — GitLab is the only source")
    return None


def _inject_ftth_forward_rules(forward_block: str) -> str:
    """Inject FTTH-specific forward rules into the compliance forward block.

    Inserts NTP Allow, Traceroute Drop, and Private Space Protect rules
    before the unauth drop / fasttrack rules to ensure correct rule ordering.
    """
    lines = forward_block.splitlines()
    insertion_idx = None
    existing = [line.strip() for line in lines if line.strip()]
    def _norm_forward_line(line: str) -> str:
        return line.replace("/ip firewall filter ", "", 1).strip()
    existing_norm = {_norm_forward_line(line) for line in existing}
    missing_rules = [rule for rule in _FTTH_EXTRA_FORWARD_RULES if _norm_forward_line(rule) not in existing_norm]
    if not missing_rules:
        return forward_block
    for i, line in enumerate(lines):
        lower = line.strip().lower()
        if 'unauth drop' in lower or 'dst-address-list=!walled-garden' in lower.replace(' ', ''):
            insertion_idx = i
            break

    if insertion_idx is not None:
        for j, rule in enumerate(missing_rules):
            lines.insert(insertion_idx + j, rule)
    else:
        # No unauth drop found — append before the last few rules
        lines.extend(missing_rules)

    return "\n".join(lines)


def _build_ftth_compliance_overlay(loopback_ip: str, blocks: dict) -> str:
    """Build the FTTH compliance overlay text from compliance blocks.

    Assembles only the blocks appropriate for FTTH BNG configs, in the
    correct order, and injects FTTH-specific firewall forward rules.
    """
    sections: list[str] = [
        "",
        "# " + "=" * 50,
        "# ENGINEERING COMPLIANCE (dynamic — GitLab-first)",
        "# " + "=" * 50,
        "# ENGINEERING-COMPLIANCE-APPLIED",
    ]
    for key in _FTTH_COMPLIANCE_BLOCKS:
        value = blocks.get(key)
        if not value:
            continue
        # Inject FTTH-specific forward rules into the forward block
        if key == "firewall_forward":
            value = _inject_ftth_forward_rules(value)
        sections.append(f"\n# {key.upper().replace('_', ' ')}")
        sections.append(value.strip())

    if len(sections) <= 4:
        # Only headers, no actual blocks
        return ""

    return "\n".join(sections).strip()


def _strip_compliance_address_lists(config: str) -> str:
    """Remove compliance-owned address-list entries; keep FTTH-specific ones."""
    lines = config.splitlines()
    out = []
    in_address_list_section = False
    for line in lines:
        stripped = line.strip()
        # Track when we enter/leave the address-list section
        if stripped == "/ip firewall address-list":
            in_address_list_section = True
            out.append(line)
            continue
        if stripped.startswith("/") and stripped != "/ip firewall address-list":
            in_address_list_section = False

        if in_address_list_section and stripped.startswith("add address=") and "list=" in stripped:
            match = re.search(r'list=(\S+)', stripped)
            if match and match.group(1) in _COMPLIANCE_ADDRESS_LIST_NAMES:
                continue  # Drop compliance-owned entry
        out.append(line)
    return "\n".join(out)


def _inject_ftth_forward_into_raw(raw_text: str) -> str:
    """Inject FTTH-specific forward rules into verbatim raw compliance text.

    Finds the forward chain section and inserts the FTTH rules before the
    unauth-drop / fasttrack rules (same ordering as the parsed-blocks path).
    If the forward section isn't found, the FTTH rules are appended at the end.
    """
    lines = raw_text.splitlines()
    # Normalise for comparison
    def _norm(s: str) -> str:
        return s.replace("/ip firewall filter ", "", 1).strip()
    existing_norm = {_norm(l) for l in lines if l.strip()}
    missing = [r for r in _FTTH_EXTRA_FORWARD_RULES if _norm(r) not in existing_norm]
    if not missing:
        return raw_text

    # Find insertion point — just before "unauth drop" / fasttrack in forward chain
    insert_idx = None
    for i, line in enumerate(lines):
        low = line.strip().lower()
        if 'unauth drop' in low or 'dst-address-list=!walled-garden' in low.replace(' ', ''):
            insert_idx = i
            break
    if insert_idx is not None:
        for j, rule in enumerate(missing):
            lines.insert(insert_idx + j, rule)
    else:
        lines.extend(missing)

    return "\n".join(lines)


def _apply_ftth_compliance(config: str, loopback_ip: str) -> str:
    """Apply GitLab-sourced compliance overlay to the rendered FTTH config.

    Verbatim-first approach:
      1.  Try to fetch the raw TX-ARv2.rsc text from GitLab.
      2.  Inject FTTH-specific forward rules into the raw text.
      3.  Strip hardcoded compliance sections from the rendered config.
      4.  Strip compliance-owned address-list entries.
      5.  Append the raw text as a verbatim compliance overlay.

    Parsed-blocks fallback (when GitLab raw text is unavailable):
      Uses the existing parsed-blocks path with block selection.

    If GitLab-derived compliance data is unavailable, fall back to the local
    engineering compliance template so FTTH output still carries the baseline
    compliance marker and system-note footer expected by the UI.
    """
    # ── Verbatim raw text (preferred) ───────────────────────────────
    if _FTTH_HAS_GITLAB and _get_gitlab_loader is not None:
        try:
            loader = _get_gitlab_loader()
            if loader.is_configured():
                bare_ip = loopback_ip.split("/")[0] if "/" in loopback_ip else loopback_ip
                raw = loader.get_raw_compliance_text(loopback_ip=bare_ip)
                if raw:
                    # Inject FTTH-specific forward rules
                    raw = _inject_ftth_forward_into_raw(raw)
                    # Strip hardcoded sections from rendered config
                    result = _strip_named_sections(config, _FTTH_COMPLIANCE_STRIP_SECTIONS)
                    result = _strip_compliance_address_lists(result)
                    banner = (
                        "\n\n# " + "=" * 50 + "\n"
                        "# ENGINEERING COMPLIANCE (verbatim from GitLab TX-ARv2.rsc)\n"
                        "# " + "=" * 50 + "\n"
                        "# ENGINEERING-COMPLIANCE-APPLIED\n\n"
                    )
                    print(f"[FTTH-COMPLIANCE] Applied verbatim GitLab compliance ({len(raw)} chars)")
                    return result.rstrip() + banner + raw + "\n"
        except Exception as exc:
            print(f"[FTTH-COMPLIANCE] Raw text error, falling back to parsed blocks: {exc}")

    # ── Parsed blocks fallback ──────────────────────────────────────
    blocks = _fetch_compliance_blocks(loopback_ip)

    # Strip hardcoded compliance sections
    result = _strip_named_sections(config, _FTTH_COMPLIANCE_STRIP_SECTIONS)

    # Strip compliance-owned address-list entries
    result = _strip_compliance_address_lists(result)

    # Build and append the compliance overlay
    overlay = _build_ftth_compliance_overlay(loopback_ip, blocks) if blocks else ""
    if overlay:
        return result.rstrip() + "\n\n" + overlay + "\n"

    bare_ip = loopback_ip.split("/")[0] if "/" in loopback_ip else loopback_ip
    fallback_text = load_compliance_text(bare_ip).strip()
    if fallback_text:
        fallback_overlay = (
            "\n\n# " + "=" * 50 + "\n"
            "# ENGINEERING COMPLIANCE (fallback template)\n"
            "# " + "=" * 50 + "\n"
            "# ENGINEERING-COMPLIANCE-APPLIED\n\n"
            + fallback_text
            + "\n"
        )
        return result.rstrip() + fallback_overlay

    return result


def _sanitize_tag(value: str, default: str) -> str:
    raw = (value or '').strip()
    if not raw:
        return default
    tag = re.sub(r'[^A-Za-z0-9]+', '-', raw).strip('-').upper()
    return tag or default


def _group_tag_from_name(name: str, fallback: str) -> str:
    upper = (name or '').upper()
    if 'MF2-1' in upper:
        return 'MF2-1'
    if 'MF2-2' in upper:
        return 'MF2-2'
    return fallback


def _fmt_comment(value: str) -> str:
    if value is None:
        return ''
    val = str(value)
    if ' ' in val or '"' in val:
        val = val.replace('"', '')
        return f"\"{val}\""
    return val


def _ftth_quote(value: str) -> str:
    if value is None:
        return "\"\""
    return "\"" + str(value).replace("\"", "") + "\""


def _ftth_user_passwords():
    return {
        'root': os.getenv('FTTH_USER_ROOT_PASSWORD', 'CHANGE_ME'),
        'deployment': os.getenv('FTTH_USER_DEPLOYMENT_PASSWORD', 'CHANGE_ME'),
        'infra': os.getenv('FTTH_USER_INFRA_PASSWORD', 'CHANGE_ME'),
        'ido': os.getenv('FTTH_USER_IDO_PASSWORD', 'CHANGE_ME'),
        'sts': os.getenv('FTTH_USER_STS_PASSWORD', 'CHANGE_ME'),
        'eng': os.getenv('FTTH_USER_ENG_PASSWORD', 'CHANGE_ME'),
        'noc': os.getenv('FTTH_USER_NOC_PASSWORD', 'CHANGE_ME'),
        'comeng': os.getenv('FTTH_USER_COMENG_PASSWORD', 'CHANGE_ME'),
        'devops': os.getenv('FTTH_USER_DEVOPS_PASSWORD', 'CHANGE_ME'),
        'acq': os.getenv('FTTH_USER_ACQ_PASSWORD', 'CHANGE_ME'),
        'admin': os.getenv('FTTH_ADMIN_PASSWORD', 'CHANGE_ME'),
    }

def _stable_laa_mac(seed: str) -> str:
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    octets = [int(digest[i:i + 2], 16) for i in range(0, 12, 2)]
    # Locally administered unicast MAC.
    octets[0] = (octets[0] | 0x02) & 0xFE
    return ":".join(f"{b:02X}" for b in octets)


def _render_bridge_lines(is_outstate: bool) -> str:
    if is_outstate:
        return "\n".join([
            "add comment=DYNAMIC name=bridge1000 port-cost-mode=short protocol-mode=none",
            "add comment=STATIC name=bridge2000 port-cost-mode=short protocol-mode=none",
            "add comment=INFRA name=bridge3000 port-cost-mode=short protocol-mode=none",
            "add comment=CPE name=bridge4000 port-cost-mode=short protocol-mode=none",
            "add name=lan-bridge",
            "add comment=LOOPBACK name=loop0 port-cost-mode=short",
            "add name=nat-public-bridge",
        ])
    return "\n".join([
        "add name=bridge1000",
        "add name=bridge2000",
        "add name=bridge3000",
        "add name=bridge4000",
        "add name=lan-bridge",
        "add name=loop0",
        "add name=nat-public-bridge",
    ])


def _render_outstate_vpls_lines(
    *,
    enabled: bool,
    router_identity: str,
    state_id: str,
    bng1_ip: str,
    bng2_ip: str,
    pw_l2mtu: str,
) -> str:
    if not enabled:
        return ""
    sid = re.sub(r"[^0-9]", "", str(state_id or "")) or "249"
    services = [
        ("bridge1000", 1000, "DYNAMIC"),
        ("bridge2000", 2000, "STATIC"),
        ("bridge3000", 3000, "INFRA"),
        ("bridge4000", 4000, "CPE"),
    ]
    lines = []
    for bridge_name, base, _svc in services:
        cisco_id = f"{base // 1000}{sid}"
        for idx, peer in enumerate((bng1_ip, bng2_ip), start=1):
            vpls_name = f"vpls{base}-bng{idx}"
            mac = _stable_laa_mac(f"{router_identity}|{vpls_name}|{peer}|{cisco_id}")
            lines.append(
                "add arp=enabled "
                f"bridge={bridge_name} "
                "bridge-horizon=1 "
                f"cisco-static-id={cisco_id} "
                "disabled=no "
                f"mac-address={mac} "
                "mtu=1500 "
                f"name={vpls_name} "
                f"peer={peer} "
                "pw-control-word=disabled "
                f"pw-l2mtu={pw_l2mtu} "
                "pw-type=raw-ethernet"
            )
    return "\n".join(lines)


def _net_details(cidr: str):
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = list(net.hosts())
    if not hosts:
        raise ValueError(f'No usable hosts in {cidr}')
    return net, hosts[0], hosts[-1]


def _pool_range(net: ipaddress.IPv4Network, start_offset: int):
    start_ip = ipaddress.ip_address(int(net.network_address) + start_offset)
    end_ip = list(net.hosts())[-1]
    return str(start_ip), str(end_ip)


def _strip_ftth_headers(config: str) -> str:
    """Remove human-readable headers/metadata from generated FTTH output."""
    drop_prefixes = (
        "FTTH BNG Configuration - ",
        "Generated:",
        "Deployment Type:",
        "Device:",
        "Location:",
        "Total configuration lines:",
        "Deployment:",
        "Please review",
        "CONFIGURATION COMPLETE",
        "==========",
        "#==========",
        "# FTTH BNG Configuration",
    )
    cleaned = []
    for line in config.splitlines():
        stripped = line.strip()
        if stripped.startswith(drop_prefixes):
            continue
        # Drop banner lines like "======" or "#==========SECTION=========="
        if re.match(r"^#?=+.*=+$", stripped):
            continue
        cleaned.append(line)
    return "\n".join(cleaned).strip() + "\n"


def _normalize_ftth_output(config: str) -> str:
    """Normalize FTTH output to legacy RouterOS CLI section syntax."""
    # Normalize line endings first to make replacements reliable.
    normalized = config.replace("\r\n", "\n").replace("\r", "\n")
    replacements = [
        ("/interface/bridge/port", "/interface bridge port"),
        ("/interface/bridge", "/interface bridge"),
        ("/interface/ethernet", "/interface ethernet"),
        ("/interface/bonding", "/interface bonding"),
        ("/interface/vlan", "/interface vlan"),
        ("/ip/dhcp-server/network", "/ip dhcp-server network"),
        ("/ip/dhcp-server", "/ip dhcp-server"),
        ("/ip/firewall/address-list", "/ip firewall address-list"),
        ("/ip/firewall/nat", "/ip firewall nat"),
        ("/ip/firewall/filter", "/ip firewall filter"),
        ("/ip/firewall/mangle", "/ip firewall mangle"),
        ("/ip/firewall/raw", "/ip firewall raw"),
        ("/ip/firewall/service-port", "/ip firewall service-port"),
        ("/ip/address", "/ip address"),
        ("/ip/dns", "/ip dns"),
        ("/routing/ospf/interface-template", "/routing ospf interface-template"),
        ("/routing/ospf/area", "/routing ospf area"),
        ("/routing/ospf/instance", "/routing ospf instance"),
        ("/routing/bgp/connection", "/routing bgp connection"),
        ("/routing/bgp/template", "/routing bgp template"),
        ("/routing/bgp/instance", "/routing bgp instance"),
        ("/snmp/community", "/snmp community"),
        ("/system/ntp/client/servers", "/system ntp client servers"),
        ("/system/ntp/client", "/system ntp client"),
        ("/system/logging", "/system logging"),
        ("/system/identity", "/system identity"),
        ("/system/clock", "/system clock"),
        ("/system/note", "/system note"),
        ("/system/routerboard/settings", "/system routerboard settings"),
    ]

    for old, new in replacements:
        normalized = normalized.replace(old, new)
    return normalized


def _strip_named_sections(config: str, section_headers: list[str]) -> str:
    """Remove full RouterOS sections by header name."""
    lines = config.splitlines()
    remove_headers = {h.strip() for h in section_headers}
    out: list[str] = []
    i = 0
    total = len(lines)
    while i < total:
        current = lines[i].strip()
        if current in remove_headers:
            i += 1
            # Skip until next section header.
            while i < total and not lines[i].startswith("/"):
                i += 1
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out).strip() + "\n"


def _strip_outstate_subscriber_features(config: str) -> str:
    """Out-of-state profile should not include subscriber DHCP/CGNAT automation blocks."""
    section_headers = [
        "/ip dhcp-server option",
        "/ip dhcp-server option sets",
        "/ip pool",
        "/ip dhcp-server",
        "/ip dhcp-server network",
        "/ip firewall mangle",
        "/routing filter rule",
        "/system scheduler",
        "/system script",
    ]
    return _strip_named_sections(config, section_headers)


def _strip_matching_lines(config: str, predicates):
    out = []
    for line in config.splitlines():
        if any(pred(line) for pred in predicates):
            continue
        out.append(line)
    return "\n".join(out).strip() + "\n"


# Pure-substring predicates for out-of-state transport-only pruning.
# Extracted to module level so the tuple is created once, not on every call.
_OUTSTATE_SKIP_SUBSTRINGS = (
    "lan-bridge",
    "add name=lan-bridge",
    "add name=nat-public-bridge",
    "interface=lan-bridge",
    ' comment="CPE/Tower Gear"',
    ' comment="CGNAT Private"',
    ' comment="CGNAT Public"',
    "interface=bridge3000 network=",
    "interfaces=bridge3000 ",
    "src-address-list=unauth",
    "WALLED-GARDEN",
    "NAT-EXEMPT-DST",
    "Voip-Servers",
    "NETFLIX",
)


def _prune_outstate_transport_only(config: str) -> str:
    # Out-of-state should keep transport/routing only:
    # - no LAN bridge, no subscriber/NAT addressing
    # - IP addressing limited to loopback + routed backhaul uplinks
    def _should_skip(s: str) -> bool:
        if any(sub in s for sub in _OUTSTATE_SKIP_SUBSTRINGS):
            return True
        # Compound conditions that cannot be reduced to a single substring:
        if " comment=UNAUTH " in f" {s} ":  # word-boundary guard; must keep f-string form
            return True
        if " list=bgp-networks" in s and ("UNAUTH" in s or "CGNAT_" in s):
            return True
        if "dst-address=10.0.0.1" in s and "NTP Allow" in s:
            return True
        return False

    out = [line for line in config.splitlines() if not _should_skip(line)]
    return "\n".join(out).strip() + "\n"


def _dedupe_preserve_order(lines):
    seen = set()
    out = []
    for line in lines:
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


def _enforce_outstate_ospf_area(config: str, area_name: str, area_id: str) -> str:
    # Safety net: if an older template still has backbone-v2 hardcoded, rewrite it.
    cfg = config
    cfg = re.sub(
        r"(^\s*add\s+)(?!.*area-id=)(.*\binstance=default-v2\b.*\bname=)backbone-v2(\b.*)$",
        rf"\1area-id={area_id} \2{area_name}\3",
        cfg,
        flags=re.M,
    )
    cfg = re.sub(r"\barea=backbone-v2\b", f"area={area_name}", cfg)
    return cfg


OUTSTATE_STATE_PROFILES = {
    "IA": {"ospf_area": "42", "ospf_area_id": "0.0.0.42", "vpls_state_id": "245"},
    "NE": {"ospf_area": "249", "ospf_area_id": "0.0.0.249", "vpls_state_id": "249"},
    "KS": {"ospf_area": "248", "ospf_area_id": "0.0.0.248", "vpls_state_id": "248"},
    "LA": {"ospf_area": "250", "ospf_area_id": "0.0.0.250", "vpls_state_id": "250"},
    "IL": {"ospf_area": "0", "ospf_area_id": "0.0.0.0", "vpls_state_id": "247"},
}


def _resolve_outstate_profile(data: dict, loopback: ipaddress.IPv4Interface):
    state_code = str(data.get("state_code", "") or "").strip().upper()
    profile = OUTSTATE_STATE_PROFILES.get(state_code)
    if profile:
        return profile
    fallback_area = str(data.get("ospf_area") or str(loopback.ip).split(".")[1]).strip()
    fallback_state = str(data.get("vpls_state_id") or fallback_area).strip()
    return {
        "ospf_area": fallback_area,
        "ospf_area_id": f"0.0.0.{fallback_area}",
        "vpls_state_id": fallback_state,
    }


def render_ftth_config(data: dict) -> str:
    if not TEMPLATE_PATH.exists():
        raise FileNotFoundError(f"FTTH template missing: {TEMPLATE_PATH}")

    def _s(key, fallback=''):
        """Normalize a string field: get, coerce to str, strip whitespace."""
        return (data.get(key) or fallback).strip()

    router_identity = data.get('router_identity', 'RTR-MTCCR2216.FTTH-BNG')
    deployment_type = str(data.get('deployment_type', 'instate') or 'instate').strip().lower()
    is_outstate = deployment_type in ('outstate', 'out_of_state', 'out-of-state')
    location = _s('location').replace('"', '') or '0,0'

    loopback_ip = data.get('loopback_ip', '')
    cpe_network = data.get('cpe_network', '')
    cgnat_private = data.get('cgnat_private', '')
    cgnat_public = data.get('cgnat_public', '')
    unauth_network = data.get('unauth_network', '')

    olt_network = data.get('olt_network', '') or data.get('olt_network_primary', '')
    olt_network_100g = _s('olt_network_100g')
    olt_network_secondary = _s('olt_network_secondary') or _s('olt_network2')
    olt_name = _s('olt_name') or _s('olt_name_primary') or 'OLT-MF2-1'
    olt_name_secondary = _s('olt_name_secondary')
    olt_name_100g = _s('olt_name_100g')
    if olt_network_secondary and not olt_name_secondary:
        olt_name_secondary = 'OLT-MF2-2'

    routeros_version = _s('routeros_version')
    uplinks = data.get('uplinks', [])
    if not uplinks:
        uplinks = [{
            'port': data.get('uplink_port', 'sfp28-1'),
            'type': data.get('uplink_type', 'routed'),
            'ip': data.get('uplink_ip', ''),
            'speed': data.get('uplink_speed', 'auto'),
            'comment': data.get('uplink_comment', 'to-CORE'),
            'cost': data.get('uplink_cost', '10'),
            'mtu': data.get('uplink_mtu', '9000'),
            'l2mtu': data.get('uplink_l2mtu', '9212'),
            'auto_negotiation': data.get('uplink_auto_negotiation', False),
        }]

    olt_ports = data.get('olt_ports', [])
    has_olt2_ports = has_olt1_ports = has_100g_ports = False
    for _p in olt_ports:
        _g = str(_p.get('group') or '')
        if _g == '2':
            has_olt2_ports = True
        if _g == '1' or _g == '':  # '' is falsy so original `or '1'` treated it as group 1
            has_olt1_ports = True
        if _g.lower() == '100g':
            has_100g_ports = True
        if has_olt2_ports and has_olt1_ports and has_100g_ports:
            break

    if has_100g_ports and olt_network_100g:
        olt_network = olt_network_100g
    # Out-of-state generation follows the transport-focused template and should
    # not hard-require FTTH subscriber pools from UI.
    if is_outstate:
        cpe_network = (cpe_network or '10.255.0.0/22').strip()
        cgnat_private = (cgnat_private or '100.127.252.0/22').strip()
        cgnat_public = (cgnat_public or '203.0.113.1/32').strip()
        unauth_network = (unauth_network or '10.255.4.0/22').strip()
        if not all([loopback_ip, olt_network]):
            raise ValueError('Missing required IP allocation fields (outstate requires Loopback and OLT Network).')
    else:
        if not all([loopback_ip, cpe_network, cgnat_private, cgnat_public, unauth_network, olt_network]):
            raise ValueError('Missing required IP allocation fields.')

    loopback = ipaddress.ip_interface(loopback_ip)
    outstate_profile = _resolve_outstate_profile(data, loopback)
    ospf_area = outstate_profile["ospf_area"]
    ospf_area_id = outstate_profile["ospf_area_id"] if is_outstate else "0.0.0.0"
    ospf_area_name = f"area{ospf_area}" if is_outstate else "backbone-v2"
    vpls_state_id = outstate_profile["vpls_state_id"]
    cpe_net, cpe_first, _cpe_last = _net_details(cpe_network)
    cgnat_net, cgnat_first, _cgnat_last = _net_details(cgnat_private)
    unauth_net, unauth_first, _unauth_last = _net_details(unauth_network)
    cgnat_pub = ipaddress.ip_interface(cgnat_public)
    olt1_net, olt1_first, _olt1_last = _net_details(olt_network)
    olt2_net = olt2_first = None
    if olt_network_secondary:
        olt2_net, olt2_first, _olt2_last = _net_details(olt_network_secondary)

    cpe_pool_start, cpe_pool_end = _pool_range(cpe_net, 10)
    unauth_pool_start, unauth_pool_end = _pool_range(unauth_net, 10)
    cgnat_pool_start, cgnat_pool_end = _pool_range(cgnat_net, 3)

    group1_tag = _group_tag_from_name(olt_name, 'MF2-1')
    group2_tag = _group_tag_from_name(olt_name_secondary, 'MF2-2')

    uplink_lines = []
    uplink_ip_lines = []
    uplink_ospf_lines = []
    uplink_ldp_lines = []

    for uplink in uplinks:
        port = uplink.get('port', 'sfp28-1')
        comment = _fmt_comment(uplink.get('comment', 'UPLINK'))
        speed = uplink.get('speed', 'auto')
        mtu = uplink.get('mtu', '9000')
        l2mtu = uplink.get('l2mtu', '9212')
        auto_neg = uplink.get('auto_negotiation', False)
        parts = [f"set [ find default-name={port} ]"]
        if comment:
            parts.append(f"comment={comment}")
        if l2mtu:
            parts.append(f"l2mtu={l2mtu}")
        if mtu:
            parts.append(f"mtu={mtu}")
        _append_ftth_speed_parts(parts, speed, auto_neg=bool(auto_neg))
        uplink_lines.append(" ".join(parts))

        uplink_ip = uplink.get('ip', '')
        if uplink.get('type', 'routed') == 'routed' and uplink_ip:
            uplink_iface = ipaddress.ip_interface(uplink_ip)
            ospf_comment = _fmt_comment(uplink.get('comment', 'UPLINK'))
            ospf_comment_part = f" comment={ospf_comment}" if ospf_comment else ""
            uplink_ip_lines.append(
                f"add address={uplink_ip} comment={_fmt_comment(uplink.get('comment', 'UPLINK'))} interface={port} network={uplink_iface.network.network_address}"
            )
            uplink_ospf_lines.append(
                f"add area={ospf_area_name} auth=md5 auth-id=1 auth-key=m8M5JwvdYM{ospf_comment_part} cost=10 disabled=no interfaces={port} networks={uplink_iface.network.network_address}/{uplink_iface.network.prefixlen} priority=1 type=ptp"
            )
        uplink_ldp_lines.append(f"add disabled=no interface={port}")

    primary_uplink = uplinks[0].get('port', 'sfp28-1') if uplinks else 'sfp28-1'
    primary_mtu = uplinks[0].get('mtu', '9000') if uplinks else '9000'

    if has_100g_ports and (has_olt1_ports or has_olt2_ports):
        raise ValueError('200G OLT ports cannot be combined with LAG 1 or LAG 2 ports.')
    if has_olt2_ports and not olt_network_secondary:
        raise ValueError('OLT Network 2 is required when OLT LAG 2 ports are configured.')
    if has_olt2_ports and not olt_name_secondary:
        olt_name_secondary = 'OLT-MF2-2'
    if has_100g_ports and olt_network_secondary:
        raise ValueError('OLT Network 2 should not be set when using 200G OLT ports.')
    if has_100g_ports and not olt_network_100g:
        raise ValueError('OLT Network (200G) is required when using 200G OLT ports.')
    if has_100g_ports and not olt_name_100g:
        olt_name_100g = 'OLT-MF2-100G'
    if has_100g_ports and olt_name_100g:
        olt_name = olt_name_100g
        group1_tag = 'MF2_100G'
    olt_lines = []
    for port_cfg in olt_ports:
        port = port_cfg.get('port')
        if not port:
            continue
        group = str(port_cfg.get('group') or '1')
        if group == '100g':
            base_name = olt_name
        else:
            base_name = olt_name_secondary if group == '2' and olt_name_secondary else olt_name
        comment = _fmt_comment(port_cfg.get('comment') or base_name)
        speed = port_cfg.get('speed', 'auto')
        parts = [f"set [ find default-name={port} ]"]
        if comment:
            parts.append(f"comment={comment}")
        _append_ftth_speed_parts(parts, speed)
        olt_lines.append(" ".join(parts))

    if not olt_lines:
        olt1_comment = _fmt_comment(olt_name)
        olt_lines = [
            f"set [ find default-name=sfp28-3 ] auto-negotiation=no comment={olt1_comment}",
            f"set [ find default-name=sfp28-4 ] auto-negotiation=no comment={olt1_comment}",
            f"set [ find default-name=sfp28-5 ] auto-negotiation=no comment={olt1_comment}",
            f"set [ find default-name=sfp28-6 ] auto-negotiation=no comment={olt1_comment}",
        ]
        if olt_network_secondary or olt_name_secondary or has_olt2_ports:
            olt2_comment = _fmt_comment(olt_name_secondary or 'OLT-MF2-2')
            olt_lines.extend([
                f"set [ find default-name=sfp28-7 ] auto-negotiation=no comment={olt2_comment}",
                f"set [ find default-name=sfp28-8 ] auto-negotiation=no comment={olt2_comment}",
                f"set [ find default-name=sfp28-9 ] auto-negotiation=no comment={olt2_comment}",
                f"set [ find default-name=sfp28-10 ] auto-negotiation=no comment={olt2_comment}",
            ])

    if has_100g_ports:
        bonding_name = "bonding_MF2_100G"
        bonding_comment = _fmt_comment(f"MF2_100G_IP-ADDR: {olt1_first}")
        olt1_bonding_line = (
            f"add comment={bonding_comment} lacp-rate=1sec mode=802.3ad "
            f"name={bonding_name} slaves=qsfp28-1-1,qsfp28-2-1 transmit-hash-policy=layer-2-and-3"
        )
        olt1_vlan_lines = "\n".join([
            f"add interface={bonding_name} name=vlan1000-{group1_tag} vlan-id=1000",
            f"add interface={bonding_name} name=vlan2000-{group1_tag} vlan-id=2000",
            f"add interface={bonding_name} name=vlan3000-{group1_tag} vlan-id=3000",
            f"add interface={bonding_name} name=vlan4000-{group1_tag} vlan-id=4000",
        ])
        olt1_bridge_ports = "\n".join([
            f"add bridge=bridge1000 ingress-filtering=no interface=vlan1000-{group1_tag} internal-path-cost=10 path-cost=10",
            f"add bridge=bridge2000 interface=vlan2000-{group1_tag}",
            f"add bridge=bridge3000 interface=vlan3000-{group1_tag}",
            f"add bridge=bridge4000 ingress-filtering=no interface=vlan4000-{group1_tag} internal-path-cost=10 path-cost=10",
        ])
    else:
        olt1_bonding_line = (
            f"add mode=802.3ad name=bonding3000-{group1_tag} "
            "slaves=sfp28-3,sfp28-4,sfp28-5,sfp28-6 transmit-hash-policy=layer-2-and-3"
        )
        olt1_vlan_lines = "\n".join([
            f"add interface=bonding3000-{group1_tag} name=vlan1000-{group1_tag} vlan-id=1000",
            f"add interface=bonding3000-{group1_tag} name=vlan2000-{group1_tag} vlan-id=2000",
            f"add interface=bonding3000-{group1_tag} name=vlan3000-{group1_tag} vlan-id=3000",
            f"add interface=bonding3000-{group1_tag} name=vlan4000-{group1_tag} vlan-id=4000",
        ])
        olt1_bridge_ports = "\n".join([
            f"add bridge=bridge1000 ingress-filtering=no interface=vlan1000-{group1_tag} internal-path-cost=10 path-cost=10",
            f"add bridge=bridge2000 interface=vlan2000-{group1_tag}",
            f"add bridge=bridge3000 interface=vlan3000-{group1_tag}",
            f"add bridge=bridge4000 ingress-filtering=no interface=vlan4000-{group1_tag} internal-path-cost=10 path-cost=10",
        ])
    olt1_ip_line = (
        f"add address={olt1_first}/{olt1_net.prefixlen} comment={_fmt_comment(olt_name)} "
        f"interface=bridge3000 network={olt1_net.network_address}"
    )
    olt1_ospf_line = (
        f"add area={ospf_area_name} comment={_fmt_comment(olt_name)} cost=10 disabled=no "
        f"interfaces=bridge3000 networks={olt1_net.network_address}/{olt1_net.prefixlen} priority=1"
    )

    olt2_bonding_line = ''
    olt2_vlan_lines = ''
    olt2_bridge_ports = ''
    olt2_ip_line = ''
    olt2_ospf_line = ''
    if (olt2_net and olt2_first) or has_olt2_ports:
        olt2_bonding_line = (
            f"add mode=802.3ad name=bonding3000-{group2_tag} "
            "slaves=sfp28-7,sfp28-8,sfp28-9,sfp28-10 transmit-hash-policy=layer-2-and-3"
        )
        olt2_vlan_lines = "\n".join([
            f"add interface=bonding3000-{group2_tag} name=vlan1000-{group2_tag} vlan-id=1000",
            f"add interface=bonding3000-{group2_tag} name=vlan2000-{group2_tag} vlan-id=2000",
            f"add interface=bonding3000-{group2_tag} name=vlan3000-{group2_tag} vlan-id=3000",
            f"add interface=bonding3000-{group2_tag} name=vlan4000-{group2_tag} vlan-id=4000",
        ])
        olt2_bridge_ports = "\n".join([
            f"add bridge=bridge1000 ingress-filtering=no interface=vlan1000-{group2_tag} internal-path-cost=10 path-cost=10",
            f"add bridge=bridge2000 interface=vlan2000-{group2_tag}",
            f"add bridge=bridge3000 interface=vlan3000-{group2_tag}",
            f"add bridge=bridge4000 ingress-filtering=no interface=vlan4000-{group2_tag} internal-path-cost=10 path-cost=10",
        ])
        if olt2_net and olt2_first:
            olt2_ip_line = (
                f"add address={olt2_first}/{olt2_net.prefixlen} comment={_fmt_comment(olt_name_secondary)} "
                f"interface=bridge3000 network={olt2_net.network_address}"
            )
            olt2_ospf_line = (
                f"add area={ospf_area_name} comment={_fmt_comment(olt_name_secondary)} cost=10 disabled=no "
                f"interfaces=bridge3000 networks={olt2_net.network_address}/{olt2_net.prefixlen} priority=1"
            )

    if routeros_version == '7.20.2':
        bgp_instance_block = "\n".join([
            "/routing bgp instance",
            f"add as=26077 disabled=no name=bgp-instance-1 router-id={loopback.ip}",
        ])
        bgp_template_line = "set default as=26077 disabled=no output.network=bgp-networks"
        bgp_connection_lines = "\n".join([
            f"add cisco-vpls-nlri-len-fmt=auto-bits connect=yes disabled=no instance=bgp-instance-1 listen=yes "
            f"local.address={loopback.ip} .role=ibgp multihop=yes name=CR7 output.network=bgp-networks "
            f"remote.address=10.2.0.107/32 .as=26077 .port=179 routing-table=main templates=default",
            f"add cisco-vpls-nlri-len-fmt=auto-bits connect=yes disabled=no instance=bgp-instance-1 listen=yes "
            f"local.address={loopback.ip} .role=ibgp multihop=yes name=CR8 output.network=bgp-networks "
            f"remote.address=10.2.0.108/32 .as=26077 .port=179 routing-table=main templates=default",
        ])
    else:
        bgp_instance_block = ''
        bgp_template_line = f"set default as=26077 disabled=no output.network=bgp-networks router-id={loopback.ip}"
        bgp_connection_lines = "\n".join([
            f"add cisco-vpls-nlri-len-fmt=auto-bits connect=yes listen=yes local.address={loopback.ip} "
            f".role=ibgp multihop=yes name=CR7 remote.address=10.2.0.107 .as=26077 .port=179 templates=default",
            f"add cisco-vpls-nlri-len-fmt=auto-bits connect=yes listen=yes local.address={loopback.ip} "
            f".role=ibgp multihop=yes name=CR8 remote.address=10.2.0.108 .as=26077 .port=179 templates=default",
        ])

    user_passwords = _ftth_user_passwords()
    bng_1_ip = str(data.get('bng_1_ip') or os.getenv('NEXTLINK_BNG1_IP', '10.249.0.200')).strip()
    bng_2_ip = str(data.get('bng_2_ip') or os.getenv('NEXTLINK_BNG2_IP', '10.249.0.201')).strip()
    vpls_l2mtu = str(data.get('vpls_l2_mtu') or os.getenv('NEXTLINK_VPLS_L2_MTU', '1580')).strip()
    bridge_lines = _render_bridge_lines(is_outstate=is_outstate)
    vpls_lines = _render_outstate_vpls_lines(
        enabled=is_outstate,
        router_identity=router_identity,
        state_id=vpls_state_id,
        bng1_ip=bng_1_ip,
        bng2_ip=bng_2_ip,
        pw_l2mtu=vpls_l2mtu,
    )
    accept_filters = _dedupe_preserve_order(MPLS_ACCEPT_FILTERS)
    advertise_filters = [line.replace('accept', 'advertise', 1) for line in accept_filters]

    replacements = {
        "{{BRIDGE_LINES}}": bridge_lines,
        "{{VPLS_LINES}}": vpls_lines,
        "{{UPLINK_ETHERNET_LINES}}": "\n".join(uplink_lines),
        "{{OLT_ETHERNET_LINES}}": "\n".join(olt_lines),
        "{{UPLINK_PRIMARY_PORT}}": primary_uplink,
        "{{UPLINK_PRIMARY_MTU}}": str(primary_mtu),
        "{{OLT1_TAG}}": group1_tag,
        "{{OLT1_BONDING_LINE}}": olt1_bonding_line,
        "{{OLT1_VLAN_LINES}}": olt1_vlan_lines,
        "{{OLT1_BRIDGE_PORTS}}": olt1_bridge_ports,
        "{{OLT1_IP_LINE}}": olt1_ip_line,
        "{{OLT1_OSPF_LINE}}": olt1_ospf_line,
        "{{OLT2_BONDING_LINE}}": olt2_bonding_line,
        "{{OLT2_VLAN_LINES}}": olt2_vlan_lines,
        "{{OLT2_BRIDGE_PORTS}}": olt2_bridge_ports,
        "{{OLT2_IP_LINE}}": olt2_ip_line,
        "{{OLT2_OSPF_LINE}}": olt2_ospf_line,
        "{{CGNAT_POOL_START}}": cgnat_pool_start,
        "{{CGNAT_POOL_END}}": cgnat_pool_end,
        "{{CPE_POOL_START}}": cpe_pool_start,
        "{{CPE_POOL_END}}": cpe_pool_end,
        "{{UNAUTH_POOL_START}}": unauth_pool_start,
        "{{UNAUTH_POOL_END}}": unauth_pool_end,
        "{{ROUTER_ID}}": str(loopback.ip),
        "{{OSPF_AREA_NAME}}": ospf_area_name,
        "{{OSPF_AREA_ID}}": ospf_area_id,
        "{{CPE_GATEWAY}}": str(cpe_first),
        "{{CPE_PREFIX}}": str(cpe_net.prefixlen),
        "{{CPE_NETWORK_BASE}}": str(cpe_net.network_address),
        "{{LOOPBACK_IP}}": str(loopback.ip),
        "{{UNAUTH_GATEWAY}}": str(unauth_first),
        "{{UNAUTH_PREFIX}}": str(unauth_net.prefixlen),
        "{{UNAUTH_NETWORK_BASE}}": str(unauth_net.network_address),
        "{{CGNAT_GATEWAY}}": str(cgnat_first),
        "{{CGNAT_PREFIX}}": str(cgnat_net.prefixlen),
        "{{CGNAT_NETWORK_BASE}}": str(cgnat_net.network_address),
        "{{OLT1_IP}}": str(olt1_first),
        "{{OLT1_PREFIX}}": str(olt1_net.prefixlen),
        "{{OLT1_NETWORK_BASE}}": str(olt1_net.network_address),
        "{{CGNAT_PUBLIC}}": str(cgnat_pub.ip),
        "{{UPLINK_IP_LINES}}": "\n".join(uplink_ip_lines),
        "{{UPLINK_OSPF_LINES}}": "\n".join(uplink_ospf_lines),
        "{{UPLINK_LDP_LINES}}": "\n".join(uplink_ldp_lines),
        "{{MPLS_ACCEPT_FILTERS}}": "\n".join(accept_filters),
        "{{MPLS_ADVERTISE_FILTERS}}": "\n".join(advertise_filters),
        "{{OLT1_NAME}}": _fmt_comment(olt_name),
        "{{ROUTER_IDENTITY}}": router_identity,
        "{{LOCATION}}": location,
        "{{SNMP_CONTACT}}": os.getenv('NEXTLINK_SNMP_CONTACT', 'noc@team.nxlink.com'),
        "{{GENERATED_AT}}": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "{{BGP_INSTANCE_BLOCK}}": bgp_instance_block,
        "{{BGP_TEMPLATE_LINE}}": bgp_template_line,
        "{{BGP_CONNECTION_LINES}}": bgp_connection_lines,
        "{{USER_ROOT_PASSWORD}}": _ftth_quote(user_passwords['root']),
        "{{USER_DEPLOYMENT_PASSWORD}}": _ftth_quote(user_passwords['deployment']),
        "{{USER_INFRA_PASSWORD}}": _ftth_quote(user_passwords['infra']),
        "{{USER_IDO_PASSWORD}}": _ftth_quote(user_passwords['ido']),
        "{{USER_STS_PASSWORD}}": _ftth_quote(user_passwords['sts']),
        "{{USER_ENG_PASSWORD}}": _ftth_quote(user_passwords['eng']),
        "{{USER_NOC_PASSWORD}}": _ftth_quote(user_passwords['noc']),
        "{{USER_COMENG_PASSWORD}}": _ftth_quote(user_passwords['comeng']),
        "{{USER_DEVOPS_PASSWORD}}": _ftth_quote(user_passwords['devops']),
        "{{USER_ACQ_PASSWORD}}": _ftth_quote(user_passwords['acq']),
        "{{USER_ADMIN_PASSWORD}}": _ftth_quote(user_passwords['admin']),
    }

    template = TEMPLATE_PATH.read_text(encoding='utf-8')
    template = _FTTH_TEMPLATE_RE.sub(lambda m: replacements[m.group(0)], template)

    if has_100g_ports:
        template = re.sub(
            r"^.*default-name=qsfp28-1-1.*disabled=yes.*\n",
            "",
            template,
            flags=re.M,
        )
        template = re.sub(
            r"^.*default-name=qsfp28-2-1.*disabled=yes.*\n",
            "",
            template,
            flags=re.M,
        )

    template = _strip_ftth_headers(template)
    template = _normalize_ftth_output(template)

    if is_outstate:
        template = _enforce_outstate_ospf_area(template, ospf_area_name, ospf_area_id)
        template = _strip_outstate_subscriber_features(template)
        template = _prune_outstate_transport_only(template)

    # --- GitLab compliance integration ---
    # Replace hardcoded compliance sections with GitLab-sourced data.
    # Falls back to hardcoded reference if GitLab is unavailable.
    # Keep this as the final mutating pass so outstate pruning does not
    # accidentally strip compliance markers/blocks.
    template = _apply_ftth_compliance(template, str(loopback.ip))
    return template
