import os
import re
from pathlib import Path
from netaddr import IPNetwork
from jinja2 import Environment, FileSystemLoader


###################################
###          Constants          ###
###################################

DEVICE_TYPES = {
    "MT1009": {
        "port_count": 8,
        "config_template": "mt_1009_tower_config.rsc",
        "port_map_template": "mt_1009_tower_port_map.txt",
    },
    "MT1036": {
        "port_count": 12,
        "config_template": "mt_1036_tower_config.rsc",
        "port_map_template": "mt_1036_tower_port_map.txt",
    },
    "MT1072": {
        "port_count": 8,
        "config_template": "mt_1072_tower_config.rsc",
        "port_map_template": "mt_1072_tower_port_map.txt",
    },
    "MT2004": {
        "port_count": 12,
        "config_template": "mt_2004_tower_config.rsc",
        "port_map_template": "mt_2004_tower_port_map.txt",
    },
    "MT2216": {
        "port_count": 12,
        "config_template": "mt_2216_tower_config.rsc",
        "port_map_template": "mt_2216_tower_port_map.txt",
    },
}

PORT_POLICY = {
    "MT1009": {
        "management": "ether1",
        "switch": ["ether2", "ether3"],
        "backhaul": ["sfp-sfpplus1", "ether4", "ether5", "ether6", "ether7", "ether8", "ether9", "ether10"],
    },
    "MT1036": {
        "management": "ether1",
        "switch": ["sfp1", "sfp2"],
        "backhaul": ["sfp3", "sfp4", "ether2", "ether3", "ether4", "ether5", "ether6", "ether7", "ether8", "ether9", "ether10", "ether11", "ether12"],
    },
    "MT1072": {
        "management": "ether1",
        "switch": ["sfp1", "sfp2"],
        "backhaul": ["sfp3", "sfp4", "ether2", "ether3", "ether4", "ether5", "ether6", "ether7", "ether8", "ether9", "ether10", "ether11", "ether12"],
    },
    "MT2004": {
        "management": "ether1",
        "switch": ["sfp-sfpplus1", "sfp-sfpplus2"],
        "backhaul": [
            "sfp-sfpplus4", "sfp-sfpplus5", "sfp-sfpplus6", "sfp-sfpplus7",
            "sfp-sfpplus8", "sfp-sfpplus9", "sfp-sfpplus10", "sfp-sfpplus11",
            "sfp-sfpplus12", "sfp28-1", "sfp28-2"
        ],
    },
    "MT2216": {
        "management": "ether1",
        "switch": ["sfp28-1", "sfp28-2"],
        "backhaul": [
            "sfp28-4", "sfp28-5", "sfp28-6", "sfp28-7", "sfp28-8", "sfp28-9",
            "sfp28-10", "sfp28-11", "sfp28-12",
            "qsfp28-1-1", "qsfp28-1-2", "qsfp28-1-3", "qsfp28-1-4",
            "qsfp28-2-1", "qsfp28-2-2", "qsfp28-2-3", "qsfp28-2-4",
        ],
    },
}

TARANA_SECTORS = [
    {"name": "Alpha", "port": "sfp-sfpplus8", "address_offset": 2},
    {"name": "Beta", "port": "sfp-sfpplus9", "address_offset": 3},
    {"name": "Gamma", "port": "sfp-sfpplus10", "address_offset": 4},
    {"name": "Delta", "port": "sfp-sfpplus11", "address_offset": 5},
]


###################################
###        Config Paths         ###
###################################

def _base_config_path() -> Path:
    env = os.getenv("BASE_CONFIG_PATH") or os.getenv("NEXTLINK_BASE_CONFIG_PATH")
    if env:
        configured = Path(env)
        required = configured / "Router" / "Tower" / "config"
        if required.is_dir():
            return configured
    # Bundled fallback inside nexus repo
    return Path(__file__).resolve().parent.parent / "base_configs"


def normalize_port_name(p):
    if p is None:
        return p
    s = str(p).strip()
    if not s:
        return s
    if s.startswith("sfp"):
        return s
    if s.startswith("28-"):
        return "sfp" + s
    if s.isdigit():
        return "sfp-sfpplus" + s
    return s


class MTTowerConfig:
    def __init__(self, **params):
        try:
            self.router_type = params["router_type"]
            if self.router_type not in DEVICE_TYPES:
                raise ValueError(f"Invalid router type: {self.router_type}.")
            self.router_params = DEVICE_TYPES[self.router_type]

            # Validate backhauls
            self.backhauls = params["backhauls"]
            if not self.backhauls:
                raise ValueError("No backhauls provided.")
            for backhaul in self.backhauls:
                if not all((
                    backhaul.get("name"),
                    backhaul.get("subnet"),
                    backhaul.get("master") is not None,
                    backhaul.get("port") is not None,
                    backhaul.get("bandwidth"),
                )):
                    raise ValueError(f"Invalid backhaul params: {backhaul}.")

            self.loopback_subnet = IPNetwork(params["loopback_subnet"])
            self.gateway = IPNetwork(params["backhauls"][0]["subnet"])
            self.cpe_subnet = IPNetwork(params["cpe_subnet"])
            self.unauth_subnet = IPNetwork(params["unauth_subnet"])
            self.cgn_priv_subnet = IPNetwork(params["cgn_priv"])
            self.cgn_pub = str(params["cgn_pub"]).strip()
            if "/" not in self.cgn_pub:
                self.cgn_pub = f"{self.cgn_pub}/32"
            self.cgn_pub_subnet = IPNetwork(self.cgn_pub)
            self.tower_name = params["tower_name"]
            self.latitude = params["latitude"]
            self.longitude = params["longitude"]
            self.state_code = params["state_code"]
            self.deployment_mode = str(params.get("deployment_mode", "out-of-state")).strip().lower()
            self.asn = params["asn"]
            self.peer_1_address = params["peer_1_address"]
            self.peer_1_name = params["peer_1_name"]
            self.peer_2_address = params["peer_2_address"]
            self.peer_2_name = params["peer_2_name"]

            self.is_6ghz = params.get("is_6ghz", False)
            self.is_lte = params.get("is_lte", False)

            self.is_326 = params.get("is_326", False)
            if self.is_326:
                self.crs_326_mgmt_subnet = IPNetwork(params["326_mgmt_subnet"])

            self.is_tachyon = params.get("is_tachyon", False)

            if self.is_6ghz or self.is_tachyon:
                self.six_ghz_subnet = IPNetwork(params["6ghz_subnet"])

            self.is_ub_wave = params.get("is_ub_wave", False)
            if self.is_ub_wave:
                self.ub_wave_subnet = IPNetwork(params["ub_wave_subnet"])

            self.enable_contractor_login = params.get("enable_contractor_login", False)
            self.is_tarana = params.get("is_tarana", False)
            self.switches = params.get("switches", []) or []
            for sw in self.switches:
                if not sw.get("name") or not sw.get("port"):
                    raise ValueError(f"Invalid switch params: {sw}.")

            self._bgp_md5_key = os.getenv("NEXTLINK_BGP_MD5_KEY", "m8M5JwvdYM")
            self._ospf_md5_key = os.getenv("NEXTLINK_OSPF_MD5_KEY", "m8M5JwvdYM")

            self._validate_port_policy()

            if self.is_tarana:
                self.tarana_subnet = IPNetwork(params["tarana_subnet"])
                self.tarana_sector_count = int(params.get("tarana_sector_count", 3))
                self.tarana_sector_start = int(params.get("tarana_sector_start", 0))
                # Accept custom sector port assignments from frontend
                self._custom_sectors = params.get("tarana_sectors", None)
                # Unicorn MGMT subnet (defaults to tarana_subnet if not provided)
                raw_unicorn = params.get("unicorn_mgmt_subnet") or str(self.tarana_subnet)
                self.unicorn_mgmt_subnet = IPNetwork(raw_unicorn)

        except KeyError as err:
            raise ValueError(f"Missing parameter: {err}")

        base_path = _base_config_path()
        config_template_path = str(base_path / "Router" / "Tower" / "config")
        port_map_template_path = str(base_path / "Router" / "Tower" / "port_map")

        # Configure jinja environment
        self.jinja_env = Environment(
            loader=FileSystemLoader([config_template_path, port_map_template_path])
        )
        self.jinja_env.trim_blocks = True
        self.jinja_env.lstrip_blocks = True

    def _validate_port_policy(self):
        policy = PORT_POLICY.get(self.router_type)
        if not policy:
            return

        backhaul_ports = [normalize_port_name(str(bh.get("port", "")).strip()) for bh in self.backhauls]
        switch_ports = [normalize_port_name(str(sw.get("port", "")).strip()) for sw in self.switches]
        management_port = policy["management"]
        allowed_backhaul = set(policy["backhaul"])
        allowed_switch = set(policy["switch"])
        used = set()

        for port in switch_ports:
            if port not in allowed_switch:
                raise ValueError(f"Switch port '{port}' is not valid for {self.router_type}. Allowed switch ports: {sorted(allowed_switch)}")
            if port in used:
                raise ValueError(f"Port collision detected on {port}")
            used.add(port)

        for port in backhaul_ports:
            if port == management_port or port not in allowed_backhaul:
                raise ValueError(f"Backhaul port '{port}' is not valid for {self.router_type}. Allowed backhaul ports: {sorted(allowed_backhaul)}")
            if port in used:
                raise ValueError(f"Port collision detected on {port}")
            used.add(port)

        # MT2004 tower policy (Engineering):
        # ether1 = management, sfp-sfpplus1-2 = switch, sfp-sfpplus4+ = backhaul
        if self.router_type == "MT2004":
            reserved = set()
            if getattr(self, "is_lte", False):
                reserved.add("sfp-sfpplus6")
            if getattr(self, "is_tarana", False):
                reserved.update({"sfp-sfpplus6", "sfp-sfpplus7", "sfp-sfpplus8"})
                # Reserve the actual Tarana sector ports (custom or default)
                custom = getattr(self, "_custom_sectors", None)
                if custom:
                    reserved.update(normalize_port_name(s.get("port", "")) for s in custom if s.get("port"))
                else:
                    count = getattr(self, "tarana_sector_count", 3)
                    for i in range(min(count, len(TARANA_SECTORS))):
                        reserved.add(TARANA_SECTORS[i]["port"])

            violations = sorted(set(backhaul_ports).intersection(reserved))
            if violations:
                raise ValueError(
                    "Backhaul port policy violation for MT2004. "
                    f"Reserved by enabled features: {violations}."
                )

    def get_tarana_sectors(self):
        azimuths = [
            (int(360 / self.tarana_sector_count + 0.5) * x + self.tarana_sector_start)
            % 360
            for x in range(self.tarana_sector_count)
        ]

        # Use custom sector ports from frontend if provided
        custom = getattr(self, "_custom_sectors", None)
        result = []
        for i in range(self.tarana_sector_count):
            if custom and i < len(custom) and custom[i].get("port"):
                port = normalize_port_name(custom[i]["port"])
                name = custom[i].get("name", TARANA_SECTORS[i]["name"])
            else:
                port = TARANA_SECTORS[i]["port"]
                name = TARANA_SECTORS[i]["name"]
            result.append({
                "name": name,
                "port": port,
                "address_offset": TARANA_SECTORS[i]["address_offset"],
                "azimuth": azimuths[i],
            })
        return result

    def get_base_params(self, params=None):
        if not params:
            params = {}

        params["tower_name"] = self.tower_name
        params["loopback"] = self.loopback_subnet
        params["loopback_net"] = self.loopback_subnet.network
        params["router_type"] = self.router_type
        params["asn"] = self.asn
        params["peer1_name"] = self.peer_1_name
        params["peer1"] = self.peer_1_address
        params["peer2_name"] = self.peer_2_name
        params["peer2"] = self.peer_2_address
        params["bgp_md5_key"] = self._bgp_md5_key
        params["ospf_md5_key"] = self._ospf_md5_key
        params["cgn_pub"] = self.cgn_pub
        params["cgn_pub_ip"] = str(self.cgn_pub_subnet.ip)
        params["cgn_pub_sub"] = self.cgn_pub_subnet.prefixlen
        params["cgn_pub_network"] = str(self.cgn_pub_subnet.network)
        params["cgn_priv"] = self.cgn_priv_subnet
        params["gps"] = f"{self.latitude}, {self.longitude}"
        params["state_code"] = self.state_code
        params["deployment_mode"] = self.deployment_mode
        params["use_lan_bridge"] = self.deployment_mode != "out-of-state"

        params["unauth_ip"] = str(self.unauth_subnet.network + 1)
        params["unauth_ip_sub"] = self.unauth_subnet.prefixlen
        params["unauth_net"] = self.unauth_subnet
        params["unauth_range_low"] = str(self.unauth_subnet.network + 2)
        params["unauth_range_high"] = str(self.unauth_subnet.broadcast - 1)

        params["gateway_ip"] = str(self.gateway.network + 1)
        params["cgn_priv_ip"] = str(self.cgn_priv_subnet.network + 1)
        params["cgn_priv_range_low"] = str(self.cgn_priv_subnet.network + 3)
        params["cgn_priv_range_high"] = str(self.cgn_priv_subnet.broadcast - 1)
        params["cgn_priv_net"] = self.cgn_priv_subnet
        params["cgn_priv_sub"] = self.cgn_priv_subnet.prefixlen
        params["enable_contractor_login"] = self.enable_contractor_login

        params["is_326"] = self.is_326
        params["is_tarana"] = self.is_tarana
        params["is_tachyon"] = self.is_tachyon
        params["is_6ghz"] = self.is_6ghz
        params["is_ub_wave"] = self.is_ub_wave
        params["switches"] = [
            {**sw, "port": normalize_port_name(sw.get("port"))}
            for sw in self.switches
        ]

        return params

    def get_backhaul_params(self, params=None, num=None):
        if not params:
            params = {}
    
        params["backhauls"] = []
    
        for backhaul in [self.backhauls[num]] if num else self.backhauls:
            subnet_raw = str(backhaul["subnet"]).strip()
            bh_net = IPNetwork(subnet_raw)
            link_mode = str(backhaul.get("link_mode", "auto")).strip().lower()
            raw_ip = subnet_raw.split("/")[0].strip()
            user_pinned_ip = raw_ip if raw_ip and raw_ip != str(bh_net.network) else ""

            if user_pinned_ip:
                bhip = user_pinned_ip
            else:
                if backhaul["master"]:
                    addr_offset = 1
                else:
                    if link_mode == "2+0":
                        addr_offset = 2 if bh_net.size > 2 else 1
                    elif link_mode == "4+0":
                        addr_offset = 4 if bh_net.size > 4 else 2
                    else:
                        # Auto: /30 uses second usable host, /29+ uses +4 layout.
                        addr_offset = 2 if bh_net.size <= 4 else 4
                bhip = str(bh_net.network + addr_offset)
            link_side_1 = self.tower_name if backhaul["master"] else backhaul["name"]
            link_side_2 = backhaul["name"] if backhaul["master"] else self.tower_name
    
            params["backhauls"].append({
                "bhname": backhaul["name"],
                "bhip": bhip,
                "interface_bandwidth": backhaul["bandwidth"],
                "port": normalize_port_name(backhaul["port"]),
                "bhip_sub": bh_net.prefixlen,
                "bhsubnet": str(bh_net),
                "bh_network": str(bh_net.network),
                "bh_cidr": f"{bh_net.network}/{bh_net.prefixlen}",
                "masterbh_int": str(bh_net.network + 1),
                "masterbh": str(bh_net.network + 2),
                "slavebh": str(bh_net.network + 3),
                "slavebh_int": str(bh_net.network + 4),
                "link_side_1": link_side_1,
                "link_side_2": link_side_2,
            })
    
        return params

    def get_tarana_params(self, params=None):
        if not params:
            params = {}

        params["tarana_network"] = str(self.tarana_subnet.network)
        params["tarana_gateway"] = str(self.tarana_subnet.network + 1)
        params["tarana_netmask_bits"] = str(self.tarana_subnet.netmask.netmask_bits())
        params["tarana_sectors"] = self.get_tarana_sectors()

        # Unicorn MGMT subnet params for the template
        params["unicorn_mgmt_ip"] = str(self.unicorn_mgmt_subnet.network + 1)
        params["unicorn_mgmt_prefix"] = self.unicorn_mgmt_subnet.prefixlen
        params["unicorn_mgmt_network"] = str(self.unicorn_mgmt_subnet.network)

        return params

    def get_6ghz_params(self, params=None):
        if not params:
            params = {}

        params["six_ghz_network"] = self.six_ghz_subnet.network
        params["six_ghz_address"] = str(self.six_ghz_subnet.network + 1)
        params["six_ghz_prefixlen"] = self.six_ghz_subnet.prefixlen
        params["six_ghz_range_low"] = str(self.six_ghz_subnet.network + 2)
        params["six_ghz_range_high"] = str(self.six_ghz_subnet.broadcast - 1)

        return params

    def get_ub_wave_params(self, params=None):
        if not params:
            params = {}

        params["ub_wave_network"] = self.ub_wave_subnet.network
        params["ub_wave_address"] = str(self.ub_wave_subnet.network + 1)
        params["ub_wave_prefixlen"] = self.ub_wave_subnet.prefixlen
        params["ub_wave_range_low"] = str(self.ub_wave_subnet.network + 2)
        params["ub_wave_range_high"] = str(self.ub_wave_subnet.broadcast - 1)

        return params

    def get_326_params(self, params=None):
        if not params:
            params = {}

        params["crs_326_mgmt_network"] = self.crs_326_mgmt_subnet.network
        params["crs_326_mgmt_mask_bits"] = (
            self.crs_326_mgmt_subnet.netmask.netmask_bits()
        )
        params["crs_326_mgmt_address"] = self.crs_326_mgmt_subnet

        return params

    def get_tachyon_params(self, params=None):
        if not params:
            params = {}

        params["six_ghz_address"] = self.six_ghz_subnet.ip
        params["six_ghz_network"] = self.six_ghz_subnet
        params["six_ghz_cpe_address"] = self.six_ghz_subnet

        return params

    def get_cpe_params(self, params=None):
        if not params:
            params = {}

        params["cpe_net"] = self.cpe_subnet
        params["cpe_ip"] = str(self.cpe_subnet.network + 1)
        params["cpe_ip_sub"] = self.cpe_subnet.prefixlen
        params["cpe_address"] = self.cpe_subnet.ip
        params["cpe_network"] = self.cpe_subnet.network
        params["cpe_gateway"] = self.cpe_subnet.network + 1
        params["cpe_range_low"] = str(self.cpe_subnet.network + 50)
        params["cpe_range_high"] = str(self.cpe_subnet.broadcast - 1)
        params["vlan_4000_cpe_range_low"] = str(self.cpe_subnet.network + 50)
        params["vlan_4000_cpe_range_high"] = str(self.cpe_subnet.broadcast - 1)
        params["cpe_mask_bits"] = self.cpe_subnet.netmask.netmask_bits()
        params["cpe_mask"] = str(self.cpe_subnet.netmask)
        params["cpe_ups"] = str(self.cpe_subnet.network + 2)
        params["cpe_wps"] = str(self.cpe_subnet.network + 5)
        params["cpe_switch"] = str(self.cpe_subnet.network + 6)
        params["cpe_ap_low"] = str(self.cpe_subnet.network + 10)
        params["cpe_ap_high"] = str(self.cpe_subnet.network + 49)

        return params

    def generate_config(self):
        def _normalize_block_spacing(text: str) -> str:
            lines = text.splitlines()
            out: list[str] = []
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("/") and out and out[-1].strip() != "":
                    out.append("")
                out.append(line.rstrip())
            return "\n".join(out).rstrip() + "\n"

        params = self.get_base_params()
        params = self.get_backhaul_params(params)
        params = self.get_cpe_params(params)
        if self.is_tarana:
            params = self.get_tarana_params(params)
        if self.is_6ghz and not self.is_tachyon:
            params = self.get_6ghz_params(params)
        if self.is_tachyon:
            params = self.get_tachyon_params(params)
        if self.is_ub_wave:
            params = self.get_ub_wave_params(params)
        if self.is_326:
            params = self.get_326_params(params)

        template = self.jinja_env.get_template(
            DEVICE_TYPES[self.router_type]["config_template"]
        )

        config_text = template.render(params)
        # Guard against Jinja trim/lstrip collapsing adjacent interface "set" commands.
        config_text = re.sub(
            r'(?<!\n)(set \[ find default-name=)',
            r'\n\1',
            config_text,
        )
        config_text = _normalize_block_spacing(config_text)

        # Compatibility guard: if external templates omit feature stanzas, append them.
        if self.is_6ghz and "comment=6GHZ" not in config_text:
            config_text += (
                f"\n\n# 6GHz management network (auto-appended)\n"
                f"/ip address\n"
                f"add address={self.six_ghz_subnet.network + 1}/{self.six_ghz_subnet.prefixlen} "
                f"interface=bridge3000 network={self.six_ghz_subnet.network} comment=6GHZ\n"
            )
        if self.is_ub_wave and "comment=UB-WAVE" not in config_text:
            config_text += (
                f"\n\n# UB WAVE management network (auto-appended)\n"
                f"/ip address\n"
                f"add address={self.ub_wave_subnet.network + 1}/{self.ub_wave_subnet.prefixlen} "
                f"interface=bridge3000 network={self.ub_wave_subnet.network} comment=UB-WAVE\n"
            )

        return config_text

    def generate_port_map(self):
        params = self.get_base_params()
        params = self.get_backhaul_params(params)
        params = self.get_cpe_params(params)

        template = self.jinja_env.get_template(
            DEVICE_TYPES[self.router_type]["port_map_template"]
        )

        port_map_text = template.render(params)

        return port_map_text
