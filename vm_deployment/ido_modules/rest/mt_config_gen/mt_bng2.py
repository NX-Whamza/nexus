import os
from pathlib import Path
from netaddr import IPNetwork
from jinja2 import Environment, FileSystemLoader


###################################
###          Constants          ###
###################################

ROUTER_TYPES = {
    "MT2004": {
        "config_template": "mt_2004_bng2_config.rsc",
        "port_map_template": "mt_2004_bng2_port_map.txt",
    },
    "7535": {
        "config_template": "7535_bng2_config.txt",
        "port_map_template": "7535_bng2_port_map.txt",
    },
    "7316": {
        "config_template": "7316_bng2_config.txt",
        "port_map_template": "7316_bng2_port_map.txt",
    }
}

BNG2_PORT_POLICY = {
    "MT2004": {
        "management": "ether1",
        "backhaul": [
            "sfp-sfpplus4", "sfp-sfpplus5", "sfp-sfpplus6", "sfp-sfpplus7",
            "sfp-sfpplus8", "sfp-sfpplus9", "sfp-sfpplus10", "sfp-sfpplus11",
            "sfp-sfpplus12", "sfp28-1", "sfp28-2"
        ],
    },
    "7535": {
        "management": "ether1",
        "backhaul": ["ether3", "ether4", "ether5", "ether6", "ether7", "ether8"],
    },
    "7316": {
        "management": "ether1",
        "backhaul": ["ether3", "ether4", "ether5", "ether6", "ether7", "ether8"],
    },
}

MSTP_STATES = {
    "42": "IA",
    "241": "IN",
    "243": "OK",
    "245": "IA",
    "248": "KS",
    "249": "NE",
    "250": "LA",
    "0": "IL",
}
MSTP_STATE_CODES = frozenset(MSTP_STATES.values())

TARANA_SECTORS = [
    {"name": "Alpha", "port": "sfp-sfpplus9", "address_offset": 2},
    {"name": "Beta", "port": "sfp-sfpplus10", "address_offset": 3},
    {"name": "Gamma", "port": "sfp-sfpplus11", "address_offset": 4},
    {"name": "Delta", "port": "sfp-sfpplus6", "address_offset": 5},
]

PORT_COUNT = 12

BBU_PORT = "sfp-sfpplus3"

AP_MODEL_NON_6GHZ = "CNEP3K-5-AL060"
AP_MODEL_6GHZ = "CN4600-6-AL060"

UPLINK_2_NON_6GHZ = "Netonix Uplink #2"
UPLINK_2_6GHZ = "SWT-MT2004/CRS309"


###################################
###        Config Paths         ###
###################################

def _base_config_path() -> Path:
    env = os.getenv("BASE_CONFIG_PATH") or os.getenv("NEXTLINK_BASE_CONFIG_PATH")
    if env:
        configured = Path(env)
        required = configured / "Router" / "BNG2" / "config"
        if required.is_dir():
            return configured
    # Bundled fallback inside nexus repo
    return Path(__file__).resolve().parent.parent / "base_configs"


class MTBNG2Config:
    @staticmethod
    def _strip_prefix(ip_or_cidr: str) -> str:
        value = str(ip_or_cidr or "").strip()
        return value.split("/")[0] if "/" in value else value

    def __init__(self, **params):
        try:
            self.router_type = params["router_type"]
            if self.router_type not in ROUTER_TYPES:
                raise ValueError(f"Invalid router type: {self.router_type}.")

            self.loop_ip = IPNetwork(params["loop_ip"])
            self.tower_name = params["tower_name"]
            self.gateway = IPNetwork(params["gateway"])
            self.latitude = params["latitude"]
            self.longitude = params["longitude"]
            self.bng_1_ip = params["bng_1_ip"]
            self.bng_2_ip = params["bng_2_ip"]
            self.vlan_1000_cisco = params["vlan_1000_cisco"]
            self.vlan_2000_cisco = params["vlan_2000_cisco"]
            self.vlan_3000_cisco = params["vlan_3000_cisco"]
            self.vlan_4000_cisco = params["vlan_4000_cisco"]
            self.mpls_mtu = params["mpls_mtu"]
            self.vpls_l2_mtu = params["vpls_l2_mtu"]

            self.state_code = params["state_code"]
            if self.state_code not in MSTP_STATE_CODES:
                raise ValueError(
                    f"State '{self.state_code}' is not valid for this config type."
                )
            self.ospf_area = params["ospf_area"]
            if self.ospf_area not in MSTP_STATES:
                raise ValueError("Invalid OSPF area.")

            self.is_switchless = params.get("is_switchless", False)
            self.switch_ip = IPNetwork(params["switch_ip"])

            self.is_lte = params.get("is_lte", False)
            if self.is_lte:
                self.bbu_s1_subnet = IPNetwork(params["bbu_s1_subnet"])
                self.bbu_mgmt_subnet = IPNetwork(params["bbu_mgmt_subnet"])

            self.is_tarana = params.get("is_tarana", False)
            if self.is_tarana:
                self.tarana_subnet = IPNetwork(params["tarana_subnet"])
                self.tarana_sector_count = int(params.get("tarana_sector_count", 3))
                self.tarana_sector_start = int(params.get("tarana_sector_start", 0))
                # Accept custom sector port assignments from frontend
                self._custom_sectors = params.get("tarana_sectors", None)
                # Unicorn MGMT subnet (defaults to tarana_subnet if not provided)
                raw_unicorn = params.get("unicorn_mgmt_subnet") or str(self.tarana_subnet)
                self.unicorn_mgmt_subnet = IPNetwork(raw_unicorn)

                if self.tarana_sector_count > len(TARANA_SECTORS):
                    raise ValueError(
                        f"Tarana sector counts above {len(TARANA_SECTORS)} sectors are not supported."
                    )

            self.is_326 = params.get("is_326", False)
            if self.is_326:
                self.crs_326_mgmt_subnet = IPNetwork(params["326_mgmt_subnet"])

            self.is_6ghz = params.get("is_6ghz", False)
            if self.is_6ghz:
                self.six_ghz_subnet = IPNetwork(params["6ghz_subnet"])

            self.is_ub_wave = params.get("is_ub_wave", False)
            if self.is_ub_wave:
                self.ub_wave_subnet = IPNetwork(params["ub_wave_subnet"])

            self.enable_contractor_login = params.get("enable_contractor_login", False)
            self.switches = self._normalize_switches(params.get("switches", []) or [])
            self._ospf_auth_type = os.getenv("NEXTLINK_OSPF_AUTH_TYPE", "md5")
            self._ospf_auth_id = os.getenv("NEXTLINK_OSPF_AUTH_ID", "1")
            self._ospf_md5_key = os.getenv("NEXTLINK_OSPF_MD5_KEY", "m8M5JwvdYM")
            self._bgp_md5_key = str(
                params.get("bgp_md5_key")
                or os.getenv("NEXTLINK_BGP_MD5_KEY", "m8M5JwvdYM")
            ).strip()
            self.asn = str(params.get("asn", "26077")).strip()
            self.peer_1_name = str(params.get("peer_1_name", "CR7")).strip() or "CR7"
            self.peer_2_name = str(params.get("peer_2_name", "CR8")).strip() or "CR8"
            self.peer_1_address = self._strip_prefix(
                params.get("peer_1_address", "10.2.0.107/32")
            )
            self.peer_2_address = self._strip_prefix(
                params.get("peer_2_address", "10.2.0.108/32")
            )

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
                )):
                    raise ValueError(f"Invalid backhaul params: {backhaul}")
            self._validate_port_policy()
            self._validate_switch_policy()

        except KeyError as err:
            raise ValueError(f"Missing parameter: {err}")

        base_path = _base_config_path()
        config_template_path = str(base_path / "Router" / "BNG2" / "config")
        port_map_template_path = str(base_path / "Router" / "BNG2" / "port_map")

        # Configure jinja environment
        self.jinja_env = Environment(
            loader=FileSystemLoader([config_template_path, port_map_template_path])
        )
        self.jinja_env.trim_blocks = True
        self.jinja_env.lstrip_blocks = True

    def _validate_port_policy(self):
        policy = BNG2_PORT_POLICY.get(self.router_type)
        if not policy:
            return
        management_port = policy["management"]
        allowed_backhaul = set(policy["backhaul"])
        for backhaul in self.backhauls:
            port = str(backhaul.get("port", "")).strip()
            if port == management_port or port not in allowed_backhaul:
                raise ValueError(
                    f"Backhaul port '{port}' is not valid for {self.router_type}. "
                    f"Allowed backhaul ports: {sorted(allowed_backhaul)}"
                )

    def _validate_switch_policy(self):
        policy = BNG2_PORT_POLICY.get(self.router_type)
        if not policy:
            return
        management_port = policy["management"]
        backhaul_ports = {str(b.get("port", "")).strip() for b in self.backhauls}
        seen: set[str] = set()
        for sw in self.switches:
            port = str(sw.get("port", "")).strip()
            if not port:
                continue
            if port == management_port:
                raise ValueError(f"Switch uplink port '{port}' cannot be the management port.")
            if port in backhaul_ports:
                raise ValueError(f"Switch uplink port '{port}' collides with a backhaul port.")
            if port in seen:
                raise ValueError(f"Duplicate switch uplink port '{port}' is not allowed.")
            seen.add(port)

    @staticmethod
    def _normalize_switches(switches):
        out = []
        seen = set()
        for sw in list(switches or []):
            if not isinstance(sw, dict):
                continue
            port = str(sw.get("port", "")).strip()
            if not port or port in seen:
                continue
            seen.add(port)
            out.append(sw)
        return out

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
                port = str(custom[i]["port"]).strip()
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

        params["sysname"] = self.tower_name
        params["loopip"] = self.loop_ip.network
        params["gps"] = f"{self.latitude}, {self.longitude}"
        params["state_code"] = self.state_code
        params["bng1_ip"] = self.bng_1_ip
        params["bng2_ip"] = self.bng_2_ip
        params["OSPF_area"] = self.ospf_area
        params["state"] = MSTP_STATES[self.ospf_area]
        params["state_lc"] = str(params["state"]).lower()
        params["ospf_area_id"] = f"0.0.0.{self.ospf_area}"
        params["vpls1000"] = self.vlan_1000_cisco
        params["vpls2000"] = self.vlan_2000_cisco
        params["vpls3000"] = self.vlan_3000_cisco
        params["vpls4000"] = self.vlan_4000_cisco
        params["mpls_mtu"] = self.mpls_mtu
        params["vpls_l2mtu"] = self.vpls_l2_mtu
        params["ospf_auth_type"] = self._ospf_auth_type
        params["ospf_auth_id"] = self._ospf_auth_id
        params["ospf_md5_key"] = self._ospf_md5_key
        params["bgp_md5_key"] = self._bgp_md5_key
        params["asn"] = self.asn
        params["peer1_name"] = self.peer_1_name
        params["peer2_name"] = self.peer_2_name
        params["peer1"] = self.peer_1_address
        params["peer2"] = self.peer_2_address
        state_mesh_base = f"10.{self.ospf_area}.0"
        params["mesh_peer_1"] = str(params.get("mesh_peer_1") or f"{state_mesh_base}.3")
        params["mesh_peer_2"] = str(params.get("mesh_peer_2") or f"{state_mesh_base}.4")
        params["state_vpls_peer"] = str(params.get("state_vpls_peer") or f"{state_mesh_base}.1")

        params["is_lte"] = self.is_lte
        params["is_tarana"] = self.is_tarana
        params["is_switchless"] = self.is_switchless
        params["is_326"] = self.is_326
        params["is_6ghz"] = self.is_6ghz
        params["is_ub_wave"] = self.is_ub_wave
        params["enable_contractor_login"] = self.enable_contractor_login
        params["switches"] = self.switches

        return params

    def get_backhaul_params(self, params=None, num=None):
        if not params:
            params = {}

        params["backhauls"] = []

        for backhaul in [self.backhauls[num]] if num else self.backhauls:
            bh_net = IPNetwork(backhaul["subnet"])
            addr_offset = 1 if backhaul["master"] else bh_net.size - 4
            port_map_addr_offset = 2 if backhaul["master"] else 3

            params["backhauls"].append({
                "bhname": backhaul["name"],
                "port": backhaul["port"],
                "bhip": str(bh_net.network + addr_offset),
                "port_map_bhip": str(bh_net.network + port_map_addr_offset),
                "bhip_sub": str(bh_net.prefixlen),
                "bh_net": str(bh_net.network),
                "bh_gateway": str(bh_net.network + 1),
                "bh_netmask": bh_net.netmask,
            })

        return params

    def get_bbu_params(self, params=None):
        if not params:
            params = {}

        params["bbu_s1_gateway"] = str(self.bbu_s1_subnet.network + 1)
        params["bbu_s1_subnet"] = self.bbu_s1_subnet
        params["bbu_s1_subnet_mask"] = self.bbu_s1_subnet.prefixlen
        params["bbu_s1_subnet_network"] = self.bbu_s1_subnet.network
        params["bbu_mgmt_gateway"] = str(self.bbu_mgmt_subnet.network + 1)
        params["bbu_mgmt_ip"] = str(self.bbu_mgmt_subnet.network + 2)
        params["bbu_mgmt_subnet"] = str(self.bbu_mgmt_subnet.netmask)
        params["bbu_mgmt_subnet_mask"] = self.bbu_mgmt_subnet.prefixlen
        params["bbu_mgmt_subnet_network"] = self.bbu_mgmt_subnet.network
        params["bbu_port"] = BBU_PORT

        return params

    def get_tarana_params(self, params=None):
        if not params:
            params = {}

        params["tarana_sectors"] = []
        params["tarana_gateway"] = str(self.tarana_subnet.network + 1)
        params["tarana_subnet"] = self.tarana_subnet.netmask

        for sector in self.get_tarana_sectors():
            sector["address"] = str(
                self.tarana_subnet.network + sector["address_offset"]
            )
            params["tarana_sectors"].append(sector)

        # Unicorn MGMT subnet params for the template
        params["unicorn_mgmt_ip"] = str(self.unicorn_mgmt_subnet.network + 1)
        params["unicorn_mgmt_prefix"] = self.unicorn_mgmt_subnet.prefixlen
        params["unicorn_mgmt_network"] = str(self.unicorn_mgmt_subnet.network)

        return params

    def get_port_map_params(self, params=None):
        if not params:
            params = {}

        params["gateway"] = self.gateway.ip
        params["subnet"] = self.gateway.netmask
        params["gateway_ip"] = str(self.gateway.ip)
        params["gateway_prefix"] = self.gateway.prefixlen
        params["gateway_network"] = str(self.gateway.network)
        params["switch_ip"] = self.switch_ip
        params["switch"] = str(self.switch_ip.network)
        params["ups"] = str(self.switch_ip.network + 1)
        params["wps"] = str(self.switch_ip.network + 2)
        params["access_points"] = [
            str(self.switch_ip.network + 9 + x) for x in range(6)
        ]
        params["ap_model"] = AP_MODEL_6GHZ if self.is_6ghz else AP_MODEL_NON_6GHZ
        params["uplink_2"] = UPLINK_2_6GHZ if self.is_6ghz else UPLINK_2_NON_6GHZ

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

    def generate_config(self):
        params = self.get_base_params()
        params = self.get_backhaul_params(params)
        params = self.get_port_map_params(params)
        if self.is_lte:
            params = self.get_bbu_params(params)
        if self.is_tarana:
            params = self.get_tarana_params(params)
        if self.is_6ghz:
            params = self.get_6ghz_params(params)
        if self.is_ub_wave:
            params = self.get_ub_wave_params(params)
        if self.is_326:
            params = self.get_326_params(params)

        template = self.jinja_env.get_template(
            ROUTER_TYPES[self.router_type]["config_template"]
        )

        config_text = template.render(params)
        config_text = self._sanitize_transport_only_output(config_text)

        return config_text

    def generate_port_map(self):
        params = self.get_base_params()
        params = self.get_port_map_params(params)
        if self.is_lte:
            params = self.get_bbu_params(params)
        if self.is_tarana:
            params = self.get_tarana_params(params)
        params = self.get_backhaul_params(params)

        template = self.jinja_env.get_template(
            ROUTER_TYPES[self.router_type]["port_map_template"]
        )

        port_map_text = template.render(params)

        return port_map_text

    @staticmethod
    def _sanitize_transport_only_output(config_text: str) -> str:
        banned_fragments = (
            "lan-bridge",
            "nat-public-bridge",
            "/ip dhcp-server",
            "/ip pool",
            "address-pool=",
            "comment=Switch-Mgmt",
            "src-address-list=unauth",
        )
        seen = set()
        kept = []
        for line in str(config_text or "").splitlines():
            if any(fragment in line for fragment in banned_fragments):
                continue
            normalized = line.strip()
            if normalized and normalized in seen:
                continue
            if normalized:
                seen.add(normalized)
            kept.append(line)
        return "\n".join(kept).strip() + "\n"
