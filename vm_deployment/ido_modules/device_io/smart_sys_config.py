#!/usr/bin/python3

import logging
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime

import requests

from .util import *


BATTERY_CAPACITY = [
    ("Lithium Ion (200)", "200.0", "li_ion_200"),
    ("Lithium Ion (100)", "100.0", "li_ion_100"),
    ("Lead Acid (190)", "190.0", "lead_acid_190"),
    ("Lead Acid (100)", "100.0", "lead_acid_100"),
]

PRE_CHECK_ATTRIBUTES = [
    (
        "SC501 Firmware",
        "/data/about.xml",
        lambda values: values.get("version"),
        "V201",
    )
]

DEBUG = False

HELP_MESSAGE = (
    "Usage: %s [-i address] [-b capacity] [-c latitude,longitude]\n\
                \n\
            Available options:\n\
                -i,--ip-address        IP address of device to connect to\n\
                -b,--battery-capacity  Capacity of cabinet's batteries\n\
                -c,--coordinates       GPS coordinates of cabinet (comma-separated)\n\
                -h,--help              Show this help message\n\
                -p,--password          Password to use when logging into device"
    % (__file__.split("/")[-1])
)


class SmartSysConfig:
    def __init__(self, logstream=None, **params):
        self.ip_address = params["ip_address"]
        self.logger = logging.getLogger(__name__ + f"_{self.ip_address}")
        self.logger.setLevel(
            logging.DEBUG if params.get("debug") or DEBUG else logging.INFO
        )

        if logstream:
            log_handler = logging.StreamHandler(logstream)
            log_handler.setFormatter(ConfigLogFormatter())
            log_handler.setLevel(logging.INFO)
            self.logger.addHandler(log_handler)

        self.user = params.get("user", "admin")
        self.password = params.get("password", "170313")
        self.logged_in = False
        self.session = None

        self.site_name = params.get("site_name")
        self.site_id = params.get("site_id")
        self.site_addr = params.get("site_addr")
        self.latitude = params.get("latitude")
        self.longitude = params.get("longitude")
        self.altitude = params.get("altitude")
        self.trap_addr = params.get("trap_addr")
        self.snmp_community = params.get("snmp_community")
        self.battery_type = params.get("battery_type")
        self.battery_capacity = params.get("battery_capacity")
        self.device_number = params.get("device_number", "1")
        self.device_name = None

    @staticmethod
    def _decode_response(response):
        return response.content.decode("iso-8859-1", errors="replace")

    @staticmethod
    def _root_to_values(root):
        values = {}
        for child in root.iter():
            if "val" in child.attrib:
                values[child.tag] = child.attrib.get("val", "")
        return values

    @staticmethod
    def _build_xml(root_tag, values):
        root = ET.Element(root_tag)
        for key, value in values.items():
            element = ET.SubElement(root, key)
            element.set("val", "" if value is None else str(value))
        return ET.tostring(
            root, encoding="iso-8859-1", xml_declaration=True
        )

    @staticmethod
    def _battery_type_from_flag(flag):
        return "li_ion" if str(flag) == "1" else "lead_acid"

    @staticmethod
    def _coord_flag(value, positive_token):
        return positive_token if float(value) >= 0 else ("0" if positive_token == "1" else "1")

    @staticmethod
    def _dms_to_decimal(hemisphere, degrees, minutes, seconds):
        if degrees in (None, ""):
            return None
        deg = float(degrees)
        minute = float(minutes or 0)
        second = float(seconds or 0)
        decimal = deg + (minute / 60.0) + (second / 3600.0)
        return decimal if hemisphere in ("1", "0E", "1N", "E", "N") else -decimal

    @staticmethod
    def _format_decimal(value):
        if value in (None, ""):
            return None
        numeric = float(value)
        if numeric.is_integer():
            return str(int(numeric))
        return str(round(numeric, 6)).rstrip("0").rstrip(".")

    @staticmethod
    def _format_capacity(value):
        return f"{float(value):.1f}"

    def login(self):
        self.session = requests.Session()
        req = self.session.post(
            f"http://{self.ip_address}/data/login.cgi",
            params={"uid": int(time.time() * 1000)},
            data=(f"user={self.user}&password={self.password}").encode("ascii"),
            timeout=20,
        )
        if req.status_code != 200:
            raise Exception("Invalid IP address or host down.")

        return_code = req.text.strip()
        if return_code == "0":
            self.logged_in = True
            return

        raise Exception("Failed to login. Is the password correct?")

    def _get_xml(self, path, params=None):
        if not self.logged_in:
            raise Exception("Not logged in")

        query = dict(params or {})
        query.setdefault("uid", int(time.time() * 1000))
        url = f"http://{self.ip_address}{path}"
        req = self.session.get(url, params=query, timeout=20)
        if req.status_code != 200:
            raise Exception(f"Server returned code {req.status_code} while requesting {path}.")
        return ET.fromstring(self._decode_response(req))

    def _get_xml_values(self, path, params=None):
        root = self._get_xml(path, params=params)
        return root.tag, self._root_to_values(root)

    def _post_xml(self, path, data):
        self.logger.debug("%s\n%s" % (path, data.decode("iso-8859-1", errors="replace")))

        if not self.logged_in:
            raise Exception("Not logged in")

        url = f"http://{self.ip_address}{path}"
        req = self.session.post(
            url,
            headers={"Content-Type": "text/xml"},
            data=data,
            timeout=20,
        )
        if req.status_code != 200:
            raise Exception(
                "Server returned code %d while sending %s."
                % (req.status_code, path)
            )
        if req.text.strip() != "0":
            raise Exception(f"Device rejected {path}: {req.text.strip() or 'unknown error'}")
        return req

    def get_battery_status(self, cabinet_number=1):
        if not self.logged_in:
            self.login()

        try:
            batt_data = self._get_xml(
                "/data/batt_data.xml", {"dcCabNum": cabinet_number}
            )
            status = int(batt_data.find("./Summary/Status").attrib["val"])
        except Exception:
            return None

        if status in (1, 4):
            return "boost"
        if status == 2:
            return "float"
        if status == 0:
            return "discharge"
        return str(status)

    def _get_battery_capacity(self, battery_number=1):
        if not self.logged_in:
            self.login()

        _, batt_data = self._get_xml_values("/data/battbasicconfig.xml")
        key = f"Batt{battery_number}TotCap"
        if key not in batt_data:
            raise Exception("Failed to determine battery capacity from device.")
        return float(batt_data[key])

    def _apply_about_config(self):
        root_tag, values = self._get_xml_values("/data/about.xml")
        if self.site_name:
            values["siteName"] = self.site_name
        if self.site_id:
            values["siteID"] = self.site_id
        if self.site_addr:
            values["siteAddr"] = self.site_addr
        if self.latitude not in (None, "") and self.longitude not in (None, ""):
            lat_deg, lat_min, lat_sec = convert_coord_to_dms(self.latitude)
            lon_deg, lon_min, lon_sec = convert_coord_to_dms(self.longitude)
            values["Lati"] = "1" if float(self.latitude) >= 0 else "0"
            values["LatiDegree"] = str(lat_deg)
            values["LatiMinu"] = str(lat_min)
            values["LatiSec"] = str(lat_sec)
            values["Long"] = "0" if float(self.longitude) >= 0 else "1"
            values["LongDegree"] = str(lon_deg)
            values["LongMinu"] = str(lon_min)
            values["LongSec"] = str(lon_sec)
        if self.altitude not in (None, ""):
            values["altitude"] = self._format_decimal(self.altitude)
        self._post_xml("/data/about.cgi", self._build_xml(root_tag, values))

    def _apply_battery_config(self):
        root_tag, values = self._get_xml_values("/data/battbasicconfig.xml")
        formatted_capacity = self._format_capacity(self.battery_capacity)
        for key in list(values.keys()):
            if re.fullmatch(r"Batt\d+TotCap", key):
                values[key] = formatted_capacity
        self._post_xml(
            "/data/battbasicconfig.cgi", self._build_xml(root_tag, values)
        )

    def _apply_snmp_config(self):
        root_tag, values = self._get_xml_values("/data/SNMPconfig.xml")
        if self.trap_addr:
            values["TrapEn"] = "1"
            values["TrapAddr1"] = self.trap_addr
        if self.snmp_community:
            values["Community1"] = self.snmp_community
        self._post_xml("/data/commconfig.cgi", self._build_xml(root_tag, values))

    def send_configuration(self):
        if self.site_name or self.latitude not in (None, "") or self.longitude not in (None, "") or self.altitude not in (None, ""):
            self.logger.info("Sending site metadata and coordinate update.")
            self._apply_about_config()
        if self.battery_capacity not in (None, ""):
            self.logger.info("Sending battery capacity update.")
            self._apply_battery_config()
        if self.trap_addr or self.snmp_community:
            self.logger.info("Sending SNMP trap update.")
            self._apply_snmp_config()

    def init_and_configure(self):
        required_params = [
            self.ip_address,
            self.site_name,
            self.latitude,
            self.longitude,
            self.battery_capacity,
            self.trap_addr,
        ]

        if not all(x not in (None, "") for x in required_params):
            raise Exception("Missing required value.")

        self.login()
        self.logger.info("Logged in.")
        self.send_configuration()
        self.device_name = f"UPS-SS{self.device_number}.{self.site_name}"
        self.logger.info("\nConfiguration finished.")

    @staticmethod
    def request_params(default_params={}, **params):
        if not params.get("use_default"):
            if not params.get("ip_address"):
                params["ip_address"] = input("[?] IP address: ")
            if not params.get("site_name"):
                params["site_name"] = input("[?] Site name: ")
            if not params.get("device_number"):
                params["device_number"] = input_default("[?] Device number: ", "1")
            if not params.get("latitude"):
                params["latitude"] = input("[?] Site latitude: ")
            if not params.get("longitude"):
                params["longitude"] = input("[?] Site longitude: ")
            if not params.get("trap_addr"):
                params["trap_addr"] = input("[?] Trap address: ")

        try:
            if not params.get("battery_capacity"):
                ss = SmartSysConfig(**params)
                params["battery_capacity"] = ss._get_battery_capacity()
            if not params.get("battery_capacity"):
                raise Exception()
        except Exception:
            use_callback_or_print(
                "Could not determine battery type from device.", params.get("on_log")
            )
            params["battery_capacity"] = prompt_list(
                "Enter battery type: ", BATTERY_CAPACITY
            )[1]

        use_callback_or_print("", params.get("on_log"))
        use_callback_or_print(
            "IP Address: %s" % (params.get("ip_address")), params.get("on_log")
        )
        use_callback_or_print(
            "Latitude: %s deg" % (str(params.get("latitude"))), params.get("on_log")
        )
        use_callback_or_print(
            "Longitude: %s deg" % (str(params.get("longitude"))),
            params.get("on_log"),
        )
        use_callback_or_print(
            "Battery capacity: %s Ah" % (str(params.get("battery_capacity"))),
            params.get("on_log"),
        )

        return params

    def pre_check(self):
        if not self.session:
            self.login()

        attributes = []
        battery_status = self.get_battery_status()
        attributes.append(
            (
                "Battery status",
                battery_status or "unsupported",
                "float",
                None if battery_status is None else battery_status == "float",
            )
        )

        for attribute in PRE_CHECK_ATTRIBUTES:
            _, values = self._get_xml_values(attribute[1])
            result = attribute[2](values)
            attributes.append(
                (attribute[0], result, attribute[3], attribute[3] in str(result))
            )

        return attributes

    @staticmethod
    def get_device_info(ip_address, device_type, password=None, run_tests=False):
        result = {}

        params = {
            "ip_address": ip_address,
            "device_type": device_type,
        }

        if password:
            params["password"] = password

        try:
            d = SmartSysConfig(**params, use_default=True)
            d.login()

            _, about = d._get_xml_values("/data/about.xml")
            _, equipment = d._get_xml_values("/data/equipment.xml")
            _, batt_basic = d._get_xml_values("/data/battbasicconfig.xml")
            _, sysconfig = d._get_xml_values("/data/sysconfig.xml")
            _, snmp = d._get_xml_values("/data/SNMPconfig.xml")

            latitude = SmartSysConfig._dms_to_decimal(
                "N" if about.get("Lati") == "1" else "S",
                about.get("LatiDegree"),
                about.get("LatiMinu"),
                about.get("LatiSec"),
            )
            longitude = SmartSysConfig._dms_to_decimal(
                "E" if about.get("Long") == "0" else "W",
                about.get("LongDegree"),
                about.get("LongMinu"),
                about.get("LongSec"),
            )

            result.update(
                {
                    "success": True,
                    "model": about.get("model") or equipment.get("model"),
                    "firmware": about.get("version") or equipment.get("swVer"),
                    "site_name": about.get("siteName"),
                    "site_id": about.get("siteID"),
                    "site_address": about.get("siteAddr"),
                    "latitude": latitude,
                    "longitude": longitude,
                    "altitude": about.get("altitude"),
                    "battery_capacity": float(batt_basic.get("Batt1TotCap", "0") or 0),
                    "battery_type": SmartSysConfig._battery_type_from_flag(
                        sysconfig.get("BattTyp")
                    ),
                    "trap_addr": snmp.get("TrapAddr1"),
                    "snmp_community": snmp.get("Community1"),
                    "trap_enabled": snmp.get("TrapEn") == "1",
                }
            )

            if run_tests:
                result["test_results"] = [
                    {"name": x[0], "expected": x[2], "actual": x[1], "pass": x[3]}
                    for x in d.pre_check()
                ]
        except Exception as err:
            result["success"] = False
            result["message"] = str(err)

        return result


def main():
    def parse_CLI_args(args, delimiter=" "):
        if isinstance(args, str):
            args = args.split(delimiter)

        result = {}
        while len(args) > 0:
            if "-" not in args[0]:
                args.pop(0)
            else:
                val = args[0].split("=")[0]
                if val == "--ip-address" or val == "-i":
                    if "=" not in args[0]:
                        args.pop(0)
                    else:
                        args[0] = args[0].split("=")[1]
                    result["ip_address"] = args[0]
                elif val == "--battery-capacity" or val == "-b":
                    if "=" not in args[0]:
                        args.pop(0)
                    else:
                        args[0] = args[0].split("=")[1]
                    result["battery_capacity"] = args[0]
                elif val == "--coordinates" or val == "-c":
                    if "=" not in args[0]:
                        args.pop(0)
                    else:
                        args[0] = args[0].split("=")[1]
                    result["latitude"], result["longitude"] = args[0].split(",")
                elif val == "--password" or val == "-p":
                    if "=" not in args[0]:
                        args.pop(0)
                    else:
                        args[0] = args[0].split("=")[1]
                    result["password"] = args[0]
                elif val == "-h" or val == "--help":
                    print(HELP_MESSAGE)
                    exit()
                else:
                    print("Unrecognized option `%s`\n" % (args[0]))
                    print(HELP_MESSAGE)
                    exit()
                args.pop(0)
        return result

    params = SmartSysConfig.request_params(**parse_CLI_args(sys.argv))
    ssc = SmartSysConfig(**params)
    ssc.init_and_configure()


if __name__ == "__main__":
    main()
