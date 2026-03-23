#!/usr/bin/python3

import sys
import requests
import re
import logging
import urllib
import time
from bs4 import BeautifulSoup
import os
from datetime import datetime
from .util import *


_BASE_CONFIG_ROOT = os.getenv("BASE_CONFIG_PATH") or os.getenv("FIRMWARE_PATH") or ""
BASE_PATH = os.path.join(_BASE_CONFIG_ROOT, "SmartSys") + "/" if _BASE_CONFIG_ROOT else ""


BATTERY_CAPACITY = [
    ("Lithium Ion (200)", "200.0", "li_ion_200"),
    ("Lithium Ion (100)", "100.0", "li_ion_100"),
    ("Lead Acid (190)", "190.0", "lead_acid_190"),
    ("Lead Acid (100)", "100.0", "lead_acid_100"),
]

PRE_CHECK_ATTRIBUTES = [
    # (human-readable, address, xml, expected value)
    (
        "SC501 Firmware",
        "/data/equipment.xml",
        lambda x: x.EquipmentInfo.Unit.swVer["val"],
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
        self.cookies = ""

        self.latitude = params.get("latitude")
        self.longitude = params.get("longitude")

        self.trap_addr = params.get("trap_addr")

        self.battery_type = params.get("battery_type")
        self.battery_capacity = params.get(
            "battery_capacity", self._get_battery_capacity()
        )

        # Lambda functions assigned to keys for replacement of "{key}" in base config files
        self.substitutions = {
            "year": lambda: datetime.now().year,
            "month": lambda: datetime.now().month,
            "day": lambda: datetime.now().day,
            "hour": lambda: datetime.now().hour,
            "minute": lambda: datetime.now().minute,
            "second": lambda: datetime.now().second,
            "LatiDegree": lambda: convert_coord_to_dms(self.latitude)[0],
            "LatiMinu": lambda: convert_coord_to_dms(self.latitude)[1],
            "LatiSec": lambda: convert_coord_to_dms(self.latitude)[2],
            "LongDegree": lambda: convert_coord_to_dms(self.longitude)[0],
            "LongMinu": lambda: convert_coord_to_dms(self.longitude)[1],
            "LongSec": lambda: convert_coord_to_dms(self.longitude)[2],
            "Batt1TotCap": lambda: f"{float(self.battery_capacity):.1f}",
            "TrapAddr": lambda: self.trap_addr,
            "battType": lambda: ("1" if self.battery_type == "li_ion" else "0"),
        }

        self.session = None

    def login(self):
        self.session = requests.Session()
        req = self.session.post(
            f"http://{self.ip_address}/data/login.cgi",
            params={"uid": time.time() * 1000},
            data=(f"user={self.user}&password={self.password}").encode("ascii"),
        )
        if req.status_code != 200:
            raise Exception("Invalid IP address or host down.")

        return_code = req.content.decode("ascii")

        if return_code == "0":
            self.logged_in = True

            # Set cookies required for further requests
            self.cookies = "User=%s; Language=0; LogTime=%s" % (
                self.user,
                str(int(time.time() * 1000)),
            )
            return

        raise Exception("Failed to login. Is the password correct?")

    def _get_xml(self, path, params={}):
        # path: Path of file, including leading slash
        if not self.logged_in:
            raise Exception("Not logged in")

        params["uid"] = int(time.time() * 1000)
        url = "http://%s%s?" % (self.ip_address, path) + urllib.parse.urlencode(params)
        req = self.session.get(url)

        return BeautifulSoup(req.content.decode("ascii"), "xml")

    def _post_xml(self, path, data, params={}):
        self.logger.debug("%s\n%s" % (path, data))

        if not self.logged_in:
            raise Exception("Not logged in")

        params["uid"] = int(time.time() * 1000)
        url = "http://%s%s?" % (self.ip_address, path) + urllib.parse.urlencode(params)
        req = requests.post(
            url,
            headers={
                "Content-Type": "text/xml",
            },
            data=data.encode("ascii"),
        )
        return req

    def get_battery_status(self, cabinet_number=1):
        if not self.logged_in:
            self.login()

        batt_data = self._get_xml("/data/batt_data.xml", {"dcCabNum": cabinet_number})

        # print(batt_data)
        # print(batt_data.BatteryData.Summary.Status["val"])
        status = int(batt_data.BatteryData.Summary.Status["val"])
        if status in (1, 4):
            return "boost"
        if status == 2:
            return "float"
        if status == 0:
            return "discharge"

        raise Exception("Failed to get battery status.")

    def _get_battery_capacity(self, battery_number=1):
        if not self.logged_in:
            self.login()

        batt_data = self._get_xml("/data/battbasicconfig.xml")
        # {"dcCabNum": cabinet_number})

        return float(
            eval('batt_data.BattBasicConfig.Batt%sTotCap["val"]' % str(battery_number))
        )

    def _replace_keywords(self, xml):
        try:  # If value is a lambda, execute to get value, else get value
            return xml.format(
                **{
                    k: v() if callable(v) else str(v)
                    for k, v in self.substitutions.items()
                }
            )
        except KeyError:
            raise Exception("Missing required parameters.")

    def send_configuration(self):
        for file in os.listdir(BASE_PATH):
            self.logger.info(f"Sending configuration file {file}.")
            xml = self._replace_keywords(self._read_file(BASE_PATH + file))
            xml = re.split(r"\r?\n---\r?\n", xml)
            for data in xml:
                response = self._post_xml("/data/" + file, data)
                if response.status_code != 200:
                    raise Exception(
                        "Server returned code %d while sending file %s with message: \n%s"
                        % (response.status, file, response.reason)
                    )

    def init_and_configure(self):
        required_params = [
            self.latitude,
            self.longitude,
            self.battery_capacity,
            self.ip_address,
        ]

        if not all(required_params):
            raise Exception("Missing required value.")

        self.login()
        self.logger.info("Logged in.")
        self.send_configuration()

        self.logger.info("\nConfiguration finished.")

    @staticmethod
    def request_params(default_params={}, **params):
        if not params.get("use_default"):
            if not params.get("ip_address"):
                params["ip_address"] = input("[?] IP address: ")
            if not params.get("latitude"):
                params["latitude"] = input("[?] Site latitude: ")
            if not params.get("longitude"):
                params["longitude"] = input("[?] Site longitude: ")
            if not params.get("wattage"):
                params["wattage"] = input("[?] Wattage: ")
            if not params.get("voltage"):
                params["voltage"] = input("[?] Voltage: ")
            if not params.get("device_number"):
                params["device_number"] = input_default("[?] Device number: ", "1")

            params["name"] = "UPS-SS%s-%s-%s.%s" % (
                params.get("wattage"),
                params.get("voltage"),
                int(params.get("device_number")),
                params.get("site_name"),
            )

        # f not params.get("battery_capacity"):
        #   params["battery_capacity"] = prompt_list(
        #       "Enter battery type: ", BATTERY_CAPACITY)[1]
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

    @staticmethod
    def _read_file(path):
        with open(path, "r") as file:
            return file.read()

    def pre_check(self):
        if not self.session:
            self.login()

        attributes = []
        attributes.append(
            (
                "Battery status",
                self.get_battery_status(),
                "float",
                self.get_battery_status() == "float",
            )
        )

        for attribute in PRE_CHECK_ATTRIBUTES:
            result = attribute[2](self._get_xml(attribute[1]))
            attributes.append(
                (attribute[0], result, attribute[3], attribute[3] in result)
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

            if run_tests:
                result["test_results"] = [
                    {"name": x[0], "expected": x[2], "actual": x[1], "pass": x[3]}
                    for x in d.pre_check()
                ]

            # TODO: logout
            result["success"] = True
        except Exception as err:
            result["success"] = False
            result["message"] = err

        return result


def main():
    # Command-line argument parsing
    #   Accepts either an array of strings or a string
    def parse_CLI_args(args, delimiter=" "):
        # Split args into array if string
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
    # print(ssc.get_battery_status())
    ssc.init_and_configure()


if __name__ == "__main__":
    main()
