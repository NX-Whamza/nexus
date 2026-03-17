#!/usr/bin/python3

import os
import sys
import logging
import re
import json
from .util import (
    get_item,
    input_default,
    prompt_list,
    ConfigLogFormatter,
    snmp_walk,
)
import snimpy.manager
import snimpy.snmp

# Config files defined within DEVICE_TYPES list
_BASE_CONFIG_ROOT = os.getenv("BASE_CONFIG_PATH") or os.getenv("FIRMWARE_PATH") or ""
BASE_CONFIG_PATH = os.path.join(_BASE_CONFIG_ROOT, "ICT", "UPS") + "/" if _BASE_CONFIG_ROOT else ""

MIB_PATH = "/usr/share/snmp/mibs/"

DEFAULT_COMMUNITY = os.getenv("SNMP_COMMUNITY")

DEBUG = False


"""
    name                Name of the device model, according to device
                         naming conventions.
    firmware_standard   Expected firmware to check against during precheck.
    config_file         Name of base config file.
    model_keyword       Device model number, as it appears in the device 
                         interface, or SNMP. Used to verify device model.
"""
DEVICE_TYPES = [
    {
        "name": "ICT800",
        "firmware_standard": "",
        "config_file": "ICT800.json",
        "model_keyword": "ICT800",
    },
    {
        "name": "ICTMPS",
        "firmware_standard": "",
        "config_file": "ICTMPS.json",
        "model_keyword": "ICTMPS",
    },
]

SNMP_MIBS = [
    "ICT-COMMON-MIB.mib",
    "ICT-PLATINUM-MIB.mib",
    "ietf/SNMPv2-MIB",
    "ICT-POWERSYSTEM-MIB.mib",
]

BATTERY_TYPES = [("Lead Acid", 1), ("Lithium Ion", 2)]

HELP_MESSAGE = (
    "Usage: %s [-i address] [-b type] [-c latitude,longitude]\n\
                \n\
            Available options:\n\
                -i,--ip-address        IP address of device to connect to\n\
                -b,--battery-type      Type of cabinet's batteries\n\
                -c,--coordinates       GPS coordinates of cabinet (comma-separated)\n\
                -h,--help              Show this help message\n\
                -p,--password          Password to use when logging into device"
    % (__file__.split("/")[-1])
)


class ICTUPSConfig:
    def __init__(self, logstream=None, **params):
        # Instance of snimpy manager
        self.snmp_manager = None

        try:
            self.ip_address = params["ip_address"]
            self.snmp_community = params.get("snmp_community", DEFAULT_COMMUNITY)
            self.battery_type = params.get("battery_type") or self._get_battery_type()
            self.battery_capacity = params.get("battery_capacity")
            self.site_name = params.get("site_name")
            if isinstance(params.get("device_type"), dict):
                self.device_type = params.get("device_type")
            elif isinstance(params.get("device_type"), str):
                self.device_type = get_item(params.get("device_type"), DEVICE_TYPES)

            # Log callback
            self.on_log = params.get("on_log")

        except KeyError as err:
            raise ValueError("Missing required parameter: %s" % (err))

        self.logger = logging.getLogger(__name__ + f"_{self.ip_address}")
        self.logger.setLevel(
            logging.DEBUG if params.get("debug") or DEBUG else logging.INFO
        )

        if logstream:
            log_handler = logging.StreamHandler(logstream)
            log_handler.setFormatter(ConfigLogFormatter())
            log_handler.setLevel(logging.INFO)
            self.logger.addHandler(log_handler)

        # Parameters to replace within value strings in base config
        self.substitutions = {
            "battery_type": self.battery_type,
            "device_name": "UPS-%s.%s" % (self.device_type.get("name"), self.site_name),
        }

        if self.battery_capacity:
            self.substitutions["battery_capacity"] = self.battery_capacity

    def _init_snmp(self):
        self.snmp_manager = snimpy.manager.Manager(self.ip_address, self.snmp_community)
        for mib in SNMP_MIBS:
            snimpy.manager.load(MIB_PATH + mib)

    def _get_battery_type(self):
        if not self.snmp_manager:
            self._init_snmp()

        return int(self.snmp_manager.batteryType)

    def _get_formatted_keys(self):
        # Defaults to BASE_CONFIG_PATH/<device name>.json if no
        # config file is set
        path = BASE_CONFIG_PATH + self.device_type.get(
            "config_file", "%s.json" % (self.device_type.get("name"))
        )

        with open(path, "r") as f:
            keys = json.load(f)

        # Return array of (key, index, value) tuples
        keys_formatted = []
        for key in keys.items():
            # If the key has a trailing index (e.g. .0) parse and return,
            # otherwise assume 0
            if index_match := re.match(r"^(.*)\.(\d+)$", key[0]):
                keys_formatted.append(
                    (
                        index_match.group(1),
                        index_match.group(2) or 0,
                        self._format_key_value(key[1]),
                    )
                )
            else:
                keys_formatted.append((key[0], 0, self._format_key_value(key[1])))

        return keys_formatted

    def _send_configuration(self):
        try:
            keys = self._get_formatted_keys()

            for key in keys:
                try:
                    if key[1] > 0:
                        # if index > 0, get column, set item in column to value
                        column = getattr(self.snmp_manager, key[0])
                        column[key[1] - 1] = key[2]
                        setattr(self.snmp_manager, key[0], column)
                    else:
                        setattr(self.snmp_manager, key[0], key[2])
                    self.logger.info(
                        "Set %s to %s."
                        % (key[0] + ("[%s]" % key[1] if key[1] > 0 else ""), key[2])
                    )
                except snimpy.snmp.SNMPException as err:
                    raise Exception(
                        "Error while setting %s to %s: %s"
                        % (
                            key[0] + ("[%s]" % key[1] if key[1] > 0 else ""),
                            key[2],
                            type(err).__name__,
                        )
                    )

        except ValueError as err:
            raise Exception("Error while configuring: \n%s" % err)

    def init_and_configure(self):
        if not self.snmp_manager:
            self._init_snmp()
        self._send_configuration()
        self.logger.info("\nConfiguration finished.")

    def _format_key_value(self, value):
        if isinstance(value, str):
            # Replace {var} substitutions with value in self.substitutions
            try:
                return value.format(
                    **{
                        # Call substitution if callable,
                        # otherwise use value converted to str
                        k: v() if callable(v) else str(v)
                        for k, v in self.substitutions.items()
                    }
                )
            except KeyError as err:
                raise Exception(
                    "Error while substituting base config parameters: "
                    + "%s not found in defined substitutions. " % (err)
                )
        else:
            return value

    def request_params(default_params={}, use_default=False, **params):
        if params.get("ip_address") is None:
            params["ip_address"] = input_default(
                "[?] IP Address: ",
                default_params.get("ip_address"),
                use_default=use_default,
            )
        if params.get("site_name") is None:
            params["site_name"] = input_default(
                "[?] Site name: ",
                default_params.get("site_name"),
                use_default=use_default,
            )
        if params.get("device_type") is None:
            params["device_type"] = prompt_list(
                "[?] Select device type: ",
                DEVICE_TYPES,
                default_params.get("device_type"),
                use_default=use_default,
            )
        # if params.get("battery_type") is None:
        #    params["battery_type"] = prompt_list(
        #        "[?] Select battery type: ", BATTERY_TYPES,
        #        default_params.get("battery_type"), use_default=use_default
        #    )[1]

        if isinstance(params.get("device_type"), dict):
            params["name"] = "UPS-%s.%s" % (
                params.get("device_type").get("name"),
                params.get("site_name"),
            )
        return params

    def pre_check(self):
        results = []

        if not self.snmp_manager:
            self._init_snmp()

        results.append(
            (
                "Input voltage",
                "%s VAC" % self.snmp_manager.inputVoltage.decode("utf-8"),
                ">90 VAC",
                int(self.snmp_manager.inputVoltage) > 90,
            )
        )

        results.append(
            (
                "Battery voltage",
                "%s VDC" % self.snmp_manager.batteryVoltage.decode("utf-8"),
                ">46 VDC",
                float(self.snmp_manager.batteryVoltage) > 46,
            )
        )

        results.append(
            (
                "Output current",
                "%s A" % self.snmp_manager.outputCurrent.decode("utf-8"),
                "<15 A",
                float(self.snmp_manager.outputCurrent) < 15,
            )
        )

        results.append(
            (
                "Battery charge state",
                "%s%%" % str(self.snmp_manager.batterySoc),
                "100%",
                self.snmp_manager.batterySoc == 100,
            )
        )

        # results.append((
        #    "Device model",
        #    self.snmp_manager.deviceModel.decode("utf-8"),
        #    self.device_type.get("model_keyword"),
        #    self.device_type.get("model_keyword") in
        #    self.snmp_manager.deviceModel.decode("utf-8")
        # ))

        return results

    @staticmethod
    def _pretty_print_snmp(values):
        text = ""

        oids = sorted(values.items(), key=lambda x: x[0])
        for oid, oid_values in oids:
            index_values = sorted(oid_values.items(), key=lambda x: int(x[0] or 0))

            for index, index_value in index_values:
                text += f"{oid}.{index}: {index_value}\n"

        # for oid, value in values.items():
        # if not any([x or x == 0 for x in value.keys()]):
        #     text += f"{oid}: {list(value.values())[0]}\n"
        #     continue
        #
        # max_index = max([int(x) for x in value.keys() if x or x == 0])
        # items = [str(value.get(str(i), "")) or "" for i in range(max_index)]
        # text += (
        #     f"{oid}: [ {', '.join(items)} ]\n"
        #     if items and len(items) > 1
        #     else f"{oid}: {list(value.values())[0]}\n"
        # )

        return text

    def get_running_config(self):
        config = snmp_walk(
            self.ip_address,
            os.getenv("SNMP_COMMUNITY"),
            mib_folder=MIB_PATH,
            mib_modules=SNMP_MIBS,
        )

        return self._pretty_print_snmp(config)

    def get_standard_config(self):
        config = self._get_formatted_keys()

        config_dict = {}

        for key, index, value in config:
            if not config_dict.get(key):
                config_dict[key] = {}

            config_dict[key][index] = value

        return self._pretty_print_snmp(config_dict)

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
            d = ICTUPSConfig(**params)
            if run_tests:
                result["test_results"] = [
                    {"name": x[0], "expected": x[2], "actual": x[1], "pass": x[3]}
                    for x in d.pre_check()
                ]

            result["success"] = True

        except Exception as err:
            result["success"] = False
            result["message"] = err

        return result


def main():
    def parse_cli_args(args, delimiter=" "):
        # Split args into array if it is a string
        if isinstance(args, str):
            args = args.split(delimiter)

        result = {}
        while len(args) > 0:
            if "-" not in args[0]:
                args.pop(0)
            else:
                val = args[0].split("=")[0]
                if val == "-d" or val == "--device-type":
                    if "=" not in args[0]:
                        args.pop(0)
                    else:
                        args[0] = args[0].split("=")[1]
                    result["device_type"] = get_item(args[0], DEVICE_TYPES)
                elif val == "-n" or val == "--site-name":
                    if "=" not in args[0]:
                        args.pop(0)
                    else:
                        args[0] = args[0].split("=")[1]
                    result["site_name"] = args[0]
                elif val == "-i" or val == "--ip-address":
                    if "=" not in args[0]:
                        args.pop(0)
                    else:
                        args[0] = args[0].split("=")[1]
                    result["ip_address"] = args[0]
                elif val == "-b" or val == "--battery-type":
                    if "=" not in args[0]:
                        args.pop(0)
                    else:
                        args[0] = args[0].split("=")[1]
                    result["battery_type"] = get_item(args[0], BATTERY_TYPES)[1]
                elif val == "-c" or val == "--community":
                    if "=" not in args[0]:
                        args.pop(0)
                    else:
                        args[0] = args[0].split("=")[1]
                    result["snmp_community"] = args[0]
                elif val == "-h" or val == "--help":
                    print(HELP_MESSAGE)
                    exit()

        return result

    ict = ICTUPSConfig(**ICTUPSConfig.request_params(**parse_cli_args(sys.argv)))
    ict.init_and_configure()


if __name__ == "__main__":
    main()
