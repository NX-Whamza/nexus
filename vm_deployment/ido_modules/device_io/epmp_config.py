from datetime import datetime
import json
import pathlib
import os
import re
import time
import math
from zoneinfo import ZoneInfo

# from .util import *
from .util import ConfigLogFormatter, get_item, timezone_at, haversine_distance
from enum import Enum
import requests
from requests.packages import urllib3
import logging
import logging.handlers
from .update_cn_ap import update_cn_ap

# Additional logging
DEBUG = os.getenv("NETLAUNCH_TOOLS_DEBUG", False)

CONF_TEMPLATE_PATH = os.getenv("BASE_CONFIG_PATH", "") + "/Cambium/"

DEFAULT_USER = "admin"
# List of passwords to use to attempt to login, if not specified or incorrect.
# The device's password is changed to the first entry in this list.
AP_PASSWORDS = [os.getenv("AP_STANDARD_PW"), "admin", os.getenv("SM_STANDARD_PW")]
SM_PASSWORDS = [os.getenv("SM_STANDARD_PW"), "admin", os.getenv("AP_STANDARD_PW")]

# Maximum number of parameters to send at once.
MAX_CONFIG_SIZE = 1000

# Maximum time to wait for config to apply after sending configuration
CONFIG_APPLY_TIMEOUT = 300

LOGIN_CHECK_TIMEOUT = 10
REQUEST_TIMEOUT = 5

LOCATION_ALLOWED_ERR = 100  # meters

# antennas: (name, config file, naming code)
ANTENNAS = {
    "EP3K": [
        ("Cambium CN090", "CN090_config.json", "CN090"),
        ("Alpha AL060", "AL060_config.json", "AL060"),
        ("RF Elements RFA090", "RFA090_config.json", "RFA090"),
    ],
    "EP3KL": [
        ("Cambium CN090", "CN090_config.json", "CN090"),
        ("Alpha AL060", "AL060_config.json", "AL060"),
        ("RF Elements RFA090", "RFA090_config.json", "RFA090"),
    ],
    "4600": [
        ("Alpha AL060", "AL060_config.json", "AL060"),
    ],
    "F300-CSM": [
        ("UltraDish TP 550", "TP550_config.json", "TP550"),
        ("UltraDish TP 27", "TP27_config.json", "TP27"),
        ("UltraDish TP 24", "TP24_config.json", "TP24"),
    ],
}

# Full name, device code, identifier, frequency band
AP_TYPES = [
    ("Cambium ePMP 3000", "CNEP3K", "EP3K", "5", "AP"),
    ("Cambium ePMP 3000 Lite", "CNEP3KL", "EP3KL", "5", "AP"),
    ("Cambium ePMP 4600", "CN4600", "4600", "6", "AP"),
    ("Cambium ePMP Force 4600C", "F4600C", "F4600C", "6", "SM"),
    ("Cambium ePMP Force 4525", "F4525", "F4525", "5", "SM"),
    ("Cambium ePMP Force 300-13", "F300-13", "F300-13", "5", "SM"),
    ("Cambium ePMP Force 300-16", "F300-16", "F300-16", "5", "SM"),
    ("Cambium ePMP Force 300-25", "F300-25", "F300-25", "5", "SM"),
    ("Cambium ePMP Force 300-CSM", "F300-CSM", "F300-CSM", "5", "SM"),
]

"""
Attributes to return during pre-check. (dashboard name, label, expected value)
"""
PRE_CHECK_ATTRIBUTES = {
    "EP3K": [
        ("cambiumCurrentSWInfo", "Firmware Version", "5.10.1"),
        ("cambiumEffectiveDeviceName", "Device Name", None),
        ("cambiumHWInfo", "Device SKU", ["37", "40"]),
    ],
    "EP3KL": [
        ("cambiumCurrentSWInfo", "Firmware Version", "5.10.1"),
        ("cambiumEffectiveDeviceName", "Device Name", None),
        ("cambiumHWInfo", "Device SKU", ["43", "44"]),
    ],
    "4600": [
        ("cambiumCurrentSWInfo", "Firmware Version", r"5\.10\.4"),
        ("cambiumEffectiveDeviceName", "Device Name", None),
        ("cambiumHWInfo", "Device SKU", ["53264"]),
    ],
    "F4600C": [
        ("cambiumCurrentSWInfo", "Firmware Version", r"5\.10\.4"),
        ("cambiumEffectiveDeviceName", "Device Name", None),
    ],
}

#   Valid frequency ranges (start inclusive, stop exclusive)
VALID_FREQUENCIES = {
    "EP3K": [*range(5190, 5315, 5), *range(5510, 5700, 5), *range(5745, 5875, 5)],
    "EP3KL": [*range(5190, 5315, 5), *range(5510, 5700, 5), *range(5745, 5875, 5)],
    "4600": [
        *range(5745, 5980, 5),
        6005,
        6010,
        6015,
        6020,
        6025,
        6030,
        6035,
        6040,
        6045,
        6050,
        6055,
        6060,
        6065,
        6070,
        6075,
        6080,
        6085,
        6090,
        6095,
        6100,
        6105,
        6110,
        6115,
        6120,
        6125,
        6130,
        6135,
        6140,
        6145,
        6150,
        6155,
        6160,
        6165,
        6170,
        6175,
        6180,
        6185,
        6190,
        6195,
        6200,
        6205,
        6210,
        6215,
        6220,
        6225,
        6230,
        6235,
        6240,
        6245,
        6250,
        6255,
        6260,
        6265,
        6270,
        6275,
        6280,
        6285,
        6290,
        6295,
        6300,
        6305,
        6310,
        6315,
        6320,
        6325,
        6330,
        6335,
        6340,
        6345,
        6350,
        6355,
        6360,
        6365,
        6370,
        6375,
        6380,
        6385,
        6390,
        6395,
        6400,
        6405,
        6410,
        6415,
        6420,
        6425,
        6430,
        6435,
        6440,
        6445,
        6450,
        6455,
        6460,
        6465,
        6470,
        6475,
        6480,
        6485,
        6490,
        6495,
        6500,
        6505,
        6510,
        6515,
        6520,
        6525,
        6530,
        6535,
        6540,
        6545,
        6550,
        6555,
        6560,
        6565,
        6570,
        6575,
        6580,
        6585,
        6590,
        6595,
        6600,
        6605,
        6610,
        6615,
        6620,
        6625,
        6630,
        6635,
        6640,
        6645,
        6650,
        6655,
        6660,
        6665,
        6670,
        6675,
        6680,
        6685,
        6690,
        6695,
        6700,
        6705,
        6710,
        6715,
        6720,
        6725,
        6730,
        6735,
        6740,
        6745,
        6750,
        6755,
        6760,
        6765,
        6770,
        6775,
        6780,
        6785,
        6790,
        6795,
    ],
    # [5745, 5750, 5755, 5760, 5765, 5770, 5775, 5780,
    # 5785, 5790, 5795, 5800, 5805, 5810, 5815, 5820,
    # 5825, 5830, 5835, 5840, 5845, 5850, 5855, 5860,
    # 5865, 5870, 5875, 5880, 5885, 5890, 5895, 5900,
    # 5905, 5910, 5915, 5920, 5925, 5930, 5935, 5940,
    # 5945, 5950, 5955, 5960, 5965, 5970, 5975, 5980,
    # 5985, 5990, 5995, 6000, 6005, 6010, 6015, 6020,
    # 6025, 6030, 6035, 6040, 6045, 6050, 6055, 6060,
    # 6065, 6070, 6075, 6080, 6085, 6090, 6095, 6100,
    # 6105, 6110, 6115, 6120, 6125, 6130, 6135, 6140,
    # 6145, 6150, 6155, 6160, 6165, 6170, 6175, 6180,
    # 6185, 6190, 6195, 6200, 6205, 6210, 6215, 6220,
    # 6225, 6230, 6235, 6240, 6245, 6250, 6255, 6260,
    # 6265, 6270, 6275, 6280, 6285, 6290, 6295, 6300,
    # 6305, 6310, 6315, 6320, 6325, 6330, 6335, 6340,
    # 6345, 6350, 6355, 6360, 6365, 6370, 6375, 6380,
    # 6385, 6390, 6395, 6400, 6405, 6410, 6415, 6535,
    # 6540, 6545, 6550, 6555, 6560, 6565, 6570, 6575,
    # 6580, 6585, 6590, 6595, 6600, 6605, 6610, 6615,
    # 6620, 6625, 6630, 6635, 6640, 6645, 6650, 6655,
    # 6660, 6665, 6670, 6675, 6680, 6685, 6690, 6695,
    # 6700, 6705, 6710, 6715, 6720, 6725, 6730, 6735,
    # 6740, 6745, 6750, 6755, 6760, 6765, 6770, 6775,
    # 6780, 6785, 6790, 6795, 6800, 6805, 6810, 6815,
    # 6820, 6825, 6830, 6835, 6840, 6845, 6850, 6855,
    # 6860, 6865, 5740, 6420, 6530, 6870],
}

MAX_EIRP = {
    "EP3K": {
        "10": [
            {"range": [5250, 5320], "power": 27},
            {"range": [5495, 5705], "power": 27},
            {"range": [5160, 5245], "power": 33},
            {"range": [5745, 5835], "power": 36},
            {"range": [5840, 5885], "power": 36},
        ],
        "20": [
            {"range": [5245, 5320], "power": 30},
            {"range": [5495, 5705], "power": 30},
            {"range": [5180, 5240], "power": 36},
            {"range": [5745, 5835], "power": 36},
            {"range": [5840, 5880], "power": 36},
        ],
        "40": [
            {"range": [5235, 5310], "power": 30},
            {"range": [5510, 5695], "power": 30},
            {"range": [5190, 5230], "power": 36},
            {"range": [5745, 5825], "power": 36},
            {"range": [5830, 5870], "power": 36},
        ],
        "80": [
            {"range": [5215, 5290], "power": 30},
            {"range": [5525, 5675], "power": 30},
            {"range": [5200, 5210], "power": 36},
            {"range": [5765, 5805], "power": 36},
            {"range": [5810, 5850], "power": 36},
        ],
    },
    "EP3KL": {
        "10": [
            {"range": [5250, 5320], "power": 27},
            {"range": [5495, 5705], "power": 27},
            {"range": [5160, 5245], "power": 33},
            {"range": [5745, 5835], "power": 36},
            {"range": [5840, 5885], "power": 36},
        ],
        "20": [
            {"range": [5245, 5320], "power": 30},
            {"range": [5495, 5705], "power": 30},
            {"range": [5180, 5240], "power": 36},
            {"range": [5745, 5835], "power": 36},
            {"range": [5840, 5880], "power": 36},
        ],
        "40": [
            {"range": [5235, 5310], "power": 30},
            {"range": [5510, 5695], "power": 30},
            {"range": [5190, 5230], "power": 36},
            {"range": [5745, 5825], "power": 36},
            {"range": [5830, 5870], "power": 36},
        ],
        "80": [
            {"range": [5215, 5290], "power": 30},
            {"range": [5525, 5675], "power": 30},
            {"range": [5200, 5210], "power": 36},
            {"range": [5765, 5805], "power": 36},
            {"range": [5810, 5850], "power": 36},
        ],
    },
    "4600": {
        "20": [
            {"range": [5745, 5950], "power": 36},
            {"range": [5955, 6415], "power": 36},
            {"range": [6535, 6865], "power": 36},
        ],
        "40": [
            {"range": [5755, 5960], "power": 36},
            {"range": [5965, 6405], "power": 36},
            {"range": [6545, 6855], "power": 36},
        ],
        "10": [
            {"range": [5740, 5950], "power": 36},
            {"range": [5955, 6420], "power": 36},
            {"range": [6530, 6870], "power": 36},
        ],
        "5": [
            {"range": [5740, 5950], "power": 36},
            {"range": [5955, 6420], "power": 36},
            {"range": [6530, 6870], "power": 36},
        ],
        "80": [
            {"range": [5775, 5980], "power": 36},
            {"range": [5985, 6385], "power": 36},
            {"range": [6565, 6835], "power": 36},
        ],
        "160": [
            {"range": [6025, 6345], "power": 36},
            {"range": [6605, 6795], "power": 36},
        ],
    },
}


class Bandwidth(Enum):
    BW_5 = 4
    BW_10 = 3
    BW_20 = 1
    BW_40 = 2
    BW_80 = 5
    BW_160 = 6


# Bandwidth varies according to frequency band
FREQUENCY_BANDS = {
    "EP3K": [{"range": [5190, 5875], "bandwidth": Bandwidth.BW_40}],
    "EP3KL": [{"range": [5190, 5875], "bandwidth": Bandwidth.BW_40}],
    "4600": [
        # {"range": [5745, 5975], "bandwidth": Bandwidth.BW_20},
        {"range": [6005, 6795], "bandwidth": Bandwidth.BW_160},
    ],
}

# Default time zone to use if time zone cannot
# be determined.
DEFAULT_TIMEZONE = "CST6"

# When enabled, determine time zone according to device
# coordinates. Otherwise, only configure time zone as
# specified in the device's base config.
TIMEZONE_FROM_COORDS = True

# Time zone abbreviations used by Cambium APs.
# Used to ensure determined time zone name is valid.
TIMEZONE_NAMES = [
    "UTC",
    "AZOST",
    "EGST",
    "GMT",
    "WET",
    "WT",
    "Z",
    "AZOT1",
    "AZOST1",
    "CVT1",
    "EGT1",
    "N1",
    "NDT2:30",
    "BRST2",
    "FNT2",
    "GST2",
    "O2",
    "PMDT2",
    "UYST2",
    "WGST2",
    "NST3:30",
    "ADT3",
    "AMST3",
    "ART3",
    "BRT3",
    "CLST3",
    "FKST3",
    "GFT3",
    "P3",
    "PMST3",
    "PYST3",
    "SRT3",
    "UYT3",
    "WGT3",
    "VET4:30",
    "AMT4",
    "AST4",
    "BOT4",
    "CDT4",
    "CLT4",
    "COST4",
    "ECT4",
    "EDT4",
    "FKT4",
    "GYT4",
    "PYT4",
    "Q4",
    "CDT5",
    "COT5",
    "CST5",
    "EASST5",
    "ECT5",
    "EST5",
    "PET5",
    "R5",
    "CST6",
    "EAST6",
    "GALT6",
    "MDT6",
    "S6",
    "MST7",
    "PDT7",
    "T7",
    "AKDT8",
    "CIST8",
    "PST8",
    "U8",
    "MIT9:30",
    "AKST9",
    "GAMT9",
    "GIT9",
    "HADT9",
    "V9",
    "CKT10",
    "HAST10",
    "HST10",
    "TAHT10",
    "W10",
    "NUT11",
    "SST11",
    "X11",
    "BIT12",
    "Y12",
    "A-1",
    "BST-1",
    "CET-1",
    "DFT-1",
    "IST-1",
    "WAT-1",
    "WEDT-1",
    "WEST-1",
    "WST-1",
    "B-2",
    "CAT-2",
    "CEDT-2",
    "CEST-2",
    "EET-2",
    "IST-2",
    "SAST-2",
    "WAST-2",
    "IRST-3:30",
    "AST-3",
    "C-3",
    "EAT-3",
    "EEDT-3",
    "EEST-3",
    "IDT-3",
    "MSK-3",
    "AFT-4:30",
    "IRDT-4:30",
    "AMT-4",
    "AST-4",
    "AZT-4",
    "D-4",
    "GET-4",
    "GST-4",
    "KUYT-4",
    "MSD-4",
    "MSK-4",
    "MUT-4",
    "RET-4",
    "SAMT-4",
    "SCT-4",
    "IST-5:30",
    "SLT-5:30",
    "NPT-5:45",
    "AMST-5",
    "AQTT-5",
    "AZST-5",
    "E-5",
    "HMT-5",
    "IST-5",
    "MAWT-5",
    "MVT-5",
    "PKT-5",
    "TFT-5",
    "TJT-5",
    "TMT-5",
    "UZT-5",
    "YEKT-5",
    "CCT-6:30",
    "MMT-6:30",
    "MST-6:30",
    "ALMT-6",
    "BIOT-6",
    "BST-6",
    "BTT-6",
    "F-6",
    "IOT-6",
    "KGT-6",
    "NOVT-6",
    "OMST-6",
    "YEKST-6",
    "YEKT-6",
    "YEKST-5",
    "CXT-7",
    "DAVT-7",
    "G-7",
    "HOVT-7",
    "ICT-7",
    "KRAT-7",
    "NOVST-7",
    "NOVST-6",
    "OMSST-7",
    "OMSST-6",
    "OMST-7",
    "THA-7",
    "WIB-7",
    "ACT-8",
    "AWST-8",
    "BDT-8",
    "BNT-8",
    "CAST-8",
    "CST-8",
    "H-8",
    "HKT-8",
    "IRKT-8",
    "KRAST-8",
    "KRAST-7",
    "KRAT-8",
    "MST-8",
    "MYT-8",
    "PHT-8",
    "PST-8",
    "SGT-8",
    "SST-8",
    "ULAT-8",
    "WITA-8",
    "ACST-9:30",
    "CHOST-9",
    "AWDT-9",
    "I-9",
    "IRKST-9",
    "IRKST-8",
    "IRKT-9",
    "JST-9",
    "KST-9",
    "PWT-9",
    "TLT-9",
    "WIT-9",
    "YAKT-9",
    "ACDT-10:30",
    "LHST-10:30",
    "AEST-10",
    "CHST-10",
    "K-10",
    "PGT-10",
    "VLAT-10",
    "YAKST-10",
    "YAKST-9",
    "YAKT-10",
    "YAPT-10",
    "NFT-11:30",
    "AEDT-11",
    "L-11",
    "LHDT-11",
    "MAGT-11",
    "NCT-11",
    "PONT-11",
    "SBT-11",
    "VLAST-11",
    "VLAST-10",
    "VLAT-11",
    "VUT-11",
    "CHAST-12",
    "CHAST-12:45",
    "ANAST-12",
    "ANAT-12",
    "FJT-12",
    "GILT-12",
    "M-12",
    "MAGST-12",
    "MAGT-12",
    "MHT-12",
    "NZST-12",
    "PETST-12",
    "PETST-11",
    "PETT-12",
    "TVT-12",
    "WFT-12",
    "CHADT-13",
    "FJST-13",
    "NZDT-13",
    "PHOT-13",
    "TKT-13",
    "WST-13",
    "LINT-14",
]


class EPMPConfig:
    class ConfigurationError(Exception):
        pass

    class AuthenticationError(Exception):
        pass

    class DeviceModelError(Exception):
        pass

    class ConfigurationInProgressError(Exception):
        pass

    def __init__(self, logstream=None, use_default=False, **params):
        self.ip_address = params["ip_address"]
        self.readonly = use_default

        # Configure logging
        # logging.basicConfig(
        #    level=logging.DEBUG if params.get(
        #        "debug") or DEBUG else logging.INFO,
        #    format=f"%(levelname)s:[{params.get('ip_address')}]: %(message)s"
        # )

        self.logger = logging.getLogger(__name__ + f"_{self.ip_address}")
        self.logger.setLevel(
            logging.DEBUG if params.get("debug") or DEBUG else logging.INFO
        )

        if logstream:
            log_handler = logging.StreamHandler(logstream)
            log_handler.setFormatter(ConfigLogFormatter())
            log_handler.setLevel(logging.INFO)
            self.logger.addHandler(log_handler)

        self.logger.debug(f"Params: {params}")

        try:
            # Unpack AP type parameters
            [
                self.model_label,
                self.model_code,
                self.model_identifier,
                self.band,
                self.device_category,
            ] = params.get("ap_type", get_item(params.get("device_type"), AP_TYPES))

            self.is_sm = self.device_category == "SM"
            self.password = params.get("password")

            self.latitude = (
                params.get("latitude", 0) if use_default else params["latitude"]
            )
            self.longitude = (
                params.get("longitude", 0) if use_default else params["longitude"]
            )
            self.height = params.get("height", None)

            self.cnm_url = (
                params.get("cnm_url", "") if use_default else params["cnm_url"]
            )

            if self.is_sm:
                # SM-specific parameters
                self.mac_address = (
                    params.get("mac_address", "")
                    if use_default
                    else params["mac_address"]
                )
                self.user_number = (
                    params.get("user_number", "")
                    if use_default
                    else params["user_number"]
                )
            else:
                # AP-specific parameters
                self.site_name = (
                    params.get("site_name", "") if use_default else params["site_name"]
                )

                # Right-justify azimuth number with 0s to 3 digits
                # (eg. 60 -> 060)
                azimuth_input = (
                    params.get("azimuth", 0) if use_default else params["azimuth"]
                )
                self.azimuth = str(int(azimuth_input) % 360).rjust(3, "0")
                self.configure_reuse = params.get("configure_reuse", True)

                self.device_number = (
                    params.get("device_number", 1)
                    if use_default
                    else params["device_number"]
                )

                if not params.get("frequency") and use_default:
                    self.frequency = 0
                else:
                    self.frequency = self.validate_frequency(
                        params["frequency"], self.model_identifier
                    )

            if ANTENNAS.get(self.model_identifier):
                antenna_input = (
                    params.get(
                        "antenna", ANTENNAS.get(self.model_identifier, [""])[0][2]
                    )
                    if use_default
                    else params["antenna"]
                )
                self.antenna = get_item(
                    antenna_input, ANTENNAS.get(self.model_identifier)
                )
        except AttributeError as err:
            raise AttributeError(f"Missing required parameter: {err}")

        # Generate name to be used for configuration
        self.device_name = self.format_name()

        # Disable requests SSL warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # requests session and login token
        self.session = None
        self.stok = None
        self.mgmt_url = None

    @staticmethod
    def validate_frequency(input_frequency, device_type):
        """Ensures that `input_frequency` is valid for `device_type`."""
        if not device_type or device_type not in [x[2] for x in AP_TYPES]:
            raise Exception("Invalid device type.")
        if (
            input_frequency is None
            or input_frequency == ""
            or int(input_frequency) == 0
        ):
            return

        if int(input_frequency) in VALID_FREQUENCIES.get(device_type, []):
            return int(input_frequency)
        else:
            raise ValueError(
                "Invalid frequency. Valid frequencies are: \n%s"
                % (str(VALID_FREQUENCIES.get(device_type)))
            )

    @staticmethod
    def get_bandwidth(device_type, frequency):
        """Returns the correct bandwidth for `device_type` when operating at `frequency`."""

        if not device_type or FREQUENCY_BANDS.get(device_type) == None:
            raise Exception("Invalid device type.")

        for freq_range in FREQUENCY_BANDS.get(device_type, []):
            if int(frequency) in range(
                freq_range["range"][0], freq_range["range"][1] + 1
            ):
                return freq_range["bandwidth"].value

        # If value not returned, raise error
        raise ValueError("Invalid frequency.")

    @staticmethod
    def get_eirp_max(bandwidth, frequency, device_type):
        frequency = int(frequency)

        if not device_type or MAX_EIRP.get(device_type) == None:
            raise Exception("Invalid device type.")

        for freq_range in MAX_EIRP.get(device_type, {}).get(str(bandwidth), []):
            if frequency in range(freq_range["range"][0], freq_range["range"][1] + 1):
                return freq_range["power"]

        return None

    @staticmethod
    def timezone_at(latitude, longitude):
        """
        Returns the timezone abbreviation for `latitude`, `longitude`.
        May not work outside North America. If the time zone cannot be found,
        returns None.
        """
        try:
            tz = timezone_at(latitude=latitude, longitude=longitude)
        except ValueError:
            return None

        if not tz.get("name") or not tz.get("offset_hours"):
            return None

        # datetime can provide a time zone's abbreviation
        # when provided with its identifier
        dt = datetime(1970, 1, 1, 1, tzinfo=ZoneInfo(tz.get("name", "")))

        tzname = dt.tzname()

        if not tzname:
            return None

        # Format as <TZ code><negative offset>, i.e. CST6
        tzname = f"{tzname}{-int(tz.get('offset_hours', ''))}"

        if tzname in TIMEZONE_NAMES:
            return tzname

        return None

    def format_name(self):
        """Returns a device's name according to naming standards."""
        if self.is_sm:
            return f"NX-{self.user_number}"
        else:
            return "AP-%s-%s-%s-%s-%s.%s" % (
                self.model_code,  # Device model code
                self.band,  # Band
                self.antenna[2],
                self.azimuth,
                self.device_number,
                self.site_name,
            )

    ####################
    # HTTP Interfacing #
    ####################

    def init_session(self, use_https=True, **kwargs):
        """Initializes the request session and logs in to the device."""
        self.session = requests.Session()

        self.logger.debug("Logging in...")

        if not use_https:
            self.mgmt_url = f"http://{self.ip_address}"
        else:
            # Check if device is using TLS
            try:
                requests.get(
                    f"https://{self.ip_address}", verify=False, timeout=REQUEST_TIMEOUT
                )
                self.mgmt_url = f"https://{self.ip_address}"
            except requests.RequestException as err:
                self.logger.debug(
                    f"Encountered error when using HTTPS; continuing with HTTP."
                )
                self.logger.debug(f"HTTPS request error: {err}")
                requests.get(f"http://{self.ip_address}", timeout=REQUEST_TIMEOUT)
                self.mgmt_url = f"http://{self.ip_address}"

        login_body = {}

        # Try supplied password first, then other possible passwords
        pw_options = [self.password] if self.password else []
        pw_options += SM_PASSWORDS if self.is_sm else AP_PASSWORDS

        for password in pw_options:
            resp = self.session.post(
                f"{self.mgmt_url}/cgi-bin/luci",
                data={"username": "admin", "password": password},
                verify=False,
                timeout=10,
            )

            try:
                login_body = json.loads(resp.content)
            except json.JSONDecodeError as err:
                self.logger.debug(err)
                self.logger.debug(f"Response: {resp.content}")
                raise ConnectionError(
                    "Device returned invalid response while logging in."
                )

            if login_body.get("msg") == "import_is_in_progress":
                raise self.ConfigurationInProgressError(
                    "Device configuration import is in progress."
                )

            if (
                login_body
                and login_body.get("userRole") == "admin"
                and login_body.get("stok")
            ):
                self.stok = login_body.get("stok")
                self.password = password
                break

        if not self.stok or login_body.get("userRole") != "admin":
            raise ValueError(
                "Login failed: Invalid login credentials or maximum logins reached."
            )

        if not kwargs.get("suppress_info_log"):
            self.logger.info("Logged in.")

        # Get sysauth cookie
        sysauth = [c[1] for c in self.session.cookies.items() if "sysauth" in c[0]]
        if not sysauth:
            raise ConnectionError("Failed to get authentication cookie.")
        sysauth = sysauth[0]

        # Set required cookies
        self.session.cookies.set("usernameType_80", "admin")
        self.session.cookies.set("usernameType_443", "admin")
        self.session.cookies.set("stok_80", self.stok)
        self.session.cookies.set("stok_443", self.stok)
        self.session.cookies.set(f"sysauth_{self.ip_address}_80", sysauth)
        self.session.cookies.set(f"sysauth_{self.ip_address}_443", sysauth)

        self.logger.debug(f"Logged in with stok {self.stok}")

    def is_logged_in(self):
        """Checks if current credentials are valid."""

        # Not logged in if session is not initialized
        if not self.session or not self.stok:
            return False

        test_req = self.session.post(
            "%s/cgi-bin/luci/;stok=%s/admin/test_connect" % (self.mgmt_url, self.stok),
            verify=False,
            timeout=LOGIN_CHECK_TIMEOUT,
        )

        if not test_req.content or test_req.status_code != 200:
            return False

        try:
            test_resp = json.loads(test_req.content)
        except json.JSONDecodeError as err:
            self.logger.debug(err)
            self.logger.debug(f"Response: {test_req.content}")
            raise ConnectionError(
                "Device returned invalid response while checking login status."
            )

        # Only logged in if response contains {"success": 1, "test": 1}
        logged_in = test_resp.get("success") == 1 and test_resp.get("test") == 1
        self.logger.debug(f"Login check response: {test_resp}")
        self.logger.debug(
            "Login check: " + ("logged in." if logged_in else "not logged in.")
        )
        return logged_in

    def logout(self, **kwargs):
        """Logs out on the device, if logged in."""

        if not kwargs.get("suppress_info_log"):
            self.logger.info("Logging out...")
        if not (self.session and self.stok and self.is_logged_in()):
            self.logger.warning("Attempted to log out when not logged in.")
            return

        req = self.session.post(
            f"{self.mgmt_url}/cgi-bin/luci/;stok=%s/admin/logout" % self.stok,
            verify=False,
        )

        if self.is_logged_in():
            raise ConnectionError(
                "Failed to log out. Response from device: %s" % req.content
            )

        self.logger.debug(f"logout response: {req.content}")

        if not kwargs.get("suppress_info_log"):
            self.logger.info("Logged out.")

    def get_running_config(self):
        if not (self.session and self.stok and self.is_logged_in()):
            raise self.AuthenticationError(
                "Cannot get running configuration: not logged in."
            )

        config = self.session.post(
            "%s/cgi-bin/luci/;stok=%s/admin/config_export" % (self.mgmt_url, self.stok),
            data={"opts": "json"},
            verify=False,
        )

        if not config or config.status_code != 200:
            raise ConnectionError("Failed to get current config.")

        config = json.loads(config.content)

        # Strip template_props section from config by parsing then
        # dumping device_props section
        return json.dumps(
            {"device_props": config["device_props"]}, indent=4, sort_keys=True
        )

    def send_configuration(self, config):
        """Sends dict of configuration changes to device."""

        self.logger.debug(f"Sending configuration: {config}")

        if not (self.session and self.stok and self.is_logged_in()):
            raise self.AuthenticationError("Cannot send configuration: not logged in.")

        # Log changes
        for item in config["device_props"].items():
            self.logger.info(f"Setting parameter {item[0]} to {item[1]}.")

        """conf_req = self.session.post(
            "%s/cgi-bin/luci/;stok=%s/admin/set_param" % (
                self.mgmt_url, self.stok
            ), data={"changed_elements": json.dumps(config)},
            verify=False)"""

        # Use the HTTP "config import" feature to upload the config file
        files = {"image": ("config.json", json.dumps(config))}

        conf_req = self.session.post(
            "%s/cgi-bin/luci/;stok=%s/admin/config_import" % (self.mgmt_url, self.stok),
            files=files,
            verify=False,
        )

        self.logger.debug(f"Configuration response: {conf_req.content}")

        body_text = conf_req.text if hasattr(conf_req, "text") else conf_req.content.decode(errors="replace")
        if conf_req.status_code in range(200, 300) and not body_text.strip():
            self.logger.info(
                "Configuration import accepted with empty response; waiting for apply status."
            )
            conf_resp = {"success": 1}
        else:
            try:
                conf_resp = json.loads(conf_req.content)
            except Exception as err:
                body_preview = body_text[:200]
                raise self.ConfigurationError(
                    f"Failed to send configuration: {err}. "
                    f"status={conf_req.status_code}, content_type={conf_req.headers.get('content-type', '')}, "
                    f"body={body_preview!r}"
                )

        if (err := conf_resp.get("error")) or conf_resp.get("success") != 1:
            if err:
                err_msg = f"Error while configuring: {err}"
            else:
                err_msg = "Error while configuring."

            raise self.ConfigurationError(err_msg)

        self.logger.info("Applying configuration...")

        # If device is configured to HTTP-only or HTTPS-only, switch
        # management URL after applying.
        # Certain firmware upgrades cause the device to default to HTTPS,
        # so configuration will use HTTPS until apply, then switch to HTTP.
        init_use_https = True
        if config["device_props"].get("webService") == "1":
            self.logger.debug("Changed management address to HTTP.")
            self.mgmt_url = f"http://{self.ip_address}"
            init_use_https = False
            time.sleep(15)
        elif config["device_props"].get("webService") == "2":
            self.logger.debug("Changed management address to HTTPS.")
            self.mgmt_url = f"https://{self.ip_address}"
            init_use_https = True
            time.sleep(15)

        # Wait for config to apply
        time_start = time.monotonic()

        # Loop until timeout is reached or config is applied
        while time.monotonic() < time_start + CONFIG_APPLY_TIMEOUT:
            time.sleep(2)

            params = {}

            try:
                # Session might need to be restarted due to HTTP/HTTPS change
                if not self.is_logged_in():
                    self.logger.debug("Attempting login...")
                    self.init_session(suppress_info_log=True, use_https=init_use_https)

                params = self.get_device_params(
                    full=True, apply_status=True, suppress_info_log=True
                )
            except Exception:
                pass

            logging.debug(params.get("template_props"))

            if (
                params
                and params.get("template_props", {}).get("applyFinished", {}) == 1
            ):
                return

        raise TimeoutError("Timed out while sending configuration.")

    def reboot(self):
        """Reboots the device."""

        self.logger.info("Rebooting device.")
        if not (self.session and self.stok and self.is_logged_in()):
            raise self.AuthenticationError("Cannot reboot: not logged in.")

        req = self.session.post(
            "%s/cgi-bin/luci/;stok=%s/admin/reboot" % (self.mgmt_url, self.stok),
            verify=False,
        )

        self.logger.debug(f"Reboot response: {req.content}")

        try:
            resp = json.loads(req.content)
        except json.JSONDecodeError as err:
            self.logger.debug(err)
            self.logger.debug(f"Response: {req.content}")
            raise ConnectionError("Device returned invalid response.")

        if resp.get("success") != 1:
            raise ConnectionError(f"Failed to reboot. Response: {req.content}")

    def get_device_params(self, full=False, apply_status=False, **kwargs):
        """Gets device status parameters. If `full`, return entire response,
        including template_props. If `apply_status`, send
        applyStatusNeeded: true in request data.
        """

        if not kwargs.get("suppress_info_log"):
            self.logger.info("Getting device parameters.")

        if not (self.session and self.stok and self.is_logged_in()):
            raise self.AuthenticationError("Cannot get params: not logged in.")

        data = {"act": "status", "debug": "true"}

        if apply_status:
            data["applyStatusNeeded"] = "true"

        req = self.session.post(
            "%s/cgi-bin/luci/;stok=%s/admin/get_param" % (self.mgmt_url, self.stok),
            data=data,
            verify=False,
        )

        # self.logger.debug(f"Device param response: {req.content}")

        try:
            resp = json.loads(req.content)
        except json.JSONDecodeError as err:
            self.logger.debug(err)
            self.logger.debug(f"Response: {req.content}")
            raise ConnectionError(
                f"Device returned invalid response. Response: {req.content}"
            )

        if resp.get("success") != "1":
            raise ConnectionError(f"Failed to get parameters. Response: {req.content}")

        if full:
            return resp

        return resp.get("device_props")

    #################
    # Configuration #
    #################

    def get_standard_config(self, stripped=False, json_conf=False):
        """Loads the base config for a device."""

        standard_config_path = pathlib.PurePath(
            pathlib.Path(CONF_TEMPLATE_PATH),
            self.model_identifier,
            "standard_config.json",
        )
        if stripped or not ANTENNAS.get(self.model_identifier):
            # If a device does not have a changeable antenna, the config
            # is always called config.json
            config_path = standard_config_path
        else:
            config_path = pathlib.PurePath(
                pathlib.Path(CONF_TEMPLATE_PATH), self.model_identifier, self.antenna[1]
            )
            if not pathlib.Path(config_path).exists():
                self.logger.debug(
                    "Antenna-specific config missing for %s (%s); falling back to standard_config.json",
                    self.model_identifier,
                    self.antenna[1],
                )
                config_path = standard_config_path

        self.logger.debug(f"Base config path: {config_path}")

        try:
            with open(config_path, "r") as f:
                config = json.load(f)

        except (OSError, FileNotFoundError) as err:
            raise Exception(f"Could not read base configuration: {err}")

        # self.logger.debug(f"Loaded base config: {config}")

        return json.dumps(config, indent=4, sort_keys=True) if json_conf else config

    def _configure_device_params(self, config):
        """Sets device-specific parameters (name, location, etc.) in `config`."""

        config["device_props"]["snmpSystemName"] = self.device_name
        config["device_props"]["snmpSystemDescription"] = self.device_name
        config["device_props"]["systemConfigDeviceName"] = self.device_name[0:31]
        config["device_props"]["sysLocation"] = f"{self.latitude}, {self.longitude}"
        config["device_props"]["systemDeviceLocLatitude"] = self.latitude
        config["device_props"]["systemDeviceLocLongitude"] = self.longitude
        config["device_props"]["cambiumDeviceAgentCNSURL"] = self.cnm_url
        if self.height is not None:
            config["device_props"]["systemDeviceLocHeight"] = self.height

        if TIMEZONE_FROM_COORDS:
            tz = self.timezone_at(self.latitude, self.longitude) or DEFAULT_TIMEZONE
            self.logger.debug(f"Timezone: {tz}")
            config["device_props"]["systemConfigTimezone"] = tz

        if not self.is_sm:
            config["device_props"]["wirelessInterfaceSSID"] = (
                f"{self.azimuth}-{self.device_number}.{self.site_name}"
            )
            config["device_props"]["centerFrequency"] = str(self.frequency)
            # Device bandwidth, according to frequency and device code
            config["device_props"]["wirelessInterfaceHTMode"] = str(
                self.get_bandwidth(self.model_identifier, self.frequency)
            )
            if self.configure_reuse:
                config["device_props"]["wirelessInterfaceiFreqReuseMode"] = (
                    "2" if int(self.azimuth) >= 180 else "1"
                )

    def _verify_configuration_valid(self):
        """
        Verify that a device has valid params and
        is ready to be configured.
        """

        # Check model number to verify device model.
        # Also check firmware version, and update if necessary,
        # as well as MAC address (for SMs)
        precheck = self.pre_check()

        self.logger.debug(f"precheck result: {precheck}")

        # SKU
        if not (sku_result := [x[3] for x in precheck if x[0] == "Device SKU"]):
            self.logger.warning("Could not verify device model number.")
        else:
            if not sku_result[0]:
                raise self.DeviceModelError("Incorrect device model selected.")

        # Firmware version
        if not (fw_result := [x[3] for x in precheck if x[0] == "Firmware Version"]):
            self.logger.warning(
                "Could not check firmware version. " + "Configuration may fail."
            )
        else:
            if not fw_result[0]:
                # Update device

                self.logger.info("Firmware out of date. Updating...")

                if not self.password:
                    raise ValueError("No stored password.")

                # Log out to avoid opening multiple sessions at once.
                # Suppress "Logged out" log to avoid unexpected output.
                self.logout(suppress_info_log=True)
                update_cn_ap(
                    self.ip_address,
                    self.model_identifier,
                    password=self.password,
                    on_log=lambda x: self.logger.info(x),
                )

                time.sleep(2)

                # Re-open session after reboot.
                self.init_session()

        # SM MAC address
        if self.is_sm:
            if not (fw_result := [x[3] for x in precheck if x[0] == "MAC Address"]):
                self.logger.warning("Could not verify MAC address.")
            else:
                if not fw_result[0]:
                    raise self.DeviceModelError(
                        "Specified wireless MAC address does not match device."
                    )

    def init_and_configure(self):
        """
        Initializes session, updates device firmware (if needed), then
        configures the device.
        """

        if self.readonly:
            raise Exception("Unable to configure: initialized in read-only mode.")

        try:
            if not self.is_logged_in():
                self.init_session()

            self._verify_configuration_valid()

            # In some cases, configuring immediately after
            # getting params from the device can cause a
            # connection failure
            time.sleep(1)

            config = self.get_standard_config()
            self._configure_device_params(config)

            config_params = list(config.get("device_props").items())

            # In order to avoid large requests, break up configuration into
            # smaller chunks
            while config_params:
                to_configure = []

                # Get first n parameters, where n is either the number of
                # remaining parameters, or the max. number, whichever is
                # smaller.
                for _ in range(min(len(config_params), MAX_CONFIG_SIZE)):
                    to_configure.append(config_params.pop(0))

                # Ensure device is still accessible
                time_start = time.monotonic()
                while time.monotonic() < time_start + CONFIG_APPLY_TIMEOUT:
                    time.sleep(0.25)
                    try:
                        if self.is_logged_in():
                            break
                    except Exception:
                        pass

                self.send_configuration({"device_props": dict(to_configure)})

            # For some devices, auth is lost after configuration, so
            # rebooting requires re-logging in.
            try:
                self.logout(suppress_info_log=True)
            except Exception:
                pass

            result = {
                "configuration_sent": True,
                "reboot_requested": False,
                "reboot_required": False,
                "pending_reboot": False,
            }

            try:
                self.init_session(suppress_info_log=True)
                self.logger.info("\nConfiguration finished.")
                self.reboot()
                result["reboot_requested"] = True
            except self.ConfigurationInProgressError:
                self.logger.info(
                    "Configuration import is still in progress. A reboot is still required for changes to fully take effect."
                )
                result["reboot_required"] = True
                result["pending_reboot"] = True
                result["message"] = (
                    "Configuration import is in progress on the AP. "
                    "A reboot is still required for the changes to fully take effect."
                )
            return result
        except requests.RequestException as err:
            self.logger.debug(err)
            try:
                self.logout()
            except Exception:
                pass

            raise ConnectionError(f"Connection failed. {err}")
        except Exception as err:
            self.logger.debug(err)
            if self.session and self.stok and self.is_logged_in():
                self.logout()
            raise

    ############
    # Precheck #
    ############

    def pre_check(self):
        """Check device to ensure it is ready to be configured."""

        attributes = []

        if not self.is_logged_in():
            self.init_session()

        params = self.get_device_params()

        gps_latitude = None
        gps_longitude = None
        latitude = None
        longitude = None

        try:
            gps_latitude = float(params.get("cambiumGPSLatitude"))
            gps_longitude = float(params.get("cambiumGPSLongitude"))

            attributes.append([
                "GPS Location",
                f"{gps_latitude}, {gps_longitude}",
                None,
                None,
            ])
        except Exception:
            attributes.append(["GPS Location", "GPS location unavailable", "", False])

        try:
            latitude = float(params.get("cambiumDeviceLatitude"))
            longitude = float(params.get("cambiumDeviceLongitude"))

            attributes.append([
                "Device Location",
                f"{latitude}, {longitude}",
                None,
                None,
            ])
        except Exception:
            attributes.append([
                "Device Location",
                "Device location not configured",
                "",
                False,
            ])

        if all((gps_latitude, gps_longitude, latitude, longitude)):
            distance = haversine_distance(
                (latitude, longitude), (gps_latitude, gps_longitude)
            )

            attributes.append([
                "GPS Location/Device Location",
                (
                    f"In range ({distance:.2f} m < {LOCATION_ALLOWED_ERR} m)"
                    if distance < LOCATION_ALLOWED_ERR
                    else f"Out of range ({distance:.2f} m > {LOCATION_ALLOWED_ERR} m)"
                ),
                None,
                distance < LOCATION_ALLOWED_ERR,
            ])

        if self.is_sm and self.mac_address:
            # For SMs, verify that the provided MAC address matches the
            # device's MAC
            if not (mac_addr := params.get("cambiumWirelessMACAddress")):
                raise ValueError("Could not get device MAC address.")

            attributes.append((
                "MAC Address",
                mac_addr,
                self.mac_address or "",
                self.mac_address in mac_addr,
            ))

        # Only get frequency/bandwidth for APs
        if not self.is_sm:
            if sm_count := int(params.get("cambiumAPNumberOfConnectedSTA")):
                attributes.append(["Connected SMs", f"{sm_count}", None, None])
            if frequency := int(params.get("cambiumSTAConnectedRFFrequency")):
                attributes.append(["Frequency", f"{frequency} MHz", None, None])

            bandwidth_values = {1: 20, 2: 40, 3: 10, 5: 80, 6: 160}

            if bandwidth := params.get("cambiumSTAConnectedRFBandwidth"):
                bandwidth = bandwidth_values.get(bandwidth)
                attributes.append(["Bandwidth", f"{bandwidth} MHz", None, None])

            attributes.append((
                "SSID Format",
                ap_ssid := params.get("cambiumEffectiveSSID"),
                None,
                bool(re.match(r"\d{3}-\d{1,2}\..*$", ap_ssid)),
            ))

            # EIRP check
            output_power = abs(int(params.get("cambiumMinTXPower")))
            antenna_gain = int(params.get("cambiumEffectiveAntennaGain"))

            # Only check if current frequency is valid
            if bandwidth and frequency in VALID_FREQUENCIES.get(
                self.model_identifier, []
            ):
                max_eirp = self.get_eirp_max(
                    bandwidth, frequency, self.model_identifier
                )

                if not max_eirp:
                    eirp_valid = None
                else:
                    eirp_valid = output_power + antenna_gain <= max_eirp
            else:
                eirp_valid = None

            attributes.append((
                "EIRP",
                "%d dBm (%d dBm + %d dBi) (Check gain according to specifications)"
                % (output_power + antenna_gain, output_power, antenna_gain),
                None,
                eirp_valid,
            ))

        # Iterate over list of parameters to be checked
        for param_name, param_label, expected_value in PRE_CHECK_ATTRIBUTES.get(
            self.model_identifier, []
        ):
            param_value = str(params.get(param_name))
            self.logger.debug(f"Checking {param_name}: value {param_value}")
            if not param_value:
                continue

            if not expected_value:
                result = None

            elif isinstance(expected_value, (tuple, list)):
                result = any([
                    bool(re.findall(str(x), param_value)) for x in expected_value
                ])

            else:
                result = bool(re.findall(str(expected_value), param_value))

            attributes.append([param_label, param_value, expected_value, result])

        return attributes

    @staticmethod
    def get_device_info(ip_address, device_type, password=None, run_tests=False):
        result = {}

        params = {
            "ip_address": ip_address,
            "device_type": device_type,
        }

        d = None

        if password:
            params["password"] = password

        try:
            d = EPMPConfig(**params, use_default=True)
            d.init_session()
            params = d.get_device_params()
            result["standard_config"] = d.get_standard_config(json_conf=True)
            result["running_config"] = d.get_running_config()
            if run_tests:
                result["test_results"] = [
                    {"name": x[0], "expected": x[2], "actual": x[1], "pass": x[3]}
                    for x in d.pre_check()
                ]

            d.logout()

            result["gps_latitude"] = params.get("cambiumGPSLatitude")
            result["gps_longitude"] = params.get("cambiumGPSLongitude")
            result["latitude"] = params.get("cambiumDeviceLatitude")
            result["longitude"] = params.get("cambiumDeviceLongitude")
            result["wireless_mac"] = params.get("cambiumWirelessMACAddress")
            result["sm_count"] = params.get("cambiumAPNumberOfConnectedSTA")

            result["success"] = True
        except Exception as err:
            try:
                if d:
                    d.logout()
            except Exception:
                pass

            print(err)

            result["success"] = False
            result["message"] = err

        return result
