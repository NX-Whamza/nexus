# -*- coding: utf-8 -*-

from datetime import datetime
import json
import re
from zoneinfo import ZoneInfo
import math
import logging
import os
import tzdata
from timezonefinder import TimezoneFinder
import sys
import logging

try:
    from pysnmp.hlapi import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        nextCmd,
    )
    from pysnmp.smi import builder, view
    HAS_PYSNMP = True
except Exception:
    builder = None
    view = None
    HAS_PYSNMP = False

os.environ["MIBS"] = "ALL"
# from easysnmp import Session


SITE_NAME_PATTERN = r"[A-Z]{2}-[A-Z0-9]*-(?:(?:NE)|(?:NO)|(?:EA)|(?:SE)|(?:SO)|(?:SW)|(?:WE)|(?:NW)|(?:CN))-R?\d{1,2}"


# Prompt user to choose item from list.
# If list contains dict, print values of key dict_text_key


def prompt_list(text, list, default=None, use_default=False, dict_text_key="name"):
    if use_default:
        if get_item(default, list):
            return get_item(default, list)
        elif default:
            raise ValueError("%s not found in list." % default)
        else:
            raise ValueError("use_default specified but no default provided.")

    print("[*] %s" % (text))
    for i in range(1, len(list) + 1):
        if isinstance(list[i - 1], tuple):
            print("%d. %s" % (i, list[i - 1][0]))
        elif isinstance(list[i - 1], dict):
            print("%d. %s" % (i, list[i - 1].get(dict_text_key, list[i - 1])))
        else:
            print("%d. %s" % (i, list[i - 1]))

    return get_item(
        input("%s:: " % ("[%s] " % str(default) if default else "")),
        list,
        default=default,
    )


# Return true if user inputs true_string, false if false_string, or default if other input


def binary_prompt(prompt, true_string="y", false_string="n", default=True):
    userInput = input(prompt).upper()
    if userInput == true_string.upper():
        return True
    elif userInput == false_string.upper():
        return False
    else:
        return default


# Match by input string; if input is an integer,
# select item with index of input, otherwise find first match
# containing input string


def get_item(input, input_list, default=None):
    if input is None:
        return input
    elif input == "":
        return get_item(default, input_list)
    if type(input) is tuple and input in input_list:
        return input

    elif input.isdigit() and abs(int(input)) <= len(input_list):
        return input_list[int(input) - 1]

    for item in input_list:
        matches = []
        if isinstance(item, (tuple, list)):
            for word in re.split(r"\s", input):
                match = False
                for field in item:
                    if word.upper() in str(field).upper():
                        match = True
                if match:
                    matches.append(True)
                else:
                    matches.append(False)
        else:
            for word in re.split(r"\s", input):
                if word.upper() in str(item).upper():
                    matches.append(True)
                else:
                    matches.append(False)
        if all(matches):
            return item
    raise Exception(
        "Item not found in list. Valid choices are: \n%s" % (str(input_list))
    )


# Convert CIDR suffix to subnet mask


def calc_netmask(cidr):
    bits = 0xFFFFFFFF
    for i in range(32 - cidr):  # Shift in zeros for (32-cidr) places
        bits <<= 1
    return bits_to_octets(bits)


# Convert octets of an IP address to bits


def octets_to_bits(octets):
    if isinstance(octets, str):
        octets = octets.split(".")
    address = 0x00000000
    for i in range(len(octets)):
        # Shift each octet to correct place in final value
        address += int(octets[i]) << (24 - 8 * i)
    return address


# Convert an IP address in bits to octets


def bits_to_octets(bits):
    address = [0, 0, 0, 0]
    for i in range(len(address)):
        address[i] = ((bits << 8 * i) & (0xFF000000)) // 0x1000000
    return ".".join(str(x) for x in address)


# Get first address in subnet


def get_first_address(address, subnet):
    if isinstance(address, str):
        address = octets_to_bits(address)
    if isinstance(subnet, str):
        subnet = octets_to_bits(subnet)
    elif isinstance(subnet, int):
        # convert CIDR to subnet mask
        subnet = octets_to_bits(calc_netmask(subnet))

    return bits_to_octets(
        # return network address (address AND subnet) + 1
        (address & subnet)
        + 1
    )


def read_file(path):
    with open(path, "r") as file:
        return file.read()


# Convert decimal coordinate to D/M/S


def convert_coord_to_dms(dec):
    dec = abs(float(dec))
    deg = int(dec)
    min = int(dec % 1 * 60)
    sec = (dec % 1 * 60) % 1 * 60
    return (deg, min, round(sec, 3))


# If `default` provided, append default tag to `text` and request user input


def input_default(text, default, use_default=False):
    if default:
        user_input = input(str(text) + "[%s] " % (default))
        if not user_input or use_default:
            return default
        else:
            return user_input
    else:
        return input(str(text))


# Increment last octet of `address` by `increment`


def increment_ip_address(address, increment=1):
    try:
        return (
            ".".join(address.split(".")[0:3])
            + "."
            + str(int(address.split(".")[3]) + increment)
        )
    except (IndexError, AttributeError):
        return None


def expand_ip_range(input_string, delimiter="-"):
    if input_string == "":
        return []
    elif delimiter not in input_string:
        return [input_string]
    else:
        start_ip, end_value = input_string.split(delimiter)

        return [
            ".".join(start_ip.split(".")[0:3]) + ".%s" % str(s)
            for s in range(int(start_ip.split(".")[3]), int(end_value) + 1)
        ]


# Maintain consistent length when printing separator


def print_separator():
    print("-----------------------------------")


def print_precheck_result(results):
    if not isinstance(results, list):
        return
    print()

    for result in results:
        if result[3] is None:
            print(
                " - %s :: %s"
                % (
                    result[0].ljust(
                        max([len(x[0] or "") for x in results if not x[3]])
                    ),
                    result[1],
                )
            )

        else:
            print(
                " %s %s :: Expected: %s :: Actual: %s (%s)"
                % (
                    "✓" if result[3] else "x",
                    re.sub(r"[\r\n]", "", result[0]).ljust(
                        max([len(x[0] or "") for x in results if x[3] is not None])
                    ),
                    re.sub(r"[\r\n]", "", result[2] or "N/A").ljust(
                        max([len(x[2] or "") for x in results if x[3] is not None])
                    ),
                    re.sub(r"[\r\n]", "", result[1]).ljust(
                        max([len(x[1] or "") for x in results if x[3] is not None])
                    ),
                    "Pass" if result[3] else "Fail",
                )
            )
    print()
    # Determine whether or not all values are True (or None)
    overall = all(filter(lambda x: x is not None, [row[3] for row in results]))
    print("Device result: %s\n" % ("Pass" if overall else "Fail"))

    return overall


# Send data to callback if defined, otherwise print to STDOUT
def use_callback_or_print(data, callback=None):
    if callable(callback):
        callback(data)
    else:
        print(data)


def timezone_at(latitude, longitude):
    """Get time zone name & UTC offset from device's coordinates."""

    latitude = float(latitude)
    longitude = float(longitude)

    tz = TimezoneFinder().timezone_at(lat=latitude, lng=longitude)

    if not tz:
        raise ValueError(
            "Could not determine time zone for coordinates: %s, %s"
            % (latitude, longitude)
        )

    try:
        # Use 01/01/1970 for TZ conversion instead of current date to prevent changes due to DST
        offset = datetime(1970, 1, 1, 1, tzinfo=ZoneInfo(tz)).utcoffset()
    except Exception as err:
        # Time zone conversion requires the tzdata module
        raise Exception(f"Failed to get time zone offset. Is tzdata installed? \n{err}")

    if not offset:
        raise ValueError(
            "Could not determine time zone for coordinates: %s, %s"
            % (latitude, longitude)
        )

    offset_hours = int(offset.total_seconds() / 3600)

    return {"name": tz, "offset_hours": offset_hours}


# Get all JSONPath/value pairs for a dict
def parsepath(data, head="", **kwargs):
    delimiter = kwargs.get("delim", ".")
    out = []
    if isinstance(data, dict):
        if kwargs.get("include_empty_vals") and len(data) == 0:
            out.append({"path": head, "value": {}})
            return out

        for key, value in data.items():
            new_head = f"{head}{delimiter if head else ''}{key}"
            out += parsepath(value, new_head, **kwargs)
    elif isinstance(data, list):
        if kwargs.get("include_empty_vals") and len(data) == 0:
            out.append({"path": head, "value": []})
            return out

        for index, item in enumerate(data):
            new_head = f"{head}[{index}]"
            out += parsepath(item, new_head, **kwargs)
    else:
        out.append({"path": head, "value": data})
    return out


def haversine_distance(coord1, coord2):
    # Radius of the Earth in meters
    R = 6371009

    # Coordinates in decimal degrees
    lat1, lon1 = coord1
    lat2, lon2 = coord2

    # Convert decimal degrees to radians
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])

    # Haversine formula
    dlon = lon2 - lon1
    dlat = lat2 - lat1
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    )
    c = 2 * math.asin(math.sqrt(a))

    # Distance in meters
    distance = R * c
    return distance


def snmp_walk(address, community, mib_folder, mib_modules):
    """
    Performs an SNMP walk on the given address using the provided community string.
    Resolves OIDs to their names using MIBs from the specified folder.

    :param address: The IP address of the SNMP agent.
    :param community: The SNMP community string.
    :param mib_folder: The folder containing your compiled MIB files.
    :param mib_modules: A list of MIB module names to load (without file extensions).
    """
    if not HAS_PYSNMP:
        raise RuntimeError("pysnmp is not installed")
    # Create an SNMP engine instance
    snmp_engine = SnmpEngine()

    # Get MIB builder from the SNMP engine
    mib_builder = snmp_engine.getMibBuilder()

    # Add your MIB source directory to the MIB builder
    mib_builder.addMibSources(builder.DirMibSource(mib_folder))

    # Optionally, add the MIB folder to sys.path
    sys.path.insert(0, mib_folder)

    # Load the specified MIB modules
    mib_builder.loadModules(*mib_modules)

    # Create MIB view controller
    mib_view_controller = view.MibViewController(mib_builder)

    # Create SNMP iterator starting from the desired OID
    iterator = nextCmd(
        snmp_engine,
        CommunityData(community),
        UdpTransportTarget((address, 161)),
        ContextData(),
        # Start from the specific OID defined by its symbolic name
        ObjectType(ObjectIdentity("ICT-POWERSYSTEM-MIB")),
        lexicographicMode=False,
    )

    results = {}

    # Walk through the SNMP data
    for errorIndication, errorStatus, errorIndex, varBinds in iterator:
        if errorIndication:
            print(f"Error: {errorIndication}")
            break
        elif errorStatus:
            print(f"Error: {errorStatus.prettyPrint()} at {errorIndex}")
            break
        else:
            for varBind in varBinds:
                oid, value = varBind
                # Resolve OID to its name using MIBs
                try:
                    oid = oid.resolveWithMib(mib_view_controller)
                except Exception as e:
                    logging.error(f"Could not resolve OID {oid}: {e}")
                print(f"{oid} {oid.prettyPrint()} {value.prettyPrint()}")
                # results[oid.prettyPrint()] = value.prettyPrint()

                key = re.match(r".*::(.*)\.(\d+)$", oid.prettyPrint())
                if not key:
                    continue

                if key.group(1) not in results:
                    results[key.group(1)] = {}

                results[key.group(1)][key.group(2)] = value.prettyPrint()

    return results


# def snmp_walk(address, community):
#     return {}
#
#
#     # Initialize the SNMP session
#     session = Session(hostname=address, community=community, version=2)
#
#     # Perform the SNMP walk starting from the root OID
#     results = session.walk("iso")
#
#     results_parsed = {}
#     # Print the results
#     for result in results:
#         # print(f"{result.oid}.{result.oid_index} = {result.value}")
#         if not results_parsed.get(result.oid):
#             results_parsed[result.oid] = {}
#
#         results_parsed[result.oid][result.oid_index] = result.value.replace("\x00", "")
#
#     return results_parsed


class ConfigLogFormatter(logging.Formatter):
    def __init__(self, ip=None):
        # If an IP is provided, format using address
        if ip:
            self.debug_fmt = f"DEBUG:[{ip}]::%(name)s.%(funcName)s:%(lineno)d: %(msg)s"
            self.info_fmt = f"INFO:[{ip}]: %(msg)s"
            self.fmt = f"%(levelname)s:[{ip}]: %(message)s"
        else:
            self.debug_fmt = f"DEBUG::%(name)s.%(funcName)s:%(lineno)d: %(msg)s"
            self.info_fmt = f"%(msg)s"
            self.fmt = f"%(levelname)s %(message)s"

        logging.Formatter.__init__(self, fmt=self.fmt)

    def format(self, record):
        # Save default format
        def_fmt = self._fmt

        match record.levelno:
            case logging.DEBUG:
                self._fmt = self.debug_fmt
            case logging.INFO:
                self._fmt = self.info_fmt

        self._style = logging.PercentStyle(self._fmt or self.fmt)

        result = logging.Formatter.format(self, record)

        # Restore default format
        self._fmt = def_fmt

        return result
