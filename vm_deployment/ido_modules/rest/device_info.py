import asyncio
import functools
import os
import time
import re
import concurrent.futures
from typing import List
from fastapi import APIRouter, HTTPException
import logging

try:
    from pysnmp.hlapi import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        getCmd,
        nextCmd,
    )
    HAS_PYSNMP = True
except Exception:
    HAS_PYSNMP = False

try:
    from ping3 import ping
except Exception:
    ping = None

PING_COUNT = 4

# For checking if a device is accessible, the results don't matter, so
# testing should be stopped after a short period of time
SNMP_WALK_TEST_TIMEOUT = 0.5

# Connection timeout -- for inaccessible hosts
SNMP_CONNECT_TIMEOUT = 1.0
SNMP_RETRIES = 0

app = APIRouter()


def snmp_walk(
    ip: str, community: str, timeout: float = None, version: int = 2
) -> List[str]:
    if not HAS_PYSNMP:
        raise RuntimeError("pysnmp is not installed")
    snmp_engine = SnmpEngine()
    community_data = CommunityData(community, mpModel=(0 if version == 1 else 1))
    transport = UdpTransportTarget(
        (ip, 161), timeout=SNMP_CONNECT_TIMEOUT, retries=SNMP_RETRIES
    )
    context = ContextData()
    object_type = ObjectType(ObjectIdentity("1.3.6.1.2.1"))

    results = []

    start_time = time.monotonic()
    logging.debug(f"{ip}: start walk")

    for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
        snmp_engine,
        community_data,
        transport,
        context,
        object_type,
        lexicographicMode=False,
    ):
        logging.debug(f"{ip}: walk continue")

        if errorIndication:
            raise Exception(f"Error: {errorIndication}")
        elif errorStatus:
            raise Exception(
                f'{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or "?"}'
            )
        if time.monotonic() - start_time > timeout:
            logging.debug(f"{ip}: walk finish")
            return results
        else:
            for varBind in varBinds:
                results.append(
                    f"{varBind[0].prettyPrint()} = {varBind[1].prettyPrint()}"
                )

    return results


def get_oid(ip: str, community: str, oid: str, version: int = 2) -> str:
    if not HAS_PYSNMP:
        raise RuntimeError("pysnmp is not installed")
    snmp_engine = SnmpEngine()
    community_data = CommunityData(community, mpModel=(0 if version == 1 else 1))
    transport = UdpTransportTarget(
        (ip, 161), timeout=SNMP_CONNECT_TIMEOUT, retries=SNMP_RETRIES
    )
    context = ContextData()
    object_type = ObjectType(ObjectIdentity(oid))

    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(snmp_engine, community_data, transport, context, object_type)
    )

    if errorIndication:
        raise Exception(f"Error: {errorIndication}")
    elif errorStatus:
        raise Exception(
            f'{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or "?"}'
        )
    else:
        for varBind in varBinds:
            logging.debug(f"{ip} - [{oid}]: Returns {varBind[0].prettyPrint()} : {varBind[1].prettyPrint()}")
            return f"{varBind[0].prettyPrint()} = {varBind[1].prettyPrint()}"
    return "No result found"


def device_info(
    ip_address: str,
    run_tests: bool = False,
    snmp_version: int = 2,
    disable_snmp: bool = False,
):
    result = {}

    snmp_can_connect = False

    disable_snmp = disable_snmp or not HAS_PYSNMP

    if not disable_snmp:
        community = os.getenv("SNMP_COMMUNITY")

        # Attempt to get location via SNMP
        try:
            location = get_oid(
                ip_address, community, "1.3.6.1.2.1.1.6.0", version=snmp_version
            )
            latlong = re.findall(r"(-?\d{1,2}\.\d*),\s*(-?\d{1,2}\.\d*)", location)
            if latlong:
                result["latitude"] = latlong[0][0]
                result["longitude"] = latlong[0][1]
                snmp_can_connect = True
        except Exception:
            pass

        # sysName
        try:
            name = get_oid(
                ip_address, community, "1.3.6.1.2.1.1.5.0", version=snmp_version
            )
            name = re.findall(r"\.0 = (.*)", name)
            if name:
                result["name"] = name[0]
                snmp_can_connect = True
        except Exception:
            pass

        # If previous attempts failed, perform a full walk (slower) to check if SNMP is accessible
        if not snmp_can_connect:
            try:
                walk = snmp_walk(
                    ip_address,
                    community,
                    timeout=SNMP_WALK_TEST_TIMEOUT,
                    version=snmp_version,
                )
                if walk:
                    snmp_can_connect = True
            except Exception:
                pass

    result["test_results"] = []
    if run_tests:
        if not disable_snmp:
            result["test_results"].append(
                {
                    "name": "SNMP",
                    "actual": (
                        "SNMP is accessible"
                        if snmp_can_connect
                        else "SNMP walk timed out"
                    ),
                    "expected": None,
                    "pass": snmp_can_connect,
                }
            )

        ping_results = []
        for _ in range(PING_COUNT):
            ping_results.append(ping(ip_address, unit="ms") if ping else None)

        valid_results = [x for x in ping_results if isinstance(x, float)]
        average = sum(valid_results) / len(valid_results) if valid_results else None

        result["test_results"].append(
            {
                "name": "Ping",
                "actual": (
                    f"{len(valid_results)}/{PING_COUNT} successful, average {round(average, 2)}, max {round(max(valid_results), 2)}"
                    if valid_results
                    else "Ping timed out"
                ),
                "expected": None,
                "pass": len(valid_results) == PING_COUNT,
            }
        )

        if result.get("name"):
            result["test_results"].append(
                {
                    "name": "Device Name",
                    "actual": result.get("name"),
                    "expected": None,
                    "pass": None,
                }
            )

        if (latitude := result.get("latitude")) and (
            longitude := result.get("longitude")
        ):
            result["test_results"].append(
                {
                    "name": "Device Location",
                    "actual": f"{latitude}, {longitude}",
                    "expected": None,
                    "pass": True,
                }
            )

            result["test_results"].append(
                {
                    "name": "GPS Location",
                    "actual": f"{latitude}, {longitude}",
                    "expected": None,
                    "pass": True,
                }
            )

    result["success"] = True

    if "gps_latitude" in result and "gps_longitude" in result:
        loc = f'{result["gps_latitude"]}, {result["gps_longitude"]}'
    else:
        loc = None

    fixed = {}
    for t in result["test_results"]:
        n = t["name"]
        if n == "GPS Location" and loc:
            t["actual"] = loc
            t["pass"] = True
        fixed[n] = t

    result["test_results"] = list(fixed.values())    

    return result


@app.get("/api/generic/device_info")
async def get_device_info(
    ip_address: str,
    run_tests: bool = False,
    disable_snmp: bool = False,
    snmp_version: int = 2,
):
    try:
        loop = asyncio.get_running_loop()
        with concurrent.futures.ProcessPoolExecutor() as pool:
            return await loop.run_in_executor(
                pool,
                functools.partial(
                    device_info,
                    ip_address,
                    run_tests,
                    snmp_version=snmp_version,
                    disable_snmp=disable_snmp,
                ),
            )

    except Exception as err:
        raise HTTPException(status_code=500, detail=f"{err}") from err
