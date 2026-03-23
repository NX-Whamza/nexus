#!/usr/bin/python3

import os
import pprint
import re
import sys
import urllib.request
import base64
from bs4 import BeautifulSoup
import requests
from .util import *
import logging

PRE_CHECK_FIRMWARE_VERSION = "4.01"

_BASE_CONFIG_ROOT = os.getenv("BASE_CONFIG_PATH") or os.getenv("FIRMWARE_PATH") or ""
BASE_CONFIG_PATH = os.path.join(_BASE_CONFIG_ROOT, "ICT", "200DB") + "/" if _BASE_CONFIG_ROOT else ""

DEBUG = True


DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = os.getenv("RPC_STANDARD_PW")


HELP_MESSAGE = (
    "Usage: %s [-i ip_address] [-n device_number]\n\
                     [-p password] [-s site_name] [-u username] \n\
                \n\
            Available options:\n\
                -i,--ip-address     IP address of device to configure\n\
                -n,--device-number  Device number, for device name (default 1)\n\
                -s,--site-name      Name of site local to backhaul, in format AA-BBBBBB-CC-##\n\
                -u,--username       Override default login username\n\
                -p,--password       Override default login password\n\
                -h,--help           Show this help message"
    % (__file__.split("/")[-1])
)


class ICTRPCConfig:
    def __init__(self, logstream=None, **params):
        try:
            self.ip_address = params["ip_address"]
        except KeyError as err:
            raise Exception("Value not defined: %s" % err)

        self.logger = logging.getLogger(__name__ + f"_{self.ip_address}")
        self.logger.setLevel(
            logging.DEBUG if params.get("debug") or DEBUG else logging.INFO
        )

        if logstream:
            log_handler = logging.StreamHandler(logstream)
            log_handler.setFormatter(ConfigLogFormatter())
            log_handler.setLevel(logging.INFO)
            self.logger.addHandler(log_handler)

        # Device name in format RPC-ICT200DB12-TRP##.SITE
        if params.get("site_name"):
            self.device_name = "RPC-ICT200DB12-TRP%s.%s" % (
                str(params.get("device_number", "1")),
                params.get("site_name"),
            )
        else:
            self.device_name = ""
        self.username = params.get("username", DEFAULT_USERNAME)
        self.password = params.get("password", DEFAULT_PASSWORD)

        self.substitutions = {"device_name": self.device_name}

        # Log callback
        self.on_log = params.get("on_log")

    def _read_and_send_files(self):
        files = os.listdir(BASE_CONFIG_PATH)

        # Make sure net is last, because it restarts the device
        if "net" in files:
            self.logger.debug("net found")
            files = [x for x in files if x != "net"]
            files.append("net")

        for file in files:
            # Ensure file is of type file and not dir
            if not os.path.isfile(BASE_CONFIG_PATH + file):
                continue

            # POST file contents to http://<ip address>/<filename>, then
            # add response to responses in form (file, response)
            self._post_form(
                file,
                read_file(BASE_CONFIG_PATH + file).format(
                    **{
                        # Call substitution if callable,
                        # otherwise use value converted to str
                        k: v() if callable(v) else str(v)
                        for k, v in self.substitutions.items()
                    }
                ),
            )

            self.logger.info(f"Sent configuration for file {file}.")

    def _post_form(self, url, data):
        try:
            # Ensure url has a leading /
            if url[0] != "/":
                url = "/" + url
            # parse data into dict
            if isinstance(data, str):
                data = data.replace("\n", "")
                keys = re.findall(r"(.*?)=(.*?)&", data)

                data = {}
                for key in keys:
                    # The first entry in each tuple is the key name, and
                    # the second is the value
                    data[key[0]] = key[1]

            request = requests.post(
                "http://" + self.ip_address + url,
                data=data,
                auth=(self.username, self.password),
                allow_redirects=False,
            )

            # Follow redirect: some endpoints, such as /net on 200DB, redirect to a reset page,
            # but the redirect URL appears to have a trailing space (which browsers ignore, but
            # requests does not), so a normal redirect causes a 404. Thus, the redirect URL must be
            # retrieved from the request, then the redirect request is performed again with
            # the URL corrected.
            if request.status_code in (301, 302):
                # Trim URI-encoded whitespace
                redir_url = request.headers["Location"].replace(" ", "")
                request = requests.get(
                    f"http://{self.ip_address}{redir_url}",
                    auth=(self.username, self.password),
                    headers={"Referer": request.url},
                )

                self.logger.debug(request.content)

            if request.status_code != 200:
                raise Exception(
                    "POST failed with code %d at address %s"
                    % (request.status_code, request.url)
                )
        except urllib.error.HTTPError as err:
            raise Exception(
                "Failed to POST form data to page %s with data %s: %s"
                % ("http://" + self.ip_address + url, urllib.parse.urlencode(data), err)
            )

    def _get_firmware_version(self):
        html_text = requests.get(
            "http://%s" % self.ip_address, auth=(self.username, self.password)
        ).text
        html_parsed = BeautifulSoup(html_text, "html.parser")

        try:
            version_text = html_parsed.select(".smtxt")[0].contents[4]
            version = re.search(r"Firmware: (\S*)", version_text, flags=re.M).group(1)
        except IndexError:
            raise Exception("Failed to parse device version number.")
        return version

    def _get_outputs(self):
        outputs = []

        # GET http://<ip address>/
        html_text = requests.get(
            "http://%s" % self.ip_address, auth=(self.username, self.password)
        ).text
        html_parsed = BeautifulSoup(html_text, "html.parser")

        try:
            rows = html_parsed.select("#page > tr")

            for row in rows:
                for item in row:
                    # print(item)
                    # Parse each output from main page
                    name = item.select("div > table > tr:nth-child(1) > td > b")[
                        0
                    ].contents[0]
                    if "Output" not in name:
                        continue
                    name = re.sub(r"Output (\d\S):", r"\1", name)

                    label = item.select(
                        "div > table > tr:nth-child(1) > td:nth-child(2)"
                    )[0].text.rjust(16)

                    status = item.select("div > table > tr:nth-child(3) > th")[0].text

                    current = item.select(
                        "div > table > tr:nth-child(2) > td:nth-child(2)"
                    )[0].text.rjust(7)

                    outputs.append(
                        {
                            "name": name,
                            "label": label,
                            "current": current,
                            "status": status,
                        }
                    )

        except IndexError:
            raise Exception("Failed to parse device output status.")

        # Sort so that bus A appears before bus B
        outputs.sort(
            key=lambda output: (
                int(output.get("name")[0])
                + (100 if output.get("name")[1] == "B" else 0)
            )
        )
        return outputs

    def pre_check(self):
        results = []

        outputs = self._get_outputs()
        for output in outputs:
            results.append(
                (
                    # "*" if output.get("status") == "Enabled" else " ",
                    # "Output %s [ %s ]: %s :: %s" % (
                    #    output.get("name"),
                    #    output.get("label"),
                    #    output.get("current"),
                    #    output.get("status")
                    # ),
                    (
                        f"{output.get('name')} ({re.sub(r'^ *', r'', output.get('label'))})"
                        if output.get("label").replace(" ", "")
                        else output.get("name")
                    ),
                    f"{output.get('status').replace('BREAKER OFF', 'Breaker off')} ({output.get('current').replace(' ', '')})",
                    None,
                    None,
                )
            )

        results.append(
            (
                "Firmware version",
                self._get_firmware_version(),
                PRE_CHECK_FIRMWARE_VERSION,
                PRE_CHECK_FIRMWARE_VERSION in self._get_firmware_version(),
            )
        )

        return results

    def init_and_configure(self):
        required_params = [self.device_name]

        if not all(required_params):
            raise Exception("Missing required value.")

        self._read_and_send_files()

        self.logger.info("\nConfiguration finished.")

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
            d = ICTRPCConfig(**params)

            if run_tests:
                result["test_results"] = [
                    {"name": x[0], "expected": x[2], "actual": x[1], "pass": x[3]}
                    for x in d.pre_check()
                ]

            # TODO: log out

            result["success"] = True
        except Exception as err:
            result["success"] = False
            result["message"] = err

        return result

    @staticmethod
    def request_params(**params):
        if not params.get("ip_address"):
            params["ip_address"] = input("[?] IP address: ")
        if not params.get("site_name"):
            params["site_name"] = input("[?] Site name: ")
        if not params.get("device_number"):
            params["device_number"] = input_default("[?] Device number: ", "1")

            params["name"] = "RPC-ICT200DB12-TRP%s.%s" % (
                str(params.get("device_number", "1")),
                params.get("site_name"),
            )

        return params


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
                elif val == "--site-name" or val == "-s":
                    if "=" not in args[0]:
                        args.pop(0)
                    else:
                        args[0] = args[0].split("=")[1]
                    result["site_name"] = args[0]
                elif val == "--device-number" or val == "-n":
                    if "=" not in args[0]:
                        args.pop(0)
                    else:
                        args[0] = args[0].split("=")[1]
                    result["device_number"] = args[0]
                elif val == "--password" or val == "-p":
                    if "=" not in args[0]:
                        args.pop(0)
                    else:
                        args[0] = args[0].split("=")[1]
                    result["password"] = args[0]
                elif val == "--username" or val == "-u":
                    if "=" not in args[0]:
                        args.pop(0)
                    else:
                        args[0] = args[0].split("=")[1]
                    result["username"] = args[0]
                elif val == "-h" or val == "--help":
                    print(HELP_MESSAGE)
                    exit()
                else:
                    print("Unrecognized option `%s`\n" % (args[0]))
                    print(HELP_MESSAGE)
                    exit()
                args.pop(0)
        return result

    ict = ICTRPCConfig(**ICTRPCConfig.request_params(**parse_CLI_args(sys.argv)))
    # ict.init_and_configure()
    ict.pre_check()


if __name__ == "__main__":
    main()
