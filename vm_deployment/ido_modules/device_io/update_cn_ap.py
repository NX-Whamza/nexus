#!/usr/bin/python

import argparse
import requests
from time import sleep
from .util import *
import os
import pathlib

DEVICE_WAIT_TIMEOUT = 5

DEFAULT_UPDATE_FILE = {
    "EP3K": os.getenv("FIRMWARE_PATH") + "/Cambium/EP3K/ePMP-AC-v5.10.4-13433.img",
    "EP3KL": os.getenv("FIRMWARE_PATH") + "/Cambium/EP3K/ePMP-AC-v5.10.4-13433.img",
    "4600": os.getenv("FIRMWARE_PATH") + "/Cambium/4600/ePMP-AX-v5.10.4-13433.img",
    "F4600C": os.getenv("FIRMWARE_PATH") + "/Cambium/4600/ePMP-AX-v5.10.4-13433.img",
    "F300-13": os.getenv("FIRMWARE_PATH") + "/Cambium/F300/ePMP-AC-v5.10.1.img",
    "F300-16": os.getenv("FIRMWARE_PATH") + "/Cambium/F300/ePMP-AC-v5.10.1.img",
    "F300-25": os.getenv("FIRMWARE_PATH") + "/Cambium/F300/ePMP-AC-v5.10.1.img",
    "F300-CSM": os.getenv("FIRMWARE_PATH") + "/Cambium/F300/ePMP-AC-v5.10.1.img",
}

UPDATE_FILE_PATH = {
    "EP3K": os.getenv("FIRMWARE_PATH") + "/Cambium/EP3K/",
    "EP3KL": os.getenv("FIRMWARE_PATH") + "/Cambium/EP3K/",
    "4600": os.getenv("FIRMWARE_PATH") + "/Cambium/4600/",
    "F4600C": os.getenv("FIRMWARE_PATH") + "/Cambium/4600/",
    "F300-13": os.getenv("FIRMWARE_PATH") + "/Cambium/F300/",
    "F300-16": os.getenv("FIRMWARE_PATH") + "/Cambium/F300/",
    "F300-25": os.getenv("FIRMWARE_PATH") + "/Cambium/F300/",
    "F300-CSM": os.getenv("FIRMWARE_PATH") + "/Cambium/F300/",
}

DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = os.getenv("AP_STANDARD_PW")


def update_cn_ap(
    ip_address,
    device_type,
    username=DEFAULT_USERNAME,
    password=DEFAULT_PASSWORD,
    update_file=None,
    on_log=None,
):
    if device_type not in DEFAULT_UPDATE_FILE.keys():
        raise Exception("Invalid device type.")

    # Set params to default if not defined
    username = username or DEFAULT_USERNAME
    password = password or DEFAULT_PASSWORD

    if update_file:
        path = pathlib.Path(UPDATE_FILE_PATH.get(device_type))
        matches = list(
            filter(
                lambda x: update_file + ".img" in os.path.basename(x),
                list(path.iterdir()),
            )
        )

        if not matches:
            raise FileNotFoundError("No valid firmware files found.")
        else:
            update_file_path = matches[0]

    else:
        update_file_path = DEFAULT_UPDATE_FILE.get(device_type)

    # Determine if device is using HTTP or HTTPS.
    try:
        requests.get(f"https://{ip_address}", verify=False, timeout=2)
        mgmt_url = f"https://{ip_address}"
    except requests.RequestException as err:
        mgmt_url = f"http://{ip_address}"

    sysauth = None
    token = None

    with open(update_file_path, "rb") as update_file:
        # Login to AP
        login_post = requests.post(
            f"{mgmt_url}/cgi-bin/luci",
            data={"username": username, "password": password},
            verify=False,
        )

        # Raise error if login was rejected because of max users.
        if login_post.json().get("msg"):
            raise Exception("Login failed: %s" % login_post.json().get("msg"))

        # Get token and sysauth from login request
        token = login_post.json().get("stok")
        for cookie in login_post.cookies:
            if "sysauth" in cookie.name:
                sysauth = cookie.value

        cookies = {
            # 44443 and 80 are needed for various firmware versions
            f"sysauth_{ip_address}_44443": sysauth,
            f"sysauth_{ip_address}_443": sysauth,
            f"sysauth_{ip_address}_80": sysauth,
            "usernameType_80": username,
            "usernameType_443": username,
            "stok_80": token,
            "stok_443": token,
        }

        # Update AP
        update_post = requests.post(
            f"{mgmt_url}/cgi-bin/luci/;stok={token}/admin/local_upload_image",
            cookies=cookies,
            files={"image": update_file},
            verify=False,
        )
        # use_callback_or_print(update_post.json(), callback=on_log)
        if update_post.status_code != 200:
            raise Exception(
                f"Update request failed with status {update_post.status_code}"
            )
        use_callback_or_print("Firmware uploaded.", callback=on_log)

    # Wait for upload to finish
    previous_status_code = 0
    update_status = None
    while not update_status or update_status.json().get("status") != 7:
        sleep(0.5)
        update_status = requests.post(
            f"{mgmt_url}/cgi-bin/luci/;stok={token}/admin/get_upload_status",
            cookies=cookies,
            verify=False,
        )
        if update_status.json().get("status", 0) > previous_status_code:
            use_callback_or_print(
                f'Updating... ({update_status.json().get("status")}/7)', callback=on_log
            )
        previous_status_code = update_status.json().get("status", 0)

        if error := update_status.json().get("error", 0) > 0:
            if error == 2 or error == 8:
                raise Exception(
                    "Firmware update failed. \n"
                    + "\nThis device is likely incompatible with the update firmware image.\n"
                    + "Was the correct device model selected?"
                )
            else:
                raise Exception("Firmware update failed.")

    reboot_post = requests.post(
        f"{mgmt_url}/cgi-bin/luci/;stok={token}/admin/reboot",
        cookies=cookies,
        verify=False,
    )

    sleep(8)

    use_callback_or_print("Waiting for device to reboot...", callback=on_log)

    # Continuously send GET requests to determine when device comes online
    while True:
        try:
            get_ping = requests.get(
                f"{mgmt_url}", timeout=DEVICE_WAIT_TIMEOUT, verify=False
            )
            # print(get_ping.content, get_ping.status_code)
            if get_ping.status_code == 200:
                break
            else:
                raise Exception(
                    f"HTTP GET at root returned code {get_ping.status_code}"
                )
        except OSError:
            sleep(1)
            continue
        except Exception as err:
            raise Exception(f"Error while updating device: {type(err)}:  {err}")

    use_callback_or_print("Device updated.", callback=on_log)

    # Logout
    # logout_post = requests.post(
    #        f'http://{ip_address}/cgi-bin/luci/;stok={token}/admin/logout',
    #        cookies=cookies
    #        )
    # use_callback_or_print(logout_post.json(), callback=on_log)


def main():
    parser = argparse.ArgumentParser(
        prog="update_cn_ap.py",
        description="Updates Cambium APs via HTTP",
    )
    parser.add_argument("ip_address")
    parser.add_argument("-u", "--username")
    parser.add_argument("-p", "--password")
    parser.add_argument("-f", "--update-file", type=pathlib.Path)

    args = parser.parse_args()

    update_cn_ap(
        args.ip_address,
        username=args.username,
        password=args.password,
        # update_file_path=args.update_file,
        device_type="EP3K",
    )


if __name__ == "__main__":
    main()
