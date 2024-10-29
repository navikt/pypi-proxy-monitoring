import os
import json
import base64
import logging
import tempfile
import subprocess
from typing import Tuple

from slack_sdk import WebClient
import functions_framework
import google_crc32c
from google.cloud.secretmanager import SecretManagerServiceClient
from google.cloud.bigquery import Client as BQClient

logging.basicConfig(level=logging.INFO)

def scan_package(package_name: str, package_version: str) -> Tuple[bool, str]:
    package_and_version = f"{package_name}=={package_version}"
    tmp = tempfile.NamedTemporaryFile()
    with open(tmp.name, 'w') as f:
        f.write(package_and_version)

    logging.info(f"Scanning {package_and_version}")
    result = subprocess.run(["pip-audit", "-r", tmp.name, "-l", "--cache-dir", "/tmp"], capture_output=True)
    if result.returncode != 0:
        scan_report = f"{result.stderr.decode('utf-8')}\n{result.stdout.decode('utf-8')}"
    else:
        scan_report = result.stderr.decode('utf-8')

    logging.info(scan_report)

    return result.returncode != 0, scan_report


def notify_user(package_name: str, package_version: str, user_email: str, scan_report: str) -> None:
    slack_token = get_slack_token()

    client = WebClient(token=slack_token)
    user = client.users_lookupByEmail(email=user_email)
    if not user["ok"]:
        raise Exception("todo: user not found in slack throw exception")

    user_id = user["user"]["id"]
    client.chat_postMessage(
        channel=user_id,
        text="test scan error :eyes:",
        blocks=create_slack_message(package_name=package_name, package_version=package_version, scan_report=scan_report)
    )


def get_slack_token() -> str:
    client = SecretManagerServiceClient()
    name = f"projects/knada-dev/secrets/pypi-proxy-slack-token/versions/latest"
    response = client.access_secret_version(request={"name": name})

    crc32c = google_crc32c.Checksum()
    crc32c.update(response.payload.data)
    if response.payload.data_crc32c != int(crc32c.hexdigest(), 16):
        raise Exception("crc check failed for gsm secret content")

    return response.payload.data.decode("UTF-8")


def create_slack_message(package_name: str, package_version: str, scan_report: str) -> list:
    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f":warning: _*Sårbarhet oppdaget i pakke `{package_name}=={package_version}`*_",
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn", 
                "text": f"```{scan_report}```",
            }
        }
    ]

@functions_framework.cloud_event
def entrypoint(cloud_event):
    event_data = json.loads(base64.b64decode(cloud_event.data["message"]["data"]))
    print("event:", cloud_event)
    print("event_data", event_data)
    insert_id = event_data["insertId"]

    client = BQClient()
    query = f"SELECT package, version, user_email FROM `knada-dev.pypi_proxy_data.package_installations` WHERE log_insert_id = '{insert_id}'"
    res = client.query_and_wait(query)

    print("scanning package", f"{res[0]}=={res[1]}")
    try:
        has_vulnerability, scan_report = scan_package(res[0], res[1])
        if has_vulnerability:
            notify_user(res[0], res[1], res[2], scan_report=scan_report)
    except Exception as e:
        print("todo: post to nada-alerts")
        raise
