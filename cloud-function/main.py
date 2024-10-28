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

logging.basicConfig(level=logging.INFO)

class PythonPackage:

    def __init__(self, event_data: dict):
        self.name, self.version, self.user_email = self._parse_event_data(event_data=event_data)
        self.scan_report = ""

    def _parse_event_data(self, event_data: dict) -> Tuple[str, str, str]:
        name, version = self._extract_package_and_version_from_event(event_data=event_data)
        user_email = self._extract_user_email_from_event(event_data=event_data)

        return name, version, user_email 

    def _extract_package_and_version_from_event(self, event_data: dict) -> Tuple[str, str]:
        request_url = event_data["protoPayload"]["request"]["requestUrl"]
        request_url_parts = request_url.split("/")
        package_name = request_url_parts[-2]
        package_wheel_file = request_url_parts[-1]
        package_version = self._extract_package_version_from_wheel_filename(package_wheel_file)

        return package_name, package_version

    def _extract_package_version_from_wheel_filename(self, wheel_file: str) -> str:
        return wheel_file.split("-")[1]

    def _extract_user_email_from_event(self, event_data: dict) -> str:
        return event_data["protoPayload"]["authenticationInfo"]["principalEmail"]

    def scan(self) -> bool:
        package_and_version = f"{self.name}=={self.version}"
        tmp = tempfile.NamedTemporaryFile()
        with open(tmp.name, 'w') as f:
            f.write(package_and_version)

        logging.info(f"Scanning {package_and_version}")
        result = subprocess.run(["pip-audit", "-r", tmp.name, "-l", "--cache-dir", "/tmp"], capture_output=True)
        if result.returncode != 0:
            self.scan_report = f"{result.stderr.decode('utf-8')}\n{result.stdout.decode('utf-8')}"
            logging.error(self.scan_report)
        else:
            self.scan_report = result.stderr.decode('utf-8')
            logging.info(self.scan_report)

        return result.returncode != 0


def notify_user(package: PythonPackage) -> None:
    slack_token = get_slack_token()

    client = WebClient(token=slack_token)
    user = client.users_lookupByEmail(email=package.user_email)
    if not user["ok"]:
        raise Exception("todo: user not found in slack throw exception")

    user_id = user["user"]["id"]
    client.chat_postMessage(
                channel=user_id,
                text="test scan error :eyes:",
                blocks=create_slack_message(package=package)
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


def create_slack_message(package: PythonPackage) -> list:
    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f":warning: _*Sårbarhet oppdaget i pakke `{package.name}=={package.version}`*_",
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn", 
                "text": f"```{package.scan_report}```",
            }
        }
    ]


def scan_package(event_data: dict) -> None:
    python_package = PythonPackage(event_data=event_data)

    vulnerability_discovered = python_package.scan()
    if vulnerability_discovered:
        notify_user(python_package)


@functions_framework.cloud_event
def entrypoint(cloud_event):
   event_data = json.loads(base64.b64decode(cloud_event.data["message"]["data"]))
   logging.info("event:", cloud_event)
   
   try:
      scan_package(event_data=event_data)
   except Exception as e:
      print("todo: post to nada-alerts")
      raise
