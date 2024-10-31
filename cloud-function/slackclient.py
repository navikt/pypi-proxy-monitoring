import json
import google_crc32c
from google.cloud.secretmanager import SecretManagerServiceClient
from slack_sdk import WebClient


def notify_user(package_name: str, package_version: str, user_email: str, scan_report: str) -> None:
    slack_token = _get_slack_token()

    client = WebClient(token=slack_token)
    user = client.users_lookupByEmail(email=user_email)
    if not user["ok"]:
        raise Exception(f"slack lookup user from email: user {user_email} not found in slack")

    user_id = user["user"]["id"]
    client.chat_postMessage(
        channel=user_id,
        text="sårbarhet oppdaget :eyes:",
        blocks=_create_user_notification(package_name=package_name, package_version=package_version, scan_report=scan_report)
    )


def notify_nada(log_insert_id: str, error: Exception) -> None:
    slack_token = _get_slack_token()

    client = WebClient(token=slack_token)
    client.chat_postMessage(
        channel="#nada-alerts-dev",
        text=":warning: PYPI proxy sårbarhetsscanner feiler",
        blocks=_create_nada_notification(log_insert_id, error)
    )


def _get_slack_token() -> str:
    client = SecretManagerServiceClient()
    name = f"projects/knada-dev/secrets/pypi-proxy-slack-token/versions/latest"
    response = client.access_secret_version(request={"name": name})

    crc32c = google_crc32c.Checksum()
    crc32c.update(response.payload.data)
    if response.payload.data_crc32c != int(crc32c.hexdigest(), 16):
        raise Exception("crc check failed for gsm secret content")

    return response.payload.data.decode("UTF-8")


def _create_user_notification(package_name: str, package_version: str, scan_report: str) -> list:
    message_blocks = []
    message_blocks.append(
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f":warning: _*Sårbarhet oppdaget i pakke `{package_name}=={package_version}`*_",
            }
        }
    )

    scan_data = json.loads(scan_report)
    for dep in scan_data["dependencies"]:
        if len(dep["vulns"]) > 0:
            message_blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn", 
                        "text": 
f""""
```
_*{dep["name"]}=={dep["version"]}*_
CVE: {dep.get("id")} ({dep.get("aliases")})
Description: {dep.get("description")}
Fix versions: {dep.get("fix_versions")}
```
"""
                    }
                }
            )

    return message_blocks


def _create_nada_notification(log_insert_id: str, error: Exception) -> list:
    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f":warning: PYPI proxy sårbarhetsscanner feiler",
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"```log_insert_id={log_insert_id}\nerror={error}```",
            }
        }
    ]