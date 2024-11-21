import json
import google_crc32c
from google.cloud.secretmanager import SecretManagerServiceClient
from slack_sdk import WebClient


def notify_user(gsm_secret_path: str, user_email: str, vulnerability: dict) -> None:
    slack_token = _get_slack_token(gsm_secret_path)

    client = WebClient(token=slack_token)
    user = client.users_lookupByEmail(email=user_email)
    if not user["ok"]:
        raise Exception(f"slack lookup user from email: user {user_email} not found in slack")

    attachments = _create_user_notification(
        package_name=vulnerability["package"], 
        package_version=vulnerability["version"], 
        install_timestamp=vulnerability["install_timestamp"], 
        vulnerabilities=vulnerability["vulnerabilities"]
    )

    user_id = user["user"]["id"]
    res = client.chat_postMessage(
       channel=user_id,
       attachments=attachments,
    )

    if res.status_code != 200:
        raise Exception(f"slack chat.postMessage failed: {res.status_code} {res.data}")


def notify_nada(gsm_secret_path: str, slack_channel: str, error: Exception) -> None:
    slack_token = _get_slack_token(gsm_secret_path)

    client = WebClient(token=slack_token)
    res = client.chat_postMessage(
        channel=slack_channel,
        text=":warning: PYPI proxy sårbarhetsscanner feiler",
        blocks=_create_nada_notification(error)
    )
    if res.status_code != 200:
        raise Exception(f"slack chat.postMessage failed: {res.status_code} {res.data}")


def _get_slack_token(gsm_secret_path: str) -> str:
    client = SecretManagerServiceClient()
    response = client.access_secret_version(request={"name": gsm_secret_path})

    crc32c = google_crc32c.Checksum()
    crc32c.update(response.payload.data)
    if response.payload.data_crc32c != int(crc32c.hexdigest(), 16):
        raise Exception("crc check failed for gsm secret content")

    return response.payload.data.decode("UTF-8")


def _create_user_notification(package_name: str, package_version: str, install_timestamp: str, vulnerabilities: list) -> list:
    fields = []
    for vuln in vulnerabilities:
        fields.append(
            {
                "short": False,
                "value":
f"""
Gjelder `{vuln["name"]}=={vuln["version"]}` (<https://pypi.org/project/{vuln["name"]}/{vuln["version"]}|https://pypi.org/project/{vuln["name"]}/{vuln["version"]}>)
Installasjonstidspunkt: `{install_timestamp}`
_*CVE:*_ {vuln.get("cve_link")} (aliaser: `{", ".join(vuln.get("cve_aliases"))}`)
_*Fiks versjoner:*_ `{", ".join(vuln.get("fix_versions"))}`
"""
            }
        )

    return [
        {
            "fallback": "Sårbarhet oppdaget :eyes:",
            "mrkdwn_in": ["fields", "pretext", "title"],
            "color": "danger",
            "pretext": f":warning: _*Sårbarhet oppdaget i pakke `{package_name}=={package_version}`*_\n_Du har installert denne pakken nylig på enten din Knada Notebook eller Cloud Workstation_",
            "fields": fields,
            "footer": "Nada"
        }
    ]

def _create_nada_notification(error: Exception) -> list:
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
                "text": f"```{error}```",
            }
        }
    ]
