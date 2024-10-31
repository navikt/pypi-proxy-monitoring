import json
import base64
import tempfile
import subprocess
import functions_framework
from typing import Tuple

from slackclient import notify_user, notify_nada
from bigquery import fetch_unpacked_package_installation_info, persist_scan_results


@functions_framework.cloud_event
def entrypoint(cloud_event):
    event_data = json.loads(base64.b64decode(cloud_event.data["message"]["data"]))

    try:
        log_insert_id = event_data["insertId"]
        package_name, package_version, user_email = fetch_unpacked_package_installation_info(log_insert_id=log_insert_id)

        has_vulnerability, raw_scan_report = scan_package(package_name=package_name, package_version=package_version)
        vulnerabilities = process_report(raw_report=raw_scan_report)
        persist_scan_results(log_insert_id, has_vulnerability, raw_scan_report, vulnerabilities)
        if has_vulnerability:
            notify_user(package_name=package_name, package_version=package_version, user_email=user_email, vulnerabilities=vulnerabilities)

    except Exception as e:
        print("would have notified nada")
        #notify_nada(log_insert_id, e)
        raise


def scan_package(package_name: str, package_version: str) -> Tuple[bool, dict]:
    package_and_version = f"{package_name}=={package_version}"
    tmp = tempfile.NamedTemporaryFile()
    with open(tmp.name, 'w') as f:
        f.write(package_and_version)

    print(f"Scanning {package_and_version}")
    result = subprocess.run(["pip-audit", "-r", tmp.name, "-l", "--cache-dir", "/tmp", "-f", "json"], capture_output=True)
    print(result.stderr.decode('utf-8'))

    return result.returncode != 0, json.loads(result.stdout.decode('utf-8'))


def process_report(raw_report: dict) -> list:
    vulnerabilities = []
    for dep in raw_report["dependencies"]:
        for vuln in dep["vulns"]:
            vulnerabilities.append(
                {
                    "name": dep["name"],
                    "version": dep["version"],
                    "description": vuln.get("description"),
                    "fix_versions": vuln.get("fix_versions"),
                    "cve_link": f"<https://osv.dev/vulnerability/{vuln.get('id')}|{vuln.get('id')}>",
                    "cve_aliases": vuln.get("aliases"),
                }
            )

    return vulnerabilities
