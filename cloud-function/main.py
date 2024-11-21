import os
import json
import tempfile
import subprocess
import functions_framework
from typing import Tuple

from slackclient import notify_user, notify_nada
from bigquery import fetch_unscanned_installations, persist_scan_results

from functools import partial
import multiprocessing

@functions_framework.http
def entrypoint(request):
    try:
        unscanned_package_data_view_uri = os.environ["PACKAGE_DATA_VIEW_URI"]
        scan_results_table_uri = os.environ["SCAN_RESULTS_TABLE_URI"]
        gsm_secret_path = os.environ["GSM_SECRET_PATH"]
        error_slack_channel = os.environ["ERROR_SLACK_CHANNEL"]

        unscanned, num_unscanned = fetch_unscanned_installations(unscanned_package_data_view_uri)
        if num_unscanned > 100:
            notify_nada(gsm_secret_path, error_slack_channel, f"PYPI proxy scanner is unable to catch up, the current number of unscanned installed packages are: {num_unscanned}")

        with multiprocessing.Pool() as pool:
            f = partial(scan_for_user, gsm_secret_path, scan_results_table_uri)
            pool.map(f, unscanned)
            pool.close()
            pool.join()
    except Exception as e:
        # Catch whatever exception and notify nada on slack
        print(e)
        notify_nada(gsm_secret_path, error_slack_channel, e)

    return "OK"


def scan_for_user(gsm_secret_path: str, scan_results_table_uri: str, package_installations: dict):
    user_email = package_installations["user_email"]
    print(f"Scanning newly installed packages by user {user_email}")
    print(package_installations)

    for package_installation in package_installations["packages"]:
        package = package_installation["package"]
        version = package_installation["version"]
        has_vulnerability, raw_scan_report, processed_report = scan_package(package_name=package, package_version=version)
        persist_scan_results(scan_results_table_uri, package_installation["log_insert_id"], has_vulnerability, raw_scan_report, processed_report)

        if has_vulnerability and user_email.endswith("@nav.no"):
            notify_user(gsm_secret_path, user_email, {
                "package": package,
                "version": version,
                "install_timestamp": package_installation["install_timestamp"],
                "vulnerabilities": processed_report,
            })


def scan_package(package_name: str, package_version: str) -> Tuple[bool, dict, dict]:
    package_and_version = f"{package_name}=={package_version}"
    tmp = tempfile.NamedTemporaryFile()
    with open(tmp.name, 'w') as f:
        f.write(package_and_version)

    print(f"Scanning {package_and_version}")
    result = subprocess.run(["pip-audit", "-r", tmp.name, "-l", "--cache-dir", "/tmp", "-f", "json"], capture_output=True)
    raw_scan_report = json.loads(result.stdout.decode('utf-8'))
    print(result.stderr.decode('utf-8'))

    return result.returncode != 0, raw_scan_report, process_report(raw_report=raw_scan_report)


def process_report(raw_report: dict) -> list:
    vulnerabilities = []
    for dep in raw_report["dependencies"]:
        for vuln in dep["vulns"]:
            vulnerabilities.append(
                {
                    "name": dep["name"],
                    "version": dep["version"],
                    "fix_versions": vuln.get("fix_versions"),
                    "cve_link": f"<https://osv.dev/vulnerability/{vuln.get('id')}|{vuln.get('id')}>",
                    "cve_aliases": vuln.get("aliases"),
                }
            )

    return vulnerabilities
