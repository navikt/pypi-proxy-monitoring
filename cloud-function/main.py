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

        for user_email, package_installations in unscanned.items():
            scan_for_user(gsm_secret_path, scan_results_table_uri, user_email, package_installations)

    except Exception as e:
        # Catch whatever exception and notify nada on slack
        print(e.with_traceback())
        notify_nada(gsm_secret_path, error_slack_channel, e.with_traceback())

    return "OK"


def scan_for_user(gsm_secret_path: str, scan_results_table_uri: str, user_email: str, package_installations: list):
    print(f"Scanning newly installed packages by user {user_email}")
    print(package_installations)

    with multiprocessing.Pool() as pool:
        scan_results = pool.map(scan_package, package_installations)
        pool.close()
        pool.join()

    persist_scan_results(scan_results_table_uri, scan_results)

    results_with_vulnerabilities = extract_scan_results_with_vulnerabilities(scan_results)

    if len(results_with_vulnerabilities) > 0 and user_email.endswith("@nav.no"):
        notify_user(gsm_secret_path, user_email, results_with_vulnerabilities)


def extract_scan_results_with_vulnerabilities(scan_results: list[dict]) -> list:
    scan_results_with_vulnerabilities = {}
    for res in scan_results:
        if res["has_vulnerabilities"]:
            scan_results_with_vulnerabilities[res["package_and_version"]] = {
                "package_and_version": res["package_and_version"],
                "install_timestamp": res["install_timestamp"],
                "vulnerabilities": res["vulnerabilities"],
            }

    return [scan_result for scan_result in scan_results_with_vulnerabilities.values()]


def scan_package(package_data: dict) -> dict: # Tuple[str, str, bool, dict, dict]:
    package_and_version = f"{package_data['package']}=={package_data['version']}"
    with tempfile.NamedTemporaryFile() as tmp:
        with open(tmp.name, 'w') as f:
            f.write(package_and_version)

        print(f"Scanning {package_and_version}")
        result = subprocess.run(["pip-audit", "-r", tmp.name, "-l", "--cache-dir", "/tmp", "-f", "json"], capture_output=True)
        raw_scan_report = json.loads(result.stdout.decode('utf-8'))
        print(result.stderr.decode('utf-8'))

    return {
        "package_and_version": package_and_version,
        "log_insert_id": package_data["log_insert_id"],
        "has_vulnerabilities": result.returncode != 0,
        "raw_scan_report": raw_scan_report,
        "vulnerabilities": process_report(raw_report=raw_scan_report),
    }


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
