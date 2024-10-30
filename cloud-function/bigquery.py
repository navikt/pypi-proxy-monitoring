from google.cloud.bigquery import Client
from typing import Tuple

def fetch_unpacked_package_installation_info(log_insert_id: str) -> Tuple[str, str, str]:
    client = Client()
    query = f"SELECT package, version, user_email FROM `knada-dev.pypi_proxy_data.package_installations` WHERE log_insert_id = '{log_insert_id}'"
    res = client.query_and_wait(query)

    row = [r for r in res]
    if len(row) == 1:
        package_data = row[0]
        return package_data[0], package_data[1], package_data[2]

    raise Exception(f"unable to read unpacked data for log_insert_id = '{log_insert_id}'")


def persist_scan_results(log_insert_id: str, scan_status: str, cve: str) -> None:
    client = Client()
    rows_to_insert = [
        {
            "log_insert_id": log_insert_id, 
            "scan_status": scan_status, 
            "cve": cve,
        },
    ]

    errors = client.insert_rows_json("knada-dev.pypi_proxy_data.package_installations_scan", rows_to_insert)
    if errors == []:
        print("successful insert")
    else:
        raise Exception(f"unable to write scan results for log insert id '{log_insert_id}': {errors}")
