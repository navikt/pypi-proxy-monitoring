import json
from google.cloud.bigquery import Client
from datetime import datetime
from typing import Tuple


def fetch_unscanned_installations(table_uri: str) -> Tuple[dict, int]:
    client = Client()
    query = f"SELECT user_email, package, version, install_timestamp, log_insert_id FROM `{table_uri}` WHERE package != 'psycopg2' ORDER BY install_timestamp ASC"

    res = client.query_and_wait(query)

    unscanned = {}
    count = 0
    for package_data in res:
        count += 1
        unscanned[package_data[0]] = unscanned.get(package_data[0], []) + [{
            "package": package_data[1],
            "version": package_data[2],
            "install_timestamp": package_data[3].strftime("%Y-%m-%d %H:%M:%S"),
            "log_insert_id": package_data[4],
        }]

    return unscanned, count


def persist_scan_results(table_uri: str, results: list[dict]) -> None:
    client = Client()

    rows_to_insert = [
        {
            "log_insert_id": res["log_insert_id"], 
            "scan_timestamp": datetime.now().isoformat(),
            "has_vulnerabilities": res["has_vulnerabilities"],
            "raw_scan_report": json.dumps(res["raw_scan_report"]),
            "vulnerabilities": json.dumps(res["vulnerabilities"]),
        }
        for res in results
    ]

    errors = client.insert_rows_json(table_uri, rows_to_insert)
    if errors != []:
        print("Encountered errors while inserting rows: {}".format(errors))
        raise Exception(f"BigQuery insert failed {errors}")
