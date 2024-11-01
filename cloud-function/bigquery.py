import json
from google.cloud.bigquery import Client
from typing import Tuple
from datetime import datetime
from time import sleep

MAX_NUM_READ_RETRIES = 3

def fetch_unpacked_package_installation_info(log_insert_id: str) -> Tuple[str, str, str]:
    client = Client()
    query = f"SELECT package, version, user_email FROM `knada-dev.pypi_proxy_data.package_installations` WHERE log_insert_id = '{log_insert_id}'"

    for i in range(MAX_NUM_READ_RETRIES):
        res = client.query_and_wait(query)

        rows = [r for r in res]
        if len(rows) == 1:
            package_data = rows[0]
            return package_data[0], package_data[1], package_data[2]
        
        sleep(1)

    raise Exception(f"unable to read unpacked data for log_insert_id = '{log_insert_id}', length of view query results was {len(rows)}")


def persist_scan_results(log_insert_id: str, has_vulnerabilities: bool, report: dict, vulnerabilities: list) -> None:
    client = Client()

    scan_timestamp = datetime.now().isoformat()
    query = f"INSERT INTO `knada-dev.pypi_proxy_data.package_installations_scan` VALUES ('{log_insert_id}',{has_vulnerabilities},False,'{scan_timestamp}','{json.dumps(report).replace("'","\\'")}','{json.dumps(vulnerabilities).replace("'","\\'")}')"
    client.query_and_wait(query)
