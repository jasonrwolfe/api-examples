import hashlib
import hmac
import json
import os
import time
import argparse

import requests
from dotenv import load_dotenv


load_dotenv()

API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")
HOST = os.getenv("HOST")
AUTH_HOST = os.getenv("AUTH_HOST")

required_vars = {
    "API_KEY": API_KEY,
    "API_SECRET": API_SECRET,
    "HOST": HOST,
    "AUTH_HOST": AUTH_HOST,
}

missing = [name for name, value in required_vars.items() if not value]

if missing:
    raise RuntimeError(
        f"Missing required environment variables: {', '.join(missing)}"
    )


def get_token():
    path = "/v2/tokens"
    url = f"https://{AUTH_HOST}{path}"
    timestamp = str(int(time.time() * 1000))
    method = "POST"

    payload = {
        "allowed_endpoints": [
            "DELETE",
            "GET",
            "HEAD",
            "OPTIONS",
            "PATCH",
            "POST",
            "PUT",
            "ANY",
        ],
        "validity": 240,
    }

    body = json.dumps(payload, separators=(",", ":"))
    string_to_sign = timestamp + method + path + body

    signature = hmac.new(
        API_SECRET.encode("utf-8"),
        msg=string_to_sign.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-API-Key": API_KEY,
        "X-Signature": signature,
        "X-Timestamp": timestamp,
    }

    response = requests.post(
        url,
        data=body,
        headers=headers,
        timeout=30,
    )
    response.raise_for_status()

    return response.json()["data"]


def get_vulns(image, token, registry=None):
    url = f"https://{HOST}/api/v2/hub/findings/vulnerabilities/images/list"

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }

    params = {
        "skip_count": "true",
        "search_value": image,
        "search_attribute": "image_name",
        "search_operator": "like",
        "case_sensitive": "false",
        "include_referenced_cves": "true",
        "include_vpatch_info": "true",
        "show_negligible": "true",
        "hide_base_image": "false",
        "order_by": "-acknowledged_date",
        "columns_name": "custom_columns",
        "columns": "ack_author,ack_comment,ack_expiration_configured_at,ack_expiration_days,ack_scope,acknowledged_date,aqua_severity,architecture,custom_severity,exploitability,format,has_running_workloads,image_digest,image_name,image_repository_name,image_uid,mutable,name,parent,path,permission,registry,resource.categories,resource.cpe,resource.format,resource.name,resource.path,resource.type,scan_resource_id,suppression_rule_id,suppression_rule_name,suppression_rule_scopes,type,v_patch_policy_name,v_patch_status,vendor_fix,vulnerability_id",
    }

    # Add registry filter only when supplied.
    if registry:
        params["registry_name"] = registry

    response = requests.get(
        url,
        headers=headers,
        params=params,
        timeout=30,
    )
    response.raise_for_status()

    # Logic:
    # If the parent is acknowledged, print the parent and all of its
    # referenced vulnerabilities, regardless of their ack date.
    #
    # If the parent is not acknowledged, print it only when at least one
    # referenced vulnerability is acknowledged, and print only those
    # acknowledged referenced vulnerabilities.
    #
    # 1970... and 0001... mean not acknowledged.
    NOT_ACKNOWLEDGED = {
        "1970-01-01T00:00:00Z",
        "0001-01-01T00:00:00Z",
    }

    for fields in response.json().get("result", []):
        # Skip standalone referenced CVEs returned at the top level.
        # We process them from the parent's referenced_vulnerabilities instead.
        if fields.get("parent"):
            continue

        parent_ack = fields.get("acknowledged_date")
        referenced_vulns = fields.get("referenced_vulnerabilities", [])

        # Determine whether the parent itself is acknowledged.
        parent_is_acknowledged = (
            parent_ack
            and parent_ack not in NOT_ACKNOWLEDGED
        )

        if parent_is_acknowledged:
            # Parent is acknowledged, so include ALL referenced vulnerabilities.
            referenced_to_print = referenced_vulns
        else:
            # Parent is not acknowledged, so only include acknowledged
            # referenced vulnerabilities.
            referenced_to_print = [
                referenced
                for referenced in referenced_vulns
                if referenced.get("acknowledged_date")
                and referenced.get("acknowledged_date") not in NOT_ACKNOWLEDGED
            ]

        # Nothing qualifies.
        if not parent_is_acknowledged and not referenced_to_print:
            continue

        print(
            f"Parent CVE: {fields.get('name', 'N/A')} "
            f"Severity: {fields.get('aqua_severity', 'N/A')} "
            f"Registry: {fields.get('registry', 'N/A')} "
            f"Repository: {fields.get('image_repository_name', 'N/A')} "
            f"Image: {fields.get('image_name', 'N/A')} "
            f"Acknowledged: {fields.get('acknowledged_date', 'N/A')} "
            f"Ack Expiration Days: {fields.get('ack_expiration_days', 'N/A')}"
        )

        for referenced in referenced_to_print:
            print(
                f"  Referenced CVE: {referenced.get('name', 'N/A')} "
                f"Severity: {referenced.get('aqua_severity', 'N/A')} "
                f"Acknowledged: {referenced.get('acknowledged_date', 'N/A')} "
                f"Ack Expiration Days: "
                f"{referenced.get('ack_expiration_days', 'N/A')}"
            )


def main():
    parser = argparse.ArgumentParser(
        description="List image vulnerability suppressions"
    )
    parser.add_argument(
        "image",
        help="Image name to search for, e.g. amazonlinux",
    )
    parser.add_argument(
        "registry",
        nargs="?",
        default=None,
        help='Optional registry name, e.g. "Docker Hub", "Ad Hoc Scans"',
    )

    args = parser.parse_args()

    token = get_token()
    get_vulns(args.image, token, args.registry)


if __name__ == "__main__":
    main()