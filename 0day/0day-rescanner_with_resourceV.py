#!/usr/bin/env python3
import os
import sys
import time
import json
import hmac
import hashlib
import requests


MAX_BATCH_SIZE = 10000


class AquaAuth:
    REGION_ENDPOINTS = {
        "us": "https://api.cloudsploit.com",
        "eu": "https://eu-1.api.cloudsploit.com",
        "singapore": "https://asia-1.api.cloudsploit.com",
        "sydney": "https://ap-2.api.cloudsploit.com",
    }

    TOKEN_PATH = "/v2/tokens"
    METHOD = "POST"

    def __init__(self, api_key: str, api_secret: str, region: str = "us", base_url: str | None = None):
        self.api_key = api_key
        self.api_secret = api_secret.encode()
        self.base_url = base_url.rstrip("/") if base_url else self.REGION_ENDPOINTS[region.lower()]
        self.token = None

    def _generate_signature(self, timestamp: str, body: str) -> str:
        string_to_sign = f"{timestamp}{self.METHOD}{self.TOKEN_PATH}{body}"
        return hmac.new(self.api_secret, string_to_sign.encode(), hashlib.sha256).hexdigest()

    def authenticate(self, validity: int = 240, allowed_endpoints=None, verbose: bool = False) -> str:
        if allowed_endpoints is None:
            allowed_endpoints = ["GET", "POST"]

        timestamp = str(int(time.time()))
        body_dict = {
            "validity": validity,
            "allowed_endpoints": allowed_endpoints,
        }
        body = json.dumps(body_dict, separators=(",", ":"))
        signature = self._generate_signature(timestamp, body)

        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key,
            "X-Timestamp": timestamp,
            "X-Signature": signature,
        }

        url = f"{self.base_url}{self.TOKEN_PATH}"

        if verbose:
            print(f"Auth endpoint: {url}")
            print(f"Auth body: {body}")

        response = requests.post(url, headers=headers, data=body)

        if verbose:
            print(f"Auth response status: {response.status_code}")
            print(f"Auth response body (first 1000 chars): {response.text[:1000]}")

        if response.status_code != 200:
            raise RuntimeError(f"Authentication failed: {response.text}")

        token = response.json()["data"]
        self.token = token
        return token


def make_headers(token: str) -> dict:
    return {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }


def extract_results(page_json):
    if isinstance(page_json, dict):
        if isinstance(page_json.get("result"), list):
            return page_json["result"]
        if isinstance(page_json.get("results"), list):
            return page_json["results"]
        if isinstance(page_json.get("data"), list):
            return page_json["data"]
        data = page_json.get("data")
        if isinstance(data, dict):
            if isinstance(data.get("result"), list):
                return data["result"]
            if isinstance(data.get("results"), list):
                return data["results"]
    if isinstance(page_json, list):
        return page_json
    return []


def get_all_images(session, base_url, token, search_value, resource_version=None, page_size=200, verbose=False):
    list_url = f"{base_url.rstrip('/')}/api/v2/hub/findings/vulnerabilities/images/list"
    headers = make_headers(token)

    base_params = {
        "include_vpatch_info": "true",
        "show_negligible": "true",
        "hide_base_image": "false",
        "severities": "critical,high",
        "exploit_availability": "available",
        "order_by": "-aqua_severity",
        "use_estimated_count": "false",
        "skip_count": "true",
        "pagesize": page_size,
    }

    # Keep the original filters; remove these if your tenant rejects them.
    if search_value:
        base_params["search_value"] = search_value
        base_params["search_attribute"] = "resource.name"
        base_params["search_operator"] = "like"
        base_params["case_sensitive"] = "false"

    if resource_version:
        base_params["resource_version"] = resource_version

    if verbose:
        print(f"API base URL: {base_url}")
        print(f"List endpoint: {list_url}")
        print(f"Base params: {json.dumps(base_params, sort_keys=True)}")

    all_results = []
    page = 1

    while True:
        params = base_params.copy()
        params["page"] = page

        r = session.get(list_url, headers=headers, params=params)

        if verbose:
            print(f"List request URL: {r.url}")
            print(f"List response status: {r.status_code}")
            print(f"List response body (first 1000 chars): {r.text[:1000]}")

        if r.status_code == 404:
            raise RuntimeError(
                "404 from findings images list endpoint.\n"
                f"URL: {r.url}\n"
                "The endpoint was not found on this tenant.\n"
                f"Response body: {r.text[:500]}"
            )

        if r.status_code == 403:
            raise RuntimeError(
                "403 from findings images list endpoint.\n"
                f"URL: {r.url}\n"
                "The token is not allowed to list image vulnerability findings on this platform API.\n"
                f"Response body: {r.text[:500]}"
            )

        r.raise_for_status()

        page_json = r.json()
        results = extract_results(page_json)

        if verbose:
            print(f"Parsed results on page {page}: {len(results)}")

        if not isinstance(results, list) or not results:
            break

        all_results.extend(results)

        if len(results) < page_size:
            break

        page += 1

    return all_results


def build_image_list(results):
    images = []
    seen = set()

    for item in results:
        image = None
        registry = None

        if isinstance(item, dict):
            # Findings API returns the actual container image in image_name.
            image = item.get("image_name")
            registry = item.get("registry")

            # Fallbacks for tenants with slightly different payloads.
            if not image:
                image = item.get("image_repository_name")

            if not image:
                image_obj = item.get("image")
                if isinstance(image_obj, dict):
                    image = image_obj.get("name")
                    registry = registry or image_obj.get("registry")
                elif isinstance(image_obj, str):
                    image = image_obj

            # Last-resort fallback only if no image-specific field exists.
            if not image:
                resource = item.get("resource")
                if isinstance(resource, dict):
                    image = resource.get("name")
                    registry = registry or resource.get("registry")

        if image:
            dedupe_key = (image, registry or "")
            if dedupe_key not in seen:
                seen.add(dedupe_key)
                images.append({
                    "image": image,
                    "registry": registry,
                })

    return images


def chunk_list(data, size):
    for i in range(0, len(data), size):
        yield data[i:i + size]


def post_batch(session, base_url, token, batch, verbose=False):
    url = f"{base_url.rstrip('/')}/api/v2/images"

    file_content = ""
    for item in batch:
        file_content += json.dumps(item) + "\n"

    files = {
        "file": ("images.txt", file_content, "text/plain"),
    }

    headers = make_headers(token)

    if verbose:
        print(f"Upload endpoint: {url}")
        print(f"Uploading batch of {len(batch)} images")

    r = session.post(url, headers=headers, files=files)

    if verbose:
        print(f"Upload response status: {r.status_code}")
        print(f"Upload response body (first 1000 chars): {r.text[:1000]}")

    if r.status_code == 403:
        raise RuntimeError(
            "403 from rescan upload endpoint.\n"
            f"URL: {url}\n"
            "The token is not allowed to submit rescans through /api/v2/images.\n"
            f"Response body: {r.text[:500]}"
        )

    r.raise_for_status()
    return r.json()


def resolve_token(api_key, api_secret, auth_base_url, region, verbose=False):
    direct_token = os.getenv("AQUA_PLATFORM_TOKEN") or os.getenv("AQUA_BEARER_TOKEN")
    if direct_token:
        if verbose:
            print("Using bearer token from AQUA_PLATFORM_TOKEN/AQUA_BEARER_TOKEN")
        return direct_token.strip(), "direct-platform-token"

    if not auth_base_url:
        raise RuntimeError(
            "No direct bearer token found and AQUA_CLOUDSPLOIT_URL is not set. "
            "Set AQUA_PLATFORM_TOKEN/AQUA_BEARER_TOKEN or provide AQUA_CLOUDSPLOIT_URL."
        )

    auth = AquaAuth(
        api_key,
        api_secret,
        region=region,
        base_url=auth_base_url,
    )
    token = auth.authenticate(verbose=verbose)
    return token, "cloudsploit-temporary-token"


if __name__ == "__main__":
    API_KEY = os.getenv("AQUA_API_KEY")
    API_SECRET = os.getenv("AQUA_API_SECRET")
    API_BASE_URL = os.getenv("AQUA_BASE_URL")
    AUTH_BASE_URL = os.getenv("AQUA_CLOUDSPLOIT_URL")
    REGION = os.getenv("AQUA_REGION", "us")

    if not API_KEY or not API_SECRET or not API_BASE_URL:
        raise RuntimeError("Missing required environment variables: AQUA_API_KEY, AQUA_API_SECRET, AQUA_BASE_URL")

    if len(sys.argv) < 2:
        print("Usage: python script.py <search_value> [resource_version]")
        print("Optional env override: AQUA_PLATFORM_TOKEN or AQUA_BEARER_TOKEN")
        sys.exit(1)

    SEARCH_VALUE = sys.argv[1]
    RESOURCE_VERSION = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"Using AQUA_BASE_URL={API_BASE_URL}")
    print(f"Using AQUA_CLOUDSPLOIT_URL={AUTH_BASE_URL}")
    print(f"Using AQUA_REGION={REGION}")

    token, token_source = resolve_token(
        api_key=API_KEY,
        api_secret=API_SECRET,
        auth_base_url=AUTH_BASE_URL,
        region=REGION,
        verbose=True,
    )
    print(f"Token source: {token_source}")

    session = requests.Session()

    try:
        raw_results = get_all_images(
            session=session,
            base_url=API_BASE_URL,
            token=token,
            search_value=SEARCH_VALUE,
            resource_version=RESOURCE_VERSION,
            page_size=200,
            verbose=True,
        )
    except requests.exceptions.HTTPError as e:
        response = getattr(e, "response", None)
        if response is not None:
            raise RuntimeError(
                f"HTTP request failed with status {response.status_code} for URL: {response.url}\n"
                f"Response body: {response.text[:1000]}"
            ) from e
        raise

    print(f"\nPotentially impacted findings: {len(raw_results)}")

    images = build_image_list(raw_results)

    for img in images:
        print(img["image"])

    print(f"Rescan list created: {len(images)}")

    for batch in chunk_list(images, MAX_BATCH_SIZE):
        post_batch(
            session=session,
            base_url=API_BASE_URL,
            token=token,
            batch=batch,
            verbose=True,
        )

