# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import ipaddress
import json
import re
import ssl
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import httpx

REPUTATION_ENDPOINT = "/Talos.Service.URS/QueryReputationV3"
TAXONOMY_ENDPOINT = "/Talos.Service.TTS/QueryTaxonomyCatalogs"


def make_client(asset):
    cert_pem = (
        "-----BEGIN CERTIFICATE-----\n"  # pragma: allowlist secret
        + "\n".join(
            asset.certificate[i : i + 64] for i in range(0, len(asset.certificate), 64)
        )
        + "\n-----END CERTIFICATE-----\n"
    )
    key_pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"  # pragma: allowlist secret
        + "\n".join(asset.key[i : i + 64] for i in range(0, len(asset.key), 64))
        + "\n-----END RSA PRIVATE KEY-----\n"  # pragma: allowlist secret
    )
    with tempfile.TemporaryDirectory() as directory:
        cert_path = Path(directory) / "client.pem"
        key_path = Path(directory) / "client.key"
        cert_path.write_text(cert_pem)
        key_path.write_text(key_pem)
        context = ssl.create_default_context()
        context.check_hostname = bool(asset.verify_server_cert)
        context.verify_mode = (
            ssl.CERT_REQUIRED if asset.verify_server_cert else ssl.CERT_NONE
        )
        context.load_cert_chain(str(cert_path), str(key_path))
        return context


def request(asset, endpoint, payload):
    context = make_client(asset)
    with httpx.Client(verify=context, http2=True, timeout=5.0) as client:
        response = client.post(asset.base_url.rstrip("/") + endpoint, json=payload)
        if "json" not in response.headers.get("content-type", ""):
            text = response.text.strip()
            raise RuntimeError(
                f"Status Code: {response.status_code}. Data from server:\n{text}"
            )
        try:
            data = response.json()
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Unable to parse JSON response: {exc}") from exc
        if response.status_code >= 399:
            raise RuntimeError(
                f"Error from server. Status Code: {response.status_code} Data from server: {response.text}"
            )
        return data


def app_info(soar):
    return {
        "product_family": "splunk",
        "product_id": "soar",
        "device_id": str(soar.get_asset_id()),
        "product_version": "1.0.17",
        "perf_testing": False,
    }


def reputation(asset, soar, observable, kind):
    if kind == "ip":
        try:
            address = ipaddress.ip_address(observable)
        except ValueError as exc:
            raise ValueError(
                f"{observable} is not a valid IPv4 or IPv6 address. Perhaps you meant to use the 'domain reputation' or 'url reputation' action instead of 'ip reputation'?"
            ) from exc
        encoded = (
            {"ipv4_addr": int(address)}
            if address.version == 4
            else {"ipv6_addr": address.packed.hex()}
        )
        urls = {"endpoint": [encoded]}
    elif kind == "domain":
        if not re.match(
            r"^(?!-)([A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$", observable
        ):
            raise ValueError(
                f"{observable} is not a valid domain name. Perhaps you meant to use the 'ip reputation' or 'url reputation' action instead of 'domain reputation'?"
            )
        urls = [{"raw_url": observable}]
    else:
        parsed = urlparse(observable)
        if not (parsed.scheme and parsed.netloc):
            raise ValueError(
                f"{observable} is not a valid URL. Perhaps you meant to use the 'ip reputation' or 'domain reputation' action instead of 'url reputation'?"
            )
        urls = [{"raw_url": observable}]

    metadata = app_info(soar)
    taxonomy_response = request(asset, TAXONOMY_ENDPOINT, {"app_info": metadata})
    taxonomy = taxonomy_response["catalogs"]["2"]["taxonomies"]
    response = request(asset, REPUTATION_ENDPOINT, {"urls": urls, "app_info": metadata})
    threat_level = ""
    threat_categories = []
    aup_categories = []
    for result in response.get("results", []):
        for url_result in result.get("results", []):
            for tag in url_result.get("context_tags", []):
                tax_id, entry_id = (
                    str(tag["taxonomy_id"]),
                    str(tag["taxonomy_entry_id"]),
                )
                tax = taxonomy.get(tax_id)
                if not tax or not tax.get("is_avail"):
                    continue
                category = tax["name"]["en-us"]["text"]
                entry = tax["entries"][entry_id]
                name = entry["name"]["en-us"]["text"]
                if category == "Threat Levels":
                    threat_level = name
                elif category == "Threat Categories":
                    threat_categories.append(name)
                elif category == "Acceptable Use Policy Categories":
                    aup_categories.append(name)
    return {
        "Observable": observable,
        "Threat_Level": threat_level,
        "Threat_Categories": ", ".join(threat_categories),
        "AUP": ", ".join(aup_categories),
    }
