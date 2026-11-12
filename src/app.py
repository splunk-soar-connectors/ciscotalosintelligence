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
from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.params import Param, Params
from soar_sdk.action_results import ActionOutput
from soar_sdk.asset import BaseAsset, AssetField
from soar_sdk.logging import getLogger

logger = getLogger()


class Asset(BaseAsset):
    base_url: str = AssetField(
        description="Base URL provided by Talos.",
        default="https://soar-api.talos.cisco.com",
    )
    certificate: str = AssetField(
        description="Certificate contents to authenticate with Talos."
    )
    key: str = AssetField(description="Private key to authenticate with Talos.")
    verify_server_cert: bool | None = AssetField(
        description="Verify server certificate.", default=True
    )


app = App(
    name="Cisco Talos Intelligence",
    app_type="information",
    logo="ciscotalosintelligence.svg",
    logo_dark="ciscotalosintelligence_dark.svg",
    product_vendor="Cisco",
    product_name="Talos Intelligence",
    publisher="Splunk",
    appid="7c653487-22c8-4ec1-bca0-16a8b1513c86",
    python_version="3.13",
    fips_compliant=False,
    encrypt_cache_state=True,
    encrypt_ingest_state=True,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    from .helper import app_info, request, REPUTATION_ENDPOINT

    metadata = app_info(soar)
    metadata["perf_testing"] = True
    request(
        asset,
        REPUTATION_ENDPOINT,
        {"urls": [{"raw_url": "cisco.com"}], "app_info": metadata},
    )
    soar.set_message("Test Connectivity Passed")


class IpReputationParams(Params):
    ip: str = Param(
        description="IP to query", primary=True, default="", cef_types=["ip", "ipv6"]
    )


class IpReputationOutput(ActionOutput):
    Observable: str
    Threat_Level: str
    Threat_Categories: str
    AUP: str


@app.action(
    description="Look up Cisco Talos threat intelligence for a given IP address",
    action_type="investigate",
    verbose="Provides intelligence about an IP, so you can take appropriate actions against untrusted or unwanted resources.",
)
def ip_reputation(
    params: IpReputationParams, soar: SOARClient, asset: Asset
) -> IpReputationOutput:
    from .helper import reputation

    result = reputation(asset, soar, params.ip, "ip")
    soar.set_message(f"{params.ip} has a {result['Threat_Level']} threat level")
    return IpReputationOutput(**result)


class DomainReputationParams(Params):
    domain: str = Param(
        description="Domain to query", primary=True, default="", cef_types=["domain"]
    )


class DomainReputationOutput(ActionOutput):
    Observable: str
    Threat_Level: str
    Threat_Categories: str
    AUP: str


@app.action(
    description="Look up Cisco Talos threat intelligence for a given domain",
    action_type="investigate",
    verbose="Provides intelligence about a domain, so you can take appropriate actions against untrusted or unwanted resources.",
)
def domain_reputation(
    params: DomainReputationParams, soar: SOARClient, asset: Asset
) -> DomainReputationOutput:
    from .helper import reputation

    result = reputation(asset, soar, params.domain, "domain")
    soar.set_message(f"{params.domain} has a {result['Threat_Level']} threat level")
    return DomainReputationOutput(**result)


class UrlReputationParams(Params):
    url: str = Param(
        description="URL to query", primary=True, default="", cef_types=["url"]
    )


class UrlReputationOutput(ActionOutput):
    Observable: str
    Threat_Level: str
    Threat_Categories: str
    AUP: str


@app.action(
    description="Look up Cisco Talos threat intelligence for a given URL",
    action_type="investigate",
    verbose="Provides intelligence about a URL, so you can take appropriate actions against untrusted or unwanted resources.",
)
def url_reputation(
    params: UrlReputationParams, soar: SOARClient, asset: Asset
) -> UrlReputationOutput:
    from .helper import reputation

    result = reputation(asset, soar, params.url, "url")
    soar.set_message(f"{params.url} has a {result['Threat_Level']} threat level")
    return UrlReputationOutput(**result)


if __name__ == "__main__":
    app.cli()
