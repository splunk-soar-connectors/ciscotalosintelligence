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
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory
from soar_sdk.logging import getLogger

logger = getLogger()


class Asset(BaseAsset):
    base_url: str = AssetField(
        description="Base URL provided by Talos.",
        default="https://soar-api.talos.cisco.com",
        category=FieldCategory.CONNECTIVITY,
    )
    certificate: str = AssetField(
        description="Certificate contents to authenticate with Talos.",
        required=True,
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    key: str = AssetField(
        description="Private key to authenticate with Talos.",
        required=True,
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    verify_server_cert: bool = AssetField(
        description="Verify server certificate.",
        default=True,
        category=FieldCategory.CONNECTIVITY,
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
    """Validate the Talos asset by querying Cisco.com reputation."""
    from .helper import app_info, request, REPUTATION_ENDPOINT

    metadata = app_info(soar)
    metadata["perf_testing"] = True
    request(
        asset,
        REPUTATION_ENDPOINT,
        {"urls": [{"raw_url": "cisco.com"}], "app_info": metadata},
    )


from .actions import domain_reputation, ip_reputation, make_request, url_reputation  # noqa: F401

if __name__ == "__main__":
    app.cli()
