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
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import reputation


class DomainReputationParams(Params):
    domain: str = Param(
        description="Domain to query", required=True, primary=True, cef_types=["domain"]
    )


class DomainReputationOutput(ActionOutput):
    Observable: str
    Threat_Level: str
    Threat_Categories: str
    AUP: str


@app.action(
    description="Look up Cisco Talos threat intelligence for a given domain",
    action_type="investigate",
    read_only=True,
    verbose="Provides intelligence about a domain, so you can take appropriate actions against untrusted or unwanted resources.",
)
def domain_reputation(
    params: DomainReputationParams, soar: SOARClient, asset: Asset
) -> DomainReputationOutput:
    result = reputation(asset, soar, params.domain, "domain")
    soar.set_message(f"{params.domain} has a {result['Threat_Level']} threat level")
    return DomainReputationOutput(**result)
