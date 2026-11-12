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
import json

from soar_sdk.action_results import MakeRequestOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import MakeRequestParams

from ..app import Asset, app
from ..helper import make_request


@app.make_request()
def talos_make_request(params: MakeRequestParams, asset: Asset) -> MakeRequestOutput:
    """Send a generic HTTP request to the configured Cisco Talos API host."""
    endpoint = params.endpoint.strip()
    if not endpoint or endpoint.startswith(("http://", "https://", "//")):
        raise ActionFailure(
            "Endpoint must be a relative path on the configured Talos API host."
        )

    try:
        headers = json.loads(params.headers) if params.headers else {}
    except json.JSONDecodeError as exc:
        raise ActionFailure(f"Invalid JSON headers: {exc}") from exc
    if not isinstance(headers, dict):
        raise ActionFailure("Headers must be a JSON object.")

    query = None
    if params.query_parameters:
        try:
            query = json.loads(params.query_parameters)
        except json.JSONDecodeError:
            endpoint = f"{endpoint}?{params.query_parameters.lstrip('?')}"
        else:
            if not isinstance(query, dict):
                raise ActionFailure(
                    "Query parameters must be a JSON object or query string."
                )

    body = None
    content = None
    if params.body:
        try:
            body = json.loads(params.body)
        except json.JSONDecodeError:
            content = params.body

    response = make_request(
        asset,
        endpoint,
        method=params.http_method,
        headers=headers,
        query=query,
        body=body,
        content=content,
        timeout=params.timeout or 5,
        verify_ssl=params.verify_ssl,
    )
    return MakeRequestOutput(
        status_code=response.status_code, response_body=response.text
    )
