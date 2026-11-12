# Cisco Talos Intelligence

Publisher: Splunk <br>
Connector Version: 1.0.17 <br>
Product Vendor: Cisco <br>
Product Name: Talos Intelligence <br>
Minimum Product Version: 7.0.0

This app provides investigative actions for Cisco Talos Intelligence. It is only supported on Splunk SOAR Cloud, and it is not supported for FedRAMP customers.

## Cisco Talos Intelligence license for Splunk SOAR (Cloud)

The Cisco Talos Intelligence license is included with your Splunk SOAR (Cloud) license.

## Overview

This app uses the Cisco Talos API that specializes in identifying, analyzing, and mitigating cybersecurity threats.

For additional details, see the [Cisco Talos Intelligence article](https://docs.splunk.com/Documentation/SOAR/current/Playbook/Talos) in the Splunk SOAR documentation.

**Note:** The Cisco Talos Intelligence asset is already configured in your Splunk SOAR (Cloud) deployment.

### Configuration variables

This table lists the configuration variables required to operate Cisco Talos Intelligence. These variables are specified when configuring a Talos Intelligence asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** | required | string | Base URL provided by Talos. |
**certificate** | required | password | Certificate contents to authenticate with Talos. |
**key** | required | password | Private key to authenticate with Talos. |
**verify_server_cert** | required | boolean | Verify server certificate. |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the Talos asset by querying Cisco.com reputation. <br>
[domain reputation](#action-domain-reputation) - Look up Cisco Talos threat intelligence for a given domain <br>
[ip reputation](#action-ip-reputation) - Look up Cisco Talos threat intelligence for a given IP address <br>
[make request](#action-make-request) - Send a generic HTTP request to the configured Cisco Talos API host. <br>
[url reputation](#action-url-reputation) - Look up Cisco Talos threat intelligence for a given URL

## action: 'test connectivity'

Validate the Talos asset by querying Cisco.com reputation.

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'domain reputation'

Look up Cisco Talos threat intelligence for a given domain

Type: **investigate** <br>
Read only: **True**

Provides intelligence about a domain, so you can take appropriate actions against untrusted or unwanted resources.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** | required | Domain to query | string | `domain` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.domain | string | `domain` | |
action_result.data.\*.Observable | string | | |
action_result.data.\*.Threat_Level | string | | |
action_result.data.\*.Threat_Categories | string | | |
action_result.data.\*.AUP | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'ip reputation'

Look up Cisco Talos threat intelligence for a given IP address

Type: **investigate** <br>
Read only: **True**

Provides intelligence about an IP, so you can take appropriate actions against untrusted or unwanted resources.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP to query | string | `ip` `ipv6` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ip | string | `ip` `ipv6` | |
action_result.data.\*.Observable | string | | |
action_result.data.\*.Threat_Level | string | | |
action_result.data.\*.Threat_Categories | string | | |
action_result.data.\*.AUP | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'make request'

Send a generic HTTP request to the configured Cisco Talos API host.

Type: **generic** <br>
Read only: **False**

'make request' action for the app. Used to handle arbitrary HTTP requests with the app's asset

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**http_method** | required | The HTTP method to use for the request. | string | |
**endpoint** | required | The endpoint to send the request to. | string | |
**headers** | optional | The headers to send with the request (JSON object). An example is {'Content-Type': 'application/json'} | string | |
**query_parameters** | optional | Parameters to append to the URL (JSON object or query string). An example is ?key=value&key2=value2 | string | |
**body** | optional | The body to send with the request (JSON object). An example is {'key': 'value', 'key2': 'value2'} | string | |
**timeout** | optional | The timeout for the request in seconds. | numeric | |
**verify_ssl** | optional | Whether to verify the SSL certificate. Default is True. | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.http_method | string | | |
action_result.parameter.endpoint | string | | |
action_result.parameter.headers | string | | |
action_result.parameter.query_parameters | string | | |
action_result.parameter.body | string | | |
action_result.parameter.timeout | numeric | | |
action_result.parameter.verify_ssl | boolean | | |
action_result.data.\*.status_code | numeric | | 200 404 500 |
action_result.data.\*.response_body | string | | {"key": "value"} |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'url reputation'

Look up Cisco Talos threat intelligence for a given URL

Type: **investigate** <br>
Read only: **True**

Provides intelligence about a URL, so you can take appropriate actions against untrusted or unwanted resources.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** | required | URL to query | string | `url` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.url | string | `url` | |
action_result.data.\*.Observable | string | | |
action_result.data.\*.Threat_Level | string | | |
action_result.data.\*.Threat_Categories | string | | |
action_result.data.\*.AUP | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
