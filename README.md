[comment]: # "Auto-generated SOAR connector documentation"
# Cisco Talos Intelligence

Publisher: Splunk  
Connector Version: 1.0.1  
Product Vendor: Cisco  
Product Name: Talos Cloud Intelligence  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.2.1.305  

This app provides investigative actions for Cisco Talos Intelligence

[comment]: # " File: README.md"
[comment]: # "Copyright (c) 2024 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## Getting a Talos license 

A request needs to be made to the Talos team. In the configuration window please insert the certificate contents and
private key separatley.  

## Talos

This app makes use of Ciscos Talos API that specializes in identifying, analyzing, and mitigating cybersecurity threats


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Talos Cloud Intelligence asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** |  required  | string | Base URL provided by Talos
**certificate** |  optional  | password | Certificate contents to authenticate with Talos
**key** |  optional  | password | Private key to authenticate with Talos

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[ip reputation](#action-ip-reputation) - Queries IP info  
[domain reputation](#action-domain-reputation) - Queries domain info  
[url reputation](#action-url-reputation) - Queries URL info  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'ip reputation'
Queries IP info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip | string |  `ip`  |  
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data.0.Threat Level | string |  |  
action_result.data.1.Threat Categories | string |  |  
action_result.data.2.Acceptable Use Policy Categories | string |  |    

## action: 'domain reputation'
Queries domain info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.domain | string |  `domain`  `url`  |  
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data.0.Threat Level | string |  |  
action_result.data.1.Threat Categories | string |  |  
action_result.data.2.Acceptable Use Policy Categories | string |  |    

## action: 'url reputation'
Queries URL info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to query | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.url | string |  `url`  |  
action_result.status | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data.0.Threat Level | string |  |  
action_result.data.1.Threat Categories | string |  |  
action_result.data.2.Acceptable Use Policy Categories | string |  |  