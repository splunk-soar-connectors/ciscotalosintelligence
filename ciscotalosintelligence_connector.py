#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

import ipaddress
import json
import os
import tempfile

import httpx

# Phantom App imports
import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from ciscotalosintelligence_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class TalosIntelligenceConnector(BaseConnector):
    def __init__(self):
        super(TalosIntelligenceConnector, self).__init__()

        self._state = None

        self._base_url = None
        self._certificate = None
        self._key = None

        self._appinfo = None
        self._catalog_id = 2

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"),
            None,
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace("{", "{{").replace("}", "}}")
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to parse JSON response. Error: {0}".format(str(e)),
                ),
                None,
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(r.status_code, r.text.replace("{", "{{").replace("}", "}}"))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        # Create a URL to connect to
        url = self._base_url + endpoint

        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix="test") as temp_file:
            combined_file = (
                "-----BEGIN CERTIFICATE-----\n"
                f"{self._certificate}\n"
                "-----END CERTIFICATE-----\n"
                "-----BEGIN RSA PRIVATE KEY-----\n"  # pragma: allowlist secret
                f"{self._key}\n"
                "-----END RSA PRIVATE KEY-----\n"
            )

            temp_file.write(combined_file)
            temp_file.seek(0)  # Move the file pointer to the beginning for reading
            temp_file_path = temp_file.name  # Get the name of the temporary file
        try:
            client = httpx.Client(
                http2=True,
                verify=config.get("verify_server_cert", False),
                cert=temp_file_path,
            )
            request_func = getattr(client, method)

            r = request_func(url, **kwargs)

        except Exception as e:
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)

            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Connecting to server. Details: {0}".format(str(e)),
                ),
                resp_json,
            )

        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to endpoint")

        ret_val, response = self._make_rest_call(
            ENDPOINT_QUERY_AUP_CAT_MAP,
            action_result,
            "post",
            json={"app_info": self._appinfo},
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        self.save_progress("Received Metadata")
        self.save_progress("Test Connectivity Passed")

        self._state = {}
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_ip_reputation(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param["ip"]

        try:
            ip_addr = ipaddress.ip_address(ip)
            big_endian = int(ip_addr)

        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid IP Address")

        payload = {
            "urls": {"endpoint": [{"ipv4_addr": big_endian}]},
            "app_info": self._appinfo,
        }

        self._query_reputation(action_result, payload)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_domain_reputation(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param["domain"]

        payload = {"urls": [{"raw_url": domain}], "app_info": self._appinfo}

        self._query_reputation(action_result, payload)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_url_reputation(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        url = param["url"]

        payload = {"urls": [{"raw_url": url}], "app_info": self._appinfo}

        self._query_reputation(action_result, payload)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _query_reputation(self, action_result, payload):
        taxonomy_ret_val, taxonomy = self._fetch_taxonomy(action_result)

        if phantom.is_fail(taxonomy_ret_val):
            return action_result.get_status()

        # make rest call
        ret_val, response = self._make_rest_call(ENDPOINT_QUERY_REPUTATION_V3, action_result, method="post", json=payload)
        response_taxonomy_map_version = response["taxonomy_map_version"]

        if response_taxonomy_map_version > self._state["taxonomy_version"]:
            taxonomy_ret_val, taxonomy = self._fetch_taxonomy(action_result, allow_cache=False)

        if phantom.is_fail(ret_val) or "results" not in response:
            return action_result.get_status()

        summary = action_result.update_summary({})

        threat_level = ""
        threat_categories = {}
        aup_categories = {}

        for result in response["results"]:
            for url_result in result["results"]:
                for tag in url_result["context_tags"]:
                    tax_id = str(tag["taxonomy_id"])
                    entry_id = str(tag["taxonomy_entry_id"])

                    if tax_id not in taxonomy["taxonomies"]:
                        continue

                    category = taxonomy["taxonomies"][tax_id]["name"]["en-us"]["text"]
                    name = taxonomy["taxonomies"][tax_id]["entries"][entry_id]["name"]["en-us"]["text"]
                    description = taxonomy["taxonomies"][tax_id]["entries"][entry_id]["description"]["en-us"]["text"]

                    if category == "Threat Levels":
                        threat_level = name
                    elif category == "Threat Categories":
                        threat_categories[name] = description
                    elif category == "Acceptable Use Policy Categories":
                        aup_categories[name] = description

            summary["Threat Levels"] = threat_level
            action_result.add_data({"Threat Level": threat_level})

            summary["Threat Categories"] = threat_categories
            action_result.add_data({"Threat Categories": ", ".join(list(threat_categories.keys()))})

            summary["Acceptable Use Policy Categories"] = aup_categories
            action_result.add_data({"Acceptable Use Policy Categories": ", ".join(list(aup_categories.keys()))})

    def _fetch_taxonomy(self, action_result, allow_cache=True):
        payload = {"app_info": self._appinfo}

        if "taxonomy" in self._state and allow_cache:
            return 1, self._state["taxonomy"]

        ret_val, response = self._make_rest_call(ENDPOINT_QUERY_TAXONOMIES, action_result, method="post", json=payload)
        taxonomy = response["catalogs"][str(self._catalog_id)]

        self._state = {"taxonomy": taxonomy, "taxonomy_version": response["version"]}

        return ret_val, taxonomy

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == "ip_reputation":
            ret_val = self._handle_ip_reputation(param)

        if action_id == "domain_reputation":
            ret_val = self._handle_domain_reputation(param)

        if action_id == "url_reputation":
            ret_val = self._handle_url_reputation(param)

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        def insert_newlines(string, every=64):
            return "\n".join(string[i : i + every] for i in range(0, len(string), every))

        self._base_url = config["base_url"]
        self._certificate = insert_newlines(config["certificate"])
        self._key = insert_newlines(config["key"])

        self._appinfo = {
            "product_family": "splunk",
            "product_id": "soar",
            "device_id": self.get_product_installation_id(),
            "product_version": self.get_product_version(),
        }

        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = TalosIntelligenceConnector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = TalosIntelligenceConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
