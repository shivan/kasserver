# kasserver - Manage domains hosted on All-Inkl.com through the KAS server API
# Copyright (c) 2018 Christian Fetzer
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Manage domains hosted on All-Inkl.com through the KAS server API"""

import importlib.metadata
import json
import logging
import math
import netrc
import os
import stat
import time
from pathlib import Path

import pyotp
import zeep
import zeep.helpers

__version__ = importlib.metadata.version("kasserver")
LOGGER = logging.getLogger(__name__)


class KasServer:
    """Manage domains hosted on All-Inkl.com through the KAS server API"""

    AUTH_WSDL = "https://kasapi.kasserver.com/soap/wsdl/KasAuth.wsdl"

    def __init__(self):
        wsdl_file = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "KasApi.wsdl",
        )
        self._client = zeep.Client(wsdl_file)
        self._auth_client = zeep.Client(self.AUTH_WSDL)

        self._username = None
        self._password = None
        self._session_token = None

        self._session_lifetime = int(os.environ.get("KASSERVER_SESSION_LIFETIME", "600"))
        self._session_update_lifetime = os.environ.get(
            "KASSERVER_SESSION_UPDATE_LIFETIME", "Y"
        )
        self._totp_secret = os.environ.get("KASSERVER_TOTP_SECRET")
        self._session_file = os.environ.get("KASSERVER_SESSION_FILE")

        self._get_credentials()
        self._flood_timeout = 0

    def _get_credentials(self):
        self._username = os.environ.get("KASSERVER_USER")
        self._password = os.environ.get("KASSERVER_PASSWORD")
        self._session_token = os.environ.get("KASSERVER_SESSION_TOKEN")

        if self._session_token:
            return

        if self._username:
            return

        server = "kasapi.kasserver.com"
        try:
            info = netrc.netrc().authenticators(server)
            if info:
                self._username = info[0]
                self._password = info[2]
        except (FileNotFoundError, netrc.NetrcParseError) as err:
            LOGGER.warning(
                "Cannot load credentials for %s from .netrc: %s",
                server,
                err,
            )

    def _load_session_from_file(self):
        if not self._session_file:
            return None

        path = Path(self._session_file)
        if not path.exists():
            return None

        try:
            st_mode = path.stat().st_mode
            if stat.S_IMODE(st_mode) & 0o077:
                LOGGER.warning(
                    "Session file %s is accessible by other users. "
                    "Recommended mode is 0600.",
                    path,
                )
            token = path.read_text(encoding="utf-8").strip()
            return token or None
        except OSError as err:
            LOGGER.warning("Cannot read session file %s: %s", path, err)
            return None

    def _save_session_to_file(self, token):
        if not self._session_file:
            return

        path = Path(self._session_file)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(token, encoding="utf-8")
            path.chmod(0o600)
        except OSError as err:
            LOGGER.warning("Cannot write session file %s: %s", path, err)

    def _get_totp_code(self):
        if not self._totp_secret:
            return None

        try:
            return pyotp.TOTP(self._totp_secret).now()
        except Exception as err:
            raise RuntimeError("Invalid KASSERVER_TOTP_SECRET") from err

    def _create_session_token(self):
        if self._session_token:
            return self._session_token

        file_token = self._load_session_from_file()
        if file_token:
            self._session_token = file_token
            return self._session_token

        if not self._username or not self._password:
            raise RuntimeError(
                "No KAS credentials found. Set KASSERVER_USER/KASSERVER_PASSWORD "
                "or provide KASSERVER_SESSION_TOKEN."
            )

        params = {
            "kas_login": self._username,
            "kas_auth_type": "plain",
            "kas_auth_data": self._password,
            "session_lifetime": self._session_lifetime,
            "session_update_lifetime": self._session_update_lifetime,
        }

        totp_code = self._get_totp_code()
        if totp_code:
            params["session_2fa"] = totp_code

        token = self._auth_client.service.KasAuth(json.dumps(params))
        self._session_token = token
        self._save_session_to_file(token)
        return token

    def _build_auth(self):
        if self._session_token:
            return "session", self._session_token

        file_token = self._load_session_from_file()
        if file_token:
            self._session_token = file_token
            return "session", self._session_token

        if self._totp_secret:
            token = self._create_session_token()
            return "session", token

        return "plain", self._password

    def _request(self, request, params):
        auth_type, auth_data = self._build_auth()

        request = {
            "KasUser": self._username,
            "KasAuthType": auth_type,
            "KasAuthData": auth_data,
            "KasRequestType": request,
            "KasRequestParams": params,
        }

        def _send_request(request_data):
            time.sleep(self._flood_timeout)
            try:
                result = self._client.service.KasApi(json.dumps(request_data))
                self._flood_timeout = result[1]["value"]["item"][0]["value"]
                return result
            except zeep.exceptions.Fault as exc:
                if exc.message == "flood_protection":
                    timeout = math.ceil(float(exc.detail.text))
                    LOGGER.warning("Hit flood protection, retrying in %ds", timeout)
                    time.sleep(timeout)
                    return _send_request(request_data)

                if request_data["KasAuthType"] == "session" and exc.message in {
                    "invalid credential",
                    "session invalid",
                    "session expired",
                }:
                    LOGGER.info("Session token invalid/expired, requesting new one")
                    self._session_token = None
                    if self._session_file:
                        try:
                            Path(self._session_file).unlink(missing_ok=True)
                        except OSError:
                            pass

                    auth_type, auth_data = self._build_auth()
                    request_data["KasAuthType"] = auth_type
                    request_data["KasAuthData"] = auth_data
                    return _send_request(request_data)

                raise

        return _send_request(request)

    @staticmethod
    def _split_fqdn(fqdn):
        """Split a FQDN into record_name and zone_name values"""
        if not fqdn:
            raise ValueError("Error: No valid FQDN given.")
        split_dns = fqdn.rstrip(".").rsplit(".", 2)
        return "".join(split_dns[:-2]), ".".join(split_dns[-2:]) + "."

    def get_dns_records(self, fqdn):
        """Get list of DNS records."""
        _, zone_name = self._split_fqdn(fqdn)
        res = self._request("get_dns_settings", {"zone_host": zone_name})

        items = res[1]["value"]["item"][2]["value"]["_value_1"]
        result = []
        for item in items:
            result.append(
                {i["key"].split("_", 1)[-1]: i["value"] for i in item["item"]}
            )
        return result

    def get_dns_record(self, fqdn, record_type):
        """Get a specific DNS record for a FQDN and type"""
        record_name, zone_name = self._split_fqdn(fqdn)
        result = self.get_dns_records(zone_name)
        for item in result:
            if item["name"] == record_name and item["type"] == record_type:
                return item
        return None

    def add_dns_record(self, fqdn, record_type, record_data, record_aux=None):
        """Add or update a DNS record"""
        record_name, zone_name = self._split_fqdn(fqdn)
        params = {
            "zone_host": zone_name,
            "record_name": record_name,
            "record_type": record_type,
            "record_data": record_data,
            "record_aux": record_aux if record_aux else "0",
        }

        existing_record = self.get_dns_record(fqdn, record_type)
        if existing_record:
            params["record_id"] = existing_record["id"]
            self._request("update_dns_settings", params)
        else:
            self._request("add_dns_settings", params)

    def delete_dns_record(self, fqdn, record_type):
        """Remove an existing DNS record"""
        existing_record = self.get_dns_record(fqdn, record_type)
        if existing_record:
            self._request("delete_dns_settings", {"record_id": existing_record["id"]})
