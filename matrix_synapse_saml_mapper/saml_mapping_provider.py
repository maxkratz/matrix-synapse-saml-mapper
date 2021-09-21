# -*- coding: utf-8 -*-
# Copyright 2021 Max Kratz
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

"""
This module will be used to map custom SAML attributes.
"""

import os
from datetime import datetime
from typing import Set, Tuple

from synapse.handlers.sso import MappingException
from synapse.module_api import ModuleApi
from synapse.api.errors import SynapseError

import attr
import psycopg2
import saml2.response
import yaml

# Heavily based on:
# https://github.com/matrix-org/synapse/blob/master/docs/sso_mapping_providers.md
#
# This class only exists because the IDP of TU Darmstadt cannot provide a
# 'displayName' value via SAML.
#
# It does not log to the synapse logger. Please keep in mind that this code might
# crash unexpectedly, but you can always check the homeservers log file for python
# error output.


module_config = yaml.safe_load(open("/etc/matrix-synapse/saml_mapper_config.yml"))
db_config = module_config.get("db")
log_config = module_config.get("log")


@attr.s
class SamlConfig:
    # This is just a config attribute, thus it does not need public methods.
    # pylint: disable=R0903
    """
    Used to configure the Matrix ID source attribute.
    This value will later be passed by the homeserver.yml configuration file.
    """
    mxid_source_attribute = attr.ib()


def save_to_custom_db(
        tuid: str,
        orga_unit: str,
        givenname: str,
        surname: str,
        email: str,
        edu_person_affiliation: str
):
    # Our database needs that much input values.
    # pylint: disable=R0913
    """
    Saves the provided information from SAML to our custom database.
    Uses the current time as timestamp for saving to the database.

    Args:
        tuid: TU-ID. Fancy name for the UID at TU Darmstadt. This is just one string.
        orga_unit: Department. This is an array for, e.g., students with two departments.
        givenname: Given name. Just one string (two names get concatenated by the TUs IDP).
        surname: Surname. Just one string (two names get concatenated by the TUs IDP).
        email: Email address. Array for persons with more than one address.
        edu_person_affiliation: Student/... Array, because most people have 'student' and
        'member'.
    """
    # Check if the custom database is disabled, if true return.
    if not db_config.get("enabled"):
        return

    # Get current date and time as utc.
    now = datetime.utcnow()

    try:
        conn = psycopg2.connect(
            database=db_config.get("database"),
            user=db_config.get("user"),
            password=db_config.get("password"),
            host=db_config.get("host"),
            port=db_config.get("port")
        )

        cur = conn.cursor()
        cur.execute(
            """INSERT INTO user_external_saml (
            tuid, ou, givenname, surname, email, edu_person_affiliation, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s);""",
            (tuid, orga_unit, givenname, surname, email, edu_person_affiliation, now)
        )

        conn.commit()
        conn.close()

    except Exception as error:
        raise Exception(
            'Connection to our custom database could not be established and/or'
            'update/insert failed.'
        ) from error


def run_script(tuid: str):
    """
    Will be used to run a custom script. For now, it just saves the TU-ID with a timestamp to a
    dummy log file.

    Args:
        tuid: String of the TU-ID to save.
    """
    # Check if logging is disabled, if true return.
    if not log_config.get("enabled"):
        return

    with open(log_config.get("path"), "a") as file:
        file.write(tuid + ";" + str(datetime.utcnow()) + os.linesep)
        file.close()


class SamlMappingProvider:
    """
    This is the heart of our custom mapping provider. Its purpose is to concatenate the attribute
    "givenName" and "surname" of our TUs IDP to "<givenName> <surname>".
    """
    def __init__(self, parsed_config: SamlConfig, module_api: ModuleApi):
        """
        Initializes the class with a given parsed SamlConfig.

        Args:
            parsed_config: A configuration object that is the return value of the parse_config
                method. You should set any configuration options needed by the module here.
            module_api: This one is just there for interface compatibility of synapse.
        """
        self._mxid_source_attribute = parsed_config.mxid_source_attribute

    @staticmethod
    def parse_config(config: dict) -> SamlConfig:
        """
        Parses a given dictionary (config) to our own SamlConfig format. The dictionary is the
        output of the config section in homeserver.yml/saml2...

        Args:
            config: A dict representing the parsed content of the
                saml_config.user_mapping_provider.config homeserver config option. Runs on
                homeserver startup. Providers should extract and validate any option values they
                need here.
        Returns:
            SamlConfig: A custom config object for this module
        """
        # Parse config options and use defaults ("uid") where necessary
        mxid_source_attribute = config.get("mxid_source_attribute", "uid")
        return SamlConfig(mxid_source_attribute)

    @staticmethod
    def get_saml_attributes(config: SamlConfig) -> Tuple[Set[str], Set[str]]:
        """
        Returns the saml attributes that this mapping provider will need. This contains
        mandatory as well as "nice-to-have" attributes.

        Args:
            config: A object resulting from a call to parse_config.
        Returns:
            The first set equates to the saml auth response attributes that are required for the
            module to function, whereas the second set consists of those attributes which can be
            used if available, but are not necessary
        """
        return {
            config.mxid_source_attribute,
            "surname",
            "givenName",
            "email",
            "ou",
            "eduPersonAffiliation"
            }, {"eduPersonScopedAffiliation"}

    def get_remote_user_id(
            self, saml_response: saml2.response.AuthnResponse, client_redirect_url: str
    ) -> str:
        # This method declaration is given by synapses documentation.
        # pylint: disable=R0201
        """
        Extracts the user ID from a given saml2.response.AuthnResponse object.

        Args:
            saml_response: A saml2.response.AuthnResponse object to extract user information
            from.
            client_redirect_url: A string, the URL that the client will be redirected to. This one
            will not be used.
        """
        try:
            return saml_response.ava[self._mxid_source_attribute][0]
        except KeyError as key_error:
            raise MappingException(
                f"{self._mxid_source_attribute} not in SAML2 response") from key_error

    def saml_response_to_user_attributes(
            self,
            saml_response,
            failures,
            client_redirect_url
    ) -> dict:
        """
        Maps the saml response attributes to user attributes for synapse.

        Args:
            saml_response: A saml2.response.AuthnResponse object to extract user information from.
            failures: An int that represents the amount of times the returned mxid localpart
                mapping has failed. This should be used to create a deduplicated mxid localpart
                which should be returned instead. For example, if this method returns john.doe as
                the value of mxid_localpart in the returned dict, and that is already taken on the
                homeserver, this method will be called again with the same parameters but with
                failures=1. The method should then return a different mxid_localpart value, such as
                john.doe1.
            client_redirect_url: A string, the URL that the client will be redirected to. This one
            will not be used.
        Returns:
            dict: A dict containing new user attributes. Possible keys:
                * mxid_localpart (str): Required. The localpart of the user's mxid
                * displayname (str): The displayname of the user
                * emails (list[str]): Any emails for the user
        """
        try:
            mxid_source = saml_response.ava[self._mxid_source_attribute][0]
        except KeyError as key_error:
            raise SynapseError(
                400, f"{self._mxid_source_attribute} not in SAML2 response"
            ) from key_error

        base_mxid_localpart = mxid_source

        # Append suffix integer if last call to this function failed to produce a usable MXID
        localpart = base_mxid_localpart + (str(failures) if failures else "")

        # Get names (custom stuff for our Matrix instance)
        givenname = saml_response.ava.get("givenName", [None])[0]
        surname = saml_response.ava.get("surname", [None])[0]

        # Retrieve the display name from the SAML responses given and surname
        displayname = givenname + " " + surname

        # Retrieve any emails present in the SAML response (array)
        emails = saml_response.ava.get("email", [])

        # Retrieve eduPersonAffiliation present in the SAML response (array)
        edu_person_affiliation = saml_response.ava.get("eduPersonAffiliation", [])

        # Save the OU(s) to our custom database.
        orga_unit = saml_response.ava.get("ou", [None])

        save_to_custom_db(
           mxid_source, orga_unit, givenname, surname, emails, edu_person_affiliation
        )

        # Trigger custom script here
        run_script(mxid_source)

        return {
            "mxid_localpart": localpart,
            "displayname": displayname,
            "emails": emails,
        }
