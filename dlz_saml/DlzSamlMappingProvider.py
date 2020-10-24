import attr
import psycopg2
import saml2.response
from typing import Set, Tuple


# Heavily based on:
# https://github.com/matrix-org/synapse/blob/master/docs/sso_mapping_providers.md
#
# This class only exists, because the HRZ of TU Darmstadt can not provide a
# 'displayName' value via IDP.
#
# It does not log to the synapse logger nor does it throw the expected errors
# from the synapse package. Please keep in mind, that this code might crash unexpectedly,
# but you can always check the homeservers log file for python error output.
#


@attr.s
class SamlConfig:
    """
    Used to configure the Matrix id source attribute.
    This value will later be passed by the homeserver.yml configuration file.
    """
    mxid_source_attribute = attr.ib()


class MappingException(Exception):
    """
    Used to catch errors when mapping the SAML2 response to a user.
    Maybe this will lead to incompatibility with the class within the synapse package,
    but it works for now.
    """


class DlzSamlMappingProvider:
    """
    This is the heart of our custom mapping provider. Its purpose is to concatenate the attribute
    "givenName" and "surname" of our HRZs IDP to "<givenName> <surname>".
    """

    __author__ = "Maximilian Kratz"
    __email__ = "mkratz@fs-etit.de"
    __version__ = "0.0.2"
    __license__ = "'I hate the HRZ for not providing displayName'-License"
    __status__ = "Development"

    def __init__(self, parsed_config: SamlConfig, module_api):
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
        return {config.mxid_source_attribute, "surname", "givenName", "mail"}, {"ou"}

    def get_remote_user_id(
            self, saml_response: saml2.response.AuthnResponse, client_redirect_url: str
    ) -> str:
        """
        Extracts the user id from a given saml2.response.AuthnResponse object.

        Args:
            saml_response: A saml2.response.AuthnResponse object to extract user information from.
            client_redirect_url: A string, the URL that the client will be redirected to. This one will not be used.
        """
        try:
            return saml_response.ava["uid"][0]
        except KeyError:
            raise MappingException("'uid' not in SAML2 response")

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
            client_redirect_url: A string, the URL that the client will be redirected to. This one will not be used.
        Returns:
            dict: A dict containing new user attributes. Possible keys:
                * mxid_localpart (str): Required. The localpart of the user's mxid
                * displayname (str): The displayname of the user
                * emails (list[str]): Any emails for the user
        """
        try:
            mxid_source = saml_response.ava[self._mxid_source_attribute][0]
        except KeyError:
            raise AttributeError(
                400, "%s not in SAML2 response" % (self._mxid_source_attribute,)
            )

        base_mxid_localpart = mxid_source

        # Append suffix integer if last call to this function failed to produce a usable mxid
        localpart = base_mxid_localpart + (str(failures) if failures else "")

        # Concatenate names (custom stuff for our DLZ instance)
        givenname = saml_response.ava.get("givenName", [None])[0]
        surname = saml_response.ava.get("surname", [None])[0]

        # Retrieve the display name from the saml response
        displayname = givenname + " " + surname

        # Retrieve any emails present in the saml response
        emails = saml_response.ava.get("email", [])

        #
        # Save the ou to our custom database.
        #
        ou = saml_response.ava.get("ou", [None])

        # Convert ou array from saml_response to one string.
        # Fields are separated with commas.
        def join_l(l, sep):
            li = iter(l)
            string = str(next(li))
            for i in li:
                string += str(sep) + str(i)
            return string

        ou_str = join_l(ou, ',')

        try:
            conn = psycopg2.connect(
                database="ou",
                user="ou_user",
                password="<secret>>",
                host="chat-db.dek.e-technik.tu-darmstadt.de",
                port="5432")

            cur = conn.cursor()
            cur.execute(
                """INSERT INTO user_external_ous (tuid, ou) VALUES (%s, %s);""",
                (mxid_source, ou_str)
            )

            conn.commit()
            conn.close()
        except:
            raise Exception(
                "Connection to our custom DLZ database could not be established and/or update/insert failed."
            )

        return {
            "mxid_localpart": localpart,
            "displayname": displayname,
            "emails": emails,
        }
