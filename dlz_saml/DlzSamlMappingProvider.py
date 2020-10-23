import attr
import saml2.response
from typing import Set, Tuple


# Heavily based on:
# https://github.com/matrix-org/synapse/blob/master/docs/sso_mapping_providers.md
#
# This class only exists, because the HRZ of TU Darmstadt can not provide a
# 'displayName' value via IDP.
#


@attr.s
class SamlConfig:
    mxid_source_attribute = attr.ib()


class MappingException(Exception):
    """Used to catch errors when mapping the SAML2 response to a user."""


class DlzSamlMappingProvider:
    __author__ = "Maximilian Kratz"
    __email__ = "mkratz@fs-etit.de"
    __version__ = "0.0.1"
    __license__ = "'I hate the HRZ for not providing displayName'-License"
    __status__ = "Development"

    def __init__(self, parsed_config: SamlConfig, module_api):
        """
        Args:
            parsed_config: A configuration object that is the return value of the parse_config
                method. You should set any configuration options needed by the module here.
            module_api: This one is just there for interface compatibility of synapse.
        """
        self._mxid_source_attribute = parsed_config.mxid_source_attribute

    @staticmethod
    def parse_config(config: dict) -> SamlConfig:
        """
        Args:
            config: A dict representing the parsed content of the 
                saml_config.user_mapping_provider.config homeserver config option. Runs on
                homeserver startup. Providers should extract and validate any option values they
                need here.
        Returns:
            SamlConfig: A custom config object for this module
        """
        # Parse config options and use defaults where necessary
        mxid_source_attribute = config.get("mxid_source_attribute", "uid")
        return SamlConfig(mxid_source_attribute)

    @staticmethod
    def get_saml_attributes(config: SamlConfig) -> Tuple[Set[str], Set[str]]:
        """
        Args:
            config: A object resulting from a call to parse_config.
        Returns:
            The first set equates to the saml auth response
                attributes that are required for the module to function, whereas the
                second set consists of those attributes which can be used if
                available, but are not necessary
        """
        # return {"uid", config.mxid_source_attribute}, {"displayName", "email"}
        return {"uid", config.mxid_source_attribute}, {"surname", "givenName", "mail"}

    def get_remote_user_id(
            self, saml_response: saml2.response.AuthnResponse, client_redirect_url: str
    ) -> str:
        """
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

        return {
            "mxid_localpart": localpart,
            "displayname": displayname,
            "emails": emails,
        }
