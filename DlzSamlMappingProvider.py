

# See https://github.com/matrix-org/synapse/blob/master/docs/sso_mapping_providers.md

class DlzSamlMappingProvider:
    __author__ = "Maximilian Kratz"
    __email__ = "mkratz@fs-etit.de"
    __version__ = "0.0.1"
    __license__ = "I hate the HRZ for not providing displayName - License"
    __status__ = "Development"

    def __init__(self, parsed_config):
        """
        Args:
            parsed_config - A configuration object that is the return value of the parse_config 
                method. You should set any configuration options needed by the module here.
        """

    @staticmethod
    def parse_config(config):
        """
        Args:
            config: A dict representing the parsed content of the 
                saml_config.user_mapping_provider.config homeserver config option. Runs on
                homeserver startup. Providers should extract and validate any option values they
                need here.
        Returns:
            SamlConfig: A custom config object for this module
        """

    @staticmethod
    def get_saml_attributes(config):
        """
        Args:
            config: A object resulting from a call to parse_config.
        Returns:
            The first set equates to the saml auth response
                attributes that are required for the module to function, whereas the
                second set consists of those attributes which can be used if
                available, but are not necessary
        """

    def get_remote_user_id(self, saml_response, client_redirect_url):
        """
        Args:
            saml_response: A saml2.response.AuthnResponse object to extract user information from.
            client_redirect_url: A string, the URL that the client will be redirected to.
        """

    def saml_response_to_user_attributes(self, saml_response, failures, client_redirect_url):
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
            client_redirect_url: A string, the URL that the client will be redirected to.
        Returns:
            dict: A dict containing new user attributes. Possible keys:
                * mxid_localpart (str): Required. The localpart of the user's mxid
                * displayname (str): The displayname of the user
                * emails (list[str]): Any emails for the user
        """
