""" IR-Flow Integrations Utility - Microsoft Graph API Authentication Helpers

This class provides utility functions that are used to provide easier authentication using the
OAuth2 Flows provided by the Microsoft Graph API - These functions are used internally in the
:class:`MSGraph` class.

Examples: Each of the authentication functions return the authentication tokens granted to the
user if the credentials passed are valid. Both use the client credentials OAuth2 Flow,
the :func:`MSAuth.legacy_authentication` function makes use of the typical client secret and
client ID values, whereas the :func:`MSAuth.client_credentials_authentication` function uses the
tenant_id provided by Microsoft, and uses Azure AD's ``adal`` module. A refresh token is not
granted when :func:`MSAuth.client_credentials_authentication` is used::

        # Authenticating using user credentials
        bearer, refresh = MSAuth.legacy_authentication('<tenant>', '<client_id>', '<client_secret>',
                                                       '<username>', '<password>')

        # Authenticating as a service - the service must have the proper scopes allowed to access
        resources

        bearer = MSAuth.client_credentials_authentication('<tenant>',
                                                        '<client_id>',
                                                        '<client_secret>')
"""
import json
import logging

import adal
from oauthlib.oauth2 import InvalidGrantError, LegacyApplicationClient
from requests_oauthlib import OAuth2Session

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class MSAuth(object):
    """ Class that contains static authentication helpers """

    @staticmethod
    def legacy_authentication(tenant_id, client_id, client_secret, username, password):
        """Username and Password based OAuth2 token grant

        Args:
            tenant_id (str): The tenant ID for this AAD instance
            client_id (str): The client ID for this AAD instance
            client_secret (str): The client secret for the provided client ID
            username (str): The username of the user to gain permissions from
            password (str): The password of the provided user.

        Returns:
            tuple: A bearer token and a refresh token, in that order
        """
        oauth_session = OAuth2Session(client=LegacyApplicationClient(client_id=client_id))

        try:
            token_response = oauth_session.fetch_token(token_url='https://login.windows.net/' +
                                                       tenant_id + '/oauth2/token',
                                                       username=username,
                                                       password=password,
                                                       client_id=client_id,
                                                       client_secret=client_secret,
                                                       resource='https://graph.microsoft.com')
        except InvalidGrantError as e:
            logger.error('Invalid Grant Error, possible directory sync issue...')
            raise e

        bearer_token = token_response['access_token']
        refresh_token = token_response['refresh_token']

        return bearer_token, refresh_token

    @staticmethod
    def client_credentials_authentication(tenant_id, client_id, client_secret):
        """Client Credentials OAuth2 token grant via `adal`

        Args:
            tenant_id (str): The tenant ID for this AAD instance
            client_id (str): The client ID for this AAD instance
            client_secret (str): The client secret for the provided client ID

        Returns:
            str: The bearer token provided by `adal`
        """
        context = adal.AuthenticationContext('https://login.microsoftonline.com/' + tenant_id,
                                             validate_authority=tenant_id != 'adfs',
                                             api_version=None)

        token_response = context.acquire_token_with_client_credentials(
            resource='https://graph.microsoft.com',
            client_id=client_id,
            client_secret=client_secret)

        logger.debug(json.dumps(token_response, indent=2))

        bearer_token = token_response['accessToken']

        return bearer_token
