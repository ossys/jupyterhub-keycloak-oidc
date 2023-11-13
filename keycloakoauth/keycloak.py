"""
Custom Authenticator to use KeyCloak with JupyterHub
"""

import json
import os
import base64
import urllib
import logging

from tornado.auth import OAuth2Mixin
from tornado import web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode, Dict, Bool, Union, default, observe
from .traitlets import Callable

from .oauth2 import OAuthLoginHandler, OAuthenticator

class KeycloakOAuthenticator(OAuthenticator):
    login_service = Unicode("Keycloak OAuth", config=True)

    extra_params = Dict(help="Extra parameters for first POST request").tag(config=True)

    username_key = Union(
        [Unicode(os.environ.get('OAUTH2_USERNAME_KEY', 'username')), Callable()],
        config=True,
        help="""
        Userdata username key from returned json for USERDATA_URL.

        Can be a string key name or a callable that accepts the returned
        json (as a dict) and returns the username.  The callable is useful
        e.g. for extracting the username from a nested object in the
        response.
        """,
    )

    userdata_params = Dict(
        help="Userdata params to get user data login information"
    ).tag(config=True)

    userdata_method = Unicode(
        os.environ.get('OAUTH2_USERDATA_METHOD', 'GET'),
        config=True,
        help="Userdata method to get user data login information",
    )
    userdata_token_method = Unicode(
        os.environ.get('OAUTH2_USERDATA_REQUEST_TYPE', 'header'),
        config=True,
        help="Method for sending access token in userdata request. Supported methods: header, url. Default: header",
    )

    tls_verify = Bool(
        os.environ.get('OAUTH2_TLS_VERIFY', 'True').lower() in {'true', '1'},
        config=True,
        help="Disable TLS verification on http request",
    )

    basic_auth = Bool(
        os.environ.get('OAUTH2_BASIC_AUTH', 'True').lower() in {'true', '1'},
        config=True,
        help="Disable basic authentication for access token request",
    )

    def http_client(self):
        return AsyncHTTPClient(force_instance=True, defaults=dict(validate_cert=self.tls_verify))

    async def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        http_client = self.http_client()


        if self.client_id:
            client_id = self.client_id
        else:
            raise ValueError("Please set the $OAUTH2_CLIENT_ID environment variable")
        if self.client_secret:
            client_secret = self.client_secret
        else:
            raise ValueError("Please set the $OAUTH2_CLIENT_SECRET environment variable")

        if not self.token_url:
            raise ValueError("Please set the $OAUTH2_TOKEN_URL environment variable")
        else:
            url = self.token_url

        if not self.scope:
            scope = "openid profile email roles"
        else:
            scope = self.scope

        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=code,
            grant_type='authorization_code',
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
        )
        params.update(self.extra_params)

        headers = {"Accept": "application/json", "User-Agent": "JupyterHub"}

        req = HTTPRequest(
            url,
            method="POST",
            headers=headers,
            body=urllib.parse.urlencode(params),
        )

        resp = await http_client.fetch(req, raise_error = False)
        if resp.code != 200:
            logging.getLogger().error("Expected 200 response. Got %s: %s", resp.code, resp.body)
            raise

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']
        refresh_token = resp_json.get('refresh_token', None)
        token_type = resp_json['token_type']
        scope = resp_json.get('scope', '')
        if isinstance(scope, str):
            scope = scope.split(' ')

        # Determine who the logged in user is
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "{} {}".format(token_type, access_token),
        }
        if self.userdata_url:
            url = url_concat(self.userdata_url, self.userdata_params)
        else:
            raise ValueError("Please set the OAUTH2_USERDATA_URL environment variable")

        if self.userdata_token_method == "url":
            url = url_concat(self.userdata_url, dict(access_token=access_token))

        req = HTTPRequest(
            url,
            method=self.userdata_method,
            headers=headers,
        )
        resp = await http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        logging.getLogger().warning("json: %s", resp_json)

        if callable(self.username_key):
            name = self.username_key(resp_json)
        else:
            name = resp_json.get(self.username_key)
            if not name:
                self.log.error(
                    "OAuth user contains no key %s: %s", self.username_key, resp_json
                )
                return

        return {
            'name': name,
            'auth_state': {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'oauth_user': resp_json,
                'scope': scope,
            },
        }


class LocalKeycloakOAuthenticator(LocalAuthenticator, KeycloakOAuthenticator):

    """A version that mixes in local system user creation"""

    pass
