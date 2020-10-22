# jupyterhub-keycloak-oidc

Based on the generic authenticator from oauthenticator.

## usage
`/etc/jupyterhub/jupyterhub_config.py`:

```yaml
import os

from keycloak_oauth import LocalKeycloakOAuthenticator
from sudospawner import SudoSpawner

c.JupyterHub.log_level = 10
c.Spawner.default_url = '/lab'
c.JupyterHub.spawner_class=SudoSpawner

c.JupyterHub.authenticator_class = 'keycloak_oauth.LocalKeycloakOAuthenticator'

c.LocalKeycloakOAuthenticator.username_key = 'email'
c.LocalKeycloakOAuthenticator.client_id = os.environ['OAUTH2_CLIENT_ID']
c.LocalKeycloakOAuthenticator.client_secret = os.environ['OAUTH2_CLIENT_SECRET']
c.LocalKeycloakOAuthenticator.oauth_callback_url = os.environ['OAUTH2_CALLBACK_URL']
c.LocalKeycloakOAuthenticator.token_url = os.environ['OAUTH2_TOKEN_URL']
c.LocalKeycloakOAuthenticator.oauth_userdata_url = os.environ['OAUTH2_USERDATA_URL']

c.LocalKeycloakOAuthenticator.create_system_users = True
c.LocalKeycloakOAuthenticator.whitelist = { 'andrew' }
```

env vars
```bash
OAUTH2_TOKEN_URL=https://<auth-domain>/auth/realms/org-aaabbb/protocol/openid-connect/token
OAUTH2_AUTHORIZE_URL=https://<auth-domain>/auth/realms/org-aaabbb/protocol/openid-connect/auth
OAUTH2_CALLBACK_URL=https://<callback-domain>/hub/oauth_callback
OAUTH2_USERDATA_URL=https://<auth-domain>/auth/realms/org-aaabbb/protocol/openid-connect/userinfo

OAUTH2_CLIENT_ID=<realm client id>
OAUTH2_CLIENT_SECRET=<realm client secret>
```

## contributors

- [Andrew Zah (maintainer)](https://github.com/andrewzah)
