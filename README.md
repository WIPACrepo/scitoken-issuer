<!--- Top of README Badges (automated) --->
[![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/WIPACrepo/scitoken-issuer?include_prereleases)](https://github.com/WIPACrepo/scitoken-issuer/) [![GitHub issues](https://img.shields.io/github/issues/WIPACrepo/scitoken-issuer)](https://github.com/WIPACrepo/scitoken-issuer/issues?q=is%3Aissue+sort%3Aupdated-desc+is%3Aopen) [![GitHub pull requests](https://img.shields.io/github/issues-pr/WIPACrepo/scitoken-issuer)](https://github.com/WIPACrepo/scitoken-issuer/pulls?q=is%3Apr+sort%3Aupdated-desc+is%3Aopen)
<!--- End of README Badges (automated) --->
# scitoken-issuer
IceCube / WIPAC SciToken Issuer

## Running the Issuer

After installing the package, run:

    python -m scitoken_issuer

and it will start a web server capable of issuing tokens.

## Key Environment Variables

* IDP_ADDRESS - the full address to the upstream identity provider
* IDP_CLIENT_ID - the upstream identity provider client id
* IDP_CLIENT_SECRET - the upstream identity provider client secret
* IDP_USERNAME_CLAIM - the username claim in the identity token (default: preferred_username)

* ISSUER_ADDRESS - the full address to this issuer
* CUSTOM_CLAIMS - a json of custom claims to add, like `aud`
* KEY_TYPE - the issuer public key type (default: RS256)
* STATIC_CLIENTS - statically registered clients, json of client_id: client_secret
* STATIC_IMPERSONATION_CLIENTS - like above, except these can do impersonation via token exchange

* POSIX_PATH - base path for group information lookup

* MONGODB_URL: str = 'mongodb://localhost/scitokens'
* MONGODB_USER: str = ''
* MONGODB_PASSWORD: str = ''
* MONGODB_TIMEOUT: int = 10  # seconds
* MONGODB_WRITE_CONCERN: int = 1  # number of replicas that need to be up

* HOST - the interface to bind to. set to an empty string to bind to all interfaces (default: localhost)
* PORT - port to bind to (default :8080)
* COOKIE_SECRET - for browser-based cross-site scripting protection, set a hex string
* DEBUG - only useful for debugging, prints more info in the browser on failures (default: false)
* LOG_LEVEL - log verbosity (default: INFO)

If you use LDAP:
* USE_LDAP - enable LDAP support (default: false)
* LDAP_URL - full address to ldap server
* LDAP_USER_BASE - user OU
* LDAP_GROUP_BASE - group OU

Some time intervals in seconds (override as necessary):
* ACCESS_TOKEN_EXPIRATION
* REFRESH_TOKEN_EXPIRATION
* DEVICE_CODE_POLLING_INTERVAL
* DEVICE_CODE_EXPIRATION
* AUTHORIZATION_CODE_EXPIRATION
* CLIENT_REGISTRATION_EXPIRATION

## Code Structure

Tests are in tests/
Code is in src/scitoken_issuer/

* config.py - configuration variables from the environment
* server.py - main server code
* group_validation.py - validating scopes against a POSIX filesystem



## OpenID Details

OpenID flows supported:

* authorization code flow (with client secret)
* device code flow
* refresh flow

### OpenID URLs

* openid config `/.well-known/openid-configuration`
* public certs in jwks format `/auth/certs`
* token endpoint `/auth/token`
* authorization endpoint `/auth/authorize`
* user info endpoint `/auth/userinfo`
* device auth endpoint `/auth/device/code`
* client registration `/auth/client/registration`


### authorization code flow

For browsers.

1. user requests token with scopes
2. redirect to identity provider (authorization code flow)
3. user logs in with IdP
4. redirect back to token service
5. do code exchange with IdP to gain identity token
6. do scope auth
7. return refresh + access tokens (or deny request)

### device code flow

For command line clients.

1. user requests token with scopes, via device grant
2. return device + user code, local verification url
2. verification url redirects to identity provider (authorization code flow)
3. user logs in with IdP
4. redirect back to token service
5. do code exchange with IdP to gain identity token
6. do scope auth
7. return refresh + access tokens (or deny request) on /oauth/token poll

### refresh flow

For refresh tokens.

1. api request to token endpoint with refresh
2. do we check with IdP here? hold a refresh token for IdP?
3. do scope auth
4. return refresh + access tokens (or deny request)
