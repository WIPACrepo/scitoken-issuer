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
* ISSUER_ADDRESS - the full address to this issuer
* AUDIENCE - aud to add to tokens
* POSIX_PATH - base path for group information lookup

If you use LDAP:
* USE_LDAP - boolean
* LDAP_URL - full address to ldap server
* LDAP_USER_BASE - user OU
* LDAP_GROUP_BASE - group OU

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
