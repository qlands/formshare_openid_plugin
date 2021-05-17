FormShare OpenID Plugin
==============

This plug-in enable FormShare to become a [OpenID](https://en.wikipedia.org/wiki/OpenID) server where third-party applications could use it to authenticate users. The plug-in uses [pyOP](https://github.com/IdentityPython/pyop)

Getting Started
---------------

- Activate the FormShare environment.
```sh
activate ./path/to/FormShare/bin/activate
```

- Change directory into your newly created plug-in.
```sh
cd openid
```

- Build the plug-in
```sh
pip install requirements.txt
python setup.py develop
```

- Add the plug-in to the FormShare list of plug-ins by editing the following line in development.ini or production.ini and add the plug-in configuration items
```ini
#formshare.plugins = examplePlugin
formshare.plugins = openid
openid.server.name = your.FormShare_Server.com(without https://)(Your server must run over HTTPS)
openid.signing.key.file = /path/to/signing_key.pem (See: https://gist.github.com/ygotthilf/baa58da5c3dd1f69fae9)
openid.subject.id.hash.salt = 'salt'
openid.registration.key = aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa (Get one here: https://www.uuidgenerator.net/version4)
```

- Run FormShare again

## Testing

- If you are testing locally you need [ngrok](https://ngrok.com/) to expose the local server to on-line clients. For this add the following lines to development.ini or production.ini **under the section [server:main]** to tell gunicorn to start a HTTPS server

  ```ini
  certfile = /path/to/certificate/file/https.crt
  keyfile = /path/to/key/file/https.key
  ```

  Then run ngrok:

  ```sh
  ngrok http https://local_ip:5900
  ```

- Register a client. For example https://oidcdebugger.com/

  ```bash
  curl --request POST --url 'https://your.FormShare_Server.com/openid_registration' --header 'content-type: application/json' --data '{"registration_key":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","client_name":"My Dynamic Application","redirect_uris": ["https://oidcdebugger.com/debug"]}
  ```

  This will return the following JSON:

  ```json
  {"application_type": "web", "response_types": ["code"], "client_name": "My Dynamic Application", "redirect_uris": ["https://oidcdebugger.com/debug"], "client_id": "oiLdee3N5avY", "client_id_issued_at": 1621264923, "client_secret": "7d9ebf42df8f4b3580c561f28d3933c2", "client_secret_expires_at": 0}
  ```

  **Keep the client_secret secret!**

- Perform an authorization using your client. For example https://oidcdebugger.com/

  - Authorize URI (required) = https://your.FormShare_Server.com/openid_authentication
  - Client ID (required) = oiLdee3N5avY
  - Scope = openid profile
  - Response type = code
  - Response mode = query

  Note: Only openid and profile scopes are supported

  When you authorize you will be taken to the FormShare login page to login

  Once logged in, the client will receive an authorization code like:

  ```
  https://oidcdebugger.com/debug?code=56f0f03bb14b4bb7be0c439f61289d0b
  ```

- Exchange the authorization code for tokens

  ```sh
  curl -X POST -u "oiLdee3N5avY:7d9ebf42df8f4b3580c561f28d3933c2" -H "Content-Type: application/x-www-form-urlencoded" -d "grant_type=authorization_code&code=56f0f03bb14b4bb7be0c439f61289d0b&redirect_uri=https://oidcdebugger.com/debug" https://your.FormShare_Server.com/openid_token
  ```

  This will return the following JSON:

  ```json
  {"access_token": "3e1bd3cc76644616b2758759b10db4a7", "token_type": "Bearer", "expires_in": 3600, "id_token": "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiAiaHR0cHM6Ly9xbGFuZHMubmdyb2suaW8iLCAic3ViIjogImRjMWNkMTFkZmM1MWFiOTc1MTNlMjVhN2NmZjhkNjg0MWZmMWY2MDUzY2U0ZmJkZjJmMWU4ODM3MTE5MzE0NWIiLCAiYXVkIjogWyI4b1pBM2JMcDI5YnAiXSwgImlhdCI6IDE2MjEyNjIxMDMsICJleHAiOiAxNjIxMjY1NzAzLCAiYXRfaGFzaCI6ICJ5Wk5qZ0RlWXgybFRNNXgyODlYQVZ3IiwgIm5vbmNlIjogIm9hYmxncWU3aXUifQ.g0eGczxCR8R6Oe-P7hm_zt2qi5QXyfJUb-aJ2zAsNH_mP8BEvJzLhviBQaw4KxoVPzbRZKI13EBB8mvoetQwzvbsvBm0arEIwcyXV4fjlUUhdnFmxesOW6lkBMyhG60o2liV0vsXsN5rY1a--mHnkGjIxbJUcPW58RVGYf742Is"}
  ```

  **Keep the access_token secret!**

- Get the information about the current logged user

  ```sh
  curl -H 'Accept: application/json' -H "Authorization: Bearer 3e1bd3cc76644616b2758759b10db4a7" https://your.FormShare_Server.com/openid_userinfo
  ```

  This will return the following JSON:

  ```json
  {"name": "Carlos Quiros", "sub": "dc1cd11dfc51ab97513e25a7cff8d6841ff1f6053ce4fbdf2f1e88371193145b"}
  ```

- The plug-in also provides automatic configuration 

  ```
  https://your.FormShare_Server.com/.well-known/openid-configuration
  ```

  This will return the following JSON:

  ```
  {
      "version": "3.0",
      "token_endpoint_auth_methods_supported": [
          "client_secret_basic"
      ],
      "claims_parameter_supported": true,
      "request_parameter_supported": false,
      "request_uri_parameter_supported": true,
      "require_request_uri_registration": false,
      "grant_types_supported": [
          "authorization_code",
          "implicit"
      ],
      "frontchannel_logout_supported": false,
      "frontchannel_logout_session_supported": false,
      "backchannel_logout_supported": false,
      "backchannel_logout_session_supported": false,
      "issuer": "https://your.FormShare_Server.com",
      "authorization_endpoint": "https://your.FormShare_Server.com/openid_authentication",
      "jwks_uri": "https://your.FormShare_Server.com/openid_jwks",
      "token_endpoint": "https://your.FormShare_Server.com/openid_token",
      "userinfo_endpoint": "https://your.FormShare_Server.com/openid_userinfo",
      "registration_endpoint": "https://your.FormShare_Server.com/openid_registration",
      "end_session_endpoint": "https://your.FormShare_Server.com/openid_logout",
      "scopes_supported": [
          "openid",
          "profile"
      ],
      "response_types_supported": [
          "code",
          "code id_token",
          "code token",
          "code id_token token"
      ],
      "response_modes_supported": [
          "query",
          "fragment"
      ],
      "subject_types_supported": [
          "pairwise"
      ],
      "id_token_signing_alg_values_supported": [
          "RS256"
      ]
  }
  ```

- The plug-in also provides JWKS information:

  ```
  https://your.FormShare_Server.com/openid_jwks
  ```

  This will return the following JSON:

  ```json
  {"keys": [{"kty": "RSA", "alg": "RS256", "e": "AQAB", "n": "ou58ntmHtTK1A_7GQKZX5KTJFx2Hbsnb377__iIcdQpcSkvyhv9RIasgVVb4Ry0bPaYpijMi5tqQROdaxjrf_1yobKBQGt-1SA9os-w0LlegxoMgUhWioGmAaYpxEMtlnI1OHgAZwAVdq_itlJhpKlSYXqh6jqh1CmrE-IMv-pE"}]}
  ```

  