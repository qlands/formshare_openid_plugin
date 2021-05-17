from formshare.plugins.utilities import FormSharePublicView
from pyramid.httpexceptions import HTTPNotFound, HTTPSeeOther, HTTPBadRequest
from formencode.variabledecode import variable_decode
from pyramid.response import Response
from pyop.exceptions import (
    InvalidAuthenticationRequest,
    InvalidAccessToken,
    InvalidClientAuthentication,
    OAuthError,
    InvalidClientRegistrationRequest,
    InvalidSubjectIdentifier,
)
import json
from urllib.parse import urlencode
from ast import literal_eval
from pyop.util import should_fragment_encode
from oic.oic.message import TokenErrorResponse, UserInfoErrorResponse, EndSessionRequest
from pyop.access_token import AccessToken, BearerTokenError


def get_policy(request, policy_name):
    policies = request.policies()
    for policy in policies:
        if policy["name"] == policy_name:
            return policy["policy"]
    return None


def create_json_response(data, status, headers=None):
    if headers is None:
        headers = []
    response_headers = [
        ("Content-Type", "application/json; charset=utf-8"),
    ] + headers
    response = Response(headerlist=response_headers, status=status)
    json_object = json.dumps(data, default=str)
    response.text = json_object
    return response


def to_json(data):
    return json.dumps(data, default=str)


class OpenIDRegistrationView(FormSharePublicView):
    def process_view(self):
        self.returnRawViewResult = True
        if self.request.method == "GET":
            raise HTTPNotFound()
        else:
            try:
                provider = self.request.registry.settings["openid.provider"]
                registration_data = variable_decode(self.request.POST)
                if not registration_data:
                    registration_data = self.request.json_body
                if (
                    registration_data.get("registration_key")
                    != self.request.registry.settings["openid.registration.key"]
                ):
                    raise HTTPNotFound()
                else:
                    registration_data.pop("registration_key", None)
                provider_response = provider.handle_client_registration_request(
                    to_json(registration_data)
                )
                return create_json_response(provider_response.to_dict(), 201)
            except InvalidClientRegistrationRequest as e:
                return create_json_response(e.to_dict(), 400)


class OpenIDAuthenticationView(FormSharePublicView):
    def process_view(self):
        self.returnRawViewResult = True
        if self.request.method == "POST":
            raise HTTPNotFound()
        else:
            policy = get_policy(self.request, "main")
            login_data = policy.authenticated_userid(self.request)
            if login_data is None:
                return HTTPSeeOther(
                    location=self.request.route_url(
                        "login", _query={"next": self.request.url, "openid": True}
                    ),
                    headers=self.request.headers,
                )
            login_data = literal_eval(login_data)
            if login_data["group"] != "mainApp":
                return HTTPSeeOther(
                    location=self.request.route_url(
                        "login", _query={"next": self.request.url, "openid": True}
                    ),
                    headers=self.request.headers,
                )

            provider = self.request.registry.settings["openid.provider"]
            try:
                auth_req = provider.parse_authentication_request(
                    urlencode(self.request.params), self.request.headers
                )
            except InvalidAuthenticationRequest as e:
                print("received invalid authn request")
                error_url = e.to_error_url()
                if error_url:
                    return HTTPSeeOther(location=error_url)
                else:
                    raise HTTPBadRequest("Something went wrong: {}".format(str(e)))
            authn_response = provider.authorize(auth_req, login_data["login"])
            response_url = authn_response.request(
                auth_req["redirect_uri"], should_fragment_encode(auth_req)
            )
            return HTTPSeeOther(location=response_url)


class OpenIDConfigurationView(FormSharePublicView):
    def process_view(self):
        self.returnRawViewResult = True
        provider = self.request.registry.settings["openid.provider"]
        return create_json_response(provider.provider_configuration.to_dict(), 200)


class OpenIDJWKSView(FormSharePublicView):
    def process_view(self):
        self.returnRawViewResult = True
        provider = self.request.registry.settings["openid.provider"]
        return create_json_response(provider.jwks, 200)


class OpenIDTokenView(FormSharePublicView):
    def process_view(self):
        self.returnRawViewResult = True
        if self.request.method == "GET":
            raise HTTPNotFound()
        else:
            provider = self.request.registry.settings["openid.provider"]
            try:
                post_data = variable_decode(self.request.POST)
                registration_data = []
                for key, value in post_data.items():
                    registration_data.append(key + "=" + value)
                registration_data = "&".join(registration_data)

                token_response = provider.handle_token_request(
                    registration_data, self.request.headers
                )
                return create_json_response(token_response.to_dict(), 200)
            except InvalidClientAuthentication as e:
                print("invalid client authentication at token endpoint")
                error_resp = TokenErrorResponse(
                    error="invalid_client", error_description=str(e)
                )
                return create_json_response(
                    error_resp.to_json(), 401, [("WWW-Authenticate", "Basic")]
                )
            except OAuthError as e:
                print("invalid request: %s", str(e))
                error_resp = TokenErrorResponse(
                    error=e.oauth_error, error_description=str(e)
                )
                return create_json_response(error_resp.to_json(), 400)


class OpenIDUserInfoView(FormSharePublicView):
    def process_view(self):
        self.returnRawViewResult = True
        provider = self.request.registry.settings["openid.provider"]
        try:
            if self.request.method == "POST":
                registration_data = variable_decode(self.request.POST)
                if not registration_data:
                    registration_data = self.request.json_body
            else:
                registration_data = self.request.params
            open_id_response = provider.handle_userinfo_request(
                registration_data, self.request.headers
            )
            return create_json_response(open_id_response.to_dict(), 200)
        except (BearerTokenError, InvalidAccessToken) as e:
            error_resp = UserInfoErrorResponse(
                error="invalid_token", error_description=str(e)
            )
            return create_json_response(
                error_resp.to_json(),
                401,
                [("WWW-Authenticate", AccessToken.BEARER_TOKEN_TYPE)],
            )


def do_logout(provider, end_session_request):
    try:
        provider.logout_user(end_session_request=end_session_request)
    except InvalidSubjectIdentifier as e:
        print("OpenID: Unable to logout: {}".format(str(e)))
        return False, ""
    redirect_url = provider.do_post_logout_redirect(end_session_request)
    if redirect_url:
        return redirect_url
    return ""


class OpenIDLogoutView(FormSharePublicView):
    def process_view(self):
        self.returnRawViewResult = True
        end_session_request = EndSessionRequest().deserialize(
            urlencode(self.request.params)
        )
        end_session_request_dict = end_session_request.to_dict()
        provider = self.request.registry.settings["openid.provider"]
        redirect_url = do_logout(
            provider, EndSessionRequest().from_dict(end_session_request_dict)
        )
        if redirect_url != "":
            return HTTPSeeOther(location=redirect_url)
        return HTTPSeeOther(location=self.request.route_url("home"))
