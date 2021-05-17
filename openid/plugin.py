import formshare.plugins as plugins
import formshare.plugins.utilities as u
from .views import (
    OpenIDRegistrationView,
    OpenIDAuthenticationView,
    OpenIDConfigurationView,
    OpenIDJWKSView,
    OpenIDTokenView,
    OpenIDUserInfoView,
    OpenIDLogoutView,
)
from pyramid.request import Request
from jwkest.jwk import RSAKey, rsa_load
from pyop.authz_state import AuthorizationState
from pyop.provider import Provider
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from pyop.userinfo import Userinfo
from sqlalchemy import Table, Column, Unicode, UnicodeText, BigInteger
from sqlalchemy.orm import mapper
from .orm.clients import OpenIDClients
from .wrappers import UserWrapper, ClientWrapper


def init_oidc_provider(config):
    users = UserWrapper(config.registry.settings["sqlalchemy.url"])

    config.registry.settings["openid.users"] = users
    config.registry.settings["openid.clients"] = ClientWrapper(
        config.registry.settings["sqlalchemy.url"]
    )
    server_name = config.registry.settings.get("openid.server.name")
    request = Request.blank(
        "/",
        base_url="https://{}".format(
            server_name,
        ),
    )
    request.registry = config.registry
    issuer = request.route_url("home")[:-1]
    authentication_endpoint = request.route_url("openid_authentication_endpoint")
    jwks_uri = request.route_url("openid_jwks_uri")
    token_endpoint = request.route_url("openid_token_endpoint")
    userinfo_endpoint = request.route_url("openid_userinfo_endpoint")
    registration_endpoint = request.route_url("openid_registration_endpoint")
    end_session_endpoint = request.route_url("openid_logout_endpoint")

    configuration_information = {
        "issuer": issuer,
        "authorization_endpoint": authentication_endpoint,
        "jwks_uri": jwks_uri,
        "token_endpoint": token_endpoint,
        "userinfo_endpoint": userinfo_endpoint,
        "registration_endpoint": registration_endpoint,
        "end_session_endpoint": end_session_endpoint,
        "scopes_supported": ["openid", "profile"],
        "response_types_supported": [
            "code",
            "code id_token",
            "code token",
            "code id_token token",
        ],  # code and hybrid
        "response_modes_supported": ["query", "fragment"],
        "grant_types_supported": ["authorization_code", "implicit"],
        "subject_types_supported": ["pairwise"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "claims_parameter_supported": True,
    }
    userinfo_db = Userinfo(config.registry.settings["openid.users"])
    signing_key = RSAKey(
        key=rsa_load(config.registry.settings["openid.signing.key.file"]), alg="RS256"
    )
    provider = Provider(
        signing_key,
        configuration_information,
        AuthorizationState(
            HashBasedSubjectIdentifierFactory(
                config.registry.settings["openid.subject.id.hash.salt"]
            )
        ),
        config.registry.settings["openid.clients"],
        userinfo_db,
    )
    config.registry.settings["openid.provider"] = provider


class OpenID(plugins.SingletonPlugin):
    plugins.implements(plugins.IRoutes)
    plugins.implements(plugins.IEnvironment)
    plugins.implements(plugins.IDatabase)

    def update_orm(self, metadata):
        t = Table(
            "openidclients",
            metadata,
            Column("client_id", Unicode(64), primary_key=True),
            Column("client_name", Unicode(120)),
            Column("application_type", Unicode(120)),
            Column("redirect_uris", UnicodeText),
            Column("response_types", UnicodeText),
            Column("client_id_issued_at", BigInteger),
            Column("client_secret", Unicode(64)),
            Column("client_secret_expires_at", BigInteger),
        )
        metadata.create_all()
        mapper(OpenIDClients, t)

    def after_environment_load(self, config):
        init_oidc_provider(config)

    def before_mapping(self, config):
        # We don't add any routes before the host application
        return []

    def after_mapping(self, config):
        # We add here a new route /json that returns a JSON
        custom_map = [
            u.add_route(
                "openid_registration_endpoint",
                "/openid_registration",
                OpenIDRegistrationView,
                None,
            ),
            u.add_route(
                "openid_authentication_endpoint",
                "/openid_authentication",
                OpenIDAuthenticationView,
                None,
            ),
            u.add_route(
                "openid_provider_configuration",
                "/.well-known/openid-configuration",
                OpenIDConfigurationView,
                None,
            ),
            u.add_route(
                "openid_jwks_uri",
                "/openid_jwks",
                OpenIDJWKSView,
                None,
            ),
            u.add_route(
                "openid_token_endpoint",
                "/openid_token",
                OpenIDTokenView,
                None,
            ),
            u.add_route(
                "openid_userinfo_endpoint",
                "/openid_userinfo",
                OpenIDUserInfoView,
                None,
            ),
            u.add_route(
                "openid_logout_endpoint",
                "/openid_logout",
                OpenIDLogoutView,
                None,
            ),
        ]

        return custom_map
