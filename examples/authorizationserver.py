import hashlib
import logging
import re
import itertools
import colander
import deform.widget
from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.httpexceptions import HTTPFound, HTTPForbidden
from pyramid.config import Configurator
from pyramid import security
from pyramid_sqlalchemy import (
    BaseObject,
    Session,
)
from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    String,
    Unicode,
    UnicodeText,
)
from sqlalchemy.orm import (
    relationship,
)
from oauthlib.oauth2 import RequestValidator

SETTINGS = {
    "sqlalchemy.url": "sqlite:///authorization.db",
    "sqlalchemy.echo": True,
    "authtkt.secret": "secret",
    "pyramid.debug_all": True,
    "pyramid.reaload_all": True,
}


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
# models


class User(BaseObject):
    __tablename__ = 'oauth_users'
    query = Session.query_property()
    id = Column(Integer, primary_key=True)
    username = Column(Unicode(255))
    password_digest = Column(String(255))

    def digest_password(self, password):
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    def set_password(self, password):
        self.password_digest = self.digest_password(password)

    password = property(fset=set_password)

    def verify_password(self, password):
        return self.password_digest == self.digest_password(password)


class Client(BaseObject):
    __tablename__ = 'oauth_clients'
    query = Session.query_property()
    id = Column(Integer, primary_key=True)
    clientname = Column(Unicode(255))
    identifier = Column(Unicode(255))
    secret_digest = Column(String(255))
    _allowed_grants = Column(UnicodeText)
    _redirect_uris = Column(UnicodeText)
    _default_scopes = Column(UnicodeText)

    @property
    def client_id(self):
        return self.identifier

    @property
    def allowed_grants(self):
        if not self._allowed_grants:
            return []
        return [g.strip() for g in self._allowed_grants.split()]

    @property
    def redirect_uris(self):
        if not self._redirect_uris:
            return []
        return [u.strip() for u in self._redirect_uris.split()]

    @property
    def default_scopes(self):
        if not self._default_scopes:
            return []
        return [s.strip() for s in self._default_scopes.split()]

    def digest_secret(self, secret):
        return hashlib.sha256(secret.encode('utf-8')).hexdigest()

    def set_secret(self, secret):
        self.secret_digest = self.digest_secret(secret)

    secret = property(fset=set_secret)

    def verify_secret(self, secret):
        return self.secret_digest == self.digest_secret(secret)


class Grant(BaseObject):
    __tablename__ = 'oauth_grants'
    query = Session.query_property()
    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey('oauth_clients.id'))
    user_id = Column(Integer, ForeignKey('oauth_users.id'))
    client = relationship('Client')
    user = relationship('User')
    code = Column(UnicodeText)
    state = Column(UnicodeText)
    _scopes = Column(UnicodeText)

    @property
    def scopes(self):
        if not self._scopes:
            return []
        return [s.strip() for s in self._scopes.split()]


class BearerToken(BaseObject):
    __tablename__ = 'oauth_tokens'
    query = Session.query_property()
    id = Column(Integer, primary_key=True)
    access_token = Column(Unicode(255))
    refresh_token = Column(Unicode(255))
    client_id = Column(Integer, ForeignKey('oauth_clients.id'))
    user_id = Column(Integer, ForeignKey('oauth_users.id'))
    client = relationship('Client')
    user = relationship('User')
    _scopes = Column(UnicodeText)

    @property
    def scopes(self):
        if not self._scopes:
            return []
        return [s.strip() for s in self._scopes.split()]


# oauth validator

# Skeleton for an OAuth 2 Web Application Server which is an OAuth
# provider configured for Authorization Code, Refresh Token grants and
# for dispensing Bearer Tokens.

# This example is meant to act as a supplement to the documentation,
# see https://oauthlib.readthedocs.io/en/latest/.


class OAuthValidator(RequestValidator):

    # Ordered roughly in order of appearance in the authorization grant flow

    # Pre- and post-authorization.

    def validate_client_id(self, client_id, request, *args, **kwargs):
        client = Client.query.filter(
            Client.identifier == client_id).first()
        request.client = client
        return client

    def validate_redirect_uri(
            self, client_id, redirect_uri, request, *args, **kwargs):
        return redirect_uri in request.client.redirect_uris

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        # The redirect used if none has been supplied.
        # Prefer your clients to pre register a redirect uri rather than
        # supplying one on each authorization request.
        uris = request.client.redirect_uris
        if not uris:
            return None
        return uris[0]

    def validate_scopes(
            self, client_id, scopes, client, request, *args, **kwargs):
        # Is the client allowed to access the requested scopes?
        request.scopes = scopes
        return True

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        # Scopes a client will authorize for if none are supplied in the
        # authorization request.
        pass

    def validate_response_type(
            self, client_id, response_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of response type, the
        # one associated with their one allowed grant type.
        # In this case it must be "code".
        return True

    # Post-authorization

    def save_authorization_code(
            self, client_id, code, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.redirect_uri
        # request.client, request.state and request.user (the last is passed in
        # post_authorization credentials, i.e. { 'user': request.user}.
        user = User.query.filter(
            User.username == request.authenticated_userid).first()
        logger.info("allow grant to %s: %s" %
                    (request.authenticated_userid, user))
        grant = Grant(
            code=code["code"],
            state=code["state"],
            _scopes=" ".join(request.scopes),
            client=request.client,
            user=user,
        )
        Session.add(grant)

    # Token request
    def client_authentication_required(self, request):
        return False

    def authenticate_client(self, request, *args, **kwargs):
        # Whichever authentication method suits you, HTTP Basic might work
        return False

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        # Don't allow public (non-authenticated) clients
        client = Client.query.filter(
            Client.identifier == client_id).first()
        request.client = client
        assert hasattr(request.client, "client_id")
        return client is not None

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        # Validate the code belongs to the client. Add associated scopes,
        # state and user to request.scopes and request.user.
        grant = Grant.query.filter(
            Grant.code == code,
            Grant.client_id == client.id).first()
        request.grant = grant
        return grant is not None

    def confirm_redirect_uri(
            self, client_id, code, redirect_uri, client, *args, **kwargs):
        # You did save the redirect uri with the authorization code right?
        return True

    def validate_grant_type(
            self, client_id, grant_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of grant.
        # In this case, it must be "authorization_code" or "refresh_token"
        return True

    def save_bearer_token(
            self, token, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.user and
        # request.client. The two former will be set when you validate
        # the authorization code. Don't forget to save both the
        # access_token and the refresh_token and set expiration for the
        # access_token to now + expires_in seconds.
        bearer = BearerToken(
            access_token=token["access_token"],
            _scopes=request.grant._scopes,
            client=request.client,
            user=request.grant.user)
        Session.add(bearer)

    def invalidate_authorization_code(
            self, client_id, code, request, *args, **kwargs):
        # Authorization codes are use once, invalidate it when a Bearer token
        # has been acquired.
        grant = Grant.query.filter(
            Grant.code == code,
            Grant.client_id == Client.id,
            Client.identifier == client_id).first()
        Session.delete(grant)

    # Protected resource request

    def validate_bearer_token(
            self, token, scopes, request):
        # Remember to check expiration and scope membership
        pass

    # Token refresh request

    def get_original_scopes(
            self, refresh_token, request, *args, **kwargs):
        # Obtain the token associated with the given refresh_token and
        # return its scopes, these will be passed on to the refreshed
        # access token if the client did not specify a scope during the
        # request.
        pass

# authentication policy


class BearerTokenAuthenticationPolicy:
    def forget(self, request):
        pass

    def unauthenticated_userid(self, request):
        if not request.authorization:
            return
        if request.authorization.authtype != "Bearer":
            return
        return request.authorization.params

    def rememeber(self, request):
        pass

    def effective_principals(self, request):
        logger.debug("=" * 30)
        token = self.unauthenticated_userid(request)
        bearer = BearerToken.query.filter(
            BearerToken.access_token == token).first()
        if not bearer:
            logger.info('invalid access token %s' % token)
            return []
        logger.info('scopes %s' % bearer.scopes)
        return bearer.scopes

    def authenticated_userid(self, request):
        token = self.unauthenticated_userid(request)
        user = User.query.filter(
            User.id == BearerToken.user_id,
            BearerToken.access_token == token,
        ).first()
        logger.info('authenticated %s' % user)
        if not user:
            return
        return user.username


class CompositAuthenticationPolicy:
    def __init__(self, *authenticators):
        self.authenticators = authenticators

    def forget(self, request):
        for a in self.authenticators:
            f = a.forget(request)
            if f:
                return f

    def unauthenticated_userid(self, request):
        for a in self.authenticators:
            u = a.unauthenticated_userid(request)
            if u:
                return u

    def remember(self, request, userid):
        for a in self.authenticators:
            r = a.remember(request, userid)
            if r:
                return r

    def effective_principals(self, request):
        return list(
            itertools.chain.from_iterable(a.effective_principals(request)
                                          for a in self.authenticators))

    def authenticated_userid(self, request):
        for a in self.authenticators:
            u = a.authenticated_userid(request)
            if u:
                return u

# schema


class LoginSchema(colander.Schema):
    username = colander.SchemaNode(
        colander.String())
    password = colander.SchemaNode(
        colander.String(),
        widget=deform.widget.PasswordWidget())
    from_ = colander.SchemaNode(
        colander.String(),
        widget=deform.widget.HiddenWidget())

# views


def index(request):
    return dict()


def authorize(request):
    request.response_mode = None
    scopes = request.params.get("scopes")
    client_id = request.params["client_id"]
    client = Client.query.filter(Client.identifier == client_id).first()
    if not scopes:
        scopes = client.default_scopes
    return request.create_authorization_response(scopes=scopes)


def token(request):
    request.response_mode = None
    request.client = None
    response = request.create_token_response()
    print(response)
    return response


def protected(request):
    pass


def login(request):
    form = deform.Form(LoginSchema(),
                       buttons=('Login',))
    if request.method == "GET":
        from_ = request.params.get("from_")
        if from_:
            form.set_appstruct({"from_": from_})
    if request.method == "POST":
        try:
            controls = request.params.items()
            params = form.validate(controls)
            user = User.query.filter(
                User.username == params["username"]).first()
            if not user:
                return dict(form=form)
            if not user.verify_password(params["password"]):
                return dict(form=form)
            headers = security.remember(request, user.username)
            location = params.get("from_")
            if location == colander.null:
                location = request.route_url('core.index')
            return HTTPFound(location=location, headers=headers)
        except deform.ValidationFailure as e:
            return dict(form=e.field)
    return dict(form=form)


def logout(request):
    pass


def forbidden(request):
    if request.path.startswith("/api"):
        return HTTPForbidden()
    location = request.route_url('core.login', _query={'from_': request.url})
    return HTTPFound(location=location)


def protected_api(request):
    return dict(message="OK",
                user=request.authenticated_userid)


# resource


class Resource:
    def __init__(self, request):
        self.request = request

    @property
    def __acl__(self):
        return [
            (security.Allow, security.Authenticated, "authorize"),
            (security.Allow, "read", "api.protected"),
        ]

# construction


def oauth(config):
    validator = OAuthValidator()
    config.add_response_type('oauthlib.oauth2.AuthorizationCodeGrant',
                             name='code',
                             request_validator=validator)
    config.add_grant_type('oauthlib.oauth2.AuthorizationCodeGrant',
                          name='authorization_code',
                          request_validator=validator)
    config.add_token_type('oauthlib.oauth2.BearerToken',
                          request_validator=validator)
    config.add_route('oauth.authorize', 'authorize')
    config.add_route('oauth.token', 'token')
    config.add_view(
        authorize,
        route_name='oauth.authorize',
        permission="authorize",
        renderer="authorize.html",
    )
    config.add_view(
        token,
        route_name='oauth.token',
        renderer="json",
    )


def core(config):
    config.add_route('core.index', '/')
    config.add_route('core.login', '/login')
    config.add_view(
        login,
        route_name='core.login',
        renderer='login.html',
    )


def api(config):
    config.add_route('api.protected', 'protected')
    config.add_view(
        protected_api,
        route_name='api.protected',
        permission="api.protected",
        renderer='json')


def demodata(config):
    import transaction
    BaseObject.metadata.drop_all()
    BaseObject.metadata.create_all()
    user = User(
        username="demouser",
        password="password",
    )
    Session.add(user)
    client = Client(
        identifier='democlient',
        secret='secret',
        _allowed_grants="authorization_code",
        _redirect_uris="http://localhost:5001/oauth/callback",
        _default_scopes='read',
    )
    Session.add(client)
    transaction.commit()


def main(global_config, **settings):
    secret = settings['authtkt.secret'].encode('utf-8')
    secret = hashlib.sha256().hexdigest()
    authentication_policy = CompositAuthenticationPolicy(
        AuthTktAuthenticationPolicy(secret),
        BearerTokenAuthenticationPolicy())
    authorization_policy = ACLAuthorizationPolicy()
    config = Configurator(
        authentication_policy=authentication_policy,
        authorization_policy=authorization_policy,
        root_factory=Resource,
        settings=settings)
    config.include('pyramid_tm')
    config.include('pyramid_jinja2')
    config.include('pyramid_sqlalchemy')
    config.include('pyramid_oauthlib')
    config.add_static_view(
        path='deform:static',
        name='deform-static')
    config.add_jinja2_renderer('.html')
    config.include(oauth, route_prefix='oauth')
    config.include(api, route_prefix='api')
    config.include(core)
    config.include(demodata)
    return config.make_wsgi_app()


if __name__ == '__main__':
    import waitress
    app = main({}, **SETTINGS)
    waitress.serve(app, port=5000)
