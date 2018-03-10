import os
import hashlib
from pyramid import security
from pyramid.httpexceptions import HTTPFound
from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.config import Configurator

from requests_oauthlib import OAuth2Session


# this is example, using insecure port
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


SETTINGS = {
    "sqlalchemy.url": "sqlite:///codeclient.db",
    "sqlalchemy.echo": True,
    "authtkt.secret": "secret",
    "pyramid.reload_templates": True,
    "authorization_base_url": 'http://localhost:5000/oauth/authorize',
    "token_url": 'http://localhost:5000/oauth/token',
    "client_id": "democlient",
    "client_secret": "secret",
}


# views

def index(request):
    request.response.text = """\
<html>
<body>
<h1>Authorization code client</h1>
<a href="%s">Authorize</a>
</body>
</html>
""" % (request.route_url('oauth.authorize'))
    return request.response


def oauth_authorize(request):
    print("authorize")
    provider = OAuth2Session(request.context.client_id)
    authorization_url, state = provider.authorization_url(
        request.context.authorization_base_url)
    print(authorization_url)
    return HTTPFound(location=authorization_url)


def oauth_callback(request):
    provider = OAuth2Session(request.context.client_id)
    token = provider.fetch_token(
        request.context.token_url,
        client_secret=request.context.client_secret,
        authorization_response=request.url)
    print(token)
    return provider.get('http://localhost:5000/api/protected').json()
# resource


class AuthorizationCodeResource:
    def __init__(self, request):
        self.request = request

    @property
    def authorization_base_url(self):
        return self.request.registry.settings["authorization_base_url"]

    @property
    def token_url(self):
        return self.request.registry.settings["token_url"]

    @property
    def client_id(self):
        return self.request.registry.settings["client_id"]

    @property
    def client_secret(self):
        return self.request.registry.settings["client_secret"]

    @property
    def __acl__(self):
        return [
            (security.Allow, security.Authenticated, "authorize"),
        ]


def main(global_config, **settings):
    authentication_policy = AuthTktAuthenticationPolicy(
        hashlib.sha256(settings['authtkt.secret'].encode('utf-8')).hexdigest())
    authorization_policy = ACLAuthorizationPolicy()
    config = Configurator(
        authentication_policy=authentication_policy,
        authorization_policy=authorization_policy,
        root_factory=AuthorizationCodeResource,
        settings=settings)
    config.add_route("index", "/")
    config.add_route("oauth.authorize", "/oauth/authorize")
    config.add_route("oauth.callback", "/oauth/callback")
    config.add_view(
        index,
        route_name="index")
    config.add_view(
        oauth_authorize,
        route_name="oauth.authorize")
    config.add_view(
        oauth_callback,
        route_name="oauth.callback",
        renderer="string")
    return config.make_wsgi_app()


if __name__ == '__main__':
    import waitress
    app = main({}, **SETTINGS)
    waitress.serve(app, port=5001)
